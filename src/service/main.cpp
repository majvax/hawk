#include "capture_host.hpp"
#include "credential_store.hpp"
#include "websocket/websocket.hpp"

#include <windows.h>

#include <glaze/glaze.hpp>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <variant>
#include <vector>

namespace net = hawk::net;
namespace svc = hawk::service;

namespace {

// Points at the relay server under src/server (see src/server/README.md),
// which now serves TLS by default (`bun run certs` + a cert/key on disk).
// WinHTTP validates the server cert against the Windows trust store like any
// other wss:// client, so the self-signed dev cert must be imported into
// this machine's Trusted Root Certification Authorities before a local dev
// relay will accept a connection — see the TLS section of that README. For
// anything beyond localhost, use a cert from a real CA instead.
constexpr std::string_view kRelayServerUrl = "wss://127.0.0.1:8080/v1/ws";
constexpr std::chrono::seconds kReconnectDelay{5};
// After the relay refuses this machine (unknown credential or code), or
// while there's nothing to identify with, retry less eagerly.
constexpr std::chrono::seconds kRejectedRetryDelay{30};
// RFC 6455 "policy violation": the relay's answer to an unknown machine.
constexpr std::uint16_t kPolicyViolationCode = 1008;
constexpr std::wstring_view kServiceName = L"HawkService";

// Exactly one of `credential` / `enroll_code` is set; unset members are left
// out of the JSON.
struct HelloMessage {
    std::string                type = "hello";
    std::string                machine_id;  // the hostname, shown to the owner
    std::optional<std::string> credential;
    std::optional<std::string> enroll_code;
};

// A message from the relay. Unknown fields are ignored, so commands can grow
// parameters without breaking this parser. `machine_id` and `credential`
// are only set on "enrolled".
struct RelayCommand {
    std::string type;
    std::string machine_id;
    std::string credential;
};

// Binary frame carrying one H.264 access unit to the relay:
//   [0]      u8   kind, kVideoFrameKind = H.264 Annex B
//   [1]      u8   flags, bit 0 = keyframe
//   [2..9]   i64  timestamp in microseconds since the stream started, little-endian
//   [10..]        the access unit
constexpr std::byte   kVideoFrameKind{0x01};
constexpr std::byte   kVideoFrameKeyframeFlag{0x01};
constexpr std::size_t kVideoFrameHeaderSize = 10;

}  // namespace

template <>
struct glz::meta<HelloMessage> {
    using T                     = HelloMessage;
    static constexpr auto value = object("type", &T::type, "machine_id", &T::machine_id, "credential",
                                         &T::credential, "enroll_code", &T::enroll_code);
};

template <>
struct glz::meta<RelayCommand> {
    using T                     = RelayCommand;
    static constexpr auto value =
        object("type", &T::type, "machine_id", &T::machine_id, "credential", &T::credential);
};

namespace {

// Bundles everything ServiceCtrlHandlerEx needs so it can be reached through
// RegisterServiceCtrlHandlerExW's lpContext parameter instead of through
// module-level globals. Owned by ServiceMain's stack frame, which outlives
// every possible invocation of the handler (registration happens first;
// ServiceMain doesn't return until after the service has fully stopped).
struct ServiceContext {
    SERVICE_STATUS        status{};
    SERVICE_STATUS_HANDLE status_handle = nullptr;
    HANDLE                stop_event = nullptr;
    std::stop_source      stop_source;

    // Published by RelayLoop() while connected so the control handler,
    // running on a different thread, can call close() to cancel a blocked
    // receive() immediately on stop/shutdown rather than waiting on it.
    std::atomic<net::WebSocketClient*> active_client{nullptr};
};

void InitLogging() {
    constexpr const char* kLogDirectory = R"(C:\ProgramData\HawkService)";
    constexpr const char* kLogPath = R"(C:\ProgramData\HawkService\hawk-service.log)";

    CreateDirectoryA(kLogDirectory, nullptr);  // best-effort; ignored if it already exists.
    try {
        auto logger = spdlog::basic_logger_mt("hawk-service", kLogPath);
        spdlog::set_default_logger(logger);
        spdlog::flush_on(spdlog::level::info);
    } catch (const spdlog::spdlog_ex& ex) {
        // Logging is best-effort: the service must still run without it
        // (e.g. if C:\ProgramData isn't writable for some reason). Surface
        // the failure to a debugger/DebugView instead of swallowing it.
        OutputDebugStringA(ex.what());
    }
}

// How this machine identifies itself to the relay: a pending enrollment
// code wins over a stored credential (that's how a machine is re-enrolled).
// Nothing at all means it was never enrolled.
struct Identity {
    std::optional<std::string> credential;
    std::optional<std::string> enroll_code;
};

[[nodiscard]] std::optional<Identity> LoadIdentity() {
    if (auto code = svc::load_enroll_code(); code.has_value()) {
        return Identity{.credential = std::nullopt, .enroll_code = std::move(code)};
    }
    if (auto credential = svc::load_credential(); credential.has_value()) {
        return Identity{.credential = std::move(credential), .enroll_code = std::nullopt};
    }
    return std::nullopt;
}

[[nodiscard]] std::string BuildHelloMessage(Identity identity) {
    std::array<char, MAX_COMPUTERNAME_LENGTH + 1> name_buffer{};
    auto name_length = static_cast<DWORD>(name_buffer.size());
    GetComputerNameA(name_buffer.data(), &name_length);

    HelloMessage hello{
        .machine_id = std::string(name_buffer.data(), name_length),
        .credential = std::move(identity.credential),
        .enroll_code = std::move(identity.enroll_code),
    };
    if (auto json = glz::write_json(hello); json.has_value()) {
        return *json;
    }
    spdlog::error("relay: failed to serialize hello message");
    return {};
}

[[nodiscard]] std::vector<std::byte> BuildVideoFrame(const svc::CapturePacket& packet) {
    std::vector<std::byte> frame(kVideoFrameHeaderSize + packet.data.size());
    frame[0] = kVideoFrameKind;
    frame[1] = packet.is_keyframe ? kVideoFrameKeyframeFlag : std::byte{0};
    const auto timestamp = static_cast<std::uint64_t>(packet.timestamp.count());
    for (std::size_t i = 0; i < sizeof(timestamp); ++i) {
        frame[2 + i] = static_cast<std::byte>((timestamp >> (8 * i)) & 0xFFU);
    }
    std::ranges::copy(packet.data, frame.begin() + kVideoFrameHeaderSize);
    return frame;
}

// Launches hawk-capture in the logged-on user's session and forwards every
// packet it produces to the relay as a binary frame.
void StartCapture(net::WebSocketClient& client, svc::CaptureHost& capture) {
    if (capture.is_running()) {
        spdlog::info("relay: start_capture ignored, capture already running");
        return;
    }

    auto started = capture.start([&client](const svc::CapturePacket& packet) {
        if (auto sent = client.send_binary(BuildVideoFrame(packet)); !sent.has_value()) {
            spdlog::warn("relay: failed to forward video packet: {}", net::to_string(sent.error()));
        }
    });
    if (!started.has_value()) {
        spdlog::error("relay: failed to start capture: {}", svc::to_string(started.error()));
    }
}

void HandleRelayCommand(std::string_view text, net::WebSocketClient& client, svc::CaptureHost& capture) {
    RelayCommand command;
    if (auto error = glz::read<glz::opts{.error_on_unknown_keys = false}>(command, text); error) {
        spdlog::warn("relay: received unparseable message: {}", text);
        return;
    }

    if (command.type == "enrolled") {
        // The code is spent either way; only the credential works from now on.
        if (svc::save_credential(command.credential)) {
            svc::delete_enroll_code();
            spdlog::info("relay: enrolled as machine {}", command.machine_id);
        } else {
            spdlog::error("relay: enrolled as machine {}, but the credential couldn't be saved; "
                          "remove the machine in the dashboard and enroll it again",
                          command.machine_id);
        }
    } else if (command.type == "start_capture") {
        StartCapture(client, capture);
    } else if (command.type == "stop_capture") {
        capture.stop();
    } else {
        spdlog::info("relay: ignoring unknown command \"{}\"", command.type);
    }
}

// Handles one received message. Returns the close code once the relay has
// closed the connection, nullopt while it stays open.
[[nodiscard]] std::optional<std::uint16_t> HandleRelayMessage(const net::WebSocketMessage& message,
                                                              net::WebSocketClient& client, svc::CaptureHost& capture) {
    return std::visit(
        [&]<typename T>(const T& payload) -> std::optional<std::uint16_t> {
            if constexpr (std::is_same_v<T, std::string>) {
                HandleRelayCommand(payload, client, capture);
                return std::nullopt;
            } else if constexpr (std::is_same_v<T, std::vector<std::byte>>) {
                spdlog::info("relay: received binary message ({} bytes)", payload.size());
                return std::nullopt;
            } else {
                spdlog::info("relay: server closed the connection (code={}, reason=\"{}\")", payload.code,
                             payload.reason);
                return payload.code;
            }
        },
        message);
}

// Sleeps for `duration`, waking early if the service is stopping.
void SleepUnlessStopped(const std::stop_token& stop_token, std::chrono::seconds duration) {
    const auto deadline = std::chrono::steady_clock::now() + duration;
    while (!stop_token.stop_requested() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
}

void RelayLoop(const std::stop_token& stop_token, std::atomic<net::WebSocketClient*>& active_client) {
    net::WebSocketClient client;
    // Declared after `client` so it's destroyed (stopped) first: its reader
    // thread sends through `client`.
    svc::CaptureHost capture;

    bool warned_not_enrolled = false;
    while (!stop_token.stop_requested()) {
        auto identity = LoadIdentity();
        if (!identity.has_value()) {
            if (!warned_not_enrolled) {
                spdlog::warn("relay: this machine isn't enrolled. Create an enrollment code in the dashboard "
                             "(Machines > Add machine) and reinstall with install-service.ps1 -EnrollCode <code>");
                warned_not_enrolled = true;
            }
            SleepUnlessStopped(stop_token, kRejectedRetryDelay);
            continue;
        }
        warned_not_enrolled = false;

        if (auto connected = client.connect(kRelayServerUrl); !connected.has_value()) {
            spdlog::error("relay: connect failed: {}", net::to_string(connected.error()));
            SleepUnlessStopped(stop_token, kReconnectDelay);
            continue;
        }

        spdlog::info("relay: connected to {}", kRelayServerUrl);
        active_client.store(&client);

        if (auto sent = client.send_text(BuildHelloMessage(std::move(*identity))); !sent.has_value()) {
            spdlog::warn("relay: failed to send hello message: {}", net::to_string(sent.error()));
        }

        std::optional<std::uint16_t> close_code;
        while (!stop_token.stop_requested()) {
            auto message = client.receive();
            if (!message.has_value()) {
                spdlog::warn("relay: receive failed: {}", net::to_string(message.error()));
                break;
            }
            close_code = HandleRelayMessage(*message, client, capture);
            if (close_code.has_value()) {
                break;
            }
        }

        // Capture only runs on behalf of a viewer reached through this
        // connection; stop it before the socket it forwards to goes away.
        capture.stop();
        active_client.store(nullptr);
        client.close();

        if (close_code == kPolicyViolationCode) {
            spdlog::warn("relay: the relay refused this machine (removed, owner disabled, or an invalid "
                         "enrollment code); retrying in {}s",
                         kRejectedRetryDelay.count());
            SleepUnlessStopped(stop_token, kRejectedRetryDelay);
        } else if (!close_code.has_value()) {
            SleepUnlessStopped(stop_token, kReconnectDelay);
        }
    }

    spdlog::info("relay: loop stopped");
}

DWORD WINAPI ServiceCtrlHandlerEx(DWORD ctrl, [[maybe_unused]] DWORD event_type,
                                   [[maybe_unused]] LPVOID event_data, LPVOID context) {
    auto* service = static_cast<ServiceContext*>(context);

    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        service->status.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(service->status_handle, &service->status);

        service->stop_source.request_stop();
        if (net::WebSocketClient* client = service->active_client.load(); client != nullptr) {
            client->close();
        }
        SetEvent(service->stop_event);
    }
    return NO_ERROR;
}

void WINAPI ServiceMain([[maybe_unused]] DWORD argc, [[maybe_unused]] LPWSTR* argv) {
    InitLogging();

    ServiceContext service;
    service.status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    service.status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    service.status.dwCurrentState = SERVICE_START_PENDING;

    // kServiceName's view is constructed directly from a string literal, whose
    // storage is guaranteed null-terminated, so .data() is safe here even
    // though std::string_view doesn't promise that in general.
    // NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage)
    service.status_handle = RegisterServiceCtrlHandlerExW(kServiceName.data(), ServiceCtrlHandlerEx, &service);
    SetServiceStatus(service.status_handle, &service.status);

    service.stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    service.status.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(service.status_handle, &service.status);

    std::jthread relay_thread(
        [&service] { RelayLoop(service.stop_source.get_token(), service.active_client); });

    WaitForSingleObject(service.stop_event, INFINITE);
    relay_thread.join();

    spdlog::info("service: stopped");
    spdlog::shutdown();

    service.status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(service.status_handle, &service.status);
}

}  // namespace

int wmain() {
    // SERVICE_TABLE_ENTRYW::lpServiceName is LPWSTR (non-const) even though
    // the SCM only ever reads it; a mutable local avoids a const_cast.
    std::array<wchar_t, kServiceName.size() + 1> service_name{};
    std::ranges::copy(kServiceName, service_name.begin());

    std::array<SERVICE_TABLE_ENTRYW, 2> table{
        SERVICE_TABLE_ENTRYW{.lpServiceName = service_name.data(), .lpServiceProc = ServiceMain},
        SERVICE_TABLE_ENTRYW{.lpServiceName = nullptr, .lpServiceProc = nullptr},
    };
    StartServiceCtrlDispatcherW(table.data());
    return 0;
}
