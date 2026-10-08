#include "capture_host.hpp"
#include "machine_identity.hpp"
#include "machine_key.hpp"
#include "websocket/websocket.hpp"

#include <windows.h>
#include <wincrypt.h>

#include <glaze/glaze.hpp>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
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
// After the relay refuses this machine (unknown machine, bad code, failed
// key proof), or while there's nothing to identify with, retry less eagerly.
constexpr std::chrono::seconds kRejectedRetryDelay{30};
// RFC 6455 "policy violation": the relay's answer to an unknown machine.
constexpr std::uint16_t kPolicyViolationCode = 1008;
constexpr std::wstring_view kServiceName = L"HawkService";

// What the machine signs to answer the relay's challenge; must match
// machine_auth_message() in src/server/relay/src/protocol.rs.
constexpr std::string_view kMachineAuthContext{"hawk-machine-auth-v1\0", 21};

// Opens every connection. An enrolled machine sends `machine`; a new one
// sends `enroll_code`, `public_key` and `key_storage`. Unset members are
// left out of the JSON.
struct HelloMessage {
    std::string                type = "hello";
    std::string                machine_id;  // the hostname, shown to the owner
    std::optional<std::string> machine;
    std::optional<std::string> enroll_code;
    std::optional<std::string> public_key;  // base64 uncompressed P-256 point
    std::optional<std::string> key_storage;  // "tpm" or "software"
};

// Answers the relay's challenge.
struct ProofMessage {
    std::string type = "proof";
    std::string signature;  // base64 r || s
};

// A message from the relay. Unknown fields are ignored, so commands can grow
// parameters without breaking this parser. `nonce` is only set on
// "challenge", `machine_id` only on "enrolled".
struct RelayCommand {
    std::string type;
    std::string nonce;
    std::string machine_id;
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
    static constexpr auto value =
        object("type", &T::type, "machine_id", &T::machine_id, "machine", &T::machine, "enroll_code",
               &T::enroll_code, "public_key", &T::public_key, "key_storage", &T::key_storage);
};

template <>
struct glz::meta<ProofMessage> {
    using T                     = ProofMessage;
    static constexpr auto value = object("type", &T::type, "signature", &T::signature);
};

template <>
struct glz::meta<RelayCommand> {
    using T                     = RelayCommand;
    static constexpr auto value = object("type", &T::type, "nonce", &T::nonce, "machine_id", &T::machine_id);
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

[[nodiscard]] std::string Base64Encode(std::span<const std::byte> data) {
    const auto* bytes = reinterpret_cast<const BYTE*>(data.data());
    const auto  flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;
    DWORD       length = 0;
    if (CryptBinaryToStringA(bytes, static_cast<DWORD>(data.size()), flags, nullptr, &length) == FALSE) {
        return {};
    }
    std::string text(length, '\0');
    if (CryptBinaryToStringA(bytes, static_cast<DWORD>(data.size()), flags, text.data(), &length) == FALSE) {
        return {};
    }
    text.resize(length);  // drop the terminator the size query counted
    return text;
}

[[nodiscard]] std::optional<std::vector<std::byte>> Base64Decode(std::string_view text) {
    DWORD length = 0;
    if (CryptStringToBinaryA(text.data(), static_cast<DWORD>(text.size()), CRYPT_STRING_BASE64, nullptr, &length,
                             nullptr, nullptr) == FALSE) {
        return std::nullopt;
    }
    std::vector<std::byte> data(length);
    if (CryptStringToBinaryA(text.data(), static_cast<DWORD>(text.size()), CRYPT_STRING_BASE64,
                             reinterpret_cast<BYTE*>(data.data()), &length, nullptr, nullptr) == FALSE) {
        return std::nullopt;
    }
    data.resize(length);
    return data;
}

// What one connection authenticates with. A pending enrollment code wins
// over the stored identity (that's how a machine is re-enrolled): it gets a
// brand-new key under a fresh name, so a rejected code never disturbs the
// key the machine already has.
struct Session {
    svc::MachineKey            key;
    std::wstring               key_name;
    std::optional<std::string> machine_id;   // set when already enrolled
    std::optional<std::string> enroll_code;  // set while enrolling
};

enum class SessionProblem : std::uint8_t {
    not_enrolled,  // nothing to identify with yet
    failed,        // logged already
};

[[nodiscard]] std::expected<Session, SessionProblem> PrepareSession() {
    if (auto code = svc::load_enroll_code(); code.has_value()) {
        std::wstring name = svc::new_machine_key_name();
        auto         key = svc::MachineKey::create(name);
        if (!key.has_value()) {
            spdlog::error("relay: {}", key.error());
            return std::unexpected(SessionProblem::failed);
        }
        spdlog::info("relay: enrolling with a new {} key", key->storage());
        return Session{.key = std::move(*key),
                       .key_name = std::move(name),
                       .machine_id = std::nullopt,
                       .enroll_code = std::move(code)};
    }
    if (auto identity = svc::load_machine_identity(); identity.has_value()) {
        auto key = svc::MachineKey::open(identity->key_name);
        if (!key.has_value()) {
            spdlog::error("relay: this machine's key is missing ({}); remove it in the dashboard and enroll it again",
                          key.error());
            return std::unexpected(SessionProblem::failed);
        }
        return Session{.key = std::move(*key),
                       .key_name = std::move(identity->key_name),
                       .machine_id = std::move(identity->machine_id),
                       .enroll_code = std::nullopt};
    }
    return std::unexpected(SessionProblem::not_enrolled);
}

// If `session` was enrolling and didn't get through, deletes the key it
// created for that attempt. The session (and its open key handle) is
// released first: the TPM provider won't delete a key that's still open.
// Returns whether it was an enrollment attempt.
bool DiscardFailedEnrollment(std::expected<Session, SessionProblem>& session) {
    if (!session.has_value() || !session->enroll_code.has_value()) {
        return false;
    }
    const std::wstring key_name = session->key_name;
    session = std::unexpected(SessionProblem::failed);
    if (auto destroyed = svc::MachineKey::destroy(key_name); !destroyed.has_value()) {
        spdlog::warn("relay: couldn't delete the unused enrollment key: {}", destroyed.error());
    }
    return true;
}

[[nodiscard]] std::string BuildHelloMessage(const Session& session) {
    std::array<char, MAX_COMPUTERNAME_LENGTH + 1> name_buffer{};
    auto name_length = static_cast<DWORD>(name_buffer.size());
    GetComputerNameA(name_buffer.data(), &name_length);

    HelloMessage hello{
        .machine_id = std::string(name_buffer.data(), name_length),
        .machine = session.machine_id,
        .enroll_code = session.enroll_code,
        .public_key = std::nullopt,
        .key_storage = std::nullopt,
    };
    if (session.enroll_code.has_value()) {
        auto public_key = session.key.public_key();
        if (!public_key.has_value()) {
            spdlog::error("relay: exporting the public key failed: {}", public_key.error());
            return {};
        }
        hello.public_key = Base64Encode(*public_key);
        hello.key_storage = std::string(session.key.storage());
    }
    if (auto json = glz::write_json(hello); json.has_value()) {
        return *json;
    }
    spdlog::error("relay: failed to serialize hello message");
    return {};
}

// Signs the relay's challenge with the machine key.
[[nodiscard]] std::string BuildProofMessage(const Session& session, std::string_view nonce_base64) {
    const auto nonce = Base64Decode(nonce_base64);
    if (!nonce.has_value()) {
        spdlog::error("relay: received an unreadable challenge");
        return {};
    }
    std::vector<std::byte> message(kMachineAuthContext.size());
    std::ranges::transform(kMachineAuthContext, message.begin(), [](char c) { return static_cast<std::byte>(c); });
    message.insert(message.end(), nonce->begin(), nonce->end());

    auto signature = session.key.sign(message);
    if (!signature.has_value()) {
        spdlog::error("relay: signing the challenge failed: {}", signature.error());
        return {};
    }
    if (auto json = glz::write_json(ProofMessage{.signature = Base64Encode(*signature)}); json.has_value()) {
        return *json;
    }
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

// The relay accepted this connection's enrollment: make the new key and
// machine id this PC's identity, and retire what it had before.
void CompleteEnrollment(Session& session, const std::string& machine_id) {
    const auto previous = svc::load_machine_identity();
    if (!svc::save_machine_identity({.machine_id = machine_id, .key_name = session.key_name})) {
        spdlog::error("relay: enrolled as machine {}, but couldn't save that; remove the machine in the dashboard "
                      "and enroll it again",
                      machine_id);
        return;
    }
    svc::delete_enroll_code();
    if (previous.has_value() && previous->key_name != session.key_name) {
        if (auto destroyed = svc::MachineKey::destroy(previous->key_name); !destroyed.has_value()) {
            spdlog::warn("relay: couldn't delete the previous machine key: {}", destroyed.error());
        }
    }
    svc::delete_legacy_credential();
    session.machine_id = machine_id;
    session.enroll_code.reset();
    spdlog::info("relay: enrolled as machine {} ({} key)", machine_id, session.key.storage());
}

void HandleRelayCommand(std::string_view text, net::WebSocketClient& client, svc::CaptureHost& capture,
                        Session& session) {
    RelayCommand command;
    if (auto error = glz::read<glz::opts{.error_on_unknown_keys = false}>(command, text); error) {
        spdlog::warn("relay: received unparseable message: {}", text);
        return;
    }

    if (command.type == "challenge") {
        if (auto sent = client.send_text(BuildProofMessage(session, command.nonce)); !sent.has_value()) {
            spdlog::warn("relay: failed to send key proof: {}", net::to_string(sent.error()));
        }
    } else if (command.type == "enrolled") {
        CompleteEnrollment(session, command.machine_id);
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
                                                              net::WebSocketClient& client, svc::CaptureHost& capture,
                                                              Session& session) {
    return std::visit(
        [&]<typename T>(const T& payload) -> std::optional<std::uint16_t> {
            if constexpr (std::is_same_v<T, std::string>) {
                HandleRelayCommand(payload, client, capture, session);
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
    bool warned_unpinned = false;
    while (!stop_token.stop_requested()) {
        auto session = PrepareSession();
        if (!session.has_value()) {
            if (session.error() == SessionProblem::not_enrolled && !warned_not_enrolled) {
                spdlog::warn("relay: this machine isn't enrolled. Create an enrollment code in the dashboard "
                             "(Machines > Add machine) and reinstall with install-service.ps1 -EnrollCode <code>");
                warned_not_enrolled = true;
            }
            SleepUnlessStopped(stop_token, kRejectedRetryDelay);
            continue;
        }
        warned_not_enrolled = false;

        net::WebSocketClient::ConnectOptions options;
        options.pinned_keys = svc::load_relay_pins();
        if (options.pinned_keys.empty() && !warned_unpinned) {
            spdlog::warn("relay: no relay key pinned; only the certificate chain is checked. Reinstall with "
                         "install-service.ps1 -RelayPin <pin> (shown with the enrollment code) to pin it");
            warned_unpinned = true;
        }

        if (auto connected = client.connect(kRelayServerUrl, options); !connected.has_value()) {
            DiscardFailedEnrollment(session);  // a fresh key is made next attempt
            if (connected.error().code == net::WebSocketError::Code::pin_mismatch) {
                // Either the relay's key changed or someone is in the middle:
                // either way, nothing is sent until a pinned key shows up.
                spdlog::error("relay: refusing {}: {}. If the relay's TLS key really changed, reinstall with the "
                              "new -RelayPin",
                              kRelayServerUrl, connected.error().message);
                SleepUnlessStopped(stop_token, kRejectedRetryDelay);
            } else {
                spdlog::error("relay: connect failed: {}", net::to_string(connected.error()));
                SleepUnlessStopped(stop_token, kReconnectDelay);
            }
            continue;
        }

        spdlog::info("relay: connected to {}", kRelayServerUrl);
        active_client.store(&client);

        if (auto sent = client.send_text(BuildHelloMessage(*session)); !sent.has_value()) {
            spdlog::warn("relay: failed to send hello message: {}", net::to_string(sent.error()));
        }

        std::optional<std::uint16_t> close_code;
        while (!stop_token.stop_requested()) {
            auto message = client.receive();
            if (!message.has_value()) {
                spdlog::warn("relay: receive failed: {}", net::to_string(message.error()));
                break;
            }
            close_code = HandleRelayMessage(*message, client, capture, *session);
            if (close_code.has_value()) {
                break;
            }
        }

        // Capture only runs on behalf of a viewer reached through this
        // connection; stop it before the socket it forwards to goes away.
        capture.stop();
        active_client.store(nullptr);
        client.close();

        // An enrollment that didn't go through leaves no key behind.
        const bool enrollment_failed = DiscardFailedEnrollment(session);

        if (close_code == kPolicyViolationCode && enrollment_failed) {
            // A wrong or expired code never becomes right; stop retrying it.
            svc::delete_enroll_code();
            spdlog::error("relay: the enrollment code was rejected (wrong, expired or already used). Create a new "
                          "one in the dashboard and reinstall with install-service.ps1 -EnrollCode <code>");
            SleepUnlessStopped(stop_token, kRejectedRetryDelay);
        } else if (close_code == kPolicyViolationCode) {
            spdlog::warn("relay: the relay refused this machine (removed, owner disabled, or the key proof "
                         "failed); retrying in {}s",
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
