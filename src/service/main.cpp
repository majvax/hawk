#include "websocket/websocket.hpp"

#include <windows.h>

#include <glaze/glaze.hpp>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <variant>
#include <vector>

namespace net = hawk::net;

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
constexpr std::wstring_view kServiceName = L"HawkService";

struct HelloMessage {
    std::string type = "hello";
    std::string machine_id;
};

}  // namespace

template <>
struct glz::meta<HelloMessage> {
    using T                     = HelloMessage;
    static constexpr auto value = object("type", &T::type, "machine_id", &T::machine_id);
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

[[nodiscard]] std::string BuildHelloMessage() {
    std::array<char, MAX_COMPUTERNAME_LENGTH + 1> name_buffer{};
    auto name_length = static_cast<DWORD>(name_buffer.size());
    GetComputerNameA(name_buffer.data(), &name_length);

    HelloMessage hello{.machine_id = std::string(name_buffer.data(), name_length)};
    if (auto json = glz::write_json(hello); json.has_value()) {
        return *json;
    }
    spdlog::error("relay: failed to serialize hello message");
    return {};
}

// Handles one received message. Returns true if the connection should be
// treated as over (no immediate reconnect attempt) rather than retried.
[[nodiscard]] bool HandleRelayMessage(const net::WebSocketMessage& message) {
    return std::visit(
        []<typename T>(const T& payload) -> bool {
            if constexpr (std::is_same_v<T, std::string>) {
                spdlog::info("relay: received text message: {}", payload);
                // TODO: parse and dispatch the relay command protocol here.
                return false;
            } else if constexpr (std::is_same_v<T, std::vector<std::byte>>) {
                spdlog::info("relay: received binary message ({} bytes)", payload.size());
                return false;
            } else {
                spdlog::info("relay: server closed the connection (code={}, reason=\"{}\")", payload.code,
                             payload.reason);
                return true;
            }
        },
        message);
}

void RelayLoop(const std::stop_token& stop_token, std::atomic<net::WebSocketClient*>& active_client) {
    net::WebSocketClient client;

    while (!stop_token.stop_requested()) {
        if (auto connected = client.connect(kRelayServerUrl); !connected.has_value()) {
            spdlog::error("relay: connect failed: {}", net::to_string(connected.error()));
            std::this_thread::sleep_for(kReconnectDelay);
            continue;
        }

        spdlog::info("relay: connected to {}", kRelayServerUrl);
        active_client.store(&client);

        if (auto sent = client.send_text(BuildHelloMessage()); !sent.has_value()) {
            spdlog::warn("relay: failed to send hello message: {}", net::to_string(sent.error()));
        }

        bool peer_closed = false;
        while (!stop_token.stop_requested()) {
            auto message = client.receive();
            if (!message.has_value()) {
                spdlog::warn("relay: receive failed: {}", net::to_string(message.error()));
                break;
            }
            if (HandleRelayMessage(*message)) {
                peer_closed = true;
                break;
            }
        }

        active_client.store(nullptr);
        client.close();

        if (!stop_token.stop_requested() && !peer_closed) {
            std::this_thread::sleep_for(kReconnectDelay);
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
