#include "capture_host.hpp"
#include "config.hpp"
#include "crypto.hpp"
#include "e2e.hpp"
#include "files.hpp"
#include "shell.hpp"
#include "machine_identity.hpp"
#include "machine_key.hpp"
#include "updater.hpp"
#include "websocket/websocket.hpp"

#include <hawk/version.hpp>

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
#include <cstdio>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <variant>
#include <vector>

namespace ipc = hawk::ipc;
namespace net = hawk::net;
namespace svc = hawk::service;

namespace {

// The relay's address comes from config.toml ([[relay]] url), which the
// installer writes. WinHTTP validates the relay's certificate against the
// Windows trust store like any other wss:// client, and the pins in
// relay-pins.txt on top of that.
constexpr std::chrono::seconds kReconnectDelay{5};
// Must match PROTOCOL_VERSION in src/server/relay/src/protocol.rs.
constexpr std::uint32_t kProtocolVersion = 1;
// After the relay refuses this machine (unknown machine, bad code, failed
// key proof), or while there's nothing to identify with, retry less eagerly.
constexpr std::chrono::seconds kRejectedRetryDelay{30};
// RFC 6455 "policy violation": the relay's answer to an unknown machine.
constexpr std::uint16_t kPolicyViolationCode = 1008;
constexpr std::wstring_view kServiceName = L"HawkService";

namespace crypto = hawk::crypto;

// What the machine signs to answer the relay's challenge; must match
// machine_auth_message() in src/server/relay/src/protocol.rs.
constexpr std::string_view kMachineAuthContext{"hawk-machine-auth-v1\0", 21};

// Opens every connection. An enrolled machine sends `machine`; a new one
// sends the hash of its enrollment code (never the code, which keys the
// bindings), `public_key`, `key_storage` and `binding`. Unset members are
// left out of the JSON.
struct HelloMessage {
    std::string                type = "hello";
    std::string                machine_id;  // the hostname, shown to the owner
    std::optional<std::string> machine;
    std::optional<std::string> enroll_code_hash;
    std::optional<std::string> public_key;  // base64 uncompressed P-256 point
    std::optional<std::string> key_storage;  // "tpm" or "software"
    std::optional<std::string> binding;      // base64 HMAC of public_key under the code
    std::string                version{internal::version::full_version};
    std::uint32_t              protocol = kProtocolVersion;
};

// The update this machine's updater is holding for the owner, if any.
struct UpdateStatusMessage {
    std::string                type = "update_status";
    std::optional<std::string> available;
};

// Answers the relay's challenge.
struct ProofMessage {
    std::string type = "proof";
    std::string signature;  // base64 r || s
};

// A message from the relay. Unknown fields are ignored, so commands can grow
// parameters without breaking this parser. See DeviceCommand in
// relay/src/protocol.rs for which command carries what. Viewers' requests
// and input arrive signed or sealed for this machine; the relay can't read
// or forge them, and ViewerHub checks them.
struct RelayCommand {
    std::string                                  type;
    std::string                                  nonce;          // challenge
    std::string                                  machine_id;     // enrolled
    std::string                                  owner_key;      // enrolled: base64 identity key
    std::string                                  owner_binding;  // enrolled: base64 HMAC under the code
    std::uint64_t                                viewer = 0;     // viewer_join, viewer_left, input, clipboard, file, shell
    std::string                                  statement;      // viewer_join
    std::string                                  signature;      // viewer_join
    std::optional<svc::SignedStatement>          grant;          // viewer_join
    std::string                                  sealed;         // input, clipboard, file, shell
    std::vector<svc::SignedStatement>            revocations;    // revocations
};

}  // namespace

template <>
struct glz::meta<HelloMessage> {
    using T                     = HelloMessage;
    static constexpr auto value =
        object("type", &T::type, "machine_id", &T::machine_id, "machine", &T::machine, "enroll_code_hash",
               &T::enroll_code_hash, "public_key", &T::public_key, "key_storage", &T::key_storage, "binding",
               &T::binding, "version", &T::version, "protocol", &T::protocol);
};

template <>
struct glz::meta<hawk::service::SignedStatement> {
    using T                     = hawk::service::SignedStatement;
    static constexpr auto value = object("statement", &T::statement, "signature", &T::signature);
};

template <>
struct glz::meta<ProofMessage> {
    using T                     = ProofMessage;
    static constexpr auto value = object("type", &T::type, "signature", &T::signature);
};

template <>
struct glz::meta<RelayCommand> {
    using T                     = RelayCommand;
    static constexpr auto value =
        object("type", &T::type, "nonce", &T::nonce, "machine_id", &T::machine_id, "owner_key", &T::owner_key,
               "owner_binding", &T::owner_binding, "viewer", &T::viewer, "statement", &T::statement, "signature",
               &T::signature, "grant", &T::grant, "sealed", &T::sealed, "revocations", &T::revocations);
};

template <>
struct glz::meta<UpdateStatusMessage> {
    using T                     = UpdateStatusMessage;
    static constexpr auto value = object("type", &T::type, "available", &T::available);
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

// What the service is doing, for hawk-setup: it shows enrollment live while
// installing, and after an update waits for "connected" before calling the
// update good. Replaced whole each time.
struct ServiceStatus {
    std::string  state;
    std::string  detail;
    std::string  version;
    std::int64_t at = 0;
};

const std::filesystem::path kStatusPath = R"(C:\ProgramData\HawkService\status.json)";

void WriteStatus(std::string_view state, std::string_view detail = {}) {
    const ServiceStatus status{.state = std::string(state),
                               .detail = std::string(detail),
                               .version = std::string(internal::version::full_version),
                               .at = std::chrono::duration_cast<std::chrono::seconds>(
                                         std::chrono::system_clock::now().time_since_epoch())
                                         .count()};
    auto json = glz::write_json(status);
    if (!json.has_value()) {
        return;
    }
    auto temporary = kStatusPath;
    temporary += L".tmp";
    {
        std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
        if (!file) {
            return;
        }
        file << *json;
    }
    MoveFileExW(temporary.c_str(), kStatusPath.c_str(), MOVEFILE_REPLACE_EXISTING);
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
        .enroll_code_hash = std::nullopt,
        .public_key = std::nullopt,
        .key_storage = std::nullopt,
        .binding = std::nullopt,
    };
    if (session.enroll_code.has_value()) {
        auto public_key = session.key.public_key();
        if (!public_key.has_value()) {
            spdlog::error("relay: exporting the public key failed: {}", public_key.error());
            return {};
        }
        const auto binding = svc::enroll_binding(*session.enroll_code, "hawk-enroll-machine-v1", *public_key);
        hello.enroll_code_hash = svc::enroll_code_hash(*session.enroll_code);
        hello.public_key = crypto::base64_encode(*public_key);
        hello.key_storage = std::string(session.key.storage());
        hello.binding = crypto::base64_encode(binding);
    }
    if (auto json = glz::write_json(hello); json.has_value()) {
        return *json;
    }
    spdlog::error("relay: failed to serialize hello message");
    return {};
}

// Signs the relay's challenge with the machine key.
[[nodiscard]] std::string BuildProofMessage(const Session& session, std::string_view nonce_base64) {
    const auto nonce = crypto::base64_decode(nonce_base64);
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
    if (auto json = glz::write_json(ProofMessage{.signature = crypto::base64_encode(*signature)}); json.has_value()) {
        return *json;
    }
    return {};
}

// Launches hawk-capture in the logged-on user's session and forwards every
// packet it produces to the relay, sealed for the machine's viewers. With
// the clipboard allowed, what hawk-capture reads off it goes to the viewers
// that asked (or, in sync mode, everyone who may read it).
void StartCapture(net::WebSocketClient& client, svc::CaptureHost& capture, svc::ViewerHub& hub,
                  const svc::ClipboardConfig& clipboard) {
    if (capture.is_running()) {
        spdlog::info("relay: start_capture ignored, capture already running");
        return;
    }

    const svc::CaptureOptions options{.clipboard = clipboard.mode != svc::ClipboardMode::off,
                                      .clipboard_listen = clipboard.mode == svc::ClipboardMode::sync};
    auto on_clipboard = [&hub](ipc::ClipboardKind kind, std::string_view text) {
        hub.deliver_clipboard(text, kind == ipc::ClipboardKind::changed);
    };
    auto started = capture.start([&client, &hub](const svc::CapturePacket& packet) {
        // Frames come steadily, so this is where shares that ran out are
        // noticed and their viewers cut off.
        hub.check_expiry();
        const auto frame = hub.seal_frame(packet.data, packet.is_keyframe, packet.timestamp);
        if (frame.empty()) {
            return;
        }
        if (auto sent = client.send_binary(frame); !sent.has_value()) {
            spdlog::warn("relay: failed to forward video packet: {}", net::to_string(sent.error()));
        }
    }, options, on_clipboard);
    if (!started.has_value()) {
        spdlog::error("relay: failed to start capture: {}", svc::to_string(started.error()));
    }
}

// Hands input to hawk-capture, which replays it in the user's session.
// Whether it landed is CaptureHost's business to log: one lost input event
// is never worth more than a line in the log.
void ForwardInput(svc::CaptureHost& capture, const ipc::InputPacket& packet) {
    if (capture.is_running()) {
        static_cast<void>(capture.send_input(packet));
    }
}

// The relay accepted this connection's enrollment: check the owner key it
// names against the enrollment code, pin it, then make the new key and
// machine id this PC's identity and retire what it had before. Returns
// false if the owner key doesn't check out, leaving everything as it was.
bool CompleteEnrollment(Session& session, const RelayCommand& command) {
    const auto& machine_id = command.machine_id;
    const auto  owner_key = crypto::base64_decode(command.owner_key);
    const auto  owner_binding = crypto::base64_decode(command.owner_binding);
    if (!session.enroll_code.has_value() || !owner_key.has_value() || !owner_binding.has_value() ||
        !crypto::is_public_key(*owner_key) ||
        !crypto::equal(svc::enroll_binding(*session.enroll_code, "hawk-enroll-owner-v1", *owner_key),
                       *owner_binding)) {
        // Whoever answered doesn't know the code: not the owner who made it.
        spdlog::error("relay: the owner key the relay sent doesn't match the enrollment code; refusing to enroll. "
                      "Remove the machine in the dashboard and enroll it again with a new code");
        return false;
    }
    if (!svc::save_owner_key(*owner_key)) {
        spdlog::error("relay: couldn't save the owner's key; enroll this machine again");
        return false;
    }
    const auto previous = svc::load_machine_identity();
    if (!svc::save_machine_identity({.machine_id = machine_id, .key_name = session.key_name})) {
        spdlog::error("relay: enrolled as machine {}, but couldn't save that; remove the machine in the dashboard "
                      "and enroll it again",
                      machine_id);
        return false;
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
    spdlog::info("relay: enrolled as machine {} ({} key); owner key {}", machine_id, session.key.storage(),
                 svc::fingerprint(*owner_key));
    return true;
}

// Everything one relay connection works with.
struct Connection {
    net::WebSocketClient&                client;
    svc::CaptureHost&                    capture;
    Session&                             session;
    std::unique_ptr<svc::ViewerHub>&     hub;
    std::unique_ptr<svc::FileTransfers>& files;
    std::unique_ptr<svc::ShellSessions>& shells;
    const svc::MachineConfig&            config;
    svc::Updater&                        updater;
};

// The connection's viewers, once the machine knows its id.
void OpenViewerHub(Connection& connection) {
    if (connection.hub != nullptr || !connection.session.machine_id.has_value()) {
        return;
    }
    auto owner_key = svc::load_owner_key();
    if (!owner_key.has_value()) {
        spdlog::warn("relay: no owner key pinned; viewers are refused until this machine is enrolled again");
    }
    auto& client = connection.client;
    connection.hub = std::make_unique<svc::ViewerHub>(
        connection.session.key, *connection.session.machine_id, std::move(owner_key), connection.config,
        [&client](const std::string& text) {
            if (text.empty()) {
                return;
            }
            if (auto sent = client.send_text(text); !sent.has_value()) {
                spdlog::warn("relay: failed to answer a viewer: {}", net::to_string(sent.error()));
            }
        });
    if (connection.config.files.enabled) {
        connection.files = std::make_unique<svc::FileTransfers>(connection.config.files, *connection.hub);
    }
    if (connection.config.shell.enabled) {
        connection.shells = std::make_unique<svc::ShellSessions>(connection.config.shell, *connection.hub);
    }
}

void HandleRelayCommand(std::string_view text, Connection& connection) {
    RelayCommand command;
    if (auto error = glz::read<glz::opts{.error_on_unknown_keys = false}>(command, text); error) {
        spdlog::warn("relay: received unparseable message: {}", text);
        return;
    }
    auto& [client, capture, session, hub, files, shells, config, updater] = connection;

    if (command.type == "challenge") {
        if (auto sent = client.send_text(BuildProofMessage(session, command.nonce)); !sent.has_value()) {
            spdlog::warn("relay: failed to send key proof: {}", net::to_string(sent.error()));
        }
    } else if (command.type == "enrolled") {
        if (CompleteEnrollment(session, command)) {
            WriteStatus("enrolled", session.machine_id.value_or(""));
            OpenViewerHub(connection);
        } else {
            WriteStatus("rejected", "the owner key didn't match the enrollment code");
        }
    } else if (command.type == "install_update") {
        // Only the owner's dashboard can send this, and hawk-setup checks
        // the release's signature whoever asked.
        updater.install_now();
    } else if (hub == nullptr) {
        // Not enrolled, or the owner key didn't check out: nothing to serve.
        spdlog::debug("relay: ignoring \"{}\" before enrollment", command.type);
    } else if (command.type == "start_capture") {
        StartCapture(client, capture, *hub, config.clipboard);
    } else if (command.type == "stop_capture") {
        capture.stop();
    } else if (command.type == "viewer_join") {
        hub->join(command.viewer, {.statement = command.statement, .signature = command.signature}, command.grant);
    } else if (command.type == "viewer_left") {
        // It may have keys or buttons held down: let go of them.
        for (const auto& release : hub->leave(command.viewer)) {
            ForwardInput(capture, release);
        }
        if (files != nullptr) {
            files->drop_viewer(command.viewer);
        }
        if (shells != nullptr) {
            shells->drop_viewer(command.viewer);
        }
    } else if (command.type == "input") {
        if (const auto packet = hub->input(command.viewer, command.sealed); packet.has_value()) {
            ForwardInput(capture, *packet);
        }
    } else if (command.type == "clipboard") {
        if (const auto request = hub->clipboard(command.viewer, command.sealed); request.has_value()) {
            const auto kind = request->op == svc::ClipboardRequest::Op::set ? ipc::ClipboardKind::set
                                                                             : ipc::ClipboardKind::get;
            if (!capture.is_running() || !capture.send_clipboard(kind, request->text)) {
                spdlog::info("relay: the clipboard request from viewer {} couldn't reach hawk-capture",
                             command.viewer);
            }
        }
    } else if (command.type == "file") {
        if (auto message = hub->file(command.viewer, command.sealed); message.has_value() && files != nullptr) {
            files->handle(command.viewer, std::move(*message));
        }
    } else if (command.type == "shell") {
        if (auto message = hub->shell(command.viewer, command.sealed); message.has_value() && shells != nullptr) {
            shells->handle(command.viewer, std::move(*message));
        }
    } else if (command.type == "revocations") {
        hub->apply_revocations(command.revocations);
    } else {
        spdlog::info("relay: ignoring unknown command \"{}\"", command.type);
    }
}

// Handles one received message. Returns the close code once the relay has
// closed the connection, nullopt while it stays open.
[[nodiscard]] std::optional<std::uint16_t> HandleRelayMessage(const net::WebSocketMessage& message,
                                                              Connection& connection) {
    return std::visit(
        [&]<typename T>(const T& payload) -> std::optional<std::uint16_t> {
            if constexpr (std::is_same_v<T, std::string>) {
                HandleRelayCommand(payload, connection);
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

void SendUpdateStatus(net::WebSocketClient& client, const std::optional<std::string>& available) {
    if (auto json = glz::write_json(UpdateStatusMessage{.available = available}); json.has_value()) {
        static_cast<void>(client.send_text(*json));
    }
}

void RelayLoop(const std::stop_token& stop_token, std::atomic<net::WebSocketClient*>& active_client,
               const svc::MachineConfig& config, svc::Updater& updater) {
    net::WebSocketClient client;
    // Declared after `client` so it's destroyed (stopped) first: its reader
    // thread sends through `client`.
    svc::CaptureHost capture;

    const std::string& relay_url = config.relay.url;
    if (relay_url.empty()) {
        WriteStatus("misconfigured", "no relay address");
        spdlog::error("relay: no relay to connect to; set [[relay]] url in the config, or run hawk-setup again");
        return;
    }

    bool warned_not_enrolled = false;
    bool warned_unpinned = false;
    while (!stop_token.stop_requested()) {
        auto session = PrepareSession();
        if (!session.has_value()) {
            if (session.error() == SessionProblem::not_enrolled && !warned_not_enrolled) {
                WriteStatus("not_enrolled");
                spdlog::warn("relay: this machine isn't enrolled. Create an enrollment code in the dashboard "
                             "(Machines > Add machine) and run hawk-setup again with it");
                warned_not_enrolled = true;
            }
            SleepUnlessStopped(stop_token, kRejectedRetryDelay);
            continue;
        }
        warned_not_enrolled = false;

        net::WebSocketClient::ConnectOptions options;
        options.pinned_keys = svc::load_relay_pins();
        if (options.pinned_keys.empty() && !warned_unpinned) {
            spdlog::warn("relay: no relay key pinned; only the certificate chain is checked. Run hawk-setup "
                         "again with the relay's pin (shown with the enrollment code) to pin it");
            warned_unpinned = true;
        }

        WriteStatus("connecting", relay_url);
        if (auto connected = client.connect(relay_url, options); !connected.has_value()) {
            DiscardFailedEnrollment(session);  // a fresh key is made next attempt
            if (connected.error().code == net::WebSocketError::Code::pin_mismatch) {
                // Either the relay's key changed or someone is in the middle:
                // either way, nothing is sent until a pinned key shows up.
                WriteStatus("pin_mismatch", connected.error().message);
                spdlog::error("relay: refusing {}: {}. If the relay's TLS key really changed, run hawk-setup "
                              "again with the new pin",
                              relay_url, connected.error().message);
                SleepUnlessStopped(stop_token, kRejectedRetryDelay);
            } else {
                WriteStatus("unreachable", net::to_string(connected.error()));
                spdlog::error("relay: connect failed: {}", net::to_string(connected.error()));
                SleepUnlessStopped(stop_token, kReconnectDelay);
            }
            continue;
        }

        spdlog::info("relay: connected to {}", relay_url);
        active_client.store(&client);
        // For the owner to compare with the dashboard when verifying the
        // machine from a browser that didn't make its enrollment code.
        if (auto public_key = session->key.public_key(); public_key.has_value()) {
            spdlog::info("relay: machine key fingerprint {}", svc::fingerprint(*public_key));
        }

        if (auto sent = client.send_text(BuildHelloMessage(*session)); !sent.has_value()) {
            spdlog::warn("relay: failed to send hello message: {}", net::to_string(sent.error()));
        }

        std::unique_ptr<svc::ViewerHub>     hub;
        std::unique_ptr<svc::FileTransfers> files;
        std::unique_ptr<svc::ShellSessions> shells;
        Connection                          connection{.client = client,
                                                       .capture = capture,
                                                       .session = *session,
                                                       .hub = hub,
                                                       .files = files,
                                                       .shells = shells,
                                                       .config = config,
                                                       .updater = updater};
        OpenViewerHub(connection);
        if (session->machine_id.has_value()) {
            WriteStatus("connected", *session->machine_id);
        }
        if (auto available = updater.available(); available.has_value()) {
            SendUpdateStatus(client, available);
        }

        std::optional<std::uint16_t> close_code;
        while (!stop_token.stop_requested()) {
            auto message = client.receive();
            if (!message.has_value()) {
                spdlog::warn("relay: receive failed: {}", net::to_string(message.error()));
                break;
            }
            close_code = HandleRelayMessage(*message, connection);
            if (close_code.has_value()) {
                break;
            }
        }

        // Capture only runs on behalf of a viewer reached through this
        // connection; stop it before the socket it forwards to goes away,
        // and before the viewers it seals frames for.
        capture.stop();
        files.reset();  // these answer through the hub
        shells.reset();
        hub.reset();
        active_client.store(nullptr);
        client.close();

        // An enrollment that didn't go through leaves no key behind.
        const bool enrollment_failed = DiscardFailedEnrollment(session);

        if (close_code == kPolicyViolationCode && enrollment_failed) {
            // A wrong or expired code never becomes right; stop retrying it.
            svc::delete_enroll_code();
            WriteStatus("rejected", "the enrollment code was wrong, expired or already used");
            spdlog::error("relay: the enrollment code was rejected (wrong, expired or already used). Create a new "
                          "one in the dashboard and run hawk-setup again with it");
            SleepUnlessStopped(stop_token, kRejectedRetryDelay);
        } else if (close_code == kPolicyViolationCode) {
            WriteStatus("refused", "removed, owner disabled, or the key proof failed");
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

[[nodiscard]] std::string_view to_string(svc::ClipboardMode mode) {
    switch (mode) {
        case svc::ClipboardMode::off:
            return "off";
        case svc::ClipboardMode::pull:
            return "pull";
        case svc::ClipboardMode::sync:
            return "sync";
    }
    return "unknown";
}

void WINAPI ServiceMain([[maybe_unused]] DWORD argc, [[maybe_unused]] LPWSTR* argv) {
    InitLogging();
    spdlog::info("service: hawk-service {} starting", internal::version::full_version);
    const svc::MachineConfig config = svc::load_machine_config();
    spdlog::info("config: clipboard {}{}", to_string(config.clipboard.mode),
                 config.clipboard.view_pull ? ", view shares may read it" : "");
    spdlog::info("config: file transfer {}", config.files.enabled ? "on" : "off");
    spdlog::info("config: shell {}", config.shell.enabled ? std::format("on (\"{}\")", config.shell.command) : "off");

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

    // Tells the owner's dashboards about an update waiting for them, through
    // whichever connection is up.
    svc::Updater updater(config.update, [&service](const std::optional<std::string>& available) {
        if (net::WebSocketClient* client = service.active_client.load(); client != nullptr) {
            SendUpdateStatus(*client, available);
        }
    });

    std::jthread relay_thread([&service, &config, &updater] {
        RelayLoop(service.stop_source.get_token(), service.active_client, config, updater);
    });

    WaitForSingleObject(service.stop_event, INFINITE);
    relay_thread.join();

    spdlog::info("service: stopped");
    spdlog::shutdown();

    service.status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(service.status_handle, &service.status);
}

// Forgets this machine: deletes its key (from the TPM or the software key
// store) and everything it pinned, so a reinstall starts over. For
// hawk-setup's uninstall, run as an administrator with the service stopped.
// Returns the process exit code.
int RemoveIdentity() {
    int result = 0;
    if (auto identity = svc::load_machine_identity(); identity.has_value()) {
        if (auto destroyed = svc::MachineKey::destroy(identity->key_name); !destroyed.has_value()) {
            std::fprintf(stderr, "couldn't delete the machine key: %s\n", destroyed.error().c_str());
            result = 1;
        }
    }
    static constexpr std::array kFiles{L"machine.txt",    L"owner-key.txt",  L"access-state.txt", L"enroll-code.txt",
                                       L"relay-pins.txt", L"credential.bin", L"status.json"};
    const std::filesystem::path data = R"(C:\ProgramData\HawkService)";
    for (const auto* file : kFiles) {
        std::error_code ignored;
        std::filesystem::remove(data / file, ignored);
    }
    return result;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    const std::span<wchar_t*> args(argv, static_cast<std::size_t>(argc));
    if (args.size() > 1) {
        const std::wstring_view command = args[1];
        if (command == L"--version") {
            std::printf("hawk-service %s (protocol %u)\n", std::string(internal::version::full_version).c_str(),
                        kProtocolVersion);
            return 0;
        }
        if (command == L"--remove-identity") {
            return RemoveIdentity();
        }
        std::fprintf(stderr,
                     "hawk-service runs as a Windows service; install it with hawk-setup.\n"
                     "  --version            print the version\n"
                     "  --remove-identity    delete this machine's key and enrollment\n");
        return 2;
    }

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
