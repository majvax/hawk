#include "capture_host.hpp"
#include "config.hpp"
#include "config_sync.hpp"
#include "crypto.hpp"
#include "e2e.hpp"
#include "clipboard_images.hpp"
#include "files.hpp"
#include "shell.hpp"
#include "machine_identity.hpp"
#include "machine_key.hpp"
#include "metrics.hpp"
#include "audio_devices.hpp"
#include "power.hpp"
#include "quality.hpp"
#include "sas.hpp"
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
#include <mutex>
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
constexpr std::uint32_t kProtocolVersion = 10;
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

// Tells the relay this machine is about to restart or shut down, so the
// dashboards show it as restarting rather than just gone. Only ever sent
// once Windows has accepted the shutdown.
struct GoingDownMessage {
    std::string type = "going_down";
    bool        restart = false;
};

// The echo of a viewer's ping, for the round trip its stats show. Nothing
// in it is secret, so it isn't sealed.
struct PongMessage {
    std::string   type = "pong";
    std::uint64_t viewer = 0;
    std::string   nonce;
};

// What the stream is encoded at now, for the relay (Auto's controller
// runs there) and the stats of everyone watching. Nothing in it is
// secret: the relay sees about as much from the frames' sizes.
struct QualityMessage {
    std::string   type = "quality";
    std::string   preset;
    std::uint32_t bitrate = 0;
    std::uint32_t fps = 0;
};

// The header of the audio channel's one message: the machine's output
// devices, and which one the stream captures (empty for the default).
struct AudioDeviceEntry {
    std::string id;
    std::string name;
    bool        is_default = false;
};

struct AudioDevicesReply {
    std::vector<AudioDeviceEntry> devices;
    std::string                   selected;
    // Whether sound goes with the stream at all ([[audio]] and the relay).
    bool                          sound = false;
    std::string                   error;
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
    std::string                                  nonce;          // challenge, ping
    std::string                                  machine_id;     // enrolled
    std::string                                  owner_key;      // enrolled: base64 identity key
    std::string                                  owner_binding;  // enrolled: base64 HMAC under the code
    std::uint64_t                                viewer = 0;     // viewer_join, viewer_left, input, clipboard*, file, shell, metrics, audio_*, config_*, quality, sas, ping
    std::string                                  statement;      // viewer_join
    std::string                                  signature;      // viewer_join
    std::optional<svc::SignedStatement>          grant;          // viewer_join
    std::string                                  sealed;         // input, clipboard*, file, shell, metrics, power, audio_*, config_*, quality, sas
    std::vector<svc::SignedStatement>            revocations;    // revocations
    bool                                         audio = false;  // start_capture: the relay passes sound on
    std::uint32_t                                bitrate = 0;    // bitrate: Auto's next step, bits per second
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
struct glz::meta<AudioDeviceEntry> {
    using T                     = AudioDeviceEntry;
    static constexpr auto value = object("id", &T::id, "name", &T::name, "default", &T::is_default);
};

template <>
struct glz::meta<AudioDevicesReply> {
    using T                     = AudioDevicesReply;
    static constexpr auto value =
        object("devices", &T::devices, "selected", &T::selected, "sound", &T::sound, "error", &T::error);
};

template <>
struct glz::meta<GoingDownMessage> {
    using T                     = GoingDownMessage;
    static constexpr auto value = object("type", &T::type, "restart", &T::restart);
};

template <>
struct glz::meta<QualityMessage> {
    using T                     = QualityMessage;
    static constexpr auto value = object("type", &T::type, "preset", &T::preset, "bitrate", &T::bitrate, "fps", &T::fps);
};

template <>
struct glz::meta<PongMessage> {
    using T                     = PongMessage;
    static constexpr auto value = object("type", &T::type, "viewer", &T::viewer, "nonce", &T::nonce);
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
               &T::signature, "grant", &T::grant, "sealed", &T::sealed, "revocations", &T::revocations, "audio",
               &T::audio, "bitrate", &T::bitrate);
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

// What hawk-capture encodes the picture at.
struct Encoding {
    svc::QualityPreset preset = svc::QualityPreset::automatic;
    std::uint32_t      bitrate_bps = 0;
    std::uint32_t      fps = 0;

    bool operator==(const Encoding&) const = default;
};

// Everything one relay connection works with.
struct Connection {
    net::WebSocketClient&                client;
    svc::CaptureHost&                    capture;
    Session&                             session;
    std::unique_ptr<svc::ViewerHub>&     hub;
    std::unique_ptr<svc::FileTransfers>& files;
    std::unique_ptr<svc::ClipboardImages>& images;
    std::unique_ptr<svc::ShellSessions>& shells;
    std::unique_ptr<svc::MetricsChannel>& metrics;
    svc::MetricsRecorder*                recorder;  // null with [[metrics]] off
    // Changed by the owner from the dashboard: what applies live is
    // updated here (ApplyConfig), the rest waits for the next start.
    svc::MachineConfig&                  config;
    svc::Updater&                        updater;
    // A viewer asked for the stream (start_capture) and hasn't stopped it:
    // CaptureSupervisor keeps hawk-capture running until then.
    bool capture_wanted = false;
    // And the machine's sound with it: the relay passes it on, and the
    // config allows it.
    bool capture_audio = false;
    // Whether the relay passes sound on, as it said at start_capture: sound
    // turned on in the config mid-stream goes out only if it does.
    bool relay_audio = false;
    // The output device a viewer chose for this stream (an endpoint id),
    // empty for the default. Forgotten when the stream stops.
    std::string audio_device;
    // The quality preset a viewer with control chose for this stream;
    // without one, the config's. Forgotten when the stream stops.
    std::optional<svc::QualityPreset> quality_choice;
    // Auto's bitrate, as the relay's controller last steered it.
    std::uint32_t auto_bitrate = svc::level(svc::QualityPreset::automatic).bitrate_bps;
    // What hawk-capture was last started with or told, and whether telling
    // it failed (its input pipe wasn't open yet) and should be tried again.
    Encoding encoding;
    bool     encoder_pending = false;
};

// What the stream should be encoded at now.
[[nodiscard]] Encoding CurrentEncoding(const Connection& connection) {
    const auto  preset = connection.quality_choice.value_or(connection.config.stream.quality);
    const auto& level = svc::level(preset);
    const auto  bitrate =
        preset == svc::QualityPreset::automatic ? svc::clamp_auto_bitrate(connection.auto_bitrate) : level.bitrate_bps;
    return {.preset = preset, .bitrate_bps = bitrate, .fps = level.fps};
}

// Tells the relay, and through it everyone watching, what the stream is
// encoded at.
void ReportQuality(net::WebSocketClient& client, const Encoding& encoding) {
    const QualityMessage message{.preset = std::string(svc::to_string(encoding.preset)),
                                 .bitrate = encoding.bitrate_bps,
                                 .fps = encoding.fps};
    if (auto json = glz::write_json(message); json.has_value()) {
        if (auto sent = client.send_text(*json); !sent.has_value()) {
            spdlog::warn("relay: failed to say what the stream is encoded at: {}", net::to_string(sent.error()));
        }
    }
}

// Launches hawk-capture in the console session (the sign-in screen when
// nobody is signed in) and forwards every
// packet it produces to the relay, sealed for the machine's viewers. With
// the clipboard allowed, what hawk-capture reads off it goes to the viewers
// that asked (or, in sync mode, everyone who may read it): text through the
// hub, pictures through ClipboardImages. The stream starts
// at the quality it should have now, which the relay is told.
void StartCapture(Connection& connection) {
    auto&       client = connection.client;
    auto&       capture = connection.capture;
    auto&       hub = *connection.hub;
    const auto& clipboard = connection.config.clipboard;
    const bool  audio = connection.capture_audio;
    const auto& audio_device = connection.audio_device;
    if (capture.is_running()) {
        spdlog::info("relay: start_capture ignored, capture already running");
        return;
    }

    const auto                encoding = CurrentEncoding(connection);
    const svc::CaptureOptions options{.clipboard = clipboard.mode != svc::ClipboardMode::off,
                                      .clipboard_listen = clipboard.mode == svc::ClipboardMode::sync,
                                      .clipboard_images = clipboard.images,
                                      .audio = audio,
                                      // plausible_device_id() let only ASCII through.
                                      .audio_device = std::wstring(audio_device.begin(), audio_device.end()),
                                      .bitrate_bps = encoding.bitrate_bps,
                                      .fps = encoding.fps};
    auto on_clipboard = [&hub, images = connection.images.get()](ipc::ClipboardKind kind, std::string_view payload) {
        if (!ipc::is_image(kind)) {
            hub.deliver_clipboard(payload, kind == ipc::ClipboardKind::changed);
            return;
        }
        const bool pushed = kind == ipc::ClipboardKind::image_changed;
        if (auto viewers = hub.deliver_clipboard_image(pushed); !viewers.empty() && images != nullptr) {
            images->send(std::move(viewers), payload, pushed);
        }
    };
    auto started = capture.start([&client, &hub](const svc::CapturePacket& packet) {
        // Frames come steadily, so this is where shares that ran out are
        // noticed and their viewers cut off.
        hub.check_expiry();
        const auto frame = hub.seal_frame(packet.data, packet.is_keyframe, packet.timestamp, packet.is_audio);
        if (frame.empty()) {
            return;
        }
        if (auto sent = client.send_binary(frame); !sent.has_value()) {
            spdlog::warn("relay: failed to forward video packet: {}", net::to_string(sent.error()));
        }
    }, options, on_clipboard);
    if (!started.has_value()) {
        spdlog::error("relay: failed to start capture: {}", svc::to_string(started.error()));
        return;
    }
    connection.encoding = encoding;
    connection.encoder_pending = false;
    ReportQuality(connection.client, encoding);
}

// Moves the stream to the quality it should have now (a viewer's choice,
// the config's default, Auto's latest step) if it isn't there already, and
// tells the relay. hawk-capture takes it without starting over; one that
// hasn't opened its input pipe yet is told again by CaptureSupervisor.
void ApplyQuality(Connection& connection) {
    const auto encoding = CurrentEncoding(connection);
    const bool changed = encoding != connection.encoding;
    if (connection.capture.is_running() && (changed || connection.encoder_pending)) {
        const ipc::InputPacket packet{.kind = static_cast<std::uint8_t>(ipc::InputKind::encoder),
                                      .bitrate_bps = encoding.bitrate_bps,
                                      .fps = encoding.fps};
        connection.encoder_pending = !connection.capture.send_input(packet);
    }
    if (changed && connection.capture.is_running()) {
        connection.encoding = encoding;
        ReportQuality(connection.client, encoding);
    }
}


// Sends one viewer the machine's output devices, and which one is captured.
void SendAudioDevices(svc::ViewerHub& hub, std::uint64_t viewer, const Connection& connection) {
    AudioDevicesReply reply;
    reply.selected = connection.audio_device;
    reply.sound = connection.capture_audio;
    if (auto devices = svc::list_audio_devices(); devices.has_value()) {
        for (auto& device : *devices) {
            reply.devices.push_back({.id = std::move(device.id), .name = std::move(device.name), .is_default = device.is_default});
        }
    } else {
        spdlog::warn("audio: couldn't list the output devices: {}", devices.error());
        reply.error = devices.error();
    }
    auto header = glz::write_json(reply);
    if (!header.has_value() || !hub.send_audio(viewer, {.op = 0, .header = std::move(*header), .data = {}})) {
        spdlog::info("audio: couldn't send viewer {} the output devices", viewer);
    }
}

// Captures from the output device a viewer chose ("" for the default), by
// starting hawk-capture over with it: the picture pauses for a moment.
// A device that isn't there is refused.
void SelectAudioDevice(Connection& connection, const std::string& id) {
    if (!id.empty()) {
        const auto devices = svc::list_audio_devices();
        const bool present = svc::plausible_device_id(id) && devices.has_value() &&
                             std::ranges::any_of(*devices, [&id](const svc::AudioDevice& device) { return device.id == id; });
        if (!present) {
            spdlog::warn("audio: no output device {}; keeping the current one", id);
            return;
        }
    }
    if (id == connection.audio_device) {
        return;
    }
    connection.audio_device = id;
    if (connection.capture_audio && connection.capture.is_running()) {
        connection.capture.stop();
        StartCapture(connection);
    }
}

// Sends one viewer the machine's config, its schema, and whether it may
// change it; `error` says why a change it asked for wasn't made.
void SendConfig(svc::ViewerHub& hub, std::uint64_t viewer, bool saved = false, std::string_view error = {}) {
    const auto snapshot = svc::read_config_snapshot();
    if (error.empty() && !snapshot.has_value()) {
        error = snapshot.error();
    }
    auto header = svc::config_reply(snapshot.has_value() ? &*snapshot : nullptr, hub.may_change_config(viewer), saved,
                                    error);
    if (!hub.send_config(viewer, {.op = 0, .header = std::move(header), .data = {}})) {
        spdlog::info("config: couldn't send viewer {} the config", viewer);
    }
}

// Takes what a change to the config makes live at once: the clipboard rules,
// whether sound goes with the stream, and its default quality. The first
// two are hawk-capture's options, so a stream that's running starts over
// with them; the quality it takes as it runs, unless a viewer chose one.
// The rest waits for the service to start again.
void ApplyConfig(Connection& connection, const svc::MachineConfig& saved) {
    auto&      config = connection.config;
    const bool restart_capture = saved.clipboard.mode != config.clipboard.mode ||
                                 saved.clipboard.images != config.clipboard.images ||
                                 saved.audio.enabled != config.audio.enabled;
    const bool was_auto = CurrentEncoding(connection).preset == svc::QualityPreset::automatic;
    config.clipboard = saved.clipboard;
    config.audio = saved.audio;
    config.stream = saved.stream;
    // Back on Auto from a fixed preset: it starts over from its start.
    if (!was_auto && CurrentEncoding(connection).preset == svc::QualityPreset::automatic) {
        connection.auto_bitrate = svc::level(svc::QualityPreset::automatic).bitrate_bps;
    }
    connection.hub->set_clipboard(config.clipboard);
    connection.capture_audio = connection.relay_audio && config.audio.enabled;
    if (restart_capture && connection.capture.is_running()) {
        connection.capture.stop();
        StartCapture(connection);
    } else {
        ApplyQuality(connection);
    }
}

// A viewer with control chose a preset for the stream. Auto picks up from
// the bitrate the stream has now.
void ChooseQuality(Connection& connection, svc::QualityPreset preset) {
    if (preset == svc::QualityPreset::automatic && CurrentEncoding(connection).preset != preset) {
        connection.auto_bitrate = svc::clamp_auto_bitrate(CurrentEncoding(connection).bitrate_bps);
    }
    connection.quality_choice = preset;
    ApplyQuality(connection);
}

// Makes the change the owner asked for, if it's still against the file as
// it is and the file's rules allow it, and answers with the config as it
// now stands (or why not).
void ChangeConfig(Connection& connection, std::uint64_t viewer, std::string_view json) {
    auto&      hub = *connection.hub;
    const auto change = svc::parse_config_change(json);
    if (!change.has_value()) {
        SendConfig(hub, viewer, false, "the change couldn't be read");
        return;
    }
    const auto snapshot = svc::read_config_snapshot();
    if (!snapshot.has_value()) {
        SendConfig(hub, viewer);
        return;
    }
    if (change->version != snapshot->version) {
        SendConfig(hub, viewer, false, "the config changed on the machine since you loaded it; here it is as it is now");
        return;
    }
    const auto edited = svc::edit_config_text(snapshot->text, change->changes);
    if (!edited.has_value()) {
        spdlog::info("config: refused viewer {}'s change: {}", viewer, edited.error());
        SendConfig(hub, viewer, false, edited.error());
        return;
    }
    if (const auto saved = svc::save_config_text(*edited); !saved.has_value()) {
        spdlog::error("config: {}", saved.error());
        SendConfig(hub, viewer, false, saved.error());
        return;
    }
    std::string keys;
    for (const auto& [key, value] : change->changes) {
        keys += keys.empty() ? key : ", " + key;
    }
    spdlog::info("config: viewer {} ({}) changed {}", viewer, hub.fingerprint_of(viewer), keys);
    if (const auto written = svc::read_config_snapshot(); written.has_value()) {
        ApplyConfig(connection, written->config);
    }
    SendConfig(hub, viewer, true);
}

// Carries out a power action a viewer asked for, and for a restart or shut
// down tells the relay before the connection drops.
void RunPowerAction(net::WebSocketClient& client, svc::PowerAction action) {
    if (auto done = svc::perform(action); !done.has_value()) {
        spdlog::error("power: couldn't {}: {}", svc::to_string(action), done.error());
        return;
    }
    if (!svc::goes_down(action)) {
        return;
    }
    const GoingDownMessage message{.restart = action == svc::PowerAction::restart};
    if (auto json = glz::write_json(message); json.has_value()) {
        if (auto sent = client.send_text(*json); !sent.has_value()) {
            spdlog::warn("relay: failed to say the machine is going down: {}", net::to_string(sent.error()));
        }
    }
}

// Presses Ctrl+Alt+Del for a viewer, and tells it whether that worked:
// SendSAS itself says nothing, so mostly whether the policy allows it.
void PressCtrlAltDel(svc::ViewerHub& hub, std::uint64_t viewer) {
    const auto done = svc::send_sas();
    if (!done.has_value()) {
        spdlog::warn("sas: couldn't press Ctrl+Alt+Del: {}", done.error());
    }
    hub.send_sas_result(viewer, done.has_value() ? std::string_view{} : std::string_view(done.error()));
}

// The longest nonce echoed back; the dashboard sends a counter.
constexpr std::size_t kMaxPingNonce = 32;

// Echoes a viewer's ping straight back.
void SendPong(net::WebSocketClient& client, std::uint64_t viewer, const std::string& nonce) {
    if (nonce.size() > kMaxPingNonce) {
        return;
    }
    const PongMessage message{.viewer = viewer, .nonce = nonce};
    if (auto json = glz::write_json(message); json.has_value()) {
        if (auto sent = client.send_text(*json); !sent.has_value()) {
            spdlog::debug("relay: failed to answer a ping: {}", net::to_string(sent.error()));
        }
    }
}

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
    // Whatever the config says now: the owner can turn pictures on live.
    connection.images = std::make_unique<svc::ClipboardImages>(*connection.hub);
    if (connection.config.shell.enabled) {
        connection.shells = std::make_unique<svc::ShellSessions>(connection.config.shell, *connection.hub);
    }
    if (connection.recorder != nullptr) {
        connection.metrics = std::make_unique<svc::MetricsChannel>(*connection.recorder, *connection.hub);
    }
}

void HandleRelayCommand(std::string_view text, Connection& connection) {
    RelayCommand command;
    if (auto error = glz::read<glz::opts{.error_on_unknown_keys = false}>(command, text); error) {
        spdlog::warn("relay: received unparseable message: {}", text);
        return;
    }
    auto& [client, capture, session, hub, files, images, shells, metrics, recorder, config, updater, capture_wanted,
           capture_audio, relay_audio, audio_device, quality_choice, auto_bitrate, encoding, encoder_pending] =
        connection;

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
        // A new stream: Auto starts from its start, whatever came before.
        if (!capture.is_running()) {
            auto_bitrate = svc::level(svc::QualityPreset::automatic).bitrate_bps;
        }
        capture_wanted = true;
        // A relay too old to pass sound on doesn't ask for it.
        relay_audio = command.audio;
        capture_audio = relay_audio && config.audio.enabled;
        StartCapture(connection);
    } else if (command.type == "stop_capture") {
        capture_wanted = false;
        audio_device.clear();
        quality_choice.reset();
        auto_bitrate = svc::level(svc::QualityPreset::automatic).bitrate_bps;
        encoding = {};
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
        if (images != nullptr) {
            images->drop_viewer(command.viewer);
        }
        if (shells != nullptr) {
            shells->drop_viewer(command.viewer);
        }
        if (metrics != nullptr) {
            metrics->drop_viewer(command.viewer);
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
    } else if (command.type == "clipboard_image") {
        if (auto message = hub->clipboard_image(command.viewer, command.sealed); message.has_value() && images != nullptr) {
            images->handle(command.viewer, std::move(*message));
        }
    } else if (command.type == "clipboard_image_put") {
        std::string refusal;
        if (const auto message = hub->clipboard_image_put(command.viewer, command.sealed, refusal);
            message.has_value() && images != nullptr) {
            if (!refusal.empty()) {
                images->refuse(command.viewer, *message, refusal);
            } else if (const auto pasted = images->receive(command.viewer, *message); pasted.has_value()) {
                const bool set = capture.is_running() && capture.send_clipboard(ipc::ClipboardKind::set_image, pasted->png);
                images->finished(command.viewer, pasted->id, set ? "" : "the machine's clipboard isn't reachable right now");
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
    } else if (command.type == "metrics") {
        if (auto message = hub->metrics(command.viewer, command.sealed); message.has_value() && metrics != nullptr) {
            metrics->handle(command.viewer, std::move(*message));
        }
    } else if (command.type == "power") {
        if (const auto action = hub->power(command.viewer, command.sealed); action.has_value()) {
            RunPowerAction(client, *action);
        }
    } else if (command.type == "audio_devices") {
        if (hub->audio_devices(command.viewer, command.sealed)) {
            SendAudioDevices(*hub, command.viewer, connection);
        }
    } else if (command.type == "audio_select") {
        if (const auto id = hub->audio_select(command.viewer, command.sealed); id.has_value()) {
            SelectAudioDevice(connection, *id);
            SendAudioDevices(*hub, command.viewer, connection);
        }
    } else if (command.type == "config_get") {
        if (hub->config_get(command.viewer, command.sealed)) {
            SendConfig(*hub, command.viewer);
        }
    } else if (command.type == "config_set") {
        if (const auto json = hub->config_set(command.viewer, command.sealed); json.has_value()) {
            ChangeConfig(connection, command.viewer, *json);
        }
    } else if (command.type == "quality") {
        if (const auto preset = hub->quality(command.viewer, command.sealed); preset.has_value()) {
            ChooseQuality(connection, *preset);
        }
    } else if (command.type == "sas") {
        if (hub->sas(command.viewer, command.sealed)) {
            PressCtrlAltDel(*hub, command.viewer);
        }
    } else if (command.type == "bitrate") {
        // Only ever from the relay, whose controller runs Auto: anything
        // else ignores it, and Auto keeps it in range (quality.hpp).
        // A late one, after the stream stopped, would set where the next
        // stream starts: only a running stream takes it.
        if (command.bitrate != 0 && capture_wanted && capture.is_running() &&
            CurrentEncoding(connection).preset == svc::QualityPreset::automatic) {
            auto_bitrate = svc::clamp_auto_bitrate(command.bitrate);
            ApplyQuality(connection);
        }
    } else if (command.type == "ping") {
        SendPong(client, command.viewer, command.nonce);
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

// How often CaptureSupervisor looks at hawk-capture, and how long it waits
// before relaunching one that keeps failing.
constexpr std::chrono::seconds kCaptureCheckInterval{1};
constexpr std::chrono::seconds kCaptureRetryMax{30};

// Keeps hawk-capture running for as long as a viewer wants the stream.
// Signing in, signing out or switching user moves the console to another
// session or ends the one hawk-capture ran in; this relaunches it there, so
// the view goes from the sign-in screen into the session that opens without
// the viewer doing anything. A helper that keeps failing is retried less
// and less often. Everything it touches is the relay thread's, so it holds
// `lock` while it works, which the relay thread holds around each command.
void CaptureSupervisor(const std::stop_token& stop_token, std::mutex& lock, Connection& connection) {
    auto retry_delay = kCaptureCheckInterval;
    auto next_attempt = std::chrono::steady_clock::now();
    auto started_at = std::chrono::steady_clock::now();
    while (!stop_token.stop_requested()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        const auto now = std::chrono::steady_clock::now();
        const std::scoped_lock guard(lock);
        if (!connection.capture_wanted || connection.hub == nullptr) {
            retry_delay = kCaptureCheckInterval;
            continue;
        }
        const DWORD console = WTSGetActiveConsoleSessionId();
        auto&       capture = connection.capture;
        if (capture.is_running() && capture.session() == console) {
            if (now - started_at > kCaptureRetryMax) {
                retry_delay = kCaptureCheckInterval;  // it ran fine; a later failure starts the backoff over
            }
            if (connection.encoder_pending) {
                ApplyQuality(connection);  // hawk-capture's input pipe wasn't open the last time
            }
            continue;
        }
        if (now < next_attempt) {
            continue;
        }
        if (capture.is_running()) {
            spdlog::info("capture: the console moved to session {}, following it", console);
        } else {
            spdlog::info("capture: hawk-capture isn't running, starting it again");
        }
        capture.stop();
        StartCapture(connection);
        started_at = now;
        next_attempt = now + retry_delay;
        retry_delay = std::min(retry_delay * 2, kCaptureRetryMax);
    }
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
               svc::MachineConfig& config, svc::Updater& updater) {
    net::WebSocketClient client;
    // Declared after `client` so it's destroyed (stopped) first: its reader
    // thread sends through `client`.
    svc::CaptureHost capture;
    // Samples for as long as the service runs, connected or not, so the
    // history has no hole where the relay was unreachable.
    const auto recorder =
        config.metrics.enabled ? std::make_unique<svc::MetricsRecorder>(config.metrics) : nullptr;

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
        std::unique_ptr<svc::ClipboardImages> images;
        std::unique_ptr<svc::ShellSessions> shells;
        std::unique_ptr<svc::MetricsChannel> metrics;
        Connection                          connection{.client = client,
                                                       .capture = capture,
                                                       .session = *session,
                                                       .hub = hub,
                                                       .files = files,
                                                       .images = images,
                                                       .shells = shells,
                                                       .metrics = metrics,
                                                       .recorder = recorder.get(),
                                                       .config = config,
                                                       .updater = updater};
        OpenViewerHub(connection);
        if (session->machine_id.has_value()) {
            WriteStatus("connected", *session->machine_id);
        }
        if (auto available = updater.available(); available.has_value()) {
            SendUpdateStatus(client, available);
        }

        std::mutex   capture_lock;
        std::jthread supervisor([&capture_lock, &connection](const std::stop_token& token) {
            CaptureSupervisor(token, capture_lock, connection);
        });

        std::optional<std::uint16_t> close_code;
        while (!stop_token.stop_requested()) {
            auto message = client.receive();
            if (!message.has_value()) {
                spdlog::warn("relay: receive failed: {}", net::to_string(message.error()));
                break;
            }
            const std::scoped_lock guard(capture_lock);
            close_code = HandleRelayMessage(*message, connection);
            if (close_code.has_value()) {
                break;
            }
        }
        supervisor.request_stop();
        supervisor.join();

        // Capture only runs on behalf of a viewer reached through this
        // connection; stop it before the socket it forwards to goes away,
        // and before the viewers it seals frames for.
        capture.stop();
        files.reset();  // these answer through the hub
        images.reset();
        shells.reset();
        metrics.reset();
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
    svc::MachineConfig config = svc::load_machine_config();
    spdlog::info("config: clipboard {}{}{}", to_string(config.clipboard.mode),
                 config.clipboard.view_pull ? ", view shares may read it" : "",
                 config.clipboard.images ? ", pictures too" : ", text only");
    spdlog::info("config: file transfer {}", config.files.enabled ? "on" : "off");
    spdlog::info("config: shell {}", config.shell.enabled ? std::format("on (\"{}\")", config.shell.command) : "off");
    spdlog::info("config: sound {}", config.audio.enabled ? "on" : "off");
    spdlog::info("config: stream quality {}", svc::to_string(config.stream.quality));

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
