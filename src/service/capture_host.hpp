#pragma once

#include "common/clipboard_pipe.hpp"
#include "common/input_pipe.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace hawk::service {

struct CaptureHostError {
    enum class Code : std::uint8_t {
        already_running,
        no_user_session,  // no session is attached to the console
        pipe_failed,
        launch_failed,
    };

    Code          code;
    std::uint32_t native_code = 0;  // underlying Win32 error, if any
    std::string   message;
};

[[nodiscard]] std::string_view to_string(CaptureHostError::Code code) noexcept;
[[nodiscard]] std::string      to_string(const CaptureHostError& error);

// One H.264 access unit (Annex B), or with `is_audio` one Opus packet,
// received from hawk-capture. `data` is only valid for the duration of the
// PacketHandler call.
struct CapturePacket {
    std::span<const std::byte> data;
    bool                       is_keyframe = false;
    bool                       is_audio = false;
    std::chrono::microseconds  timestamp{0};
};

// What hawk-capture is started with besides capture and input.
struct CaptureOptions {
    // Open the clipboard pipe, so viewers can paste and read the clipboard.
    bool clipboard = false;
    // Have hawk-capture report every copy made on the machine (sync mode).
    bool clipboard_listen = false;
    // Capture what the machine plays, too.
    bool audio = false;
    // From this output device (an endpoint id) rather than the default.
    std::wstring audio_device;
};

// Runs hawk-capture.exe inside the active console session and receives its
// encoded packets over a private named pipe.
//
// A Session 0 service can't see the desktop, so the capture has to run
// inside the console session: start() launches hawk-capture.exe from the
// service's own directory with CreateProcessAsUser, as SYSTEM retargeted to
// that session, so it can also capture the secure desktop.
//
// Like WebSocketClient, no Windows type crosses this interface.
//
// Thread-safety: start(), stop(), send_input() and send_clipboard() must
// all be called from the same thread. The PacketHandler and the
// ClipboardHandler each run on an internal reader thread of their own.
class CaptureHost {
public:
    using PacketHandler = std::function<void(const CapturePacket&)>;
    // Clipboard text from hawk-capture: `text` answering a get, or
    // `changed` for a copy made on the machine. Only valid during the call.
    using ClipboardHandler = std::function<void(ipc::ClipboardKind kind, std::string_view text)>;

    CaptureHost();
    ~CaptureHost();

    CaptureHost(const CaptureHost&) = delete;
    CaptureHost& operator=(const CaptureHost&) = delete;
    CaptureHost(CaptureHost&&) = delete;
    CaptureHost& operator=(CaptureHost&&) = delete;

    [[nodiscard]] std::expected<void, CaptureHostError> start(PacketHandler on_packet, CaptureOptions options = {},
                                                              ClipboardHandler on_clipboard = {});

    // Sends one input event to hawk-capture, which replays it into the
    // session with SendInput. Returns false when capture isn't running, or
    // the control pipe is gone (the reason is logged); input is best-effort,
    // so callers have nothing to do about that but carry on. Blocks for at
    // most a couple of seconds, and only once per run: a pipe that fails is
    // closed until capture restarts.
    [[nodiscard]] bool send_input(const ipc::InputPacket& packet);

    // Asks hawk-capture to set (`set`, with `text`) or read (`get`) the
    // clipboard; a read is answered through the ClipboardHandler. Returns
    // false, logged, when the clipboard pipe isn't open or isn't connected
    // yet; like input, it never waits for hawk-capture to start up.
    [[nodiscard]] bool send_clipboard(ipc::ClipboardKind kind, std::string_view text = {});

    // Stops the reader thread and hawk-capture. Once it returns, the
    // PacketHandler is never called again. Safe to call when not running.
    void stop() noexcept;

    // False once stopped, or once hawk-capture exits or breaks the pipe on
    // its own (stop() must still be called to clean up in that case).
    [[nodiscard]] bool is_running() const noexcept;

    // The console session the last start() launched hawk-capture into. The
    // console moves to another session when someone signs out or switches
    // user, and capture has to be started again to follow it.
    [[nodiscard]] std::uint32_t session() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace hawk::service
