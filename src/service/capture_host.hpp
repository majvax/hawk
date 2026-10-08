#pragma once

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
        no_user_session,
        pipe_failed,
        launch_failed,
    };

    Code          code;
    std::uint32_t native_code = 0;  // underlying Win32 error, if any
    std::string   message;
};

[[nodiscard]] std::string_view to_string(CaptureHostError::Code code) noexcept;
[[nodiscard]] std::string      to_string(const CaptureHostError& error);

// One H.264 access unit (Annex B) received from hawk-capture. `data` is only
// valid for the duration of the PacketHandler call.
struct CapturePacket {
    std::span<const std::byte> data;
    bool                       is_keyframe = false;
    std::chrono::microseconds  timestamp{0};
};

// Runs hawk-capture.exe inside the active console session and receives its
// encoded packets over a private named pipe.
//
// A Session 0 service can't see the desktop, so the capture has to run as
// the logged-on user: start() takes that user's token (WTSQueryUserToken,
// which requires running as SYSTEM) and launches hawk-capture.exe from the
// service's own directory with CreateProcessAsUser.
//
// Like WebSocketClient, no Windows type crosses this interface.
//
// Thread-safety: start(), stop() and send_input() must all be called from
// the same thread. The PacketHandler runs on an internal reader thread.
class CaptureHost {
public:
    using PacketHandler = std::function<void(const CapturePacket&)>;

    CaptureHost();
    ~CaptureHost();

    CaptureHost(const CaptureHost&) = delete;
    CaptureHost& operator=(const CaptureHost&) = delete;
    CaptureHost(CaptureHost&&) = delete;
    CaptureHost& operator=(CaptureHost&&) = delete;

    [[nodiscard]] std::expected<void, CaptureHostError> start(PacketHandler on_packet);

    // Sends one input event to hawk-capture, which replays it into the
    // session with SendInput. Returns false when capture isn't running, or
    // the control pipe is gone (the reason is logged); input is best-effort,
    // so callers have nothing to do about that but carry on. Blocks for at
    // most a couple of seconds, and only once per run: a pipe that fails is
    // closed until capture restarts.
    [[nodiscard]] bool send_input(const ipc::InputPacket& packet);

    // Stops the reader thread and hawk-capture. Once it returns, the
    // PacketHandler is never called again. Safe to call when not running.
    void stop() noexcept;

    // False once stopped, or once hawk-capture exits or breaks the pipe on
    // its own (stop() must still be called to clean up in that case).
    [[nodiscard]] bool is_running() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace hawk::service
