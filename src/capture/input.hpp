#pragma once

#include "duplication.hpp"  // DesktopBounds

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace hawk::capture {

// What hawk-service asked the stream to be encoded at.
struct EncoderRequest {
    std::uint32_t bitrate_bps = 0;
    std::uint32_t fps = 0;
};

// Receives input events from hawk-service over the control pipe (see
// common/input_pipe.hpp) and replays them into this session with SendInput.
//
// Reading happens on its own thread: an event is injected the moment it
// arrives, and the capture loop's frame clock never waits on one.
//
// The same pipe carries the stream's encoder settings (ipc::InputKind::
// encoder), which the capture loop picks up with take_encoder_request().
//
// Whatever input is holding down is released when the channel closes — the
// viewer stopping, hawk-service closing the pipe, or this process exiting
// all lead there — so a key can never stay stuck down on the machine.
//
// hawk-capture runs as LocalSystem inside the interactive session, so its
// injected input is at System integrity and reaches elevated windows (no
// uiAccess needed), and the reader thread follows the input desktop (see
// desktop.hpp) so input also reaches the secure desktop the UAC prompt and
// lock screen live on — the one case ordinary remote tools can't touch.
class InputChannel {
public:
    InputChannel();
    ~InputChannel();

    InputChannel(const InputChannel&) = delete;
    InputChannel& operator=(const InputChannel&) = delete;
    InputChannel(InputChannel&&) = delete;
    InputChannel& operator=(InputChannel&&) = delete;

    // Opens hawk-service's end of the pipe and starts reading. `bounds` is
    // the captured monitor's rectangle, which pointer positions are
    // relative to. Failures are logged; input simply stays unavailable.
    [[nodiscard]] bool open(const std::string& pipe_name, DesktopBounds bounds);

    // Where the captured monitor now sits, after a reacquired duplication
    // found it moved on the virtual desktop. Safe to call from any thread,
    // and when the channel was never opened.
    void set_bounds(DesktopBounds bounds);

    // The encoder settings hawk-service asked for since the last call, the
    // latest one only; nullopt if it asked for none. Safe to call from any
    // thread, and when the channel was never opened.
    [[nodiscard]] std::optional<EncoderRequest> take_encoder_request();

    // Stops reading and releases anything still held. Safe to call when the
    // channel was never opened.
    void close() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace hawk::capture
