#pragma once

#include "duplication.hpp"  // DesktopBounds

#include <memory>
#include <string>

namespace hawk::capture {

// Receives input events from hawk-service over the control pipe (see
// common/input_pipe.hpp) and replays them into this session with SendInput.
//
// Reading happens on its own thread: an event is injected the moment it
// arrives, and the capture loop's frame clock never waits on one.
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

    // Stops reading and releases anything still held. Safe to call when the
    // channel was never opened.
    void close() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace hawk::capture
