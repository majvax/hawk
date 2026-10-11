#pragma once

#include "config.hpp"
#include "e2e.hpp"

#include <cstdint>
#include <memory>

// Shells for viewers whose role allows one (owner and dev): a ConPTY
// running the configured command as the logged-on user, in that user's
// session and environment, never as SYSTEM. Each one runs in a job object
// that kills everything it started once the shell closes.
//
// The messages travel over ViewerHub's shell channel, end-to-end encrypted.
// Each one is an op, a JSON header and (for keystrokes and output) bytes:
//
//   viewer -> machine                    machine -> viewer
//   open   {id, cols, rows}              opened {id}
//   input  {id} + bytes                  output {id, offset} + bytes
//   resize {id, cols, rows}              exited {id, code}
//   ack    {id, received}                error  {id, message}
//   close  {id}
//
// Output is windowed: at most 256 KB of it unacknowledged per shell, and
// the ConPTY isn't read again until the viewer catches up, so a command
// printing without end can't flood the relay or the viewer.
namespace hawk::service {

namespace shell_op {
inline constexpr std::uint8_t open = 1;
inline constexpr std::uint8_t input = 2;
inline constexpr std::uint8_t resize = 3;
inline constexpr std::uint8_t ack = 4;
inline constexpr std::uint8_t close = 5;

inline constexpr std::uint8_t opened = 17;
inline constexpr std::uint8_t output = 18;
inline constexpr std::uint8_t exited = 19;
inline constexpr std::uint8_t error = 20;
}  // namespace shell_op

// Thread-safety: handle() and drop_viewer() may be called from any thread.
// Destroy this before the hub; doing so closes every shell.
class ShellSessions {
public:
    ShellSessions(ShellConfig config, ViewerHub& hub);
    ~ShellSessions();
    ShellSessions(const ShellSessions&) = delete;
    ShellSessions& operator=(const ShellSessions&) = delete;
    ShellSessions(ShellSessions&&) = delete;
    ShellSessions& operator=(ShellSessions&&) = delete;

    // A message the hub opened for this viewer.
    void handle(std::uint64_t viewer, ChannelMessage message);

    // The viewer stopped watching: its shells, and everything they started,
    // are closed.
    void drop_viewer(std::uint64_t viewer);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace hawk::service
