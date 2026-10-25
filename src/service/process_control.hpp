#pragma once

#include <cstdint>
#include <string>
#include <string_view>

// Ending a process from the Processes tab, for a viewer with control, dev
// or the owner's role. The request arrives sealed (ViewerHub::end_process),
// so the relay can neither read nor forge one, and names the process by its
// PID and when it started: a PID Windows has since handed to another
// process is never the one ended.
namespace hawk::service {

// Which process, as the process list gives it (metrics.cpp): `started` is
// its creation time in unix milliseconds.
struct ProcessTarget {
    std::uint32_t pid = 0;
    std::int64_t  started = 0;
};

// Ended, or why not. `name` is the image name whenever it could be read,
// for the viewer's message and the log.
struct EndProcessOutcome {
    bool        ended = false;
    std::string name;
    std::string error;
};

// Ends it with TerminateProcess, unless ending it would stop Windows or
// Hawk: PID 0 and 4, Windows' own (csrss, wininit, smss, lsass, services,
// winlogon, System, Idle and the like), anything Windows marks critical
// (ProcessBreakOnTermination) or protects (protected processes), and Hawk's
// service and capture helper. With `as_user`, the process is opened as the
// signed-in user, so a shared account ends only what that user could end
// in Task Manager; without, as the service (the owner's request).
// Returns as soon as Windows has been told: it doesn't wait for the exit.
[[nodiscard]] EndProcessOutcome end_process(const ProcessTarget& target, bool as_user);

// Whether an image name ("lsass.exe", "System") is one never ended, wherever
// it runs from. Case-insensitive.
[[nodiscard]] bool is_essential_process(std::string_view name) noexcept;

}  // namespace hawk::service
