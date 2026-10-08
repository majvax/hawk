#pragma once

#include <windows.h>

namespace hawk::capture {

// Follows the session's *input desktop* — the one the user's keyboard and
// mouse are attached to right now. That's the normal "Default" desktop most
// of the time, but Windows switches to the "Winlogon" secure desktop for the
// UAC consent prompt, the lock screen and Ctrl+Alt+Del. DXGI Desktop
// Duplication and SendInput both act on the desktop the calling thread is
// attached to, so a thread that captures or injects has to move with the
// switch or it ends up working on a desktop nobody is looking at.
//
// Reaching the secure desktop at all needs a SYSTEM process: that desktop's
// DACL admits only SYSTEM, which is why hawk-service launches hawk-capture
// with a LocalSystem token (see service/capture_host.cpp). For an ordinary
// user process OpenInputDesktop on the secure desktop is denied, and this
// simply reports failure and leaves the thread where it is.
//
// `held` is the desktop this thread is currently attached to; the caller
// keeps it between calls and starts it at nullptr. It's updated in place and
// must be closed with CloseDesktop when the thread is done (close_desktop).
// A thread can't be moved off a desktop that's then closed, so the previous
// handle is released only after the switch succeeds.
//
// Returns true if the thread is on the current input desktop afterwards,
// false if it couldn't be reached (and the thread is left as it was).
[[nodiscard]] bool follow_input_desktop(HDESK& held);

// Releases a handle taken by follow_input_desktop. Safe on nullptr.
void close_desktop(HDESK& held) noexcept;

}  // namespace hawk::capture
