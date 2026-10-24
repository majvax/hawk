#pragma once

#include <expected>
#include <string>

// Ctrl+Alt+Del for a viewer with control. It's the secure attention
// sequence, which Winlogon only takes from the keyboard driver or from
// SendSAS: a key press through SendInput never reaches it. So the request
// arrives sealed (ViewerHub::sas) and the service asks Windows itself, as
// LocalSystem.
namespace hawk::service {

// Presses Ctrl+Alt+Del on the console: the sign-in prompt behind the lock
// screen (where Windows asks for it before signing in), or the security
// options while someone is signed in. hawk-capture follows the input
// desktop, so the view shows either. Fails, saying what to change, when
// Windows' policy doesn't let services send it.
[[nodiscard]] std::expected<void, std::string> send_sas();

}  // namespace hawk::service
