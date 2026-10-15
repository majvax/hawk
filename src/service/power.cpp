#include "power.hpp"

#include "win_util.hpp"

#include <windows.h>
#include <reason.h>
#include <wtsapi32.h>

#include <format>

namespace hawk::service {

namespace {

constexpr DWORD kNoConsoleSession = 0xFFFFFFFF;

// The console session, if someone is signed in to it.
[[nodiscard]] std::expected<DWORD, std::string> signed_in_console() {
    const DWORD session = WTSGetActiveConsoleSessionId();
    if (session == kNoConsoleSession || !win::user_token()) {
        return std::unexpected(std::string("nobody is signed in to the machine"));
    }
    return session;
}

[[nodiscard]] std::expected<void, std::string> shut_down(bool restart) {
    if (!win::enable_privilege(SE_SHUTDOWN_NAME)) {
        return std::unexpected(std::format("can't enable SeShutdownPrivilege (error {})", GetLastError()));
    }
    // Forced: the point is a machine nobody is sitting at, where an app
    // asking to save its work would hold the restart up indefinitely.
    const DWORD flags = SHUTDOWN_FORCE_OTHERS | SHUTDOWN_FORCE_SELF | (restart ? SHUTDOWN_RESTART : SHUTDOWN_POWEROFF);
    const DWORD result = InitiateShutdownW(nullptr, nullptr, 0, flags,
                                           SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_FLAG_PLANNED);
    if (result != ERROR_SUCCESS) {
        return std::unexpected(std::format("InitiateShutdownW failed (error {})", result));
    }
    return {};
}

}  // namespace

std::optional<PowerAction> to_power_action(std::uint8_t value) noexcept {
    switch (value) {
        case static_cast<std::uint8_t>(PowerAction::lock):
        case static_cast<std::uint8_t>(PowerAction::sign_out):
        case static_cast<std::uint8_t>(PowerAction::restart):
        case static_cast<std::uint8_t>(PowerAction::shut_down):
            return static_cast<PowerAction>(value);
        default:
            return std::nullopt;
    }
}

std::string_view to_string(PowerAction action) noexcept {
    switch (action) {
        case PowerAction::lock:
            return "lock";
        case PowerAction::sign_out:
            return "sign out";
        case PowerAction::restart:
            return "restart";
        case PowerAction::shut_down:
            return "shut down";
    }
    return "unknown";
}

std::expected<void, std::string> perform(PowerAction action) {
    switch (action) {
        case PowerAction::lock: {
            // Disconnecting the console session puts the sign-in screen up
            // and keeps the user's session, apps and all, for when they
            // sign back in: what Lock does, from outside the session.
            auto session = signed_in_console();
            if (!session.has_value()) {
                return std::unexpected(session.error());
            }
            if (WTSDisconnectSession(WTS_CURRENT_SERVER_HANDLE, *session, FALSE) == FALSE) {
                return std::unexpected(std::format("WTSDisconnectSession failed (error {})", GetLastError()));
            }
            return {};
        }
        case PowerAction::sign_out: {
            auto session = signed_in_console();
            if (!session.has_value()) {
                return std::unexpected(session.error());
            }
            if (WTSLogoffSession(WTS_CURRENT_SERVER_HANDLE, *session, FALSE) == FALSE) {
                return std::unexpected(std::format("WTSLogoffSession failed (error {})", GetLastError()));
            }
            return {};
        }
        case PowerAction::restart:
            return shut_down(true);
        case PowerAction::shut_down:
            return shut_down(false);
    }
    return std::unexpected(std::string("unknown power action"));
}

}  // namespace hawk::service
