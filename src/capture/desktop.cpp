#include "desktop.hpp"

#include <spdlog/spdlog.h>

#include <array>

namespace hawk::capture {

namespace {

// The desktop's name, for comparing the current input desktop against the
// one this thread already holds. Empty on failure, which just forces a
// (harmless) re-attach.
[[nodiscard]] std::wstring desktop_name(HDESK desktop) {
    if (desktop == nullptr) {
        return {};
    }
    std::array<wchar_t, 256> buffer{};
    DWORD                    needed = 0;
    if (GetUserObjectInformationW(desktop, UOI_NAME, buffer.data(), sizeof(buffer), &needed) == FALSE) {
        return {};
    }
    return std::wstring(buffer.data());
}

}  // namespace

bool follow_input_desktop(HDESK& held) {
    // GENERIC_ALL: duplication needs to read the desktop and injection needs
    // to post input to it. SYSTEM is granted this on the secure desktop; a
    // lesser token is denied, and OpenInputDesktop fails below.
    const HDESK input = OpenInputDesktop(0, FALSE, GENERIC_ALL);
    if (input == nullptr) {
        return false;
    }

    // Already on it: drop the extra handle and keep the one we hold, so a
    // steady desktop doesn't churn a SetThreadDesktop every poll.
    if (held != nullptr && desktop_name(held) == desktop_name(input) && !desktop_name(input).empty()) {
        CloseDesktop(input);
        return true;
    }

    if (SetThreadDesktop(input) == FALSE) {
        // Fails if the thread owns windows or hooks (this one doesn't) or if
        // the switch races the desktop going away; the caller retries.
        spdlog::debug("desktop: SetThreadDesktop failed: Win32 error {}", GetLastError());
        CloseDesktop(input);
        return false;
    }

    // The thread is off the old desktop now, so it's safe to close.
    if (held != nullptr) {
        CloseDesktop(held);
    }
    held = input;
    return true;
}

void close_desktop(HDESK& held) noexcept {
    if (held != nullptr) {
        CloseDesktop(held);
        held = nullptr;
    }
}

}  // namespace hawk::capture
