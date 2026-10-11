#pragma once

#include <windows.h>
#include <wtsapi32.h>

#include <optional>
#include <string>
#include <string_view>
#include <utility>

// Small Win32 helpers shared by the parts of the service that act for the
// logged-on user (file transfer, shells).
namespace hawk::service::win {

// Owns a kernel HANDLE. Treats both nullptr and INVALID_HANDLE_VALUE as
// empty, since Win32 APIs disagree on which one signals failure.
class UniqueHandle {
public:
    UniqueHandle() = default;
    explicit UniqueHandle(HANDLE handle) noexcept : handle_(handle) {}
    ~UniqueHandle() { reset(); }
    UniqueHandle(UniqueHandle&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            reset(std::exchange(other.handle_, nullptr));
        }
        return *this;
    }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    [[nodiscard]] HANDLE get() const noexcept { return handle_; }
    [[nodiscard]] explicit operator bool() const noexcept {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }
    void reset(HANDLE handle = nullptr) noexcept {
        if (*this) {
            CloseHandle(handle_);
        }
        handle_ = handle;
    }
    [[nodiscard]] HANDLE release() noexcept { return std::exchange(handle_, nullptr); }

private:
    HANDLE handle_ = nullptr;
};

// Runs the calling thread as the logged-on user until destroyed. Handles
// opened meanwhile keep the access they were opened with afterwards.
class Impersonation {
public:
    explicit Impersonation(HANDLE token) : ok_(ImpersonateLoggedOnUser(token) != FALSE) {}
    ~Impersonation() {
        if (ok_) {
            RevertToSelf();
        }
    }
    Impersonation(const Impersonation&) = delete;
    Impersonation& operator=(const Impersonation&) = delete;
    Impersonation(Impersonation&&) = delete;
    Impersonation& operator=(Impersonation&&) = delete;

    [[nodiscard]] bool ok() const noexcept { return ok_; }

private:
    bool ok_;
};

// The token of whoever is logged on to the console session; empty when
// nobody is. Everything done for a viewer on the machine runs under it,
// never under the service's own SYSTEM token.
[[nodiscard]] inline UniqueHandle user_token() {
    HANDLE      token = nullptr;
    const DWORD session = WTSGetActiveConsoleSessionId();
    if (session == 0xFFFFFFFF || WTSQueryUserToken(session, &token) == FALSE) {
        return {};
    }
    return UniqueHandle(token);
}

// nullopt for text that isn't UTF-8.
[[nodiscard]] inline std::optional<std::wstring> to_wide(std::string_view text) {
    if (text.empty()) {
        return std::wstring{};
    }
    const int length =
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (length <= 0) {
        return std::nullopt;
    }
    std::wstring wide(static_cast<std::size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), wide.data(), length);
    return wide;
}

[[nodiscard]] inline std::string to_utf8(std::wstring_view text) {
    if (text.empty()) {
        return {};
    }
    const int length =
        WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string utf8(static_cast<std::size_t>(length > 0 ? length : 0), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), utf8.data(), length, nullptr, nullptr);
    return utf8;
}

}  // namespace hawk::service::win
