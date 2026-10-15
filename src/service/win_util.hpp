#pragma once

#include <windows.h>
#include <aclapi.h>
#include <wtsapi32.h>

#include <array>
#include <expected>
#include <filesystem>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

// Small Win32 helpers shared by the parts of the service that act for the
// logged-on user (file transfer, shells), and by those that read its own
// settings and keys.
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

// Enables one privilege on this process's token. SYSTEM holds the ones the
// service needs but Windows leaves them disabled until asked.
[[nodiscard]] inline bool enable_privilege(const wchar_t* name) {
    HANDLE raw = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &raw) == FALSE) {
        return false;
    }
    const UniqueHandle token(raw);
    LUID               luid{};
    if (LookupPrivilegeValueW(nullptr, name, &luid) == FALSE) {
        return false;
    }
    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (AdjustTokenPrivileges(token.get(), FALSE, &privileges, 0, nullptr, nullptr) == FALSE) {
        return false;
    }
    return GetLastError() == ERROR_SUCCESS;  // ERROR_NOT_ALL_ASSIGNED comes back here, not as a failure
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

// Reads one of the service's settings or key files, nullopt when there's
// none. Refused unless SYSTEM or the administrators own it and it isn't a
// link: ProgramData lets any user create files in a folder until it's
// locked down, and whoever owns a file can change who may write to it.
// Checked on the handle it's read from, so what's read is what was checked.
[[nodiscard]] inline std::expected<std::optional<std::string>, std::string> read_protected_file(
    const std::filesystem::path& path) {
    const UniqueHandle file(CreateFileW(path.c_str(), GENERIC_READ | READ_CONTROL,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (!file) {
        const DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            return std::nullopt;
        }
        return std::unexpected(std::format("can't open it (error {})", error));
    }

    BY_HANDLE_FILE_INFORMATION info{};
    if (GetFileInformationByHandle(file.get(), &info) == FALSE) {
        return std::unexpected(std::format("can't read its attributes (error {})", GetLastError()));
    }
    if ((info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0) {
        return std::unexpected(std::string("it's a link or a folder"));
    }

    PSID                 owner = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD          result = GetSecurityInfo(file.get(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner, nullptr,
                                                  nullptr, nullptr, &descriptor);
    if (result != ERROR_SUCCESS) {
        return std::unexpected(std::format("can't read who owns it (error {})", result));
    }
    const bool trusted = IsWellKnownSid(owner, WinLocalSystemSid) != FALSE ||
                         IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != FALSE;
    LocalFree(descriptor);
    if (!trusted) {
        return std::unexpected(std::string("it isn't owned by SYSTEM or the administrators"));
    }

    constexpr std::size_t        kChunk = 16384;
    std::string                  contents;
    std::array<char, kChunk>     buffer{};
    for (;;) {
        DWORD read = 0;
        if (ReadFile(file.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr) == FALSE) {
            return std::unexpected(std::format("can't read it (error {})", GetLastError()));
        }
        if (read == 0) {
            return contents;
        }
        contents.append(buffer.data(), read);
    }
}

}  // namespace hawk::service::win
