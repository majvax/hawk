#include "process_control.hpp"

#include "win_util.hpp"

#include <windows.h>
#include <winternl.h>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <filesystem>
#include <format>
#include <optional>
#include <string>

namespace hawk::service {

namespace {

namespace fs = std::filesystem;

// FILETIME counts 100 ns from 1601; the process list sends unix milliseconds.
constexpr std::int64_t kFiletimeUnixEpoch = 116444736000000000LL;

// The idle "process" and System: Windows itself.
constexpr std::uint32_t kIdlePid = 0;
constexpr std::uint32_t kSystemPid = 4;

// Never ended, whoever asks and wherever they run from. Windows bugchecks
// when csrss, wininit, smss or services exits, and lsass or winlogon going
// takes every session down with it; the pseudo-processes (System, Registry,
// Memory Compression, Secure System) and the credential guard's LsaIso are
// the kernel's. svchost hosts services whose recovery action can be a
// restart, dwm draws every window, and fontdrvhost serves the sign-in
// screen's fonts. Hawk's own are refused here too, so the machine never
// cuts off the viewer asking. Matched on the name alone, so a look-alike
// elsewhere on the disk is refused as well, which costs nothing.
constexpr std::array<std::string_view, 19> kEssential{
    "idle",         "system",          "registry",     "memory compression", "secure system", "smss.exe",
    "csrss.exe",    "wininit.exe",     "winlogon.exe", "services.exe",       "lsass.exe",     "lsaiso.exe",
    "lsm.exe",      "svchost.exe",     "dwm.exe",      "fontdrvhost.exe",    "hawk-service.exe",
    "hawk-capture.exe", "hawk-setup.exe",
};

// NtQueryInformationProcess classes, which winternl.h doesn't name.
constexpr auto kProcessBreakOnTermination = static_cast<PROCESSINFOCLASS>(29);
constexpr auto kProcessProtectionInformation = static_cast<PROCESSINFOCLASS>(61);

using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

[[nodiscard]] NtQueryInformationProcessFn query_information_process() {
    static const auto function = reinterpret_cast<NtQueryInformationProcessFn>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess")));
    return function;
}

// One fixed-size fact about a process; nullopt when Windows won't say.
template <typename T>
[[nodiscard]] std::optional<T> query(HANDLE process, PROCESSINFOCLASS what) {
    const auto function = query_information_process();
    T          value{};
    if (function == nullptr || function(process, what, &value, sizeof(value), nullptr) < 0) {
        return std::nullopt;
    }
    return value;
}

[[nodiscard]] std::string lowercase(std::string_view text) {
    std::string lower(text);
    std::ranges::transform(lower, lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return lower;
}

// The folder hawk-service.exe runs from: hawk-capture and the updater's
// copy of hawk-setup live there too.
[[nodiscard]] const fs::path& own_directory() {
    static const fs::path directory = [] {
        std::array<wchar_t, 32768> buffer{};
        const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        return length == 0 ? fs::path{} : fs::path(std::wstring(buffer.data(), length)).parent_path();
    }();
    return directory;
}

// A path in one spelling: long names for 8.3 ones (GetLongPathNameW), no
// "\\?\" prefix, no trailing separator. nullopt when Windows can't say,
// which the caller takes as a reason to refuse.
[[nodiscard]] std::optional<std::wstring> normalise(const fs::path& path) {
    if (path.empty()) {
        return std::nullopt;
    }
    std::wstring               text = path.wstring();
    std::array<wchar_t, 32768> buffer{};
    const DWORD length = GetLongPathNameW(text.c_str(), buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size()) {
        return std::nullopt;
    }
    text.assign(buffer.data(), length);
    if (text.starts_with(LR"(\\?\UNC\)")) {
        text = LR"(\\)" + text.substr(8);
    } else if (text.starts_with(LR"(\\?\)")) {
        text.erase(0, 4);
    }
    while (text.size() > 3 && (text.back() == L'\\' || text.back() == L'/')) {
        text.pop_back();
    }
    return text;
}

// Whether `image` lies in `directory` or a folder under it, compared
// case-insensitively once both are normalised; nullopt when either can't
// be.
[[nodiscard]] std::optional<bool> inside(const fs::path& image, const fs::path& directory) {
    const auto file = normalise(image);
    const auto folder = normalise(directory);
    if (!file.has_value() || !folder.has_value()) {
        return std::nullopt;
    }
    const auto prefix = *folder + L'\\';
    return file->size() > prefix.size() &&
           CompareStringOrdinal(file->c_str(), static_cast<int>(prefix.size()), prefix.c_str(),
                                static_cast<int>(prefix.size()), TRUE) == CSTR_EQUAL;
}

[[nodiscard]] std::int64_t unix_millis(const FILETIME& time) {
    const auto ticks = (static_cast<std::int64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
    return ticks > 0 ? (ticks - kFiletimeUnixEpoch) / 10000 : 0;
}

// Opens it for ending and asking about, as the service or as the signed-in
// user; empty, with `error` set, when that isn't allowed.
[[nodiscard]] win::UniqueHandle open_process(std::uint32_t pid, bool as_user, std::string& error) {
    constexpr DWORD access = PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION;
    win::UniqueHandle process;
    DWORD             failure = ERROR_SUCCESS;
    if (as_user) {
        const auto token = win::user_token();
        if (!token) {
            error = "nobody is signed in to the machine, and a shared account ends processes as the signed-in user";
            return {};
        }
        const win::Impersonation user(token.get());
        if (!user.ok()) {
            error = std::format("couldn't act as the signed-in user (error {})", GetLastError());
            return {};
        }
        process.reset(OpenProcess(access, FALSE, pid));
        failure = GetLastError();
    } else {
        process.reset(OpenProcess(access, FALSE, pid));
        failure = GetLastError();
    }
    if (process) {
        return process;
    }
    switch (failure) {
        case ERROR_INVALID_PARAMETER:
            error = "it isn't running any more";
            break;
        case ERROR_ACCESS_DENIED:
            error = as_user ? "the signed-in user may not end it (it runs as another account, or elevated)"
                            : "Windows doesn't let it be ended";
            break;
        default:
            error = std::format("couldn't open it (error {})", failure);
    }
    return {};
}

}  // namespace

bool is_essential_process(std::string_view name) noexcept {
    const auto lower = lowercase(name);
    return std::ranges::find(kEssential, std::string_view(lower)) != kEssential.end();
}

EndProcessOutcome end_process(const ProcessTarget& target, bool as_user) {
    EndProcessOutcome outcome;
    const auto refuse = [&](std::string why) {
        outcome.error = std::move(why);
        spdlog::warn("processes: not ending PID {} ({}): {}", target.pid, outcome.name.empty() ? "?" : outcome.name,
                     outcome.error);
        return outcome;
    };
    if (target.pid == kIdlePid || target.pid == kSystemPid) {
        outcome.name = target.pid == kIdlePid ? "Idle" : "System";
        return refuse("it's Windows itself");
    }
    if (target.pid == GetCurrentProcessId()) {
        outcome.name = "hawk-service.exe";
        return refuse("it's Hawk's own service, which this view runs through");
    }

    std::string error;
    const auto  process = open_process(target.pid, as_user, error);
    if (!process) {
        return refuse(std::move(error));
    }

    // What it is: without its image there's no telling it's safe to end.
    std::array<wchar_t, 32768> path{};
    DWORD                      length = static_cast<DWORD>(path.size());
    if (QueryFullProcessImageNameW(process.get(), 0, path.data(), &length) == FALSE) {
        return refuse(std::format("couldn't tell what it is (error {})", GetLastError()));
    }
    const fs::path image(std::wstring(path.data(), length));
    outcome.name = win::to_utf8(image.filename().wstring());

    // The same process the viewer saw, not a newer one given its PID.
    FILETIME created{};
    FILETIME exited{};
    FILETIME kernel{};
    FILETIME user{};
    if (GetProcessTimes(process.get(), &created, &exited, &kernel, &user) == FALSE) {
        return refuse(std::format("couldn't tell when it started (error {})", GetLastError()));
    }
    if (unix_millis(created) != target.started) {
        return refuse(std::format("it isn't running any more: PID {} now belongs to a process started since",
                                  target.pid));
    }

    if (is_essential_process(outcome.name)) {
        return refuse("Windows can't run without it");
    }
    const auto hawk = inside(image, own_directory());
    if (!hawk.has_value()) {
        return refuse("couldn't tell whether it's part of Hawk");
    }
    if (*hawk) {
        return refuse("it's part of Hawk, which this view runs through");
    }
    // A protected process (anti-malware, DRM, LSA): Windows wouldn't let
    // it be ended anyway, but say so rather than fail.
    const auto protection = query<std::uint8_t>(process.get(), kProcessProtectionInformation);
    if (!protection.has_value()) {
        return refuse("couldn't tell whether Windows protects it");
    }
    if (*protection != 0) {
        return refuse("Windows protects it");
    }
    // Marked critical: Windows stops with a blue screen when it exits.
    const auto critical = query<ULONG>(process.get(), kProcessBreakOnTermination);
    if (!critical.has_value()) {
        return refuse("couldn't tell whether Windows needs it");
    }
    if (*critical != 0) {
        return refuse("Windows marks it critical: ending it would stop the machine");
    }

    if (TerminateProcess(process.get(), 1) == FALSE) {
        return refuse(std::format("Windows didn't end it (error {})", GetLastError()));
    }
    outcome.ended = true;
    spdlog::info("processes: ended {} (PID {}){}", outcome.name, target.pid, as_user ? " as the signed-in user" : "");
    return outcome;
}

}  // namespace hawk::service
