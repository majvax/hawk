#include "updater.hpp"

#include <windows.h>

#include <spdlog/spdlog.h>

#include <array>
#include <chrono>
#include <string>
#include <utility>
#include <vector>

namespace hawk::service {

namespace {

// Long enough after a boot for the network to come up, and for a service
// that just updated to settle before it looks again.
constexpr std::chrono::minutes kFirstCheckDelay{3};
// hawk-setup's exit code for "a newer release is available".
constexpr DWORD kExitUpdateAvailable = 10;
// A check that takes longer than this is abandoned.
constexpr std::chrono::minutes kCheckTimeout{5};

[[nodiscard]] std::wstring quoted(const std::filesystem::path& path) {
    return L"\"" + path.wstring() + L"\"";
}

// Runs `command_line` hidden and waits for it, returning its exit code and
// the first line it printed. Gives up (and ends it) on a timeout or when the
// service is stopping. Its output is a line or two, which the pipe's buffer
// holds without anyone reading until it exits.
[[nodiscard]] std::optional<std::pair<DWORD, std::string>> run_and_capture(std::wstring           command_line,
                                                                           const std::stop_token& stop_token) {
    SECURITY_ATTRIBUTES inherit{.nLength = sizeof(SECURITY_ATTRIBUTES), .lpSecurityDescriptor = nullptr,
                                .bInheritHandle = TRUE};
    HANDLE read_end = nullptr;
    HANDLE write_end = nullptr;
    if (CreatePipe(&read_end, &write_end, &inherit, 64 * 1024) == FALSE) {
        return std::nullopt;
    }
    SetHandleInformation(read_end, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = write_end;
    startup.hStdError = write_end;
    startup.hStdInput = nullptr;
    PROCESS_INFORMATION process{};
    const BOOL started = CreateProcessW(nullptr, command_line.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                                        nullptr, nullptr, &startup, &process);
    CloseHandle(write_end);
    if (started == FALSE) {
        CloseHandle(read_end);
        return std::nullopt;
    }

    const auto deadline = std::chrono::steady_clock::now() + kCheckTimeout;
    bool       finished = false;
    while (!stop_token.stop_requested() && std::chrono::steady_clock::now() < deadline) {
        if (WaitForSingleObject(process.hProcess, 500) == WAIT_OBJECT_0) {
            finished = true;
            break;
        }
    }
    DWORD exit_code = 1;
    if (finished) {
        GetExitCodeProcess(process.hProcess, &exit_code);
    } else {
        TerminateProcess(process.hProcess, 1);
        WaitForSingleObject(process.hProcess, 5000);
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);

    std::string           output;
    std::array<char, 512> buffer{};
    DWORD                 available = 0;
    DWORD                 read = 0;
    while (PeekNamedPipe(read_end, nullptr, 0, nullptr, &available, nullptr) != FALSE && available > 0 &&
           ReadFile(read_end, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr) != FALSE && read > 0) {
        output.append(buffer.data(), read);
    }
    CloseHandle(read_end);
    if (!finished) {
        return std::nullopt;
    }
    const auto end = output.find_first_of("\r\n");
    return std::pair{exit_code, output.substr(0, end)};
}

// Starts `command_line` on its own: not a child this service waits for, and
// one that outlives it, since it stops the service.
[[nodiscard]] bool launch_detached(std::wstring command_line) {
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    constexpr DWORD flags = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS;
    BOOL started = CreateProcessW(nullptr, command_line.data(), nullptr, nullptr, FALSE,
                                  flags | CREATE_BREAKAWAY_FROM_JOB, nullptr, nullptr, &startup, &process);
    if (started == FALSE) {
        // Not in a job, or one that doesn't allow breaking away.
        started = CreateProcessW(nullptr, command_line.data(), nullptr, nullptr, FALSE, flags, nullptr, nullptr,
                                 &startup, &process);
    }
    if (started == FALSE) {
        return false;
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return true;
}

}  // namespace

std::filesystem::path setup_path() {
    std::vector<wchar_t> buffer(MAX_PATH);
    for (;;) {
        const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) {
            return L"hawk-setup.exe";
        }
        if (length < buffer.size()) {
            return std::filesystem::path(std::wstring(buffer.data(), length)).parent_path() / L"hawk-setup.exe";
        }
        buffer.resize(buffer.size() * 2);
    }
}

Updater::Updater(UpdateConfig config, Notify notify) : config_(std::move(config)), notify_(std::move(notify)) {
    if (config_.policy == UpdatePolicy::off) {
        spdlog::info("update: off (config)");
        return;
    }
    thread_ = std::jthread([this](const std::stop_token& stop_token) { run(stop_token); });
}

Updater::~Updater() {
    if (thread_.joinable()) {
        thread_.request_stop();
        thread_.join();
    }
}

std::optional<std::string> Updater::available() const {
    const std::scoped_lock lock(mutex_);
    return available_;
}

void Updater::install_now() {
    const auto setup = setup_path();
    if (!std::filesystem::exists(setup)) {
        spdlog::error("update: {} is missing; reinstall the machine to get updates", setup.string());
        return;
    }
    spdlog::info("update: installing as the owner asked");
    if (!launch_detached(quoted(setup) + L" update machine --quiet")) {
        spdlog::error("update: couldn't start hawk-setup (error {})", GetLastError());
    }
}

void Updater::run(const std::stop_token& stop_token) {
    auto next = std::chrono::steady_clock::now() + kFirstCheckDelay;
    while (!stop_token.stop_requested()) {
        if (std::chrono::steady_clock::now() >= next) {
            check(stop_token);
            next = std::chrono::steady_clock::now() + std::chrono::hours(config_.check_hours);
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void Updater::check(const std::stop_token& stop_token) {
    const auto setup = setup_path();
    if (!std::filesystem::exists(setup)) {
        spdlog::warn("update: {} is missing, so this machine can't update itself", setup.string());
        return;
    }
    auto result = run_and_capture(quoted(setup) + L" update machine --check --quiet", stop_token);
    if (!result.has_value()) {
        if (!stop_token.stop_requested()) {
            spdlog::warn("update: hawk-setup didn't run, or didn't finish checking");
        }
        return;
    }
    auto& [exit_code, line] = *result;
    std::optional<std::string> available;
    if (exit_code == kExitUpdateAvailable && !line.empty()) {
        available = line.substr(0, 32);
    } else if (exit_code != 0) {
        spdlog::warn("update: the check failed ({}): {}", exit_code, line);
        return;
    }

    if (available.has_value() && config_.policy == UpdatePolicy::automatic) {
        spdlog::info("update: {} is available; installing (policy auto)", *available);
        if (!launch_detached(quoted(setup) + L" update machine --quiet")) {
            spdlog::error("update: couldn't start hawk-setup (error {})", GetLastError());
        }
        return;
    }

    bool changed = false;
    {
        const std::scoped_lock lock(mutex_);
        changed = available_ != available;
        available_ = available;
    }
    if (changed) {
        if (available.has_value()) {
            spdlog::info("update: {} is available; waiting for the owner (policy notify)", *available);
        }
        notify_(available);
    }
}

}  // namespace hawk::service
