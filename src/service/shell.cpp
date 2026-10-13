#include "shell.hpp"

// The pseudoconsole API (Windows 10 1809) is only declared for that target
// or later; set it before any Windows header is included.
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00  // NOLINT
#undef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000006  // NTDDI_WIN10_RS5

#include "win_util.hpp"

#include <windows.h>
#include <userenv.h>

#include <glaze/glaze.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <expected>
#include <format>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016
#endif

namespace hawk::service {

namespace {

using win::UniqueHandle;
using win::to_utf8;
using win::to_wide;
using win::user_token;

// The most terminal bytes in one message, and how much output may be
// unacknowledged before the shell's output stops being read.
constexpr std::size_t kChunkSize = 16 * 1024;
constexpr std::uint64_t kWindow = 256 * 1024;
constexpr std::size_t kMaxPerViewer = 2;
constexpr std::size_t kMaxShells = 4;
constexpr std::size_t kMaxIdLength = 40;
constexpr int kMaxCols = 1000;
constexpr int kMaxRows = 500;

struct RequestHeader {
    std::string   id;
    int           cols = 0;
    int           rows = 0;
    std::uint64_t received = 0;
};

struct ReplyHeader {
    std::string                  id;
    std::optional<std::uint64_t> offset;
    std::optional<std::uint32_t> code;
    std::optional<std::string>   message;
};

}  // namespace

}  // namespace hawk::service

template <>
struct glz::meta<hawk::service::RequestHeader> {
    using T                     = hawk::service::RequestHeader;
    static constexpr auto value = object("id", &T::id, "cols", &T::cols, "rows", &T::rows, "received", &T::received);
};

template <>
struct glz::meta<hawk::service::ReplyHeader> {
    using T                     = hawk::service::ReplyHeader;
    static constexpr auto value =
        object("id", &T::id, "offset", &T::offset, "code", &T::code, "message", &T::message);
};

namespace hawk::service {

namespace {

[[nodiscard]] bool is_valid_id(std::string_view id) {
    return !id.empty() && id.size() <= kMaxIdLength && std::ranges::all_of(id, [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-';
    });
}

[[nodiscard]] COORD console_size(int cols, int rows) {
    return COORD{.X = static_cast<SHORT>(std::clamp(cols, 1, kMaxCols)),
                 .Y = static_cast<SHORT>(std::clamp(rows, 1, kMaxRows))};
}

// "DOMAIN\\user" for a token, for the log; empty if it can't be told. Also
// how a SYSTEM token is caught: nothing here ever runs as LocalSystem.
struct AccountInfo {
    std::string name;
    bool        system = true;
};

[[nodiscard]] AccountInfo describe(HANDLE token) {
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<std::byte> buffer(size);
    if (size == 0 || GetTokenInformation(token, TokenUser, buffer.data(), size, &size) == FALSE) {
        return {};
    }
    PSID sid = reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid;
    AccountInfo user{.name = {}, .system = IsWellKnownSid(sid, WinLocalSystemSid) != FALSE};
    std::array<wchar_t, 256> name{};
    std::array<wchar_t, 256> domain{};
    auto                     name_size = static_cast<DWORD>(name.size());
    auto                     domain_size = static_cast<DWORD>(domain.size());
    SID_NAME_USE             use{};
    if (LookupAccountSidW(nullptr, sid, name.data(), &name_size, domain.data(), &domain_size, &use) != FALSE) {
        user.name = to_utf8(std::wstring(domain.data()) + L"\\" + name.data());
    }
    return user;
}

// One running shell. Its output is read on a thread of its own, which
// pauses while the window is full; a second thread waits for the process
// to exit and then closes the pseudoconsole, which is what lets the output
// pipe reach its end once the last of the output is read.
struct Shell {
    std::uint64_t viewer = 0;
    std::string   id;
    HPCON         console = nullptr;
    UniqueHandle  input;   // what we write keystrokes to
    UniqueHandle  output;  // what we read the terminal from
    UniqueHandle  process;
    UniqueHandle  job;
    UniqueHandle  stop;  // manual-reset; set when the viewer closes it

    std::mutex              mutex;
    std::condition_variable window_open;
    std::uint64_t           sent = 0;
    std::uint64_t           acked = 0;
    bool                    closing = false;  // drain and discard: nobody is listening

    std::atomic<bool>     console_closed{false};
    std::atomic<bool>     finished{false};
    std::uint64_t         bytes_in = 0;
    std::chrono::steady_clock::time_point started = std::chrono::steady_clock::now();

    std::jthread reader;
    std::jthread waiter;

    Shell() = default;
    Shell(const Shell&) = delete;
    Shell& operator=(const Shell&) = delete;
    Shell(Shell&&) = delete;
    Shell& operator=(Shell&&) = delete;

    ~Shell() {
        shut();
        if (waiter.joinable()) {
            waiter.join();
        }
        if (reader.joinable()) {
            reader.join();
        }
        close_console();
    }

    void close_console() {
        if (!console_closed.exchange(true) && console != nullptr) {
            ClosePseudoConsole(console);
        }
    }

    // Ends it from our side: everything it started is killed, and its
    // output is drained without being sent.
    void shut() {
        {
            const std::lock_guard lock(mutex);
            closing = true;
        }
        window_open.notify_all();
        if (stop) {
            SetEvent(stop.get());
        }
        if (job) {
            TerminateJobObject(job.get(), 1);
        }
    }
};

struct Request {
    std::uint64_t  viewer = 0;
    ChannelMessage message;
};

struct Drop {
    std::uint64_t viewer = 0;
};

}  // namespace

struct ShellSessions::Impl {
    ShellConfig config;
    ViewerHub&  hub;

    std::mutex                              mutex;
    std::condition_variable                 wake;
    std::deque<std::variant<Request, Drop>> queue;
    bool                                    stopping = false;

    // Worker thread only.
    std::map<std::pair<std::uint64_t, std::string>, std::unique_ptr<Shell>> shells;

    std::jthread worker;

    Impl(ShellConfig shell_config, ViewerHub& viewer_hub) : config(std::move(shell_config)), hub(viewer_hub) {
        worker = std::jthread([this] { run(); });
    }

    ~Impl() {
        {
            const std::lock_guard lock(mutex);
            stopping = true;
        }
        wake.notify_all();
        worker.join();
    }

    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
    Impl(Impl&&) = delete;
    Impl& operator=(Impl&&) = delete;

    void push(std::variant<Request, Drop> event) {
        {
            const std::lock_guard lock(mutex);
            queue.push_back(std::move(event));
        }
        wake.notify_one();
    }

    void run() {
        for (;;) {
            std::deque<std::variant<Request, Drop>> events;
            {
                std::unique_lock lock(mutex);
                // Woken for requests; otherwise now and then, to reap shells
                // that ended on their own.
                wake.wait_for(lock, std::chrono::milliseconds(500), [this] { return stopping || !queue.empty(); });
                if (stopping) {
                    break;
                }
                std::swap(events, queue);
            }
            for (auto& event : events) {
                if (auto* request = std::get_if<Request>(&event)) {
                    serve(request->viewer, request->message);
                } else {
                    close_viewer(std::get<Drop>(event).viewer);
                }
            }
            reap();
        }
        for (auto& [key, shell] : shells) {
            log_closed(*shell);
        }
        shells.clear();
    }

    void reply(std::uint64_t viewer, std::uint8_t op, const ReplyHeader& header, std::span<const std::byte> data = {}) {
        auto json = glz::write_json(header);
        hub.send_shell(viewer, ChannelMessage{.op = op, .header = json.value_or("{}"), .data = {data.begin(), data.end()}});
    }

    void fail(std::uint64_t viewer, const std::string& id, std::string message) {
        spdlog::info("shell: viewer {} ({}): {}", viewer, hub.fingerprint_of(viewer), message);
        reply(viewer, shell_op::error, ReplyHeader{.id = id, .message = std::move(message)});
    }

    void serve(std::uint64_t viewer, const ChannelMessage& message) {
        RequestHeader header;
        if (glz::read<glz::opts{.error_on_unknown_keys = false}>(header, message.header) || !is_valid_id(header.id)) {
            return;
        }
        const auto key = std::pair{viewer, header.id};
        if (message.op == shell_op::open) {
            open(viewer, header);
            return;
        }
        const auto found = shells.find(key);
        if (found == shells.end()) {
            return;
        }
        Shell& shell = *found->second;
        switch (message.op) {
            case shell_op::input:
                write_input(shell, message.data);
                break;
            case shell_op::resize:
                ResizePseudoConsole(shell.console, console_size(header.cols, header.rows));
                break;
            case shell_op::ack: {
                {
                    const std::lock_guard lock(shell.mutex);
                    shell.acked = std::clamp(header.received, shell.acked, shell.sent);
                }
                shell.window_open.notify_all();
                break;
            }
            case shell_op::close:
                log_closed(shell);
                shells.erase(found);  // shuts it down
                break;
            default:
                break;
        }
    }

    void write_input(Shell& shell, std::span<const std::byte> data) {
        if (data.size() > kChunkSize) {
            return;
        }
        shell.bytes_in += data.size();
        while (!data.empty()) {
            DWORD written = 0;
            if (WriteFile(shell.input.get(), data.data(), static_cast<DWORD>(data.size()), &written, nullptr) == FALSE ||
                written == 0) {
                return;  // it's exiting; the reader reports that
            }
            data = data.subspan(written);
        }
    }

    void open(std::uint64_t viewer, const RequestHeader& header) {
        const auto key = std::pair{viewer, header.id};
        if (shells.contains(key)) {
            return;
        }
        const auto mine = static_cast<std::size_t>(
            std::ranges::count_if(shells, [viewer](const auto& entry) { return entry.first.first == viewer; }));
        if (mine >= kMaxPerViewer || shells.size() >= kMaxShells) {
            fail(viewer, header.id, "too many shells open; close one first");
            return;
        }

        auto token = user_token();
        if (!token) {
            fail(viewer, header.id, "nobody is logged on to the machine");
            return;
        }
        const auto user = describe(token.get());
        if (user.system) {
            // Never SYSTEM, whatever the token turned out to be.
            fail(viewer, header.id, "refusing to open a shell as SYSTEM");
            return;
        }

        auto shell = spawn(token.get(), header);
        if (!shell.has_value()) {
            fail(viewer, header.id, shell.error());
            return;
        }
        (*shell)->viewer = viewer;
        (*shell)->id = header.id;
        spdlog::info("shell: viewer {} ({}) opened \"{}\" as {}", viewer, hub.fingerprint_of(viewer), config.command,
                     user.name);
        reply(viewer, shell_op::opened, ReplyHeader{.id = header.id});
        start(**shell);
        shells.emplace(key, std::move(*shell));
    }

    [[nodiscard]] std::expected<std::unique_ptr<Shell>, std::string> spawn(HANDLE token, const RequestHeader& header) {
        auto command = to_wide(config.command);
        if (!command.has_value()) {
            return std::unexpected("the configured shell command isn't valid text");
        }
        auto shell = std::make_unique<Shell>();

        HANDLE input_read = nullptr;
        HANDLE input_write = nullptr;
        HANDLE output_read = nullptr;
        HANDLE output_write = nullptr;
        if (CreatePipe(&input_read, &input_write, nullptr, 0) == FALSE) {
            return std::unexpected(std::format("CreatePipe failed (Win32 error {})", GetLastError()));
        }
        const UniqueHandle console_input(input_read);
        shell->input.reset(input_write);
        if (CreatePipe(&output_read, &output_write, nullptr, 0) == FALSE) {
            return std::unexpected(std::format("CreatePipe failed (Win32 error {})", GetLastError()));
        }
        const UniqueHandle console_output(output_write);
        shell->output.reset(output_read);

        if (const HRESULT result = CreatePseudoConsole(console_size(header.cols, header.rows), console_input.get(),
                                                       console_output.get(), 0, &shell->console);
            FAILED(result)) {
            shell->console = nullptr;
            return std::unexpected(std::format("CreatePseudoConsole failed ({:#x})", static_cast<unsigned>(result)));
        }

        SIZE_T attribute_size = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_size);
        std::vector<std::byte> attribute_buffer(attribute_size);
        auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_buffer.data());
        if (InitializeProcThreadAttributeList(attributes, 1, 0, &attribute_size) == FALSE) {
            return std::unexpected("couldn't set up the process attributes");
        }
        const bool attached = UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                                                        shell->console, sizeof(HPCON), nullptr, nullptr) != FALSE;
        if (!attached) {
            DeleteProcThreadAttributeList(attributes);
            return std::unexpected("couldn't attach the pseudoconsole");
        }

        // The user's own environment and home, as if they'd opened it.
        void* environment = nullptr;
        CreateEnvironmentBlock(&environment, token, FALSE);
        std::array<wchar_t, MAX_PATH> profile{};
        auto                          profile_size = static_cast<DWORD>(profile.size());
        const bool has_profile = GetUserProfileDirectoryW(token, profile.data(), &profile_size) != FALSE;

        shell->job.reset(CreateJobObjectW(nullptr, nullptr));
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!shell->job || SetInformationJobObject(shell->job.get(), JobObjectExtendedLimitInformation, &limits,
                                                   sizeof(limits)) == FALSE) {
            DeleteProcThreadAttributeList(attributes);
            if (environment != nullptr) {
                DestroyEnvironmentBlock(environment);
            }
            return std::unexpected("couldn't create a job for the shell");
        }

        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        std::wstring desktop = L"winsta0\\default";
        startup.StartupInfo.lpDesktop = desktop.data();
        startup.lpAttributeList = attributes;
        PROCESS_INFORMATION process{};
        const BOOL          created = CreateProcessAsUserW(
            token, nullptr, command->data(), nullptr, nullptr, FALSE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED, environment,
            has_profile ? profile.data() : nullptr, &startup.StartupInfo, &process);
        const DWORD error = GetLastError();
        DeleteProcThreadAttributeList(attributes);
        if (environment != nullptr) {
            DestroyEnvironmentBlock(environment);
        }
        if (created == FALSE) {
            return std::unexpected(std::format("couldn't start \"{}\" (Win32 error {})", config.command, error));
        }
        const UniqueHandle thread(process.hThread);
        shell->process.reset(process.hProcess);
        if (AssignProcessToJobObject(shell->job.get(), process.hProcess) == FALSE) {
            TerminateProcess(process.hProcess, 1);
            return std::unexpected("couldn't put the shell in its job");
        }
        ResumeThread(thread.get());
        shell->stop.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        return shell;
    }

    void start(Shell& shell) {
        shell.waiter = std::jthread([&shell] {
            const std::array<HANDLE, 2> waits{shell.process.get(), shell.stop.get()};
            WaitForMultipleObjects(static_cast<DWORD>(waits.size()), waits.data(), FALSE, INFINITE);
            // With the process gone the pseudoconsole flushes what's left and
            // closes, and the reader sees the end of its output.
            shell.close_console();
        });
        shell.reader = std::jthread([this, &shell] { read_output(shell); });
    }

    void read_output(Shell& shell) {
        std::vector<std::byte> buffer(kChunkSize);
        for (;;) {
            {
                std::unique_lock lock(shell.mutex);
                shell.window_open.wait(lock, [&] { return shell.closing || shell.sent - shell.acked < kWindow; });
            }
            DWORD read = 0;
            if (ReadFile(shell.output.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr) ==
                    FALSE ||
                read == 0) {
                break;
            }
            std::uint64_t offset = 0;
            {
                const std::lock_guard lock(shell.mutex);
                if (shell.closing) {
                    continue;  // drained, not sent
                }
                offset = shell.sent;
                shell.sent += read;
            }
            reply(shell.viewer, shell_op::output, ReplyHeader{.id = shell.id, .offset = offset},
                  std::span(buffer).first(read));
        }
        bool closing = false;
        {
            const std::lock_guard lock(shell.mutex);
            closing = shell.closing;
        }
        if (!closing) {
            DWORD code = 0;
            WaitForSingleObject(shell.process.get(), 2000);
            GetExitCodeProcess(shell.process.get(), &code);
            reply(shell.viewer, shell_op::exited, ReplyHeader{.id = shell.id, .code = code});
        }
        shell.finished.store(true);
        wake.notify_one();
    }

    void log_closed(const Shell& shell) {
        const auto seconds =
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - shell.started).count();
        spdlog::info("shell: viewer {}'s shell closed after {}s ({} bytes in, {} bytes out)", shell.viewer, seconds,
                     shell.bytes_in, shell.sent);
    }

    void close_viewer(std::uint64_t viewer) {
        for (auto it = shells.begin(); it != shells.end();) {
            if (it->first.first == viewer) {
                log_closed(*it->second);
                it = shells.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Shells that exited on their own.
    void reap() {
        for (auto it = shells.begin(); it != shells.end();) {
            if (it->second->finished.load()) {
                log_closed(*it->second);
                it = shells.erase(it);
            } else {
                ++it;
            }
        }
    }
};

ShellSessions::ShellSessions(ShellConfig config, ViewerHub& hub)
    : impl_(std::make_unique<Impl>(std::move(config), hub)) {}

ShellSessions::~ShellSessions() = default;

void ShellSessions::handle(std::uint64_t viewer, ChannelMessage message) {
    impl_->push(Request{.viewer = viewer, .message = std::move(message)});
}

void ShellSessions::drop_viewer(std::uint64_t viewer) {
    impl_->push(Drop{.viewer = viewer});
}

}  // namespace hawk::service
