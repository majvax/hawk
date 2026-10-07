#include "capture_host.hpp"

#include "common/capture_pipe.hpp"

#include <windows.h>
#include <sddl.h>
#include <userenv.h>
#include <wtsapi32.h>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <format>
#include <limits>
#include <thread>
#include <utility>
#include <vector>

namespace hawk::service {

namespace {

constexpr std::wstring_view capture_executable = L"hawk-capture.exe";
constexpr DWORD             pipe_buffer_size = 1024 * 1024;
constexpr DWORD             capture_exit_timeout_ms = 2000;
constexpr DWORD             no_console_session = 0xFFFFFFFF;

// What hawk-capture's end of the pipe is opened with, and so exactly what the
// pipe's DACL grants the logged-on user. FILE_READ_ATTRIBUTES is not
// optional: CreateFile() adds it to the access it asks the object manager
// for, so a grant of only the write rights is denied with ERROR_ACCESS_DENIED
// before hawk-capture gets a handle. Keep this in sync with the CreateFileA
// call in capture/main.cpp.
constexpr DWORD capture_client_access = FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;

[[nodiscard]] CaptureHostError make_error(CaptureHostError::Code code, DWORD native_code, std::string_view context) {
    return CaptureHostError{
        .code = code,
        .native_code = native_code,
        .message = std::format("{}: Win32 error {}", context, native_code),
    };
}

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

private:
    HANDLE handle_ = nullptr;
};

[[nodiscard]] std::expected<std::wstring, CaptureHostError> user_sid_string(HANDLE token) {
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<std::byte> buffer(size);
    if (GetTokenInformation(token, TokenUser, buffer.data(), size, &size) == FALSE) {
        return std::unexpected(
            make_error(CaptureHostError::Code::no_user_session, GetLastError(), "GetTokenInformation(TokenUser)"));
    }

    // TOKEN_USER is followed in the same buffer by the SID it points at.
    const auto* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
    LPWSTR      sid_text = nullptr;
    if (ConvertSidToStringSidW(user->User.Sid, &sid_text) == FALSE) {
        return std::unexpected(
            make_error(CaptureHostError::Code::no_user_session, GetLastError(), "ConvertSidToStringSidW"));
    }
    std::wstring result(sid_text);
    LocalFree(sid_text);
    return result;
}

// Inbound-only, single-instance, local-only pipe that only SYSTEM and the
// logged-on user can open — per the README, never a blanket grant to
// Authenticated Users. FILE_FLAG_FIRST_PIPE_INSTANCE makes creation fail if
// anyone else already squats the name.
[[nodiscard]] std::expected<UniqueHandle, CaptureHostError> create_pipe(const std::wstring& name,
                                                                         const std::wstring& user_sid) {
    const std::wstring   sddl = std::format(L"D:P(A;;GA;;;SY)(A;;0x{:08X};;;{})", capture_client_access, user_sid);
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor,
                                                             nullptr) == FALSE) {
        return std::unexpected(make_error(CaptureHostError::Code::pipe_failed, GetLastError(),
                                          "ConvertStringSecurityDescriptorToSecurityDescriptorW"));
    }

    SECURITY_ATTRIBUTES attributes{
        .nLength = sizeof(SECURITY_ATTRIBUTES),
        .lpSecurityDescriptor = descriptor,
        .bInheritHandle = FALSE,
    };
    UniqueHandle pipe(CreateNamedPipeW(name.c_str(),
                                       PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                                       PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                       1, 0, pipe_buffer_size, 0, &attributes));
    const DWORD  error = GetLastError();
    LocalFree(descriptor);
    if (!pipe) {
        return std::unexpected(make_error(CaptureHostError::Code::pipe_failed, error, "CreateNamedPipeW"));
    }
    return pipe;
}

// hawk-capture.exe is installed next to hawk-service.exe.
[[nodiscard]] std::expected<std::wstring, CaptureHostError> service_directory() {
    std::wstring path(MAX_PATH, L'\0');
    for (;;) {
        const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (length == 0) {
            return std::unexpected(
                make_error(CaptureHostError::Code::launch_failed, GetLastError(), "GetModuleFileNameW"));
        }
        if (length < path.size()) {
            path.resize(length);
            break;
        }
        path.resize(path.size() * 2);
    }
    path.resize(path.find_last_of(L"\\/") + 1);
    return path;
}

[[nodiscard]] std::expected<UniqueHandle, CaptureHostError> launch_capture(HANDLE                user_token,
                                                                            const std::wstring& pipe_name) {
    auto directory = service_directory();
    if (!directory.has_value()) {
        return std::unexpected(directory.error());
    }
    const std::wstring executable = *directory + std::wstring(capture_executable);
    std::wstring       command_line = std::format(L"\"{}\" --pipe {}", executable, pipe_name);
    std::wstring       desktop = L"winsta0\\default";

    LPVOID environment = nullptr;
    if (CreateEnvironmentBlock(&environment, user_token, FALSE) == FALSE) {
        return std::unexpected(
            make_error(CaptureHostError::Code::launch_failed, GetLastError(), "CreateEnvironmentBlock"));
    }

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.lpDesktop = desktop.data();
    PROCESS_INFORMATION process{};
    const BOOL launched = CreateProcessAsUserW(user_token, executable.c_str(), command_line.data(), nullptr, nullptr,
                                               FALSE, CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW, environment,
                                               directory->c_str(), &startup, &process);
    const DWORD error = GetLastError();
    DestroyEnvironmentBlock(environment);
    if (launched == FALSE) {
        return std::unexpected(make_error(CaptureHostError::Code::launch_failed, error, "CreateProcessAsUserW"));
    }

    CloseHandle(process.hThread);
    return UniqueHandle(process.hProcess);
}

// Waits for an overlapped operation on `pipe` that returned
// ERROR_IO_PENDING. If `stop_event` fires or hawk-capture exits first, the
// operation is cancelled — and waited on, so `overlapped` is never left in
// use — and ERROR_OPERATION_ABORTED / ERROR_BROKEN_PIPE is returned.
[[nodiscard]] DWORD finish_overlapped(HANDLE pipe, OVERLAPPED& overlapped, HANDLE stop_event, HANDLE process,
                                      DWORD& transferred) {
    const std::array<HANDLE, 3> waits{overlapped.hEvent, stop_event, process};
    const DWORD wait = WaitForMultipleObjects(static_cast<DWORD>(waits.size()), waits.data(), FALSE, INFINITE);
    if (wait != WAIT_OBJECT_0) {
        CancelIoEx(pipe, &overlapped);
        GetOverlappedResult(pipe, &overlapped, &transferred, TRUE);
        return wait == WAIT_OBJECT_0 + 1 ? ERROR_OPERATION_ABORTED : ERROR_BROKEN_PIPE;
    }
    if (GetOverlappedResult(pipe, &overlapped, &transferred, FALSE) == FALSE) {
        return GetLastError();
    }
    return NO_ERROR;
}

}  // namespace

std::string_view to_string(CaptureHostError::Code code) noexcept {
    switch (code) {
        case CaptureHostError::Code::already_running:
            return "already_running";
        case CaptureHostError::Code::no_user_session:
            return "no_user_session";
        case CaptureHostError::Code::pipe_failed:
            return "pipe_failed";
        case CaptureHostError::Code::launch_failed:
            return "launch_failed";
    }
    return "unknown";
}

std::string to_string(const CaptureHostError& error) {
    return std::format("[{}] {}", to_string(error.code), error.message);
}

struct CaptureHost::Impl {
    UniqueHandle      pipe;
    UniqueHandle      process;
    UniqueHandle      stop_event;  // manual-reset; set by stop()
    UniqueHandle      io_event;    // manual-reset; the reader's OVERLAPPED event
    std::jthread      reader;
    std::atomic<bool> running{false};

    [[nodiscard]] DWORD connect() {
        OVERLAPPED overlapped{};
        overlapped.hEvent = io_event.get();
        ResetEvent(io_event.get());
        if (ConnectNamedPipe(pipe.get(), &overlapped) != FALSE) {
            return NO_ERROR;
        }
        const DWORD error = GetLastError();
        if (error == ERROR_PIPE_CONNECTED) {
            return NO_ERROR;
        }
        if (error != ERROR_IO_PENDING) {
            return error;
        }
        DWORD transferred = 0;
        return finish_overlapped(pipe.get(), overlapped, stop_event.get(), process.get(), transferred);
    }

    [[nodiscard]] DWORD read_exact(std::span<std::byte> out) {
        std::size_t done = 0;
        while (done < out.size()) {
            const auto chunk =
                static_cast<DWORD>(std::min<std::size_t>(out.size() - done, std::numeric_limits<DWORD>::max()));
            OVERLAPPED overlapped{};
            overlapped.hEvent = io_event.get();
            ResetEvent(io_event.get());

            DWORD transferred = 0;
            if (ReadFile(pipe.get(), out.subspan(done).data(), chunk, nullptr, &overlapped) != FALSE) {
                GetOverlappedResult(pipe.get(), &overlapped, &transferred, FALSE);
            } else if (const DWORD error = GetLastError(); error != ERROR_IO_PENDING) {
                return error;
            } else if (const DWORD result =
                           finish_overlapped(pipe.get(), overlapped, stop_event.get(), process.get(), transferred);
                       result != NO_ERROR) {
                return result;
            }
            done += transferred;
        }
        return NO_ERROR;
    }

    void read_packets(const PacketHandler& on_packet) {
        DWORD result = connect();
        if (result == NO_ERROR) {
            spdlog::info("capture: hawk-capture connected");
        }

        std::vector<std::byte> payload;
        while (result == NO_ERROR) {
            ipc::CapturePacketHeader header{};
            result = read_exact(std::as_writable_bytes(std::span(&header, 1)));
            if (result != NO_ERROR) {
                break;
            }
            if (header.magic != ipc::capture_packet_magic || header.size > ipc::max_capture_packet_size) {
                spdlog::error("capture: malformed packet header from hawk-capture, dropping the stream");
                break;
            }

            payload.resize(header.size);
            result = read_exact(payload);
            if (result != NO_ERROR) {
                break;
            }
            on_packet(CapturePacket{
                .data = payload,
                .is_keyframe = (header.flags & ipc::capture_flag_keyframe) != 0,
                .timestamp = std::chrono::microseconds{header.timestamp_us},
            });
        }

        if (result == ERROR_BROKEN_PIPE) {
            spdlog::warn("capture: hawk-capture exited or closed the pipe");
        } else if (result != NO_ERROR && result != ERROR_OPERATION_ABORTED) {
            spdlog::error("capture: reading from hawk-capture failed: Win32 error {}", result);
        }
        running.store(false);
    }
};

CaptureHost::CaptureHost() : impl_(std::make_unique<Impl>()) {}

CaptureHost::~CaptureHost() {
    stop();
}

std::expected<void, CaptureHostError> CaptureHost::start(PacketHandler on_packet) {
    if (impl_->running.load()) {
        return std::unexpected(CaptureHostError{
            .code = CaptureHostError::Code::already_running, .native_code = 0, .message = "capture already running"});
    }
    stop();  // reap a previous run that ended on its own

    const DWORD session = WTSGetActiveConsoleSessionId();
    if (session == no_console_session) {
        return std::unexpected(CaptureHostError{.code = CaptureHostError::Code::no_user_session,
                                                .native_code = 0,
                                                .message = "no session is attached to the console"});
    }

    HANDLE raw_token = nullptr;
    if (WTSQueryUserToken(session, &raw_token) == FALSE) {
        // ERROR_NO_TOKEN: nobody is logged on to the console session.
        return std::unexpected(make_error(CaptureHostError::Code::no_user_session, GetLastError(), "WTSQueryUserToken"));
    }
    const UniqueHandle user_token(raw_token);

    auto user_sid = user_sid_string(user_token.get());
    if (!user_sid.has_value()) {
        return std::unexpected(user_sid.error());
    }

    static std::atomic<std::uint32_t> pipe_counter{0};
    const std::wstring                pipe_name =
        std::format(L"\\\\.\\pipe\\hawk-capture-{}-{}", GetCurrentProcessId(), pipe_counter.fetch_add(1));

    auto pipe = create_pipe(pipe_name, *user_sid);
    if (!pipe.has_value()) {
        return std::unexpected(pipe.error());
    }

    UniqueHandle stop_event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    UniqueHandle io_event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!stop_event || !io_event) {
        return std::unexpected(make_error(CaptureHostError::Code::pipe_failed, GetLastError(), "CreateEventW"));
    }

    auto process = launch_capture(user_token.get(), pipe_name);
    if (!process.has_value()) {
        return std::unexpected(process.error());
    }

    impl_->pipe = std::move(*pipe);
    impl_->process = std::move(*process);
    impl_->stop_event = std::move(stop_event);
    impl_->io_event = std::move(io_event);
    impl_->running.store(true);
    impl_->reader = std::jthread([impl = impl_.get(), handler = std::move(on_packet)] { impl->read_packets(handler); });

    spdlog::info("capture: launched hawk-capture in session {}", session);
    return {};
}

void CaptureHost::stop() noexcept {
    if (!impl_->process) {
        return;
    }

    SetEvent(impl_->stop_event.get());
    if (impl_->reader.joinable()) {
        impl_->reader.join();
    }

    // Closing our end breaks hawk-capture's next write, which it takes as
    // the signal to exit.
    impl_->pipe.reset();
    if (WaitForSingleObject(impl_->process.get(), capture_exit_timeout_ms) == WAIT_TIMEOUT) {
        spdlog::warn("capture: hawk-capture did not exit in time, terminating it");
        TerminateProcess(impl_->process.get(), 1);
    }

    impl_->process.reset();
    impl_->stop_event.reset();
    impl_->io_event.reset();
    impl_->running.store(false);
    spdlog::info("capture: stopped");
}

bool CaptureHost::is_running() const noexcept {
    return impl_->running.load();
}

}  // namespace hawk::service
