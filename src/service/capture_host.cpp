#include "capture_host.hpp"

#include "common/capture_pipe.hpp"
#include "common/clipboard_pipe.hpp"
#include "common/input_pipe.hpp"
#include "win_util.hpp"

#include <windows.h>
#include <sddl.h>
#include <userenv.h>
#include <wtsapi32.h>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
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

// The input pipe carries 64-byte packets at the rate a person moves a mouse,
// so this holds a few hundred of them if hawk-capture ever falls behind.
constexpr DWORD input_buffer_size = 16 * 1024;
// Input is sent from the relay thread, which has to keep servicing the
// socket: rather than wait on a write hawk-capture isn't taking, give up on
// the event. Losing one is nothing; stalling the relay link is not. For the
// same reason the relay thread never waits for hawk-capture to open the
// input pipe at all (see poll_input_connection).
constexpr DWORD input_write_timeout_ms = 1000;

// What hawk-capture's end of the pipe is opened with, and so exactly what the
// pipe's DACL grants SYSTEM. FILE_READ_ATTRIBUTES is not
// optional: CreateFile() adds it to the access it asks the object manager
// for, so a grant of only the write rights is denied with ERROR_ACCESS_DENIED
// before hawk-capture gets a handle. Keep this in sync with the CreateFileA
// call in capture/main.cpp.
constexpr DWORD capture_client_access = FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;

// The same, for hawk-capture's end of the input pipe, which it only reads.
// Keep this in sync with the CreateFileA call in capture/input.cpp.
constexpr DWORD input_client_access = FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;

// And for the clipboard pipe, which hawk-capture both reads and writes.
// Keep this in sync with the CreateFileA call in capture/clipboard.cpp.
constexpr DWORD clipboard_client_access = FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
// Each way: a quarter of the largest text, which hawk-capture's reader
// drains as it arrives.
constexpr DWORD clipboard_buffer_size = 64 * 1024;
// A paste is sent from the relay thread too; the same reasoning as
// input_write_timeout_ms, with room for the larger write.
constexpr DWORD clipboard_write_timeout_ms = 2000;

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

// One-directional, single-instance, local-only pipe that only SYSTEM can
// open. hawk-capture runs as SYSTEM (see system_token_for_session), so the
// logged-on user needs no grant; giving them one would let any process they
// run connect first and, even though verify_client then rejects it, take the
// single instance away from hawk-capture. `client_access` is exactly what
// hawk-capture opens its end with, and so exactly what the DACL grants.
// FILE_FLAG_FIRST_PIPE_INSTANCE makes creation fail if anyone else already
// squats the name.
[[nodiscard]] std::expected<UniqueHandle, CaptureHostError> create_pipe(const std::wstring& name, DWORD access_mode,
                                                                         DWORD pipe_mode, DWORD client_access,
                                                                         DWORD out_buffer, DWORD in_buffer) {
    const std::wstring sddl = std::format(L"D:P(A;;0x{:08X};;;SY)", client_access);
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
                                       access_mode | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                                       pipe_mode | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, out_buffer, in_buffer,
                                       0, &attributes));
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

// Builds a LocalSystem primary token aimed at `session`. The capture helper
// runs from it, so it runs as SYSTEM *inside* the interactive session —
// which is what lets it reach the secure desktop the UAC prompt and lock
// screen live on (that desktop's DACL admits only SYSTEM) and follow the
// switch to it. Retargeting a token's session needs SeTcbPrivilege.
[[nodiscard]] std::expected<UniqueHandle, CaptureHostError> system_token_for_session(DWORD session) {
    if (!win::enable_privilege(SE_TCB_NAME)) {
        return std::unexpected(make_error(CaptureHostError::Code::launch_failed, GetLastError(), "enable SeTcbPrivilege"));
    }
    HANDLE raw_self = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &raw_self) == FALSE) {
        return std::unexpected(make_error(CaptureHostError::Code::launch_failed, GetLastError(), "OpenProcessToken"));
    }
    const UniqueHandle self_token(raw_self);
    HANDLE             raw_dup = nullptr;
    if (DuplicateTokenEx(self_token.get(), TOKEN_ALL_ACCESS, nullptr, SecurityIdentification, TokenPrimary, &raw_dup) ==
        FALSE) {
        return std::unexpected(make_error(CaptureHostError::Code::launch_failed, GetLastError(), "DuplicateTokenEx"));
    }
    UniqueHandle dup(raw_dup);
    if (SetTokenInformation(dup.get(), TokenSessionId, &session, sizeof(session)) == FALSE) {
        return std::unexpected(
            make_error(CaptureHostError::Code::launch_failed, GetLastError(), "SetTokenInformation(TokenSessionId)"));
    }
    return dup;
}

[[nodiscard]] std::expected<UniqueHandle, CaptureHostError> launch_capture(DWORD               session,
                                                                            const std::wstring& pipe_name,
                                                                            const std::wstring& input_pipe_name,
                                                                            const std::wstring& clipboard_pipe_name,
                                                                            bool                clipboard_listen) {
    auto directory = service_directory();
    if (!directory.has_value()) {
        return std::unexpected(directory.error());
    }
    const std::wstring executable = *directory + std::wstring(capture_executable);
    std::wstring       command_line =
        std::format(L"\"{}\" --pipe {} --input-pipe {}", executable, pipe_name, input_pipe_name);
    if (!clipboard_pipe_name.empty()) {
        command_line += std::format(L" --clipboard-pipe {}", clipboard_pipe_name);
        if (clipboard_listen) {
            command_line += L" --clipboard-listen";
        }
    }
    std::wstring desktop = L"winsta0\\default";

    auto token = system_token_for_session(session);
    if (!token.has_value()) {
        return std::unexpected(token.error());
    }

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    // Starts on the normal desktop; the helper re-attaches its own threads to
    // whichever desktop holds input (see capture/desktop.hpp) and so follows
    // the switch to the secure desktop on its own. Environment is inherited
    // from this SYSTEM service, so the helper logs under SYSTEM's %TEMP%
    // (C:\Windows\Temp), which it can always write.
    startup.lpDesktop = desktop.data();
    PROCESS_INFORMATION process{};
    const BOOL          launched =
        CreateProcessAsUserW(token->get(), executable.c_str(), command_line.data(), nullptr, nullptr, FALSE,
                             CREATE_NO_WINDOW, nullptr, directory->c_str(), &startup, &process);
    if (launched == FALSE) {
        return std::unexpected(make_error(CaptureHostError::Code::launch_failed, GetLastError(), "CreateProcessAsUserW"));
    }

    CloseHandle(process.hThread);
    return UniqueHandle(process.hProcess);
}

// Waits for an overlapped operation on `pipe` that returned
// ERROR_IO_PENDING. If `stop_event` fires, hawk-capture exits, or
// `timeout_ms` runs out first, the operation is cancelled — and waited on,
// so `overlapped` is never left in use — and ERROR_OPERATION_ABORTED,
// ERROR_BROKEN_PIPE or ERROR_TIMEOUT is returned.
[[nodiscard]] DWORD finish_overlapped(HANDLE pipe, OVERLAPPED& overlapped, HANDLE stop_event, HANDLE process,
                                      DWORD& transferred, DWORD timeout_ms = INFINITE) {
    const std::array<HANDLE, 3> waits{overlapped.hEvent, stop_event, process};
    const DWORD wait = WaitForMultipleObjects(static_cast<DWORD>(waits.size()), waits.data(), FALSE, timeout_ms);
    if (wait != WAIT_OBJECT_0) {
        CancelIoEx(pipe, &overlapped);
        GetOverlappedResult(pipe, &overlapped, &transferred, TRUE);
        if (wait == WAIT_OBJECT_0 + 1) {
            return ERROR_OPERATION_ABORTED;
        }
        return wait == WAIT_TIMEOUT ? static_cast<DWORD>(ERROR_TIMEOUT) : static_cast<DWORD>(ERROR_BROKEN_PIPE);
    }
    if (GetOverlappedResult(pipe, &overlapped, &transferred, FALSE) == FALSE) {
        return GetLastError();
    }
    return NO_ERROR;
}

// The pipe names are predictable and the DACL admits any SYSTEM process, so
// whoever connected first isn't necessarily hawk-capture. Anyone else is
// disconnected: they'd otherwise be fed the viewer's keystrokes, or get to
// forge the video stream.
[[nodiscard]] DWORD verify_client(HANDLE pipe, HANDLE process) {
    ULONG client_pid = 0;
    if (GetNamedPipeClientProcessId(pipe, &client_pid) == FALSE) {
        return GetLastError();
    }
    if (client_pid != GetProcessId(process)) {
        spdlog::error("capture: process {} connected to a hawk-capture pipe in its place; disconnecting it",
                      client_pid);
        DisconnectNamedPipe(pipe);
        return ERROR_ACCESS_DENIED;
    }
    return NO_ERROR;
}

// Waits for hawk-capture to open `pipe`, then checks it's really
// hawk-capture that did. `io_event` is the caller's OVERLAPPED event.
[[nodiscard]] DWORD connect_pipe(HANDLE pipe, HANDLE io_event, HANDLE stop_event, HANDLE process) {
    OVERLAPPED overlapped{};
    overlapped.hEvent = io_event;
    ResetEvent(io_event);
    if (ConnectNamedPipe(pipe, &overlapped) == FALSE) {
        const DWORD error = GetLastError();
        if (error == ERROR_IO_PENDING) {
            DWORD transferred = 0;
            if (const DWORD result = finish_overlapped(pipe, overlapped, stop_event, process, transferred);
                result != NO_ERROR) {
                return result;
            }
        } else if (error != ERROR_PIPE_CONNECTED) {
            return error;
        }
    }
    return verify_client(pipe, process);
}

// Fills `out` from `pipe`, however many reads that takes.
[[nodiscard]] DWORD read_exact(HANDLE pipe, HANDLE io_event, HANDLE stop_event, HANDLE process,
                               std::span<std::byte> out) {
    std::size_t done = 0;
    while (done < out.size()) {
        const auto chunk =
            static_cast<DWORD>(std::min<std::size_t>(out.size() - done, std::numeric_limits<DWORD>::max()));
        OVERLAPPED overlapped{};
        overlapped.hEvent = io_event;
        ResetEvent(io_event);

        DWORD transferred = 0;
        if (ReadFile(pipe, out.subspan(done).data(), chunk, nullptr, &overlapped) != FALSE) {
            GetOverlappedResult(pipe, &overlapped, &transferred, FALSE);
        } else if (const DWORD error = GetLastError(); error != ERROR_IO_PENDING) {
            return error;
        } else if (const DWORD result = finish_overlapped(pipe, overlapped, stop_event, process, transferred);
                   result != NO_ERROR) {
            return result;
        }
        done += transferred;
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
    DWORD             session = 0;  // the console session hawk-capture was launched into

    // The input pipe is written from the thread that sends input, never from
    // the reader thread, so it gets its own OVERLAPPED event.
    UniqueHandle input_pipe;
    UniqueHandle input_event;
    bool         input_connected = false;
    // The ConnectNamedPipe on the input pipe, while it waits for hawk-capture.
    // It lives here, not on a stack, because it stays in flight across calls.
    OVERLAPPED   input_connect{};
    bool         input_connect_pending = false;

    // The clipboard pipe, when the config allows the clipboard: read on its
    // own thread (which also waits for hawk-capture to connect it), written
    // from the thread that sends input, each with an OVERLAPPED event.
    UniqueHandle      clipboard_pipe;
    UniqueHandle      clipboard_read_event;
    UniqueHandle      clipboard_write_event;
    std::jthread      clipboard_reader;
    std::atomic<bool> clipboard_connected{false};
    bool              clipboard_failed = false;

    // Whether hawk-capture has opened the input pipe yet, without waiting for
    // it: it does so only once its D3D device and duplication are up, which
    // can take a while, and a viewer may click before then. Returns
    // ERROR_IO_INCOMPLETE while it hasn't — the event is dropped, and the
    // next one asks again.
    [[nodiscard]] DWORD poll_input_connection() {
        if (!input_connect_pending) {
            input_connect = OVERLAPPED{};
            input_connect.hEvent = input_event.get();
            ResetEvent(input_event.get());
            if (ConnectNamedPipe(input_pipe.get(), &input_connect) == FALSE) {
                const DWORD error = GetLastError();
                if (error == ERROR_IO_PENDING) {
                    input_connect_pending = true;
                } else if (error != ERROR_PIPE_CONNECTED) {
                    return error;
                }
            }
        }
        if (input_connect_pending) {
            DWORD transferred = 0;
            if (GetOverlappedResult(input_pipe.get(), &input_connect, &transferred, FALSE) == FALSE) {
                const DWORD error = GetLastError();
                input_connect_pending = error == ERROR_IO_INCOMPLETE;
                return error;
            }
            input_connect_pending = false;
        }
        return verify_client(input_pipe.get(), process.get());
    }

    // Closes the input pipe, first cancelling a connect still in flight so
    // `input_connect` is never left in use.
    void close_input() noexcept {
        if (input_connect_pending) {
            CancelIoEx(input_pipe.get(), &input_connect);
            DWORD transferred = 0;
            GetOverlappedResult(input_pipe.get(), &input_connect, &transferred, TRUE);
            input_connect_pending = false;
        }
        input_pipe.reset();
        input_connected = false;
    }

    // Closes the input pipe for the rest of this run. Whatever went wrong
    // would go wrong the same way for every event after it — and a write
    // hawk-capture isn't taking would hold the relay thread up for the full
    // timeout each time — so there's no retrying it.
    void give_up_on_input(std::string_view what, DWORD error) {
        spdlog::warn("capture: {} (Win32 error {}); giving up on input until capture restarts", what, error);
        close_input();
    }

    // The pipe is message-mode, so one packet is one message: a write either
    // goes through whole or not at all.
    [[nodiscard]] bool write_input(const ipc::InputPacket& packet) {
        if (!input_pipe) {
            return false;
        }
        if (!input_connected) {
            if (const DWORD result = poll_input_connection(); result == ERROR_IO_INCOMPLETE) {
                return false;  // hawk-capture is still starting up
            } else if (result != NO_ERROR) {
                give_up_on_input("connecting hawk-capture's input pipe failed", result);
                return false;
            }
            input_connected = true;
        }

        OVERLAPPED overlapped{};
        overlapped.hEvent = input_event.get();
        ResetEvent(input_event.get());
        DWORD transferred = 0;
        DWORD result = NO_ERROR;
        if (WriteFile(input_pipe.get(), &packet, sizeof(packet), nullptr, &overlapped) != FALSE) {
            GetOverlappedResult(input_pipe.get(), &overlapped, &transferred, FALSE);
        } else if (result = GetLastError(); result == ERROR_IO_PENDING) {
            result = finish_overlapped(input_pipe.get(), overlapped, stop_event.get(), process.get(), transferred,
                                       input_write_timeout_ms);
        }
        if (result != NO_ERROR) {
            give_up_on_input("sending input to hawk-capture failed", result);
            return false;
        }
        return transferred == sizeof(packet);
    }

    [[nodiscard]] DWORD read_exact(std::span<std::byte> out) {
        return hawk::service::read_exact(pipe.get(), io_event.get(), stop_event.get(), process.get(), out);
    }

    // header || UTF-8 text, in one write. Never blocks on a hawk-capture
    // that hasn't connected yet; a write that fails or times out closes
    // the clipboard for the rest of the run, as with input.
    [[nodiscard]] bool write_clipboard(ipc::ClipboardKind kind, std::string_view text) {
        if (!clipboard_pipe || clipboard_failed) {
            return false;
        }
        if (!clipboard_connected.load()) {
            spdlog::info("capture: hawk-capture hasn't opened the clipboard pipe yet; dropping the request");
            return false;
        }
        if (text.size() > ipc::max_clipboard_size) {
            return false;
        }
        const ipc::ClipboardPacketHeader header{.size = static_cast<std::uint32_t>(text.size()),
                                                .kind = static_cast<std::uint8_t>(kind)};
        std::vector<std::byte> message(sizeof(header) + text.size());
        std::memcpy(message.data(), &header, sizeof(header));
        std::memcpy(message.data() + sizeof(header), text.data(), text.size());

        OVERLAPPED overlapped{};
        overlapped.hEvent = clipboard_write_event.get();
        ResetEvent(clipboard_write_event.get());
        DWORD transferred = 0;
        DWORD result = NO_ERROR;
        if (WriteFile(clipboard_pipe.get(), message.data(), static_cast<DWORD>(message.size()), nullptr,
                      &overlapped) != FALSE) {
            GetOverlappedResult(clipboard_pipe.get(), &overlapped, &transferred, FALSE);
        } else if (result = GetLastError(); result == ERROR_IO_PENDING) {
            result = finish_overlapped(clipboard_pipe.get(), overlapped, stop_event.get(), process.get(), transferred,
                                       clipboard_write_timeout_ms);
        }
        if (result != NO_ERROR || transferred != message.size()) {
            spdlog::warn("capture: sending the clipboard to hawk-capture failed (Win32 error {}); giving up on the "
                         "clipboard until capture restarts",
                         result);
            clipboard_failed = true;
            return false;
        }
        return true;
    }

    void read_clipboard(const ClipboardHandler& on_clipboard) {
        const HANDLE pipe_handle = clipboard_pipe.get();
        const HANDLE event = clipboard_read_event.get();
        DWORD        result = connect_pipe(pipe_handle, event, stop_event.get(), process.get());
        if (result == NO_ERROR) {
            clipboard_connected.store(true);
        }
        std::string text;
        while (result == NO_ERROR) {
            ipc::ClipboardPacketHeader header{};
            result = hawk::service::read_exact(pipe_handle, event, stop_event.get(), process.get(),
                                               std::as_writable_bytes(std::span(&header, 1)));
            if (result != NO_ERROR) {
                break;
            }
            const auto kind = static_cast<ipc::ClipboardKind>(header.kind);
            if (header.magic != ipc::clipboard_packet_magic || header.size > ipc::max_clipboard_size ||
                (kind != ipc::ClipboardKind::text && kind != ipc::ClipboardKind::changed)) {
                spdlog::error("capture: malformed clipboard message from hawk-capture, closing the clipboard");
                break;
            }
            text.resize(header.size);
            result = hawk::service::read_exact(pipe_handle, event, stop_event.get(), process.get(),
                                               std::as_writable_bytes(std::span(text)));
            if (result != NO_ERROR) {
                break;
            }
            if (on_clipboard) {
                on_clipboard(kind, text);
            }
        }
        if (result != NO_ERROR && result != ERROR_OPERATION_ABORTED && result != ERROR_BROKEN_PIPE) {
            spdlog::warn("capture: reading the clipboard from hawk-capture failed: Win32 error {}", result);
        }
        clipboard_connected.store(false);
    }

    void read_packets(const PacketHandler& on_packet) {
        DWORD result = connect_pipe(pipe.get(), io_event.get(), stop_event.get(), process.get());
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
            DWORD exit_code = STILL_ACTIVE;
            GetExitCodeProcess(process.get(), &exit_code);
            if (exit_code == STILL_ACTIVE) {
                spdlog::warn("capture: hawk-capture closed the pipe");
            } else {
                spdlog::warn("capture: hawk-capture exited with code {:#x}", exit_code);
            }
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

std::expected<void, CaptureHostError> CaptureHost::start(PacketHandler on_packet, CaptureOptions options,
                                                         ClipboardHandler on_clipboard) {
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

    // Nobody has to be signed in: hawk-capture runs as SYSTEM, so with no
    // user it captures the sign-in screen, which is how a machine that just
    // restarted gets signed in to remotely.

    static std::atomic<std::uint32_t> pipe_counter{0};
    const std::uint32_t               serial = pipe_counter.fetch_add(1);
    const std::wstring                pipe_name =
        std::format(L"\\\\.\\pipe\\hawk-capture-{}-{}", GetCurrentProcessId(), serial);
    const std::wstring input_pipe_name =
        std::format(L"\\\\.\\pipe\\hawk-input-{}-{}", GetCurrentProcessId(), serial);
    const std::wstring clipboard_pipe_name =
        options.clipboard ? std::format(L"\\\\.\\pipe\\hawk-clip-{}-{}", GetCurrentProcessId(), serial)
                          : std::wstring{};

    auto pipe = create_pipe(pipe_name, PIPE_ACCESS_INBOUND, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE,
                            capture_client_access, 0, pipe_buffer_size);
    if (!pipe.has_value()) {
        return std::unexpected(pipe.error());
    }
    auto input_pipe = create_pipe(input_pipe_name, PIPE_ACCESS_OUTBOUND,
                                  PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, input_client_access, input_buffer_size,
                                  0);
    if (!input_pipe.has_value()) {
        return std::unexpected(input_pipe.error());
    }
    UniqueHandle clipboard_pipe;
    if (options.clipboard) {
        auto created = create_pipe(clipboard_pipe_name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE,
                                   clipboard_client_access, clipboard_buffer_size, clipboard_buffer_size);
        if (!created.has_value()) {
            return std::unexpected(created.error());
        }
        clipboard_pipe = std::move(*created);
    }

    UniqueHandle stop_event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    UniqueHandle io_event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    UniqueHandle input_event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    UniqueHandle clipboard_read_event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    UniqueHandle clipboard_write_event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!stop_event || !io_event || !input_event || !clipboard_read_event || !clipboard_write_event) {
        return std::unexpected(make_error(CaptureHostError::Code::pipe_failed, GetLastError(), "CreateEventW"));
    }

    auto process =
        launch_capture(session, pipe_name, input_pipe_name, clipboard_pipe_name, options.clipboard_listen);
    if (!process.has_value()) {
        return std::unexpected(process.error());
    }

    impl_->pipe = std::move(*pipe);
    impl_->process = std::move(*process);
    impl_->stop_event = std::move(stop_event);
    impl_->io_event = std::move(io_event);
    impl_->input_pipe = std::move(*input_pipe);
    impl_->input_event = std::move(input_event);
    impl_->input_connected = false;
    impl_->clipboard_pipe = std::move(clipboard_pipe);
    impl_->clipboard_read_event = std::move(clipboard_read_event);
    impl_->clipboard_write_event = std::move(clipboard_write_event);
    impl_->clipboard_connected.store(false);
    impl_->clipboard_failed = false;
    impl_->session = session;
    impl_->running.store(true);
    impl_->reader = std::jthread([impl = impl_.get(), handler = std::move(on_packet)] { impl->read_packets(handler); });
    if (impl_->clipboard_pipe) {
        impl_->clipboard_reader = std::jthread(
            [impl = impl_.get(), handler = std::move(on_clipboard)] { impl->read_clipboard(handler); });
    }

    spdlog::info("capture: launched hawk-capture in session {}", session);
    return {};
}

bool CaptureHost::send_input(const ipc::InputPacket& packet) {
    if (!impl_->running.load()) {
        return false;
    }
    return impl_->write_input(packet);
}

bool CaptureHost::send_clipboard(ipc::ClipboardKind kind, std::string_view text) {
    if (!impl_->running.load()) {
        return false;
    }
    return impl_->write_clipboard(kind, text);
}

void CaptureHost::stop() noexcept {
    if (!impl_->process) {
        return;
    }

    SetEvent(impl_->stop_event.get());
    if (impl_->reader.joinable()) {
        impl_->reader.join();
    }
    if (impl_->clipboard_reader.joinable()) {
        impl_->clipboard_reader.join();
    }
    impl_->clipboard_pipe.reset();
    impl_->clipboard_read_event.reset();
    impl_->clipboard_write_event.reset();

    // Closing the input pipe is also what tells hawk-capture's input reader
    // to let go of whatever it is still holding down.
    impl_->close_input();
    impl_->input_event.reset();

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

std::uint32_t CaptureHost::session() const noexcept {
    return impl_->session;
}

}  // namespace hawk::service
