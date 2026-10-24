#include "clipboard.hpp"

#include "clipboard_image.hpp"
#include "common/clipboard_pipe.hpp"

#include <windows.h>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <format>
#include <future>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace hawk::capture {

namespace {

namespace ipc = hawk::ipc;

// Posted to the clipboard window: a request read off the pipe (wParam the
// ClipboardKind, lParam a std::string* the window takes ownership of), and
// the signal to shut down.
constexpr UINT kRequestMessage = WM_APP + 1;
constexpr UINT kQuitMessage = WM_APP + 2;

// Applications often put several formats on the clipboard one after the
// other, each raising WM_CLIPBOARDUPDATE: wait for them to settle before
// reading, so one copy is one report.
constexpr UINT_PTR kSettleTimer = 1;
constexpr UINT     kSettleMs = 150;

// Someone else may have the clipboard open for a moment.
constexpr int  kOpenAttempts = 10;
constexpr auto kOpenRetryDelay = std::chrono::milliseconds(20);

constexpr DWORD kWriteTimeoutMs = 2000;

constexpr wchar_t kWindowClass[] = L"HawkCaptureClipboard";

class ClipboardScope {
public:
    explicit ClipboardScope(HWND owner) {
        for (int attempt = 0; attempt < kOpenAttempts; ++attempt) {
            if (OpenClipboard(owner) != FALSE) {
                open_ = true;
                return;
            }
            std::this_thread::sleep_for(kOpenRetryDelay);
        }
    }
    ~ClipboardScope() {
        if (open_) {
            CloseClipboard();
        }
    }

    ClipboardScope(const ClipboardScope&) = delete;
    ClipboardScope& operator=(const ClipboardScope&) = delete;
    ClipboardScope(ClipboardScope&&) = delete;
    ClipboardScope& operator=(ClipboardScope&&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

private:
    bool open_ = false;
};

[[nodiscard]] std::optional<std::wstring> to_utf16(std::string_view text) {
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

// UTF-8 of at most `limit` bytes, cut between characters.
[[nodiscard]] std::string to_utf8(std::wstring_view text, std::size_t limit) {
    // Each UTF-16 unit is at most 3 bytes of UTF-8, so no more than `limit`
    // units are ever needed; don't split a surrogate pair taking them.
    if (text.size() > limit) {
        std::size_t end = limit;
        if (end > 0 && text[end - 1] >= 0xD800 && text[end - 1] <= 0xDBFF) {
            --end;
        }
        text = text.substr(0, end);
    }
    if (text.empty()) {
        return {};
    }
    const int length =
        WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (length <= 0) {
        return {};
    }
    std::string utf8(static_cast<std::size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), utf8.data(), length, nullptr,
                        nullptr);
    if (utf8.size() > limit) {
        std::size_t end = limit;
        while (end > 0 && (static_cast<unsigned char>(utf8[end]) & 0xC0U) == 0x80U) {
            --end;
        }
        utf8.resize(end);
    }
    return utf8;
}

// The most a packed DIB worth reading can be: the largest header, its
// masks and a colour table, then 32-bit pixels up to the limit, and a little
// for GlobalAlloc's rounding. Anything larger is too large to send anyway.
constexpr std::size_t kMaxDibBytes =
    sizeof(BITMAPV5HEADER) + 12 + 256 * 4 + ipc::max_clipboard_image_pixels * 4 + 64 * 1024;

// A copy of what the clipboard holds in `format`, or nullopt when it holds
// none; empty when it's over `max_bytes`, so nothing that large is copied.
// The clipboard must be open.
[[nodiscard]] std::optional<ImageBytes> clipboard_bytes(UINT format, std::size_t max_bytes) {
    HANDLE data = GetClipboardData(format);
    if (data == nullptr) {
        return std::nullopt;
    }
    if (GlobalSize(data) > max_bytes) {
        return ImageBytes{};
    }
    const auto* locked = static_cast<const std::byte*>(GlobalLock(data));
    if (locked == nullptr) {
        return std::nullopt;
    }
    ImageBytes bytes(locked, locked + GlobalSize(data));
    GlobalUnlock(data);
    return bytes;
}

// Puts a copy of `bytes` on the open clipboard as `format`.
[[nodiscard]] bool put_bytes(UINT format, std::span<const std::byte> bytes) {
    HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes.size());
    if (memory == nullptr) {
        return false;
    }
    if (void* locked = GlobalLock(memory); locked != nullptr) {
        std::memcpy(locked, bytes.data(), bytes.size());
        GlobalUnlock(memory);
    }
    if (SetClipboardData(format, memory) == nullptr) {
        GlobalFree(memory);
        return false;
    }
    return true;  // the clipboard owns the memory now
}

[[nodiscard]] std::string_view as_text(std::span<const std::byte> bytes) {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

}  // namespace

struct ClipboardChannel::Impl {
    HANDLE pipe = INVALID_HANDLE_VALUE;
    HANDLE read_event = nullptr;   // manual-reset; the reader's OVERLAPPED event
    HANDLE write_event = nullptr;  // manual-reset; the window thread's
    HANDLE stop_event = nullptr;   // manual-reset; set by close()
    bool   listen = false;
    bool   images = false;
    // The "PNG" clipboard format browsers and Office put pictures on as.
    UINT png_format = 0;

    std::atomic<HWND> window{nullptr};
    std::jthread      window_thread;
    std::jthread      reader;

    // Window thread only: the sequence number of the clipboard as `set`
    // left it (not a copy anyone made), and of the last copy reported.
    DWORD own_sequence = 0;
    DWORD reported_sequence = 0;
    // And the text `set` put there: clipboard history and the like can
    // touch the clipboard again after us, moving the sequence number on
    // without anyone copying anything. Likewise the picture.
    std::string own_text;
    std::string own_image;

    ~Impl() { close(); }

    void close() noexcept {
        if (stop_event != nullptr) {
            SetEvent(stop_event);
        }
        if (reader.joinable()) {
            reader.join();
        }
        if (const HWND hwnd = window.load(); hwnd != nullptr) {
            PostMessageW(hwnd, kQuitMessage, 0, 0);
        }
        if (window_thread.joinable()) {
            window_thread.join();
        }
        for (HANDLE* handle : {&read_event, &write_event, &stop_event}) {
            if (*handle != nullptr) {
                CloseHandle(*handle);
                *handle = nullptr;
            }
        }
        if (pipe != INVALID_HANDLE_VALUE) {
            CloseHandle(pipe);
            pipe = INVALID_HANDLE_VALUE;
        }
    }

    // --- the pipe --------------------------------------------------------------

    [[nodiscard]] DWORD read_exact(std::span<std::byte> out) {
        std::size_t done = 0;
        while (done < out.size()) {
            OVERLAPPED overlapped{};
            overlapped.hEvent = read_event;
            ResetEvent(read_event);

            DWORD transferred = 0;
            if (ReadFile(pipe, out.subspan(done).data(), static_cast<DWORD>(out.size() - done), nullptr,
                         &overlapped) != FALSE) {
                GetOverlappedResult(pipe, &overlapped, &transferred, FALSE);
            } else if (const DWORD error = GetLastError(); error != ERROR_IO_PENDING) {
                return error;
            } else {
                const std::array<HANDLE, 2> waits{read_event, stop_event};
                const DWORD                 wait =
                    WaitForMultipleObjects(static_cast<DWORD>(waits.size()), waits.data(), FALSE, INFINITE);
                if (wait != WAIT_OBJECT_0) {
                    CancelIoEx(pipe, &overlapped);
                    GetOverlappedResult(pipe, &overlapped, &transferred, TRUE);
                    return ERROR_OPERATION_ABORTED;
                }
                if (GetOverlappedResult(pipe, &overlapped, &transferred, FALSE) == FALSE) {
                    return GetLastError();
                }
            }
            if (transferred == 0) {
                return ERROR_BROKEN_PIPE;
            }
            done += transferred;
        }
        return NO_ERROR;
    }

    // Reads requests until hawk-service closes the pipe or close() is
    // called, and hands each one to the window thread.
    void read_requests() {
        for (;;) {
            ipc::ClipboardPacketHeader header{};
            DWORD                      result = read_exact(std::as_writable_bytes(std::span(&header, 1)));
            const auto                 kind = static_cast<ipc::ClipboardKind>(header.kind);
            const bool known = kind == ipc::ClipboardKind::set || kind == ipc::ClipboardKind::get ||
                               (images && kind == ipc::ClipboardKind::set_image);
            if (result == NO_ERROR &&
                (header.magic != ipc::clipboard_packet_magic || !known || header.size > ipc::max_payload(kind))) {
                spdlog::error("clipboard: malformed request from hawk-service, closing the clipboard");
                return;
            }
            auto text = std::make_unique<std::string>(header.size, '\0');
            if (result == NO_ERROR) {
                result = read_exact(std::as_writable_bytes(std::span(*text)));
            }
            if (result != NO_ERROR) {
                if (result == ERROR_BROKEN_PIPE) {
                    spdlog::info("clipboard: hawk-service closed the clipboard pipe");
                } else if (result != ERROR_OPERATION_ABORTED) {
                    spdlog::error("clipboard: reading from hawk-service failed: Win32 error {}", result);
                }
                return;
            }
            const HWND hwnd = window.load();
            if (hwnd != nullptr &&
                PostMessageW(hwnd, kRequestMessage, header.kind, reinterpret_cast<LPARAM>(text.get())) != FALSE) {
                static_cast<void>(text.release());  // the window owns it now
            }
        }
    }

    // Window thread only.
    void write_message(ipc::ClipboardKind kind, std::string_view text) {
        const ipc::ClipboardPacketHeader header{.size = static_cast<std::uint32_t>(text.size()),
                                                .kind = static_cast<std::uint8_t>(kind)};
        std::vector<std::byte> message(sizeof(header) + text.size());
        std::memcpy(message.data(), &header, sizeof(header));
        std::memcpy(message.data() + sizeof(header), text.data(), text.size());

        OVERLAPPED overlapped{};
        overlapped.hEvent = write_event;
        ResetEvent(write_event);
        DWORD transferred = 0;
        if (WriteFile(pipe, message.data(), static_cast<DWORD>(message.size()), nullptr, &overlapped) != FALSE) {
            GetOverlappedResult(pipe, &overlapped, &transferred, FALSE);
        } else if (const DWORD error = GetLastError(); error != ERROR_IO_PENDING) {
            spdlog::warn("clipboard: sending to hawk-service failed: Win32 error {}", error);
            return;
        } else {
            const std::array<HANDLE, 2> waits{write_event, stop_event};
            const DWORD wait = WaitForMultipleObjects(static_cast<DWORD>(waits.size()), waits.data(), FALSE,
                                                      kWriteTimeoutMs);
            if (wait != WAIT_OBJECT_0) {
                CancelIoEx(pipe, &overlapped);
            }
            GetOverlappedResult(pipe, &overlapped, &transferred, TRUE);
        }
        if (transferred != message.size()) {
            spdlog::warn("clipboard: sending to hawk-service didn't complete");
        }
    }

    // --- the clipboard (window thread only) -----------------------------------

    void set_text(HWND hwnd, std::string_view text) {
        const auto wide = to_utf16(text);
        if (!wide.has_value()) {
            spdlog::warn("clipboard: the text to set isn't valid UTF-8");
            return;
        }
        {
            const ClipboardScope clipboard(hwnd);
            if (!clipboard.is_open()) {
                spdlog::warn("clipboard: couldn't open the clipboard to set it: Win32 error {}", GetLastError());
                return;
            }
            EmptyClipboard();
            const std::size_t bytes = (wide->size() + 1) * sizeof(wchar_t);
            HGLOBAL           memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
            if (memory == nullptr) {
                return;
            }
            if (void* locked = GlobalLock(memory); locked != nullptr) {
                std::memcpy(locked, wide->c_str(), bytes);
                GlobalUnlock(memory);
            }
            if (SetClipboardData(CF_UNICODETEXT, memory) == nullptr) {
                spdlog::warn("clipboard: SetClipboardData failed: Win32 error {}", GetLastError());
                GlobalFree(memory);
                return;
            }
            // The clipboard owns the memory now.
        }
        // Remember the clipboard as it was left, once closed, so the copy
        // just made isn't reported back as someone else's.
        own_sequence = GetClipboardSequenceNumber();
        own_text = text;
        own_image.clear();
        spdlog::info("clipboard: set ({} bytes)", text.size());
    }

    // Puts a viewer's PNG on the clipboard as itself, and as CF_DIBV5 and
    // CF_DIB for the apps that only paste those.
    void set_image(HWND hwnd, const std::string& png) {
        auto bitmap = decode_png(std::as_bytes(std::span(png)));
        if (!bitmap.has_value()) {
            spdlog::warn("clipboard: the picture to set doesn't decode: {}", bitmap.error());
            return;
        }
        auto       dibv5 = write_dibv5(*bitmap);
        auto       dib = write_dib(*bitmap);
        const auto width = bitmap->width;
        const auto height = bitmap->height;
        // An 8K picture is ~130 MB a copy: each is let go as soon as it's
        // been handed over, so no more than two are held at once.
        ImageBytes{}.swap(bitmap->bgra);
        {
            const ClipboardScope clipboard(hwnd);
            if (!clipboard.is_open()) {
                spdlog::warn("clipboard: couldn't open the clipboard to set it: Win32 error {}", GetLastError());
                return;
            }
            EmptyClipboard();
            bool put = png_format == 0 || put_bytes(png_format, std::as_bytes(std::span(png)));
            put = put_bytes(CF_DIBV5, dibv5) && put;
            ImageBytes{}.swap(dibv5);
            put = put_bytes(CF_DIB, dib) && put;
            ImageBytes{}.swap(dib);
            if (!put) {
                spdlog::warn("clipboard: SetClipboardData failed: Win32 error {}", GetLastError());
            }
        }
        own_sequence = GetClipboardSequenceNumber();
        own_text.clear();
        own_image = png;
        spdlog::info("clipboard: set a {}x{} picture ({} bytes of PNG)", width, height, png.size());
    }

    [[nodiscard]] bool has_image() const {
        return (png_format != 0 && IsClipboardFormatAvailable(png_format) != FALSE) ||
               IsClipboardFormatAvailable(CF_DIBV5) != FALSE || IsClipboardFormatAvailable(CF_DIB) != FALSE;
    }

    // The clipboard's picture as PNG: nullopt when it holds none, empty
    // when it's too large to send (or can't be read). PNG an app put there
    // goes as it is; a bitmap is encoded, once the clipboard is closed
    // again so nobody waits on it meanwhile.
    [[nodiscard]] std::optional<std::string> read_image(HWND hwnd) {
        if (!has_image()) {
            return std::nullopt;
        }
        std::optional<ImageBytes> png;
        std::optional<ImageBytes> dib;
        {
            const ClipboardScope clipboard(hwnd);
            if (!clipboard.is_open()) {
                spdlog::warn("clipboard: couldn't open the clipboard to read it: Win32 error {}", GetLastError());
                return std::nullopt;
            }
            if (png_format != 0) {
                png = clipboard_bytes(png_format, ipc::max_clipboard_image_size);
            }
            if (!png.has_value()) {
                dib = clipboard_bytes(CF_DIBV5, kMaxDibBytes);
                if (!dib.has_value()) {
                    dib = clipboard_bytes(CF_DIB, kMaxDibBytes);
                }
            }
        }
        if (png.has_value()) {
            const auto size = ipc::png_size(*png);
            if (size.has_value() && ipc::image_fits(*size) && png->size() <= ipc::max_clipboard_image_size) {
                return std::string(as_text(*png));
            }
            spdlog::info("clipboard: the picture copied ({} bytes of PNG) is too large to send", png->size());
            return std::string{};
        }
        if (!dib.has_value()) {
            return std::nullopt;
        }
        const auto bitmap = read_dib(*dib);
        if (!bitmap.has_value()) {
            spdlog::info("clipboard: the picture copied can't be sent: {}", bitmap.error());
            return std::string{};
        }
        const auto encoded = encode_png(*bitmap);
        if (!encoded.has_value() || encoded->size() > ipc::max_clipboard_image_size) {
            spdlog::info("clipboard: the {}x{} picture copied can't be sent: {}", bitmap->width, bitmap->height,
                         encoded.has_value() ? std::format("{} bytes of PNG is too large", encoded->size())
                                             : encoded.error());
            return std::string{};
        }
        return std::string(as_text(*encoded));
    }

    // The clipboard's text, or nullopt when it holds none.
    [[nodiscard]] std::optional<std::string> get_text(HWND hwnd) {
        if (IsClipboardFormatAvailable(CF_UNICODETEXT) == FALSE) {
            return std::nullopt;
        }
        const ClipboardScope clipboard(hwnd);
        if (!clipboard.is_open()) {
            spdlog::warn("clipboard: couldn't open the clipboard to read it: Win32 error {}", GetLastError());
            return std::nullopt;
        }
        HANDLE data = GetClipboardData(CF_UNICODETEXT);
        if (data == nullptr) {
            return std::nullopt;
        }
        const auto* locked = static_cast<const wchar_t*>(GlobalLock(data));
        if (locked == nullptr) {
            return std::nullopt;
        }
        // Never past the end of the block, whether or not it's terminated.
        const std::size_t units = GlobalSize(data) / sizeof(wchar_t);
        const std::size_t length = std::wstring_view(locked, units).find(L'\0');
        auto text = to_utf8(std::wstring_view(locked, length == std::wstring_view::npos ? units : length),
                            ipc::max_clipboard_size);
        GlobalUnlock(data);
        return text;
    }

    void on_request(HWND hwnd, ipc::ClipboardKind kind, const std::string& payload) {
        if (kind == ipc::ClipboardKind::set) {
            set_text(hwnd, payload);
        } else if (kind == ipc::ClipboardKind::set_image) {
            set_image(hwnd, payload);
        } else if (kind == ipc::ClipboardKind::get) {
            // Text wins over a picture copied with it (cells, a slide);
            // nothing either way reads as empty text: the viewer still gets
            // an answer.
            auto text = get_text(hwnd).value_or(std::string{});
            if (text.empty() && images) {
                if (auto image = read_image(hwnd); image.has_value()) {
                    write_message(ipc::ClipboardKind::image, *image);
                    return;
                }
            }
            write_message(ipc::ClipboardKind::text, text);
        }
    }

    void on_settled(HWND hwnd) {
        const DWORD sequence = GetClipboardSequenceNumber();
        if (sequence == own_sequence || sequence == reported_sequence) {
            return;
        }
        reported_sequence = sequence;
        if (auto text = get_text(hwnd); text.has_value() && !text->empty()) {
            if (*text != own_text) {
                write_message(ipc::ClipboardKind::changed, *text);
            }
            return;
        }
        if (!images) {
            return;
        }
        if (auto image = read_image(hwnd); image.has_value() && (image->empty() || *image != own_image)) {
            write_message(ipc::ClipboardKind::image_changed, *image);
        }
    }

    static LRESULT CALLBACK window_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
        auto* impl = reinterpret_cast<Impl*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        switch (message) {
            case kRequestMessage: {
                const std::unique_ptr<std::string> text(reinterpret_cast<std::string*>(lparam));
                if (impl != nullptr) {
                    impl->on_request(hwnd, static_cast<ipc::ClipboardKind>(wparam), *text);
                }
                return 0;
            }
            case WM_CLIPBOARDUPDATE:
                SetTimer(hwnd, kSettleTimer, kSettleMs, nullptr);
                return 0;
            case WM_TIMER:
                if (wparam == kSettleTimer) {
                    KillTimer(hwnd, kSettleTimer);
                    if (impl != nullptr) {
                        impl->on_settled(hwnd);
                    }
                }
                return 0;
            case kQuitMessage:
                DestroyWindow(hwnd);
                return 0;
            case WM_DESTROY:
                RemoveClipboardFormatListener(hwnd);
                PostQuitMessage(0);
                return 0;
            default:
                return DefWindowProcW(hwnd, message, wparam, lparam);
        }
    }

    void run_window(std::promise<bool>& ready) {
        // WIC, for pictures, is COM.
        const HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        run_window_com(ready);
        if (SUCCEEDED(com)) {
            CoUninitialize();
        }
    }

    void run_window_com(std::promise<bool>& ready) {
        const HINSTANCE instance = GetModuleHandleW(nullptr);
        WNDCLASSEXW     window_class{};
        window_class.cbSize = sizeof(window_class);
        window_class.lpfnWndProc = window_proc;
        window_class.hInstance = instance;
        window_class.lpszClassName = kWindowClass;
        if (RegisterClassExW(&window_class) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
            spdlog::error("clipboard: RegisterClassExW failed: Win32 error {}", GetLastError());
            ready.set_value(false);
            return;
        }
        // Message-only: never shown, and gets no broadcasts; the clipboard
        // listener is all it's for.
        HWND hwnd = CreateWindowExW(0, kWindowClass, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, instance, nullptr);
        if (hwnd == nullptr) {
            spdlog::error("clipboard: CreateWindowExW failed: Win32 error {}", GetLastError());
            ready.set_value(false);
            return;
        }
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
        if (listen && AddClipboardFormatListener(hwnd) == FALSE) {
            spdlog::warn("clipboard: AddClipboardFormatListener failed: Win32 error {}; copies won't be pushed",
                         GetLastError());
        }
        if (images) {
            png_format = RegisterClipboardFormatW(L"PNG");
        }
        // A copy that was already there when the viewer joined isn't news.
        reported_sequence = GetClipboardSequenceNumber();
        window.store(hwnd);
        ready.set_value(true);

        MSG message{};
        while (GetMessageW(&message, nullptr, 0, 0) > 0) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        window.store(nullptr);
        // Requests posted after the window went away were never taken.
        while (PeekMessageW(&message, nullptr, kRequestMessage, kRequestMessage, PM_REMOVE) != FALSE) {
            delete reinterpret_cast<std::string*>(message.lParam);
        }
    }
};

ClipboardChannel::ClipboardChannel() : impl_(std::make_unique<Impl>()) {}

ClipboardChannel::~ClipboardChannel() = default;

bool ClipboardChannel::open(const std::string& pipe_name, bool listen, bool images) {
    // Exactly what hawk-service's DACL grants (clipboard_client_access in
    // service/capture_host.cpp): GENERIC_READ | GENERIC_WRITE would also
    // ask for rights it doesn't.
    constexpr DWORD access = FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    impl_->pipe = CreateFileA(pipe_name.c_str(), access, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    if (impl_->pipe == INVALID_HANDLE_VALUE) {
        spdlog::error("clipboard: failed to open pipe {}: Win32 error {}", pipe_name, GetLastError());
        return false;
    }

    impl_->read_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    impl_->write_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    impl_->stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (impl_->read_event == nullptr || impl_->write_event == nullptr || impl_->stop_event == nullptr) {
        spdlog::error("clipboard: CreateEventW failed: Win32 error {}", GetLastError());
        impl_->close();
        return false;
    }
    impl_->listen = listen;
    impl_->images = images;

    std::promise<bool> ready;
    auto               window_ready = ready.get_future();
    impl_->window_thread = std::jthread([impl = impl_.get(), &ready] { impl->run_window(ready); });
    if (!window_ready.get()) {
        impl_->close();
        return false;
    }
    impl_->reader = std::jthread([impl = impl_.get()] { impl->read_requests(); });
    spdlog::info("clipboard: serving the clipboard{}{}", images ? " with pictures" : "",
                 listen ? ", reporting copies" : "");
    return true;
}

void ClipboardChannel::close() noexcept {
    impl_->close();
}

}  // namespace hawk::capture
