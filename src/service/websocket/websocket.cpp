#include "websocket.hpp"

#include <windows.h>
#include <winhttp.h>

#include <array>
#include <atomic>
#include <charconv>
#include <cstring>
#include <format>
#include <mutex>
#include <utility>

namespace hawk::net {

namespace {

[[nodiscard]] std::wstring utf8_to_wide(std::string_view text) {
    if (text.empty()) {
        return {};
    }
    const int length =
        MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring result(static_cast<std::size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), length);
    return result;
}

[[nodiscard]] std::string wide_to_utf8(std::wstring_view text) {
    if (text.empty()) {
        return {};
    }
    const int length = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                            nullptr, 0, nullptr, nullptr);
    std::string result(static_cast<std::size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), length,
                         nullptr, nullptr);
    return result;
}

// WinHTTP error codes (12000-12186) aren't in the system message table, so a
// plain FormatMessage(FROM_SYSTEM) lookup fails for them and we have to retry
// against winhttp.dll's own message table.
//
// A fixed-size caller-owned buffer (rather than FORMAT_MESSAGE_ALLOCATE_BUFFER)
// is used deliberately: it avoids both a LocalFree cleanup and the
// reinterpret_cast<LPWSTR> that flag's "pass &buffer as if it were the
// buffer itself" idiom otherwise requires. Every Win32/WinHTTP error string
// comfortably fits; a message that somehow doesn't just falls back below.
[[nodiscard]] std::string win_error_message(std::uint32_t native_code) {
    constexpr DWORD base_flags = FORMAT_MESSAGE_IGNORE_INSERTS;
    constexpr std::size_t buffer_capacity = 512;

    std::array<wchar_t, buffer_capacity> buffer{};
    DWORD length = FormatMessageW(base_flags | FORMAT_MESSAGE_FROM_SYSTEM, nullptr, native_code, 0,
                                   buffer.data(), static_cast<DWORD>(buffer.size()), nullptr);

    if (length == 0) {
        if (HMODULE winhttp_module = GetModuleHandleW(L"winhttp.dll"); winhttp_module != nullptr) {
            length = FormatMessageW(base_flags | FORMAT_MESSAGE_FROM_HMODULE, winhttp_module, native_code,
                                     0, buffer.data(), static_cast<DWORD>(buffer.size()), nullptr);
        }
    }

    if (length == 0) {
        return std::format("unknown error {}", native_code);
    }

    std::wstring_view message(buffer.data(), length);
    while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n')) {
        message.remove_suffix(1);
    }
    return wide_to_utf8(message);
}

[[nodiscard]] WebSocketError make_error(WebSocketError::Code code, std::uint32_t native_code,
                                         std::string_view context) {
    return WebSocketError{
        .code = code,
        .native_code = native_code,
        .message = std::format("{}: {}", context, win_error_message(native_code)),
    };
}

[[nodiscard]] WebSocketError make_simple_error(WebSocketError::Code code, std::string message) {
    return WebSocketError{.code = code, .native_code = 0, .message = std::move(message)};
}

struct ParsedUrl {
    bool secure = false;
    std::wstring host;
    std::uint16_t port = 0;
    std::wstring path;
};

constexpr std::string_view wss_scheme = "wss://";
constexpr std::string_view ws_scheme = "ws://";
constexpr std::uint16_t default_wss_port = 443;
constexpr std::uint16_t default_ws_port = 80;

[[nodiscard]] std::expected<ParsedUrl, WebSocketError> parse_url(std::string_view url) {
    bool secure = false;
    std::string_view rest;

    if (url.starts_with(wss_scheme)) {
        secure = true;
        rest = url.substr(wss_scheme.size());
    } else if (url.starts_with(ws_scheme)) {
        secure = false;
        rest = url.substr(ws_scheme.size());
    } else {
        return std::unexpected(make_simple_error(
            WebSocketError::Code::invalid_url,
            std::format("url '{}' must start with ws:// or wss://", url)));
    }

    const auto slash = rest.find('/');
    const std::string_view authority = rest.substr(0, slash);
    const std::string_view path = slash == std::string_view::npos ? std::string_view{"/"} : rest.substr(slash);

    if (authority.empty()) {
        return std::unexpected(
            make_simple_error(WebSocketError::Code::invalid_url, std::format("url '{}' has no host", url)));
    }

    std::string_view host = authority;
    std::uint16_t port = secure ? default_wss_port : default_ws_port;

    if (const auto colon = authority.rfind(':'); colon != std::string_view::npos) {
        host = authority.substr(0, colon);
        const std::string_view port_text = authority.substr(colon + 1);
        const auto parse_result =
            std::from_chars(port_text.data(), port_text.data() + port_text.size(), port);
        if (parse_result.ec != std::errc{} || parse_result.ptr != port_text.data() + port_text.size()) {
            return std::unexpected(make_simple_error(
                WebSocketError::Code::invalid_url, std::format("url '{}' has an invalid port", url)));
        }
    }

    if (host.empty()) {
        return std::unexpected(
            make_simple_error(WebSocketError::Code::invalid_url, std::format("url '{}' has no host", url)));
    }

    return ParsedUrl{
        .secure = secure,
        .host = utf8_to_wide(host),
        .port = port,
        .path = utf8_to_wide(path),
    };
}

[[nodiscard]] std::wstring build_header_block(
    const std::vector<std::pair<std::string, std::string>>& headers) {
    std::wstring block;
    for (const auto& [name, value] : headers) {
        block += utf8_to_wide(name);
        block += L": ";
        block += utf8_to_wide(value);
        block += L"\r\n";
    }
    return block;
}

}  // namespace

std::string_view to_string(WebSocketError::Code code) noexcept {
    switch (code) {
        case WebSocketError::Code::invalid_url:
            return "invalid_url";
        case WebSocketError::Code::connection_failed:
            return "connection_failed";
        case WebSocketError::Code::handshake_failed:
            return "handshake_failed";
        case WebSocketError::Code::send_failed:
            return "send_failed";
        case WebSocketError::Code::receive_failed:
            return "receive_failed";
        case WebSocketError::Code::not_connected:
            return "not_connected";
        case WebSocketError::Code::already_connected:
            return "already_connected";
    }
    return "unknown";
}

std::string to_string(const WebSocketError& error) {
    if (error.native_code != 0) {
        return std::format("[{}] {} (native code {})", to_string(error.code), error.message,
                            error.native_code);
    }
    return std::format("[{}] {}", to_string(error.code), error.message);
}

struct WebSocketClient::Impl {
    std::mutex mutex;
    // WinHTTP allows one send and one receive in flight at a time, so sends
    // from different threads are serialized here; receive() stays unlocked.
    std::mutex send_mutex;
    HINTERNET hSession = nullptr;
    HINTERNET hConnect = nullptr;
    HINTERNET hWebSocket = nullptr;
    std::atomic<bool> connected{false};
};

WebSocketClient::WebSocketClient() : impl_(std::make_unique<Impl>()) {}

WebSocketClient::~WebSocketClient() {
    if (impl_ != nullptr) {
        close();
    }
}

WebSocketClient::WebSocketClient(WebSocketClient&&) noexcept = default;
WebSocketClient& WebSocketClient::operator=(WebSocketClient&&) noexcept = default;

std::expected<void, WebSocketError> WebSocketClient::connect(std::string_view url,
                                                               const ConnectOptions& options) {
    {
        std::scoped_lock lock(impl_->mutex);
        if (impl_->connected.load()) {
            return std::unexpected(make_simple_error(WebSocketError::Code::already_connected,
                                                       "connect() called on an already-connected client"));
        }
    }

    auto parsed = parse_url(url);
    if (!parsed.has_value()) {
        return std::unexpected(parsed.error());
    }

    HINTERNET session = WinHttpOpen(L"hawk-service/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (session == nullptr) {
        return std::unexpected(make_error(WebSocketError::Code::connection_failed, GetLastError(),
                                           "WinHttpOpen"));
    }

    WinHttpSetTimeouts(session, static_cast<int>(options.resolve_timeout.count()),
                        static_cast<int>(options.connect_timeout.count()),
                        static_cast<int>(options.send_timeout.count()),
                        static_cast<int>(options.receive_timeout.count()));

    HINTERNET connect_handle = WinHttpConnect(session, parsed->host.c_str(), parsed->port, 0);
    if (connect_handle == nullptr) {
        WebSocketError error =
            make_error(WebSocketError::Code::connection_failed, GetLastError(), "WinHttpConnect");
        WinHttpCloseHandle(session);
        return std::unexpected(std::move(error));
    }

    HINTERNET request =
        WinHttpOpenRequest(connect_handle, L"GET", parsed->path.c_str(), nullptr, WINHTTP_NO_REFERER,
                           WINHTTP_DEFAULT_ACCEPT_TYPES, parsed->secure ? WINHTTP_FLAG_SECURE : 0);
    if (request == nullptr) {
        WebSocketError error =
            make_error(WebSocketError::Code::handshake_failed, GetLastError(), "WinHttpOpenRequest");
        WinHttpCloseHandle(connect_handle);
        WinHttpCloseHandle(session);
        return std::unexpected(std::move(error));
    }

    if (WinHttpSetOption(request, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0) == FALSE) {
        WebSocketError error = make_error(WebSocketError::Code::handshake_failed, GetLastError(),
                                           "WinHttpSetOption(UPGRADE_TO_WEB_SOCKET)");
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect_handle);
        WinHttpCloseHandle(session);
        return std::unexpected(std::move(error));
    }

    const std::wstring header_block = build_header_block(options.headers);
    const BOOL sent = WinHttpSendRequest(
        request, header_block.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : header_block.c_str(),
        header_block.empty() ? 0 : static_cast<DWORD>(header_block.size()), WINHTTP_NO_REQUEST_DATA, 0, 0,
        0);

    if (sent == FALSE || WinHttpReceiveResponse(request, nullptr) == FALSE) {
        WebSocketError error = make_error(WebSocketError::Code::handshake_failed, GetLastError(),
                                           "WinHttpSendRequest/WinHttpReceiveResponse");
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect_handle);
        WinHttpCloseHandle(session);
        return std::unexpected(std::move(error));
    }

    HINTERNET socket = WinHttpWebSocketCompleteUpgrade(request, 0);
    WinHttpCloseHandle(request);  // superseded by `socket` once upgraded; no longer needed either way.

    if (socket == nullptr) {
        WebSocketError error = make_error(WebSocketError::Code::handshake_failed, GetLastError(),
                                           "WinHttpWebSocketCompleteUpgrade");
        WinHttpCloseHandle(connect_handle);
        WinHttpCloseHandle(session);
        return std::unexpected(std::move(error));
    }

    std::scoped_lock lock(impl_->mutex);
    impl_->hSession = session;
    impl_->hConnect = connect_handle;
    impl_->hWebSocket = socket;
    impl_->connected.store(true);
    return {};
}

std::expected<void, WebSocketError> WebSocketClient::send_text(std::string_view message) {
    HINTERNET socket = nullptr;
    {
        std::scoped_lock lock(impl_->mutex);
        if (!impl_->connected.load()) {
            return std::unexpected(make_simple_error(WebSocketError::Code::not_connected,
                                                       "send_text() called while not connected"));
        }
        socket = impl_->hWebSocket;
    }

    std::scoped_lock send_lock(impl_->send_mutex);
    const DWORD result = WinHttpWebSocketSend(
        socket, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
        const_cast<void*>(static_cast<const void*>(message.data())), static_cast<DWORD>(message.size()));
    if (result != NO_ERROR) {
        return std::unexpected(make_error(WebSocketError::Code::send_failed, result, "WinHttpWebSocketSend"));
    }
    return {};
}

std::expected<void, WebSocketError> WebSocketClient::send_binary(std::span<const std::byte> data) {
    HINTERNET socket = nullptr;
    {
        std::scoped_lock lock(impl_->mutex);
        if (!impl_->connected.load()) {
            return std::unexpected(make_simple_error(WebSocketError::Code::not_connected,
                                                       "send_binary() called while not connected"));
        }
        socket = impl_->hWebSocket;
    }

    std::scoped_lock send_lock(impl_->send_mutex);
    const DWORD result = WinHttpWebSocketSend(
        socket, WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE,
        const_cast<void*>(static_cast<const void*>(data.data())), static_cast<DWORD>(data.size()));
    if (result != NO_ERROR) {
        return std::unexpected(make_error(WebSocketError::Code::send_failed, result, "WinHttpWebSocketSend"));
    }
    return {};
}

std::expected<WebSocketMessage, WebSocketError> WebSocketClient::receive() {
    HINTERNET socket = nullptr;
    {
        std::scoped_lock lock(impl_->mutex);
        if (!impl_->connected.load()) {
            return std::unexpected(
                make_simple_error(WebSocketError::Code::not_connected, "receive() called while not connected"));
        }
        socket = impl_->hWebSocket;
    }

    constexpr std::size_t receive_chunk_size = 4096;
    std::vector<std::byte> accumulated;
    std::array<std::byte, receive_chunk_size> chunk{};

    // Deliberately unlocked for the blocking WinHTTP call below: close(),
    // running on another thread, closes this same handle value to cancel it
    // (a documented WinHTTP pattern) without needing to wait on `mutex`.
    for (;;) {
        DWORD bytes_read = 0;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE buffer_type{};
        const DWORD result = WinHttpWebSocketReceive(socket, chunk.data(), static_cast<DWORD>(chunk.size()),
                                                       &bytes_read, &buffer_type);
        if (result != NO_ERROR) {
            impl_->connected.store(false);
            return std::unexpected(
                make_error(WebSocketError::Code::receive_failed, result, "WinHttpWebSocketReceive"));
        }

        accumulated.insert(accumulated.end(), chunk.begin(),
                            chunk.begin() + static_cast<std::ptrdiff_t>(bytes_read));

        switch (buffer_type) {
            case WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE: {
                impl_->connected.store(false);
                USHORT close_code = 0;
                std::array<char, WINHTTP_WEB_SOCKET_MAX_CLOSE_REASON_LENGTH> reason_buffer{};
                DWORD reason_length = 0;
                WinHttpWebSocketQueryCloseStatus(socket, &close_code, reason_buffer.data(),
                                                  static_cast<DWORD>(reason_buffer.size()), &reason_length);
                return WebSocketCloseInfo{
                    .code = close_code,
                    .reason = std::string(reason_buffer.data(), reason_length),
                };
            }
            case WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE: {
                // std::memcpy (unlike reinterpret_cast<const char*>) copies
                // through object representations without requiring a
                // pointer-type-punning cast between std::byte and char.
                std::string text(accumulated.size(), '\0');
                std::memcpy(text.data(), accumulated.data(), accumulated.size());
                return text;
            }
            case WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE:
                return accumulated;
            case WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE:
            case WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE:
                continue;  // more fragments of the same message are coming.
            default:
                impl_->connected.store(false);
                return std::unexpected(make_simple_error(WebSocketError::Code::receive_failed,
                                                           "WinHttpWebSocketReceive returned an unknown buffer type"));
        }
    }
}

void WebSocketClient::close(std::uint16_t code, std::string_view reason) noexcept {
    if (impl_ == nullptr) {
        return;
    }

    HINTERNET socket = nullptr;
    HINTERNET connect_handle = nullptr;
    HINTERNET session = nullptr;
    {
        std::scoped_lock lock(impl_->mutex);
        if (!impl_->connected.exchange(false)) {
            return;
        }
        socket = std::exchange(impl_->hWebSocket, nullptr);
        connect_handle = std::exchange(impl_->hConnect, nullptr);
        session = std::exchange(impl_->hSession, nullptr);
    }

    // Deliberately done outside `mutex`: a concurrent receive() may already
    // be blocked in WinHttpWebSocketReceive on this same handle value, and
    // closing it from here is what cancels that call (see receive()).
    if (socket != nullptr) {
        constexpr int close_timeout_ms = 2000;
        WinHttpSetTimeouts(socket, close_timeout_ms, close_timeout_ms, close_timeout_ms, close_timeout_ms);
        WinHttpWebSocketClose(socket, code,
                               reason.empty() ? nullptr : const_cast<void*>(static_cast<const void*>(reason.data())),
                               static_cast<DWORD>(reason.size()));
        WinHttpCloseHandle(socket);
    }
    if (connect_handle != nullptr) {
        WinHttpCloseHandle(connect_handle);
    }
    if (session != nullptr) {
        WinHttpCloseHandle(session);
    }
}

bool WebSocketClient::is_connected() const noexcept {
    return impl_ != nullptr && impl_->connected.load();
}

}  // namespace hawk::net
