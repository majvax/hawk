#pragma once

#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace hawk::net {

// RFC 6455 close code for a normal, planned shutdown.
inline constexpr std::uint16_t normal_closure_code = 1000;

inline constexpr std::chrono::milliseconds default_resolve_timeout{10'000};
inline constexpr std::chrono::milliseconds default_connect_timeout{10'000};
inline constexpr std::chrono::milliseconds default_send_timeout{30'000};
inline constexpr std::chrono::milliseconds default_receive_timeout{0};  // 0 = infinite

// A graceful WebSocket close frame: either the one we sent via close(), or
// the one the peer sent to end the connection.
struct WebSocketCloseInfo {
    std::uint16_t code = normal_closure_code;
    std::string   reason;
};

// A single application-level message. Fragmented frames are reassembled
// internally before being surfaced here, so callers never see partial data.
using WebSocketMessage = std::variant<std::string, std::vector<std::byte>, WebSocketCloseInfo>;

struct WebSocketError {
    enum class Code : std::uint8_t {
        invalid_url,
        connection_failed,
        handshake_failed,
        send_failed,
        receive_failed,
        not_connected,
        already_connected,
        pin_mismatch,  // TLS key doesn't match ConnectOptions::pinned_keys
    };

    Code          code;
    std::uint32_t native_code = 0;  // underlying OS/WinHTTP error code, if any
    std::string   message;
};

[[nodiscard]] std::string_view to_string(WebSocketError::Code code) noexcept;
[[nodiscard]] std::string      to_string(const WebSocketError& error);

// A synchronous WebSocket client, implemented on top of WinHTTP.
//
// The public interface is STL-only: no Windows/WinHTTP type ever crosses
// this boundary, in either direction. All platform state lives behind a
// PIMPL defined entirely in websocket.cpp.
//
// Thread-safety: close() may be called from a different thread than the one
// blocked in receive() in order to cancel it — this mirrors how a service's
// control handler stops a worker thread. send_text()/send_binary() may be
// called from any thread, including while another is blocked in receive();
// concurrent sends are serialized internally. connect() and receive() must
// not be called concurrently with each other or with themselves.
class WebSocketClient {
public:
    struct ConnectOptions {
        std::vector<std::pair<std::string, std::string>> headers;
        std::chrono::milliseconds resolve_timeout;
        std::chrono::milliseconds connect_timeout;
        std::chrono::milliseconds send_timeout;
        std::chrono::milliseconds receive_timeout;  // 0 = infinite

        // Certificate pinning for wss://. When non-empty, the server's leaf
        // certificate must have one of these public keys, given as base64
        // SHA-256 of its DER SubjectPublicKeyInfo. Checked right after the
        // TLS handshake, before connect() returns, so nothing is ever sent
        // over a connection that fails it. The usual chain validation
        // against the Windows trust store still applies on top.
        std::vector<std::string> pinned_keys;

        // A nested class's default member initializers aren't usable until
        // its *outer* class is complete, which makes them unusable as a
        // default argument for a sibling member function (connect(), right
        // below) from within the same enclosing class body. An explicit
        // default constructor avoids that rule entirely.
        ConnectOptions()
            : resolve_timeout(default_resolve_timeout),
              connect_timeout(default_connect_timeout),
              send_timeout(default_send_timeout),
              receive_timeout(default_receive_timeout) {}
    };

    WebSocketClient();
    ~WebSocketClient();

    WebSocketClient(WebSocketClient&&) noexcept;
    WebSocketClient& operator=(WebSocketClient&&) noexcept;

    WebSocketClient(const WebSocketClient&) = delete;
    WebSocketClient& operator=(const WebSocketClient&) = delete;

    // Performs the HTTP(S) handshake and upgrades to a WebSocket connection.
    // `url` must be of the form "ws://host[:port]/path" or "wss://host[:port]/path".
    [[nodiscard]] std::expected<void, WebSocketError> connect(std::string_view url,
                                                                const ConnectOptions& options = {});

    // Sends a UTF-8 text message. `message` must be valid UTF-8.
    [[nodiscard]] std::expected<void, WebSocketError> send_text(std::string_view message);

    [[nodiscard]] std::expected<void, WebSocketError> send_binary(std::span<const std::byte> data);

    // Blocks until a full message (or close frame) has been received.
    // Returns WebSocketCloseInfo once, then NotConnected on any further call.
    [[nodiscard]] std::expected<WebSocketMessage, WebSocketError> receive();

    // Initiates a graceful close. Safe to call from another thread to
    // unblock a pending receive(); safe to call more than once.
    void close(std::uint16_t code = normal_closure_code, std::string_view reason = {}) noexcept;

    [[nodiscard]] bool is_connected() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace hawk::net
