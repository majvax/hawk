#include "e2e.hpp"

#include <glaze/glaze.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cmath>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <set>
#include <system_error>
#include <utility>

namespace hawk::service {

namespace {

namespace fs = std::filesystem;

const fs::path kDataDirectory = R"(C:\ProgramData\HawkService)";
const fs::path kOwnerKeyPath = kDataDirectory / "owner-key.txt";
const fs::path kAccessStatePath = kDataDirectory / "access-state.txt";

constexpr std::string_view kJoinContext = "hawk-join-v1";
constexpr std::string_view kGrantContext = "hawk-grant-v1";
constexpr std::string_view kRevokeContext = "hawk-revoke-v1";
constexpr std::string_view kAcceptContext = "hawk-accept-v1";
constexpr std::string_view kStreamKeyAad = "hawk-stream-key-v1";
constexpr std::string_view kInputAad = "hawk-input-v1";
constexpr std::string_view kClipboardAad = "hawk-clipboard-v1";

// The first byte of a sealed clipboard message; UTF-8 text follows it.
// Viewer to machine: set (with text) or get (without). Machine to viewer:
// text (answering a get) or push (a copy on the machine, sync mode).
constexpr std::byte kClipboardSet{1};
constexpr std::byte kClipboardGet{2};
constexpr std::byte kClipboardText{3};
constexpr std::byte kClipboardPush{4};

// A single-view grant still admits its viewer this long after their
// viewing ends, so a dashboard that dropped and reconnects isn't refused.
// Mirrors the relay's SINGLE_VIEW_GRACE.
constexpr std::int64_t kSingleViewGraceSeconds = 60;
// Beyond this a wheel event is a bug or an attempt to spin the remote page.
constexpr std::int32_t kMaxWheel = 1200;
// More keys than a person can hold; caps what a viewer can make us track.
constexpr std::size_t kMaxHeld = 32;

constexpr std::byte   kFrameKindEncrypted{0x02};
constexpr std::byte   kFrameKeyframeFlag{0x01};
constexpr std::size_t kFrameAadSize = 14;  // kind, flags, timestamp, key id

[[nodiscard]] std::int64_t unix_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

[[nodiscard]] std::optional<std::int64_t> parse_int(std::string_view text) {
    std::int64_t value = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size()) {
        return std::nullopt;
    }
    return value;
}

// The fields of a statement with this context: key=value lines after the
// context line. nullopt for another context, a malformed line or a key
// that appears twice.
using Fields = std::map<std::string, std::string, std::less<>>;

[[nodiscard]] std::optional<Fields> parse_statement(std::string_view text, std::string_view context) {
    Fields fields;
    bool   first = true;
    while (true) {
        const auto newline = text.find('\n');
        const auto line = text.substr(0, newline);
        if (first) {
            if (line != context) {
                return std::nullopt;
            }
            first = false;
        } else {
            const auto equals = line.find('=');
            if (equals == std::string_view::npos ||
                !fields.emplace(std::string(line.substr(0, equals)), std::string(line.substr(equals + 1))).second) {
                return std::nullopt;
            }
        }
        if (newline == std::string_view::npos) {
            return fields;
        }
        text.remove_prefix(newline + 1);
    }
}

[[nodiscard]] std::string_view field(const Fields& fields, std::string_view key) {
    const auto found = fields.find(key);
    return found == fields.end() ? std::string_view{} : std::string_view(found->second);
}

[[nodiscard]] std::optional<crypto::Bytes> public_key_field(const Fields& fields, std::string_view key) {
    auto decoded = crypto::base64_decode(field(fields, key));
    if (!decoded.has_value() || !crypto::is_public_key(*decoded)) {
        return std::nullopt;
    }
    return decoded;
}

// True when `signed_statement` carries a valid signature by `public_key`.
[[nodiscard]] bool verify(std::span<const std::byte> public_key, const SignedStatement& signed_statement) {
    const auto signature = crypto::base64_decode(signed_statement.signature);
    return signature.has_value() &&
           crypto::ecdsa_verify(public_key, crypto::as_bytes(signed_statement.statement), *signature);
}

[[nodiscard]] std::optional<std::string> read_file(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return std::nullopt;
    }
    return std::string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

// Writes to a temporary file and renames it over the old one, so a crash
// mid-write never leaves half a file behind.
[[nodiscard]] bool write_file(const fs::path& path, std::string_view contents) {
    std::error_code error;
    fs::create_directories(kDataDirectory, error);
    const auto temporary = fs::path(path).concat(".tmp");
    {
        std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
        file << contents;
        if (!file) {
            return false;
        }
    }
    fs::rename(temporary, path, error);
    return !error;
}

[[nodiscard]] std::string canonical_code(std::string_view code) {
    std::string canonical;
    for (const char c : code) {
        if (std::isalnum(static_cast<unsigned char>(c)) == 0) {
            continue;
        }
        char upper = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        if (upper == 'O') {
            upper = '0';
        } else if (upper == 'I' || upper == 'L') {
            upper = '1';
        }
        canonical.push_back(upper);
    }
    return canonical;
}

// What the owner's signatures have said so far, kept across restarts so a
// relay can't replay an old grant after a newer one, or after a revocation.
struct AccessState {
    std::map<std::string, std::int64_t, std::less<>> latest_grant;  // viewer key -> newest grant's issued (ms)
    std::map<std::string, std::int64_t, std::less<>> revoked;       // viewer key -> newest revocation's issued (ms)
    std::map<std::string, std::int64_t, std::less<>> used;          // single-view grant id -> when used (s)

    static AccessState load() {
        AccessState state;
        const auto  contents = read_file(kAccessStatePath);
        if (!contents.has_value()) {
            return state;
        }
        std::string_view rest = *contents;
        while (!rest.empty()) {
            const auto newline = rest.find('\n');
            const auto line = rest.substr(0, newline);
            rest = newline == std::string_view::npos ? std::string_view{} : rest.substr(newline + 1);
            const auto first = line.find(' ');
            const auto second = line.rfind(' ');
            if (first == std::string_view::npos || second == first) {
                continue;
            }
            const auto kind = line.substr(0, first);
            const auto key = std::string(line.substr(first + 1, second - first - 1));
            const auto value = parse_int(line.substr(second + 1));
            if (!value.has_value()) {
                continue;
            }
            if (kind == "grant") {
                state.latest_grant[key] = *value;
            } else if (kind == "revoked") {
                state.revoked[key] = *value;
            } else if (kind == "used") {
                state.used[key] = *value;
            }
        }
        return state;
    }

    void save() const {
        std::string contents;
        for (const auto& [key, value] : latest_grant) {
            contents += std::format("grant {} {}\n", key, value);
        }
        for (const auto& [key, value] : revoked) {
            contents += std::format("revoked {} {}\n", key, value);
        }
        for (const auto& [key, value] : used) {
            contents += std::format("used {} {}\n", key, value);
        }
        if (!write_file(kAccessStatePath, contents)) {
            spdlog::error("e2e: saving {} failed", kAccessStatePath.string());
        }
    }

    [[nodiscard]] std::int64_t get(const std::map<std::string, std::int64_t, std::less<>>& map,
                                   std::string_view key) const {
        const auto found = map.find(key);
        return found == map.end() ? 0 : found->second;
    }
};

// One input event as the dashboard seals it (protocol.ts InputEvent).
struct InputMessage {
    std::string  kind;  // "mouse_move", "mouse_button", "wheel", "key"
    double       x = 0.0;
    double       y = 0.0;
    std::string  button;
    bool         down = false;
    std::int32_t dx = 0;
    std::int32_t dy = 0;
    std::string  code;
};

struct AcceptMessage {
    std::string   type = "viewer_accept";
    std::uint64_t viewer = 0;
    std::string   statement;
    std::string   signature;
    std::string   wrapped_key;
    // What this viewer may do with the clipboard: "off", "pull" or "sync".
    // For the dashboard to show the right buttons; the machine checks for
    // itself on every request.
    std::string clipboard;
};

struct RejectMessage {
    std::string   type = "viewer_reject";
    std::uint64_t viewer = 0;
    std::string   reason;
};

struct StreamKeyMessage {
    std::string   type = "stream_key";
    std::uint64_t viewer = 0;
    std::string   wrapped_key;
};

struct ClipboardMessage {
    std::string   type = "clipboard";
    std::uint64_t viewer = 0;
    std::string   sealed;
};

}  // namespace

}  // namespace hawk::service

template <>
struct glz::meta<hawk::service::InputMessage> {
    using T                     = hawk::service::InputMessage;
    static constexpr auto value = object("kind", &T::kind, "x", &T::x, "y", &T::y, "button", &T::button, "down",
                                         &T::down, "dx", &T::dx, "dy", &T::dy, "code", &T::code);
};

template <>
struct glz::meta<hawk::service::AcceptMessage> {
    using T                     = hawk::service::AcceptMessage;
    static constexpr auto value = object("type", &T::type, "viewer", &T::viewer, "statement", &T::statement,
                                         "signature", &T::signature, "wrapped_key", &T::wrapped_key, "clipboard", &T::clipboard);
};

template <>
struct glz::meta<hawk::service::RejectMessage> {
    using T                     = hawk::service::RejectMessage;
    static constexpr auto value = object("type", &T::type, "viewer", &T::viewer, "reason", &T::reason);
};

template <>
struct glz::meta<hawk::service::StreamKeyMessage> {
    using T                     = hawk::service::StreamKeyMessage;
    static constexpr auto value = object("type", &T::type, "viewer", &T::viewer, "wrapped_key", &T::wrapped_key);
};

template <>
struct glz::meta<hawk::service::ClipboardMessage> {
    using T                     = hawk::service::ClipboardMessage;
    static constexpr auto value = object("type", &T::type, "viewer", &T::viewer, "sealed", &T::sealed);
};

namespace hawk::service {

namespace {

template <typename Message>
[[nodiscard]] std::string to_json(const Message& message) {
    auto json = glz::write_json(message);
    return json.has_value() ? *json : std::string{};
}

// A held key or button, named so two viewers holding the same one compare
// equal: "button:left", "key:ShiftLeft".
[[nodiscard]] std::optional<std::string> held_name(const ipc::InputPacket& packet) {
    switch (static_cast<ipc::InputKind>(packet.kind)) {
        case ipc::InputKind::mouse_button:
            return std::format("button:{}", packet.button);
        case ipc::InputKind::key:
            return std::format("key:{}", packet.code.data());
        default:
            return std::nullopt;
    }
}

// The packet that lets go of a held key or button.
[[nodiscard]] ipc::InputPacket release_packet(std::string_view held) {
    ipc::InputPacket packet{};
    if (held.starts_with("button:")) {
        packet.kind = static_cast<std::uint8_t>(ipc::InputKind::mouse_button);
        packet.button = static_cast<std::uint8_t>(parse_int(held.substr(7)).value_or(0));
    } else {
        const auto code = held.substr(4);
        packet.kind = static_cast<std::uint8_t>(ipc::InputKind::key);
        std::ranges::copy(code.substr(0, packet.code.size() - 1), packet.code.begin());
    }
    packet.down = 0;
    return packet;
}

// A viewer's event, brought into range, as hawk-capture takes it; nullopt
// for anything that can't be made sense of.
[[nodiscard]] std::optional<ipc::InputPacket> to_packet(const InputMessage& event) {
    ipc::InputPacket packet{};
    if (event.kind == "mouse_move") {
        if (!std::isfinite(event.x) || !std::isfinite(event.y)) {
            return std::nullopt;
        }
        packet.kind = static_cast<std::uint8_t>(ipc::InputKind::mouse_move);
        packet.x = std::clamp(event.x, 0.0, 1.0);
        packet.y = std::clamp(event.y, 0.0, 1.0);
    } else if (event.kind == "mouse_button") {
        ipc::InputButton button{};
        if (event.button == "left") {
            button = ipc::InputButton::left;
        } else if (event.button == "right") {
            button = ipc::InputButton::right;
        } else if (event.button == "middle") {
            button = ipc::InputButton::middle;
        } else {
            return std::nullopt;
        }
        packet.kind = static_cast<std::uint8_t>(ipc::InputKind::mouse_button);
        packet.button = static_cast<std::uint8_t>(button);
        packet.down = event.down ? 1 : 0;
    } else if (event.kind == "wheel") {
        packet.kind = static_cast<std::uint8_t>(ipc::InputKind::wheel);
        packet.wheel_dx = std::clamp(event.dx, -kMaxWheel, kMaxWheel);
        packet.wheel_dy = std::clamp(event.dy, -kMaxWheel, kMaxWheel);
    } else if (event.kind == "key") {
        // The packet holds the name and its terminator. A longer name, or
        // one with anything but letters and digits, is no key on any
        // keyboard.
        const bool valid = !event.code.empty() && event.code.size() < packet.code.size() &&
                           std::ranges::all_of(event.code, [](char c) { return std::isalnum(static_cast<unsigned char>(c)) != 0; });
        if (!valid) {
            return std::nullopt;
        }
        packet.kind = static_cast<std::uint8_t>(ipc::InputKind::key);
        packet.down = event.down ? 1 : 0;
        std::ranges::copy(event.code, packet.code.begin());
    } else {
        return std::nullopt;
    }
    return packet;
}

void put_u32_be(crypto::Bytes& out, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::byte>((value >> shift) & 0xFFU));
    }
}

void put_u64_be(crypto::Bytes& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::byte>((value >> shift) & 0xFFU));
    }
}

// A 12-byte GCM nonce from a counter: counter (big-endian) || 4 zeros.
[[nodiscard]] crypto::Bytes counter_nonce(std::uint64_t counter) {
    crypto::Bytes nonce;
    put_u64_be(nonce, counter);
    nonce.resize(crypto::gcm_iv_size);
    return nonce;
}

// True for well-formed UTF-8 without overlongs, surrogates or anything past
// U+10FFFF: what the clipboard is handed is text the machine can convert.
[[nodiscard]] bool is_utf8(std::string_view text) {
    constexpr std::array<std::uint32_t, 5> kSmallest{0, 0, 0x80, 0x800, 0x10000};
    std::size_t                            i = 0;
    while (i < text.size()) {
        const auto    lead = static_cast<unsigned char>(text[i]);
        std::size_t   length = 0;
        std::uint32_t point = 0;
        if (lead < 0x80U) {
            ++i;
            continue;
        }
        if ((lead & 0xE0U) == 0xC0U) {
            length = 2;
            point = lead & 0x1FU;
        } else if ((lead & 0xF0U) == 0xE0U) {
            length = 3;
            point = lead & 0x0FU;
        } else if ((lead & 0xF8U) == 0xF0U) {
            length = 4;
            point = lead & 0x07U;
        } else {
            return false;
        }
        if (i + length > text.size()) {
            return false;
        }
        for (std::size_t k = 1; k < length; ++k) {
            const auto next = static_cast<unsigned char>(text[i + k]);
            if ((next & 0xC0U) != 0x80U) {
                return false;
            }
            point = (point << 6U) | (next & 0x3FU);
        }
        if (point < kSmallest[length] || point > 0x10FFFFU || (point >= 0xD800U && point <= 0xDFFFU)) {
            return false;
        }
        i += length;
    }
    return true;
}

// The longest prefix of `text` within `limit` bytes that doesn't cut a
// character in half.
[[nodiscard]] std::string_view utf8_prefix(std::string_view text, std::size_t limit) {
    if (text.size() <= limit) {
        return text;
    }
    std::size_t end = limit;
    while (end > 0 && (static_cast<unsigned char>(text[end]) & 0xC0U) == 0x80U) {
        --end;
    }
    return text.substr(0, end);
}

struct StreamKey {
    std::uint32_t                 id = 0;
    crypto::Bytes                 raw;
    std::optional<crypto::AesGcm> cipher;
    std::uint64_t                 frames = 0;  // the nonce counter
};

[[nodiscard]] StreamKey new_stream_key(std::uint32_t id) {
    StreamKey key{.id = id, .raw = crypto::Bytes(crypto::aes_key_size), .cipher = std::nullopt, .frames = 0};
    crypto::random(key.raw);
    key.cipher = crypto::AesGcm::create(key.raw);
    return key;
}

struct Viewer {
    std::string                  viewer_key;  // base64 identity key
    std::string                  role;        // "owner", "control" or "view"
    std::string                  fingerprint;  // of viewer_key, for the log
    crypto::AesGcm               input_key;
    crypto::AesGcm               wrap_key;
    // Seals what the machine sends this viewer alone (clipboard text),
    // under nonces from its own counter.
    crypto::AesGcm               reply_key;
    std::uint64_t                reply_counter = 0;
    // Shared by input and clipboard requests, which the dashboard numbers
    // from one counter.
    std::uint64_t                last_counter = 0;
    std::int64_t                 grant_issued = 0;  // 0 for the owner
    std::optional<std::int64_t>  not_after;         // unix seconds
    std::optional<std::string>   single_view_grant;
    std::set<std::string, std::less<>> held;
    bool                         sent_input = false;
    bool                         awaiting_clipboard = false;
    // Refused after it joined (revoked, expired): waits for the relay's
    // viewer_left to let go of its input, and gets nothing meanwhile.
    bool refused = false;
};

// What a grant lets a viewer do, once its signature and terms checked out.
struct Admission {
    std::string                 role;
    std::int64_t                grant_issued = 0;
    std::optional<std::int64_t> not_after;
    std::optional<std::string>  single_view_grant;
};

}  // namespace

std::string enroll_code_hash(std::string_view code) {
    return crypto::base64_encode(crypto::sha256(crypto::as_bytes(canonical_code(code))));
}

crypto::Sha256Digest enroll_binding(std::string_view code, std::string_view context,
                                    std::span<const std::byte> public_key) {
    const auto key = crypto::hkdf_sha256(crypto::as_bytes(canonical_code(code)), {}, "hawk-enroll-v1", 32);
    auto       message = crypto::as_bytes(context);
    message.push_back(std::byte{0});
    message.insert(message.end(), public_key.begin(), public_key.end());
    return crypto::hmac_sha256(key, message);
}

std::string fingerprint(std::span<const std::byte> public_key) {
    const auto  digest = crypto::sha256(public_key);
    std::string text;
    for (std::size_t i = 0; i < 16; ++i) {
        if (i > 0 && i % 2 == 0) {
            text += ' ';
        }
        text += std::format("{:02X}", std::to_integer<unsigned>(digest[i]));
    }
    return text;
}

std::optional<crypto::Bytes> load_owner_key() {
    const auto contents = read_file(kOwnerKeyPath);
    if (!contents.has_value()) {
        return std::nullopt;
    }
    auto text = std::string_view(*contents);
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back())) != 0) {
        text.remove_suffix(1);
    }
    auto key = crypto::base64_decode(text);
    if (!key.has_value() || !crypto::is_public_key(*key)) {
        return std::nullopt;
    }
    return key;
}

bool save_owner_key(std::span<const std::byte> key) {
    return write_file(kOwnerKeyPath, crypto::base64_encode(key) + "\n");
}

struct ViewerHub::Impl {
    const MachineKey&            machine_key;
    std::string                  machine_id;
    std::optional<crypto::Bytes> owner_key;
    std::string                  owner_key_text;
    ClipboardConfig              clipboard;
    Sender                       send;

    std::mutex                       mutex;
    AccessState                      state = AccessState::load();
    std::map<std::uint64_t, Viewer>  viewers;
    StreamKey                        stream = new_stream_key(1);
    std::chrono::steady_clock::time_point last_expiry_check{};

    Impl(const MachineKey& key, std::string id, std::optional<crypto::Bytes> owner, ClipboardConfig clipboard_config,
         Sender sender)
        : machine_key(key),
          machine_id(std::move(id)),
          owner_key(std::move(owner)),
          owner_key_text(owner_key.has_value() ? crypto::base64_encode(*owner_key) : std::string{}),
          clipboard(clipboard_config),
          send(std::move(sender)) {}

    [[nodiscard]] bool may_set_clipboard(const Viewer& viewer) const {
        return clipboard.mode != ClipboardMode::off && viewer.role != "view";
    }

    [[nodiscard]] bool may_read_clipboard(const Viewer& viewer) const {
        return clipboard.mode != ClipboardMode::off && (viewer.role != "view" || clipboard.view_pull);
    }

    // What the dashboard is told this viewer may do with the clipboard.
    [[nodiscard]] std::string clipboard_access(const Viewer& viewer) const {
        if (!may_read_clipboard(viewer)) {
            return "off";
        }
        return clipboard.mode == ClipboardMode::sync ? "sync" : "pull";
    }

    // counter || AES-GCM(reply key, op || text), base64: for one viewer.
    [[nodiscard]] static std::string seal_reply(Viewer& viewer, std::byte op, std::string_view text) {
        crypto::Bytes plain;
        plain.reserve(1 + text.size());
        plain.push_back(op);
        const auto bytes = std::as_bytes(std::span(text));
        plain.insert(plain.end(), bytes.begin(), bytes.end());
        const auto    counter = ++viewer.reply_counter;
        crypto::Bytes out;
        put_u64_be(out, counter);
        const auto sealed = viewer.reply_key.encrypt(counter_nonce(counter), plain, crypto::as_bytes(kClipboardAad));
        out.insert(out.end(), sealed.begin(), sealed.end());
        return crypto::base64_encode(out);
    }

    // Opens counter || ciphertext from a viewer, sealed under its input key
    // with `aad`: the plaintext if it's genuine and its counter is newer
    // than any before. Input and clipboard requests share the counter.
    [[nodiscard]] static std::optional<crypto::Bytes> open_request(Viewer& viewer, std::string_view sealed,
                                                                   std::string_view aad) {
        const auto bytes = crypto::base64_decode(sealed);
        if (!bytes.has_value() || bytes->size() < 8 + crypto::gcm_tag_size) {
            return std::nullopt;
        }
        std::uint64_t counter = 0;
        for (std::size_t i = 0; i < 8; ++i) {
            counter = (counter << 8U) | std::to_integer<std::uint64_t>((*bytes)[i]);
        }
        // Each counter once, in order: the relay can't replay a keystroke.
        if (counter <= viewer.last_counter) {
            return std::nullopt;
        }
        auto plain =
            viewer.input_key.decrypt(counter_nonce(counter), std::span(*bytes).subspan(8), crypto::as_bytes(aad));
        if (!plain.has_value()) {
            return std::nullopt;
        }
        viewer.last_counter = counter;
        return plain;
    }

    void reject(std::uint64_t viewer, std::string reason) {
        spdlog::info("e2e: refusing viewer {}: {}", viewer, reason);
        send(to_json(RejectMessage{.viewer = viewer, .reason = std::move(reason)}));
    }

    // iv || AES-GCM(wrap key, key id || stream key): the stream key for
    // one viewer's eyes only.
    [[nodiscard]] std::string wrap_stream_key(const Viewer& viewer) const {
        crypto::Bytes plain;
        put_u32_be(plain, stream.id);
        plain.insert(plain.end(), stream.raw.begin(), stream.raw.end());
        crypto::Bytes iv(crypto::gcm_iv_size);
        crypto::random(iv);
        auto sealed = viewer.wrap_key.encrypt(iv, plain, crypto::as_bytes(kStreamKeyAad));
        iv.insert(iv.end(), sealed.begin(), sealed.end());
        return crypto::base64_encode(iv);
    }

    // Moves every viewer still admitted to a fresh stream key. The new key
    // goes out before the switch, and frames are sealed under the same
    // lock, so nobody gets a frame before its key.
    void rekey() {
        auto next = new_stream_key(stream.id + 1);
        std::swap(stream, next);  // wrap_stream_key reads `stream`
        for (const auto& [id, viewer] : viewers) {
            if (!viewer.refused) {
                send(to_json(StreamKeyMessage{.viewer = id, .wrapped_key = wrap_stream_key(viewer)}));
            }
        }
    }

    // Refuses a viewer that had been admitted, and moves the rest to a key
    // it doesn't have.
    void refuse(std::uint64_t id, Viewer& viewer, std::string reason) {
        if (viewer.refused) {
            return;
        }
        viewer.refused = true;
        reject(id, std::move(reason));
        rekey();
    }

    // Checks the owner's grant for this viewer. Caller holds the lock.
    [[nodiscard]] std::expected<Admission, std::string> admit(const std::string& viewer_key,
                                                              const std::optional<SignedStatement>& grant) {
        if (viewer_key == owner_key_text) {
            return Admission{.role = "owner"};
        }
        if (!grant.has_value()) {
            return std::unexpected("the owner hasn't signed a grant for this account");
        }
        if (!verify(*owner_key, *grant)) {
            return std::unexpected("the grant isn't signed by the owner");
        }
        const auto fields = parse_statement(grant->statement, kGrantContext);
        if (!fields.has_value() || fields->size() != 7 || field(*fields, "machine") != machine_id ||
            field(*fields, "viewer") != viewer_key) {
            return std::unexpected("the grant is for someone or something else");
        }
        const auto role = std::string(field(*fields, "role"));
        const auto issued = parse_int(field(*fields, "issued"));
        if ((role != "view" && role != "control") || !issued.has_value()) {
            return std::unexpected("the grant is malformed");
        }
        const auto now = unix_seconds();
        std::optional<std::int64_t> not_after;
        for (const auto* name : {"not_before", "not_after"}) {
            const auto value = field(*fields, name);
            if (value == "-") {
                continue;
            }
            const auto time = parse_int(value);
            if (!time.has_value()) {
                return std::unexpected("the grant is malformed");
            }
            if (std::string_view(name) == "not_before" && now < *time) {
                return std::unexpected("this share hasn't started yet");
            }
            if (std::string_view(name) == "not_after") {
                if (now >= *time) {
                    return std::unexpected("this share has expired");
                }
                not_after = *time;
            }
        }
        if (*issued < state.get(state.latest_grant, viewer_key)) {
            return std::unexpected("a newer grant replaced this one");
        }
        if (*issued <= state.get(state.revoked, viewer_key)) {
            return std::unexpected("access was revoked");
        }
        std::optional<std::string> single_view;
        if (field(*fields, "single_view") == "1") {
            auto id = crypto::base64_encode(crypto::sha256(crypto::as_bytes(grant->statement)));
            const auto used = state.used.find(id);
            if (used != state.used.end() && now - used->second > kSingleViewGraceSeconds) {
                return std::unexpected("this one-viewing share was already used");
            }
            single_view = std::move(id);
        }
        if (*issued > state.get(state.latest_grant, viewer_key)) {
            state.latest_grant[viewer_key] = *issued;
            state.save();
        }
        return Admission{
            .role = role, .grant_issued = *issued, .not_after = not_after, .single_view_grant = std::move(single_view)};
    }
};

ViewerHub::ViewerHub(const MachineKey& key, std::string machine_id, std::optional<crypto::Bytes> owner_key,
                     ClipboardConfig clipboard, Sender send)
    : impl_(std::make_unique<Impl>(key, std::move(machine_id), std::move(owner_key), clipboard, std::move(send))) {}

ViewerHub::~ViewerHub() = default;

void ViewerHub::join(std::uint64_t viewer, const SignedStatement& request, const std::optional<SignedStatement>& grant) {
    auto& impl = *impl_;
    if (!impl.owner_key.has_value()) {
        impl.reject(viewer, "this machine was enrolled before end-to-end encryption; its owner must enroll it again");
        return;
    }
    const auto fields = parse_statement(request.statement, kJoinContext);
    if (!fields.has_value() || field(*fields, "machine") != impl.machine_id) {
        impl.reject(viewer, "malformed join request");
        return;
    }
    const auto viewer_key = public_key_field(*fields, "viewer");
    const auto ephemeral = public_key_field(*fields, "ephemeral");
    if (!viewer_key.has_value() || !ephemeral.has_value() || !verify(*viewer_key, request)) {
        impl.reject(viewer, "the join request isn't signed by its viewer");
        return;
    }
    const auto viewer_key_text = std::string(field(*fields, "viewer"));

    std::expected<Admission, std::string> admission;
    {
        const std::lock_guard lock(impl.mutex);
        admission = impl.admit(viewer_key_text, grant);
    }
    if (!admission.has_value()) {
        impl.reject(viewer, admission.error());
        return;
    }

    // The key exchange, and the machine's signature over its half: slow
    // (the TPM signs), so outside the lock frames are sealed under.
    auto exchange = crypto::ExchangeKey::generate();
    auto shared = exchange.has_value() ? exchange->agree(*ephemeral) : std::nullopt;
    if (!shared.has_value()) {
        impl.reject(viewer, "key exchange failed");
        return;
    }
    const auto join_hash = crypto::sha256(crypto::as_bytes(request.statement));
    // HKDF output is a prefix of any longer output: the first 64 bytes are
    // the input and wrap keys whatever length is asked for.
    const auto keys = crypto::hkdf_sha256(*shared, join_hash, "hawk-session-v1", 96);
    auto input_key = crypto::AesGcm::create(std::span(keys).first(32));
    auto wrap_key = crypto::AesGcm::create(std::span(keys).subspan(32, 32));
    auto reply_key = crypto::AesGcm::create(std::span(keys).subspan(64, 32));
    const auto accept = std::format("{}\nmachine={}\njoin={}\nephemeral={}\nrole={}", kAcceptContext, impl.machine_id,
                                    crypto::base64_encode(join_hash), crypto::base64_encode(exchange->public_key()),
                                    admission->role);
    const auto signature = impl.machine_key.sign(crypto::as_bytes(accept));
    if (!input_key.has_value() || !wrap_key.has_value() || !reply_key.has_value() || !signature.has_value()) {
        impl.reject(viewer, "the machine couldn't sign its answer");
        return;
    }

    const std::lock_guard lock(impl.mutex);
    Viewer session{
        .viewer_key = viewer_key_text,
        .role = admission->role,
        .fingerprint = fingerprint(*viewer_key),
        .input_key = std::move(*input_key),
        .wrap_key = std::move(*wrap_key),
        .reply_key = std::move(*reply_key),
        .grant_issued = admission->grant_issued,
        .not_after = admission->not_after,
        .single_view_grant = admission->single_view_grant,
    };
    // Asked again by a viewer already watching: whatever its input holds
    // stays recorded, so it's still released when it leaves.
    if (const auto previous = impl.viewers.find(viewer); previous != impl.viewers.end()) {
        session.held = std::move(previous->second.held);
        session.sent_input = previous->second.sent_input;
    }
    const auto wrapped = impl.wrap_stream_key(session);
    auto       clipboard = impl.clipboard_access(session);
    spdlog::info("e2e: viewer {} ({}) admitted as {}", viewer, session.fingerprint, admission->role);
    impl.viewers.insert_or_assign(viewer, std::move(session));
    impl.send(to_json(AcceptMessage{.viewer = viewer,
                                    .statement = accept,
                                    .signature = crypto::base64_encode(*signature),
                                    .wrapped_key = wrapped,
                                    .clipboard = std::move(clipboard)}));
}

std::vector<ipc::InputPacket> ViewerHub::leave(std::uint64_t viewer) {
    auto&                 impl = *impl_;
    const std::lock_guard lock(impl.mutex);
    const auto            found = impl.viewers.find(viewer);
    if (found == impl.viewers.end()) {
        return {};
    }
    Viewer leaving = std::move(found->second);
    impl.viewers.erase(found);

    if (leaving.single_view_grant.has_value() && !impl.state.used.contains(*leaving.single_view_grant)) {
        impl.state.used[*leaving.single_view_grant] = unix_seconds();
        impl.state.save();
    }
    // Whoever is left moves to a key the one leaving never had.
    impl.rekey();

    // Lets go of what this viewer holds. With nobody else holding anything,
    // everything is released, which also catches a release that never
    // arrived; otherwise only what no other viewer holds too.
    std::vector<ipc::InputPacket> releases;
    if (!leaving.sent_input) {
        return releases;
    }
    const bool others_hold = std::ranges::any_of(impl.viewers, [](const auto& entry) { return !entry.second.held.empty(); });
    if (!others_hold) {
        releases.push_back(ipc::InputPacket{.kind = static_cast<std::uint8_t>(ipc::InputKind::release_all)});
        return releases;
    }
    for (const auto& held : leaving.held) {
        const bool shared =
            std::ranges::any_of(impl.viewers, [&](const auto& entry) { return entry.second.held.contains(held); });
        if (!shared) {
            releases.push_back(release_packet(held));
        }
    }
    return releases;
}

std::optional<ipc::InputPacket> ViewerHub::input(std::uint64_t viewer, std::string_view sealed) {
    auto&                 impl = *impl_;
    const std::lock_guard lock(impl.mutex);
    const auto            found = impl.viewers.find(viewer);
    if (found == impl.viewers.end() || found->second.refused || found->second.role == "view") {
        return std::nullopt;
    }
    Viewer&    session = found->second;
    const auto plain = Impl::open_request(session, sealed, kInputAad);
    if (!plain.has_value()) {
        return std::nullopt;
    }

    InputMessage event;
    const std::string json(reinterpret_cast<const char*>(plain->data()), plain->size());
    if (glz::read<glz::opts{.error_on_unknown_keys = false}>(event, json)) {
        return std::nullopt;
    }
    auto packet = to_packet(event);
    if (!packet.has_value()) {
        return std::nullopt;
    }
    session.sent_input = true;
    if (const auto held = held_name(*packet); held.has_value()) {
        if (packet->down == 0) {
            session.held.erase(*held);
        } else if (session.held.size() < kMaxHeld) {
            session.held.insert(*held);
        }
    }
    return packet;
}

std::optional<ClipboardRequest> ViewerHub::clipboard(std::uint64_t viewer, std::string_view sealed) {
    auto&                 impl = *impl_;
    const std::lock_guard lock(impl.mutex);
    const auto            found = impl.viewers.find(viewer);
    if (found == impl.viewers.end() || found->second.refused || !impl.may_read_clipboard(found->second)) {
        return std::nullopt;
    }
    Viewer&    session = found->second;
    const auto plain = Impl::open_request(session, sealed, kClipboardAad);
    if (!plain.has_value() || plain->empty()) {
        return std::nullopt;
    }
    const auto op = plain->front();
    const auto text = std::string_view(reinterpret_cast<const char*>(plain->data()) + 1, plain->size() - 1);
    if (op == kClipboardGet && text.empty()) {
        session.awaiting_clipboard = true;
        spdlog::info("clipboard: viewer {} ({}) asked for the clipboard", viewer, session.fingerprint);
        return ClipboardRequest{.op = ClipboardRequest::Op::get, .text = {}};
    }
    if (op == kClipboardSet && impl.may_set_clipboard(session)) {
        if (text.size() > impl.clipboard.max_size || !is_utf8(text)) {
            spdlog::warn("clipboard: viewer {} ({}) sent {} bytes that aren't text within the limit; ignored", viewer,
                         session.fingerprint, text.size());
            return std::nullopt;
        }
        spdlog::info("clipboard: viewer {} ({}) set the clipboard ({} bytes)", viewer, session.fingerprint,
                     text.size());
        return ClipboardRequest{.op = ClipboardRequest::Op::set, .text = std::string(text)};
    }
    spdlog::warn("clipboard: viewer {} ({}) asked for something its role doesn't allow; ignored", viewer,
                 session.fingerprint);
    return std::nullopt;
}

void ViewerHub::deliver_clipboard(std::string_view text, bool pushed) {
    auto&                 impl = *impl_;
    const std::lock_guard lock(impl.mutex);
    if (pushed && impl.clipboard.mode != ClipboardMode::sync) {
        return;
    }
    const auto prefix = utf8_prefix(text, impl.clipboard.max_size);
    for (auto& [id, viewer] : impl.viewers) {
        if (viewer.refused || !impl.may_read_clipboard(viewer) || (!pushed && !viewer.awaiting_clipboard)) {
            continue;
        }
        viewer.awaiting_clipboard = false;
        spdlog::info("clipboard: {} viewer {} ({}) the clipboard ({} bytes)", pushed ? "pushed to" : "sent", id,
                     viewer.fingerprint, prefix.size());
        impl.send(to_json(ClipboardMessage{
            .viewer = id, .sealed = Impl::seal_reply(viewer, pushed ? kClipboardPush : kClipboardText, prefix)}));
    }
}

void ViewerHub::apply_revocations(const std::vector<SignedStatement>& revocations) {
    auto&                 impl = *impl_;
    const std::lock_guard lock(impl.mutex);
    if (!impl.owner_key.has_value()) {
        return;
    }
    bool changed = false;
    for (const auto& revocation : revocations) {
        const auto fields = parse_statement(revocation.statement, kRevokeContext);
        if (!fields.has_value() || fields->size() != 3 || field(*fields, "machine") != impl.machine_id ||
            !verify(*impl.owner_key, revocation)) {
            spdlog::warn("e2e: ignoring a revocation that isn't the owner's, or isn't for this machine");
            continue;
        }
        const auto viewer_key = std::string(field(*fields, "viewer"));
        const auto issued = parse_int(field(*fields, "issued"));
        if (!issued.has_value() || *issued <= impl.state.get(impl.state.revoked, viewer_key)) {
            continue;
        }
        impl.state.revoked[viewer_key] = *issued;
        changed = true;
    }
    if (!changed) {
        return;
    }
    impl.state.save();
    for (auto& [id, viewer] : impl.viewers) {
        if (viewer.role != "owner" && viewer.grant_issued <= impl.state.get(impl.state.revoked, viewer.viewer_key)) {
            impl.refuse(id, viewer, "access was revoked");
        }
    }
}

void ViewerHub::check_expiry() {
    auto&      impl = *impl_;
    const auto now = std::chrono::steady_clock::now();
    const std::lock_guard lock(impl.mutex);
    if (now - impl.last_expiry_check < std::chrono::seconds(1)) {
        return;
    }
    impl.last_expiry_check = now;
    const auto unix_now = unix_seconds();
    for (auto& [id, viewer] : impl.viewers) {
        if (viewer.not_after.has_value() && unix_now >= *viewer.not_after) {
            impl.refuse(id, viewer, "this share has expired");
        }
    }
}

crypto::Bytes ViewerHub::seal_frame(std::span<const std::byte> access_unit, bool keyframe,
                                    std::chrono::microseconds timestamp) {
    auto&                 impl = *impl_;
    const std::lock_guard lock(impl.mutex);
    auto&                 stream = impl.stream;
    if (!stream.cipher.has_value()) {
        return {};
    }
    crypto::Bytes frame;
    frame.reserve(kFrameAadSize + crypto::gcm_iv_size + access_unit.size() + crypto::gcm_tag_size);
    frame.push_back(kFrameKindEncrypted);
    frame.push_back(keyframe ? kFrameKeyframeFlag : std::byte{0});
    const auto ticks = static_cast<std::uint64_t>(timestamp.count());
    for (std::size_t i = 0; i < sizeof(ticks); ++i) {
        frame.push_back(static_cast<std::byte>((ticks >> (8 * i)) & 0xFFU));
    }
    put_u32_be(frame, stream.id);
    stream.frames += 1;
    const auto nonce = counter_nonce(stream.frames);
    const auto sealed = stream.cipher->encrypt(nonce, access_unit, std::span(frame).first(kFrameAadSize));
    if (sealed.empty()) {
        return {};
    }
    frame.insert(frame.end(), nonce.begin(), nonce.end());
    frame.insert(frame.end(), sealed.begin(), sealed.end());
    return frame;
}

}  // namespace hawk::service
