#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

// Wire format of the local named pipe hawk-service and hawk-capture trade
// the clipboard over: text, and (with `--clipboard-images`) pictures as
// PNG. Both ends are built from this tree for the same architecture, so the
// header is written and read as a raw struct.
//
// The pipe is created by hawk-service (duplex, byte mode, remote clients
// rejected, DACL limited to SYSTEM, which hawk-capture runs as) only when
// the machine's config lets the clipboard be used at all, and its name is
// handed to hawk-capture on its command line as `--clipboard-pipe <name>`.
// The clipboard belongs to the interactive session, which is why
// hawk-capture, not the service, is the one that touches it.
namespace hawk::ipc {

inline constexpr std::uint32_t clipboard_packet_magic = 0x50494C43;  // "CLIP", little-endian

// The most text either end sends: 256 KB of UTF-8. Also what keeps a corrupt
// header from making the reader allocate an arbitrary amount of memory.
inline constexpr std::uint32_t max_clipboard_size = 256U * 1024U;

// The most PNG either end sends, and the largest picture it may hold: an
// image past either is skipped, never cut. Readers check the size of every
// image message against this one, as they do text against the one above.
inline constexpr std::uint32_t max_clipboard_image_size = 8U * 1024U * 1024U;
inline constexpr std::uint32_t max_clipboard_image_side = 16384;
inline constexpr std::uint64_t max_clipboard_image_pixels = 7680ULL * 4320ULL;  // 8K

enum class ClipboardKind : std::uint8_t {
    // service -> capture: put this text on the clipboard.
    set = 1,
    // service -> capture: read the clipboard; answered with `text`, or
    // with `image` when it holds a picture and no text.
    get = 2,
    // capture -> service: what the clipboard holds, answering a `get`.
    text = 3,
    // capture -> service: someone copied something (only with
    // `--clipboard-listen`, which the service passes in sync mode). Copies
    // made by `set` are not reported back.
    changed = 4,
    // service -> capture: put this PNG on the clipboard (as PNG, CF_DIBV5
    // and CF_DIB, so any app can paste it).
    set_image = 5,
    // capture -> service: the clipboard's picture as PNG, answering a
    // `get`. Empty when there's one too large to send.
    image = 6,
    // capture -> service: someone copied a picture (as `changed`). Empty
    // when it's too large to send.
    image_changed = 7,
};

[[nodiscard]] constexpr bool is_image(ClipboardKind kind) noexcept {
    return kind == ClipboardKind::set_image || kind == ClipboardKind::image || kind == ClipboardKind::image_changed;
}

// The most a message of this kind may carry.
[[nodiscard]] constexpr std::uint32_t max_payload(ClipboardKind kind) noexcept {
    return is_image(kind) ? max_clipboard_image_size : max_clipboard_size;
}

// Precedes the payload of every message (UTF-8 text, or PNG), in both
// directions.
struct ClipboardPacketHeader {
    std::uint32_t magic = clipboard_packet_magic;
    std::uint32_t size = 0;  // payload bytes that follow
    std::uint8_t  kind = 0;  // ClipboardKind
    std::array<std::uint8_t, 7> reserved{};
};
static_assert(sizeof(ClipboardPacketHeader) == 16);

struct ImageSize {
    std::uint32_t width = 0;
    std::uint32_t height = 0;
};

// The width and height a PNG's header says, if `png` starts like one.
[[nodiscard]] inline std::optional<ImageSize> png_size(std::span<const std::byte> png) noexcept {
    constexpr std::array<std::uint8_t, 16> kStart{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n',
                                                  0,    0,   0,   13,  'I',  'H',  'D',  'R'};
    if (png.size() < 24) {
        return std::nullopt;
    }
    for (std::size_t i = 0; i < kStart.size(); ++i) {
        if (std::to_integer<std::uint8_t>(png[i]) != kStart[i]) {
            return std::nullopt;
        }
    }
    const auto u32 = [png](std::size_t at) {
        return (std::to_integer<std::uint32_t>(png[at]) << 24U) | (std::to_integer<std::uint32_t>(png[at + 1]) << 16U) |
               (std::to_integer<std::uint32_t>(png[at + 2]) << 8U) | std::to_integer<std::uint32_t>(png[at + 3]);
    };
    return ImageSize{.width = u32(16), .height = u32(20)};
}

// Whether a picture this size may go either way.
[[nodiscard]] constexpr bool image_fits(ImageSize size) noexcept {
    return size.width > 0 && size.height > 0 && size.width <= max_clipboard_image_side &&
           size.height <= max_clipboard_image_side &&
           std::uint64_t{size.width} * size.height <= max_clipboard_image_pixels;
}

}  // namespace hawk::ipc
