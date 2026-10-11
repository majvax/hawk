#pragma once

#include <array>
#include <cstdint>

// Wire format of the local named pipe hawk-service and hawk-capture trade
// clipboard text over. Both ends are built from this tree for the same
// architecture, so the header is written and read as a raw struct.
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

enum class ClipboardKind : std::uint8_t {
    // service -> capture: put this text on the clipboard.
    set = 1,
    // service -> capture: read the clipboard; answered with `text`.
    get = 2,
    // capture -> service: what the clipboard holds, answering a `get`.
    text = 3,
    // capture -> service: someone copied something (only with
    // `--clipboard-listen`, which the service passes in sync mode). Copies
    // made by `set` are not reported back.
    changed = 4,
};

// Precedes the UTF-8 text of every message, in both directions.
struct ClipboardPacketHeader {
    std::uint32_t magic = clipboard_packet_magic;
    std::uint32_t size = 0;  // payload bytes that follow
    std::uint8_t  kind = 0;  // ClipboardKind
    std::array<std::uint8_t, 7> reserved{};
};
static_assert(sizeof(ClipboardPacketHeader) == 16);

}  // namespace hawk::ipc
