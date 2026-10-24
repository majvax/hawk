#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

// Wire format of the local named pipe hawk-service sends input events to
// hawk-capture over, which hawk-capture replays into the session with
// SendInput. Both ends are built from this tree for the same architecture,
// so a packet is written and read as a raw struct.
//
// The pipe is created by hawk-service (outbound only, remote clients
// rejected, DACL limited to SYSTEM, which hawk-capture runs as) alongside the
// video pipe, and its name is handed to hawk-capture on its command line as
// `--input-pipe <name>`. Keeping input off the video pipe is the control /
// data channel separation the README asks for: a stalled video reader can't
// hold up input, and neither end has to frame two kinds of packet. The
// stream's encoder settings travel here too: they're control, not data.
namespace hawk::ipc {

inline constexpr std::uint32_t input_packet_magic = 0x504E4948;  // "HINP", little-endian

enum class InputKind : std::uint8_t {
    mouse_move = 1,
    mouse_button = 2,
    wheel = 3,
    key = 4,
    // Release everything input is holding down (the viewer stopped watching
    // or lost control), so nothing stays stuck on the machine.
    release_all = 5,
    // Encode at `bitrate_bps` and `fps` from now on (the viewer's quality
    // preset, or Auto's next step).
    encoder = 6,
    // Type `length` UTF-16 units from `code` as characters, whatever the
    // machine's keyboard layout (KEYEVENTF_UNICODE): what a phone's
    // keyboard typed. Nothing is held down after it.
    text = 7,
    // A shortcut: the modifiers in `button` (modifier_* bits) held while
    // the key that types the one UTF-16 unit in `code` is pressed, that key
    // found in the layout of the window it goes to (Ctrl+A is Ctrl and
    // whichever key types "a" there). All pressed and let go at once.
    chord = 8,
};

// A chord's modifiers, as bits of InputPacket::button.
inline constexpr std::uint8_t modifier_ctrl = 1;
inline constexpr std::uint8_t modifier_alt = 2;
inline constexpr std::uint8_t modifier_shift = 4;
inline constexpr std::uint8_t modifier_win = 8;

enum class InputButton : std::uint8_t {
    left = 1,
    right = 2,
    middle = 3,
};

// Room for a `KeyboardEvent.code` and its terminator. The relay caps codes
// at 31 characters to fit; a longer one names no key on any keyboard, and
// hawk-service drops it too rather than sending a truncated name.
inline constexpr std::size_t max_key_code_size = 32;
// The most UTF-16 units one text packet carries, in the same array. A
// surrogate pair is never split across packets.
inline constexpr std::size_t max_text_units = max_key_code_size / sizeof(char16_t);

// One input event. Fixed size: the reader knows every packet's length up
// front, so there's nothing to frame and nothing to allocate per event.
struct InputPacket {
    std::uint32_t magic = input_packet_magic;
    std::uint8_t  kind = 0;    // InputKind
    std::uint8_t  button = 0;  // InputButton; mouse_button only. chord: modifier_* bits
    std::uint8_t  down = 0;    // mouse_button and key only
    std::uint8_t  length = 0;  // text and chord: UTF-16 units in `code`
    // Pointer position as a fraction of the captured screen, 0..=1 from its
    // top-left corner: the browser doesn't need the machine's resolution,
    // and the position stays right across a mode change.
    double x = 0.0;
    double y = 0.0;
    // Wheel movement in WHEEL_DELTA units (120 per notch); positive is up /
    // right. wheel only.
    std::int32_t wheel_dx = 0;
    std::int32_t wheel_dy = 0;
    // The physical key, as `KeyboardEvent.code` ("KeyA", "ShiftLeft"),
    // NUL-terminated. key only. For text and chord, `length` UTF-16 units
    // instead, in this machine's byte order, not terminated.
    std::array<char, max_key_code_size> code{};
    // encoder only.
    std::uint32_t bitrate_bps = 0;
    std::uint32_t fps = 0;
};
static_assert(sizeof(InputPacket) == 72);

}  // namespace hawk::ipc
