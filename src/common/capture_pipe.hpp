#pragma once

#include <array>
#include <cstdint>

// Wire format of the local named pipe hawk-capture streams its encoded video
// to hawk-service over. Both ends are built from this tree for the same
// architecture, so the header is written and read as a raw struct.
//
// The pipe itself is created by hawk-service (inbound only, remote clients
// rejected, DACL limited to SYSTEM and the logged-on user) and its name is
// handed to hawk-capture on its command line as `--pipe <name>`.
namespace hawk::ipc {

inline constexpr std::uint32_t capture_packet_magic = 0x4B574148;  // "HAWK", little-endian
inline constexpr std::uint8_t  capture_flag_keyframe = 0x01;

// Upper bound on one access unit, so a corrupt header can't make the reader
// allocate an arbitrary amount of memory.
inline constexpr std::uint32_t max_capture_packet_size = 16U * 1024U * 1024U;

// Precedes every H.264 access unit (Annex B) on the pipe.
struct CapturePacketHeader {
    std::uint32_t               magic = capture_packet_magic;
    std::uint32_t               size = 0;          // payload bytes that follow
    std::int64_t                timestamp_us = 0;  // since the start of the stream
    std::uint8_t                flags = 0;         // capture_flag_*
    std::array<std::uint8_t, 7> reserved{};
};
static_assert(sizeof(CapturePacketHeader) == 24);

}  // namespace hawk::ipc
