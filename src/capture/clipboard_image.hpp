#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

// Clipboard pictures, between what Windows keeps on the clipboard (a packed
// DIB: CF_DIB or CF_DIBV5) and what travels to viewers: PNG, the one image
// format browsers read from and write to their clipboard. WIC encodes and
// decodes the PNG, so the calling thread must have COM initialised.
//
// Everything is checked against ipc::max_clipboard_image_side and
// ipc::max_clipboard_image_pixels before any pixels are allocated.
namespace hawk::capture {

using ImageBytes = std::vector<std::byte>;

// 32-bit BGRA, top-down, straight (not premultiplied) alpha.
struct Bitmap {
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    ImageBytes    bgra;
    bool          opaque = true;  // every alpha is 255
};

// The pixels of a packed DIB: 24- or 32-bit, BI_RGB or BI_BITFIELDS,
// bottom-up or top-down. A 32-bit DIB whose alpha is zero throughout is
// taken as opaque: most apps leave that byte unused.
[[nodiscard]] std::expected<Bitmap, std::string> read_dib(std::span<const std::byte> dib);

[[nodiscard]] std::expected<Bitmap, std::string> decode_png(std::span<const std::byte> png);

// Without an alpha channel when the picture has no transparency: smaller.
[[nodiscard]] std::expected<ImageBytes, std::string> encode_png(const Bitmap& bitmap);

// CF_DIB: 24-bit and bottom-up, transparency laid over white, for the many
// apps that read only this and would show it black.
[[nodiscard]] ImageBytes write_dib(const Bitmap& bitmap);

// CF_DIBV5: 32-bit and bottom-up with an alpha mask, for the apps that keep
// transparency.
[[nodiscard]] ImageBytes write_dibv5(const Bitmap& bitmap);

}  // namespace hawk::capture
