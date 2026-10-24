#include "clipboard_image.hpp"

#include "common/clipboard_pipe.hpp"

#include <windows.h>
#include <objidl.h>
#include <wincodec.h>
#include <wrl/client.h>

#include <bit>
#include <cstring>
#include <format>
#include <limits>

namespace hawk::capture {

namespace {

using Microsoft::WRL::ComPtr;

// The two headers a packed DIB starts with; BITMAPV4HEADER sits between
// them and reads like the V5 as far as the masks.
constexpr std::uint32_t kInfoHeaderSize = sizeof(BITMAPINFOHEADER);
constexpr std::uint32_t kV4HeaderSize = sizeof(BITMAPV4HEADER);
constexpr std::uint32_t kV5HeaderSize = sizeof(BITMAPV5HEADER);

[[nodiscard]] std::string hresult_text(std::string_view what, HRESULT hr) {
    return std::format("{} failed (0x{:08X})", what, static_cast<std::uint32_t>(hr));
}

// Bytes in one row of a DIB: whole DWORDs.
[[nodiscard]] constexpr std::uint64_t dib_stride(std::uint32_t width, std::uint32_t bits) {
    return ((std::uint64_t{width} * bits + 31) / 32) * 4;
}

[[nodiscard]] bool fits(std::uint64_t width, std::uint64_t height) {
    return width <= std::numeric_limits<std::uint32_t>::max() && height <= std::numeric_limits<std::uint32_t>::max() &&
           ipc::image_fits({.width = static_cast<std::uint32_t>(width), .height = static_cast<std::uint32_t>(height)});
}

// One colour channel of a BI_BITFIELDS pixel, scaled to 8 bits.
struct Channel {
    std::uint32_t mask = 0;
    int           shift = 0;
    int           bits = 0;

    explicit Channel(std::uint32_t m) : mask(m), shift(m == 0 ? 0 : std::countr_zero(m)), bits(std::popcount(m)) {}

    [[nodiscard]] std::uint8_t read(std::uint32_t pixel) const {
        if (bits == 0) {
            return 0;
        }
        const std::uint32_t value = (pixel & mask) >> static_cast<unsigned>(shift);
        if (bits >= 8) {
            return static_cast<std::uint8_t>(value >> static_cast<unsigned>(bits - 8));
        }
        const std::uint32_t top = (1U << static_cast<unsigned>(bits)) - 1;
        return static_cast<std::uint8_t>((value * 255 + top / 2) / top);
    }
};

[[nodiscard]] std::uint32_t read_u32(const std::byte* at) {
    std::uint32_t value = 0;
    std::memcpy(&value, at, sizeof(value));
    return value;
}

[[nodiscard]] ComPtr<IWICImagingFactory> factory() {
    ComPtr<IWICImagingFactory> wic;
    CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&wic));
    return wic;
}

[[nodiscard]] bool all_opaque(const ImageBytes& bgra) {
    for (std::size_t i = 3; i < bgra.size(); i += 4) {
        if (bgra[i] != std::byte{0xFF}) {
            return false;
        }
    }
    return true;
}

}  // namespace

std::expected<Bitmap, std::string> read_dib(std::span<const std::byte> dib) {
    if (dib.size() < kInfoHeaderSize) {
        return std::unexpected("the bitmap is too short");
    }
    BITMAPINFOHEADER header{};
    std::memcpy(&header, dib.data(), sizeof(header));
    if (header.biSize != kInfoHeaderSize && header.biSize != kV4HeaderSize && header.biSize != kV5HeaderSize) {
        return std::unexpected(std::format("bitmap header of {} bytes", header.biSize));
    }
    if (header.biSize > dib.size()) {
        return std::unexpected("the bitmap is too short");
    }
    const std::uint32_t bits = header.biBitCount;
    const bool          bitfields = header.biCompression == BI_BITFIELDS;
    if ((bits != 24 && bits != 32) || (header.biCompression != BI_RGB && !(bitfields && bits == 32)) ||
        header.biPlanes != 1) {
        return std::unexpected(std::format("{}-bit bitmaps (compression {}) aren't supported", bits,
                                           header.biCompression));
    }
    const std::int64_t  signed_height = header.biHeight;
    const bool          top_down = signed_height < 0;
    const std::uint64_t width = header.biWidth < 0 ? 0 : static_cast<std::uint64_t>(header.biWidth);
    const std::uint64_t height = static_cast<std::uint64_t>(top_down ? -signed_height : signed_height);
    if (!fits(width, height)) {
        return std::unexpected(std::format("a {}x{} picture is past what's sent", width, height));
    }

    // Masks: in the header from V4 on, otherwise three DWORDs right after it.
    std::uint32_t red = 0x00FF0000;
    std::uint32_t green = 0x0000FF00;
    std::uint32_t blue = 0x000000FF;
    std::uint32_t alpha = bits == 32 ? 0xFF000000 : 0;
    std::uint64_t offset = header.biSize;
    if (bitfields) {
        const std::byte* masks = dib.data() + kInfoHeaderSize;
        if (header.biSize == kInfoHeaderSize) {
            if (dib.size() < kInfoHeaderSize + 12) {
                return std::unexpected("the bitmap is too short");
            }
            offset += 12;
            alpha = 0;  // only V4 and V5 headers can say where alpha is
        } else {
            alpha = read_u32(masks + 12);
        }
        red = read_u32(masks);
        green = read_u32(masks + 4);
        blue = read_u32(masks + 8);
    }
    // A colour table is only for 8 bits or fewer, but may be there anyway.
    offset += std::uint64_t{header.biClrUsed} * 4;
    const auto stride = dib_stride(static_cast<std::uint32_t>(width), bits);
    if (offset > dib.size() || stride * height > dib.size() - offset) {
        return std::unexpected("the bitmap is shorter than its size says");
    }

    Bitmap bitmap{.width = static_cast<std::uint32_t>(width), .height = static_cast<std::uint32_t>(height), .bgra = {}};
    bitmap.bgra.resize(width * height * 4);
    const Channel r(red);
    const Channel g(green);
    const Channel b(blue);
    const Channel a(alpha);
    bool          any_alpha = false;
    for (std::uint64_t y = 0; y < height; ++y) {
        const std::byte* row = dib.data() + offset + stride * (top_down ? y : height - 1 - y);
        std::byte*       out = bitmap.bgra.data() + y * width * 4;
        for (std::uint64_t x = 0; x < width; ++x, out += 4) {
            if (bits == 24) {
                out[0] = row[x * 3];
                out[1] = row[x * 3 + 1];
                out[2] = row[x * 3 + 2];
                out[3] = std::byte{0xFF};
                continue;
            }
            const std::uint32_t pixel = read_u32(row + x * 4);
            out[0] = std::byte{b.read(pixel)};
            out[1] = std::byte{g.read(pixel)};
            out[2] = std::byte{r.read(pixel)};
            out[3] = std::byte{a.read(pixel)};
            any_alpha = any_alpha || out[3] != std::byte{0};
        }
    }
    // An alpha that's zero everywhere is a byte nobody filled in, not a
    // picture nobody can see.
    if (bits == 32 && !any_alpha) {
        for (std::size_t i = 3; i < bitmap.bgra.size(); i += 4) {
            bitmap.bgra[i] = std::byte{0xFF};
        }
    }
    bitmap.opaque = bits == 24 || !any_alpha || all_opaque(bitmap.bgra);
    return bitmap;
}

std::expected<Bitmap, std::string> decode_png(std::span<const std::byte> png) {
    const auto size = ipc::png_size(png);
    if (!size.has_value()) {
        return std::unexpected("not a PNG");
    }
    if (!ipc::image_fits(*size)) {
        return std::unexpected(std::format("a {}x{} picture is past what's taken", size->width, size->height));
    }
    const auto wic = factory();
    if (wic == nullptr) {
        return std::unexpected("WIC isn't available");
    }
    ComPtr<IWICStream> stream;
    HRESULT            hr = wic->CreateStream(&stream);
    if (SUCCEEDED(hr)) {
        // WIC only reads it.
        hr = stream->InitializeFromMemory(reinterpret_cast<BYTE*>(const_cast<std::byte*>(png.data())),
                                          static_cast<DWORD>(png.size()));
    }
    ComPtr<IWICBitmapDecoder> decoder;
    if (SUCCEEDED(hr)) {
        hr = wic->CreateDecoderFromStream(stream.Get(), &GUID_VendorMicrosoft, WICDecodeMetadataCacheOnDemand,
                                          &decoder);
    }
    ComPtr<IWICBitmapFrameDecode> frame;
    if (SUCCEEDED(hr)) {
        hr = decoder->GetFrame(0, &frame);
    }
    UINT width = 0;
    UINT height = 0;
    if (SUCCEEDED(hr)) {
        hr = frame->GetSize(&width, &height);
    }
    if (FAILED(hr)) {
        return std::unexpected(hresult_text("reading the PNG", hr));
    }
    if (!fits(width, height)) {
        return std::unexpected(std::format("a {}x{} picture is past what's taken", width, height));
    }
    ComPtr<IWICBitmapSource> converted;
    hr = WICConvertBitmapSource(GUID_WICPixelFormat32bppBGRA, frame.Get(), &converted);
    Bitmap bitmap{.width = width, .height = height, .bgra = {}};
    bitmap.bgra.resize(std::size_t{width} * height * 4);
    if (SUCCEEDED(hr)) {
        hr = converted->CopyPixels(nullptr, width * 4, static_cast<UINT>(bitmap.bgra.size()),
                                   reinterpret_cast<BYTE*>(bitmap.bgra.data()));
    }
    if (FAILED(hr)) {
        return std::unexpected(hresult_text("decoding the PNG", hr));
    }
    bitmap.opaque = all_opaque(bitmap.bgra);
    return bitmap;
}

std::expected<ImageBytes, std::string> encode_png(const Bitmap& bitmap) {
    if (!ipc::image_fits({.width = bitmap.width, .height = bitmap.height}) ||
        bitmap.bgra.size() != std::size_t{bitmap.width} * bitmap.height * 4) {
        return std::unexpected("not a picture that's sent");
    }
    const auto wic = factory();
    if (wic == nullptr) {
        return std::unexpected("WIC isn't available");
    }
    // 24-bit for an opaque picture: a quarter fewer bytes to compress.
    const UINT  pixel_bytes = bitmap.opaque ? 3 : 4;
    ImageBytes  packed;
    const auto* pixels = bitmap.bgra.data();
    if (bitmap.opaque) {
        packed.resize(std::size_t{bitmap.width} * bitmap.height * 3);
        for (std::size_t i = 0, o = 0; i < bitmap.bgra.size(); i += 4, o += 3) {
            packed[o] = bitmap.bgra[i];
            packed[o + 1] = bitmap.bgra[i + 1];
            packed[o + 2] = bitmap.bgra[i + 2];
        }
        pixels = packed.data();
    }

    ComPtr<IStream> stream;
    HRESULT         hr = CreateStreamOnHGlobal(nullptr, TRUE, &stream);
    ComPtr<IWICBitmapEncoder> encoder;
    if (SUCCEEDED(hr)) {
        hr = wic->CreateEncoder(GUID_ContainerFormatPng, nullptr, &encoder);
    }
    if (SUCCEEDED(hr)) {
        hr = encoder->Initialize(stream.Get(), WICBitmapEncoderNoCache);
    }
    ComPtr<IWICBitmapFrameEncode> frame;
    if (SUCCEEDED(hr)) {
        hr = encoder->CreateNewFrame(&frame, nullptr);
    }
    if (SUCCEEDED(hr)) {
        hr = frame->Initialize(nullptr);
    }
    if (SUCCEEDED(hr)) {
        hr = frame->SetSize(bitmap.width, bitmap.height);
    }
    WICPixelFormatGUID format = bitmap.opaque ? GUID_WICPixelFormat24bppBGR : GUID_WICPixelFormat32bppBGRA;
    if (SUCCEEDED(hr)) {
        hr = frame->SetPixelFormat(&format);
    }
    if (SUCCEEDED(hr) && format != (bitmap.opaque ? GUID_WICPixelFormat24bppBGR : GUID_WICPixelFormat32bppBGRA)) {
        hr = E_UNEXPECTED;  // the encoder wanted another layout
    }
    if (SUCCEEDED(hr)) {
        const UINT stride = bitmap.width * pixel_bytes;
        hr = frame->WritePixels(bitmap.height, stride, stride * bitmap.height,
                                reinterpret_cast<BYTE*>(const_cast<std::byte*>(pixels)));
    }
    if (SUCCEEDED(hr)) {
        hr = frame->Commit();
    }
    if (SUCCEEDED(hr)) {
        hr = encoder->Commit();
    }
    HGLOBAL memory = nullptr;
    if (SUCCEEDED(hr)) {
        hr = GetHGlobalFromStream(stream.Get(), &memory);
    }
    STATSTG stat{};
    if (SUCCEEDED(hr)) {
        hr = stream->Stat(&stat, STATFLAG_NONAME);
    }
    if (FAILED(hr)) {
        return std::unexpected(hresult_text("encoding the PNG", hr));
    }
    const auto  size = static_cast<std::size_t>(stat.cbSize.QuadPart);
    const auto* locked = static_cast<const std::byte*>(GlobalLock(memory));
    if (locked == nullptr) {
        return std::unexpected("encoding the PNG failed (GlobalLock)");
    }
    ImageBytes png(locked, locked + size);
    GlobalUnlock(memory);
    return png;
}

ImageBytes write_dib(const Bitmap& bitmap) {
    const auto stride = dib_stride(bitmap.width, 24);
    ImageBytes dib(kInfoHeaderSize + stride * bitmap.height);
    BITMAPINFOHEADER header{};
    header.biSize = kInfoHeaderSize;
    header.biWidth = static_cast<LONG>(bitmap.width);
    header.biHeight = static_cast<LONG>(bitmap.height);  // bottom-up
    header.biPlanes = 1;
    header.biBitCount = 24;
    header.biCompression = BI_RGB;
    header.biSizeImage = static_cast<DWORD>(stride * bitmap.height);
    std::memcpy(dib.data(), &header, sizeof(header));
    for (std::uint32_t y = 0; y < bitmap.height; ++y) {
        const std::byte* in = bitmap.bgra.data() + std::size_t{y} * bitmap.width * 4;
        std::byte*       row = dib.data() + kInfoHeaderSize + stride * (bitmap.height - 1 - y);
        for (std::uint32_t x = 0; x < bitmap.width; ++x, in += 4) {
            const auto alpha = std::to_integer<unsigned>(in[3]);
            for (std::size_t c = 0; c < 3; ++c) {
                // Over white: c * a + 255 * (1 - a), rounded.
                const auto value = std::to_integer<unsigned>(in[c]);
                row[std::size_t{x} * 3 + c] = std::byte(static_cast<std::uint8_t>((value * alpha + 255 * (255 - alpha) + 127) / 255));
            }
        }
    }
    return dib;
}

ImageBytes write_dibv5(const Bitmap& bitmap) {
    const std::size_t stride = std::size_t{bitmap.width} * 4;
    ImageBytes        dib(kV5HeaderSize + stride * bitmap.height);
    BITMAPV5HEADER    header{};
    header.bV5Size = kV5HeaderSize;
    header.bV5Width = static_cast<LONG>(bitmap.width);
    header.bV5Height = static_cast<LONG>(bitmap.height);  // bottom-up
    header.bV5Planes = 1;
    header.bV5BitCount = 32;
    header.bV5Compression = BI_BITFIELDS;
    header.bV5SizeImage = static_cast<DWORD>(stride * bitmap.height);
    header.bV5RedMask = 0x00FF0000;
    header.bV5GreenMask = 0x0000FF00;
    header.bV5BlueMask = 0x000000FF;
    header.bV5AlphaMask = 0xFF000000;
    header.bV5CSType = 0x73524742;  // LCS_sRGB ('sRGB'), spelled out: the macro is a multi-character constant
    header.bV5Intent = LCS_GM_IMAGES;
    std::memcpy(dib.data(), &header, sizeof(header));
    for (std::uint32_t y = 0; y < bitmap.height; ++y) {
        std::memcpy(dib.data() + kV5HeaderSize + stride * (bitmap.height - 1 - y),
                    bitmap.bgra.data() + stride * y, stride);
    }
    return dib;
}

}  // namespace hawk::capture
