#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

struct ID3D11Device;
struct ID3D11Texture2D;

namespace hawk::capture {

struct EncoderError {
    enum class Code : std::uint8_t {
        mf_startup_failed,
        no_hardware_encoder,
        configure_failed,
        device_manager_failed,
        convert_failed,
        encode_failed,
    };

    Code          code;
    std::uint32_t native_code = 0;  // underlying HRESULT, if any
    std::string   message;
};

[[nodiscard]] std::string_view to_string(EncoderError::Code code) noexcept;
[[nodiscard]] std::string      to_string(const EncoderError& error);

inline constexpr std::uint32_t default_encoder_fps = 30;
inline constexpr std::uint32_t default_encoder_bitrate_bps = 4'000'000;

struct EncoderConfig {
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    std::uint32_t fps = default_encoder_fps;
    std::uint32_t bitrate_bps = default_encoder_bitrate_bps;
};

// One Annex-B (start-code-prefixed) H.264 access unit.
struct EncodedPacket {
    std::vector<std::byte>    data;
    bool                       is_keyframe = false;
    std::chrono::microseconds timestamp{0};
};

// Hardware H.264 encoder on top of Media Foundation's hardware encoder MFT
// (whichever this system exposes — Quick Sync, NVENC, VCE, ...). Takes
// BGRA8 frames straight off the DesktopDuplicator's own D3D11 device: a GPU
// video processor does the BGRA->NV12 conversion the encoder needs, so a
// frame never has to round-trip through system memory.
//
// Requires the caller's process to have called CoInitializeEx on the
// encoding thread before open() — Media Foundation and the hardware MFTs
// it activates depend on COM being initialized.
class H264Encoder {
public:
    H264Encoder();
    ~H264Encoder();

    H264Encoder(H264Encoder&&) noexcept;
    H264Encoder& operator=(H264Encoder&&) noexcept;

    H264Encoder(const H264Encoder&) = delete;
    H264Encoder& operator=(const H264Encoder&) = delete;

    // `device` must be the same ID3D11Device the frames passed to encode()
    // live on (e.g. DesktopDuplicator::device()).
    [[nodiscard]] std::expected<void, EncoderError> open(ID3D11Device* device, const EncoderConfig& config);

    // Submits one BGRA8 GPU texture, sized to match the EncoderConfig given
    // to open(), for encoding. Returns std::nullopt when the encoder is
    // still buffering and hasn't produced an access unit yet — rare with a
    // low-latency hardware encoder, but callers should handle it.
    [[nodiscard]] std::expected<std::optional<EncodedPacket>, EncoderError> encode(
        ID3D11Texture2D* bgra_texture, std::chrono::microseconds timestamp);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace hawk::capture
