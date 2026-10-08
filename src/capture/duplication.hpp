#pragma once

#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>

struct ID3D11Device;
struct ID3D11DeviceContext;
struct ID3D11Texture2D;

namespace hawk::capture {

inline constexpr std::uint32_t default_frame_timeout_ms = 500;

struct CaptureError {
    enum class Code : std::uint8_t {
        no_duplication_support,
        device_creation_failed,
        duplication_failed,
        access_lost,
        timeout,
        frame_failed,
    };

    Code          code;
    std::uint32_t native_code = 0;  // underlying HRESULT, if any
    std::string   message;
};

[[nodiscard]] std::string_view to_string(CaptureError::Code code) noexcept;
[[nodiscard]] std::string      to_string(const CaptureError& error);

// The captured monitor's rectangle on the virtual desktop, in pixels, as
// DXGI reports it (DXGI_OUTPUT_DESC::DesktopCoordinates). Frames cover
// exactly this rectangle, so it's what turns a position within a frame back
// into a position on the desktop — see capture/input.cpp.
struct DesktopBounds {
    std::int32_t left = 0;
    std::int32_t top = 0;
    std::int32_t right = 0;
    std::int32_t bottom = 0;
};

// A captured frame, resident entirely on the GPU: BGRA8, D3D11_USAGE_DEFAULT,
// bound as a render target (what D3D11 video-processor input views require)
// so it can feed straight into a video processor for color conversion (e.g.
// H264Encoder). Borrows the DesktopDuplicator's copy texture: valid only
// until the next capture_frame() call or the duplicator's destruction,
// whichever is first.
struct Frame {
    std::uint32_t    width = 0;
    std::uint32_t    height = 0;
    ID3D11Texture2D* texture = nullptr;  // owned by the DesktopDuplicator, not this Frame
};

// Captures the desktop via the DXGI Desktop Duplication API.
//
// This only ever sees the desktop of the session it runs in — a Session 0
// Windows service has no desktop to capture at all, so this must be used
// from an ordinary process running in the interactive user's own session.
class DesktopDuplicator {
public:
    DesktopDuplicator();
    ~DesktopDuplicator();

    DesktopDuplicator(DesktopDuplicator&&) noexcept;
    DesktopDuplicator& operator=(DesktopDuplicator&&) noexcept;

    DesktopDuplicator(const DesktopDuplicator&) = delete;
    DesktopDuplicator& operator=(const DesktopDuplicator&) = delete;

    // Binds to the given output (monitor) index on the default adapter.
    [[nodiscard]] std::expected<void, CaptureError> open(std::uint32_t output_index = 0);

    // Blocks up to `timeout_ms` for the next frame. A timeout (no screen
    // changes in that window) is reported as CaptureError::Code::timeout;
    // callers should treat that as "nothing new yet", not fatal, and call
    // capture_frame() again.
    [[nodiscard]] std::expected<Frame, CaptureError> capture_frame(std::uint32_t timeout_ms = default_frame_timeout_ms);

    // Rebuilds the duplication after capture_frame() returns
    // CaptureError::Code::access_lost — which DXGI raises on a desktop
    // switch (the UAC prompt and lock screen run on the secure desktop,
    // which this can't read) and on a mode change. The D3D device and the
    // frame texture are preserved, so an encoder bound to device() stays
    // valid across the call. Fails while the secure desktop is still up;
    // callers retry until it succeeds. Only valid after a successful open().
    [[nodiscard]] std::expected<void, CaptureError> reacquire();

    // Where on the virtual desktop the captured monitor sits. Only
    // meaningful after a successful open().
    [[nodiscard]] DesktopBounds bounds() const noexcept;

    // Shared with H264Encoder so encoding happens on the same D3D11 device
    // the capture texture lives on — required for the zero-copy GPU path.
    // Only valid after a successful open().
    [[nodiscard]] ID3D11Device* device() const noexcept;

private:
    // (Re)binds the duplication interface for `output_index` on the existing
    // device. Shared by open() and reacquire().
    [[nodiscard]] std::expected<void, CaptureError> acquire_duplication(std::uint32_t output_index);

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace hawk::capture
