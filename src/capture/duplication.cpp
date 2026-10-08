#include "duplication.hpp"

#include <d3d11.h>
#include <dxgi1_2.h>

#include <array>
#include <format>
#include <utility>

namespace hawk::capture {

namespace {

[[nodiscard]] CaptureError make_error(CaptureError::Code code, long hresult, std::string_view context) {
    return CaptureError{
        .code = code,
        .native_code = static_cast<std::uint32_t>(hresult),
        .message = std::format("{}: HRESULT 0x{:08X}", context, static_cast<std::uint32_t>(hresult)),
    };
}

[[nodiscard]] CaptureError make_simple_error(CaptureError::Code code, std::string message) {
    return CaptureError{.code = code, .native_code = 0, .message = std::move(message)};
}

template <typename T>
void release(T*& ptr) noexcept {
    if (ptr != nullptr) {
        ptr->Release();
        ptr = nullptr;
    }
}

// QueryInterface fundamentally reinterprets a vtable pointer as a different
// interface type; funnelling that single cast through a void* here (rather
// than reinterpret_cast<T**> at each call site) keeps every call site to a
// plain, checkable static_cast<T*>(void*).
template <typename T>
[[nodiscard]] HRESULT query_interface(IUnknown* source, REFIID iid, T** out) {
    void*          raw = nullptr;
    const HRESULT  result = source->QueryInterface(iid, &raw);
    *out = static_cast<T*>(raw);
    return result;
}

}  // namespace

std::string_view to_string(CaptureError::Code code) noexcept {
    switch (code) {
        case CaptureError::Code::no_duplication_support:
            return "no_duplication_support";
        case CaptureError::Code::device_creation_failed:
            return "device_creation_failed";
        case CaptureError::Code::duplication_failed:
            return "duplication_failed";
        case CaptureError::Code::access_lost:
            return "access_lost";
        case CaptureError::Code::timeout:
            return "timeout";
        case CaptureError::Code::frame_failed:
            return "frame_failed";
    }
    return "unknown";
}

std::string to_string(const CaptureError& error) {
    if (error.native_code != 0) {
        return std::format("[{}] {} (native code 0x{:08X})", to_string(error.code), error.message,
                            error.native_code);
    }
    return std::format("[{}] {}", to_string(error.code), error.message);
}

struct DesktopDuplicator::Impl {
    ID3D11Device*           device = nullptr;
    ID3D11DeviceContext*    context = nullptr;
    IDXGIOutputDuplication* duplication = nullptr;
    ID3D11Texture2D*        copy = nullptr;  // GPU-resident BGRA8, reused every frame

    std::uint32_t width = 0;
    std::uint32_t height = 0;
    std::uint32_t output_index = 0;  // the monitor open() bound, so reacquire() hits the same one
    DesktopBounds bounds{};

    Impl() = default;
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
    Impl(Impl&&) = delete;
    Impl& operator=(Impl&&) = delete;

    ~Impl() {
        release(copy);
        release(duplication);
        release(context);
        release(device);
    }
};

DesktopDuplicator::DesktopDuplicator() : impl_(std::make_unique<Impl>()) {}
DesktopDuplicator::~DesktopDuplicator() = default;
DesktopDuplicator::DesktopDuplicator(DesktopDuplicator&&) noexcept = default;
DesktopDuplicator& DesktopDuplicator::operator=(DesktopDuplicator&&) noexcept = default;

std::expected<void, CaptureError> DesktopDuplicator::open(std::uint32_t output_index) {
    static constexpr std::array<D3D_FEATURE_LEVEL, 4> feature_levels{
        D3D_FEATURE_LEVEL_11_1,
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_1,
        D3D_FEATURE_LEVEL_10_0,
    };

    // VIDEO_SUPPORT + BGRA_SUPPORT: required for the ID3D11VideoDevice /
    // video processor interop that H264Encoder uses to convert these BGRA8
    // frames to NV12 on the GPU.
    constexpr UINT device_flags = D3D11_CREATE_DEVICE_VIDEO_SUPPORT | D3D11_CREATE_DEVICE_BGRA_SUPPORT;

    D3D_FEATURE_LEVEL obtained_level{};
    HRESULT hresult =
        D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, device_flags, feature_levels.data(),
                          static_cast<UINT>(feature_levels.size()), D3D11_SDK_VERSION, &impl_->device,
                          &obtained_level, &impl_->context);
    if (FAILED(hresult)) {
        return std::unexpected(
            make_error(CaptureError::Code::device_creation_failed, hresult, "D3D11CreateDevice"));
    }

    if (auto acquired = acquire_duplication(output_index); !acquired.has_value()) {
        return acquired;
    }

    const D3D11_TEXTURE2D_DESC copy_desc{
        .Width = impl_->width,
        .Height = impl_->height,
        .MipLevels = 1,
        .ArraySize = 1,
        .Format = DXGI_FORMAT_B8G8R8A8_UNORM,
        .SampleDesc = {.Count = 1, .Quality = 0},
        .Usage = D3D11_USAGE_DEFAULT,
        // D3D11 video-processor input views (see H264Encoder's BGRA->NV12
        // step) require the source resource to carry this bind flag;
        // SHADER_RESOURCE alone makes CreateVideoProcessorInputView fail
        // with E_INVALIDARG.
        .BindFlags = D3D11_BIND_RENDER_TARGET,
        .CPUAccessFlags = 0,
        .MiscFlags = 0,
    };
    hresult = impl_->device->CreateTexture2D(&copy_desc, nullptr, &impl_->copy);
    if (FAILED(hresult)) {
        return std::unexpected(
            make_error(CaptureError::Code::device_creation_failed, hresult, "CreateTexture2D(copy)"));
    }

    return {};
}

// (Re)acquires the duplication interface for `output_index` on the already
// created device, releasing any prior one. Everything else the duplicator
// holds — the D3D device the encoder is bound to, the copy texture — is
// left intact, so this is safe to call to recover a lost duplication
// without disturbing the encoder. See reacquire().
std::expected<void, CaptureError> DesktopDuplicator::acquire_duplication(std::uint32_t output_index) {
    release(impl_->duplication);
    impl_->duplication = nullptr;
    impl_->output_index = output_index;

    IDXGIDevice* dxgi_device = nullptr;
    HRESULT      hresult = query_interface(impl_->device, __uuidof(IDXGIDevice), &dxgi_device);
    if (FAILED(hresult)) {
        return std::unexpected(make_error(CaptureError::Code::device_creation_failed, hresult, "IDXGIDevice"));
    }

    IDXGIAdapter* adapter = nullptr;
    hresult = dxgi_device->GetAdapter(&adapter);
    release(dxgi_device);
    if (FAILED(hresult)) {
        return std::unexpected(make_error(CaptureError::Code::device_creation_failed, hresult, "IDXGIAdapter"));
    }

    IDXGIOutput* output = nullptr;
    hresult = adapter->EnumOutputs(output_index, &output);
    release(adapter);
    if (FAILED(hresult)) {
        return std::unexpected(make_error(CaptureError::Code::no_duplication_support, hresult, "EnumOutputs"));
    }

    IDXGIOutput1* output1 = nullptr;
    hresult = query_interface(output, __uuidof(IDXGIOutput1), &output1);
    release(output);
    if (FAILED(hresult)) {
        return std::unexpected(make_error(CaptureError::Code::no_duplication_support, hresult, "IDXGIOutput1"));
    }

    // Where this monitor sits on the virtual desktop; input replayed into
    // the session is positioned against it (see capture/input.cpp).
    DXGI_OUTPUT_DESC output_desc{};
    if (SUCCEEDED(output1->GetDesc(&output_desc))) {
        impl_->bounds = DesktopBounds{
            .left = output_desc.DesktopCoordinates.left,
            .top = output_desc.DesktopCoordinates.top,
            .right = output_desc.DesktopCoordinates.right,
            .bottom = output_desc.DesktopCoordinates.bottom,
        };
    }

    hresult = output1->DuplicateOutput(impl_->device, &impl_->duplication);
    release(output1);
    if (FAILED(hresult)) {
        return std::unexpected(make_error(CaptureError::Code::duplication_failed, hresult, "DuplicateOutput"));
    }

    DXGI_OUTDUPL_DESC desc{};
    impl_->duplication->GetDesc(&desc);
    impl_->width = desc.ModeDesc.Width;
    impl_->height = desc.ModeDesc.Height;
    if (impl_->bounds.right <= impl_->bounds.left || impl_->bounds.bottom <= impl_->bounds.top) {
        // GetDesc above didn't say where the monitor is; assume it's the one
        // at the desktop's origin, which is where a single monitor sits.
        impl_->bounds = DesktopBounds{.left = 0,
                                      .top = 0,
                                      .right = static_cast<std::int32_t>(impl_->width),
                                      .bottom = static_cast<std::int32_t>(impl_->height)};
    }
    return {};
}

std::expected<void, CaptureError> DesktopDuplicator::reacquire() {
    if (impl_->device == nullptr) {
        return std::unexpected(make_simple_error(CaptureError::Code::duplication_failed, "reacquire() before open()"));
    }
    const std::uint32_t previous_width = impl_->width;
    const std::uint32_t previous_height = impl_->height;
    if (auto acquired = acquire_duplication(impl_->output_index); !acquired.has_value()) {
        return acquired;
    }
    // The copy texture and the encoder downstream are sized to the old
    // resolution. If the mode changed while duplication was lost, keeping
    // them would feed the encoder a mismatched frame; report it as a lost
    // duplication so the caller restarts instead.
    if (impl_->width != previous_width || impl_->height != previous_height) {
        return std::unexpected(make_simple_error(CaptureError::Code::access_lost,
                                                 "display mode changed while duplication was lost"));
    }
    return {};
}

std::expected<Frame, CaptureError> DesktopDuplicator::capture_frame(std::uint32_t timeout_ms) {
    if (impl_->duplication == nullptr) {
        return std::unexpected(
            make_simple_error(CaptureError::Code::duplication_failed, "capture_frame() called before open()"));
    }

    DXGI_OUTDUPL_FRAME_INFO frame_info{};
    IDXGIResource*          resource = nullptr;
    HRESULT hresult = impl_->duplication->AcquireNextFrame(timeout_ms, &frame_info, &resource);

    if (hresult == DXGI_ERROR_WAIT_TIMEOUT) {
        return std::unexpected(make_simple_error(CaptureError::Code::timeout, "no new frame within timeout"));
    }
    if (hresult == DXGI_ERROR_ACCESS_LOST) {
        return std::unexpected(make_error(CaptureError::Code::access_lost, hresult, "AcquireNextFrame"));
    }
    if (FAILED(hresult)) {
        return std::unexpected(make_error(CaptureError::Code::frame_failed, hresult, "AcquireNextFrame"));
    }

    ID3D11Texture2D* frame_texture = nullptr;
    hresult = query_interface(resource, __uuidof(ID3D11Texture2D), &frame_texture);
    release(resource);
    if (FAILED(hresult)) {
        impl_->duplication->ReleaseFrame();
        return std::unexpected(make_error(CaptureError::Code::frame_failed, hresult, "ID3D11Texture2D"));
    }

    impl_->context->CopyResource(impl_->copy, frame_texture);
    release(frame_texture);
    impl_->duplication->ReleaseFrame();

    return Frame{
        .width = impl_->width,
        .height = impl_->height,
        .texture = impl_->copy,
    };
}

DesktopBounds DesktopDuplicator::bounds() const noexcept {
    return impl_->bounds;
}

ID3D11Device* DesktopDuplicator::device() const noexcept {
    return impl_->device;
}

}  // namespace hawk::capture
