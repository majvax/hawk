#include "encoder.hpp"

// d3d11.h must come first: it pulls in <unknwn.h>, which declares the
// __mingw_uuidof_s primary template that codecapi.h's DEFINE_CODECAPI_GUID
// macro explicitly specializes. Included in the other order, GCC rejects
// those specializations as targeting a non-template.
#include <d3d11.h>
#include <codecapi.h>
#include <d3d10.h>  // ID3D10Multithread, which also guards D3D11 devices
#include <icodecapi.h>
#include <mfapi.h>
#include <mferror.h>
#include <mfidl.h>
#include <mftransform.h>
#include <wrl/client.h>

#include <array>
#include <cstddef>
#include <cstring>
#include <format>
#include <utility>

// COM reference counting here is funnelled entirely through
// Microsoft::WRL::ComPtr rather than manual Release() calls (unlike
// duplication.cpp's handful of interfaces): this pipeline touches a dozen+
// COM interfaces across many fallible steps, and ComPtr's RAII is what
// makes that tractable to get right without a Windows box to iterate on.
using Microsoft::WRL::ComPtr;

namespace hawk::capture {

namespace {

[[nodiscard]] EncoderError make_error(EncoderError::Code code, long hresult, std::string_view context) {
    return EncoderError{
        .code = code,
        .native_code = static_cast<std::uint32_t>(hresult),
        .message = std::format("{}: HRESULT 0x{:08X}", context, static_cast<std::uint32_t>(hresult)),
    };
}

[[nodiscard]] EncoderError make_simple_error(EncoderError::Code code, std::string message) {
    return EncoderError{.code = code, .native_code = 0, .message = std::move(message)};
}

constexpr LONGLONG hundred_ns_per_second = 10'000'000LL;

// An async encoder still reads an input texture after ProcessInput returns,
// for as many frames as its pipeline is deep. Converting every frame into
// one shared NV12 texture would overwrite a frame mid-encode, so we rotate
// through a ring sized past a low-latency hardware encoder's usual 1-2
// frames in flight.
constexpr std::size_t nv12_ring_size = 4;
using Nv12Ring = std::array<ComPtr<ID3D11Texture2D>, nv12_ring_size>;

[[nodiscard]] std::expected<void, EncoderError> create_device_manager(ID3D11Device* device,
                                                                       ComPtr<IMFDXGIDeviceManager>& out) {
    UINT    reset_token = 0;
    HRESULT hresult = MFCreateDXGIDeviceManager(&reset_token, &out);
    if (FAILED(hresult)) {
        return std::unexpected(
            make_error(EncoderError::Code::device_manager_failed, hresult, "MFCreateDXGIDeviceManager"));
    }

    hresult = out->ResetDevice(device, reset_token);
    if (FAILED(hresult)) {
        return std::unexpected(make_error(EncoderError::Code::device_manager_failed, hresult, "ResetDevice"));
    }
    return {};
}

// Everything needed to turn a BGRA8 texture into the NV12 texture the
// encoder consumes, entirely on the GPU.
struct VideoProcessor {
    ComPtr<ID3D11VideoDevice>              device;
    ComPtr<ID3D11VideoContext>             context;
    ComPtr<ID3D11VideoProcessorEnumerator> enumerator;
    ComPtr<ID3D11VideoProcessor>           processor;
    Nv12Ring                               nv12_textures;
};

[[nodiscard]] std::expected<VideoProcessor, EncoderError> create_video_processor(ID3D11Device*        device,
                                                                                  const EncoderConfig& config) {
    VideoProcessor video;

    HRESULT hresult = device->QueryInterface(__uuidof(ID3D11VideoDevice), &video.device);
    if (FAILED(hresult)) {
        return std::unexpected(
            make_error(EncoderError::Code::device_manager_failed, hresult, "ID3D11VideoDevice"));
    }

    ComPtr<ID3D11DeviceContext> immediate_context;
    device->GetImmediateContext(&immediate_context);
    hresult = immediate_context.As(&video.context);
    if (FAILED(hresult)) {
        return std::unexpected(
            make_error(EncoderError::Code::device_manager_failed, hresult, "ID3D11VideoContext"));
    }

    const D3D11_VIDEO_PROCESSOR_CONTENT_DESC content_desc{
        .InputFrameFormat = D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
        .InputFrameRate = {.Numerator = config.fps, .Denominator = 1},
        .InputWidth = config.width,
        .InputHeight = config.height,
        .OutputFrameRate = {.Numerator = config.fps, .Denominator = 1},
        .OutputWidth = config.width,
        .OutputHeight = config.height,
        .Usage = D3D11_VIDEO_USAGE_PLAYBACK_NORMAL,
    };
    hresult = video.device->CreateVideoProcessorEnumerator(&content_desc, &video.enumerator);
    if (FAILED(hresult)) {
        return std::unexpected(
            make_error(EncoderError::Code::convert_failed, hresult, "CreateVideoProcessorEnumerator"));
    }

    hresult = video.device->CreateVideoProcessor(video.enumerator.Get(), 0, &video.processor);
    if (FAILED(hresult)) {
        return std::unexpected(make_error(EncoderError::Code::convert_failed, hresult, "CreateVideoProcessor"));
    }

    const D3D11_TEXTURE2D_DESC nv12_desc{
        .Width = config.width,
        .Height = config.height,
        .MipLevels = 1,
        .ArraySize = 1,
        .Format = DXGI_FORMAT_NV12,
        .SampleDesc = {.Count = 1, .Quality = 0},
        .Usage = D3D11_USAGE_DEFAULT,
        .BindFlags = D3D11_BIND_RENDER_TARGET,
        .CPUAccessFlags = 0,
        .MiscFlags = 0,
    };
    for (auto& nv12_texture : video.nv12_textures) {
        hresult = device->CreateTexture2D(&nv12_desc, nullptr, &nv12_texture);
        if (FAILED(hresult)) {
            return std::unexpected(make_error(EncoderError::Code::convert_failed, hresult, "CreateTexture2D(nv12)"));
        }
    }

    return video;
}

[[nodiscard]] std::expected<ComPtr<IMFTransform>, EncoderError> activate_hardware_h264_encoder() {
    MFT_REGISTER_TYPE_INFO wanted_output{.guidMajorType = MFMediaType_Video, .guidSubtype = MFVideoFormat_H264};
    IMFActivate**           activations = nullptr;
    UINT32                  activation_count = 0;
    HRESULT hresult = MFTEnumEx(MFT_CATEGORY_VIDEO_ENCODER, MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER,
                                nullptr, &wanted_output, &activations, &activation_count);
    if (SUCCEEDED(hresult) && activation_count == 0) {
        hresult = MF_E_NO_MORE_TYPES;
    }
    if (FAILED(hresult)) {
        if (activations != nullptr) {
            CoTaskMemFree(static_cast<void*>(activations));
        }
        return std::unexpected(make_simple_error(EncoderError::Code::no_hardware_encoder,
                                                  "no hardware H.264 encoder MFT found on this system"));
    }

    ComPtr<IMFTransform> transform;
    hresult = activations[0]->ActivateObject(__uuidof(IMFTransform), &transform);
    for (UINT32 i = 0; i < activation_count; ++i) {
        activations[i]->Release();
    }
    CoTaskMemFree(static_cast<void*>(activations));
    if (FAILED(hresult)) {
        return std::unexpected(make_error(EncoderError::Code::no_hardware_encoder, hresult, "ActivateObject"));
    }

    // Most hardware encoder MFTs (since Windows 8) are asynchronous and
    // reject nearly every call — including MFT_MESSAGE_SET_D3D_MANAGER —
    // with MF_E_TRANSFORM_ASYNC_LOCKED until this is set. Unlocking is not
    // enough on its own: an async MFT must then be driven by its event
    // queue (see H264Encoder::Impl::poll_events()), or ProcessOutput fails
    // with E_UNEXPECTED.
    ComPtr<IMFAttributes> attributes;
    if (SUCCEEDED(transform->GetAttributes(&attributes))) {
        UINT32 is_async = 0;
        attributes->GetUINT32(MF_TRANSFORM_ASYNC, &is_async);
        if (is_async != 0) {
            attributes->SetUINT32(MF_TRANSFORM_ASYNC_UNLOCK, TRUE);
        }
    }

    return transform;
}

[[nodiscard]] std::expected<void, EncoderError> configure_output_type(IMFTransform&        transform,
                                                                       const EncoderConfig& config) {
    ComPtr<IMFMediaType> out_type;
    HRESULT              hresult = MFCreateMediaType(&out_type);
    if (SUCCEEDED(hresult)) {
        hresult = out_type->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
    }
    if (SUCCEEDED(hresult)) {
        hresult = out_type->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_H264);
    }
    if (SUCCEEDED(hresult)) {
        hresult = out_type->SetUINT32(MF_MT_AVG_BITRATE, config.bitrate_bps);
    }
    if (SUCCEEDED(hresult)) {
        hresult = out_type->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);
    }
    if (SUCCEEDED(hresult)) {
        hresult = MFSetAttributeSize(out_type.Get(), MF_MT_FRAME_SIZE, config.width, config.height);
    }
    if (SUCCEEDED(hresult)) {
        hresult = MFSetAttributeRatio(out_type.Get(), MF_MT_FRAME_RATE, config.fps, 1);
    }
    if (SUCCEEDED(hresult)) {
        hresult = MFSetAttributeRatio(out_type.Get(), MF_MT_PIXEL_ASPECT_RATIO, 1, 1);
    }
    if (SUCCEEDED(hresult)) {
        hresult = transform.SetOutputType(0, out_type.Get(), 0);
    }
    if (FAILED(hresult)) {
        return std::unexpected(make_error(EncoderError::Code::configure_failed, hresult, "SetOutputType"));
    }
    return {};
}

[[nodiscard]] std::expected<void, EncoderError> configure_input_type(IMFTransform&        transform,
                                                                      const EncoderConfig& config) {
    ComPtr<IMFMediaType> in_type;
    HRESULT              hresult = MFCreateMediaType(&in_type);
    if (SUCCEEDED(hresult)) {
        hresult = in_type->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
    }
    if (SUCCEEDED(hresult)) {
        hresult = in_type->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_NV12);
    }
    if (SUCCEEDED(hresult)) {
        hresult = in_type->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);
    }
    if (SUCCEEDED(hresult)) {
        hresult = MFSetAttributeSize(in_type.Get(), MF_MT_FRAME_SIZE, config.width, config.height);
    }
    if (SUCCEEDED(hresult)) {
        hresult = MFSetAttributeRatio(in_type.Get(), MF_MT_FRAME_RATE, config.fps, 1);
    }
    if (SUCCEEDED(hresult)) {
        hresult = MFSetAttributeRatio(in_type.Get(), MF_MT_PIXEL_ASPECT_RATIO, 1, 1);
    }
    if (SUCCEEDED(hresult)) {
        hresult = transform.SetInputType(0, in_type.Get(), 0);
    }
    if (FAILED(hresult)) {
        return std::unexpected(make_error(EncoderError::Code::configure_failed, hresult, "SetInputType"));
    }
    return {};
}

// Best-effort: ask for real-time, low-latency behavior if this encoder
// exposes ICodecAPI. Not every hardware MFT implements it, and that's not
// fatal — it just means we take whatever its defaults are.
void enable_low_latency_mode(IMFTransform& transform) {
    ComPtr<ICodecAPI> codec_api;
    if (FAILED(transform.QueryInterface(__uuidof(ICodecAPI), &codec_api))) {
        return;
    }

    VARIANT enabled{};
    enabled.vt = VT_BOOL;
    enabled.boolVal = VARIANT_TRUE;
    codec_api->SetValue(&CODECAPI_AVLowLatencyMode, &enabled);
    codec_api->SetValue(&CODECAPI_AVEncCommonRealTime, &enabled);
}

}  // namespace

std::string_view to_string(EncoderError::Code code) noexcept {
    switch (code) {
        case EncoderError::Code::mf_startup_failed:
            return "mf_startup_failed";
        case EncoderError::Code::no_hardware_encoder:
            return "no_hardware_encoder";
        case EncoderError::Code::configure_failed:
            return "configure_failed";
        case EncoderError::Code::device_manager_failed:
            return "device_manager_failed";
        case EncoderError::Code::convert_failed:
            return "convert_failed";
        case EncoderError::Code::encode_failed:
            return "encode_failed";
    }
    return "unknown";
}

std::string to_string(const EncoderError& error) {
    if (error.native_code != 0) {
        return std::format("[{}] {} (native code 0x{:08X})", to_string(error.code), error.message,
                            error.native_code);
    }
    return std::format("[{}] {}", to_string(error.code), error.message);
}

struct H264Encoder::Impl {
    ComPtr<IMFDXGIDeviceManager>            device_manager;
    ComPtr<IMFTransform>                    transform;
    ComPtr<ID3D11VideoDevice>               video_device;
    ComPtr<ID3D11VideoContext>              video_context;
    ComPtr<ID3D11VideoProcessorEnumerator>  video_enumerator;
    ComPtr<ID3D11VideoProcessor>            video_processor;
    Nv12Ring                                nv12_textures;  // GPU conversion targets, used in rotation
    std::size_t                             next_nv12 = 0;

    std::uint32_t width = 0;
    std::uint32_t height = 0;
    std::uint32_t fps = 0;
    DWORD         output_stream_size = 0;
    bool          mft_provides_output_samples = false;
    bool          mf_started = false;

    // Async MFT bookkeeping. An async MFT accepts ProcessInput only after
    // METransformNeedInput and ProcessOutput only after
    // METransformHaveOutput (anything else is MF_E_NOTACCEPTING /
    // E_UNEXPECTED), so we count the outstanding requests of each kind.
    ComPtr<IMFMediaEventGenerator> event_generator;  // null for a synchronous MFT
    std::uint32_t                  pending_input_requests = 0;
    std::uint32_t                  pending_outputs = 0;

    // Drains the MFT's event queue without blocking.
    [[nodiscard]] std::expected<void, EncoderError> poll_events() {
        for (;;) {
            ComPtr<IMFMediaEvent> event;
            HRESULT hresult = event_generator->GetEvent(MF_EVENT_FLAG_NO_WAIT, &event);
            if (hresult == MF_E_NO_EVENTS_AVAILABLE) {
                return {};
            }
            if (FAILED(hresult)) {
                return std::unexpected(make_error(EncoderError::Code::encode_failed, hresult, "GetEvent"));
            }

            HRESULT event_status = S_OK;
            event->GetStatus(&event_status);
            if (FAILED(event_status)) {
                return std::unexpected(
                    make_error(EncoderError::Code::encode_failed, event_status, "encoder event status"));
            }

            MediaEventType type = MEUnknown;
            event->GetType(&type);
            switch (type) {
                case METransformNeedInput:
                    ++pending_input_requests;
                    break;
                case METransformHaveOutput:
                    ++pending_outputs;
                    break;
                case MEError:
                    return std::unexpected(make_simple_error(EncoderError::Code::encode_failed, "encoder MEError"));
                default:
                    break;
            }
        }
    }

    // BGRA8 -> NV12 on the GPU, then hands the NV12 frame to the encoder.
    // Returns false if the encoder refused it (frame dropped).
    [[nodiscard]] std::expected<bool, EncoderError> submit_frame(ID3D11Texture2D*          bgra_texture,
                                                                 std::chrono::microseconds timestamp) {
        // --- BGRA8 -> NV12, entirely on the GPU ---
        D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC input_view_desc{
            .FourCC = 0,
            .ViewDimension = D3D11_VPIV_DIMENSION_TEXTURE2D,
            .Texture2D = {.MipSlice = 0, .ArraySlice = 0},
        };

        ComPtr<ID3D11VideoProcessorInputView> input_view;
        HRESULT hresult = video_device->CreateVideoProcessorInputView(
            bgra_texture, video_enumerator.Get(), &input_view_desc, &input_view);
        if (FAILED(hresult)) {
            return std::unexpected(
                make_error(EncoderError::Code::convert_failed, hresult, "CreateVideoProcessorInputView"));
        }

        D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC output_view_desc{
            .ViewDimension = D3D11_VPOV_DIMENSION_TEXTURE2D,
            .Texture2D = {.MipSlice = 0},
        };

        ID3D11Texture2D* nv12_texture = nv12_textures.at(next_nv12).Get();

        ComPtr<ID3D11VideoProcessorOutputView> output_view;
        hresult = video_device->CreateVideoProcessorOutputView(nv12_texture, video_enumerator.Get(),
                                                               &output_view_desc, &output_view);
        if (FAILED(hresult)) {
            return std::unexpected(
                make_error(EncoderError::Code::convert_failed, hresult, "CreateVideoProcessorOutputView"));
        }

        D3D11_VIDEO_PROCESSOR_STREAM stream{};
        stream.Enable = TRUE;
        stream.pInputSurface = input_view.Get();
        hresult = video_context->VideoProcessorBlt(video_processor.Get(), output_view.Get(), 0, 1, &stream);
        if (FAILED(hresult)) {
            return std::unexpected(make_error(EncoderError::Code::convert_failed, hresult, "VideoProcessorBlt"));
        }

        // --- wrap the NV12 texture in a sample and feed the encoder ---
        ComPtr<IMFMediaBuffer> input_buffer;
        hresult = MFCreateDXGISurfaceBuffer(__uuidof(ID3D11Texture2D), nv12_texture, 0, FALSE, &input_buffer);
        if (FAILED(hresult)) {
            return std::unexpected(make_error(EncoderError::Code::encode_failed, hresult, "MFCreateDXGISurfaceBuffer"));
        }

        const LONGLONG sample_time = timestamp.count() * 10;  // microseconds -> 100ns units
        const LONGLONG sample_duration = hundred_ns_per_second / fps;

        ComPtr<IMFSample> input_sample;
        hresult = MFCreateSample(&input_sample);
        if (SUCCEEDED(hresult)) {
            hresult = input_sample->AddBuffer(input_buffer.Get());
        }
        if (SUCCEEDED(hresult)) {
            hresult = input_sample->SetSampleTime(sample_time);
        }
        if (SUCCEEDED(hresult)) {
            hresult = input_sample->SetSampleDuration(sample_duration);
        }
        if (FAILED(hresult)) {
            return std::unexpected(make_error(EncoderError::Code::encode_failed, hresult, "build input sample"));
        }

        hresult = transform->ProcessInput(0, input_sample.Get(), 0);
        if (hresult == MF_E_NOTACCEPTING) {
            // A synchronous MFT that still has output pending. Dropping this
            // frame is fine for live capture; the caller will offer the next one.
            return false;
        }
        if (FAILED(hresult)) {
            return std::unexpected(make_error(EncoderError::Code::encode_failed, hresult, "ProcessInput"));
        }
        // Only a texture the encoder accepted is in flight; a refused one is
        // free to be converted into again next frame.
        next_nv12 = (next_nv12 + 1) % nv12_ring_size;
        return true;
    }

    // Pulls one access unit. `fallback_timestamp` is used only if the MFT
    // didn't carry the input sample time through.
    [[nodiscard]] std::expected<std::optional<EncodedPacket>, EncoderError> pull_output(
        std::chrono::microseconds fallback_timestamp) {
        HRESULT                hresult = S_OK;
        MFT_OUTPUT_DATA_BUFFER output_buffer{};
        if (!mft_provides_output_samples) {
            ComPtr<IMFSample>      preallocated_sample;
            ComPtr<IMFMediaBuffer> preallocated_buffer;
            hresult = MFCreateSample(&preallocated_sample);
            if (SUCCEEDED(hresult)) {
                hresult = MFCreateMemoryBuffer(output_stream_size, &preallocated_buffer);
            }
            if (SUCCEEDED(hresult)) {
                hresult = preallocated_sample->AddBuffer(preallocated_buffer.Get());
            }
            if (FAILED(hresult)) {
                return std::unexpected(make_error(EncoderError::Code::encode_failed, hresult, "allocate output sample"));
            }
            output_buffer.pSample = preallocated_sample.Detach();
        }

        DWORD status = 0;
        hresult = transform->ProcessOutput(0, 1, &output_buffer, &status);

        // Whatever ProcessOutput left in pSample/pEvents, we now own exactly one
        // reference to it (ours, carried through from the branch above, or one
        // the MFT allocated and AddRef'd) — Attach takes ownership of that
        // without an extra AddRef, on every path including the error ones below.
        ComPtr<IMFSample>     result_sample;
        ComPtr<IMFCollection> result_events;
        result_sample.Attach(output_buffer.pSample);
        result_events.Attach(output_buffer.pEvents);

        if (hresult == MF_E_TRANSFORM_NEED_MORE_INPUT) {
            return std::optional<EncodedPacket>{};  // still buffering; nothing to emit yet
        }
        if (FAILED(hresult)) {
            return std::unexpected(make_error(EncoderError::Code::encode_failed, hresult, "ProcessOutput"));
        }
        if (result_sample.Get() == nullptr) {
            return std::unexpected(
                make_simple_error(EncoderError::Code::encode_failed, "ProcessOutput succeeded with no sample"));
        }

        UINT32 is_keyframe = 0;
        result_sample->GetUINT32(MFSampleExtension_CleanPoint, &is_keyframe);

        // Output can lag input by a frame or more, so stamp the packet with the
        // time of the frame it actually encodes, not the one just submitted.
        LONGLONG output_time = 0;
        const auto packet_timestamp = SUCCEEDED(result_sample->GetSampleTime(&output_time))
                                          ? std::chrono::microseconds{output_time / 10}  // 100ns units -> microseconds
                                          : fallback_timestamp;

        ComPtr<IMFMediaBuffer> result_buffer;
        hresult = result_sample->ConvertToContiguousBuffer(&result_buffer);
        if (FAILED(hresult)) {
            return std::unexpected(make_error(EncoderError::Code::encode_failed, hresult, "ConvertToContiguousBuffer"));
        }

        BYTE* raw_data = nullptr;
        DWORD data_length = 0;
        hresult = result_buffer->Lock(&raw_data, nullptr, &data_length);
        if (FAILED(hresult)) {
            return std::unexpected(make_error(EncoderError::Code::encode_failed, hresult, "Lock(output buffer)"));
        }

        EncodedPacket packet{.data = {}, .is_keyframe = is_keyframe != 0, .timestamp = packet_timestamp};
        packet.data.resize(data_length);
        std::memcpy(packet.data.data(), raw_data, data_length);
        result_buffer->Unlock();

        return std::optional<EncodedPacket>{std::move(packet)};
    }

    Impl() = default;
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
    Impl(Impl&&) = delete;
    Impl& operator=(Impl&&) = delete;

    ~Impl() {
        if (transform.Get() != nullptr) {
            transform->ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
            transform->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0);
        }
        // Explicit, ordered teardown before MFShutdown() tears down the MF
        // platform out from under any of these — ComPtr destructors alone
        // would run in declaration order, but Reset() here makes that
        // ordering an explicit invariant rather than an accident of layout.
        event_generator.Reset();
        transform.Reset();
        video_processor.Reset();
        video_enumerator.Reset();
        for (auto& nv12_texture : nv12_textures) {
            nv12_texture.Reset();
        }
        video_context.Reset();
        video_device.Reset();
        device_manager.Reset();
        if (mf_started) {
            MFShutdown();
        }
    }
};

H264Encoder::H264Encoder() : impl_(std::make_unique<Impl>()) {}
H264Encoder::~H264Encoder() = default;
H264Encoder::H264Encoder(H264Encoder&&) noexcept = default;
H264Encoder& H264Encoder::operator=(H264Encoder&&) noexcept = default;

std::expected<void, EncoderError> H264Encoder::open(ID3D11Device* device, const EncoderConfig& config) {
    impl_->width = config.width;
    impl_->height = config.height;
    impl_->fps = config.fps;

    HRESULT hresult = MFStartup(MF_VERSION, MFSTARTUP_FULL);
    if (FAILED(hresult)) {
        return std::unexpected(make_error(EncoderError::Code::mf_startup_failed, hresult, "MFStartup"));
    }
    impl_->mf_started = true;

    // An async encoder MFT runs on its own worker thread and uses this same
    // device and its immediate context (through the device manager) while
    // the capture thread is still issuing CopyResource / VideoProcessorBlt
    // on it. An immediate context isn't thread-safe unless multithread
    // protection is on; without it, encoder output goes missing or the
    // driver stalls, differently on every run.
    ComPtr<ID3D10Multithread> multithread;
    hresult = device->QueryInterface(__uuidof(ID3D10Multithread), &multithread);
    if (FAILED(hresult)) {
        return std::unexpected(make_error(EncoderError::Code::device_manager_failed, hresult, "ID3D10Multithread"));
    }
    multithread->SetMultithreadProtected(TRUE);

    if (auto result = create_device_manager(device, impl_->device_manager); !result.has_value()) {
        return std::unexpected(result.error());
    }

    auto video = create_video_processor(device, config);
    if (!video.has_value()) {
        return std::unexpected(video.error());
    }
    impl_->video_device = std::move(video->device);
    impl_->video_context = std::move(video->context);
    impl_->video_enumerator = std::move(video->enumerator);
    impl_->video_processor = std::move(video->processor);
    impl_->nv12_textures = std::move(video->nv12_textures);

    // Hardware H.264 encoder MFT — Quick Sync / NVENC / VCE, whichever this
    // system exposes.
    auto transform = activate_hardware_h264_encoder();
    if (!transform.has_value()) {
        return std::unexpected(transform.error());
    }
    impl_->transform = std::move(*transform);

    ComPtr<IMFAttributes> transform_attributes;
    if (SUCCEEDED(impl_->transform->GetAttributes(&transform_attributes))) {
        UINT32 is_async = 0;
        transform_attributes->GetUINT32(MF_TRANSFORM_ASYNC, &is_async);
        if (is_async != 0) {
            hresult = impl_->transform.As(&impl_->event_generator);
            if (FAILED(hresult)) {
                return std::unexpected(
                    make_error(EncoderError::Code::configure_failed, hresult, "IMFMediaEventGenerator"));
            }
        }
    }

    hresult = impl_->transform->ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER,
                                               reinterpret_cast<ULONG_PTR>(impl_->device_manager.Get()));
    if (FAILED(hresult)) {
        return std::unexpected(
            make_error(EncoderError::Code::configure_failed, hresult, "MFT_MESSAGE_SET_D3D_MANAGER"));
    }

    // Output type first: most hardware encoder MFTs require this before
    // they'll accept an input type.
    if (auto result = configure_output_type(*impl_->transform.Get(), config); !result.has_value()) {
        return std::unexpected(result.error());
    }
    if (auto result = configure_input_type(*impl_->transform.Get(), config); !result.has_value()) {
        return std::unexpected(result.error());
    }

    enable_low_latency_mode(*impl_->transform.Get());

    MFT_OUTPUT_STREAM_INFO stream_info{};
    hresult = impl_->transform->GetOutputStreamInfo(0, &stream_info);
    if (FAILED(hresult)) {
        return std::unexpected(make_error(EncoderError::Code::configure_failed, hresult, "GetOutputStreamInfo"));
    }
    constexpr auto provides_or_can_provide_samples = static_cast<DWORD>(MFT_OUTPUT_STREAM_PROVIDES_SAMPLES) |
                                                      static_cast<DWORD>(MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES);
    impl_->mft_provides_output_samples = (stream_info.dwFlags & provides_or_can_provide_samples) != 0;
    impl_->output_stream_size = stream_info.cbSize;

    impl_->transform->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0);
    impl_->transform->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);

    return {};
}

std::expected<std::vector<EncodedPacket>, EncoderError> H264Encoder::encode(
    ID3D11Texture2D* bgra_texture, std::chrono::microseconds timestamp) {
    std::vector<EncodedPacket> packets;

    // An async MFT only accepts input it has asked for, and only hands out
    // output it has announced; anything else fails (ProcessOutput returns
    // E_UNEXPECTED). With no input request outstanding, this frame is
    // dropped (skipping the GPU conversion too), which is fine for live capture.
    const bool is_async = impl_->event_generator.Get() != nullptr;

    // Output lags input, so take everything announced so far, not just one
    // access unit — otherwise it sits in the encoder until a later call and
    // the stream visibly stalls behind the screen.
    const auto drain_outputs = [&]() -> std::expected<void, EncoderError> {
        if (auto polled = impl_->poll_events(); !polled.has_value()) {
            return std::unexpected(polled.error());
        }
        while (impl_->pending_outputs > 0) {
            --impl_->pending_outputs;
            auto packet = impl_->pull_output(timestamp);
            if (!packet.has_value()) {
                return std::unexpected(packet.error());
            }
            if (packet->has_value()) {
                packets.push_back(std::move(**packet));
            }
        }
        return {};
    };

    // Collect last tick's output before deciding whether to submit: the MFT
    // only asks for its next input once that output has been taken, so
    // checking for an input request first skips every other frame.
    if (is_async) {
        if (auto drained = drain_outputs(); !drained.has_value()) {
            return std::unexpected(drained.error());
        }
        if (auto polled = impl_->poll_events(); !polled.has_value()) {
            return std::unexpected(polled.error());
        }
    }

    if (!is_async || impl_->pending_input_requests > 0) {
        auto submitted = impl_->submit_frame(bgra_texture, timestamp);
        if (!submitted.has_value()) {
            return std::unexpected(submitted.error());
        }
        if (!*submitted) {
            return packets;
        }
        if (is_async) {
            --impl_->pending_input_requests;
        }
    }

    if (!is_async) {
        auto packet = impl_->pull_output(timestamp);
        if (!packet.has_value()) {
            return std::unexpected(packet.error());
        }
        if (packet->has_value()) {
            packets.push_back(std::move(**packet));
        }
        return packets;
    }

    if (auto drained = drain_outputs(); !drained.has_value()) {
        return std::unexpected(drained.error());
    }
    return packets;
}

}  // namespace hawk::capture
