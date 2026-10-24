#include "audio.hpp"

#include <windows.h>
#include <audioclient.h>
#include <mmdeviceapi.h>
#include <mmreg.h>
#include <objbase.h>
#include <wrl/client.h>

#include <opus.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using Microsoft::WRL::ComPtr;

namespace hawk::capture {

namespace {

constexpr std::uint32_t kSampleRate = 48'000;
constexpr std::uint32_t kChannels = 2;
// 20 ms: Opus's sweet spot between overhead and latency.
constexpr std::size_t kFrameSamples = kSampleRate / 50;
constexpr std::int32_t kBitrate = 96'000;
constexpr std::size_t  kMaxPacket = 1500;
// WASAPI's own buffer, in 100 ns units: generous, it's drained every 10 ms.
constexpr REFERENCE_TIME kBufferDuration = 2'000'000;  // 200 ms
constexpr auto kPollInterval = std::chrono::milliseconds(10);
// How often to look for a change of default device, and how long to wait
// after failing to open one.
constexpr auto kDeviceCheckInterval = std::chrono::seconds(2);
constexpr auto kRetryInterval = std::chrono::seconds(2);
// Below this a 20 ms frame is silence, and isn't sent.
constexpr float kSilence = 1.0e-5F;

class ComScope {
public:
    ComScope() : hresult_(CoInitializeEx(nullptr, COINIT_MULTITHREADED)) {}
    ~ComScope() {
        if (SUCCEEDED(hresult_)) {
            CoUninitialize();
        }
    }
    ComScope(const ComScope&) = delete;
    ComScope& operator=(const ComScope&) = delete;
    ComScope(ComScope&&) = delete;
    ComScope& operator=(ComScope&&) = delete;

    [[nodiscard]] bool ok() const noexcept { return SUCCEEDED(hresult_); }

private:
    HRESULT hresult_;
};

struct CoTaskMemDeleter {
    void operator()(void* memory) const noexcept { CoTaskMemFree(memory); }
};
template <typename T>
using CoTaskMemPtr = std::unique_ptr<T, CoTaskMemDeleter>;

// The sample formats a mix format can come in that we can read.
enum class SampleFormat : std::uint8_t { float32, int16, int32 };

// What WASAPI hands over, as this code reads it.
struct SourceFormat {
    SampleFormat  sample = SampleFormat::float32;
    std::uint32_t rate = kSampleRate;
    std::uint32_t channels = kChannels;
};

// Reads a WAVEFORMATEX(TENSIBLE) as one of the formats above; nullopt for
// anything else (24-bit packed, compressed...).
[[nodiscard]] std::optional<SourceFormat> read_format(const WAVEFORMATEX& format) {
    WORD tag = format.wFormatTag;
    if (tag == WAVE_FORMAT_EXTENSIBLE && format.cbSize >= sizeof(WAVEFORMATEXTENSIBLE) - sizeof(WAVEFORMATEX)) {
        // The subformat GUIDs are {0000000X-0000-0010-8000-00AA00389B71},
        // X being the plain format tag.
        tag = static_cast<WORD>(reinterpret_cast<const WAVEFORMATEXTENSIBLE&>(format).SubFormat.Data1);
    }
    SourceFormat source{.rate = format.nSamplesPerSec, .channels = format.nChannels};
    if (tag == WAVE_FORMAT_IEEE_FLOAT && format.wBitsPerSample == 32) {
        source.sample = SampleFormat::float32;
    } else if (tag == WAVE_FORMAT_PCM && format.wBitsPerSample == 16) {
        source.sample = SampleFormat::int16;
    } else if (tag == WAVE_FORMAT_PCM && format.wBitsPerSample == 32) {
        source.sample = SampleFormat::int32;
    } else {
        return std::nullopt;
    }
    if (source.channels == 0 || source.rate == 0) {
        return std::nullopt;
    }
    return source;
}

// Turns whatever the device delivers into 48 kHz interleaved stereo float:
// the first two channels (or the one, twice), resampled linearly when the
// device runs at another rate. Linear is plenty for a remote desktop's
// sound, and cheap.
class Converter {
public:
    explicit Converter(SourceFormat format)
        : format_(format), step_(static_cast<double>(format.rate) / kSampleRate) {}

    void push(const BYTE* data, std::uint32_t frames, std::vector<float>& out) {
        stereo_.resize(static_cast<std::size_t>(frames) * kChannels);
        for (std::uint32_t frame = 0; frame < frames; ++frame) {
            const std::uint32_t right = format_.channels > 1 ? 1 : 0;
            stereo_[(frame * kChannels) + 0] = sample(data, (frame * format_.channels) + 0);
            stereo_[(frame * kChannels) + 1] = sample(data, (frame * format_.channels) + right);
        }
        if (format_.rate == kSampleRate) {
            out.insert(out.end(), stereo_.begin(), stereo_.end());
            return;
        }
        // s[0] is the last sample of the previous buffer, s[k] this
        // buffer's k-1th; t walks across them a source step at a time.
        const auto at = [this](std::size_t index, std::uint32_t channel) {
            return index == 0 ? previous_[channel] : stereo_[((index - 1) * kChannels) + channel];
        };
        const auto count = static_cast<double>(frames);
        while (position_ < count) {
            const auto   index = static_cast<std::size_t>(position_);
            const auto   fraction = static_cast<float>(position_ - static_cast<double>(index));
            for (std::uint32_t channel = 0; channel < kChannels; ++channel) {
                out.push_back((at(index, channel) * (1.0F - fraction)) + (at(index + 1, channel) * fraction));
            }
            position_ += step_;
        }
        position_ -= count;
        if (frames > 0) {
            previous_ = {stereo_[stereo_.size() - 2], stereo_[stereo_.size() - 1]};
        }
    }

private:
    [[nodiscard]] float sample(const BYTE* data, std::size_t index) const {
        switch (format_.sample) {
            case SampleFormat::float32: {
                float value = 0;
                std::memcpy(&value, data + (index * sizeof(float)), sizeof(float));
                return value;
            }
            case SampleFormat::int16: {
                std::int16_t value = 0;
                std::memcpy(&value, data + (index * sizeof(value)), sizeof(value));
                return static_cast<float>(value) / 32768.0F;
            }
            case SampleFormat::int32: {
                std::int32_t value = 0;
                std::memcpy(&value, data + (index * sizeof(value)), sizeof(value));
                return static_cast<float>(static_cast<double>(value) / 2147483648.0);
            }
        }
        return 0;
    }

    SourceFormat               format_;
    double                     step_;
    double                     position_ = 0;
    std::array<float, kChannels> previous_{};
    std::vector<float>         stereo_;
};

struct OpusEncoderDeleter {
    void operator()(OpusEncoder* encoder) const noexcept { opus_encoder_destroy(encoder); }
};

// The default output device's id, or empty when there is none.
[[nodiscard]] std::wstring default_device_id(IMMDeviceEnumerator& enumerator) {
    ComPtr<IMMDevice> device;
    if (FAILED(enumerator.GetDefaultAudioEndpoint(eRender, eConsole, &device))) {
        return {};
    }
    LPWSTR raw = nullptr;
    if (FAILED(device->GetId(&raw))) {
        return {};
    }
    const CoTaskMemPtr<wchar_t> id(raw);
    return id.get();
}

// A WASAPI QPC position (performance counter time in 100 ns units) on
// steady_clock, which the stream's timestamps count on. Measured against
// the counter rather than assumed: steady_clock reads the same counter on
// Windows, but nothing promises the same epoch or unit.
std::chrono::steady_clock::time_point from_qpc(UINT64 position) {
    static const auto offset = [] {
        LARGE_INTEGER frequency{};
        LARGE_INTEGER counter{};
        QueryPerformanceFrequency(&frequency);
        QueryPerformanceCounter(&counter);
        const auto steady = std::chrono::steady_clock::now();
        const auto ticks = std::chrono::nanoseconds(static_cast<std::int64_t>(
            static_cast<long double>(counter.QuadPart) * 1'000'000'000.0L / static_cast<long double>(frequency.QuadPart)));
        return steady.time_since_epoch() - ticks;
    }();
    const auto since_counter_zero = std::chrono::nanoseconds(static_cast<std::int64_t>(position) * 100);
    return std::chrono::steady_clock::time_point(
        std::chrono::duration_cast<std::chrono::steady_clock::duration>(since_counter_zero + offset));
}

}  // namespace

struct AudioCapture::Impl {
    std::jthread thread;

    // Why one session of capture ended.
    enum class Ended : std::uint8_t { stopped, sink_closed, device_lost, failed };

    static void run(const std::stop_token& stop, std::chrono::steady_clock::time_point stream_start,
                    const PacketSink& sink, const std::wstring& wanted_id) {
        const ComScope com;
        if (!com.ok()) {
            spdlog::error("audio: CoInitializeEx failed; no sound");
            return;
        }
        ComPtr<IMMDeviceEnumerator> enumerator;
        if (FAILED(CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
                                    IID_PPV_ARGS(&enumerator)))) {
            spdlog::error("audio: no audio device enumerator; no sound");
            return;
        }
        bool warned = false;
        while (!stop.stop_requested()) {
            const auto ended = capture(stop, *enumerator.Get(), stream_start, sink, wanted_id, warned);
            if (ended == Ended::stopped || ended == Ended::sink_closed) {
                return;
            }
            if (ended == Ended::failed) {
                const auto retry_at = std::chrono::steady_clock::now() + kRetryInterval;
                while (!stop.stop_requested() && std::chrono::steady_clock::now() < retry_at) {
                    std::this_thread::sleep_for(kPollInterval);
                }
            }
        }
    }

    // Whether the endpoint `id` is there and active.
    [[nodiscard]] static ComPtr<IMMDevice> active_device(IMMDeviceEnumerator& enumerator, const std::wstring& id) {
        ComPtr<IMMDevice> device;
        DWORD             state = 0;
        if (FAILED(enumerator.GetDevice(id.c_str(), &device)) || FAILED(device->GetState(&state)) ||
            state != DEVICE_STATE_ACTIVE) {
            return nullptr;
        }
        return device;
    }

    // Captures from the wanted device, or while it's missing (or none was
    // asked for) the current default one, until it goes away or changes,
    // or until stopped.
    static Ended capture(const std::stop_token& stop, IMMDeviceEnumerator& enumerator,
                         std::chrono::steady_clock::time_point stream_start, const PacketSink& sink,
                         const std::wstring& wanted_id, bool& warned) {
        ComPtr<IMMDevice> device;
        if (!wanted_id.empty()) {
            device = active_device(enumerator, wanted_id);
            if (device == nullptr) {
                spdlog::info("audio: the chosen output device isn't there; using the default until it is");
            }
        }
        const bool chosen = device != nullptr;
        if (!chosen && FAILED(enumerator.GetDefaultAudioEndpoint(eRender, eConsole, &device))) {
            if (!warned) {
                spdlog::info("audio: no output device; no sound until there is one");
                warned = true;
            }
            return Ended::failed;
        }
        const std::wstring device_id = chosen ? wanted_id : default_device_id(enumerator);

        ComPtr<IAudioClient> client;
        if (FAILED(device->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr,
                                    reinterpret_cast<void**>(client.GetAddressOf())))) {
            spdlog::warn("audio: couldn't open the output device");
            return Ended::failed;
        }

        // Ask Windows for 48 kHz stereo float straight away; where it won't
        // convert for a loopback stream, take the mix format and convert
        // here.
        WAVEFORMATEX wanted{};
        wanted.wFormatTag = WAVE_FORMAT_IEEE_FLOAT;
        wanted.nChannels = kChannels;
        wanted.nSamplesPerSec = kSampleRate;
        wanted.wBitsPerSample = 32;
        wanted.nBlockAlign = static_cast<WORD>(kChannels * sizeof(float));
        wanted.nAvgBytesPerSec = kSampleRate * wanted.nBlockAlign;
        std::optional<SourceFormat> format;
        HRESULT                     result = client->Initialize(
            AUDCLNT_SHAREMODE_SHARED,
            AUDCLNT_STREAMFLAGS_LOOPBACK | AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY,
            kBufferDuration, 0, &wanted, nullptr);
        if (SUCCEEDED(result)) {
            format = SourceFormat{};  // exactly what was asked for
        } else {
            // A failed Initialize leaves the client unusable: start over.
            client.Reset();
            if (FAILED(device->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr,
                                        reinterpret_cast<void**>(client.GetAddressOf())))) {
                return Ended::failed;
            }
            WAVEFORMATEX* raw = nullptr;
            if (FAILED(client->GetMixFormat(&raw))) {
                spdlog::warn("audio: couldn't read the output device's format");
                return Ended::failed;
            }
            const CoTaskMemPtr<WAVEFORMATEX> mix(raw);
            format = read_format(*mix);
            if (!format.has_value()) {
                spdlog::warn("audio: the output device's format (tag {:#x}, {} bits) isn't one this reads; no sound",
                             mix->wFormatTag, mix->wBitsPerSample);
                return Ended::failed;
            }
            result = client->Initialize(AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_LOOPBACK, kBufferDuration, 0,
                                        mix.get(), nullptr);
        }
        if (FAILED(result) || !format.has_value()) {
            spdlog::warn("audio: couldn't start loopback capture (HRESULT {:#x})", static_cast<std::uint32_t>(result));
            return Ended::failed;
        }

        ComPtr<IAudioCaptureClient> capture_client;
        if (FAILED(client->GetService(IID_PPV_ARGS(&capture_client)))) {
            return Ended::failed;
        }

        int                                                 opus_error = OPUS_OK;
        const std::unique_ptr<OpusEncoder, OpusEncoderDeleter> encoder(
            opus_encoder_create(kSampleRate, kChannels, OPUS_APPLICATION_AUDIO, &opus_error));
        if (opus_error != OPUS_OK || encoder == nullptr) {
            spdlog::error("audio: couldn't create the Opus encoder: {}", opus_strerror(opus_error));
            return Ended::failed;
        }
        opus_encoder_ctl(encoder.get(), OPUS_SET_BITRATE(kBitrate));

        if (FAILED(client->Start())) {
            return Ended::failed;
        }
        warned = false;
        spdlog::info("audio: capturing the output device ({} Hz, {} channels{})", format->rate, format->channels,
                     format->rate == kSampleRate ? "" : ", resampled to 48000 Hz");

        Converter                         converter(*format);
        const std::uint32_t               block_align =
            format->sample == SampleFormat::int16 ? 2 * format->channels : 4 * format->channels;
        std::vector<float>                pending;
        std::vector<BYTE>                 zeros;
        std::array<unsigned char, kMaxPacket> packet{};
        auto                              next_device_check = std::chrono::steady_clock::now() + kDeviceCheckInterval;
        Ended                             ended = Ended::stopped;
        // When the sample just past the end of `pending` played, from the
        // device's own timestamps where it gives them.
        std::optional<std::chrono::steady_clock::time_point> pending_end;

        while (!stop.stop_requested()) {
            std::this_thread::sleep_for(kPollInterval);

            UINT32 available = 0;
            HRESULT status = capture_client->GetNextPacketSize(&available);
            while (SUCCEEDED(status) && available > 0) {
                BYTE*  data = nullptr;
                UINT32 frames = 0;
                DWORD  flags = 0;
                UINT64 qpc_position = 0;
                status = capture_client->GetBuffer(&data, &frames, &flags, nullptr, &qpc_position);
                if (FAILED(status)) {
                    break;
                }
                if ((flags & AUDCLNT_BUFFERFLAGS_TIMESTAMP_ERROR) == 0 && qpc_position != 0) {
                    pending_end = from_qpc(qpc_position) +
                                  std::chrono::microseconds(static_cast<std::int64_t>(frames) * 1'000'000 / format->rate);
                } else {
                    pending_end.reset();
                }
                if ((flags & AUDCLNT_BUFFERFLAGS_SILENT) != 0) {
                    // The buffer's contents are to be ignored: read zeros
                    // instead, so the timing stays right.
                    zeros.resize(std::max(zeros.size(), static_cast<std::size_t>(frames) * block_align));
                    converter.push(zeros.data(), frames, pending);
                } else {
                    converter.push(data, frames, pending);
                }
                capture_client->ReleaseBuffer(frames);
                status = capture_client->GetNextPacketSize(&available);
            }
            if (FAILED(status)) {
                if (status == AUDCLNT_E_DEVICE_INVALIDATED) {
                    spdlog::info("audio: the output device went away; looking for another");
                    ended = Ended::device_lost;
                } else {
                    spdlog::warn("audio: capture failed (HRESULT {:#x}); starting over",
                                 static_cast<std::uint32_t>(status));
                    ended = Ended::failed;
                }
                break;
            }

            // Whole 20 ms frames, oldest first. What's left is the start of
            // the next one; each frame is stamped with when its first sample
            // played, counting back from the end of what's pending: the
            // device's timestamp of it, or now when it gave none.
            const auto   now = std::chrono::steady_clock::now();
            const auto   end = pending_end.value_or(now);
            std::size_t  offset = 0;
            const auto   frame_values = kFrameSamples * kChannels;
            const auto   queued_frames = pending.size() / frame_values;
            for (std::size_t index = 0; index < queued_frames; ++index, offset += frame_values) {
                const std::span frame(pending.data() + offset, frame_values);
                const bool silent =
                    std::ranges::all_of(frame, [](float value) { return std::fabs(value) < kSilence; });
                if (silent) {
                    continue;
                }
                const auto encoded = opus_encode_float(encoder.get(), frame.data(), static_cast<int>(kFrameSamples),
                                                       packet.data(), static_cast<opus_int32>(packet.size()));
                if (encoded < 0) {
                    spdlog::warn("audio: Opus encode failed: {}", opus_strerror(encoded));
                    continue;
                }
                const auto behind = std::chrono::microseconds(
                    static_cast<std::int64_t>((pending.size() - offset) / kChannels) * 1'000'000 / kSampleRate);
                EncodedPacket out;
                out.data.resize(static_cast<std::size_t>(encoded));
                std::memcpy(out.data.data(), packet.data(), out.data.size());
                out.timestamp = std::chrono::duration_cast<std::chrono::microseconds>(end - stream_start) - behind;
                if (!sink(out)) {
                    client->Stop();
                    return Ended::sink_closed;
                }
            }
            pending.erase(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(offset));

            if (now >= next_device_check) {
                next_device_check = now + kDeviceCheckInterval;
                if (!wanted_id.empty() && !chosen && active_device(enumerator, wanted_id) != nullptr) {
                    spdlog::info("audio: the chosen output device is back; switching to it");
                    ended = Ended::device_lost;
                    break;
                }
                if (!chosen && default_device_id(enumerator) != device_id) {
                    spdlog::info("audio: the default output device changed; following it");
                    ended = Ended::device_lost;
                    break;
                }
            }
        }
        client->Stop();
        return ended;
    }
};

AudioCapture::AudioCapture() : impl_(std::make_unique<Impl>()) {}

AudioCapture::~AudioCapture() {
    stop();
}

void AudioCapture::start(std::chrono::steady_clock::time_point stream_start, PacketSink sink,
                         std::wstring device_id) {
    stop();
    impl_->thread = std::jthread(
        [stream_start, sink = std::move(sink), device_id = std::move(device_id)](const std::stop_token& stop) {
            Impl::run(stop, stream_start, sink, device_id);
        });
}

void AudioCapture::stop() noexcept {
    if (impl_->thread.joinable()) {
        impl_->thread.request_stop();
        impl_->thread.join();
    }
}

}  // namespace hawk::capture
