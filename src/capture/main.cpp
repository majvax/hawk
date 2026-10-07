#include "duplication.hpp"
#include "encoder.hpp"

#include <objbase.h>
#include <timeapi.h>

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdlib>
#include <optional>

namespace capture = hawk::capture;

namespace {

// RAII wrapper so every early return still balances CoInitializeEx — Media
// Foundation and the hardware MFTs it activates depend on COM being
// initialized on this thread.
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

// Raises the system timer resolution to 1 ms for this process. At the
// default ~15.6 ms, AcquireNextFrame's timeout can't pace a 60 fps (16.7 ms)
// frame clock: waits round up to whole timer ticks and the rate drifts low.
class TimerResolutionScope {
public:
    TimerResolutionScope() : ok_(timeBeginPeriod(1) == TIMERR_NOERROR) {}
    ~TimerResolutionScope() {
        if (ok_) {
            timeEndPeriod(1);
        }
    }

    TimerResolutionScope(const TimerResolutionScope&) = delete;
    TimerResolutionScope& operator=(const TimerResolutionScope&) = delete;
    TimerResolutionScope(TimerResolutionScope&&) = delete;
    TimerResolutionScope& operator=(TimerResolutionScope&&) = delete;

private:
    bool ok_;
};

}  // namespace

// Standalone helper: must run as an ordinary process inside the interactive
// user's own session, not the service (Session 0 has no desktop to see).
// Captures the desktop, encodes it to H.264 on the GPU, and logs packet
// stats — handing encoded packets off to hawk-service over a local pipe is
// the next piece, not yet wired up here.
int main() {
    auto logger = spdlog::stdout_color_mt("hawk-capture");
    spdlog::set_default_logger(logger);

    ComScope com;
    if (!com.ok()) {
        spdlog::error("capture: CoInitializeEx failed");
        return EXIT_FAILURE;
    }

    const TimerResolutionScope timer_resolution;

    capture::DesktopDuplicator duplicator;
    if (auto opened = duplicator.open(); !opened.has_value()) {
        spdlog::error("capture: failed to open desktop duplication: {}", capture::to_string(opened.error()));
        return EXIT_FAILURE;
    }

    spdlog::info("capture: desktop duplication started");

    capture::H264Encoder encoder;
    bool                 encoder_ready = false;

    std::uint64_t captured_count = 0;
    std::uint64_t encoded_count = 0;
    std::uint64_t packet_count = 0;
    std::size_t   bytes_this_window = 0;
    auto          window_start = std::chrono::steady_clock::now();
    const auto    stream_start = window_start;

    // Encode on a fixed frame clock at the encoder's frame rate. Desktop
    // Duplication only produces a frame when the screen changes, at up to the
    // monitor's refresh rate, so:
    //  - frames arriving faster than the clock just refresh the duplicator's
    //    copy texture, and the newest one is encoded at the next tick;
    //  - on an idle screen the last frame (still held in that copy texture)
    //    is re-encoded each tick, which keeps the stream alive and flushes
    //    frames still in flight in the encoder — without this, output freezes
    //    whenever the screen stops changing.
    constexpr auto                frame_interval = std::chrono::microseconds{1'000'000 / capture::default_encoder_fps};
    auto                          next_tick = std::chrono::steady_clock::now();
    std::optional<capture::Frame> last_frame;

    for (;;) {
        const auto until_tick = next_tick - std::chrono::steady_clock::now();
        const auto wait_ms =
            until_tick > until_tick.zero() ? std::chrono::ceil<std::chrono::milliseconds>(until_tick).count() : 0;

        auto frame = duplicator.capture_frame(static_cast<std::uint32_t>(wait_ms));
        if (frame.has_value()) {
            last_frame = *frame;
            ++captured_count;
        } else if (frame.error().code != capture::CaptureError::Code::timeout) {
            spdlog::error("capture: {}", capture::to_string(frame.error()));
            return EXIT_FAILURE;
        }
        if (!last_frame.has_value()) {
            continue;  // nothing captured yet; just try again
        }
        if (std::chrono::steady_clock::now() < next_tick) {
            continue;  // a frame came in early; hold it until the tick
        }

        next_tick += frame_interval;
        if (next_tick < std::chrono::steady_clock::now()) {
            next_tick = std::chrono::steady_clock::now() + frame_interval;  // fell behind; don't burst to catch up
        }

        if (!encoder_ready) {
            const capture::EncoderConfig config{.width = last_frame->width, .height = last_frame->height};
            if (auto opened = encoder.open(duplicator.device(), config); !opened.has_value()) {
                spdlog::error("capture: failed to open encoder: {}", capture::to_string(opened.error()));
                return EXIT_FAILURE;
            }
            encoder_ready = true;
            spdlog::info("capture: hardware H.264 encoder ready ({}x{})", last_frame->width, last_frame->height);
        }

        const auto now = std::chrono::steady_clock::now();
        const auto timestamp = std::chrono::duration_cast<std::chrono::microseconds>(now - stream_start);

        auto packets = encoder.encode(last_frame->texture, timestamp);
        if (!packets.has_value()) {
            spdlog::error("capture: encode failed: {}", capture::to_string(packets.error()));
            return EXIT_FAILURE;
        }

        ++encoded_count;
        for (const auto& packet : *packets) {
            ++packet_count;
            bytes_this_window += packet.data.size();
        }

        if (now - window_start >= std::chrono::seconds(1)) {
            const double kbps = static_cast<double>(bytes_this_window) * 8.0 / 1000.0;
            spdlog::info("capture: {}x{}, {} frames captured, {} encoded, {} packets, {:.1f} kbps",
                         last_frame->width, last_frame->height, captured_count, encoded_count, packet_count, kbps);
            captured_count = 0;
            encoded_count = 0;
            packet_count = 0;
            bytes_this_window = 0;
            window_start = now;
        }
    }
}
