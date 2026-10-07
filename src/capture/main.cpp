#include "duplication.hpp"
#include "encoder.hpp"

#include <objbase.h>

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdlib>

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

    capture::DesktopDuplicator duplicator;
    if (auto opened = duplicator.open(); !opened.has_value()) {
        spdlog::error("capture: failed to open desktop duplication: {}", capture::to_string(opened.error()));
        return EXIT_FAILURE;
    }

    spdlog::info("capture: desktop duplication started");

    capture::H264Encoder encoder;
    bool                 encoder_ready = false;

    std::uint64_t frame_count = 0;
    std::uint64_t packet_count = 0;
    std::size_t   bytes_this_window = 0;
    auto          window_start = std::chrono::steady_clock::now();
    const auto    stream_start = window_start;

    for (;;) {
        auto frame = duplicator.capture_frame();
        if (!frame.has_value()) {
            if (frame.error().code == capture::CaptureError::Code::timeout) {
                continue;  // no screen changes since the last frame; just try again
            }
            spdlog::error("capture: {}", capture::to_string(frame.error()));
            return EXIT_FAILURE;
        }

        if (!encoder_ready) {
            const capture::EncoderConfig config{.width = frame->width, .height = frame->height};
            if (auto opened = encoder.open(duplicator.device(), config); !opened.has_value()) {
                spdlog::error("capture: failed to open encoder: {}", capture::to_string(opened.error()));
                return EXIT_FAILURE;
            }
            encoder_ready = true;
            spdlog::info("capture: hardware H.264 encoder ready ({}x{})", frame->width, frame->height);
        }

        const auto now = std::chrono::steady_clock::now();
        const auto timestamp = std::chrono::duration_cast<std::chrono::microseconds>(now - stream_start);

        auto packet = encoder.encode(frame->texture, timestamp);
        if (!packet.has_value()) {
            spdlog::error("capture: encode failed: {}", capture::to_string(packet.error()));
            return EXIT_FAILURE;
        }

        ++frame_count;
        if (packet->has_value()) {
            ++packet_count;
            bytes_this_window += (*packet)->data.size();
        }

        if (now - window_start >= std::chrono::seconds(1)) {
            const double kbps = static_cast<double>(bytes_this_window) * 8.0 / 1000.0;
            spdlog::info("capture: {}x{} @ {} fps captured, {} packets, {:.1f} kbps", frame->width, frame->height,
                         frame_count, packet_count, kbps);
            frame_count = 0;
            packet_count = 0;
            bytes_this_window = 0;
            window_start = now;
        }
    }
}
