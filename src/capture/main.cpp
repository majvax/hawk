#include "audio.hpp"
#include "clipboard.hpp"
#include "common/capture_pipe.hpp"
#include "desktop.hpp"
#include "duplication.hpp"
#include "encoder.hpp"
#include "input.hpp"

#include <objbase.h>
#include <timeapi.h>

#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>

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

// Client end of the pipe hawk-service creates for us; see
// common/capture_pipe.hpp for the wire format.
class PacketPipe {
public:
    PacketPipe() = default;
    ~PacketPipe() {
        if (pipe_ != INVALID_HANDLE_VALUE) {
            CloseHandle(pipe_);
        }
    }

    PacketPipe(const PacketPipe&) = delete;
    PacketPipe& operator=(const PacketPipe&) = delete;
    PacketPipe(PacketPipe&&) = delete;
    PacketPipe& operator=(PacketPipe&&) = delete;

    [[nodiscard]] bool open(const std::string& name) {
        // Not GENERIC_WRITE: that also asks for FILE_APPEND_DATA, which on a
        // pipe is FILE_CREATE_PIPE_INSTANCE, and the service's DACL grants us
        // only what writing actually needs. FILE_READ_ATTRIBUTES is in the
        // set because CreateFile requests it for us either way.
        constexpr DWORD access = FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        pipe_ = CreateFileA(name.c_str(), access, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (pipe_ == INVALID_HANDLE_VALUE) {
            spdlog::error("capture: failed to open pipe {}: Win32 error {}", name, GetLastError());
            return false;
        }
        return true;
    }

    [[nodiscard]] bool is_open() const noexcept { return pipe_ != INVALID_HANDLE_VALUE; }

    // Returns false once hawk-service has closed its end. Video and audio
    // write from their own threads; a packet goes out whole either way.
    [[nodiscard]] bool write(const capture::EncodedPacket& packet, bool audio = false) {
        std::uint8_t flags = packet.is_keyframe ? hawk::ipc::capture_flag_keyframe : std::uint8_t{0};
        if (audio) {
            flags |= hawk::ipc::capture_flag_audio;
        }
        const hawk::ipc::CapturePacketHeader header{
            .size = static_cast<std::uint32_t>(packet.data.size()),
            .timestamp_us = packet.timestamp.count(),
            .flags = flags,
        };
        const std::scoped_lock lock(mutex_);
        return write_all(std::as_bytes(std::span(&header, 1))) && write_all(packet.data);
    }

private:
    [[nodiscard]] bool write_all(std::span<const std::byte> data) {
        while (!data.empty()) {
            DWORD written = 0;
            if (WriteFile(pipe_, data.data(), static_cast<DWORD>(data.size()), &written, nullptr) == FALSE) {
                return false;
            }
            data = data.subspan(written);
        }
        return true;
    }

    HANDLE     pipe_ = INVALID_HANDLE_VALUE;
    std::mutex mutex_;
};

// hawk-service launches us with `--pipe <name> --input-pipe <name>`,
// `--clipboard-pipe <name>` (plus `--clipboard-listen`) when its config
// allows the clipboard, and `--audio` when the machine's sound goes too.
[[nodiscard]] std::optional<std::string> option_value(std::span<char* const> args, std::string_view option) {
    for (std::size_t i = 1; i + 1 < args.size(); ++i) {
        if (std::string_view(args[i]) == option) {
            return std::string(args[i + 1]);
        }
    }
    return std::nullopt;
}

[[nodiscard]] bool has_flag(std::span<char* const> args, std::string_view flag) {
    return std::ranges::any_of(args.subspan(1), [flag](const char* arg) { return std::string_view(arg) == flag; });
}

// Launched by hawk-service there is no console to log to, so log to
// %TEMP%\hawk-capture.log (the logged-on user's temp directory) instead.
void init_logging(bool launched_by_service) {
    if (launched_by_service) {
        std::array<char, MAX_PATH + 1> temp{};
        const DWORD length = GetTempPathA(static_cast<DWORD>(temp.size()), temp.data());
        if (length != 0 && length < temp.size()) {
            try {
                auto logger = spdlog::basic_logger_mt("hawk-capture", std::string(temp.data(), length) + "hawk-capture.log",
                                                      /*truncate=*/true);
                spdlog::set_default_logger(logger);
                spdlog::flush_on(spdlog::level::info);
                return;
            } catch (const spdlog::spdlog_ex&) {  // fall through to stdout
            }
        }
    }
    spdlog::set_default_logger(spdlog::stdout_color_mt("hawk-capture"));
}

}  // namespace

// Standalone helper: must run as an ordinary process inside the interactive
// user's own session, not the service (Session 0 has no desktop to see).
// Captures the desktop and encodes it to H.264 on the GPU, and replays the
// viewer's mouse and keyboard into the session. Launched by hawk-service
// with `--pipe <name> --input-pipe <name>`, it streams the packets back over
// the first pipe, takes input events off the second, and exits once the
// service closes them. Run on its own, without `--pipe`, it only logs packet
// stats.
int main(int argc, char* argv[]) {
    const auto args = std::span(argv, static_cast<std::size_t>(argc));
    const auto pipe_name = option_value(args, "--pipe");
    const auto input_pipe_name = option_value(args, "--input-pipe");
    const auto clipboard_pipe_name = option_value(args, "--clipboard-pipe");
    init_logging(pipe_name.has_value());

    PacketPipe pipe;
    if (pipe_name.has_value() && !pipe.open(*pipe_name)) {
        return EXIT_FAILURE;
    }

    ComScope com;
    if (!com.ok()) {
        spdlog::error("capture: CoInitializeEx failed");
        return EXIT_FAILURE;
    }

    const TimerResolutionScope timer_resolution;

    // Capture whichever desktop currently holds input. Running as SYSTEM
    // (hawk-service launches us so), this reaches the secure desktop too, so
    // the UAC prompt and lock screen are captured rather than freezing the
    // stream. The thread is re-attached on every desktop switch below.
    HDESK capture_desktop = nullptr;
    if (!capture::follow_input_desktop(capture_desktop)) {
        spdlog::warn("capture: couldn't attach to the input desktop; the secure desktop won't be captured");
    }

    capture::DesktopDuplicator duplicator;
    if (auto opened = duplicator.open(); !opened.has_value()) {
        spdlog::error("capture: failed to open desktop duplication: {}", capture::to_string(opened.error()));
        capture::close_desktop(capture_desktop);
        return EXIT_FAILURE;
    }

    spdlog::info("capture: desktop duplication started");

    // Input is best-effort: a viewer who can't control the machine (or a
    // standalone run with no `--input-pipe`) just means no input channel,
    // never a failed capture. It's closed before the duplicator so nothing
    // is left held down if the capture loop gives up below.
    capture::InputChannel input;
    if (input_pipe_name.has_value() && !input.open(*input_pipe_name, duplicator.bounds())) {
        spdlog::warn("capture: continuing without input");
    }

    // Best-effort too, and only there when hawk-service's config allows it.
    capture::ClipboardChannel clipboard;
    if (clipboard_pipe_name.has_value() &&
        !clipboard.open(*clipboard_pipe_name, has_flag(args, "--clipboard-listen"))) {
        spdlog::warn("capture: continuing without the clipboard");
    }

    capture::H264Encoder encoder;
    bool                 encoder_ready = false;

    std::uint64_t captured_count = 0;
    std::uint64_t encoded_count = 0;
    std::uint64_t packet_count = 0;
    std::size_t   bytes_this_window = 0;
    auto          window_start = std::chrono::steady_clock::now();
    const auto    stream_start = window_start;

    // What the machine plays, on the same clock as the frames. Its own
    // thread, stopped before the pipe closes on any return below.
    // Run on its own, it only counts the packets.
    capture::AudioCapture audio;
    if (has_flag(args, "--audio")) {
        audio.start(stream_start, [&pipe, count = std::uint64_t{0}](const capture::EncodedPacket& packet) mutable {
            if (pipe.is_open()) {
                return pipe.write(packet, true);
            }
            if (++count % 50 == 0) {
                spdlog::info("audio: {} packets, the last {} bytes at {} ms", count, packet.data.size(),
                             packet.timestamp.count() / 1000);
            }
            return true;
        });
    }

    // Encode on a fixed frame clock at the encoder's frame rate. Desktop
    // Duplication only produces a frame when the screen changes, at up to the
    // monitor's refresh rate, so:
    //  - frames arriving faster than the clock just refresh the duplicator's
    //    copy texture, and the newest one is encoded at the next tick;
    //  - on an idle screen the last frame (still held in that copy texture)
    //    is re-encoded each tick, which keeps the stream alive and flushes
    //    frames still in flight in the encoder — without this, output freezes
    //    whenever the screen stops changing.
    //
    // The wait between ticks happens here, never inside AcquireNextFrame:
    // the device is multithread-protected (see H264Encoder::open) and DXGI
    // holds that lock for the whole AcquireNextFrame timeout, which starves
    // the async encoder's worker thread and drops most frames. So each tick
    // only polls for the newest frame (timeout 0) and then sleeps unlocked.
    constexpr auto                frame_interval = std::chrono::microseconds{1'000'000 / capture::default_encoder_fps};
    auto                          next_tick = std::chrono::steady_clock::now();
    std::optional<capture::Frame> last_frame;

    // DXGI drops the duplication whenever the desktop switches — most often
    // to the secure desktop for a UAC prompt, also the lock screen — and on
    // a display mode change. None of those are fatal: that desktop simply
    // can't be captured from this session, so the stream holds on the last
    // frame (re-encoded every tick below, so it stays alive) until the
    // normal desktop returns and reacquire() takes. Attempts are throttled
    // so a long-lived prompt doesn't spin on COM calls.
    bool       duplication_lost = false;
    auto       next_reacquire = std::chrono::steady_clock::now();
    const auto reacquire_interval = std::chrono::milliseconds(250);

    for (;;) {
        std::this_thread::sleep_until(next_tick);

        auto frame = duplicator.capture_frame(0);
        if (frame.has_value()) {
            last_frame = *frame;
            ++captured_count;
            if (duplication_lost) {
                spdlog::info("capture: desktop duplication recovered");
                duplication_lost = false;
            }
        } else if (frame.error().code == capture::CaptureError::Code::access_lost) {
            if (!duplication_lost) {
                spdlog::info("capture: desktop switched away (e.g. a UAC prompt); holding the last frame");
                duplication_lost = true;
                next_reacquire = std::chrono::steady_clock::now();
            }
            if (std::chrono::steady_clock::now() >= next_reacquire) {
                // The switch is usually *why* we lost the duplication, so move
                // to whatever desktop now holds input before rebuilding it;
                // that's how the secure desktop gets captured.
                static_cast<void>(capture::follow_input_desktop(capture_desktop));
                if (auto reacquired = duplicator.reacquire(); reacquired.has_value()) {
                    // 'recovered' is logged above once a real frame arrives.
                    // The resolution is unchanged, but the monitor may have
                    // moved on the virtual desktop while we weren't looking.
                    input.set_bounds(duplicator.bounds());
                } else if (reacquired.error().code == capture::CaptureError::Code::access_lost) {
                    // The display mode changed while the duplication was
                    // down; the encoder is sized to the old resolution, so
                    // exit and let hawk-service relaunch us to re-open at the
                    // new one.
                    spdlog::info("capture: {}; restarting", capture::to_string(reacquired.error()));
                    return EXIT_SUCCESS;
                } else {
                    // Still the secure desktop (DuplicateOutput is denied
                    // while it's up); try again shortly.
                    next_reacquire = std::chrono::steady_clock::now() + reacquire_interval;
                }
            }
        } else if (frame.error().code != capture::CaptureError::Code::timeout) {
            spdlog::error("capture: {}", capture::to_string(frame.error()));
            return EXIT_FAILURE;
        }

        next_tick += frame_interval;
        if (!last_frame.has_value()) {
            continue;  // nothing captured yet; try again next tick
        }

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
            if (pipe.is_open() && !pipe.write(packet)) {
                spdlog::info("capture: hawk-service closed the pipe, exiting");
                return EXIT_SUCCESS;
            }
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
