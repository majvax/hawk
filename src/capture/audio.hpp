#pragma once

#include "encoder.hpp"

#include <chrono>
#include <functional>
#include <memory>
#include <string>

namespace hawk::capture {

// What the machine plays, for the viewers: WASAPI loopback on the default
// output device, encoded as Opus (48 kHz stereo, 20 ms packets). Whatever
// the device's own format, it arrives here as 48 kHz stereo.
//
// Runs on a thread of its own, apart from the desktop the video follows:
// audio belongs to the session, so it keeps playing on the lock screen and
// under a UAC prompt. Silence isn't sent at all, so a quiet machine costs
// nothing. With no output device (or none yet) it waits and tries again;
// a switch of the default device (headphones plugged in) is followed,
// unless a viewer chose a device of its own, which is kept while it's
// there (and the default used while it isn't).
//
// Requires nothing of the caller's COM state: the thread sets up its own.
class AudioCapture {
public:
    // Hands one encoded packet on, timestamped on the video's clock.
    // Returns false once it can't be delivered any more (hawk-service
    // closed the pipe), which ends the capture.
    using PacketSink = std::function<bool(const EncodedPacket&)>;

    AudioCapture();
    ~AudioCapture();

    AudioCapture(const AudioCapture&) = delete;
    AudioCapture& operator=(const AudioCapture&) = delete;
    AudioCapture(AudioCapture&&) = delete;
    AudioCapture& operator=(AudioCapture&&) = delete;

    // `stream_start` is the instant the video timestamps count from.
    // `device_id` is an endpoint id to capture instead of the default.
    void start(std::chrono::steady_clock::time_point stream_start, PacketSink sink, std::wstring device_id = {});

    // Stops the thread. Safe to call when it never started.
    void stop() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace hawk::capture
