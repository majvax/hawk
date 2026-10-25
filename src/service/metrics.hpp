#pragma once

#include "config.hpp"
#include "e2e.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

// Analytics, the machine's side: the service samples its own health once
// a second and keeps the history itself, never on the relay. Viewers the
// owner allowed analytics (the owner always) ask for it over ViewerHub's
// metrics channel, end-to-end encrypted like the file and shell channels.
//
// Each message is an op, a small JSON header and, from the machine, a JSON
// body as data (history and process lists don't fit a header):
//
//   viewer -> machine              machine -> viewer
//   subscribe   {}                 info      body: what the machine is (CPU, GPUs, RAM...)
//   unsubscribe {}                 sample    body: one second's numbers, pushed while subscribed
//   history     {range}            history   body: {range, step, t: [...], cpu: [...], ...}
//   processes   {}                 processes body: {processes: [...]}
//                                  error     {message}
//
// History: one point a second for the last hour, in memory; one a minute
// for `history_days`, also in C:\ProgramData\HawkService\metrics. A range
// comes back averaged into at most a few hundred points.
//
// Temperatures ride in the samples only (`cpu_temp`, and `temp` per GPU),
// where the machine has a sensor to read: left out otherwise, so an older
// dashboard ignores them and a newer one shows them as unavailable. They
// aren't kept in the history, whose file keeps its layout.
namespace hawk::service {

namespace metrics_op {
inline constexpr std::uint8_t subscribe = 1;
inline constexpr std::uint8_t unsubscribe = 2;
inline constexpr std::uint8_t history = 3;
inline constexpr std::uint8_t processes = 4;

inline constexpr std::uint8_t info = 17;
inline constexpr std::uint8_t sample = 18;
inline constexpr std::uint8_t history_data = 19;
inline constexpr std::uint8_t process_list = 20;
inline constexpr std::uint8_t error = 23;
}  // namespace metrics_op

// Samples the machine once a second for as long as it exists, whether or
// not anyone is watching. Thread-safe.
class MetricsRecorder {
public:
    explicit MetricsRecorder(MetricsConfig config);
    ~MetricsRecorder();
    MetricsRecorder(const MetricsRecorder&) = delete;
    MetricsRecorder& operator=(const MetricsRecorder&) = delete;
    MetricsRecorder(MetricsRecorder&&) = delete;
    MetricsRecorder& operator=(MetricsRecorder&&) = delete;

    // Goes up with every new sample; 0 before the first.
    [[nodiscard]] std::uint64_t sequence() const;

    // As JSON, for the channel: what the machine is, the latest sample, a
    // range of history ("5m", "1h", "24h", "7d", "30d", "90d"; nullopt for
    // one it doesn't know), and the processes running now.
    [[nodiscard]] std::string info_json() const;
    [[nodiscard]] std::string sample_json() const;
    [[nodiscard]] std::optional<std::string> history_json(std::string_view range) const;
    [[nodiscard]] std::string processes_json();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// One relay connection's side of it: answers viewers' requests and pushes
// each new sample to the viewers subscribed. handle() and drop_viewer() may
// be called from any thread; the work happens on an internal thread, which
// answers through `hub`. Destroy this before the hub.
class MetricsChannel {
public:
    MetricsChannel(MetricsRecorder& recorder, ViewerHub& hub);
    ~MetricsChannel();
    MetricsChannel(const MetricsChannel&) = delete;
    MetricsChannel& operator=(const MetricsChannel&) = delete;
    MetricsChannel(MetricsChannel&&) = delete;
    MetricsChannel& operator=(MetricsChannel&&) = delete;

    // A message the hub opened for this viewer.
    void handle(std::uint64_t viewer, ChannelMessage message);

    // The viewer left: no more samples for it.
    void drop_viewer(std::uint64_t viewer);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace hawk::service
