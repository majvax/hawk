#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

// The stream's quality presets: what a viewer picks from the live view's
// Quality menu, and the machine's default ([[stream]] quality). Mirrors
// Preset in src/server/relay/src/quality.rs and QUALITY_PRESETS in
// frontend/src/quality.ts.
namespace hawk::service {

enum class QualityPreset : std::uint8_t { automatic, low, balanced, high, max };

struct QualityLevel {
    std::string_view name;  // as written in the config and on the wire
    std::uint32_t    bitrate_bps = 0;  // Auto: where it starts
    std::uint32_t    fps = 0;
};

// In QualityPreset's order. Low also halves the frame rate: at 1 Mbps,
// fewer, sharper frames read better than many smeared ones.
inline constexpr std::array<QualityLevel, 5> kQualityLevels{{
    {.name = "auto", .bitrate_bps = 4'000'000, .fps = 60},
    {.name = "low", .bitrate_bps = 1'000'000, .fps = 30},
    {.name = "balanced", .bitrate_bps = 4'000'000, .fps = 60},
    {.name = "high", .bitrate_bps = 8'000'000, .fps = 60},
    {.name = "max", .bitrate_bps = 16'000'000, .fps = 60},
}};

// The names alone, for the config's schema.
inline constexpr std::array<std::string_view, 5> kQualityNames{"auto", "low", "balanced", "high", "max"};
static_assert(std::ranges::equal(kQualityNames, kQualityLevels, {}, {}, &QualityLevel::name));

// Where Auto's bitrate may go: the relay's controller steers it inside
// this, and the machine holds it there whatever the relay says. Must match
// AUTO_MIN_BITRATE and AUTO_MAX_BITRATE in src/server/relay/src/quality.rs.
inline constexpr std::uint32_t kAutoMinBitrate = 500'000;
inline constexpr std::uint32_t kAutoMaxBitrate = 12'000'000;

[[nodiscard]] constexpr const QualityLevel& level(QualityPreset preset) {
    return kQualityLevels.at(static_cast<std::size_t>(preset));
}

[[nodiscard]] constexpr std::string_view to_string(QualityPreset preset) {
    return level(preset).name;
}

[[nodiscard]] constexpr std::optional<QualityPreset> parse_quality(std::string_view name) {
    const auto found = std::ranges::find(kQualityLevels, name, &QualityLevel::name);
    if (found == kQualityLevels.end()) {
        return std::nullopt;
    }
    return static_cast<QualityPreset>(found - kQualityLevels.begin());
}

[[nodiscard]] constexpr std::uint32_t clamp_auto_bitrate(std::uint32_t bitrate_bps) {
    return std::clamp(bitrate_bps, kAutoMinBitrate, kAutoMaxBitrate);
}

}  // namespace hawk::service
