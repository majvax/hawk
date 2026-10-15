#pragma once

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>

// Power actions a viewer with control can ask of the machine. The request
// arrives sealed (ViewerHub::power) so the relay can neither read nor forge
// one; the service carries it out as LocalSystem.
namespace hawk::service {

// The byte a sealed power request carries; must match POWER_ACTIONS in
// frontend/src/e2e.ts.
enum class PowerAction : std::uint8_t {
    lock = 1,
    sign_out = 2,
    restart = 3,
    shut_down = 4,
};

[[nodiscard]] std::optional<PowerAction> to_power_action(std::uint8_t value) noexcept;
[[nodiscard]] std::string_view           to_string(PowerAction action) noexcept;

// Whether the machine goes away for a while after `action`.
[[nodiscard]] constexpr bool goes_down(PowerAction action) noexcept {
    return action == PowerAction::restart || action == PowerAction::shut_down;
}

// Carries the action out. Restart and shut down close every app, saved or
// not, and return as soon as Windows has started on it. Lock and sign out
// act on whoever is signed in to the console, and fail when nobody is.
[[nodiscard]] std::expected<void, std::string> perform(PowerAction action);

}  // namespace hawk::service
