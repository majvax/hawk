#pragma once

#include <expected>
#include <string>
#include <string_view>
#include <vector>

// The machine's output devices, for the viewer's device picker. Which one
// hawk-capture loops back is chosen per stream (main.cpp keeps it with the
// connection) and passed to it as --audio-device; nothing is saved.
namespace hawk::service {

struct AudioDevice {
    std::string id;    // the endpoint id Windows gives it, UTF-8
    std::string name;  // "Speakers (Realtek(R) Audio)"
    bool        is_default = false;
};

// Every active render endpoint, the default one marked. Callable from any
// thread: it sets up COM for itself.
[[nodiscard]] std::expected<std::vector<AudioDevice>, std::string> list_audio_devices();

// Whether `id` looks like an endpoint id: it goes on hawk-capture's
// command line, so nothing that could break out of an argument.
[[nodiscard]] bool plausible_device_id(std::string_view id) noexcept;

}  // namespace hawk::service
