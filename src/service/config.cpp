#include "config.hpp"

#include "common/clipboard_pipe.hpp"

#include <glaze/toml.hpp>
#include <spdlog/spdlog.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

namespace hawk::service {

namespace {

const std::filesystem::path kConfigPath = R"(C:\ProgramData\HawkService\config.toml)";

// One [[clipboard]] table as it's written. Optional members keep the
// defaults for whatever the table leaves out.
struct ClipboardTable {
    std::optional<std::string>   mode;
    std::optional<std::uint32_t> max_size;
    std::optional<bool>          view_pull;
};

struct ConfigFile {
    std::vector<ClipboardTable> clipboard;
};

}  // namespace

}  // namespace hawk::service

template <>
struct glz::meta<hawk::service::ClipboardTable> {
    using T                     = hawk::service::ClipboardTable;
    static constexpr auto value = object("mode", &T::mode, "max_size", &T::max_size, "view_pull", &T::view_pull);
};

template <>
struct glz::meta<hawk::service::ConfigFile> {
    using T                     = hawk::service::ConfigFile;
    static constexpr auto value = object("clipboard", &T::clipboard);
};

namespace hawk::service {

namespace {

[[nodiscard]] std::optional<ClipboardConfig> clipboard_config(const std::vector<ClipboardTable>& tables) {
    ClipboardConfig config;
    if (tables.empty()) {
        return config;
    }
    if (tables.size() > 1) {
        spdlog::error("config: {} has more than one [[clipboard]] table", kConfigPath.string());
        return std::nullopt;
    }
    const auto& table = tables.front();
    if (table.mode.has_value()) {
        if (*table.mode == "off") {
            config.mode = ClipboardMode::off;
        } else if (*table.mode == "pull") {
            config.mode = ClipboardMode::pull;
        } else if (*table.mode == "sync") {
            config.mode = ClipboardMode::sync;
        } else {
            spdlog::error("config: clipboard mode \"{}\" isn't one of off, pull or sync", *table.mode);
            return std::nullopt;
        }
    }
    if (table.max_size.has_value()) {
        if (*table.max_size == 0 || *table.max_size > ipc::max_clipboard_size) {
            spdlog::error("config: clipboard max_size must be between 1 and {}", ipc::max_clipboard_size);
            return std::nullopt;
        }
        config.max_size = *table.max_size;
    }
    config.view_pull = table.view_pull.value_or(config.view_pull);
    return config;
}

}  // namespace

MachineConfig load_machine_config() {
    MachineConfig config;
    std::ifstream file(kConfigPath, std::ios::binary);
    if (!file) {
        spdlog::info("config: no {}; using the defaults", kConfigPath.string());
        return config;
    }
    const std::string text(std::istreambuf_iterator<char>(file), {});
    // glaze reads an empty buffer as an error; an empty file says nothing.
    if (text.find_first_not_of(" \t\r\n") == std::string::npos) {
        return config;
    }

    ConfigFile parsed;
    if (const auto error = glz::read_toml(parsed, text); error) {
        spdlog::error("config: {} doesn't parse ({}); the clipboard is off", kConfigPath.string(),
                      glz::format_error(error, text));
        config.clipboard.mode = ClipboardMode::off;
        return config;
    }
    if (auto clipboard = clipboard_config(parsed.clipboard); clipboard.has_value()) {
        config.clipboard = *clipboard;
    } else {
        spdlog::error("config: the clipboard is off until {} is fixed", kConfigPath.string());
        config.clipboard.mode = ClipboardMode::off;
    }
    return config;
}

}  // namespace hawk::service
