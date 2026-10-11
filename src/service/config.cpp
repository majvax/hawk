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

struct FilesTable {
    std::optional<bool>          enabled;
    std::optional<std::string>   drop_dir;
    std::optional<std::uint64_t> max_size;
};

struct ShellTable {
    std::optional<bool>        enabled;
    std::optional<std::string> command;
};

struct ConfigFile {
    std::vector<ClipboardTable> clipboard;
    std::vector<FilesTable>     files;
    std::vector<ShellTable>     shell;
};

}  // namespace

}  // namespace hawk::service

template <>
struct glz::meta<hawk::service::ClipboardTable> {
    using T                     = hawk::service::ClipboardTable;
    static constexpr auto value = object("mode", &T::mode, "max_size", &T::max_size, "view_pull", &T::view_pull);
};

template <>
struct glz::meta<hawk::service::FilesTable> {
    using T                     = hawk::service::FilesTable;
    static constexpr auto value = object("enabled", &T::enabled, "drop_dir", &T::drop_dir, "max_size", &T::max_size);
};

template <>
struct glz::meta<hawk::service::ShellTable> {
    using T                     = hawk::service::ShellTable;
    static constexpr auto value = object("enabled", &T::enabled, "command", &T::command);
};

template <>
struct glz::meta<hawk::service::ConfigFile> {
    using T                     = hawk::service::ConfigFile;
    static constexpr auto value = object("clipboard", &T::clipboard, "files", &T::files, "shell", &T::shell);
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

[[nodiscard]] std::optional<FilesConfig> files_config(const std::vector<FilesTable>& tables) {
    FilesConfig config;
    if (tables.empty()) {
        return config;
    }
    if (tables.size() > 1) {
        spdlog::error("config: {} has more than one [[files]] table", kConfigPath.string());
        return std::nullopt;
    }
    const auto& table = tables.front();
    if (table.max_size.has_value()) {
        if (*table.max_size == 0 || *table.max_size > max_file_size_limit) {
            spdlog::error("config: files max_size must be between 1 and {}", max_file_size_limit);
            return std::nullopt;
        }
        config.max_size = *table.max_size;
    }
    if (table.drop_dir.has_value()) {
        // A path the machine's own user can name, never one relative to
        // wherever the service happens to run.
        const std::filesystem::path dir = std::filesystem::path(
            std::u8string(reinterpret_cast<const char8_t*>(table.drop_dir->data()), table.drop_dir->size()));
        if (!table.drop_dir->empty() && !dir.is_absolute() && !table.drop_dir->starts_with('%')) {
            spdlog::error("config: files drop_dir \"{}\" isn't an absolute path", *table.drop_dir);
            return std::nullopt;
        }
        config.drop_dir = *table.drop_dir;
    }
    config.enabled = table.enabled.value_or(config.enabled);
    return config;
}

[[nodiscard]] std::optional<ShellConfig> shell_config(const std::vector<ShellTable>& tables) {
    ShellConfig config;
    if (tables.empty()) {
        return config;
    }
    if (tables.size() > 1) {
        spdlog::error("config: {} has more than one [[shell]] table", kConfigPath.string());
        return std::nullopt;
    }
    const auto& table = tables.front();
    if (table.command.has_value()) {
        if (table.command->find_first_not_of(" \t") == std::string::npos) {
            spdlog::error("config: shell command is empty");
            return std::nullopt;
        }
        config.command = *table.command;
    }
    config.enabled = table.enabled.value_or(config.enabled);
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
        spdlog::error("config: {} doesn't parse ({}); the clipboard, file transfer and shell are off", kConfigPath.string(),
                      glz::format_error(error, text));
        config.clipboard.mode = ClipboardMode::off;
        config.files.enabled = false;
        config.shell.enabled = false;
        return config;
    }
    if (auto clipboard = clipboard_config(parsed.clipboard); clipboard.has_value()) {
        config.clipboard = *clipboard;
    } else {
        spdlog::error("config: the clipboard is off until {} is fixed", kConfigPath.string());
        config.clipboard.mode = ClipboardMode::off;
    }
    if (auto files = files_config(parsed.files); files.has_value()) {
        config.files = *files;
    } else {
        spdlog::error("config: file transfer is off until {} is fixed", kConfigPath.string());
        config.files.enabled = false;
    }
    if (auto shell = shell_config(parsed.shell); shell.has_value()) {
        config.shell = *shell;
    } else {
        spdlog::error("config: the shell is off until {} is fixed", kConfigPath.string());
        config.shell.enabled = false;
    }
    return config;
}

}  // namespace hawk::service
