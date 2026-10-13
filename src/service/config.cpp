#include "config.hpp"

#include "common/clipboard_pipe.hpp"
#include "win_util.hpp"

#include <glaze/toml.hpp>
#include <spdlog/spdlog.h>

#include <cstdint>
#include <filesystem>
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

struct RelayTable {
    std::optional<std::string> url;
};

struct UpdateTable {
    std::optional<std::string>   policy;
    std::optional<std::uint32_t> check_hours;
    std::optional<std::string>   channel;
    std::optional<std::string>   manifest_url;
    std::optional<std::string>   public_key;
};

struct MetricsTable {
    std::optional<bool>          enabled;
    std::optional<std::uint32_t> history_days;
};

struct ConfigFile {
    std::vector<ClipboardTable> clipboard;
    std::vector<FilesTable>     files;
    std::vector<ShellTable>     shell;
    std::vector<RelayTable>     relay;
    std::vector<UpdateTable>    update;
    std::vector<MetricsTable>   metrics;
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
struct glz::meta<hawk::service::RelayTable> {
    using T                     = hawk::service::RelayTable;
    static constexpr auto value = object("url", &T::url);
};

template <>
struct glz::meta<hawk::service::UpdateTable> {
    using T                     = hawk::service::UpdateTable;
    static constexpr auto value = object("policy", &T::policy, "check_hours", &T::check_hours, "channel", &T::channel,
                                         "manifest_url", &T::manifest_url, "public_key", &T::public_key);
};

template <>
struct glz::meta<hawk::service::MetricsTable> {
    using T                     = hawk::service::MetricsTable;
    static constexpr auto value = object("enabled", &T::enabled, "history_days", &T::history_days);
};

template <>
struct glz::meta<hawk::service::ConfigFile> {
    using T                     = hawk::service::ConfigFile;
    static constexpr auto value = object("clipboard", &T::clipboard, "files", &T::files, "shell", &T::shell, "relay",
                                         &T::relay, "update", &T::update, "metrics", &T::metrics);
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

[[nodiscard]] std::optional<RelayConfig> relay_config(const std::vector<RelayTable>& tables) {
    RelayConfig config;
    if (tables.empty()) {
        return config;
    }
    if (tables.size() > 1) {
        spdlog::error("config: {} has more than one [[relay]] table", kConfigPath.string());
        return std::nullopt;
    }
    if (const auto& url = tables.front().url; url.has_value()) {
        if (!url->starts_with("wss://") && !url->starts_with("ws://")) {
            spdlog::error("config: relay url \"{}\" doesn't start with wss://", *url);
            return std::nullopt;
        }
        config.url = *url;
    }
    return config;
}

[[nodiscard]] std::optional<UpdateConfig> update_config(const std::vector<UpdateTable>& tables) {
    UpdateConfig config;
    if (tables.empty()) {
        return config;
    }
    if (tables.size() > 1) {
        spdlog::error("config: {} has more than one [[update]] table", kConfigPath.string());
        return std::nullopt;
    }
    const auto& table = tables.front();
    if (table.policy.has_value()) {
        if (*table.policy == "off") {
            config.policy = UpdatePolicy::off;
        } else if (*table.policy == "notify") {
            config.policy = UpdatePolicy::notify;
        } else if (*table.policy == "auto") {
            config.policy = UpdatePolicy::automatic;
        } else {
            spdlog::error("config: update policy \"{}\" isn't one of off, notify or auto", *table.policy);
            return std::nullopt;
        }
    }
    if (table.check_hours.has_value()) {
        if (*table.check_hours == 0 || *table.check_hours > 24 * 30) {
            spdlog::error("config: update check_hours must be between 1 and 720");
            return std::nullopt;
        }
        config.check_hours = *table.check_hours;
    }
    if (table.channel.has_value() && *table.channel != "stable" && *table.channel != "beta") {
        spdlog::error("config: update channel \"{}\" isn't stable or beta", *table.channel);
        return std::nullopt;
    }
    config.channel = table.channel.value_or("");
    config.manifest_url = table.manifest_url.value_or("");
    config.public_key = table.public_key.value_or("");
    return config;
}

[[nodiscard]] std::optional<MetricsConfig> metrics_config(const std::vector<MetricsTable>& tables) {
    MetricsConfig config;
    if (tables.empty()) {
        return config;
    }
    if (tables.size() > 1) {
        spdlog::error("config: {} has more than one [[metrics]] table", kConfigPath.string());
        return std::nullopt;
    }
    const auto& table = tables.front();
    if (table.history_days.has_value()) {
        if (*table.history_days == 0 || *table.history_days > max_metrics_history_days) {
            spdlog::error("config: metrics history_days must be between 1 and {}", max_metrics_history_days);
            return std::nullopt;
        }
        config.history_days = *table.history_days;
    }
    config.enabled = table.enabled.value_or(config.enabled);
    return config;
}

}  // namespace

MachineConfig load_machine_config() {
    MachineConfig config;
    const auto    read = win::read_protected_file(kConfigPath);
    if (!read.has_value()) {
        // Someone else's file could name its own update feed and key, or
        // turn the shell on: trust none of it.
        spdlog::error("config: ignoring {} ({}); the clipboard, file transfer, shell and relay connection are off",
                      kConfigPath.string(), read.error());
        config.clipboard.mode = ClipboardMode::off;
        config.files.enabled = false;
        config.shell.enabled = false;
        config.relay.url.clear();
        return config;
    }
    if (!read->has_value()) {
        spdlog::info("config: no {}; using the defaults", kConfigPath.string());
        return config;
    }
    const std::string& text = **read;
    // glaze reads an empty buffer as an error; an empty file says nothing.
    if (text.find_first_not_of(" \t\r\n") == std::string::npos) {
        return config;
    }

    ConfigFile parsed;
    if (const auto error = glz::read_toml(parsed, text); error) {
        spdlog::error("config: {} doesn't parse ({}); the clipboard, file transfer, shell and relay connection are off", kConfigPath.string(),
                      glz::format_error(error, text));
        config.clipboard.mode = ClipboardMode::off;
        config.files.enabled = false;
        config.shell.enabled = false;
        config.relay.url.clear();
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
    if (auto relay = relay_config(parsed.relay); relay.has_value()) {
        config.relay = *relay;
    } else {
        spdlog::error("config: not connecting to any relay until {} is fixed", kConfigPath.string());
        config.relay.url.clear();
    }
    if (auto update = update_config(parsed.update); update.has_value()) {
        config.update = *update;
    } else {
        spdlog::error("config: updates only notify until {} is fixed", kConfigPath.string());
    }
    if (auto metrics = metrics_config(parsed.metrics); metrics.has_value()) {
        config.metrics = *metrics;
    } else {
        spdlog::error("config: analytics use the defaults until {} is fixed", kConfigPath.string());
    }
    return config;
}

}  // namespace hawk::service
