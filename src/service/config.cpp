#include "config.hpp"

#include "common/clipboard_pipe.hpp"
#include "win_util.hpp"

#include <glaze/toml.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <format>
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
    std::optional<bool>          images;
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

struct AudioTable {
    std::optional<bool> enabled;
};

struct StreamTable {
    std::optional<std::string> quality;
};

struct LockedTable {
    std::optional<std::vector<std::string>> keys;
};

struct ConfigFile {
    std::vector<ClipboardTable> clipboard;
    std::vector<FilesTable>     files;
    std::vector<ShellTable>     shell;
    std::vector<RelayTable>     relay;
    std::vector<UpdateTable>    update;
    std::vector<MetricsTable>   metrics;
    std::vector<AudioTable>     audio;
    std::vector<StreamTable>    stream;
    std::vector<LockedTable>    locked;
};

}  // namespace

}  // namespace hawk::service

template <>
struct glz::meta<hawk::service::ClipboardTable> {
    using T                     = hawk::service::ClipboardTable;
    static constexpr auto value = object("mode", &T::mode, "max_size", &T::max_size, "view_pull", &T::view_pull,
                                         "images", &T::images);
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
struct glz::meta<hawk::service::AudioTable> {
    using T                     = hawk::service::AudioTable;
    static constexpr auto value = object("enabled", &T::enabled);
};

template <>
struct glz::meta<hawk::service::StreamTable> {
    using T                     = hawk::service::StreamTable;
    static constexpr auto value = object("quality", &T::quality);
};

template <>
struct glz::meta<hawk::service::LockedTable> {
    using T                     = hawk::service::LockedTable;
    static constexpr auto value = object("keys", &T::keys);
};

template <>
struct glz::meta<hawk::service::ConfigFile> {
    using T                     = hawk::service::ConfigFile;
    static constexpr auto value = object("clipboard", &T::clipboard, "files", &T::files, "shell", &T::shell, "relay",
                                         &T::relay, "update", &T::update, "metrics", &T::metrics, "audio", &T::audio,
                                         "stream", &T::stream, "locked", &T::locked);
};

namespace hawk::service {

namespace {

// Each table's rules. A table that breaks one says which, for the log or
// for the dashboard that asked for the change.
template <typename T>
using Checked = std::expected<T, std::string>;

[[nodiscard]] std::string more_than_one(std::string_view table) {
    return std::format("{} has more than one [[{}]] table", kConfigPath.string(), table);
}

[[nodiscard]] Checked<ClipboardConfig> clipboard_config(const std::vector<ClipboardTable>& tables) {
    ClipboardConfig config;
    if (tables.empty()) {
        return config;
    }
    if (tables.size() > 1) {
        return std::unexpected(more_than_one("clipboard"));
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
            return std::unexpected(std::format("clipboard mode \"{}\" isn't one of off, pull or sync", *table.mode));
        }
    }
    if (table.max_size.has_value()) {
        if (*table.max_size == 0 || *table.max_size > ipc::max_clipboard_size) {
            return std::unexpected(std::format("clipboard max_size must be between 1 and {}", ipc::max_clipboard_size));
        }
        config.max_size = *table.max_size;
    }
    config.view_pull = table.view_pull.value_or(config.view_pull);
    config.images = table.images.value_or(config.images);
    return config;
}

[[nodiscard]] Checked<FilesConfig> files_config(const std::vector<FilesTable>& tables) {
    FilesConfig config;
    if (tables.empty()) {
        return config;
    }
    if (tables.size() > 1) {
        return std::unexpected(more_than_one("files"));
    }
    const auto& table = tables.front();
    if (table.max_size.has_value()) {
        if (*table.max_size == 0 || *table.max_size > max_file_size_limit) {
            return std::unexpected(std::format("files max_size must be between 1 and {}", max_file_size_limit));
        }
        config.max_size = *table.max_size;
    }
    if (table.drop_dir.has_value()) {
        // A path the machine's own user can name, never one relative to
        // wherever the service happens to run.
        const std::filesystem::path dir = std::filesystem::path(
            std::u8string(reinterpret_cast<const char8_t*>(table.drop_dir->data()), table.drop_dir->size()));
        if (!table.drop_dir->empty() && !dir.is_absolute() && !table.drop_dir->starts_with('%')) {
            return std::unexpected(std::format("files drop_dir \"{}\" isn't an absolute path", *table.drop_dir));
        }
        config.drop_dir = *table.drop_dir;
    }
    config.enabled = table.enabled.value_or(config.enabled);
    return config;
}

[[nodiscard]] Checked<ShellConfig> shell_config(const std::vector<ShellTable>& tables) {
    ShellConfig config;
    if (tables.empty()) {
        return config;
    }
    if (tables.size() > 1) {
        return std::unexpected(more_than_one("shell"));
    }
    const auto& table = tables.front();
    if (table.command.has_value()) {
        if (table.command->find_first_not_of(" \t") == std::string::npos) {
            return std::unexpected(std::string("shell command is empty"));
        }
        config.command = *table.command;
    }
    config.enabled = table.enabled.value_or(config.enabled);
    return config;
}

[[nodiscard]] Checked<RelayConfig> relay_config(const std::vector<RelayTable>& tables) {
    RelayConfig config;
    if (tables.empty()) {
        return config;
    }
    if (tables.size() > 1) {
        return std::unexpected(more_than_one("relay"));
    }
    if (const auto& url = tables.front().url; url.has_value()) {
        if (!url->starts_with("wss://") && !url->starts_with("ws://")) {
            return std::unexpected(std::format("relay url \"{}\" doesn't start with wss://", *url));
        }
        config.url = *url;
    }
    return config;
}

[[nodiscard]] Checked<UpdateConfig> update_config(const std::vector<UpdateTable>& tables) {
    UpdateConfig config;
    if (tables.empty()) {
        return config;
    }
    if (tables.size() > 1) {
        return std::unexpected(more_than_one("update"));
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
            return std::unexpected(std::format("update policy \"{}\" isn't one of off, notify or auto", *table.policy));
        }
    }
    if (table.check_hours.has_value()) {
        if (*table.check_hours == 0 || *table.check_hours > 24 * 30) {
            return std::unexpected(std::string("update check_hours must be between 1 and 720"));
        }
        config.check_hours = *table.check_hours;
    }
    if (table.channel.has_value() && *table.channel != "stable" && *table.channel != "beta") {
        return std::unexpected(std::format("update channel \"{}\" isn't stable or beta", *table.channel));
    }
    config.channel = table.channel.value_or("");
    config.manifest_url = table.manifest_url.value_or("");
    config.public_key = table.public_key.value_or("");
    return config;
}

[[nodiscard]] Checked<AudioConfig> audio_config(const std::vector<AudioTable>& tables) {
    AudioConfig config;
    if (tables.empty()) {
        return config;
    }
    if (tables.size() > 1) {
        return std::unexpected(more_than_one("audio"));
    }
    config.enabled = tables.front().enabled.value_or(config.enabled);
    return config;
}

[[nodiscard]] Checked<StreamConfig> stream_config(const std::vector<StreamTable>& tables) {
    StreamConfig config;
    if (tables.empty()) {
        return config;
    }
    if (tables.size() > 1) {
        return std::unexpected(more_than_one("stream"));
    }
    if (const auto& quality = tables.front().quality; quality.has_value()) {
        const auto preset = parse_quality(*quality);
        if (!preset.has_value()) {
            return std::unexpected(
                std::format("stream quality \"{}\" isn't one of auto, low, balanced, high or max", *quality));
        }
        config.quality = *preset;
    }
    return config;
}

[[nodiscard]] Checked<MetricsConfig> metrics_config(const std::vector<MetricsTable>& tables) {
    MetricsConfig config;
    if (tables.empty()) {
        return config;
    }
    if (tables.size() > 1) {
        return std::unexpected(more_than_one("metrics"));
    }
    const auto& table = tables.front();
    if (table.history_days.has_value()) {
        if (*table.history_days == 0 || *table.history_days > max_metrics_history_days) {
            return std::unexpected(
                std::format("metrics history_days must be between 1 and {}", max_metrics_history_days));
        }
        config.history_days = *table.history_days;
    }
    config.enabled = table.enabled.value_or(config.enabled);
    return config;
}

// Only names of settings: a typo would otherwise unlock what it meant to
// lock, unnoticed.
[[nodiscard]] Checked<std::optional<std::vector<std::string>>> locked_keys(const std::vector<LockedTable>& tables) {
    if (tables.empty()) {
        return std::nullopt;
    }
    if (tables.size() > 1) {
        return std::unexpected(more_than_one("locked"));
    }
    const auto& keys = tables.front().keys;
    for (const auto& key : keys.value_or(std::vector<std::string>{})) {
        if (find_setting(key) == nullptr) {
            return std::unexpected(std::format("locked names \"{}\", which isn't a setting", key));
        }
    }
    return keys;
}

// Every setting locked: what a [[locked]] list that doesn't make sense means.
[[nodiscard]] std::vector<std::string> all_keys() {
    std::vector<std::string> keys;
    for (const auto& setting : settings()) {
        keys.emplace_back(setting.key);
    }
    return keys;
}

[[nodiscard]] bool blank(std::string_view text) {
    return text.find_first_not_of(" \t\r\n") == std::string_view::npos;
}

}  // namespace

const std::filesystem::path& machine_config_path() {
    return kConfigPath;
}

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
        config.locked = all_keys();
        return config;
    }
    if (!read->has_value()) {
        spdlog::info("config: no {}; using the defaults", kConfigPath.string());
        return config;
    }
    const std::string& text = **read;
    // glaze reads an empty buffer as an error; an empty file says nothing.
    if (blank(text)) {
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
        config.locked = all_keys();
        return config;
    }
    if (auto clipboard = clipboard_config(parsed.clipboard); clipboard.has_value()) {
        config.clipboard = *clipboard;
    } else {
        spdlog::error("config: {}; the clipboard is off until {} is fixed", clipboard.error(), kConfigPath.string());
        config.clipboard.mode = ClipboardMode::off;
    }
    if (auto files = files_config(parsed.files); files.has_value()) {
        config.files = *files;
    } else {
        spdlog::error("config: {}; file transfer is off until {} is fixed", files.error(), kConfigPath.string());
        config.files.enabled = false;
    }
    if (auto shell = shell_config(parsed.shell); shell.has_value()) {
        config.shell = *shell;
    } else {
        spdlog::error("config: {}; the shell is off until {} is fixed", shell.error(), kConfigPath.string());
        config.shell.enabled = false;
    }
    if (auto relay = relay_config(parsed.relay); relay.has_value()) {
        config.relay = *relay;
    } else {
        spdlog::error("config: {}; not connecting to any relay until {} is fixed", relay.error(), kConfigPath.string());
        config.relay.url.clear();
    }
    if (auto update = update_config(parsed.update); update.has_value()) {
        config.update = *update;
    } else {
        spdlog::error("config: {}; updates only notify until {} is fixed", update.error(), kConfigPath.string());
    }
    if (auto metrics = metrics_config(parsed.metrics); metrics.has_value()) {
        config.metrics = *metrics;
    } else {
        spdlog::error("config: {}; analytics use the defaults until {} is fixed", metrics.error(), kConfigPath.string());
    }
    if (auto audio = audio_config(parsed.audio); audio.has_value()) {
        config.audio = *audio;
    } else {
        spdlog::error("config: {}; sound is off until {} is fixed", audio.error(), kConfigPath.string());
        config.audio.enabled = false;
    }
    if (auto stream = stream_config(parsed.stream); stream.has_value()) {
        config.stream = *stream;
    } else {
        spdlog::error("config: {}; the stream is on auto until {} is fixed", stream.error(), kConfigPath.string());
    }
    if (auto locked = locked_keys(parsed.locked); locked.has_value()) {
        config.locked = *locked;
    } else {
        spdlog::error("config: {}; every setting is locked until {} is fixed", locked.error(), kConfigPath.string());
        config.locked = all_keys();
    }
    return config;
}

std::expected<MachineConfig, std::string> parse_machine_config(std::string_view text) {
    MachineConfig config;
    if (blank(text)) {
        return config;
    }
    ConfigFile parsed;
    const std::string buffer(text);
    if (const auto error = glz::read_toml(parsed, buffer); error) {
        return std::unexpected(std::format("the config doesn't parse ({})", glz::format_error(error, buffer)));
    }
    auto clipboard = clipboard_config(parsed.clipboard);
    auto files = files_config(parsed.files);
    auto shell = shell_config(parsed.shell);
    auto relay = relay_config(parsed.relay);
    auto update = update_config(parsed.update);
    auto metrics = metrics_config(parsed.metrics);
    auto audio = audio_config(parsed.audio);
    auto stream = stream_config(parsed.stream);
    auto locked = locked_keys(parsed.locked);
    for (const std::string* error :
         {clipboard ? nullptr : &clipboard.error(), files ? nullptr : &files.error(), shell ? nullptr : &shell.error(),
          relay ? nullptr : &relay.error(), update ? nullptr : &update.error(), metrics ? nullptr : &metrics.error(),
          audio ? nullptr : &audio.error(), stream ? nullptr : &stream.error(), locked ? nullptr : &locked.error()}) {
        if (error != nullptr) {
            return std::unexpected(*error);
        }
    }
    config.clipboard = *clipboard;
    config.files = *files;
    config.shell = *shell;
    config.relay = *relay;
    config.update = *update;
    config.metrics = *metrics;
    config.audio = *audio;
    config.stream = *stream;
    config.locked = *locked;
    return config;
}

namespace {

constexpr std::array<std::string_view, 3> kClipboardModes{"off", "pull", "sync"};
constexpr std::array<std::string_view, 3> kUpdatePolicies{"off", "notify", "auto"};
constexpr std::array<std::string_view, 2> kUpdateChannels{"stable", "beta"};

[[nodiscard]] std::string_view to_string(ClipboardMode mode) {
    return kClipboardModes.at(static_cast<std::size_t>(mode));
}

[[nodiscard]] std::string_view to_string(UpdatePolicy policy) {
    return kUpdatePolicies.at(static_cast<std::size_t>(policy));
}

// In the order the dashboard shows them, a table at a time.
constexpr std::array kSettings{
    Setting{.key = "clipboard.mode",
            .type = SettingType::choice,
            .description = "What viewers may do with this PC's clipboard: off, pull (paste in, and read it when "
                           "asked) or sync (pull, plus every copy here is sent to them).",
            .choices = kClipboardModes,
            .apply = SettingApply::live,
            .value = [](const MachineConfig& c) -> SettingValue { return std::string(to_string(c.clipboard.mode)); }},
    Setting{.key = "clipboard.max_size",
            .type = SettingType::integer,
            .description = "The most text taken or sent at once.",
            .min = 1,
            .max = ipc::max_clipboard_size,
            .unit = "bytes",
            .apply = SettingApply::live,
            .value = [](const MachineConfig& c) -> SettingValue { return std::uint64_t{c.clipboard.max_size}; }},
    Setting{.key = "clipboard.view_pull",
            .type = SettingType::boolean,
            .description = "Let view-only shares read the clipboard too. Pasting in always needs control.",
            .apply = SettingApply::live,
            .value = [](const MachineConfig& c) -> SettingValue { return c.clipboard.view_pull; }},
    Setting{.key = "clipboard.images",
            .type = SettingType::boolean,
            .description = "Pictures too, not only text: copied images go as PNG, up to 8 MB each, the same ways "
                           "text does.",
            .apply = SettingApply::live,
            .value = [](const MachineConfig& c) -> SettingValue { return c.clipboard.images; }},
    Setting{.key = "audio.enabled",
            .type = SettingType::boolean,
            .description = "Send what this PC plays to everyone watching, with the picture.",
            .apply = SettingApply::live,
            .value = [](const MachineConfig& c) -> SettingValue { return c.audio.enabled; }},
    Setting{.key = "stream.quality",
            .type = SettingType::choice,
            .description = "How the picture is encoded until a viewer with control picks otherwise: auto (follows "
                           "the connection), low (1 Mbps, 30 fps), balanced (4 Mbps), high (8 Mbps) or max (16 Mbps).",
            .choices = kQualityNames,
            .apply = SettingApply::live,
            .value = [](const MachineConfig& c) -> SettingValue { return std::string(to_string(c.stream.quality)); }},
    Setting{.key = "files.enabled",
            .type = SettingType::boolean,
            .description = "File transfer into and out of the drop folder, for control, dev and the owner.",
            .locked = true,
            .value = [](const MachineConfig& c) -> SettingValue { return c.files.enabled; }},
    Setting{.key = "files.drop_dir",
            .type = SettingType::text,
            .description = "Where files land and are fetched from. Empty: the signed-in user's Downloads\\Hawk.",
            .locked = true,
            .value = [](const MachineConfig& c) -> SettingValue { return c.files.drop_dir; }},
    Setting{.key = "files.max_size",
            .type = SettingType::integer,
            .description = "The largest file sent either way.",
            .min = 1,
            .max = max_file_size_limit,
            .unit = "bytes",
            .value = [](const MachineConfig& c) -> SettingValue { return c.files.max_size; }},
    Setting{.key = "shell.enabled",
            .type = SettingType::boolean,
            .description = "A shell for dev and owner shares, as the signed-in user.",
            .locked = true,
            .value = [](const MachineConfig& c) -> SettingValue { return c.shell.enabled; }},
    Setting{.key = "shell.command",
            .type = SettingType::text,
            .description = "What a shell runs.",
            .locked = true,
            .value = [](const MachineConfig& c) -> SettingValue { return c.shell.command; }},
    Setting{.key = "metrics.enabled",
            .type = SettingType::boolean,
            .description = "Sample this PC's health and keep its history here, for the Analytics tab.",
            .value = [](const MachineConfig& c) -> SettingValue { return c.metrics.enabled; }},
    Setting{.key = "metrics.history_days",
            .type = SettingType::integer,
            .description = "How long the history is kept.",
            .min = 1,
            .max = max_metrics_history_days,
            .unit = "days",
            .value = [](const MachineConfig& c) -> SettingValue { return std::uint64_t{c.metrics.history_days}; }},
    Setting{.key = "update.policy",
            .type = SettingType::choice,
            .description = "Updates: off, notify (the owner installs from the dashboard) or auto.",
            .choices = kUpdatePolicies,
            .value = [](const MachineConfig& c) -> SettingValue { return std::string(to_string(c.update.policy)); }},
    Setting{.key = "update.check_hours",
            .type = SettingType::integer,
            .description = "How often to look for one.",
            .min = 1,
            .max = 24 * 30,
            .unit = "hours",
            .value = [](const MachineConfig& c) -> SettingValue { return std::uint64_t{c.update.check_hours}; }},
    Setting{.key = "update.channel",
            .type = SettingType::choice,
            .description = "Stable or beta releases. Unset: the channel this build came from.",
            .choices = kUpdateChannels,
            .value = [](const MachineConfig& c) -> SettingValue { return c.update.channel; }},
    Setting{.key = "update.manifest_url",
            .type = SettingType::text,
            .description = "Where releases are announced. Empty: the feed this build came from.",
            .locked = true,
            .value = [](const MachineConfig& c) -> SettingValue { return c.update.manifest_url; }},
    Setting{.key = "update.public_key",
            .type = SettingType::text,
            .description = "The key releases are signed with. Empty: the one this build trusts.",
            .locked = true,
            .value = [](const MachineConfig& c) -> SettingValue { return c.update.public_key; }},
    Setting{.key = "relay.url",
            .type = SettingType::text,
            .description = "The relay this PC connects to.",
            .locked = true,
            .value = [](const MachineConfig& c) -> SettingValue { return c.relay.url; }},
};

}  // namespace

std::span<const Setting> settings() {
    return kSettings;
}

const Setting* find_setting(std::string_view key) {
    const auto found = std::ranges::find(kSettings, key, &Setting::key);
    return found == kSettings.end() ? nullptr : &*found;
}

bool is_locked(const MachineConfig& config, std::string_view key) {
    const Setting* setting = find_setting(key);
    if (setting == nullptr) {
        return true;
    }
    if (!config.locked.has_value()) {
        return setting->locked;
    }
    return std::ranges::find(*config.locked, key) != config.locked->end();
}

}  // namespace hawk::service
