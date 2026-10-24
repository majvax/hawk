#pragma once

#include "common/clipboard_pipe.hpp"
#include "quality.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

// The machine's own settings, from C:\ProgramData\HawkService\config.toml.
// Read at startup. The owner can change the unlocked ones from the
// dashboard too (config_sync.hpp), sealed end to end; anything that widens
// what the machine allows is locked by default, so only someone at the
// machine can change it.
namespace hawk::service {

// What viewers may do with the machine's clipboard.
enum class ClipboardMode : std::uint8_t {
    off,   // nothing, in either direction
    pull,  // paste into the machine; read it only when a viewer asks
    sync,  // pull, plus every copy on the machine is pushed to viewers
};

struct ClipboardConfig {
    ClipboardMode mode = ClipboardMode::pull;
    // Most UTF-8 bytes of text taken or sent at once; capped at
    // ipc::max_clipboard_size.
    std::uint32_t max_size = ipc::max_clipboard_size;
    // Whether view-only shares may read the clipboard too. Pasting into the
    // machine always needs control.
    bool view_pull = false;
};

// The most a single file may be, either way, unless the config says less.
inline constexpr std::uint64_t default_max_file_size = 1024ULL * 1024 * 1024;  // 1 GiB
// What the config may raise it to.
inline constexpr std::uint64_t max_file_size_limit = 64ULL * 1024 * 1024 * 1024;

struct FilesConfig {
    // Off unless the machine's owner turns it on.
    bool enabled = false;
    // Where uploads land and downloads come from. Empty means the logged-on
    // user's Downloads\Hawk; otherwise a path, in which that user's
    // environment variables (%USERPROFILE%) are expanded.
    std::string drop_dir;
    std::uint64_t max_size = default_max_file_size;
};

struct ShellConfig {
    // Off unless the machine's owner turns it on.
    bool enabled = false;
    // What a shell runs, as the logged-on user (never SYSTEM).
    std::string command = "powershell.exe -NoLogo";
};

struct RelayConfig {
    // Where the relay is. The installer writes it; the default is a relay
    // on this same PC, for development.
    std::string url = "wss://127.0.0.1:8080/v1/ws";
};

// What the updater (hawk-setup.exe beside the service) may do on its own.
enum class UpdatePolicy : std::uint8_t {
    off,        // never look
    notify,     // look, and tell the owner in the dashboard; install when they say
    automatic,  // look, and install
};

struct UpdateConfig {
    UpdatePolicy  policy = UpdatePolicy::notify;
    std::uint32_t check_hours = 24;
    // Read by hawk-setup, not the service: where releases are announced,
    // the key they're signed with, and stable or beta. Empty means what
    // the build was made with.
    std::string manifest_url;
    std::string public_key;
    std::string channel;
};

// [[metrics]]: the machine samples its own health (CPU, memory, disks,
// network, GPU) and keeps the history here, never on the relay; viewers
// the owner allowed analytics read it over the end-to-end encrypted
// channel. On by default: nothing leaves the machine unless asked for.
inline constexpr std::uint32_t default_metrics_history_days = 7;
inline constexpr std::uint32_t max_metrics_history_days = 90;

struct MetricsConfig {
    bool          enabled = true;
    std::uint32_t history_days = default_metrics_history_days;
};

// [[audio]]: what the machine plays goes to its viewers with the picture,
// for anyone who may watch. On by default; off keeps the room's sound in it.
struct AudioConfig {
    bool enabled = true;
};

// [[stream]]: how the picture is encoded, until a viewer with control picks
// another preset for the stream (quality.hpp).
struct StreamConfig {
    QualityPreset quality = QualityPreset::automatic;
};

struct MachineConfig {
    StreamConfig    stream;
    AudioConfig     audio;
    ClipboardConfig clipboard;
    FilesConfig     files;
    ShellConfig     shell;
    RelayConfig     relay;
    UpdateConfig    update;
    MetricsConfig   metrics;
    // [[locked]] keys: the settings the dashboard may only read. nullopt
    // means each setting's own default (Setting::locked).
    std::optional<std::vector<std::string>> locked;
};

// The config, with defaults for what it leaves out (or for a missing file).
// A file that doesn't parse, or says something that makes no sense, is
// logged and turns the clipboard off: a typo should never open up more
// than the defaults would.
//
//   [[stream]]
//   quality = "auto"     # auto | low | balanced | high | max
//
//   [[audio]]
//   enabled = true
//
//   [[clipboard]]
//   mode = "pull"        # off | pull | sync
//   max_size = 262144    # bytes, at most 262144
//   view_pull = false
//
//   [[files]]
//   enabled = false
//   drop_dir = ""        # empty: %USERPROFILE%\Downloads\Hawk
//   max_size = 1073741824
//
//   [[shell]]
//   enabled = false
//   command = "powershell.exe -NoLogo"
//
//   [[relay]]
//   url = "wss://relay.example.com/v1/ws"
//
//   [[update]]
//   policy = "notify"    # off | notify | auto
//   check_hours = 24
//   channel = "stable"   # stable | beta
//   manifest_url = ""    # empty: the release feed this build came from
//   public_key = ""      # empty: the key this build trusts
//
//   [[locked]]
//   keys = ["shell.enabled", "relay.url"]   # replaces the default list
//
// A relay url that doesn't parse leaves the service unconnected rather
// than guessing; an [[update]] table that doesn't parse falls back to
// notify, which never installs anything by itself.
[[nodiscard]] MachineConfig load_machine_config();

// Where it is.
[[nodiscard]] const std::filesystem::path& machine_config_path();

// The same rules, strictly: the first thing wrong with `text`, rather than
// the defaults for that part. For checking a change before it's written.
[[nodiscard]] std::expected<MachineConfig, std::string> parse_machine_config(std::string_view text);

// --- Schema ------------------------------------------------------------------
//
// Every setting the dashboard shows, described so it can render a form
// without knowing any of them: a new setting is its struct member, its
// table's parser above, and one entry in settings().

enum class SettingType : std::uint8_t { boolean, integer, choice, text };

// When a change takes effect: at once, or when the service next starts.
enum class SettingApply : std::uint8_t { live, restart };

// A setting's value, as the dashboard sends and sees it.
using SettingValue = std::variant<bool, std::uint64_t, std::string>;

struct Setting {
    std::string_view                  key{};  // "clipboard.mode": the table, a dot, the key
    SettingType                       type = SettingType::text;
    std::string_view                  description{};
    std::span<const std::string_view> choices{};  // choice: as written in the file
    std::uint64_t                     min = 0;  // integer
    std::uint64_t                     max = 0;
    std::string_view                  unit{};     // integer: "bytes", "days", "hours"
    SettingApply                      apply = SettingApply::restart;
    // Read-only from the dashboard unless [[locked]] says otherwise: on
    // for anything that widens what the machine allows.
    bool                              locked = false;
    SettingValue (*value)(const MachineConfig&) = nullptr;
};

[[nodiscard]] std::span<const Setting> settings();
[[nodiscard]] const Setting*           find_setting(std::string_view key);

// Whether the dashboard may only read `key` under `config`'s [[locked]]
// list. True for a key that isn't a setting.
[[nodiscard]] bool is_locked(const MachineConfig& config, std::string_view key);

}  // namespace hawk::service
