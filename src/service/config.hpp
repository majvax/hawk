#pragma once

#include "common/clipboard_pipe.hpp"

#include <cstdint>
#include <string>

// The machine's own settings, from C:\ProgramData\HawkService\config.toml.
// They're set on the machine, never through the relay, so nobody holding an
// account there can widen what the machine allows. Read once at startup.
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

struct MachineConfig {
    ClipboardConfig clipboard;
    FilesConfig     files;
    ShellConfig     shell;
    RelayConfig     relay;
    UpdateConfig    update;
    MetricsConfig   metrics;
};

// The config, with defaults for what it leaves out (or for a missing file).
// A file that doesn't parse, or says something that makes no sense, is
// logged and turns the clipboard off: a typo should never open up more
// than the defaults would.
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
// A relay url that doesn't parse leaves the service unconnected rather
// than guessing; an [[update]] table that doesn't parse falls back to
// notify, which never installs anything by itself.
[[nodiscard]] MachineConfig load_machine_config();

}  // namespace hawk::service
