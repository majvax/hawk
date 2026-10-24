#pragma once

#include "config.hpp"

#include <expected>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>

// The machine's config as the dashboard sees and changes it, over the
// sealed config channel (e2e.hpp). The machine is the authority: every
// change is checked here against the schema (config.hpp), the [[locked]]
// list and the same rules the service starts with, whatever the dashboard
// already checked, and written over the file in one piece. Comments and
// everything a change doesn't touch stay as they were.
namespace hawk::service {

// The config file as it is on disk now.
struct ConfigSnapshot {
    // Of the file's text: a change names the one it was made against, so
    // an edit made on the machine meanwhile is never overwritten unseen.
    std::string   version;
    std::string   text;
    MachineConfig config;
};

// The file, strictly parsed. A file that isn't the administrators', or
// that has something wrong with it, is for someone at the machine to fix.
[[nodiscard]] std::expected<ConfigSnapshot, std::string> read_config_snapshot();

// The version a text has.
[[nodiscard]] std::string config_version(std::string_view text);

using ConfigChanges = std::map<std::string, SettingValue, std::less<>>;

// What `text` becomes with `changes`: each one a setting that isn't locked,
// of its type and within its range, and the whole result one the service
// would start with as written. Otherwise why not, in a sentence.
[[nodiscard]] std::expected<std::string, std::string> edit_config_text(std::string_view text,
                                                                       const ConfigChanges& changes);

// Replaces the file with `text` (a temporary file renamed over it).
[[nodiscard]] std::expected<void, std::string> save_config_text(std::string_view text);

// A change a viewer asked for: the version it saw, and the new values.
struct ConfigChange {
    std::string   version;
    ConfigChanges changes;
};

[[nodiscard]] std::optional<ConfigChange> parse_config_change(std::string_view json);

// The header of the config channel's one message: the schema with each
// setting's value and default, whether this viewer may change them, and
// `error` (why the file can't be shown, or why a change was refused).
// `saved` answers a change that was written.
[[nodiscard]] std::string config_reply(const ConfigSnapshot* snapshot, bool writable, bool saved,
                                       std::string_view error);

}  // namespace hawk::service
