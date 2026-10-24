#include "config_sync.hpp"

#include "crypto.hpp"
#include "win_util.hpp"

#include <windows.h>

#include <glaze/glaze.hpp>

#include <algorithm>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <vector>

namespace hawk::service {

namespace {

// What the dashboard is shown of one setting.
struct SettingView {
    std::string              key;
    std::string              type;
    std::string              description;
    std::vector<std::string> choices;
    std::uint64_t            min = 0;
    std::uint64_t            max = 0;
    std::string              unit;
    std::string              apply;
    bool                     locked = false;
    SettingValue             value;
    SettingValue             default_value;
};

struct ConfigReply {
    std::string              version;
    std::vector<SettingView> settings;
    bool                     writable = false;
    bool                     saved = false;
    std::string              error;
};

// Longest text value taken: a path or a command line.
constexpr std::size_t kMaxText = 1024;

[[nodiscard]] std::string_view type_name(SettingType type) {
    switch (type) {
        case SettingType::boolean:
            return "boolean";
        case SettingType::integer:
            return "integer";
        case SettingType::choice:
            return "choice";
        case SettingType::text:
            return "text";
    }
    return "text";
}

[[nodiscard]] std::string_view trim(std::string_view text) {
    const auto first = text.find_first_not_of(" \t");
    if (first == std::string_view::npos) {
        return {};
    }
    return text.substr(first, text.find_last_not_of(" \t") - first + 1);
}

// "clipboard" for "[[clipboard]]" (and "[[ clipboard ]] # note"), empty for
// any other line.
[[nodiscard]] std::string_view table_name(std::string_view line) {
    if (!line.starts_with("[[")) {
        return {};
    }
    const auto end = line.find("]]");
    return end == std::string_view::npos ? std::string_view{} : trim(line.substr(2, end - 2));
}

// Whether a line (without its indent) sets `key`.
[[nodiscard]] bool sets_key(std::string_view line, std::string_view key) {
    if (!line.starts_with(key)) {
        return false;
    }
    return trim(line.substr(key.size())).starts_with('=');
}

// Where the value on a `key = value  # note` line ends, so the note stays.
[[nodiscard]] std::expected<std::size_t, std::string> value_end(std::string_view line, std::size_t start) {
    const auto rest = line.substr(start);
    if (rest.starts_with(R"(""")") || rest.starts_with("'''")) {
        return std::unexpected(std::string("it's a multi-line string"));
    }
    if (rest.starts_with('"')) {
        for (std::size_t i = 1; i < rest.size(); ++i) {
            if (rest[i] == '\\') {
                ++i;
            } else if (rest[i] == '"') {
                return start + i + 1;
            }
        }
        return std::unexpected(std::string("its string isn't closed"));
    }
    if (rest.starts_with('\'')) {
        const auto close = rest.find('\'', 1);
        if (close == std::string_view::npos) {
            return std::unexpected(std::string("its string isn't closed"));
        }
        return start + close + 1;
    }
    if (rest.starts_with('[') || rest.starts_with('{')) {
        return std::unexpected(std::string("it isn't a single value"));
    }
    const auto comment = rest.find('#');
    return start + trim(rest.substr(0, comment)).size();
}

// Sets `key` in the one [[table]] to `literal`, keeping every other line
// (and the note after the value) as it was. Adds the key under the table's
// header, or the table at the end, when the file doesn't have it yet.
[[nodiscard]] std::expected<std::string, std::string> set_value(std::string_view text, std::string_view table,
                                                                std::string_view key, std::string_view literal) {
    const std::string_view newline = text.find("\r\n") != std::string_view::npos ? "\r\n" : "\n";
    // Each line with its line break, if it has one.
    std::vector<std::string_view> lines;
    for (std::size_t at = 0; at < text.size();) {
        const auto end = text.find('\n', at);
        const auto next = end == std::string_view::npos ? text.size() : end + 1;
        lines.push_back(text.substr(at, next - at));
        at = next;
    }
    const auto content = [](std::string_view line) {
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
            line.remove_suffix(1);
        }
        return line;
    };

    std::optional<std::size_t> header;
    std::optional<std::size_t> found;
    for (std::size_t i = 0; i < lines.size(); ++i) {
        const auto line = trim(content(lines[i]));
        if (line.starts_with('[')) {
            if (header.has_value()) {
                break;
            }
            if (table_name(line) == table) {
                header = i;
            }
        } else if (header.has_value() && sets_key(line, key)) {
            found = i;
            break;
        }
    }

    std::string out;
    out.reserve(text.size() + table.size() + key.size() + literal.size() + 16);
    if (!header.has_value()) {
        out = text;
        if (!out.empty() && !out.ends_with('\n')) {
            out += newline;
        }
        out += std::format("{}[[{}]]{}{} = {}{}", out.empty() ? "" : newline, table, newline, key, literal, newline);
        return out;
    }
    for (std::size_t i = 0; i < lines.size(); ++i) {
        if (found == i) {
            const auto line = content(lines[i]);
            auto       start = line.find_first_not_of(" \t", line.find('=') + 1);
            if (start == std::string_view::npos) {
                start = line.size();
            }
            const auto stop = value_end(line, start);
            if (!stop.has_value()) {
                return std::unexpected(std::format("{}.{} can't be changed from here: {}", table, key, stop.error()));
            }
            out += line.substr(0, start);
            out += literal;
            out += line.substr(*stop);
            out += lines[i].substr(line.size());
            continue;
        }
        out += lines[i];
        if (header == i && !found.has_value()) {
            if (!lines[i].ends_with('\n')) {
                out += newline;
            }
            out += std::format("{} = {}{}", key, literal, newline);
        }
    }
    return out;
}

// A TOML basic string.
[[nodiscard]] std::string toml_string(std::string_view text) {
    std::string out = "\"";
    for (const char c : text) {
        switch (c) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                out += c;
        }
    }
    out += '"';
    return out;
}

// The value as it's written in the file, once it's checked against the
// setting; otherwise why it can't be.
[[nodiscard]] std::expected<std::string, std::string> literal_for(const Setting& setting, const SettingValue& value) {
    switch (setting.type) {
        case SettingType::boolean:
            if (const auto* flag = std::get_if<bool>(&value); flag != nullptr) {
                return std::string(*flag ? "true" : "false");
            }
            return std::unexpected(std::format("{} is on or off", setting.key));
        case SettingType::integer:
            if (const auto* number = std::get_if<std::uint64_t>(&value);
                number != nullptr && *number >= setting.min && *number <= setting.max) {
                return std::to_string(*number);
            }
            return std::unexpected(std::format("{} must be a whole number from {} to {}", setting.key, setting.min,
                                               setting.max));
        case SettingType::choice:
            if (const auto* text = std::get_if<std::string>(&value);
                text != nullptr && std::ranges::find(setting.choices, *text) != setting.choices.end()) {
                return toml_string(*text);
            }
            {
                std::string choices;
                for (const auto choice : setting.choices) {
                    choices += choices.empty() ? "" : ", ";
                    choices += choice;
                }
                return std::unexpected(std::format("{} must be one of {}", setting.key, choices));
            }
        case SettingType::text:
            if (const auto* text = std::get_if<std::string>(&value); text != nullptr && text->size() <= kMaxText &&
                // Nor DEL: TOML allows no control character but a tab.
                std::ranges::none_of(*text, [](char c) {
                    return (static_cast<unsigned char>(c) < 0x20 && c != '\t') || c == '\x7f';
                })) {
                return toml_string(*text);
            }
            return std::unexpected(std::format("{} must be one line of at most {} bytes", setting.key, kMaxText));
    }
    return std::unexpected(std::format("{} can't be set", setting.key));
}

[[nodiscard]] SettingView view_of(const Setting& setting, const MachineConfig& config) {
    SettingView view{.key = std::string(setting.key),
                     .type = std::string(type_name(setting.type)),
                     .description = std::string(setting.description),
                     .choices = {},
                     .min = setting.min,
                     .max = setting.max,
                     .unit = std::string(setting.unit),
                     .apply = setting.apply == SettingApply::live ? "live" : "restart",
                     .locked = is_locked(config, setting.key),
                     .value = setting.value(config),
                     .default_value = setting.value(MachineConfig{})};
    for (const auto choice : setting.choices) {
        view.choices.emplace_back(choice);
    }
    return view;
}

}  // namespace

}  // namespace hawk::service

template <>
struct glz::meta<hawk::service::SettingView> {
    using T                     = hawk::service::SettingView;
    static constexpr auto value = object("key", &T::key, "type", &T::type, "description", &T::description, "choices",
                                         &T::choices, "min", &T::min, "max", &T::max, "unit", &T::unit, "apply",
                                         &T::apply, "locked", &T::locked, "value", &T::value, "default",
                                         &T::default_value);
};

template <>
struct glz::meta<hawk::service::ConfigReply> {
    using T                     = hawk::service::ConfigReply;
    static constexpr auto value = object("version", &T::version, "settings", &T::settings, "writable", &T::writable,
                                         "saved", &T::saved, "error", &T::error);
};

template <>
struct glz::meta<hawk::service::ConfigChange> {
    using T                     = hawk::service::ConfigChange;
    static constexpr auto value = object("version", &T::version, "changes", &T::changes);
};

namespace hawk::service {

std::string config_version(std::string_view text) {
    const auto digest = crypto::sha256(crypto::as_bytes(text));
    return crypto::base64_encode(std::span(digest).first(16));
}

std::expected<ConfigSnapshot, std::string> read_config_snapshot() {
    const auto read = win::read_protected_file(machine_config_path());
    if (!read.has_value()) {
        return std::unexpected(std::format("the machine ignores its config file ({}); fix it there", read.error()));
    }
    std::string text = read->value_or("");
    auto        config = parse_machine_config(text);
    if (!config.has_value()) {
        return std::unexpected(std::format("{}; fix it on the machine", config.error()));
    }
    return ConfigSnapshot{.version = config_version(text), .text = std::move(text), .config = std::move(*config)};
}

std::expected<std::string, std::string> edit_config_text(std::string_view text, const ConfigChanges& changes) {
    const auto current = parse_machine_config(text);
    if (!current.has_value()) {
        return std::unexpected(std::format("{}; fix it on the machine", current.error()));
    }
    if (changes.empty()) {
        return std::unexpected(std::string("nothing to change"));
    }
    std::string edited(text);
    for (const auto& [key, value] : changes) {
        const Setting* setting = find_setting(key);
        if (setting == nullptr) {
            return std::unexpected(std::format("there's no setting {}", key));
        }
        if (is_locked(*current, key)) {
            return std::unexpected(std::format("{} is locked: only someone at the machine can change it", key));
        }
        const auto literal = literal_for(*setting, value);
        if (!literal.has_value()) {
            return std::unexpected(literal.error());
        }
        const auto dot = key.find('.');
        auto       next = set_value(edited, std::string_view(key).substr(0, dot), std::string_view(key).substr(dot + 1),
                                    *literal);
        if (!next.has_value()) {
            return std::unexpected(next.error());
        }
        edited = std::move(*next);
    }
    // The same rules the service starts with, on the whole file.
    const auto result = parse_machine_config(edited);
    if (!result.has_value()) {
        return std::unexpected(result.error());
    }
    // And each change landed where it was meant to, not somewhere the
    // line-by-line edit misread (a key spelled with quotes, say).
    for (const auto& [key, value] : changes) {
        if (find_setting(key)->value(*result) != value) {
            return std::unexpected(std::format("{} is written in a way this can't edit; change it on the machine", key));
        }
    }
    // And nothing else moved: a line that only looks like a header or a
    // key (inside a multi-line string, say) would otherwise be rewritten,
    // locked setting or not.
    for (const auto& setting : settings()) {
        if (!changes.contains(setting.key) && setting.value(*result) != setting.value(*current)) {
            return std::unexpected(std::format("{} is written in a way this can't edit; change it on the machine",
                                               changes.begin()->first));
        }
    }
    if (result->locked != current->locked) {
        return std::unexpected(std::string("the [[locked]] list would change; change it on the machine"));
    }
    return edited;
}

std::expected<void, std::string> save_config_text(std::string_view text) {
    const auto& path = machine_config_path();
    auto        temporary = path;
    temporary += L".tmp";
    // A fresh file, never one left there (or a link planted there): written
    // and flushed to disk before it takes the config's place, so a power
    // cut leaves the old file or the new one, never an empty one.
    DeleteFileW(temporary.c_str());
    {
        win::UniqueHandle file(CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                           FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!file) {
            return std::unexpected(std::format("couldn't write the new config (error {})", GetLastError()));
        }
        DWORD written = 0;
        if (text.size() > 0xFFFFFFFFU ||
            WriteFile(file.get(), text.data(), static_cast<DWORD>(text.size()), &written, nullptr) == FALSE ||
            written != text.size() || FlushFileBuffers(file.get()) == FALSE) {
            const DWORD error = GetLastError();
            file.reset();
            DeleteFileW(temporary.c_str());
            return std::unexpected(std::format("couldn't write the new config (error {})", error));
        }
    }
    if (MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == FALSE) {
        const DWORD error = GetLastError();
        DeleteFileW(temporary.c_str());
        return std::unexpected(std::format("couldn't replace the config (error {})", error));
    }
    return {};
}

std::optional<ConfigChange> parse_config_change(std::string_view json) {
    ConfigChange change;
    if (glz::read_json(change, json)) {
        return std::nullopt;
    }
    return change;
}

std::string config_reply(const ConfigSnapshot* snapshot, bool writable, bool saved, std::string_view error) {
    ConfigReply reply{.version = {}, .settings = {}, .writable = writable, .saved = saved, .error = std::string(error)};
    if (snapshot != nullptr) {
        reply.version = snapshot->version;
        for (const auto& setting : settings()) {
            reply.settings.push_back(view_of(setting, snapshot->config));
        }
    } else {
        reply.writable = false;
    }
    auto json = glz::write_json(reply);
    return json.has_value() ? *json : std::string("{}");
}

}  // namespace hawk::service
