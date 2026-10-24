// The machine's config as its Config tab shows it. The machine describes
// every setting (type, range, default, a line of help, whether it applies
// at once), so the tab renders whatever it's sent without knowing any of
// them; a new setting on the machine needs nothing here. What's checked
// here is only for a quick answer: the machine checks every change itself.

export type SettingValue = boolean | number | string;

export type SettingType = "boolean" | "integer" | "choice" | "text";

export interface ConfigSetting {
  // "clipboard.mode": the config file's table, a dot, the key.
  key: string;
  type: SettingType;
  description: string;
  // choice: the values it takes, as written in the file.
  choices: string[];
  // integer: the range, and what it counts ("bytes", "days").
  min: number;
  max: number;
  unit: string;
  // "live": takes effect at once; "restart": when the machine's service
  // next starts.
  apply: "live" | "restart";
  // Only someone at the machine can change it.
  locked: boolean;
  value: SettingValue;
  default: SettingValue;
}

export interface ConfigState {
  // Of the file the values came from; a change names it, and the machine
  // refuses one made against a file that changed since.
  version: string;
  settings: ConfigSetting[];
  // This viewer may change the unlocked settings (the owner).
  writable: boolean;
  // Answers a change that was saved.
  saved: boolean;
  // Why the config can't be shown, or why a change wasn't made.
  error: string;
}

const TYPES: readonly SettingType[] = ["boolean", "integer", "choice", "text"];

function isValue(value: unknown): value is SettingValue {
  return typeof value === "boolean" || typeof value === "number" || typeof value === "string";
}

function parseSetting(raw: unknown): ConfigSetting | null {
  if (typeof raw !== "object" || raw === null) return null;
  const { key, type, description, choices, min, max, unit, apply, locked, value, default: fallback } = raw as Record<
    string,
    unknown
  >;
  if (typeof key !== "string" || !TYPES.includes(type as SettingType) || !isValue(value) || !isValue(fallback)) {
    return null;
  }
  return {
    key,
    type: type as SettingType,
    description: typeof description === "string" ? description : "",
    choices: Array.isArray(choices) ? choices.filter((choice): choice is string => typeof choice === "string") : [],
    min: typeof min === "number" ? min : 0,
    max: typeof max === "number" ? max : 0,
    unit: typeof unit === "string" ? unit : "",
    apply: apply === "live" ? "live" : "restart",
    // Anything unclear is read-only: the machine would refuse it anyway.
    locked: locked !== false,
    value,
    default: fallback,
  };
}

// The config channel's message, as the machine sealed it; null for anything
// that isn't one.
export function parseConfig(header: unknown): ConfigState | null {
  if (typeof header !== "object" || header === null) return null;
  const { version, settings, writable, saved, error } = header as Record<string, unknown>;
  if (typeof version !== "string" || !Array.isArray(settings)) return null;
  return {
    version,
    settings: settings.flatMap((raw: unknown) => {
      const setting = parseSetting(raw);
      return setting === null ? [] : [setting];
    }),
    writable: writable === true,
    saved: saved === true,
    error: typeof error === "string" ? error : "",
  };
}

// Why `value` can't be `setting`'s, or null when it can.
export function checkValue(setting: ConfigSetting, value: SettingValue): string | null {
  switch (setting.type) {
    case "boolean":
      return typeof value === "boolean" ? null : "Must be on or off.";
    case "integer":
      return typeof value === "number" && Number.isSafeInteger(value) && value >= setting.min && value <= setting.max
        ? null
        : `A whole number from ${setting.min.toLocaleString()} to ${setting.max.toLocaleString()}.`;
    case "choice":
      return typeof value === "string" && setting.choices.includes(value)
        ? null
        : `One of ${setting.choices.join(", ")}.`;
    case "text":
      // A tab is all the machine takes below a space (nor DEL, which TOML
      // doesn't allow), and it counts the limit in UTF-8 bytes.
      return typeof value === "string" &&
        new TextEncoder().encode(value).length <= 1024 &&
        !/[\u0000-\u0008\u000a-\u001f\u007f]/.test(value)
        ? null
        : "One line, at most 1024 bytes.";
  }
}

// What an edited form changes: only the settings whose value differs from
// what the machine has.
export function changesFrom(
  settings: readonly ConfigSetting[],
  draft: Readonly<Record<string, SettingValue>>,
): Record<string, SettingValue> {
  const changes: Record<string, SettingValue> = {};
  for (const setting of settings) {
    const value = draft[setting.key];
    if (value !== undefined && value !== setting.value && !setting.locked) changes[setting.key] = value;
  }
  return changes;
}

// The settings by the config file's table, in the order the machine sent
// them: [["clipboard", [...]], ["files", [...]]].
export function groupByTable(settings: readonly ConfigSetting[]): [string, ConfigSetting[]][] {
  const groups = new Map<string, ConfigSetting[]>();
  for (const setting of settings) {
    const table = setting.key.split(".")[0] ?? setting.key;
    const group = groups.get(table);
    if (group === undefined) groups.set(table, [setting]);
    else group.push(setting);
  }
  return [...groups];
}

// The part of the key after the table: "mode" for "clipboard.mode".
export function settingName(setting: ConfigSetting): string {
  const dot = setting.key.indexOf(".");
  return dot < 0 ? setting.key : setting.key.slice(dot + 1);
}

// A value as the form shows it in passing: "on", "262,144 bytes", "(empty)".
export function formatValue(setting: ConfigSetting, value: SettingValue): string {
  if (typeof value === "boolean") return value ? "on" : "off";
  if (typeof value === "number") return `${value.toLocaleString()}${setting.unit === "" ? "" : ` ${setting.unit}`}`;
  return value === "" ? "(empty)" : value;
}
