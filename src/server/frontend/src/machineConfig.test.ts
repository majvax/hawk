import { describe, expect, test } from "bun:test";
import {
  type ConfigSetting,
  changesFrom,
  checkValue,
  formatValue,
  groupByTable,
  parseConfig,
  settingName,
} from "./machineConfig.js";

function setting(overrides: Partial<ConfigSetting> = {}): ConfigSetting {
  return {
    key: "clipboard.mode",
    type: "choice",
    description: "",
    choices: ["off", "pull", "sync"],
    min: 0,
    max: 0,
    unit: "",
    apply: "live",
    locked: false,
    value: "pull",
    default: "pull",
    ...overrides,
  };
}

describe("parseConfig", () => {
  test("reads what the machine sends", () => {
    const state = parseConfig({
      version: "abc",
      writable: true,
      saved: false,
      error: "",
      settings: [
        {
          key: "clipboard.max_size",
          type: "integer",
          description: "The most text.",
          choices: [],
          min: 1,
          max: 262144,
          unit: "bytes",
          apply: "live",
          locked: false,
          value: 1000,
          default: 262144,
        },
      ],
    });
    expect(state?.version).toBe("abc");
    expect(state?.writable).toBe(true);
    expect(state?.settings).toHaveLength(1);
    expect(state?.settings[0]?.max).toBe(262144);
    expect(state?.settings[0]?.locked).toBe(false);
  });

  test("drops settings it can't render, and reads unclear ones as locked", () => {
    const state = parseConfig({
      version: "v",
      settings: [
        { key: "a.b", type: "colour", value: 1, default: 1 },
        { key: "a.c", type: "boolean", value: { nested: true }, default: false },
        { key: "a.d", type: "boolean", value: true, default: false },
      ],
    });
    expect(state?.settings.map((s) => s.key)).toEqual(["a.d"]);
    expect(state?.settings[0]?.locked).toBe(true);
    expect(state?.settings[0]?.apply).toBe("restart");
    expect(state?.writable).toBe(false);
  });

  test("refuses what isn't a config message", () => {
    expect(parseConfig(null)).toBeNull();
    expect(parseConfig({ settings: [] })).toBeNull();
    expect(parseConfig({ version: "v", settings: {} })).toBeNull();
  });
});

describe("checkValue", () => {
  test("choices", () => {
    expect(checkValue(setting(), "sync")).toBeNull();
    expect(checkValue(setting(), "all")).toContain("off, pull, sync");
    expect(checkValue(setting(), true)).not.toBeNull();
  });

  test("whole numbers within the range", () => {
    const size = setting({ type: "integer", min: 1, max: 100, value: 5 });
    expect(checkValue(size, 1)).toBeNull();
    expect(checkValue(size, 100)).toBeNull();
    expect(checkValue(size, 0)).not.toBeNull();
    expect(checkValue(size, 101)).not.toBeNull();
    expect(checkValue(size, 2.5)).not.toBeNull();
    expect(checkValue(size, Number.NaN)).not.toBeNull();
    expect(checkValue(size, "5")).not.toBeNull();
  });

  test("on or off", () => {
    const flag = setting({ type: "boolean", value: false });
    expect(checkValue(flag, true)).toBeNull();
    expect(checkValue(flag, "true")).not.toBeNull();
  });

  test("one line of text", () => {
    const text = setting({ type: "text", value: "" });
    expect(checkValue(text, String.raw`C:\Drop`)).toBeNull();
    expect(checkValue(text, "a\tb")).toBeNull();
    expect(checkValue(text, "two\nlines")).not.toBeNull();
    expect(checkValue(text, "x".repeat(1025))).not.toBeNull();
  });
});

describe("changesFrom", () => {
  test("only what differs, and never a locked setting", () => {
    const settings = [
      setting(),
      setting({ key: "clipboard.view_pull", type: "boolean", value: false }),
      setting({ key: "shell.enabled", type: "boolean", value: false, locked: true }),
    ];
    expect(changesFrom(settings, { "clipboard.mode": "pull", "clipboard.view_pull": true, "shell.enabled": true })).toEqual(
      { "clipboard.view_pull": true },
    );
    expect(changesFrom(settings, {})).toEqual({});
  });
});

describe("layout", () => {
  test("groups by table in the order sent", () => {
    const groups = groupByTable([
      setting({ key: "clipboard.mode" }),
      setting({ key: "audio.enabled" }),
      setting({ key: "clipboard.view_pull" }),
    ]);
    expect(groups.map(([table, settings]) => [table, settings.map(settingName)])).toEqual([
      ["clipboard", ["mode", "view_pull"]],
      ["audio", ["enabled"]],
    ]);
  });

  test("formats values in passing", () => {
    expect(formatValue(setting({ type: "boolean" }), true)).toBe("on");
    expect(formatValue(setting({ type: "integer", unit: "days" }), 7)).toBe("7 days");
    expect(formatValue(setting({ type: "text" }), "")).toBe("(empty)");
  });
});

describe("edge cases", () => {
  test("text is counted in UTF-8 bytes, as the machine counts it", () => {
    const text = setting({ type: "text", value: "" });
    expect(checkValue(text, "x".repeat(1024))).toBeNull();
    // 512 characters, 1024 bytes: fits.
    expect(checkValue(text, "é".repeat(512))).toBeNull();
    // 600 characters, 1200 bytes: the machine would refuse it.
    expect(checkValue(text, "é".repeat(600))).not.toBeNull();
    expect(checkValue(text, "😀".repeat(257))).not.toBeNull();
  });

  test("text refuses every control character but a tab", () => {
    const text = setting({ type: "text", value: "" });
    for (const c of ["\0", "\r", "\n", "\u001b", "\u007f", "\u000b", "\u000c"]) {
      expect(checkValue(text, `a${c}b`)).not.toBeNull();
    }
    expect(checkValue(text, "")).toBeNull();
    expect(checkValue(text, 'quote " and \ backslash')).toBeNull();
    expect(checkValue(text, 5)).not.toBeNull();
  });

  test("integers: unsafe, negative and infinite", () => {
    const big = setting({ type: "integer", min: 1, max: Number.MAX_SAFE_INTEGER, value: 1 });
    expect(checkValue(big, Number.MAX_SAFE_INTEGER)).toBeNull();
    expect(checkValue(big, Number.MAX_SAFE_INTEGER + 1)).not.toBeNull();
    expect(checkValue(big, -1)).not.toBeNull();
    expect(checkValue(big, Number.POSITIVE_INFINITY)).not.toBeNull();
  });

  test("a choice is matched exactly", () => {
    expect(checkValue(setting(), "SYNC")).not.toBeNull();
    expect(checkValue(setting(), "")).not.toBeNull();
    expect(checkValue(setting({ choices: [] }), "off")).not.toBeNull();
  });

  test("a half-typed number is a change, so the form shows it's invalid", () => {
    const size = setting({ key: "clipboard.max_size", type: "integer", min: 1, max: 10, value: 5 });
    const changes = changesFrom([size], { "clipboard.max_size": Number.NaN });
    expect(Object.keys(changes)).toEqual(["clipboard.max_size"]);
    expect(checkValue(size, changes["clipboard.max_size"] as number)).not.toBeNull();
    // Typed back to what the machine has: no change.
    expect(changesFrom([size], { "clipboard.max_size": 5 })).toEqual({});
  });

  test("a draft for a setting the machine no longer sends is dropped", () => {
    expect(changesFrom([setting()], { "gone.key": true })).toEqual({});
  });

  test("parseConfig keeps the machine's answer and error, and only string choices", () => {
    const state = parseConfig({
      version: "v2",
      saved: true,
      writable: "yes",
      error: "the config changed on the machine",
      settings: [{ key: "a.b", type: "choice", choices: ["x", 1, null, "y"], locked: "false", value: "x", default: "y" }],
    });
    expect(state?.saved).toBe(true);
    // Only a real true makes it writable, and only a real false unlocks.
    expect(state?.writable).toBe(false);
    expect(state?.settings[0]?.locked).toBe(true);
    expect(state?.settings[0]?.choices).toEqual(["x", "y"]);
    expect(state?.error).toBe("the config changed on the machine");
    expect(parseConfig({ version: "v", settings: [], error: 5 })?.error).toBe("");
    expect(parseConfig({ version: 1, settings: [] })).toBeNull();
    expect(parseConfig("text")).toBeNull();
  });

  test("a key without a table is its own group and name", () => {
    const flat = setting({ key: "flat" });
    expect(groupByTable([flat]).map(([table]) => table)).toEqual(["flat"]);
    expect(settingName(flat)).toBe("flat");
    expect(settingName(setting({ key: "a.b.c" }))).toBe("b.c");
  });
});
