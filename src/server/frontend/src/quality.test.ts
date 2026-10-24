import { describe, expect, test } from "bun:test";
import { QUALITY_PRESETS, describeQuality, isQualityPreset, parseQuality, qualityLabel } from "./quality.js";

describe("parseQuality", () => {
  test("takes what the machine sends", () => {
    expect(parseQuality({ preset: "auto", bitrate: 3_200_000, fps: 60 })).toEqual({
      preset: "auto",
      bitrate: 3_200_000,
      fps: 60,
    });
  });

  test("refuses presets there aren't, and numbers that make no sense", () => {
    expect(parseQuality({ preset: "ultra", bitrate: 1, fps: 60 })).toBeNull();
    expect(parseQuality({ preset: "low", bitrate: "1", fps: 30 })).toBeNull();
    expect(parseQuality({ preset: "low", bitrate: 0, fps: 30 })).toBeNull();
    expect(parseQuality({ preset: "low", bitrate: 1_000_000, fps: Number.NaN })).toBeNull();
  });
});

describe("labels", () => {
  test("every preset has one, in the menu's order", () => {
    expect(QUALITY_PRESETS.map((entry) => entry.preset)).toEqual(["auto", "low", "balanced", "high", "max"]);
    expect(qualityLabel("balanced")).toBe("Balanced");
    expect(isQualityPreset("max")).toBe(true);
    expect(isQualityPreset("Max")).toBe(false);
  });

  test("Auto shows its target, a fixed preset its bitrate", () => {
    expect(describeQuality({ preset: "auto", bitrate: 3_200_000, fps: 60 })).toBe("Auto · 3.2 Mb/s target · 60 fps");
    expect(describeQuality({ preset: "low", bitrate: 1_000_000, fps: 30 })).toBe("Low · 1.0 Mb/s · 30 fps");
  });
});
