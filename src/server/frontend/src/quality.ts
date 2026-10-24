// The stream's quality presets, as the live view's Quality menu offers them
// and the stats show them. The machine holds the bitrates and frame rates
// (src/service/quality.hpp); these are only for the labels. Nothing here
// touches the DOM.

export type QualityPreset = "auto" | "low" | "balanced" | "high" | "max";

export const QUALITY_PRESETS: { preset: QualityPreset; label: string; hint: string }[] = [
  { preset: "auto", label: "Auto", hint: "Follows the connection, from 0.5 to 12 Mb/s" },
  { preset: "low", label: "Low", hint: "1 Mb/s, 30 fps" },
  { preset: "balanced", label: "Balanced", hint: "4 Mb/s" },
  { preset: "high", label: "High", hint: "8 Mb/s" },
  { preset: "max", label: "Max", hint: "16 Mb/s" },
];

// What the machine says its stream is encoded at (a quality event).
export interface StreamQuality {
  preset: QualityPreset;
  bitrate: number; // bits per second; on Auto, its current target
  fps: number;
}

export function isQualityPreset(value: unknown): value is QualityPreset {
  return QUALITY_PRESETS.some((entry) => entry.preset === value);
}

// A quality event's fields, or null for anything that doesn't make sense.
export function parseQuality(event: { preset: unknown; bitrate: unknown; fps: unknown }): StreamQuality | null {
  const { preset, bitrate, fps } = event;
  if (!isQualityPreset(preset) || typeof bitrate !== "number" || typeof fps !== "number") return null;
  if (!Number.isFinite(bitrate) || bitrate <= 0 || !Number.isFinite(fps) || fps <= 0) return null;
  return { preset, bitrate, fps };
}

export function qualityLabel(preset: QualityPreset): string {
  return QUALITY_PRESETS.find((entry) => entry.preset === preset)?.label ?? preset;
}

// "Auto · 3.2 Mb/s target · 60 fps" for the stats overlay.
export function describeQuality(quality: StreamQuality): string {
  const mbps = (quality.bitrate / 1_000_000).toFixed(1);
  const target = quality.preset === "auto" ? `${mbps} Mb/s target` : `${mbps} Mb/s`;
  return `${qualityLabel(quality.preset)} · ${target} · ${quality.fps} fps`;
}
