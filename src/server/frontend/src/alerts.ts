// Threshold alerts: the user sets, per machine, what's worth a warning
// (CPU busy for a while, memory or a disk nearly full, too hot, offline),
// and this dashboard checks while it's open. It's the only place that can:
// the samples are sealed for the browser, so the relay never sees a number,
// and the machine has nobody to tell. That makes them a viewer's own
// preference, kept in this browser (localStorage, per machine), not in the
// machine's config, which is the owner's rules for everyone it's shared
// with and which a shared account can't change.
//
// Each rule has hysteresis, so a reading hovering at the line doesn't
// flap: it fires once over the line for long enough, and clears only once
// it's back by a margin, for long enough. Everything here is pure but the
// storage at the bottom; useAlerts.ts runs it.
import type { Sample } from "./metrics.js";

export type AlertKind = "cpu" | "memory" | "disk" | "temperature" | "offline";

export const ALERT_KINDS: readonly AlertKind[] = ["cpu", "memory", "disk", "temperature", "offline"];

// Each rule's numbers. `seconds` is how long the condition has to hold.
export interface Thresholds {
  cpu: { enabled: boolean; percent: number; seconds: number };
  memory: { enabled: boolean; percent: number };
  // Any fixed drive's free space, as a share of it.
  disk: { enabled: boolean; percent: number };
  // The CPU's thermal zone or any GPU, where the machine reports one.
  temperature: { enabled: boolean; celsius: number };
  offline: { enabled: boolean; seconds: number };
}

export const DEFAULT_THRESHOLDS: Thresholds = {
  cpu: { enabled: false, percent: 90, seconds: 60 },
  memory: { enabled: false, percent: 90 },
  disk: { enabled: false, percent: 10 },
  temperature: { enabled: false, celsius: 90 },
  offline: { enabled: false, seconds: 120 },
};

// How far back past the line a reading has to come to clear, and how long
// it has to stay there.
export const CLEAR_MARGIN: Record<AlertKind, number> = {
  cpu: 10, // points
  memory: 5, // points
  disk: 2, // points of free space
  temperature: 5, // °C
  offline: 0,
};
export const CLEAR_AFTER_MS = 10_000;
// Memory and temperature fire once over for this long: one sample's spike
// isn't worth a warning. A disk fills slowly, and the machine reads it
// every ten seconds anyway.
const HOLD_MS: Record<Exclude<AlertKind, "cpu" | "offline">, number> = {
  memory: 10_000,
  disk: 0,
  temperature: 10_000,
};
// A sample older than this is no reading at all.
export const STALE_MS = 5_000;

// Whether the rules that need numbers have them: only for the machine
// being watched, with analytics, while this dashboard is open.
export function needsSamples(thresholds: Thresholds): boolean {
  return thresholds.cpu.enabled || thresholds.memory.enabled || thresholds.disk.enabled || thresholds.temperature.enabled;
}

export function anyEnabled(thresholds: Thresholds): boolean {
  return needsSamples(thresholds) || thresholds.offline.enabled;
}

// --- Readings -------------------------------------------------------------------------------

// The numbers the rules compare, from one sample.
export interface Reading {
  cpu: number;
  memory: number; // % in use
  // The fullest fixed drive: its name and % free. null with none.
  disk: { name: string; free: number } | null;
  // The hottest sensor there is, °C; null with none.
  temperature: number | null;
}

export function readingOf(sample: Sample): Reading {
  let disk: Reading["disk"] = null;
  for (const volume of sample.volumes) {
    if (volume.total <= 0) continue;
    const free = (volume.free / volume.total) * 100;
    if (disk === null || free < disk.free) disk = { name: volume.name, free };
  }
  const temps = [sample.cpu_temp, ...sample.gpus.map((gpu) => gpu.temp)].filter(
    (value): value is number => typeof value === "number" && Number.isFinite(value),
  );
  return {
    cpu: sample.cpu,
    memory: sample.mem_total > 0 ? (sample.mem_used / sample.mem_total) * 100 : 0,
    disk,
    temperature: temps.length > 0 ? Math.max(...temps) : null,
  };
}

// --- Evaluation -----------------------------------------------------------------------------

// Where one rule stands: firing or not, and since when its condition (or,
// while firing, the way out of it) has held.
export interface RuleState {
  active: boolean;
  since: number | null;
}

export type AlertState = Record<AlertKind, RuleState>;

export function idleState(): AlertState {
  return {
    cpu: { active: false, since: null },
    memory: { active: false, since: null },
    disk: { active: false, since: null },
    temperature: { active: false, since: null },
    offline: { active: false, since: null },
  };
}

// A rule that just fired (`fired`) or cleared, in words for a toast.
export interface Transition {
  kind: AlertKind;
  fired: boolean;
  message: string;
}

// One rule's step. `over`: the condition holds now; `back`: it's past the
// clear margin now. null for no reading, which settles the rule quietly:
// nothing is known, so nothing is claimed.
function step(
  rule: RuleState,
  now: number,
  reading: { over: boolean; back: boolean } | null,
  holdMs: number,
): { rule: RuleState; changed: boolean } {
  if (reading === null) return { rule: { active: false, since: null }, changed: false };
  if (!rule.active) {
    if (!reading.over) return { rule: { active: false, since: null }, changed: false };
    const since = rule.since ?? now;
    return now - since >= holdMs ? { rule: { active: true, since: null }, changed: true } : { rule: { active: false, since }, changed: false };
  }
  if (!reading.back) return { rule: { active: true, since: null }, changed: false };
  const since = rule.since ?? now;
  return now - since >= CLEAR_AFTER_MS
    ? { rule: { active: false, since: null }, changed: true }
    : { rule: { active: true, since }, changed: false };
}

const round = (value: number): number => Math.round(value);

// Where a percentage clears, held to 0..100: a threshold near either end
// would otherwise put it where no reading can go (under 0% busy, over 100%
// free), and the alert would never clear.
export function clearPoint(percent: number): number {
  return Math.min(100, Math.max(0, percent));
}

function describeSeconds(seconds: number): string {
  if (seconds < 60) return `${seconds} s`;
  const minutes = Math.round(seconds / 60);
  return minutes === 1 ? "1 min" : `${minutes} min`;
}

// Advances every rule to `now`. `online` is the relay's word on the
// machine; `reading` the latest sample's numbers (null with none fresh).
export function evaluate(
  thresholds: Thresholds,
  previous: AlertState,
  online: boolean,
  reading: Reading | null,
  now: number,
): { state: AlertState; transitions: Transition[] } {
  const state = idleState();
  const transitions: Transition[] = [];
  const run = (
    kind: AlertKind,
    enabled: boolean,
    condition: { over: boolean; back: boolean } | null,
    holdMs: number,
    fired: () => string,
    cleared: () => string,
  ): void => {
    const result = step(previous[kind], now, enabled ? condition : null, holdMs);
    state[kind] = result.rule;
    if (result.changed) transitions.push({ kind, fired: result.rule.active, message: result.rule.active ? fired() : cleared() });
  };

  const { cpu, memory, disk, temperature, offline } = thresholds;
  run(
    "cpu",
    cpu.enabled,
    reading === null ? null : { over: reading.cpu > cpu.percent, back: reading.cpu <= clearPoint(cpu.percent - CLEAR_MARGIN.cpu) },
    cpu.seconds * 1000,
    () => `CPU over ${cpu.percent}% for ${describeSeconds(cpu.seconds)} (now ${round(reading?.cpu ?? 0)}%)`,
    () => `CPU back under ${cpu.percent}%`,
  );
  run(
    "memory",
    memory.enabled,
    reading === null
      ? null
      : { over: reading.memory > memory.percent, back: reading.memory <= clearPoint(memory.percent - CLEAR_MARGIN.memory) },
    HOLD_MS.memory,
    () => `Memory over ${memory.percent}% (now ${round(reading?.memory ?? 0)}%)`,
    () => `Memory back under ${memory.percent}%`,
  );
  const drive = reading?.disk ?? null;
  run(
    "disk",
    disk.enabled,
    drive === null ? null : { over: drive.free < disk.percent, back: drive.free >= clearPoint(disk.percent + CLEAR_MARGIN.disk) },
    HOLD_MS.disk,
    () => `${drive?.name ?? "A drive"} has ${round(drive?.free ?? 0)}% free (under ${disk.percent}%)`,
    () => `Every drive has ${disk.percent}% free again`,
  );
  const hottest = reading?.temperature ?? null;
  run(
    "temperature",
    temperature.enabled,
    hottest === null
      ? null
      : { over: hottest > temperature.celsius, back: hottest <= temperature.celsius - CLEAR_MARGIN.temperature },
    HOLD_MS.temperature,
    () => `${round(hottest ?? 0)} °C, over ${temperature.celsius} °C`,
    () => `Temperature back under ${temperature.celsius} °C`,
  );
  // Offline needs no samples: the relay says it of every machine.
  run(
    "offline",
    offline.enabled,
    { over: !online, back: online },
    offline.seconds * 1000,
    () => `Offline for ${describeSeconds(offline.seconds)}`,
    () => "Back online",
  );
  return { state, transitions };
}

// The rules firing now.
export function activeKinds(state: AlertState): AlertKind[] {
  return ALERT_KINDS.filter((kind) => state[kind].active);
}

export const ALERT_LABEL: Record<AlertKind, string> = {
  cpu: "CPU",
  memory: "Memory",
  disk: "Disk space",
  temperature: "Temperature",
  offline: "Offline",
};

// A reading for evaluate(): the sample's numbers if it arrived lately, else
// none. By when it arrived here, not the time it carries: the machine's
// clock needn't agree with this one.
export function freshReading(sample: Sample | null, receivedAt: number | null, now: number): Reading | null {
  if (sample === null || receivedAt === null || now - receivedAt > STALE_MS) return null;
  return readingOf(sample);
}

// --- Stored settings --------------------------------------------------------------------------

const STORAGE_PREFIX = "hawk.alerts.";
const NOTIFY_KEY = "hawk.alerts.notify";

function number(value: unknown, fallback: number, min: number, max: number): number {
  return typeof value === "number" && Number.isFinite(value) ? Math.min(max, Math.max(min, value)) : fallback;
}

function flag(value: unknown): boolean {
  return value === true;
}

function field(value: unknown, key: string): Record<string, unknown> {
  const inner = typeof value === "object" && value !== null ? (value as Record<string, unknown>)[key] : undefined;
  return typeof inner === "object" && inner !== null ? (inner as Record<string, unknown>) : {};
}

// Stored thresholds, checked: anything missing or out of range is the
// default, so a hand-edited or older entry can't break the page.
export function parseThresholds(value: unknown): Thresholds {
  const cpu = field(value, "cpu");
  const memory = field(value, "memory");
  const disk = field(value, "disk");
  const temperature = field(value, "temperature");
  const offline = field(value, "offline");
  const d = DEFAULT_THRESHOLDS;
  return {
    cpu: {
      enabled: flag(cpu.enabled),
      percent: number(cpu.percent, d.cpu.percent, 1, 100),
      seconds: number(cpu.seconds, d.cpu.seconds, 1, 3600),
    },
    memory: { enabled: flag(memory.enabled), percent: number(memory.percent, d.memory.percent, 1, 100) },
    disk: { enabled: flag(disk.enabled), percent: number(disk.percent, d.disk.percent, 1, 99) },
    temperature: {
      enabled: flag(temperature.enabled),
      celsius: number(temperature.celsius, d.temperature.celsius, 20, 130),
    },
    offline: { enabled: flag(offline.enabled), seconds: number(offline.seconds, d.offline.seconds, 10, 86_400) },
  };
}

// A machine's thresholds in this browser; the defaults (all off) for one
// with none, or where storage is blocked.
export function loadThresholds(machineId: string): Thresholds {
  try {
    const stored = window.localStorage.getItem(STORAGE_PREFIX + machineId);
    if (stored !== null) return parseThresholds(JSON.parse(stored));
  } catch {
    // blocked or garbled: the defaults
  }
  return DEFAULT_THRESHOLDS;
}

// Saved for next time; with all rules off, forgotten.
export function saveThresholds(machineId: string, thresholds: Thresholds): void {
  try {
    if (anyEnabled(thresholds)) window.localStorage.setItem(STORAGE_PREFIX + machineId, JSON.stringify(thresholds));
    else window.localStorage.removeItem(STORAGE_PREFIX + machineId);
  } catch {
    // Not remembered, then; it still applies until the page closes.
  }
}

// Whether the user asked for browser notifications too.
export function loadNotify(): boolean {
  try {
    return window.localStorage.getItem(NOTIFY_KEY) === "1";
  } catch {
    return false;
  }
}

export function saveNotify(on: boolean): void {
  try {
    if (on) window.localStorage.setItem(NOTIFY_KEY, "1");
    else window.localStorage.removeItem(NOTIFY_KEY);
  } catch {
    // Not remembered, then.
  }
}
