import { describe, expect, test } from "bun:test";

import {
  type AlertState,
  CLEAR_AFTER_MS,
  DEFAULT_THRESHOLDS,
  type Reading,
  STALE_MS,
  type Thresholds,
  type Transition,
  activeKinds,
  anyEnabled,
  clearPoint,
  evaluate,
  freshReading,
  idleState,
  needsSamples,
  parseThresholds,
  readingOf,
} from "./alerts.js";
import type { Sample } from "./metrics.js";

function sample(overrides: Partial<Sample> = {}): Sample {
  return {
    t: 0,
    cpu: 10,
    cores: [],
    mem_total: 100,
    mem_used: 40,
    commit_used: 0,
    commit_limit: 0,
    gpus: [],
    net_rx: 0,
    net_tx: 0,
    adapters: [],
    disk_read: 0,
    disk_write: 0,
    volumes: [],
    uptime: 0,
    processes: 0,
    ...overrides,
  };
}

function reading(overrides: Partial<Reading> = {}): Reading {
  return { cpu: 10, memory: 40, disk: { name: "C:", free: 50 }, temperature: 50, ...overrides };
}

function only(patch: Partial<Thresholds>): Thresholds {
  const off = parseThresholds({});
  return { ...off, ...patch };
}

// Runs `evaluate` once a second from `from` to `to` (ms) with the reading
// `at` gives, collecting what fired and cleared.
function run(
  thresholds: Thresholds,
  from: number,
  to: number,
  at: (now: number) => { online?: boolean; reading: Reading | null },
  start: AlertState = idleState(),
): { state: AlertState; transitions: (Transition & { at: number })[] } {
  let state = start;
  const transitions: (Transition & { at: number })[] = [];
  for (let now = from; now <= to; now += 1000) {
    const input = at(now);
    const result = evaluate(thresholds, state, input.online ?? true, input.reading, now);
    state = result.state;
    for (const transition of result.transitions) transitions.push({ ...transition, at: now });
  }
  return { state, transitions };
}

describe("CPU", () => {
  const thresholds = only({ cpu: { enabled: true, percent: 90, seconds: 30 } });

  test("fires once over the line for the whole time, not before", () => {
    const { transitions } = run(thresholds, 0, 60_000, () => ({ reading: reading({ cpu: 95 }) }));
    expect(transitions.map(({ kind, fired, at }) => [kind, fired, at])).toEqual([["cpu", true, 30_000]]);
    expect(transitions[0]?.message).toBe("CPU over 90% for 30 s (now 95%)");
  });

  test("a dip under the line starts the wait over", () => {
    const { transitions } = run(thresholds, 0, 80_000, (now) => ({
      reading: reading({ cpu: now === 20_000 ? 50 : 95 }),
    }));
    expect(transitions.map(({ at }) => at)).toEqual([51_000]);
  });

  test("hovering at the line doesn't flap", () => {
    // Fired, then between 81% and 99% for minutes: never under 80, so it
    // stays on, once.
    const { state, transitions } = run(thresholds, 0, 300_000, (now) => ({
      reading: reading({ cpu: now < 40_000 ? 95 : now % 2000 === 0 ? 81 : 99 }),
    }));
    expect(transitions.filter((transition) => transition.fired)).toHaveLength(1);
    expect(transitions.filter((transition) => !transition.fired)).toHaveLength(0);
    expect(activeKinds(state)).toEqual(["cpu"]);
  });

  test("clears only back by the margin, for long enough", () => {
    const { transitions } = run(thresholds, 0, 120_000, (now) => ({
      reading: reading({ cpu: now < 40_000 ? 95 : now < 60_000 ? 85 : 70 }),
    }));
    const cleared = transitions.find((transition) => !transition.fired);
    expect(cleared?.at).toBe(60_000 + CLEAR_AFTER_MS);
    expect(cleared?.message).toBe("CPU back under 90%");
  });
});

describe("memory, disk and temperature", () => {
  test("memory holds ten seconds before firing", () => {
    const thresholds = only({ memory: { enabled: true, percent: 80 } });
    const { transitions } = run(thresholds, 0, 30_000, () => ({ reading: reading({ memory: 85 }) }));
    expect(transitions.map(({ at, message }) => [at, message])).toEqual([[10_000, "Memory over 80% (now 85%)"]]);
  });

  test("a drive under the free space fires at once, naming it, and clears two points above", () => {
    const thresholds = only({ disk: { enabled: true, percent: 10 } });
    const { transitions } = run(thresholds, 0, 40_000, (now) => ({
      reading: reading({ disk: { name: "D:", free: now < 5_000 ? 8 : now < 20_000 ? 11 : 12.5 } }),
    }));
    expect(transitions.map(({ fired, at }) => [fired, at])).toEqual([
      [true, 0],
      [false, 20_000 + CLEAR_AFTER_MS],
    ]);
    expect(transitions[0]?.message).toBe("D: has 8% free (under 10%)");
  });

  test("temperature: none reported is no alert, never an assumed one", () => {
    const thresholds = only({ temperature: { enabled: true, celsius: 80 } });
    expect(run(thresholds, 0, 60_000, () => ({ reading: reading({ temperature: null }) })).transitions).toEqual([]);
    const hot = run(thresholds, 0, 60_000, () => ({ reading: reading({ temperature: 91 }) }));
    expect(hot.transitions.map(({ at, message }) => [at, message])).toEqual([[10_000, "91 °C, over 80 °C"]]);
  });
});

describe("offline", () => {
  const thresholds = only({ offline: { enabled: true, seconds: 60 } });

  test("a short drop isn't an alert; a long one is, once", () => {
    const short = run(thresholds, 0, 120_000, (now) => ({ online: !(now > 10_000 && now < 40_000), reading: null }));
    expect(short.transitions).toEqual([]);
    const long = run(thresholds, 0, 200_000, (now) => ({ online: now < 10_000, reading: null }));
    expect(long.transitions.map(({ fired, at, message }) => [fired, at, message])).toEqual([[true, 70_000, "Offline for 1 min"]]);
  });

  test("clears once back for a while", () => {
    const { transitions } = run(thresholds, 0, 200_000, (now) => ({ online: now < 10_000 || now >= 100_000, reading: null }));
    expect(transitions.map(({ fired, at }) => [fired, at])).toEqual([
      [true, 70_000],
      [false, 100_000 + CLEAR_AFTER_MS],
    ]);
    expect(transitions[1]?.message).toBe("Back online");
  });
});

describe("extreme thresholds still clear", () => {
  test("the clear point is held to 0..100", () => {
    expect(clearPoint(1 - 10)).toBe(0);
    expect(clearPoint(99 + 2)).toBe(100);
    expect(clearPoint(42)).toBe(42);
  });

  test("CPU over 1%: clears at 0%", () => {
    const thresholds = only({ cpu: { enabled: true, percent: 1, seconds: 5 } });
    const { state, transitions } = run(thresholds, 0, 60_000, (now) => ({
      reading: reading({ cpu: now < 20_000 ? 50 : 0 }),
    }));
    expect(transitions.map(({ fired, at }) => [fired, at])).toEqual([
      [true, 5_000],
      [false, 20_000 + CLEAR_AFTER_MS],
    ]);
    expect(activeKinds(state)).toEqual([]);
  });

  test("memory over 1%: clears at 0%", () => {
    const thresholds = only({ memory: { enabled: true, percent: 1 } });
    const { transitions } = run(thresholds, 0, 60_000, (now) => ({
      reading: reading({ memory: now < 20_000 ? 40 : 0 }),
    }));
    expect(transitions.map(({ fired, at }) => [fired, at])).toEqual([
      [true, 10_000],
      [false, 20_000 + CLEAR_AFTER_MS],
    ]);
  });

  test("free space under 99%: clears at 100% free", () => {
    const thresholds = only({ disk: { enabled: true, percent: 99 } });
    const { transitions } = run(thresholds, 0, 60_000, (now) => ({
      reading: reading({ disk: { name: "C:", free: now < 20_000 ? 98 : 100 } }),
    }));
    expect(transitions.map(({ fired, at }) => [fired, at])).toEqual([
      [true, 0],
      [false, 20_000 + CLEAR_AFTER_MS],
    ]);
  });
});

describe("no reading", () => {
  test("a rule needing samples settles quietly when they stop", () => {
    const thresholds = only({ cpu: { enabled: true, percent: 50, seconds: 1 } });
    const fired = run(thresholds, 0, 5_000, () => ({ reading: reading({ cpu: 90 }) }));
    expect(activeKinds(fired.state)).toEqual(["cpu"]);
    const stopped = run(thresholds, 6_000, 7_000, () => ({ reading: null }), fired.state);
    expect(stopped.transitions).toEqual([]);
    expect(activeKinds(stopped.state)).toEqual([]);
  });

  test("rules turned off never fire", () => {
    const { transitions } = run(DEFAULT_THRESHOLDS, 0, 600_000, () => ({
      online: false,
      reading: reading({ cpu: 100, memory: 100, disk: { name: "C:", free: 0 }, temperature: 120 }),
    }));
    expect(transitions).toEqual([]);
  });
});

describe("readings", () => {
  test("the fullest drive and the hottest sensor", () => {
    const value = readingOf(
      sample({
        cpu: 33,
        mem_used: 75,
        volumes: [
          { name: "C:", label: "", total: 1000, free: 300 },
          { name: "D:", label: "", total: 1000, free: 50 },
          { name: "E:", label: "", total: 0, free: 0 },
        ],
        cpu_temp: 55,
        gpus: [{ name: "g", util: 0, dedicated_used: 0, dedicated_total: 0, shared_used: 0, temp: 71 }],
      }),
    );
    expect(value).toEqual({ cpu: 33, memory: 75, disk: { name: "D:", free: 5 }, temperature: 71 });
    expect(readingOf(sample()).temperature).toBeNull();
    expect(readingOf(sample()).disk).toBeNull();
  });

  test("an old sample is no reading", () => {
    expect(freshReading(null, 0, 0)).toBeNull();
    expect(freshReading(sample(), null, 0)).toBeNull();
    // The machine's clock is hours off; what counts is when it arrived.
    const skewed = sample({ t: 1000 - 3 * 3600_000 });
    expect(freshReading(skewed, 1000, 1000 + STALE_MS)).not.toBeNull();
    expect(freshReading(skewed, 1000, 1001 + STALE_MS)).toBeNull();
  });
});

describe("stored thresholds", () => {
  test("anything missing or out of range is the default", () => {
    expect(parseThresholds(null)).toEqual(DEFAULT_THRESHOLDS);
    expect(parseThresholds("nonsense")).toEqual(DEFAULT_THRESHOLDS);
    const parsed = parseThresholds({
      cpu: { enabled: true, percent: 250, seconds: "soon" },
      memory: { enabled: "yes", percent: 85 },
      disk: { enabled: true, percent: -3 },
      offline: { enabled: true, seconds: 5 },
    });
    expect(parsed.cpu).toEqual({ enabled: true, percent: 100, seconds: DEFAULT_THRESHOLDS.cpu.seconds });
    expect(parsed.memory).toEqual({ enabled: false, percent: 85 });
    expect(parsed.disk).toEqual({ enabled: true, percent: 1 });
    expect(parsed.temperature).toEqual(DEFAULT_THRESHOLDS.temperature);
    expect(parsed.offline).toEqual({ enabled: true, seconds: 10 });
  });

  test("a round trip keeps everything", () => {
    const thresholds: Thresholds = {
      cpu: { enabled: true, percent: 75, seconds: 120 },
      memory: { enabled: true, percent: 92 },
      disk: { enabled: false, percent: 15 },
      temperature: { enabled: true, celsius: 85 },
      offline: { enabled: true, seconds: 300 },
    };
    expect(parseThresholds(JSON.parse(JSON.stringify(thresholds)))).toEqual(thresholds);
  });

  test("which rules need samples", () => {
    expect(anyEnabled(DEFAULT_THRESHOLDS)).toBe(false);
    const offline = only({ offline: { enabled: true, seconds: 60 } });
    expect(anyEnabled(offline)).toBe(true);
    expect(needsSamples(offline)).toBe(false);
    expect(needsSamples(only({ disk: { enabled: true, percent: 5 } }))).toBe(true);
  });
});
