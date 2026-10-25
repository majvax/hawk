import { describe, expect, test } from "bun:test";

import type { Sample } from "./metrics.js";
import { Ring, SparkStore, seriesStats, sparkLabel, sparkPath, sparkPoint } from "./sparkline.js";

function sample(overrides: Partial<Sample> = {}): Sample {
  return {
    t: 1_000,
    cpu: 12,
    cores: [],
    mem_total: 1000,
    mem_used: 250,
    commit_used: 0,
    commit_limit: 0,
    gpus: [],
    net_rx: 10,
    net_tx: 20,
    adapters: [],
    disk_read: 30,
    disk_write: 40,
    volumes: [],
    uptime: 0,
    processes: 0,
    ...overrides,
  };
}

const percent = (value: number): string => `${Math.round(value)}%`;

describe("Ring", () => {
  test("keeps the newest values, oldest first", () => {
    const ring = new Ring(3);
    expect(ring.toArray()).toEqual([]);
    ring.push(1);
    ring.push(2);
    expect(ring.toArray()).toEqual([1, 2]);
    ring.push(3);
    ring.push(4);
    ring.push(5);
    expect(ring.toArray()).toEqual([3, 4, 5]);
    expect(ring.size).toBe(3);
  });

  test("never grows past its capacity", () => {
    const ring = new Ring(300);
    for (let i = 0; i < 10_000; i += 1) ring.push(i);
    const values = ring.toArray();
    expect(values.length).toBe(300);
    expect(values[0]).toBe(9_700);
    expect(values.at(-1)).toBe(9_999);
  });

  test("clears, and refuses a capacity of nothing", () => {
    const ring = new Ring(2);
    ring.push(1);
    ring.clear();
    expect(ring.toArray()).toEqual([]);
    ring.push(7);
    expect(ring.toArray()).toEqual([7]);
    expect(() => new Ring(0)).toThrow();
    expect(() => new Ring(1.5)).toThrow();
  });
});

describe("seriesStats", () => {
  test("current, lowest and highest", () => {
    expect(seriesStats([5, 1, 9, 4])).toEqual({ current: 4, min: 1, max: 9 });
    expect(seriesStats([7])).toEqual({ current: 7, min: 7, max: 7 });
  });

  test("gaps are skipped, and the current is the last reading there is", () => {
    expect(seriesStats([3, Number.NaN, 8, Number.NaN])).toEqual({ current: 8, min: 3, max: 8 });
    expect(seriesStats([])).toBeNull();
    expect(seriesStats([Number.NaN, Number.NaN])).toBeNull();
  });
});

describe("sparkLabel", () => {
  test("says the current, lowest and highest, and over how long", () => {
    const values = Array.from({ length: 300 }, (_, i) => (i === 10 ? 48 : i === 20 ? 3 : 12));
    expect(sparkLabel("CPU", values, percent)).toBe("CPU: now 12%, lowest 3%, highest 48% over the last 5 minutes");
    expect(sparkLabel("CPU", [1, 2], percent)).toBe("CPU: now 2%, lowest 1%, highest 2% over the last minute");
  });

  test("with nothing to go by", () => {
    expect(sparkLabel("GPU temperature", [Number.NaN], percent)).toBe("GPU temperature: no readings yet");
  });
});

describe("sparkPath", () => {
  test("spans the box: oldest at the left, the highest at the top", () => {
    expect(sparkPath([0, 10], 100, 22)).toBe("M0.0,21.0L100.0,1.0");
  });

  test("a fixed floor and ceiling (percentages)", () => {
    expect(sparkPath([50, 50], 10, 12, { floor: 0, ceiling: 100 })).toBe("M0.0,6.0L10.0,6.0");
    // Values beyond them are held to the edge.
    expect(sparkPath([150, -5], 10, 12, { floor: 0, ceiling: 100 })).toBe("M0.0,1.0L10.0,11.0");
  });

  test("all one value: a flat line through the middle", () => {
    expect(sparkPath([4, 4, 4], 20, 10)).toBe("M0.0,5.0L10.0,5.0L20.0,5.0");
  });

  test("a gap breaks the line, and nothing to join draws nothing", () => {
    expect(sparkPath([1, 2, Number.NaN, 2, 1], 40, 10)).toBe("M0.0,9.0L10.0,1.0M30.0,1.0L40.0,9.0");
    expect(sparkPath([1], 40, 10)).toBe("");
    expect(sparkPath([1, Number.NaN, 2], 40, 10)).toBe("");
    expect(sparkPath([], 40, 10)).toBe("");
  });
});

describe("sparkPoint", () => {
  test("a sample's numbers, memory as a share", () => {
    expect(sparkPoint(sample())).toEqual({
      cpu: 12,
      mem: 25,
      gpu: undefined,
      rx: 10,
      tx: 20,
      read: 30,
      write: 40,
      cpuTemp: undefined,
      gpuTemp: undefined,
    });
  });

  test("the busiest and the hottest GPU, and temperatures only when sent", () => {
    const gpus = [
      { name: "a", util: 20, dedicated_used: 0, dedicated_total: 0, shared_used: 0, temp: 61.5 },
      { name: "b", util: 70, dedicated_used: 0, dedicated_total: 0, shared_used: 0 },
    ];
    const point = sparkPoint(sample({ gpus, cpu_temp: 48 }));
    expect(point.gpu).toBe(70);
    expect(point.gpuTemp).toBe(61.5);
    expect(point.cpuTemp).toBe(48);
  });
});

describe("SparkStore", () => {
  test("keeps each machine apart, bounded", () => {
    const store = new SparkStore(3);
    expect(store.series("a")).toBeNull();
    expect(store.updatedAt("a")).toBeNull();
    for (let i = 1; i <= 5; i += 1) store.push("a", { cpu: i }, i * 1000);
    store.push("b", { cpu: 99, cpuTemp: 50 }, 7000);
    expect(store.series("a")?.cpu).toEqual([3, 4, 5]);
    expect(store.updatedAt("a")).toBe(5000);
    expect(store.series("b")?.cpu).toEqual([99]);
    expect(store.series("b")?.cpuTemp).toEqual([50]);
  });

  test("a value left out is a gap", () => {
    const store = new SparkStore();
    store.push("a", { cpu: 1, cpuTemp: 40 }, 1);
    store.push("a", { cpu: 2 }, 2);
    const temps = store.series("a")?.cpuTemp ?? [];
    expect(temps[0]).toBe(40);
    expect(Number.isNaN(temps[1])).toBe(true);
  });

  test("forgets a machine", () => {
    const store = new SparkStore();
    store.push("a", { cpu: 1 }, 1);
    store.forget("a");
    expect(store.series("a")).toBeNull();
  });
});

describe("edge cases", () => {
  test("only gaps, or infinities, are nothing to go by", () => {
    expect(seriesStats([Number.NaN, Number.NaN])).toBeNull();
    expect(seriesStats([Number.POSITIVE_INFINITY, 3, Number.NEGATIVE_INFINITY])).toEqual({ current: 3, min: 3, max: 3 });
    expect(sparkPath([Number.NaN, Number.NaN, Number.NaN], 40, 10)).toBe("");
    expect(sparkLabel("CPU", [Number.NaN], percent)).toBe("CPU: no readings yet");
  });

  test("a ceiling under the floor is held to it: a flat line, never NaN", () => {
    const path = sparkPath([1, 2], 10, 10, { floor: 50, ceiling: 10 });
    expect(path).not.toContain("NaN");
    expect(path).toBe("M0.0,5.0L10.0,5.0");
  });

  test("a ring wrapped many times still reads oldest first, and capacity one works", () => {
    const ring = new Ring(3);
    for (let i = 1; i <= 10; i += 1) ring.push(i);
    expect(ring.toArray()).toEqual([8, 9, 10]);
    const one = new Ring(1);
    one.push(1);
    one.push(2);
    expect(one.toArray()).toEqual([2]);
    expect(() => new Ring(1.5)).toThrow(RangeError);
  });

  test("a sample with no memory total or GPUs leaves gaps, not zeros", () => {
    const point = sparkPoint(sample({ mem_total: 0 }));
    expect(point.mem).toBeUndefined();
    expect(point.gpu).toBeUndefined();
    expect(point.cpuTemp).toBeUndefined();
    expect(point.gpuTemp).toBeUndefined();
  });
});
