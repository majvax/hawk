// The sparklines' numbers: the last few minutes of each machine's samples,
// kept in this browser only while it's open. Each series is a ring buffer
// of fixed size, so a machine watched for hours costs what one watched
// for five minutes does. Nothing here draws: AnalyticsPanel.tsx does, from
// sparkPath and sparkLabel.
import type { Sample } from "./metrics.js";

// Five minutes at the machine's one sample a second.
export const SPARK_CAPACITY = 300;

// A fixed number of values, the oldest overwritten first.
export class Ring {
  private readonly values: number[];
  private next = 0;
  private count = 0;

  constructor(readonly capacity: number) {
    if (!Number.isInteger(capacity) || capacity < 1) throw new RangeError("a ring holds at least one value");
    this.values = new Array<number>(capacity).fill(Number.NaN);
  }

  get size(): number {
    return this.count;
  }

  push(value: number): void {
    this.values[this.next] = value;
    this.next = (this.next + 1) % this.capacity;
    this.count = Math.min(this.count + 1, this.capacity);
  }

  // Oldest first.
  toArray(): number[] {
    const start = (this.next - this.count + this.capacity) % this.capacity;
    const out: number[] = [];
    for (let i = 0; i < this.count; i += 1) out.push(this.values[(start + i) % this.capacity] ?? Number.NaN);
    return out;
  }

  clear(): void {
    this.next = 0;
    this.count = 0;
  }
}

export interface SeriesStats {
  current: number;
  min: number;
  max: number;
}

// The latest, lowest and highest of the values there are; NaN marks a
// sample without one (a sensor that didn't answer) and is skipped. null
// when there's nothing to go by.
export function seriesStats(values: readonly number[]): SeriesStats | null {
  let current: number | null = null;
  let min = Number.POSITIVE_INFINITY;
  let max = Number.NEGATIVE_INFINITY;
  for (const value of values) {
    if (!Number.isFinite(value)) continue;
    current = value;
    min = Math.min(min, value);
    max = Math.max(max, value);
  }
  return current === null ? null : { current, min, max };
}

// What a sparkline says to a screen reader: "CPU: now 12%, lowest 3%,
// highest 48% over the last 5 minutes".
export function sparkLabel(
  label: string,
  values: readonly number[],
  format: (value: number) => string,
  secondsPerValue = 1,
): string {
  const found = seriesStats(values);
  if (found === null) return `${label}: no readings yet`;
  const minutes = Math.max(1, Math.round((values.length * secondsPerValue) / 60));
  const span = minutes === 1 ? "the last minute" : `the last ${minutes} minutes`;
  return `${label}: now ${format(found.current)}, lowest ${format(found.min)}, highest ${format(found.max)} over ${span}`;
}

// The line through `values` in a width × height box: oldest at the left,
// the newest at the right edge, the box's full height spanning `floor` to
// `ceiling` (by default the values' own range, or a flat line through the
// middle when they're all one). A gap (NaN) breaks the line. Empty for
// fewer than two values in a row.
export function sparkPath(
  values: readonly number[],
  width: number,
  height: number,
  bounds: { floor?: number; ceiling?: number } = {},
): string {
  const found = seriesStats(values);
  if (found === null || values.length < 2) return "";
  const floor = bounds.floor ?? found.min;
  const ceiling = Math.max(bounds.ceiling ?? found.max, floor);
  const span = ceiling - floor;
  const step = width / (values.length - 1);
  // A stroke's half-width of room top and bottom, so a peak isn't clipped.
  const inset = 1;
  const y = (value: number): number => {
    const fraction = span === 0 ? 0.5 : (Math.min(Math.max(value, floor), ceiling) - floor) / span;
    return inset + (1 - fraction) * (height - 2 * inset);
  };
  let path = "";
  let drawing = false;
  let run = 0;
  values.forEach((value, i) => {
    if (!Number.isFinite(value)) {
      drawing = false;
      return;
    }
    path += `${drawing ? "L" : "M"}${(i * step).toFixed(1)},${y(value).toFixed(1)}`;
    if (drawing) run += 1;
    drawing = true;
  });
  // Only lone points: nothing to draw a line through.
  return run === 0 ? "" : path;
}

// --- Per machine --------------------------------------------------------------------------

// What each sparkline follows. Network and disk throughput are bytes a
// second; memory a percentage of the machine's; temperatures °C (the CPU's
// thermal zone, the hottest GPU).
export const SPARK_KEYS = ["cpu", "mem", "gpu", "rx", "tx", "read", "write", "cpuTemp", "gpuTemp"] as const;
export type SparkKey = (typeof SPARK_KEYS)[number];
export type SparkSeries = Record<SparkKey, number[]>;

// One sample's worth; a key left out is a gap in its line.
export function sparkPoint(sample: Sample): Partial<Record<SparkKey, number>> {
  const gpuTemps = sample.gpus.flatMap((gpu) => (typeof gpu.temp === "number" ? [gpu.temp] : []));
  return {
    cpu: sample.cpu,
    mem: sample.mem_total > 0 ? (sample.mem_used / sample.mem_total) * 100 : undefined,
    gpu: sample.gpus.length > 0 ? Math.max(...sample.gpus.map((gpu) => gpu.util)) : undefined,
    rx: sample.net_rx,
    tx: sample.net_tx,
    read: sample.disk_read,
    write: sample.disk_write,
    cpuTemp: typeof sample.cpu_temp === "number" ? sample.cpu_temp : undefined,
    gpuTemp: gpuTemps.length > 0 ? Math.max(...gpuTemps) : undefined,
  };
}

interface Recent {
  at: number; // when the last sample came, ms since epoch
  series: Record<SparkKey, Ring>;
}

// Every machine's recent samples, each machine's on its own rings: one
// watched earlier keeps its last minutes while another is on show.
export class SparkStore {
  private readonly machines = new Map<string, Recent>();

  constructor(private readonly capacity = SPARK_CAPACITY) {}

  push(machineId: string, point: Partial<Record<SparkKey, number>>, at: number): void {
    let recent = this.machines.get(machineId);
    if (recent === undefined) {
      const series = {} as Record<SparkKey, Ring>;
      for (const key of SPARK_KEYS) series[key] = new Ring(this.capacity);
      recent = { at, series };
      this.machines.set(machineId, recent);
    }
    recent.at = at;
    for (const key of SPARK_KEYS) recent.series[key].push(point[key] ?? Number.NaN);
  }

  // The machine's series, oldest first; null for one never sampled here.
  series(machineId: string): SparkSeries | null {
    const recent = this.machines.get(machineId);
    if (recent === undefined) return null;
    const out = {} as SparkSeries;
    for (const key of SPARK_KEYS) out[key] = recent.series[key].toArray();
    return out;
  }

  // When the machine's last sample came; null for none.
  updatedAt(machineId: string): number | null {
    return this.machines.get(machineId)?.at ?? null;
  }

  forget(machineId: string): void {
    this.machines.delete(machineId);
  }
}
