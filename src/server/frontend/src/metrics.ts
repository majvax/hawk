// A machine's analytics, the dashboard's side (src/service/metrics.hpp has
// the machine's, and the message table). The machine samples itself once a
// second and keeps its own history; nothing is stored on the relay. While
// the Analytics or Processes tab is open, this subscribes to the live
// samples and asks for history and the process list.
export const METRICS_OP = {
  subscribe: 1,
  unsubscribe: 2,
  history: 3,
  processes: 4,
  info: 17,
  sample: 18,
  historyData: 19,
  processList: 20,
  error: 23,
} as const;

export type MetricsRange = "5m" | "1h" | "24h" | "7d" | "30d" | "90d";

export interface MachineInfo {
  hostname: string;
  os: string;
  cpu: { name: string; cores: number; threads: number };
  memory: number;
  gpus: { name: string; dedicated: number }[];
  history_days: number;
  ranges: MetricsRange[];
}

export interface GpuSample {
  name: string;
  util: number;
  dedicated_used: number;
  dedicated_total: number;
  shared_used: number;
  // °C, from a machine that can read it; absent otherwise (and from one
  // older than temperatures).
  temp?: number;
}

export interface Sample {
  t: number; // unix milliseconds
  cpu: number;
  cores: number[];
  mem_total: number;
  mem_used: number;
  commit_used: number;
  commit_limit: number;
  gpus: GpuSample[];
  net_rx: number;
  net_tx: number;
  adapters: { name: string; rx: number; tx: number }[];
  disk_read: number;
  disk_write: number;
  volumes: { name: string; label: string; total: number; free: number }[];
  uptime: number;
  processes: number;
  // °C, the hottest ACPI thermal zone, where the machine has one; absent
  // otherwise. Often the board's rather than the CPU package's.
  cpu_temp?: number;
}

// Columns, one value per point; `t` in unix seconds.
export interface History {
  range: MetricsRange;
  step: number;
  t: number[];
  cpu: number[];
  mem: number[];
  gpu: number[];
  vram: number[];
  rx: number[];
  tx: number[];
  read: number[];
  write: number[];
}

export interface ProcessRow {
  pid: number;
  parent: number;
  name: string;
  user: string;
  cpu: number;
  memory: number;
  private_bytes: number;
  threads: number;
  handles: number;
  session: number;
  started: number;
}

export interface MetricsState {
  enabled: boolean; // this viewer may read the machine's analytics
  info: MachineInfo | null;
  latest: Sample | null;
  // The live view: samples as they arrive, the last five minutes.
  live: Sample[];
  history: Partial<Record<MetricsRange, History>>;
  processes: { t: number; rows: ProcessRow[] } | null;
  error: string | null;
}

export const EMPTY_METRICS: MetricsState = {
  enabled: false,
  info: null,
  latest: null,
  live: [],
  history: {},
  processes: null,
  error: null,
};

export type MetricsSender = (op: number, header: object) => boolean;

const LIVE_SAMPLES = 300;

export class MetricsManager {
  private sender: MetricsSender | null = null;
  private subscribers = 0;
  private state: MetricsState = EMPTY_METRICS;

  // `onSample` hears every sample as it arrives, for the sparklines' and
  // the alerts' own bookkeeping, which outlives this manager.
  constructor(
    private readonly onChange: (state: MetricsState) => void,
    private readonly onSample: (sample: Sample) => void = () => {},
  ) {}

  // A sender while the view is secured and allows analytics; null once it
  // isn't. A new sender re-subscribes whoever was watching.
  attach(sender: MetricsSender | null): void {
    this.sender = sender;
    this.state = { ...EMPTY_METRICS, enabled: sender !== null };
    if (sender !== null && this.subscribers > 0) sender(METRICS_OP.subscribe, {});
    this.onChange(this.state);
  }

  // A tab that shows live numbers opened (true) or closed (false). The
  // machine pushes samples while at least one is open.
  watch(on: boolean): void {
    this.subscribers = Math.max(0, this.subscribers + (on ? 1 : -1));
    if (on && this.subscribers === 1) this.sender?.(METRICS_OP.subscribe, {});
    if (!on && this.subscribers === 0) this.sender?.(METRICS_OP.unsubscribe, {});
  }

  requestHistory(range: MetricsRange): void {
    this.sender?.(METRICS_OP.history, { range });
  }

  requestProcesses(): void {
    this.sender?.(METRICS_OP.processes, {});
  }

  close(): void {
    this.sender = null;
    this.subscribers = 0;
  }

  handle(op: number, header: unknown, data: Uint8Array): void {
    let body: unknown = null;
    if (data.length > 0) {
      try {
        body = JSON.parse(new TextDecoder().decode(data));
      } catch {
        return;
      }
    }
    switch (op) {
      case METRICS_OP.info:
        this.update({ info: body as MachineInfo, error: null });
        break;
      case METRICS_OP.sample: {
        const sample = body as Sample;
        const live = [...this.state.live, sample];
        if (live.length > LIVE_SAMPLES) live.splice(0, live.length - LIVE_SAMPLES);
        this.update({ latest: sample, live });
        this.onSample(sample);
        break;
      }
      case METRICS_OP.historyData: {
        const history = body as History;
        this.update({ history: { ...this.state.history, [history.range]: history } });
        break;
      }
      case METRICS_OP.processList: {
        const list = body as { t: number; processes: ProcessRow[] };
        this.update({ processes: { t: list.t, rows: list.processes } });
        break;
      }
      case METRICS_OP.error: {
        const message = (header as { message?: unknown } | null)?.message;
        this.update({ error: typeof message === "string" ? message : "the machine refused the request" });
        break;
      }
    }
  }

  private update(patch: Partial<MetricsState>): void {
    this.state = { ...this.state, ...patch };
    this.onChange(this.state);
  }
}

// --- Formatting ---------------------------------------------------------------------------

const BYTE_UNITS = ["B", "KB", "MB", "GB", "TB"];

// 1536 -> "1.5 KB": binary multiples, as Windows shows sizes.
export function formatBytes(value: number, digits = 1): string {
  let unit = 0;
  let scaled = value;
  while (scaled >= 1024 && unit < BYTE_UNITS.length - 1) {
    scaled /= 1024;
    unit += 1;
  }
  return `${scaled.toFixed(unit === 0 ? 0 : scaled >= 100 ? 0 : digits)} ${BYTE_UNITS[unit]}`;
}

export function formatRate(bytesPerSecond: number): string {
  return `${formatBytes(bytesPerSecond)}/s`;
}

export function formatDuration(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}
