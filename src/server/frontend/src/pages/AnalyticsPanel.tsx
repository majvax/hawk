// The Analytics and Processes tabs: a machine's health, sampled by the
// machine itself once a second and read over the end-to-end encrypted
// metrics channel (see ../metrics.ts). Charts are plain SVG in the
// dashboard's own palette, sized to their card.
import {
  type CSSProperties,
  type JSX,
  type PointerEvent,
  type ReactNode,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  type History,
  type MetricsRange,
  type MetricsState,
  type ProcessRow,
  type Sample,
  formatBytes,
  formatDuration,
  formatRate,
} from "../metrics.js";
import { Metric, Segmented } from "../ui.js";
import type { MetricsActions } from "../useDashboard.js";

// --- Series ---------------------------------------------------------------------------------

// The same columns whether they come from live samples or from history.
interface Series {
  step: number; // seconds between points
  t: number[]; // unix seconds
  cpu: number[];
  mem: number[];
  gpu: number[];
  vram: number[];
  rx: number[];
  tx: number[];
  read: number[];
  write: number[];
}

const SERIES_KEYS = ["t", "cpu", "mem", "gpu", "vram", "rx", "tx", "read", "write"] as const;

const EMPTY_SERIES: Series = { step: 1, t: [], cpu: [], mem: [], gpu: [], vram: [], rx: [], tx: [], read: [], write: [] };

function fromHistory(history: History): Series {
  const { t, cpu, mem, gpu, vram, rx, tx, read, write, step } = history;
  return { step, t, cpu, mem, gpu, vram, rx, tx, read, write };
}

// The live chart: the machine's last five minutes (asked for once), then
// every sample pushed since.
function liveSeries(backfill: History | undefined, live: Sample[], now: number): Series {
  const source = backfill === undefined ? EMPTY_SERIES : fromHistory(backfill);
  // Copies: what's pushed below mustn't reach the cached history.
  const series: Series = { ...source, step: 1 };
  for (const key of SERIES_KEYS) series[key] = source[key].slice();
  const last = series.t.at(-1) ?? 0;
  for (const sample of live) {
    const t = Math.floor(sample.t / 1000);
    if (t <= last) continue;
    series.t.push(t);
    series.cpu.push(sample.cpu);
    series.mem.push(sample.mem_used);
    series.gpu.push(Math.max(0, ...sample.gpus.map((gpu) => gpu.util)));
    series.vram.push(sample.gpus.reduce((sum, gpu) => sum + gpu.dedicated_used, 0));
    series.rx.push(sample.net_rx);
    series.tx.push(sample.net_tx);
    series.read.push(sample.disk_read);
    series.write.push(sample.disk_write);
  }
  // Only the window shown.
  const from = series.t.findIndex((t) => t >= now - 300);
  if (from > 0) {
    for (const key of SERIES_KEYS) series[key] = series[key].slice(from);
  }
  return series;
}

const RANGE_LABEL: Record<MetricsRange | "live", string> = {
  live: "Live",
  "5m": "5 min",
  "1h": "1 h",
  "24h": "24 h",
  "7d": "7 d",
  "30d": "30 d",
  "90d": "90 d",
};

const RANGE_SECONDS: Record<MetricsRange, number> = {
  "5m": 300,
  "1h": 3600,
  "24h": 86400,
  "7d": 7 * 86400,
  "30d": 30 * 86400,
  "90d": 90 * 86400,
};

// How often a range's history is asked for again while it's shown.
const RANGE_REFRESH_MS: Record<MetricsRange, number> = {
  "5m": 5_000,
  "1h": 10_000,
  "24h": 60_000,
  "7d": 300_000,
  "30d": 600_000,
  "90d": 900_000,
};

type Range = MetricsRange | "live";

// --- Chart ----------------------------------------------------------------------------------

interface Line {
  label: string;
  values: number[];
  color: string;
}

const CHART_HEIGHT = 132;
const PAD_TOP = 6;
const PAD_BOTTOM = 18;

// 0.83 -> 1, 3.2 -> 5, 1430 -> 2000: a round ceiling for the y axis.
function niceCeiling(value: number): number {
  if (value <= 0) return 1;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  for (const step of [1, 2, 2.5, 5, 10]) {
    if (value <= step * magnitude) return step * magnitude;
  }
  return 10 * magnitude;
}

function timeLabel(t: number, span: number): string {
  const date = new Date(t * 1000);
  if (span <= 3600) return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  if (span <= 86400) return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return date.toLocaleDateString([], { day: "numeric", month: "short" });
}

function TimeChart({
  t,
  lines,
  step,
  span,
  end,
  max,
  format,
}: {
  t: number[];
  lines: Line[];
  step: number;
  span: number; // seconds shown, ending at `end`
  end: number;
  max?: number; // a fixed top (100 for percentages); otherwise from the data
  format: (value: number) => string;
}): JSX.Element {
  const id = useId().replace(/:/g, "");
  const wrapRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(600);
  const [hover, setHover] = useState<number | null>(null);

  useEffect(() => {
    const element = wrapRef.current;
    if (element === null) return;
    const observer = new ResizeObserver(([entry]) => {
      if (entry !== undefined) setWidth(Math.max(120, Math.floor(entry.contentRect.width)));
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const start = end - span;
  const top = max ?? niceCeiling(Math.max(0, ...lines.flatMap((line) => line.values)) * 1.08);
  const plotHeight = CHART_HEIGHT - PAD_TOP - PAD_BOTTOM;
  const x = (time: number) => ((time - start) / span) * width;
  const y = (value: number) => PAD_TOP + plotHeight - (Math.min(value, top) / top) * plotHeight;

  // One path per run of points; a gap longer than a few steps is a gap.
  const paths = (values: number[]): { line: string; area: string }[] => {
    const runs: { line: string; area: string }[] = [];
    let run: [number, number][] = [];
    const flush = () => {
      if (run.length === 0) return;
      const line = run.map(([px, py], i) => `${i === 0 ? "M" : "L"}${px.toFixed(1)},${py.toFixed(1)}`).join("");
      const first = run[0] ?? [0, 0];
      const last = run.at(-1) ?? [0, 0];
      const base = (PAD_TOP + plotHeight).toFixed(1);
      runs.push({ line, area: `${line}L${last[0].toFixed(1)},${base}L${first[0].toFixed(1)},${base}Z` });
      run = [];
    };
    for (let i = 0; i < t.length; i += 1) {
      const time = t[i] ?? 0;
      if (time < start) continue;
      if (i > 0 && time - (t[i - 1] ?? 0) > step * 3) flush();
      run.push([x(time), y(values[i] ?? 0)]);
    }
    flush();
    return runs;
  };

  const onMove = (event: PointerEvent<SVGSVGElement>): void => {
    const box = event.currentTarget.getBoundingClientRect();
    const time = start + ((event.clientX - box.left) / box.width) * span;
    let best: number | null = null;
    let distance = Number.POSITIVE_INFINITY;
    for (let i = 0; i < t.length; i += 1) {
      const d = Math.abs((t[i] ?? 0) - time);
      if (d < distance) {
        distance = d;
        best = i;
      }
    }
    setHover(best !== null && distance <= Math.max(step * 2, span / 200) ? best : null);
  };

  const hoverTime = hover === null ? null : (t[hover] ?? null);
  const tooltipLeft = hoverTime === null ? 0 : x(hoverTime);

  return (
    <div className="chart" ref={wrapRef}>
      <svg
        width={width}
        height={CHART_HEIGHT}
        viewBox={`0 0 ${width} ${CHART_HEIGHT}`}
        role="img"
        aria-label={lines.map((line) => line.label).join(", ")}
        onPointerMove={onMove}
        onPointerLeave={() => setHover(null)}
      >
        <defs>
          {lines.map((line, i) => (
            <linearGradient key={line.label} id={`${id}-${i}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={line.color} stopOpacity={i === 0 ? 0.28 : 0.12} />
              <stop offset="100%" stopColor={line.color} stopOpacity={0} />
            </linearGradient>
          ))}
        </defs>
        {[0, 0.5, 1].map((fraction) => (
          <g key={fraction}>
            <line
              className="chart-grid"
              x1={0}
              x2={width}
              y1={PAD_TOP + plotHeight * (1 - fraction)}
              y2={PAD_TOP + plotHeight * (1 - fraction)}
            />
            {fraction > 0 && (
              <text className="chart-axis" x={width - 4} y={PAD_TOP + plotHeight * (1 - fraction) + 11} textAnchor="end">
                {format(top * fraction)}
              </text>
            )}
          </g>
        ))}
        {lines.map((line, i) =>
          paths(line.values).map((path, j) => (
            <g key={`${line.label}-${j}`}>
              <path d={path.area} fill={`url(#${id}-${i})`} />
              <path d={path.line} fill="none" stroke={line.color} strokeWidth={1.5} strokeLinejoin="round" />
            </g>
          )),
        )}
        <text className="chart-axis" x={2} y={CHART_HEIGHT - 4}>
          {timeLabel(start, span)}
        </text>
        <text className="chart-axis" x={width - 2} y={CHART_HEIGHT - 4} textAnchor="end">
          {timeLabel(end, span)}
        </text>
        {hover !== null && hoverTime !== null && (
          <g>
            <line className="chart-cursor" x1={tooltipLeft} x2={tooltipLeft} y1={PAD_TOP} y2={PAD_TOP + plotHeight} />
            {lines.map((line) => (
              <circle
                key={line.label}
                cx={tooltipLeft}
                cy={y(line.values[hover] ?? 0)}
                r={3}
                fill="var(--void)"
                stroke={line.color}
                strokeWidth={1.5}
              />
            ))}
          </g>
        )}
      </svg>
      {hover !== null && hoverTime !== null && (
        <div
          className="chart-tip"
          style={tooltipLeft > width / 2 ? { right: width - tooltipLeft + 10 } : { left: tooltipLeft + 10 }}
        >
          <span className="faint">{new Date(hoverTime * 1000).toLocaleString([], { dateStyle: "short", timeStyle: "medium" })}</span>
          {lines.map((line) => (
            <span key={line.label}>
              <i style={{ background: line.color }} />
              {line.label} <b>{format(line.values[hover] ?? 0)}</b>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

// --- Cards ----------------------------------------------------------------------------------

const ACCENT = "var(--accent)";
const SECOND = "var(--accent-2)";

const percent = (value: number): string => `${Math.round(value)}%`;

function Card({
  title,
  value,
  sub,
  children,
}: {
  title: string;
  value: string;
  sub?: string;
  children: ReactNode;
}): JSX.Element {
  return (
    <section className="metric-card">
      <header>
        <span className="label">{title}</span>
        <span className="metric-card-value num">{value}</span>
        {sub !== undefined && <span className="metric-card-sub muted truncate">{sub}</span>}
      </header>
      {children}
    </section>
  );
}

function Bar({ used, total, label }: { used: number; total: number; label: string }): JSX.Element {
  const fraction = total > 0 ? Math.min(1, used / total) : 0;
  const tone = fraction > 0.92 ? "err" : fraction > 0.8 ? "warn" : "ok";
  return (
    <div className="usage">
      <div className="usage-head">
        <span className="truncate">{label}</span>
        <span className="num muted">
          {formatBytes(used)} / {formatBytes(total)}
        </span>
      </div>
      <div className={`usage-track tone-${tone}`}>
        <span style={{ width: `${(fraction * 100).toFixed(1)}%` }} />
      </div>
    </div>
  );
}

function CoreStrip({ cores }: { cores: number[] }): JSX.Element {
  return (
    <div className="cores" aria-label="Load per logical processor">
      {cores.map((load, i) => (
        <span key={i} title={`CPU ${i}: ${load.toFixed(0)}%`}>
          <i style={{ height: `${Math.max(2, Math.min(100, load))}%` }} />
        </span>
      ))}
    </div>
  );
}

// --- Analytics tab ---------------------------------------------------------------------------

export function AnalyticsPanel({ metrics, actions }: { metrics: MetricsState; actions: MetricsActions }): JSX.Element {
  const [range, setRange] = useState<Range>("live");
  const { info, latest } = metrics;

  // Live samples while the tab is open, and the last five minutes to start from.
  useEffect(() => {
    actions.watch(true);
    actions.history("5m");
    return () => actions.watch(false);
  }, [actions]);

  useEffect(() => {
    if (range === "live") return;
    actions.history(range);
    const timer = window.setInterval(() => actions.history(range), RANGE_REFRESH_MS[range]);
    return () => window.clearInterval(timer);
  }, [actions, range]);

  const now = latest === null ? Math.floor(Date.now() / 1000) : Math.floor(latest.t / 1000);
  const series = useMemo(
    () => (range === "live" ? liveSeries(metrics.history["5m"], metrics.live, now) : null),
    [range, metrics.history, metrics.live, now],
  );
  const shown: Series =
    series ?? (range !== "live" && metrics.history[range] !== undefined ? fromHistory(metrics.history[range]) : EMPTY_SERIES);
  const span = range === "live" ? 300 : RANGE_SECONDS[range];
  const end = range === "live" ? now : Math.floor(Date.now() / 1000);

  if (info === null || latest === null) {
    return (
      <div className="empty">{metrics.error ?? "Waiting for the machine's first numbers…"}</div>
    );
  }

  const ranges: [Range, string][] = [
    ["live", RANGE_LABEL.live],
    ...info.ranges.filter((name) => name !== "5m").map((name): [Range, string] => [name, RANGE_LABEL[name]]),
  ];
  const chart = (lines: Line[], format: (value: number) => string, max?: number) => (
    <TimeChart t={shown.t} lines={lines} step={shown.step} span={span} end={end} max={max} format={format} />
  );
  const memoryFraction = latest.mem_total > 0 ? (latest.mem_used / latest.mem_total) * 100 : 0;

  return (
    <div className="analytics">
      <div className="analytics-head">
        <div className="strip analytics-strip">
          <Metric label="Host">{info.hostname || "—"}</Metric>
          <Metric label="System">{info.os}</Metric>
          <Metric label="Up for">{formatDuration(latest.uptime)}</Metric>
          <Metric label="Processes">{latest.processes}</Metric>
        </div>
        <Segmented small label="Time range" options={ranges} value={range} onChange={setRange} />
      </div>
      {metrics.error !== null && <div className="empty">{metrics.error}</div>}

      <div className="analytics-grid">
        <Card
          title="CPU"
          value={percent(latest.cpu)}
          sub={`${info.cpu.name} · ${info.cpu.cores} cores, ${info.cpu.threads} threads`}
        >
          {chart([{ label: "CPU", values: shown.cpu, color: ACCENT }], percent, 100)}
          <CoreStrip cores={latest.cores} />
        </Card>

        <Card
          title="Memory"
          value={percent(memoryFraction)}
          sub={`${formatBytes(latest.mem_used)} of ${formatBytes(latest.mem_total)} · committed ${formatBytes(latest.commit_used)} of ${formatBytes(latest.commit_limit)}`}
        >
          {chart([{ label: "In use", values: shown.mem, color: ACCENT }], (value) => formatBytes(value, 0), latest.mem_total)}
        </Card>

        {latest.gpus.map((gpu) => (
          <Card
            key={gpu.name}
            title="GPU"
            value={percent(gpu.util)}
            sub={`${gpu.name} · ${formatBytes(gpu.dedicated_used)} of ${formatBytes(gpu.dedicated_total)} VRAM`}
          >
            {chart([{ label: "GPU", values: shown.gpu, color: ACCENT }], percent, 100)}
            <Bar used={gpu.dedicated_used} total={gpu.dedicated_total} label="Dedicated memory" />
          </Card>
        ))}

        <Card title="Network" value={`↓ ${formatRate(latest.net_rx)}`} sub={`↑ ${formatRate(latest.net_tx)}`}>
          {chart(
            [
              { label: "Received", values: shown.rx, color: ACCENT },
              { label: "Sent", values: shown.tx, color: SECOND },
            ],
            formatRate,
          )}
          <div className="legend">
            <span>
              <i style={{ background: ACCENT }} />
              Received
            </span>
            <span>
              <i style={{ background: SECOND }} />
              Sent
            </span>
            {latest.adapters.map((adapter) => (
              <span key={adapter.name} className="faint">
                {adapter.name}
              </span>
            ))}
          </div>
        </Card>

        <Card title="Disks" value={`R ${formatRate(latest.disk_read)}`} sub={`W ${formatRate(latest.disk_write)}`}>
          {chart(
            [
              { label: "Read", values: shown.read, color: ACCENT },
              { label: "Write", values: shown.write, color: SECOND },
            ],
            formatRate,
          )}
          {latest.volumes.map((volume) => (
            <Bar
              key={volume.name}
              used={volume.total - volume.free}
              total={volume.total}
              label={volume.label === "" ? volume.name : `${volume.name} ${volume.label}`}
            />
          ))}
        </Card>
      </div>
    </div>
  );
}

// --- Processes tab ---------------------------------------------------------------------------

type SortKey = "name" | "pid" | "user" | "cpu" | "memory" | "threads";

const COLUMNS: [SortKey, string, string][] = [
  ["name", "Name", ""],
  ["pid", "PID", "num hide-narrow"],
  ["user", "User", "hide-narrow"],
  ["cpu", "CPU", "num"],
  ["memory", "Memory", "num"],
  ["threads", "Threads", "num hide-narrow"],
];

const REFRESH_PROCESSES_MS = 2_000;

export function ProcessesPanel({ metrics, actions }: { metrics: MetricsState; actions: MetricsActions }): JSX.Element {
  const [sort, setSort] = useState<{ key: SortKey; descending: boolean }>({ key: "cpu", descending: true });
  const [filter, setFilter] = useState("");

  useEffect(() => {
    actions.processes();
    const timer = window.setInterval(() => actions.processes(), REFRESH_PROCESSES_MS);
    return () => window.clearInterval(timer);
  }, [actions]);

  const rows = metrics.processes?.rows ?? null;
  const shown = useMemo(() => {
    if (rows === null) return [];
    const needle = filter.trim().toLowerCase();
    const matching =
      needle === ""
        ? rows
        : rows.filter(
            (row) =>
              row.name.toLowerCase().includes(needle) ||
              row.user.toLowerCase().includes(needle) ||
              String(row.pid) === needle,
          );
    const value = (row: ProcessRow): number | string => row[sort.key];
    return [...matching].sort((a, b) => {
      const left = value(a);
      const right = value(b);
      const order =
        typeof left === "string" && typeof right === "string"
          ? left.localeCompare(right, undefined, { sensitivity: "base" })
          : Number(left) - Number(right);
      return sort.descending ? -order : order;
    });
  }, [rows, filter, sort]);

  if (rows === null) {
    return <div className="empty">{metrics.error ?? "Asking the machine for its processes…"}</div>;
  }

  const totalCpu = rows.reduce((sum, row) => sum + row.cpu, 0);
  const totalMemory = rows.reduce((sum, row) => sum + row.memory, 0);
  const heaviest = Math.max(1, ...rows.map((row) => row.memory));

  const header = (key: SortKey, label: string, className: string) => (
    <th key={key} className={className} aria-sort={sort.key === key ? (sort.descending ? "descending" : "ascending") : "none"}>
      <button
        type="button"
        className="th-sort"
        onClick={() =>
          setSort((previous) =>
            previous.key === key
              ? { key, descending: !previous.descending }
              : { key, descending: key === "cpu" || key === "memory" || key === "threads" },
          )
        }
      >
        {label}
        {sort.key === key && <span aria-hidden>{sort.descending ? " ↓" : " ↑"}</span>}
      </button>
    </th>
  );

  return (
    <div className="processes">
      <div className="processes-head">
        <input
          className="input"
          type="search"
          placeholder="Filter by name, user or PID"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          aria-label="Filter processes"
        />
        <span className="num muted">
          {shown.length === rows.length ? rows.length : `${shown.length} of ${rows.length}`} processes · CPU{" "}
          {percent(totalCpu)} · {formatBytes(totalMemory)}
        </span>
      </div>
      <div className="table-wrap">
        <table className="table processes-table">
          <thead>
            <tr>{COLUMNS.map(([key, label, className]) => header(key, label, className))}</tr>
          </thead>
          <tbody>
            {shown.map((row) => (
              <tr key={`${row.pid}-${row.started}`}>
                <td>
                  <span className="truncate" title={row.name}>
                    {row.name}
                  </span>
                </td>
                <td className="num muted hide-narrow">{row.pid}</td>
                <td className="muted hide-narrow">
                  <span className="truncate">{row.user || "—"}</span>
                </td>
                <td className="num">
                  <span className="cell-bar" style={{ "--fill": `${Math.min(100, row.cpu)}%` } as CSSProperties}>
                    {row.cpu.toFixed(1)}%
                  </span>
                </td>
                <td className="num">
                  <span
                    className="cell-bar"
                    style={{ "--fill": `${((row.memory / heaviest) * 100).toFixed(1)}%` } as CSSProperties}
                  >
                    {formatBytes(row.memory)}
                  </span>
                </td>
                <td className="num muted hide-narrow">{row.threads}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
