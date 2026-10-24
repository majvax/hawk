import { type JSX, useCallback, useEffect, useRef, useState } from "react";

import { type ActivityEvent, type ActivityPage, type Category, CATEGORIES, describeDetails, eventLabel } from "../activity.js";
import { describeUserAgent, formatAgo, formatTime, listActivity, listAllActivity } from "../api.js";
import { Alert, errorMessage, useNow } from "../ui.js";

const PAGE = 50;

const RANGES: [string, string, number | null][] = [
  ["day", "Last 24 hours", 86_400],
  ["week", "Last 7 days", 7 * 86_400],
  ["month", "Last 30 days", 30 * 86_400],
  ["all", "Any time", null],
];

// The audit log as a table: one machine's (`machine`), the signed-in
// account's (neither), or everyone's for the admin (`all`). The relay
// decides what each may see; this only asks.
export function ActivityTable({
  machine,
  all = false,
  showMachine = true,
}: {
  machine?: string;
  all?: boolean;
  showMachine?: boolean;
}): JSX.Element {
  const [category, setCategory] = useState<Category>("all");
  const [range, setRange] = useState("week");
  const [events, setEvents] = useState<ActivityEvent[] | null>(null);
  const [next, setNext] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const now = useNow(30_000);

  // The window's start, fixed when the first page loads so "Load more"
  // continues the same window instead of one that moved since.
  const since = useRef<number | undefined>(undefined);
  // Bumped by every first-page load: an answer to an older one (filters
  // changed while it was on its way) is dropped, not mixed in.
  const generation = useRef(0);

  const fetchPage = useCallback(
    (before?: number): Promise<ActivityPage> => {
      const filter = { machine, category, since: since.current, before, limit: PAGE };
      return all ? listAllActivity(filter) : listActivity(filter);
    },
    [machine, category, all],
  );

  const load = useCallback(
    async (before?: number): Promise<void> => {
      if (before === undefined) {
        generation.current += 1;
        const seconds = RANGES.find(([id]) => id === range)?.[2] ?? null;
        since.current = seconds === null ? undefined : Date.now() / 1000 - seconds;
      }
      const current = generation.current;
      setBusy(true);
      setError(null);
      try {
        const page = await fetchPage(before);
        if (current !== generation.current) return;
        setEvents((shown) => (before === undefined ? page.events : [...(shown ?? []), ...page.events]));
        setNext(page.next);
      } catch (caught) {
        if (current === generation.current) setError(errorMessage(caught, "failed to load"));
      } finally {
        if (current === generation.current) setBusy(false);
      }
    },
    [fetchPage, range],
  );

  useEffect(() => {
    setEvents(null);
    void load();
  }, [load]);

  const columns = showMachine ? 6 : 5;

  return (
    <div className="block">
      <div className="form-row tight" style={{ alignItems: "center" }}>
        <select
          className="select"
          aria-label="Kind of event"
          value={category}
          onChange={(e) => setCategory(e.target.value as Category)}
        >
          {CATEGORIES.map(([id, label]) => (
            <option key={id} value={id}>
              {label}
            </option>
          ))}
        </select>
        <select className="select" aria-label="When" value={range} onChange={(e) => setRange(e.target.value)}>
          {RANGES.map(([id, label]) => (
            <option key={id} value={id}>
              {label}
            </option>
          ))}
        </select>
        <button type="button" className="btn btn-sm" disabled={busy} onClick={() => void load()}>
          Refresh
        </button>
      </div>
      {error !== null && <Alert>{error}</Alert>}
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>When</th>
              <th>Who</th>
              {showMachine && <th>Machine</th>}
              <th>Event</th>
              <th>Details</th>
              <th>IP address</th>
            </tr>
          </thead>
          <tbody>
            {events !== null && events.length === 0 && (
              <tr>
                <td colSpan={columns} className="muted">
                  Nothing recorded.
                </td>
              </tr>
            )}
            {events === null && (
              <tr>
                <td colSpan={columns} className="muted">
                  Loading…
                </td>
              </tr>
            )}
            {events?.map((event) => (
              <tr key={event.id}>
                <td className="num muted" title={formatTime(event.at)}>
                  {formatAgo(event.at, now)}
                </td>
                <td>
                  <span className="truncate">{event.userEmail ?? <span className="faint">unknown account</span>}</span>
                </td>
                {showMachine && (
                  <td className={event.machineName === null ? "faint" : undefined}>
                    <span className="truncate">{event.machineName ?? "—"}</span>
                  </td>
                )}
                <td>{eventLabel(event.kind)}</td>
                <td className="muted">
                  <span className="truncate">{describeDetails(event)}</span>
                </td>
                <td className="mono" title={event.userAgent === null ? undefined : describeUserAgent(event.userAgent)}>
                  {event.ip ?? <span className="faint">—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {next !== null && (
        <div>
          <button type="button" className="btn btn-sm" disabled={busy} onClick={() => void load(next)}>
            {busy ? "Loading…" : "Load more"}
          </button>
        </div>
      )}
    </div>
  );
}
