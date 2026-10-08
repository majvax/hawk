import { type FormEvent, type JSX, useCallback, useEffect, useState } from "react";

import {
  type EnrollmentCode,
  type Share,
  createEnrollmentCode,
  describeShareTerms,
  formatTime,
  listShares,
  removeMachine,
  renameMachine,
  shareMachine,
  unshareMachine,
} from "../api.js";
import type { Machine, Role } from "../protocol.js";
import { type ConnectionStatus, useDashboard } from "../useDashboard.js";
import { useRemoteInput } from "../useRemoteInput.js";

const ROLE_LABEL: Record<Role, string> = { owner: "owner", control: "can control", view: "view only" };

function installCommand(enrollment: EnrollmentCode): string {
  const pin = enrollment.relayPin === null ? "" : ` -RelayPin ${enrollment.relayPin}`;
  return `powershell -ExecutionPolicy Bypass -File scripts\\install-service.ps1 -EnrollCode ${enrollment.code}${pin}`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "request failed";
}

export function MachinesPage({ onSessionEnded }: { onSessionEnded: () => void }): JSX.Element {
  const { machines, status, retryAt, viewingId, canvasRef, startView, stopView, sendInput, reconnectNow } =
    useDashboard(onSessionEnded);
  const [managingId, setManagingId] = useState<string | null>(null);
  const [enrollment, setEnrollment] = useState<EnrollmentCode | null>(null);
  const [error, setError] = useState<string | null>(null);

  const viewing = machines.find((machine) => machine.id === viewingId) ?? null;
  const managing = machines.find((machine) => machine.id === managingId && machine.role === "owner") ?? null;

  // Nothing to send input to unless the stream is actually up, and the
  // relay would drop it from a view-only share anyway.
  const canControl = viewing !== null && viewing.role !== "view" && viewing.online && status === "open";
  const input = useRemoteInput(canvasRef, canControl, sendInput);

  const addMachine = async (): Promise<void> => {
    setError(null);
    try {
      setEnrollment(await createEnrollmentCode());
    } catch (caught) {
      setError(errorMessage(caught));
    }
  };

  return (
    <div className="stack">
      <div className="row">
        <p className="muted grow">
          <StatusDot status={status} /> relay link {status}
          {status === "reconnecting" && retryAt !== null && (
            <>
              {" "}
              — retrying in <Countdown until={retryAt} />{" "}
              <button type="button" onClick={reconnectNow}>
                Retry now
              </button>
            </>
          )}
        </p>
        <button type="button" onClick={() => void addMachine()}>
          Add machine
        </button>
      </div>
      {error !== null && <p className="error">{error}</p>}

      {enrollment !== null && (
        <div className="notice">
          <p>
            Enrollment code: <code className="code">{enrollment.code}</code> — single use, expires{" "}
            {formatTime(enrollment.expiresAt)}. On the PC, from an elevated PowerShell in the Hawk folder:
          </p>
          <pre>{installCommand(enrollment)}</pre>
          <p className="muted">
            The machine shows up here once it connects. This code won't be shown again.
            {enrollment.relayPin !== null &&
              " -RelayPin makes the machine accept only this relay's TLS key, even from a certificate it would otherwise trust."}
          </p>
          <button type="button" onClick={() => setEnrollment(null)}>
            Done
          </button>
        </div>
      )}

      {machines.length === 0 ? (
        <p className="muted">No machines yet. Add one, or ask someone to share theirs with you.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Machine</th>
              <th>Status</th>
              <th>Access</th>
              <th>Watching</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {machines.map((machine) => (
              <tr key={machine.id}>
                <td>
                  {machine.name}
                  {machine.name !== machine.hostname && <span className="muted"> ({machine.hostname})</span>}
                  {machine.role === "owner" && <KeyBadge storage={machine.keyStorage} />}
                </td>
                <td>
                  <span className={`dot ${machine.online ? "dot-open" : "dot-closed"}`} aria-hidden />
                  {machine.online
                    ? "online"
                    : machine.lastSeenAt === null
                      ? "never connected"
                      : `last seen ${formatTime(machine.lastSeenAt)}`}
                </td>
                <td>
                  {machine.role === "owner" ? "owner" : `${ROLE_LABEL[machine.role]} · ${machine.ownerEmail}`}
                  {machine.role !== "owner" && (machine.accessExpiresAt !== null || machine.singleView) && (
                    <span className="badge">
                      {describeShareTerms({ startsAt: null, expiresAt: machine.accessExpiresAt, singleView: machine.singleView })}
                    </span>
                  )}
                </td>
                <td className="muted">{machine.viewers === null ? "" : machine.viewers.join(", ") || "nobody"}</td>
                <td className="actions">
                  {viewingId === machine.id ? (
                    <button type="button" onClick={stopView}>
                      Stop
                    </button>
                  ) : (
                    <button type="button" disabled={!machine.online} onClick={() => startView(machine.id)}>
                      View
                    </button>
                  )}
                  {machine.role === "owner" && (
                    <button
                      type="button"
                      className={managingId === machine.id ? "active" : ""}
                      onClick={() => setManagingId(managingId === machine.id ? null : machine.id)}
                    >
                      Manage
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {managing !== null && <ManagePanel key={managing.id} machine={managing} onClose={() => setManagingId(null)} />}

      <section style={{ display: viewing === null ? "none" : "block" }}>
        <div className="row">
          <h2>{viewing?.name ?? "Live view"}</h2>
          {viewing !== null && viewing.role === "view" && <span className="badge">view only</span>}
        </div>
        {viewing !== null && status !== "open" && (
          <p className="muted">Connection to the relay lost. The view resumes once it's back.</p>
        )}
        {viewing !== null && status === "open" && !viewing.online && (
          <p className="muted">{viewing.name} is offline. The view resumes when it reconnects.</p>
        )}
        {viewing !== null && viewing.singleView && (
          <p className="muted">One viewing only: once you stop watching, this machine is no longer shared with you.</p>
        )}
        {canControl && (
          <p className="muted">
            {input.active ? (
              <>
                Your mouse and keyboard are going to {viewing?.name}. The screen doesn't show the machine's own
                pointer — yours is in the same place.{" "}
                <button type="button" onClick={input.release}>
                  Stop controlling
                </button>{" "}
                Shortcuts the browser keeps for itself (Ctrl+W, Alt+Tab), and Ctrl+Alt+Del, stay on your own
                computer.
              </>
            ) : (
              "Click the screen to control it with your mouse and keyboard."
            )}
          </p>
        )}
        <canvas
          ref={canvasRef}
          className={["screen", canControl && "controllable", input.active && "controlling"].filter(Boolean).join(" ")}
          // Focusable only when it can be controlled: focusing it is what
          // starts sending input, and Tab shouldn't land on a dead screen.
          tabIndex={canControl ? 0 : -1}
        />
      </section>
    </div>
  );
}

function ManagePanel({ machine, onClose }: { machine: Machine; onClose: () => void }): JSX.Element {
  const [name, setName] = useState(machine.name);
  const [shares, setShares] = useState<Share[]>([]);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Share["role"]>("view");
  const [duration, setDuration] = useState<Duration>("forever");
  const [until, setUntil] = useState("");
  const [startLater, setStartLater] = useState(false);
  const [startAt, setStartAt] = useState("");
  const [singleView, setSingleView] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async (): Promise<void> => {
    try {
      setShares(await listShares(machine.id));
    } catch (caught) {
      setError(errorMessage(caught));
    }
  }, [machine.id]);

  useEffect(() => {
    void refresh();
    // Temporary shares start, expire and get used up on their own.
    const timer = window.setInterval(() => void refresh(), 30_000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const run = async (action: () => Promise<unknown>): Promise<boolean> => {
    setError(null);
    try {
      await action();
      await refresh();
      return true;
    } catch (caught) {
      setError(errorMessage(caught));
      return false;
    }
  };

  const submitShare = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    const startsAt = startLater ? fromLocalInput(startAt) : null;
    const begins = startsAt ?? Math.floor(Date.now() / 1000);
    const expiresAt =
      duration === "forever" ? null : duration === "until" ? fromLocalInput(until) : begins + DURATION_SECONDS[duration];
    // An unreadable date must not quietly become "now" or "until revoked".
    if ((startLater && startsAt === null) || (duration !== "forever" && expiresAt === null)) {
      setError("enter a valid date and time");
      return;
    }
    if (await run(() => shareMachine(machine.id, email, { role, startsAt, expiresAt, singleView }))) setEmail("");
  };

  // Pushes a temporary share's end back by an hour (from now if it's close).
  const extend = (share: Share): Promise<boolean> => {
    const from = Math.max(share.expiresAt ?? 0, Math.floor(Date.now() / 1000));
    return run(() => shareMachine(machine.id, share.email, { ...share, expiresAt: from + 3600 }));
  };

  const submitRename = (event: FormEvent): void => {
    event.preventDefault();
    void run(() => renameMachine(machine.id, name));
  };

  const remove = (): void => {
    const confirmed = window.confirm(
      `Remove ${machine.name}? It will be disconnected, everyone it's shared with loses access, and it needs a new enrollment code to come back.`,
    );
    if (confirmed) void run(() => removeMachine(machine.id)).then((ok) => ok && onClose());
  };

  return (
    <section className="panel stack">
      <div className="row">
        <h2 className="grow">Manage {machine.name}</h2>
        <button type="button" onClick={onClose}>
          Close
        </button>
      </div>
      {error !== null && <p className="error">{error}</p>}

      <form className="row" onSubmit={submitRename}>
        <label className="grow">
          Name
          <input value={name} maxLength={64} onChange={(e) => setName(e.target.value)} required />
        </label>
        <button type="submit" className="align-end" disabled={name.trim() === machine.name}>
          Rename
        </button>
      </form>

      <div>
        <h2>Shared with</h2>
        {shares.length === 0 ? (
          <p className="muted">Only you.</p>
        ) : (
          <table>
            <tbody>
              {shares.map((share) => (
                <tr key={share.userId}>
                  <td>
                    {share.email}
                    {share.startsAt !== null && share.startsAt > Date.now() / 1000 && (
                      <span className="badge">not started</span>
                    )}
                  </td>
                  <td className="muted">{describeShareTerms(share) || "until revoked"}</td>
                  <td>
                    <select
                      value={share.role}
                      onChange={(e) =>
                        void run(() =>
                          shareMachine(machine.id, share.email, { ...share, role: e.target.value as Share["role"] }),
                        )
                      }
                    >
                      <option value="view">view only</option>
                      <option value="control">can control</option>
                    </select>
                  </td>
                  <td className="actions">
                    {share.expiresAt !== null && (
                      <button type="button" onClick={() => void extend(share)}>
                        +1 h
                      </button>
                    )}
                    <button type="button" onClick={() => void run(() => unshareMachine(machine.id, share.userId))}>
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <form className="row share-form" onSubmit={(e) => void submitShare(e)}>
          <input
            type="email"
            placeholder="their account email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
          <select value={role} onChange={(e) => setRole(e.target.value as Share["role"])}>
            <option value="view">view only</option>
            <option value="control">can control</option>
          </select>
          <select value={duration} onChange={(e) => setDuration(e.target.value as Duration)} aria-label="For how long">
            {DURATIONS.map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
          {duration === "until" && (
            <input
              type="datetime-local"
              className="when"
              aria-label="Share until"
              value={until}
              onChange={(e) => setUntil(e.target.value)}
              required
            />
          )}
          <button type="submit">Share</button>
        </form>
        <div className="row share-options">
          <label className="check">
            <input type="checkbox" checked={startLater} onChange={(e) => setStartLater(e.target.checked)} />
            Start later
          </label>
          {startLater && (
            <input
              type="datetime-local"
              className="when"
              aria-label="Share starts at"
              value={startAt}
              onChange={(e) => setStartAt(e.target.value)}
              required
            />
          )}
          <label className="check">
            <input type="checkbox" checked={singleView} onChange={(e) => setSingleView(e.target.checked)} />
            One viewing only
          </label>
        </div>
        <p className="muted">
          They need an account on this server first. "View only" can watch the screen but never send input. A
          temporary share is revoked automatically when it runs out, cutting off a live view; "one viewing only"
          ends the share once they stop watching. Sharing again with the same person replaces the terms.
        </p>
      </div>

      <div>
        <button type="button" className="danger" onClick={remove}>
          Remove machine
        </button>
      </div>
    </section>
  );
}

type Duration = "forever" | "30m" | "1h" | "2h" | "8h" | "1d" | "1w" | "until";

const DURATIONS: [Duration, string][] = [
  ["forever", "until revoked"],
  ["30m", "for 30 minutes"],
  ["1h", "for 1 hour"],
  ["2h", "for 2 hours"],
  ["8h", "for 8 hours"],
  ["1d", "for 1 day"],
  ["1w", "for 1 week"],
  ["until", "until…"],
];

const DURATION_SECONDS: Record<Exclude<Duration, "forever" | "until">, number> = {
  "30m": 30 * 60,
  "1h": 60 * 60,
  "2h": 2 * 60 * 60,
  "8h": 8 * 60 * 60,
  "1d": 24 * 60 * 60,
  "1w": 7 * 24 * 60 * 60,
};

// A <input type="datetime-local"> value (local time) as unix seconds.
function fromLocalInput(value: string): number | null {
  const millis = new Date(value).getTime();
  return Number.isNaN(millis) ? null : Math.floor(millis / 1000);
}

// Where the machine keeps the key it authenticates with, as it reports it.
function KeyBadge({ storage }: { storage: Machine["keyStorage"] }): JSX.Element {
  if (storage === null) {
    return (
      <span className="badge warn" title="Enrolled before key-based authentication; remove and enroll it again">
        re-enroll needed
      </span>
    );
  }
  return storage === "tpm" ? (
    <span className="badge" title="Its key lives in the TPM and can't be copied off the machine">
      TPM
    </span>
  ) : (
    <span className="badge" title="No usable TPM: its key is in the Windows software key store">
      software key
    </span>
  );
}

// Seconds left until `until` (ms since epoch), ticking.
function Countdown({ until }: { until: number }): JSX.Element {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 500);
    return () => window.clearInterval(timer);
  }, []);
  return <>{Math.max(0, Math.ceil((until - now) / 1000))}s</>;
}

function StatusDot({ status }: { status: ConnectionStatus }): JSX.Element {
  return <span aria-hidden className={`dot dot-${status}`} />;
}
