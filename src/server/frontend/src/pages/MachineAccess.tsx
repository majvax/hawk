// The owner's tabs on a machine: who it's shared with, and the machine
// itself (name, key, removal).
import { type FormEvent, type JSX, useCallback, useEffect, useState } from "react";

import {
  type Share,
  describeShareTerms,
  listShares,
  removeMachine,
  renameMachine,
  shareMachine,
  unshareMachine,
} from "../api.js";
import type { Machine } from "../protocol.js";
import { Alert, ConfirmButton, Segmented, Tag, errorMessage } from "../ui.js";

const SHARE_ROLES = [
  ["view", "View only"],
  ["control", "Can control"],
] as const;

type Duration = "forever" | "30m" | "1h" | "2h" | "8h" | "1d" | "1w" | "until";

const DURATIONS: [Duration, string][] = [
  ["forever", "Until revoked"],
  ["30m", "For 30 minutes"],
  ["1h", "For 1 hour"],
  ["2h", "For 2 hours"],
  ["8h", "For 8 hours"],
  ["1d", "For 1 day"],
  ["1w", "For 1 week"],
  ["until", "Until a set time…"],
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

export function SharingPanel({ machine }: { machine: Machine }): JSX.Element {
  const [shares, setShares] = useState<Share[] | null>(null);
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

  const now = Date.now() / 1000;

  return (
    <div className="pane-body">
      {error !== null && <Alert>{error}</Alert>}

      <div className="block">
        <div className="block-head">
          <span className="label">Shared with</span>
          {shares !== null && <span className="num faint">{shares.length}</span>}
        </div>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Account</th>
                <th>Access</th>
                <th>Window</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {shares !== null && shares.length === 0 && (
                <tr>
                  <td colSpan={4} className="muted">
                    Only you. Share it below.
                  </td>
                </tr>
              )}
              {shares?.map((share) => (
                <tr key={share.userId}>
                  <td>
                    <span className="cell">
                      <span className="truncate">{share.email}</span>
                      {share.startsAt !== null && share.startsAt > now && <Tag tone="idle">Scheduled</Tag>}
                    </span>
                  </td>
                  <td>
                    <Segmented
                      small
                      label={`Access for ${share.email}`}
                      options={SHARE_ROLES}
                      value={share.role}
                      onChange={(next) => void run(() => shareMachine(machine.id, share.email, { ...share, role: next }))}
                    />
                  </td>
                  <td className="num muted">{describeShareTerms(share) || "until revoked"}</td>
                  <td className="actions">
                    {share.expiresAt !== null && (
                      <button type="button" className="btn btn-sm" onClick={() => void extend(share)}>
                        +1 h
                      </button>
                    )}
                    <ConfirmButton
                      small
                      confirmLabel="Confirm"
                      onConfirm={() => void run(() => unshareMachine(machine.id, share.userId))}
                    >
                      Revoke
                    </ConfirmButton>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <form className="block" onSubmit={(e) => void submitShare(e)}>
        <span className="label">Share with someone</span>
        <div className="form-row">
          <label className="field">
            <span className="label faint">Account email</span>
            <input
              className="input"
              type="email"
              placeholder="name@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </label>
          <div className="field" style={{ flex: "none", minWidth: 0 }}>
            <span className="label faint">Access</span>
            <Segmented label="Access" options={SHARE_ROLES} value={role} onChange={setRole} />
          </div>
          <label className="field" style={{ flex: "none", minWidth: 170 }}>
            <span className="label faint">For how long</span>
            <select className="select" value={duration} onChange={(e) => setDuration(e.target.value as Duration)}>
              {DURATIONS.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          {duration === "until" && (
            <label className="field" style={{ flex: "none", minWidth: 0 }}>
              <span className="label faint">Ends</span>
              <input
                className="input"
                type="datetime-local"
                value={until}
                onChange={(e) => setUntil(e.target.value)}
                required
              />
            </label>
          )}
        </div>
        <div className="form-row tight">
          <label className="check">
            <input type="checkbox" checked={startLater} onChange={(e) => setStartLater(e.target.checked)} />
            Start later
          </label>
          {startLater && (
            <input
              className="input"
              type="datetime-local"
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
          <button type="submit" className="btn btn-primary" style={{ marginLeft: 8 }}>
            Share
          </button>
        </div>
        <p className="prose" style={{ fontSize: 12 }}>
          They need an account on this server first. View only can watch the screen but never send input. A
          temporary share is revoked when it runs out, cutting off a live view; one viewing only ends the share once
          they stop watching. Sharing again with the same person replaces the terms.
        </p>
      </form>
    </div>
  );
}

export function MachineSettings({ machine, onRemoved }: { machine: Machine; onRemoved: () => void }): JSX.Element {
  const [name, setName] = useState(machine.name);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const run = async (action: () => Promise<unknown>): Promise<boolean> => {
    setError(null);
    setSaved(false);
    try {
      await action();
      return true;
    } catch (caught) {
      setError(errorMessage(caught));
      return false;
    }
  };

  const submitRename = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    if (await run(() => renameMachine(machine.id, name))) setSaved(true);
  };

  return (
    <div className="pane-body">
      {error !== null && <Alert>{error}</Alert>}
      {saved && <Alert ok>Name saved.</Alert>}

      <form className="block" onSubmit={(e) => void submitRename(e)}>
        <span className="label">Name</span>
        <div className="form-row">
          <label className="field">
            <span className="label faint">Display name</span>
            <input
              className="input"
              value={name}
              maxLength={64}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </label>
          <button type="submit" className="btn" disabled={name.trim() === machine.name || name.trim() === ""}>
            Rename
          </button>
        </div>
        <span className="field-hint">Only changes how it's listed here; the host name stays {machine.hostname}.</span>
      </form>

      <div className="block">
        <span className="label">Identity</span>
        <div className="strip" style={{ maxWidth: 520, border: "1px solid var(--line)" }}>
          <div className="metric">
            <span className="label faint">Key storage</span>
            <span className="metric-value">
              <KeyStorage storage={machine.keyStorage} />
            </span>
          </div>
          <div className="metric">
            <span className="label faint">Machine ID</span>
            <span className="metric-value" title={machine.id}>
              {machine.id}
            </span>
          </div>
        </div>
      </div>

      <div className="block">
        <span className="label">Remove</span>
        <div className="danger-zone" style={{ maxWidth: 720 }}>
          <span className="prose" style={{ fontSize: 12 }}>
            Disconnects {machine.name}, revokes everyone it's shared with, and it needs a new enrollment code to come
            back.
          </span>
          <ConfirmButton
            confirmLabel="Confirm removal"
            onConfirm={() => void run(() => removeMachine(machine.id)).then((ok) => ok && onRemoved())}
          >
            Remove machine
          </ConfirmButton>
        </div>
      </div>
    </div>
  );
}

// Where the machine keeps the key it authenticates with, as it reports it.
export function KeyStorage({ storage }: { storage: Machine["keyStorage"] }): JSX.Element {
  if (storage === null) {
    return (
      <Tag tone="err" title="Enrolled before key-based authentication; remove and enroll it again">
        Re-enroll needed
      </Tag>
    );
  }
  return storage === "tpm" ? (
    <span title="Its key lives in the TPM and can't be copied off the machine">TPM</span>
  ) : (
    <span title="No usable TPM: its key is in the Windows software key store">Software</span>
  );
}
