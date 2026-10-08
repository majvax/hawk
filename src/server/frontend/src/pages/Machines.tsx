import { type FormEvent, type JSX, useCallback, useEffect, useState } from "react";

import {
  type EnrollmentCode,
  type Share,
  createEnrollmentCode,
  formatTime,
  listShares,
  removeMachine,
  renameMachine,
  shareMachine,
  unshareMachine,
} from "../api.js";
import type { Machine, Role } from "../protocol.js";
import { type ConnectionStatus, useDashboard } from "../useDashboard.js";

const ROLE_LABEL: Record<Role, string> = { owner: "owner", control: "can control", view: "view only" };

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "request failed";
}

export function MachinesPage({ onSocketClosed }: { onSocketClosed: () => void }): JSX.Element {
  const { machines, status, viewingId, canvasRef, startView, stopView } = useDashboard(onSocketClosed);
  const [managingId, setManagingId] = useState<string | null>(null);
  const [enrollment, setEnrollment] = useState<EnrollmentCode | null>(null);
  const [error, setError] = useState<string | null>(null);

  const viewing = machines.find((machine) => machine.id === viewingId) ?? null;
  const managing = machines.find((machine) => machine.id === managingId && machine.role === "owner") ?? null;

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
          <pre>powershell -ExecutionPolicy Bypass -File scripts\install-service.ps1 -EnrollCode {enrollment.code}</pre>
          <p className="muted">The machine shows up here once it connects. This code won't be shown again.</p>
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
                </td>
                <td>
                  <span className={`dot ${machine.online ? "dot-open" : "dot-closed"}`} aria-hidden />
                  {machine.online
                    ? "online"
                    : machine.lastSeenAt === null
                      ? "never connected"
                      : `last seen ${formatTime(machine.lastSeenAt)}`}
                </td>
                <td>{machine.role === "owner" ? "owner" : `${ROLE_LABEL[machine.role]} · ${machine.ownerEmail}`}</td>
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
        <canvas ref={canvasRef} className="screen" />
      </section>
    </div>
  );
}

function ManagePanel({ machine, onClose }: { machine: Machine; onClose: () => void }): JSX.Element {
  const [name, setName] = useState(machine.name);
  const [shares, setShares] = useState<Share[]>([]);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Share["role"]>("view");
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
    if (await run(() => shareMachine(machine.id, email, role))) setEmail("");
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
                  <td>{share.email}</td>
                  <td>
                    <select
                      value={share.role}
                      onChange={(e) =>
                        void run(() => shareMachine(machine.id, share.email, e.target.value as Share["role"]))
                      }
                    >
                      <option value="view">view only</option>
                      <option value="control">can control</option>
                    </select>
                  </td>
                  <td className="actions">
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
          <button type="submit">Share</button>
        </form>
        <p className="muted">
          They need an account on this server first. "View only" can watch the screen but never send input.
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

function StatusDot({ status }: { status: ConnectionStatus }): JSX.Element {
  return <span aria-hidden className={`dot dot-${status}`} />;
}
