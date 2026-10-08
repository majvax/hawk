import { type FormEvent, type JSX, useCallback, useEffect, useState } from "react";

import {
  type Session,
  changePassword,
  describeUserAgent,
  formatTime,
  listSessions,
  revokeOtherSessions,
  revokeSession,
} from "../api.js";

const MIN_PASSWORD_LENGTH = 10; // mirrors auth::MIN_PASSWORD_LEN

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "request failed";
}

// Every user's own account: password and sign-in sessions.
export function SettingsPage(): JSX.Element {
  const [sessions, setSessions] = useState<Session[]>([]);

  const refreshSessions = useCallback(async (): Promise<void> => {
    setSessions(await listSessions());
  }, []);

  return (
    <div className="stack">
      <PasswordSection onChanged={refreshSessions} />
      <SessionsSection sessions={sessions} refresh={refreshSessions} />
    </div>
  );
}

function PasswordSection({ onChanged }: { onChanged: () => Promise<void> }): JSX.Element {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    setDone(false);
    if (next !== confirm) {
      setError("new passwords don't match");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await changePassword(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      setDone(true);
      await onChanged();
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section>
      <h2>Change password</h2>
      <form className="card" onSubmit={submit}>
        <label>
          Current password
          <input
            type="password"
            autoComplete="current-password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            required
          />
        </label>
        <label>
          New password <span className="muted">(at least {MIN_PASSWORD_LENGTH} characters)</span>
          <input
            type="password"
            autoComplete="new-password"
            minLength={MIN_PASSWORD_LENGTH}
            value={next}
            onChange={(e) => setNext(e.target.value)}
            required
          />
        </label>
        <label>
          Confirm new password
          <input
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            required
          />
        </label>
        {error !== null && <p className="error">{error}</p>}
        {done && <p className="muted">Password changed. Your other sessions were signed out.</p>}
        <button type="submit" disabled={busy}>
          Change password
        </button>
      </form>
    </section>
  );
}

function SessionsSection({
  sessions,
  refresh,
}: {
  sessions: Session[];
  refresh: () => Promise<void>;
}): JSX.Element {
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    refresh().catch((caught: unknown) => setError(errorMessage(caught)));
  }, [refresh]);

  const run = (action: () => Promise<unknown>) => async (): Promise<void> => {
    setError(null);
    try {
      await action();
    } catch (caught) {
      setError(errorMessage(caught));
    }
    await refresh().catch(() => {});
  };

  const others = sessions.filter((session) => !session.current).length;

  return (
    <section>
      <div className="row">
        <h2>Sessions</h2>
        <button type="button" className="danger" disabled={others === 0} onClick={run(revokeOtherSessions)}>
          Sign out everywhere else
        </button>
      </div>
      {error !== null && <p className="error">{error}</p>}
      <table>
        <thead>
          <tr>
            <th>Browser</th>
            <th>IP address</th>
            <th>Signed in</th>
            <th>Expires</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {sessions.map((session) => (
            <tr key={session.id}>
              <td title={session.userAgent ?? undefined}>
                {describeUserAgent(session.userAgent)}
                {session.current && <span className="badge">this session</span>}
              </td>
              <td>{session.ip ?? <span className="muted">unknown</span>}</td>
              <td>{formatTime(session.createdAt)}</td>
              <td>{formatTime(session.expiresAt)}</td>
              <td className="actions">
                {!session.current && (
                  <button type="button" onClick={run(() => revokeSession(session.id))}>
                    Revoke
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
