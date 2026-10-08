import { type JSX, useCallback, useEffect, useState } from "react";

import {
  type AdminUserRow,
  type CreatedInvite,
  type PendingInvite,
  type User,
  createInvite,
  deleteInvite,
  formatTime,
  inviteUrl,
  listInvites,
  listUsers,
  setUserDisabled,
} from "../api.js";

export function AdminPage({ me }: { me: User }): JSX.Element {
  const [users, setUsers] = useState<AdminUserRow[]>([]);
  const [invites, setInvites] = useState<PendingInvite[]>([]);
  const [created, setCreated] = useState<CreatedInvite | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async (): Promise<void> => {
    try {
      const [nextUsers, nextInvites] = await Promise.all([listUsers(), listInvites()]);
      setUsers(nextUsers);
      setInvites(nextInvites);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "failed to load");
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const run = (action: () => Promise<unknown>) => async (): Promise<void> => {
    setError(null);
    try {
      await action();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "request failed");
    }
    await refresh();
  };

  return (
    <div className="stack">
      {error !== null && <p className="error">{error}</p>}

      <section>
        <div className="row">
          <h2>Invites</h2>
          <button type="button" onClick={run(async () => setCreated(await createInvite()))}>
            New invite link
          </button>
        </div>
        {created !== null && (
          <div className="notice">
            <p>Send this link to the person you're inviting. It works once and expires {formatTime(created.expiresAt)}.
            It won't be shown again.</p>
            <div className="row">
              <input readOnly value={inviteUrl(created.token)} onFocus={(e) => e.target.select()} />
              <button type="button" onClick={() => void navigator.clipboard.writeText(inviteUrl(created.token))}>
                Copy
              </button>
              <button type="button" onClick={() => setCreated(null)}>
                Done
              </button>
            </div>
          </div>
        )}
        {invites.length === 0 ? (
          <p className="muted">No pending invites.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Created</th>
                <th>Expires</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {invites.map((invite) => (
                <tr key={invite.id}>
                  <td>{formatTime(invite.createdAt)}</td>
                  <td>{formatTime(invite.expiresAt)}</td>
                  <td>
                    <button type="button" onClick={run(() => deleteInvite(invite.id))}>
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section>
        <h2>Users</h2>
        <table>
          <thead>
            <tr>
              <th>Email</th>
              <th>Role</th>
              <th>Joined</th>
              <th>Status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id}>
                <td>{user.email}</td>
                <td>{user.isAdmin ? "admin" : "user"}</td>
                <td>{formatTime(user.createdAt)}</td>
                <td>{user.disabled ? "disabled" : "active"}</td>
                <td>
                  {user.id !== me.id && (
                    <button type="button" onClick={run(() => setUserDisabled(user.id, !user.disabled))}>
                      {user.disabled ? "Enable" : "Disable"}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
