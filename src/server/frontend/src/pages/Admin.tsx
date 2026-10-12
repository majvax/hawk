import { type JSX, useCallback, useEffect, useState } from "react";

import {
  type AdminUserRow,
  type CreatedInvite,
  type PendingInvite,
  type User,
  createInvite,
  deleteInvite,
  formatTime,
  getPolicy,
  inviteUrl,
  listInvites,
  listUsers,
  resetUserMfa,
  setPolicy,
  setUserDisabled,
} from "../api.js";
import { Alert, CodeBlock, ConfirmButton, Dot, Metric, Tag, errorMessage } from "../ui.js";

export function AdminPage({ me }: { me: User }): JSX.Element {
  const [users, setUsers] = useState<AdminUserRow[] | null>(null);
  const [invites, setInvites] = useState<PendingInvite[] | null>(null);
  const [created, setCreated] = useState<CreatedInvite | null>(null);
  const [requireMfa, setRequireMfa] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async (): Promise<void> => {
    try {
      const [nextUsers, nextInvites, policy] = await Promise.all([listUsers(), listInvites(), getPolicy()]);
      setUsers(nextUsers);
      setInvites(nextInvites);
      setRequireMfa(policy.requireMfa);
    } catch (caught) {
      setError(errorMessage(caught, "failed to load"));
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
      setError(errorMessage(caught));
    }
    await refresh();
  };

  const active = users?.filter((user) => !user.disabled).length ?? 0;
  const admins = users?.filter((user) => user.isAdmin).length ?? 0;
  const withMfa = users?.filter((user) => user.mfa).length ?? 0;

  return (
    <div className="page">
      <div className="page-head">
        <h1>Admin</h1>
      </div>
      <div className="strip" style={{ marginBottom: 4 }}>
        <Metric label="Users">{users?.length ?? "—"}</Metric>
        <Metric label="Active">{users === null ? "—" : active}</Metric>
        <Metric label="Disabled" dim={users === null || users.length === active}>
          {users === null ? "—" : users.length - active}
        </Metric>
        <Metric label="Admins">{users === null ? "—" : admins}</Metric>
        <Metric label="Two-factor" dim={users === null || withMfa === 0}>
          {users === null ? "—" : `${withMfa}/${users.length}`}
        </Metric>
        <Metric label="Pending invites" dim={invites === null || invites.length === 0}>
          {invites?.length ?? "—"}
        </Metric>
      </div>
      {error !== null && (
        <div style={{ paddingTop: 16 }}>
          <Alert>{error}</Alert>
        </div>
      )}

      <section className="section" style={{ marginTop: 16 }}>
        <div className="section-aside">
          <h2>Invites</h2>
          <p>Accounts are by invitation only. Each link creates one account, once.</p>
        </div>
        <div className="section-main">
          <div>
            <button
              type="button"
              className="btn btn-primary"
              onClick={run(async () => setCreated(await createInvite()))}
            >
              New invite link
            </button>
          </div>
          {created !== null && (
            <div className="enroll" style={{ margin: 0 }}>
              <div className="block-head">
                <span className="prose" style={{ flex: 1, maxWidth: "none" }}>
                  Send this link to the person you're inviting. It works once and expires at{" "}
                  <span className="num">{formatTime(created.expiresAt)}</span>. It won't be shown again.
                </span>
                <button type="button" className="btn btn-sm" onClick={() => setCreated(null)}>
                  Done
                </button>
              </div>
              <CodeBlock value={inviteUrl(created.token)} />
            </div>
          )}
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Created</th>
                  <th>Expires</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {invites !== null && invites.length === 0 && (
                  <tr>
                    <td colSpan={3} className="muted">
                      No pending invites.
                    </td>
                  </tr>
                )}
                {invites?.map((invite) => (
                  <tr key={invite.id}>
                    <td className="num">{formatTime(invite.createdAt)}</td>
                    <td className="num muted">{formatTime(invite.expiresAt)}</td>
                    <td className="actions">
                      <ConfirmButton small confirmLabel="Confirm" onConfirm={() => void run(() => deleteInvite(invite.id))()}>
                        Revoke
                      </ConfirmButton>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section className="section">
        <div className="section-aside">
          <h2>Two-factor policy</h2>
          <p>
            Required, an account without a second factor can only set one up after signing in. Turn it on once your
            own account has one.
          </p>
        </div>
        <div className="section-main">
          <label className="cell" style={{ gap: 8 }}>
            <input
              type="checkbox"
              checked={requireMfa ?? false}
              disabled={requireMfa === null}
              onChange={(e) => {
                const next = e.target.checked;
                void run(async () => setRequireMfa((await setPolicy(next)).requireMfa))();
              }}
            />
            Require two-factor authentication for every account
          </label>
        </div>
      </section>

      <section className="section">
        <div className="section-aside">
          <h2>Users</h2>
          <p>
            Disabling an account signs it out everywhere, closes its open dashboards and cuts off any live view.
            Resetting two-factor is for someone who lost every authenticator and recovery code: it removes them all and
            signs the account out, so its owner can sign in with the password and set up again.
          </p>
        </div>
        <div className="section-main">
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Joined</th>
                  <th>Two-factor</th>
                  <th>Status</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {users?.map((user) => (
                  <tr key={user.id}>
                    <td>
                      <span className="cell">
                        <span className="truncate">{user.email}</span>
                        {user.id === me.id && <Tag>You</Tag>}
                      </span>
                    </td>
                    <td className={user.isAdmin ? undefined : "muted"}>{user.isAdmin ? "Admin" : "User"}</td>
                    <td className="num muted">{formatTime(user.createdAt)}</td>
                    <td className={user.mfa ? undefined : "muted"}>{user.mfa ? "On" : "Off"}</td>
                    <td>
                      <span className="cell">
                        <Dot tone={user.disabled ? "err" : user.emailVerified ? "ok" : "warn"} />
                        {user.disabled ? "Disabled" : user.emailVerified ? "Active" : "Email not confirmed"}
                      </span>
                    </td>
                    <td className="actions">
                      {user.id !== me.id && user.mfa && (
                        <ConfirmButton small confirmLabel="Reset it" onConfirm={() => void run(() => resetUserMfa(user.id))()}>
                          Reset two-factor
                        </ConfirmButton>
                      )}
                      {user.id !== me.id &&
                        (user.disabled ? (
                          <button type="button" className="btn btn-sm" onClick={run(() => setUserDisabled(user.id, false))}>
                            Enable
                          </button>
                        ) : (
                          <ConfirmButton
                            small
                            confirmLabel="Confirm"
                            onConfirm={() => void run(() => setUserDisabled(user.id, true))()}
                          >
                            Disable
                          </ConfirmButton>
                        ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>
  );
}
