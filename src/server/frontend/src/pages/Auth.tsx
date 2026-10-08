import { type FormEvent, type JSX, useEffect, useState } from "react";

import { ApiError, type InviteInfo, type User, getInvite, login, signup } from "../api.js";

const MIN_PASSWORD_LENGTH = 10; // mirrors auth::MIN_PASSWORD_LEN

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "something went wrong";
}

export function LoginPage({ onLogin }: { onLogin: (user: User) => void }): JSX.Element {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onLogin(await login(email, password));
    } catch (caught) {
      setError(caught instanceof ApiError && caught.status === 403 ? "this account is disabled" : errorMessage(caught));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="card" onSubmit={submit}>
      <h1>Hawk</h1>
      <label>
        Email
        <input type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required />
      </label>
      <label>
        Password
        <input
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
      </label>
      {error !== null && <p className="error">{error}</p>}
      <button type="submit" disabled={busy}>
        Log in
      </button>
      <p className="muted">Accounts are by invitation only.</p>
    </form>
  );
}

export function SignupPage({ token, onSignup }: { token: string; onSignup: (user: User) => void }): JSX.Element {
  const [invite, setInvite] = useState<InviteInfo | "invalid" | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    getInvite(token).then(setInvite, () => setInvite("invalid"));
  }, [token]);

  const submit = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    if (password !== confirm) {
      setError("passwords don't match");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      onSignup(await signup(token, email, password));
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  };

  if (invite === null) return <p className="card muted">Checking invite…</p>;
  if (invite === "invalid") {
    return (
      <div className="card">
        <h1>Invite not valid</h1>
        <p>This invite link has expired or was already used. Ask for a new one.</p>
        <a href="/">Go to login</a>
      </div>
    );
  }

  return (
    <form className="card" onSubmit={submit}>
      <h1>{invite.grantsAdmin ? "Create the admin account" : "Create your account"}</h1>
      {invite.grantsAdmin && <p className="muted">This account will manage this Hawk server and invite others.</p>}
      <label>
        Email
        <input type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required />
      </label>
      <label>
        Password <span className="muted">(at least {MIN_PASSWORD_LENGTH} characters)</span>
        <input
          type="password"
          autoComplete="new-password"
          minLength={MIN_PASSWORD_LENGTH}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
      </label>
      <label>
        Confirm password
        <input
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          required
        />
      </label>
      {error !== null && <p className="error">{error}</p>}
      <button type="submit" disabled={busy}>
        Create account
      </button>
    </form>
  );
}
