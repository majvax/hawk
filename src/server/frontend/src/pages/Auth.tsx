import { type FormEvent, type JSX, type ReactNode, useEffect, useState } from "react";

import { ApiError, type InviteInfo, type User, getInvite, verifyEmail } from "../api.js";
import { type Entered, type Identity, logIn, logOut, signUp, unlock } from "../keys.js";
import { CodeField } from "../stepUp.js";
import { Alert, Corners, Logo } from "../ui.js";

const MIN_PASSWORD_LENGTH = 10; // mirrors auth::MIN_PASSWORD_LEN

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "something went wrong";
}

// Every signed-out screen: the mark large on the left, the form on the
// right (stacked on a narrow screen).
function AuthFrame({
  title,
  onSubmit,
  children,
}: {
  title: string;
  onSubmit?: (event: FormEvent) => void;
  children: ReactNode;
}): JSX.Element {
  const body = (
    <>
      <Corners />
      <h1>{title}</h1>
      {children}
    </>
  );
  return (
    <main className="auth">
      <div className="auth-hero">
        <Logo size={280} />
        <div className="auth-wordmark">
          <span className="brand-name">HAWK</span>
          <span className="mono faint">{window.location.host}</span>
        </div>
      </div>
      <div className="auth-side">
        {onSubmit === undefined ? (
          <div className="auth-panel">{body}</div>
        ) : (
          <form className="auth-panel" onSubmit={onSubmit}>
            {body}
          </form>
        )}
      </div>
    </main>
  );
}

export function LoginPage({ onLogin }: { onLogin: (entered: Entered) => void }): JSX.Element {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Set once the password was right and a code is still needed.
  const [finish, setFinish] = useState<((code: string) => Promise<Entered>) | null>(null);

  const submit = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const step = await logIn(email, password);
      if (step.kind === "entered") onLogin(step.entered);
      else setFinish(() => step.finish);
    } catch (caught) {
      setError(caught instanceof ApiError && caught.status === 403 ? "this account is disabled" : errorMessage(caught));
    } finally {
      setBusy(false);
    }
  };

  if (finish !== null) {
    return (
      <SecondStep
        email={email}
        finish={finish}
        onLogin={onLogin}
        onRestart={() => {
          setFinish(null);
          setPassword("");
        }}
      />
    );
  }

  return (
    <AuthFrame title="Sign in" onSubmit={(e) => void submit(e)}>
      <label className="field">
        <span className="label">Email</span>
        <input
          className="input"
          type="email"
          autoComplete="username"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          autoFocus
        />
      </label>
      <label className="field">
        <span className="label">Password</span>
        <input
          className="input"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
      </label>
      {error !== null && <Alert>{error}</Alert>}
      <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
        {busy ? "Unlocking…" : "Log in"}
      </button>
      <p className="auth-foot">
        Accounts are by invitation only. Ask this server's admin for an invite link. Your password never leaves this
        browser: it unlocks the key your screen is encrypted with. Setting up? Read the <a href="/docs">docs</a>.
      </p>
    </AuthFrame>
  );
}

// The password was right; the account has a second factor too.
function SecondStep({
  email,
  finish,
  onLogin,
  onRestart,
}: {
  email: string;
  finish: (code: string) => Promise<Entered>;
  onLogin: (entered: Entered) => void;
  onRestart: () => void;
}): JSX.Element {
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onLogin(await finish(code));
    } catch (caught) {
      setError(caught instanceof ApiError && caught.status === 403 ? "this account is disabled" : errorMessage(caught));
      setBusy(false);
    }
  };

  return (
    <AuthFrame title="Two-factor code" onSubmit={(e) => void submit(e)}>
      <p className="prose">
        Signing in as <span className="mono">{email}</span>. Enter the code your authenticator app shows for this
        server.
      </p>
      <CodeField
        value={code}
        onChange={setCode}
        hint="Lost your phone? Enter one of the recovery codes you saved instead."
      />
      {error !== null && <Alert>{error}</Alert>}
      <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
        {busy ? "Checking…" : "Sign in"}
      </button>
      <button type="button" className="btn btn-ghost btn-block" onClick={onRestart}>
        Start over
      </button>
    </AuthFrame>
  );
}

// A verification link from an email, opened in whichever browser: it
// needs no session.
export function VerifyEmailPage({ token, onDone }: { token: string; onDone: () => void }): JSX.Element {
  const [state, setState] = useState<"checking" | "done" | string>("checking");

  useEffect(() => {
    verifyEmail(token).then(
      () => setState("done"),
      (caught: unknown) => setState(errorMessage(caught)),
    );
  }, [token]);

  if (state === "checking") {
    return (
      <AuthFrame title="Confirming your email">
        <p className="muted">One moment…</p>
      </AuthFrame>
    );
  }
  return (
    <AuthFrame title={state === "done" ? "Email confirmed" : "Link not valid"}>
      {state === "done" ? (
        <Alert ok>Your email address is confirmed. Machines can now be shared with this account.</Alert>
      ) : (
        <p className="prose">
          {state}. Sign in and ask for a new link from the notice at the top of the dashboard.
        </p>
      )}
      <button type="button" className="btn btn-primary btn-block" onClick={onDone}>
        Continue
      </button>
    </AuthFrame>
  );
}

// Signed in, but this browser doesn't hold the account's key (site data
// cleared, or signed in before keys existed): the password unlocks it.
export function UnlockPage({
  user,
  onUnlock,
  onLogOut,
}: {
  user: User;
  onUnlock: (identity: Identity) => void;
  onLogOut: () => void;
}): JSX.Element {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onUnlock(await unlock(user, password));
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthFrame title="Unlock your key" onSubmit={(e) => void submit(e)}>
      <p className="prose">
        Signed in as <span className="mono">{user.email}</span>. Enter your password to unlock the key your machines
        are encrypted with in this browser.
      </p>
      <label className="field">
        <span className="label">Password</span>
        <input
          className="input"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          autoFocus
        />
      </label>
      {error !== null && <Alert>{error}</Alert>}
      <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
        {busy ? "Unlocking…" : "Unlock"}
      </button>
      <button type="button" className="btn btn-ghost btn-block" onClick={() => void logOut().finally(onLogOut)}>
        Log out
      </button>
    </AuthFrame>
  );
}

export function SignupPage({ token, onSignup }: { token: string; onSignup: (entered: Entered) => void }): JSX.Element {
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
      onSignup(await signUp(token, email, password));
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  };

  if (invite === null) {
    return (
      <AuthFrame title="Checking invite">
        <p className="muted">One moment…</p>
      </AuthFrame>
    );
  }
  if (invite === "invalid") {
    return (
      <AuthFrame title="Invite not valid">
        <p className="prose">This invite link has expired or was already used. Ask whoever sent it for a new one.</p>
        <a className="btn btn-block" href="/" style={{ textDecoration: "none" }}>
          Go to login
        </a>
      </AuthFrame>
    );
  }

  return (
    <AuthFrame
      title={invite.grantsAdmin ? "Create the admin account" : "Create your account"}
      onSubmit={(e) => void submit(e)}
    >
      {invite.grantsAdmin && <p className="prose">This account will manage this Hawk server and invite others.</p>}
      <label className="field">
        <span className="label">Email</span>
        <input
          className="input"
          type="email"
          autoComplete="username"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          autoFocus
        />
      </label>
      <label className="field">
        <span className="label">Password</span>
        <input
          className="input"
          type="password"
          autoComplete="new-password"
          minLength={MIN_PASSWORD_LENGTH}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <span className="field-hint">At least {MIN_PASSWORD_LENGTH} characters.</span>
      </label>
      <label className="field">
        <span className="label">Confirm password</span>
        <input
          className="input"
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          required
        />
      </label>
      {error !== null && <Alert>{error}</Alert>}
      <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
        {busy ? "Creating account…" : "Create account"}
      </button>
    </AuthFrame>
  );
}
