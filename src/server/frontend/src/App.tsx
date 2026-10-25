import { type JSX, useCallback, useEffect, useState } from "react";

import { type User, getSession, resendVerification } from "./api.js";
import { type Identity, currentIdentity, logOut } from "./keys.js";
import { AdminPage } from "./pages/Admin.js";
import { LoginPage, RelayPage, SignupPage, UnlockPage, VerifyEmailPage } from "./pages/Auth.js";
import { MachinesPage, formatBitrate } from "./pages/Machines.js";
import { SettingsPage } from "./pages/Settings.js";
import { MfaSetupPage } from "./pages/TwoFactor.js";
import { type AppUpdate, installAppUpdate, onAppUpdate } from "./desktop.js";
import { STANDALONE, activeRelay, checkRelayProtocol, leaveRelay, relayIsTls, relayPageUrl } from "./relay.js";
import { StepUpProvider } from "./stepUp.js";
import { Dot, Logo, type Tone, errorMessage } from "./ui.js";
import { type ConnectionStatus, type Dashboard, useDashboard } from "./useDashboard.js";

type Tab = "machines" | "settings" | "admin";

function inviteTokenFromPath(): string | null {
  const match = /^\/invite\/([A-Za-z0-9_-]+)$/.exec(window.location.pathname);
  return match?.[1] ?? null;
}

function verifyTokenFromPath(): string | null {
  const match = /^\/verify\/([A-Za-z0-9_-]+)$/.exec(window.location.pathname);
  return match?.[1] ?? null;
}

export function App(): JSX.Element {
  // A standalone dashboard needs a relay before anything else.
  if (activeRelay() === null) return <RelayPage />;
  return <SignedOutOrIn />;
}

function SignedOutOrIn(): JSX.Element {
  // undefined: still checking; null: logged out.
  const [user, setUser] = useState<User | null | undefined>(undefined);
  // The account's identity key in this browser; null while it still has to
  // be unlocked with the password.
  const [identity, setIdentity] = useState<Identity | null | undefined>(undefined);
  const [inviteToken, setInviteToken] = useState(inviteTokenFromPath);
  const [verifyToken, setVerifyToken] = useState(verifyTokenFromPath);

  const recheckSession = useCallback((): void => {
    getSession().then(
      async (session) => {
        setIdentity(session === null ? null : await currentIdentity(session).catch(() => null));
        setUser(session);
      },
      () => setUser(null),
    );
  }, []);

  useEffect(recheckSession, [recheckSession]);

  // The account changed (a second factor, a confirmed email): re-read it,
  // keeping the unlocked key.
  const refreshUser = useCallback((): void => {
    void getSession().then((session) => session !== null && setUser(session), () => {});
  }, []);

  const enter = ({ user: next, identity: unlocked }: { user: User; identity: Identity }): void => {
    // Leave /invite/<token> so a reload doesn't show the signup page again.
    if (inviteToken !== null) {
      window.history.replaceState(null, "", "/");
      setInviteToken(null);
    }
    setIdentity(unlocked);
    setUser(next);
  };

  const leave = (): void => {
    setIdentity(null);
    setUser(null);
  };

  if (verifyToken !== null) {
    return (
      <VerifyEmailPage
        token={verifyToken}
        onDone={() => {
          window.history.replaceState(null, "", "/");
          setVerifyToken(null);
          refreshUser();
        }}
      />
    );
  }
  if (inviteToken !== null && user !== undefined) return <SignupPage token={inviteToken} onSignup={enter} />;
  if (user === undefined || identity === undefined) {
    return (
      <div className="splash" aria-busy>
        <Logo size={28} />
        <span className="label faint">Checking session</span>
      </div>
    );
  }
  if (user === null) return <LoginPage onLogin={enter} />;
  if (user.mfaSetupRequired) return <MfaSetupPage user={user} onDone={refreshUser} onLogOut={leave} />;
  if (identity === null) {
    return <UnlockPage user={user} onUnlock={(unlocked) => enter({ user, identity: unlocked })} onLogOut={leave} />;
  }
  // Keyed so a different account never inherits the last one's dashboard.
  return (
    <StepUpProvider user={user}>
      <Console key={user.id} user={user} identity={identity} onSessionEnded={leave} onAccountChanged={refreshUser} />
    </StepUpProvider>
  );
}

const TABS: [Tab, string][] = [
  ["machines", "Machines"],
  ["settings", "Settings"],
  ["admin", "Admin"],
];

function Console({
  user,
  identity,
  onSessionEnded,
  onAccountChanged,
}: {
  user: User;
  identity: Identity;
  onSessionEnded: () => void;
  onAccountChanged: () => void;
}): JSX.Element {
  const [tab, setTab] = useState<Tab>("machines");
  // Said plainly when the relay and this dashboard don't speak the same
  // protocol, instead of failing in odd ways later.
  const [mismatch, setMismatch] = useState<string | null>(null);
  useEffect(() => {
    void checkRelayProtocol().then(setMismatch);
  }, []);
  // The desktop app found a newer release of itself at start.
  const [appUpdate, setAppUpdate] = useState<AppUpdate | null>(null);
  const [installing, setInstalling] = useState(false);
  useEffect(() => onAppUpdate(setAppUpdate), []);
  // Owned here rather than by the machines page so the status bar can show
  // the relay link from any tab, and a live view survives switching tabs.
  const dashboard = useDashboard(identity, onSessionEnded);

  return (
    <div className={user.emailVerified && mismatch === null && appUpdate === null ? "shell" : "shell with-banner"}>
      <header className="topbar">
        <div className="brand">
          <Logo size={18} />
          <span className="brand-name">HAWK</span>
        </div>
        <nav className="nav">
          {TABS.filter(([id]) => id !== "admin" || user.isAdmin).map(([id, label]) => (
            <button
              key={id}
              type="button"
              aria-current={tab === id ? "page" : undefined}
              onClick={() => setTab(id)}
            >
              {label}
            </button>
          ))}
        </nav>
        <div className="topbar-end">
          <span className="whoami" title={user.email}>
            <span className="email truncate">{user.email}</span>
          </span>
          {/* A new tab, so a live view stays open. */}
          <a className="btn btn-ghost btn-sm" href={relayPageUrl("/docs")} target="_blank" rel="noopener">
            Docs
          </a>
          {STANDALONE && (
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              title="Switch to another relay (stays signed in here)"
              onClick={() => {
                leaveRelay();
                window.location.reload();
              }}
            >
              Relays
            </button>
          )}
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={() => void logOut().finally(onSessionEnded)}
          >
            Log out
          </button>
        </div>
      </header>

      {mismatch !== null && (
        <div className="banner" role="alert">
          <span>{mismatch}</span>
        </div>
      )}
      {appUpdate !== null && mismatch === null && (
        <div className="banner" role="status">
          <span>
            Hawk {appUpdate.version} is available (you have {appUpdate.current}). Installing it restarts the app, so
            finish what you're watching first.
          </span>
          <button
            type="button"
            className="btn btn-sm"
            disabled={installing}
            onClick={() => {
              setInstalling(true);
              installAppUpdate().catch(() => setInstalling(false));
            }}
          >
            {installing ? "Installing…" : "Install and restart"}
          </button>
        </div>
      )}
      {!user.emailVerified && <VerifyBanner email={user.email} />}

      {/* The machines page stays mounted so switching tabs doesn't drop a
          live view. */}
      <main className="view fixed" hidden={tab !== "machines"}>
        <MachinesPage dashboard={dashboard} identity={identity} visible={tab === "machines"} />
      </main>
      {tab === "settings" && (
        <main className="view">
          <SettingsPage user={user} identity={identity} onAccountChanged={onAccountChanged} />
        </main>
      )}
      {tab === "admin" && user.isAdmin && (
        <main className="view">
          <AdminPage me={user} />
        </main>
      )}

      <StatusBar dashboard={dashboard} />
    </div>
  );
}

// Until the address is confirmed, machines can't be enrolled under this
// account or shared with it.
function VerifyBanner({ email }: { email: string }): JSX.Element {
  const [note, setNote] = useState<string | null>(null);
  const resend = (): void => {
    resendVerification().then(
      () => setNote("Sent. Check your inbox."),
      (caught: unknown) => setNote(errorMessage(caught)),
    );
  };
  return (
    <div className="banner" role="status">
      <span>
        Confirm your email address: open the link sent to <span className="mono">{email}</span>. Until then, machines
        can't be enrolled under this account or shared with it.
      </span>
      {note !== null && <span className="muted" style={{ flex: "none" }}>{note}</span>}
      <button type="button" className="btn btn-sm" onClick={resend}>
        Send the link again
      </button>
    </div>
  );
}

const LINK: Record<ConnectionStatus, [Tone, string]> = {
  open: ["ok", "Relay linked"],
  connecting: ["warn", "Connecting"],
  reconnecting: ["warn", "Link down"],
  closed: ["err", "Session ended"],
};

function StatusBar({ dashboard }: { dashboard: Dashboard }): JSX.Element {
  const { machines, status, retryAt, viewingId, stats, reconnectNow } = dashboard;
  const [tone, label] = LINK[status];
  const online = machines.filter((machine) => machine.online).length;
  const viewing = machines.find((machine) => machine.id === viewingId);
  const secure = relayIsTls();

  return (
    <footer className="statusbar">
      <span>
        <Dot tone={tone} />
        {label}
        {status === "reconnecting" && retryAt !== null && (
          <>
            <span className="faint">
              retry in <Countdown until={retryAt} />
            </span>
            <button type="button" onClick={reconnectNow}>
              Retry now
            </button>
          </>
        )}
      </span>
      <span className="wide">
        {online}/{machines.length} online
      </span>
      {viewing !== undefined && (
        <span className="accent">
          <Dot tone="accent" />
          {viewing.name}
        </span>
      )}
      {viewing !== undefined && stats !== null && (
        <span className="wide">
          {stats.fps} fps · {formatBitrate(stats.kbps)}
        </span>
      )}
      <span className="spacer" />
      <span className="end" title={secure ? "Served over TLS" : "Not served over TLS"}>
        <Dot tone={secure ? "ok" : "warn"} />
        {secure ? "TLS" : "No TLS"}
      </span>
    </footer>
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
