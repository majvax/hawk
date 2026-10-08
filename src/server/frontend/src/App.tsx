import { type JSX, useCallback, useEffect, useState } from "react";

import { type User, getSession, logout } from "./api.js";
import { AdminPage } from "./pages/Admin.js";
import { LoginPage, SignupPage } from "./pages/Auth.js";
import { MachinesPage, formatBitrate } from "./pages/Machines.js";
import { SettingsPage } from "./pages/Settings.js";
import { Dot, Logo, type Tone } from "./ui.js";
import { type ConnectionStatus, type Dashboard, useDashboard } from "./useDashboard.js";

type Tab = "machines" | "settings" | "admin";

function inviteTokenFromPath(): string | null {
  const match = /^\/invite\/([A-Za-z0-9_-]+)$/.exec(window.location.pathname);
  return match?.[1] ?? null;
}

export function App(): JSX.Element {
  // undefined: still checking; null: logged out.
  const [user, setUser] = useState<User | null | undefined>(undefined);
  const [inviteToken, setInviteToken] = useState(inviteTokenFromPath);

  const recheckSession = useCallback((): void => {
    getSession().then(setUser, () => setUser(null));
  }, []);

  useEffect(recheckSession, [recheckSession]);

  const enter = (next: User): void => {
    // Leave /invite/<token> so a reload doesn't show the signup page again.
    if (inviteToken !== null) {
      window.history.replaceState(null, "", "/");
      setInviteToken(null);
    }
    setUser(next);
  };

  if (inviteToken !== null && user !== undefined) return <SignupPage token={inviteToken} onSignup={enter} />;
  if (user === undefined) {
    return (
      <div className="splash" aria-busy>
        <Logo size={28} />
        <span className="label faint">Checking session</span>
      </div>
    );
  }
  if (user === null) return <LoginPage onLogin={enter} />;
  // Keyed so a different account never inherits the last one's dashboard.
  return <Console key={user.id} user={user} onSessionEnded={() => setUser(null)} />;
}

const TABS: [Tab, string][] = [
  ["machines", "Machines"],
  ["settings", "Settings"],
  ["admin", "Admin"],
];

function Console({ user, onSessionEnded }: { user: User; onSessionEnded: () => void }): JSX.Element {
  const [tab, setTab] = useState<Tab>("machines");
  // Owned here rather than by the machines page so the status bar can show
  // the relay link from any tab, and a live view survives switching tabs.
  const dashboard = useDashboard(onSessionEnded);

  return (
    <div className="shell">
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
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={() => void logout().finally(onSessionEnded)}
          >
            Log out
          </button>
        </div>
      </header>

      {/* The machines page stays mounted so switching tabs doesn't drop a
          live view. */}
      <main className="view fixed" hidden={tab !== "machines"}>
        <MachinesPage dashboard={dashboard} visible={tab === "machines"} />
      </main>
      {tab === "settings" && (
        <main className="view">
          <SettingsPage />
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
  const secure = window.location.protocol === "https:";

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
