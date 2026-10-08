import { type JSX, useCallback, useEffect, useState } from "react";

import { type User, getSession, logout } from "./api.js";
import { AdminPage } from "./pages/Admin.js";
import { LoginPage, SignupPage } from "./pages/Auth.js";
import { MachinesPage } from "./pages/Machines.js";
import { SettingsPage } from "./pages/Settings.js";

type Tab = "machines" | "settings" | "admin";

function inviteTokenFromPath(): string | null {
  const match = /^\/invite\/([A-Za-z0-9_-]+)$/.exec(window.location.pathname);
  return match?.[1] ?? null;
}

export function App(): JSX.Element {
  // undefined: still checking; null: logged out.
  const [user, setUser] = useState<User | null | undefined>(undefined);
  const [inviteToken, setInviteToken] = useState(inviteTokenFromPath);
  const [tab, setTab] = useState<Tab>("machines");

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
    setTab("machines");
    setUser(next);
  };

  if (inviteToken !== null && user !== undefined) {
    return (
      <main className="centered">
        <SignupPage token={inviteToken} onSignup={enter} />
      </main>
    );
  }
  if (user === undefined) return <main className="centered muted">Loading…</main>;
  if (user === null) {
    return (
      <main className="centered">
        <LoginPage onLogin={enter} />
      </main>
    );
  }

  return (
    <main>
      <header>
        <strong>Hawk</strong>
        <nav>
          <button type="button" className={tab === "machines" ? "active" : ""} onClick={() => setTab("machines")}>
            Machines
          </button>
          <button type="button" className={tab === "settings" ? "active" : ""} onClick={() => setTab("settings")}>
            Settings
          </button>
          {user.isAdmin && (
            <button type="button" className={tab === "admin" ? "active" : ""} onClick={() => setTab("admin")}>
              Admin
            </button>
          )}
        </nav>
        <span className="muted">{user.email}</span>
        <button type="button" onClick={() => void logout().finally(() => setUser(null))}>
          Log out
        </button>
      </header>
      {/* Machines stays mounted so switching tabs doesn't drop a live view. */}
      <div style={{ display: tab === "machines" ? "block" : "none" }}>
        <MachinesPage onSessionEnded={() => setUser(null)} />
      </div>
      {tab === "settings" && <SettingsPage />}
      {tab === "admin" && user.isAdmin && <AdminPage me={user} />}
    </main>
  );
}
