import { type CSSProperties, type FormEvent, type JSX, useCallback, useEffect, useState } from "react";

import {
  type Session,
  type User,
  describeUserAgent,
  formatTime,
  listSessions,
  revokeOtherSessions,
  revokeSession,
} from "../api.js";
import { fingerprint } from "../crypto.js";
import {
  type AppSettings,
  type AppUpdate,
  IN_APP,
  appSettings,
  appVersion,
  checkAppUpdate,
  installAppUpdate,
  saveAppSettings,
} from "../desktop.js";
import { type Identity, changePassword } from "../keys.js";
import { ACCENT_PRESETS, DEFAULT_ACCENT, applyAccent, isAccent, loadAccent, saveAccent } from "../theme.js";
import { Alert, ConfirmButton, Dot, Segmented, Tag, errorMessage } from "../ui.js";
import { TwoFactorSection } from "./TwoFactor.js";

const MIN_PASSWORD_LENGTH = 10; // mirrors auth::MIN_PASSWORD_LEN

// Every user's own settings: the look of this dashboard, identity key,
// second factors, password and sign-in sessions.
export function SettingsPage({
  user,
  identity,
  onAccountChanged,
}: {
  user: User;
  identity: Identity;
  onAccountChanged: () => void;
}): JSX.Element {
  const [sessions, setSessions] = useState<Session[] | null>(null);

  const refreshSessions = useCallback(async (): Promise<void> => {
    setSessions(await listSessions());
  }, []);

  return (
    <div className="page">
      <div className="page-head">
        <h1>Settings</h1>
      </div>
      <AccentSection />
      {IN_APP && <AppSection />}
      <KeySection identity={identity} />
      <TwoFactorSection
        user={user}
        onChanged={() => {
          onAccountChanged();
          // Adding or removing a factor signs out every other session.
          void refreshSessions().catch(() => {});
        }}
      />
      <SessionsSection sessions={sessions} refresh={refreshSessions} />
      <PasswordSection user={user} onChanged={refreshSessions} />
    </div>
  );
}

function AccentSection(): JSX.Element {
  const [accent, setAccent] = useState(loadAccent);
  const [draft, setDraft] = useState(accent);

  const choose = (color: string): void => {
    const next = color.toLowerCase();
    setAccent(next);
    setDraft(next);
    applyAccent(next);
    saveAccent(next);
  };

  const preset = ACCENT_PRESETS.find((candidate) => candidate.color === accent);

  return (
    <section className="section">
      <div className="section-aside">
        <h2>Accent color</h2>
        <p>Marks live sessions, captured input and the connect button. Saved in this browser only.</p>
      </div>
      <div className="section-main">
        <div className="swatches" role="radiogroup" aria-label="Accent color">
          {ACCENT_PRESETS.map((candidate) => (
            <button
              key={candidate.id}
              type="button"
              role="radio"
              aria-checked={candidate.color === accent}
              className="swatch"
              style={{ "--swatch": candidate.color } as CSSProperties}
              onClick={() => choose(candidate.color)}
            >
              <span className="swatch-chip" aria-hidden />
              {candidate.label}
            </button>
          ))}
          <label className="swatch" aria-checked={preset === undefined} role="radio">
            <input type="color" value={accent} onChange={(e) => choose(e.target.value)} aria-label="Custom color" />
            Custom
          </label>
        </div>
        <div className="form-row tight">
          <label className="field" style={{ flex: "none", minWidth: 0 }}>
            <span className="label faint">Hex</span>
            <input
              className="input"
              style={{ width: 120 }}
              value={draft}
              maxLength={7}
              spellCheck={false}
              onChange={(e) => {
                setDraft(e.target.value);
                if (isAccent(e.target.value)) choose(e.target.value);
              }}
              onBlur={() => setDraft(accent)}
            />
          </label>
          {accent !== DEFAULT_ACCENT && (
            <button type="button" className="btn btn-ghost" style={{ alignSelf: "flex-end" }} onClick={() => choose(DEFAULT_ACCENT)}>
              Reset to cyan
            </button>
          )}
        </div>
        <div className="accent-preview" aria-label="Preview">
          <Tag tone="accent" solid>
            Live
          </Tag>
          <button type="button" className="btn btn-accent" tabIndex={-1}>
            Connect
          </button>
          <Tag tone="accent">Live</Tag>
          <span className="cell muted" style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
            <Dot tone="accent" />
            Studio workstation
          </span>
        </div>
      </div>
    </section>
  );
}

// The account's identity key, which signs everything this user does with
// their machines: its fingerprint is what others compare to be sure it's
// theirs.
const APP_POLICIES: [AppSettings["policy"], string][] = [
  ["notify", "Ask me"],
  ["auto", "At start"],
  ["off", "Never"],
];

const APP_CHANNELS: [AppSettings["channel"], string][] = [
  ["stable", "Stable"],
  ["beta", "Beta"],
];

// The desktop app's own updates: checked against the release signature it
// was built to trust (or the key set here, for a fork's releases).
function AppSection(): JSX.Element {
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [version, setVersion] = useState("");
  const [update, setUpdate] = useState<AppUpdate | null | undefined>(undefined);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void appSettings().then(setSettings, (caught: unknown) => setError(errorMessage(caught)));
    void appVersion().then(setVersion, () => {});
  }, []);

  const save = (next: AppSettings): void => {
    setSettings(next);
    setNote(null);
    setError(null);
    saveAppSettings(next).then(
      () => setNote("Saved."),
      (caught: unknown) => setError(errorMessage(caught)),
    );
  };

  const check = (): void => {
    setBusy(true);
    setError(null);
    checkAppUpdate().then(
      (found) => {
        setUpdate(found);
        setBusy(false);
      },
      (caught: unknown) => {
        setError(errorMessage(caught));
        setBusy(false);
      },
    );
  };

  const install = (): void => {
    setBusy(true);
    setError(null);
    installAppUpdate().catch((caught: unknown) => {
      setError(errorMessage(caught));
      setBusy(false);
    });
  };

  return (
    <section className="section">
      <div className="section-aside">
        <h2>App updates</h2>
        <p>
          New releases are checked against the project's signing key before they install. This app is version{" "}
          <span className="mono">{version || "…"}</span>.
        </p>
      </div>
      <div className="section-main form-grid">
        {settings !== null && (
          <>
            <div className="field">
              <span className="label">Install updates</span>
              <Segmented
                label="Install updates"
                options={APP_POLICIES}
                value={settings.policy}
                onChange={(policy) => save({ ...settings, policy })}
              />
            </div>
            <div className="field">
              <span className="label">Channel</span>
              <Segmented
                label="Channel"
                options={APP_CHANNELS}
                value={settings.channel}
                onChange={(channel) => save({ ...settings, channel })}
              />
            </div>
            <label className="field">
              <span className="label">Release feed</span>
              <input
                className="input"
                placeholder="the one this app was built with"
                spellCheck={false}
                value={settings.feedUrl}
                onChange={(e) => setSettings({ ...settings, feedUrl: e.target.value })}
                onBlur={() => save(settings)}
              />
              <span className="field-hint">
                For a fork's releases: its feed URL, and below, the key they're signed with.
              </span>
            </label>
            <label className="field">
              <span className="label">Release key</span>
              <input
                className="input"
                placeholder="the one this app was built with"
                spellCheck={false}
                value={settings.publicKey}
                onChange={(e) => setSettings({ ...settings, publicKey: e.target.value })}
                onBlur={() => save(settings)}
              />
            </label>
          </>
        )}
        <div className="form-row" style={{ alignItems: "center" }}>
          {update ? (
            <button type="button" className="btn btn-accent" disabled={busy} onClick={install}>
              {busy ? "Installing…" : `Install ${update.version} and restart`}
            </button>
          ) : (
            <button type="button" className="btn" disabled={busy} onClick={check}>
              {busy ? "Checking…" : "Check for updates"}
            </button>
          )}
          {update === null && <span className="muted">Up to date.</span>}
          {note !== null && <span className="muted">{note}</span>}
        </div>
        {error !== null && <Alert>{error}</Alert>}
      </div>
    </section>
  );
}

function KeySection({ identity }: { identity: Identity }): JSX.Element {
  const [print, setPrint] = useState<string | null>(null);
  useEffect(() => {
    void fingerprint(identity.publicKey).then(setPrint);
  }, [identity]);

  return (
    <section className="section">
      <div className="section-aside">
        <h2>Identity key</h2>
        <p>
          Signs your machines, your shares and every view you open. It's stored on the relay encrypted with your
          password, which never leaves your browser.
        </p>
      </div>
      <div className="section-main">
        <span className="label faint">Fingerprint</span>
        <code className="mono fingerprint">{print ?? "…"}</code>
        <p className="field-hint">
          Someone sharing a machine with you sees this fingerprint for your account. If they compare it with you, a
          relay that swapped your key would be caught.
        </p>
      </div>
    </section>
  );
}

function PasswordSection({ user, onChanged }: { user: User; onChanged: () => Promise<void> }): JSX.Element {
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
      await changePassword(user, current, next);
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
    <section className="section">
      <div className="section-aside">
        <h2>Password</h2>
        <p>
          Changing it signs out every other session on this account. Your identity key stays the same; it's only
          re-encrypted under the new password.
        </p>
      </div>
      <form className="section-main form-grid" onSubmit={(e) => void submit(e)}>
        <label className="field">
          <span className="label">Current password</span>
          <input
            className="input"
            type="password"
            autoComplete="current-password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            required
          />
        </label>
        <label className="field">
          <span className="label">New password</span>
          <input
            className="input"
            type="password"
            autoComplete="new-password"
            minLength={MIN_PASSWORD_LENGTH}
            value={next}
            onChange={(e) => setNext(e.target.value)}
            required
          />
          <span className="field-hint">At least {MIN_PASSWORD_LENGTH} characters.</span>
        </label>
        <label className="field">
          <span className="label">Confirm new password</span>
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
        {done && <Alert ok>Password changed. Your other sessions were signed out.</Alert>}
        <div>
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? "Changing…" : "Change password"}
          </button>
        </div>
      </form>
    </section>
  );
}

function SessionsSection({
  sessions,
  refresh,
}: {
  sessions: Session[] | null;
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

  const others = sessions?.filter((session) => !session.current).length ?? 0;

  return (
    <section className="section">
      <div className="section-aside">
        <h2>Sessions</h2>
        <p>Every browser signed in to this account. Revoke any you don't recognise.</p>
      </div>
      <div className="section-main">
        {error !== null && <Alert>{error}</Alert>}
        <div className="table-wrap">
          <table className="table">
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
              {sessions?.map((session) => (
                <tr key={session.id}>
                  <td title={session.userAgent ?? undefined}>
                    <span className="cell">
                      <span className="truncate">{describeUserAgent(session.userAgent)}</span>
                      {session.current && <Tag tone="ok">This browser</Tag>}
                    </span>
                  </td>
                  <td className="mono">{session.ip ?? <span className="faint">unknown</span>}</td>
                  <td className="num muted">{formatTime(session.createdAt)}</td>
                  <td className="num muted">{formatTime(session.expiresAt)}</td>
                  <td className="actions">
                    {!session.current && (
                      <button type="button" className="btn btn-sm" onClick={run(() => revokeSession(session.id))}>
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div>
          <ConfirmButton
            confirmLabel={`Sign out ${others} ${others === 1 ? "session" : "sessions"}`}
            disabled={others === 0}
            onConfirm={() => void run(revokeOtherSessions)()}
          >
            Sign out everywhere else
          </ConfirmButton>
        </div>
      </div>
    </section>
  );
}
