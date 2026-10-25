// Second factors: adding an authenticator app or a passkey, the recovery
// codes that come with the first one, and the page an account is held on
// while the admin requires a second factor it doesn't have yet.
import { type FormEvent, type JSX, useCallback, useEffect, useState } from "react";

import {
  type Factors,
  type User,
  addPasskey,
  addTotp,
  formatTime,
  listFactors,
  passkeySetup,
  regenerateRecoveryCodes,
  removeFactor,
  totpSetup,
} from "../api.js";
import { authKeyFor, logOut } from "../keys.js";
import { CodeField, QrCode } from "../stepUp.js";
import { Alert, CodeBlock, ConfirmButton, Corners, CopyButton, Logo, Segmented, Tag, errorMessage } from "../ui.js";
import { type CreationOptionsJson, PasskeyCancelled, createPasskey, passkeysUsable } from "../webauthn.js";

const DEFAULT_LABEL = "Authenticator app";
const DEFAULT_PASSKEY_LABEL = "Passkey";

const KIND_NAMES = { totp: "Authenticator app", passkey: "Passkey" } as const;

// The Settings section: every factor on the account, adding and removing
// them, and the recovery codes.
export function TwoFactorSection({ user, onChanged }: { user: User; onChanged: () => void }): JSX.Element {
  const [factors, setFactors] = useState<Factors | null>(null);
  const [adding, setAdding] = useState<"totp" | "passkey" | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async (): Promise<void> => {
    try {
      setFactors(await listFactors());
    } catch (caught) {
      setError(errorMessage(caught));
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const run = (action: () => Promise<unknown>) => async (): Promise<void> => {
    setError(null);
    try {
      await action();
      onChanged();
    } catch (caught) {
      setError(errorMessage(caught));
    }
    await refresh();
  };

  const count = factors?.factors.length ?? 0;
  const passkeys = passkeysUsable(user.passkeyRpId);
  const added = (recovery: string[] | null): void => {
    setAdding(null);
    if (recovery !== null) setCodes(recovery);
    onChanged();
    void refresh();
  };

  return (
    <section className="section">
      <div className="section-aside">
        <h2>Two-factor authentication</h2>
        <p>
          A passkey (a security key, Windows Hello, Touch ID, your phone) or a code from an app on your phone, on top of
          your password, to sign in and to confirm what matters: removing or sharing a machine, controlling it, opening
          a shell. Adding or removing one signs out every other session.
        </p>
      </div>
      <div className="section-main">
        {error !== null && <Alert>{error}</Alert>}
        {codes !== null && <RecoveryCodes codes={codes} onDone={() => setCodes(null)} />}
        {factors !== null && count === 0 && adding === null && (
          <p className="prose">
            Not set up. {factors.required ? "This server requires it." : "Anyone with your password can sign in."}
          </p>
        )}
        {count > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Kind</th>
                  <th>Added</th>
                  <th>Last used</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {factors?.factors.map((factor) => (
                  <tr key={factor.id}>
                    <td>{factor.label}</td>
                    <td className="muted">{KIND_NAMES[factor.kind]}</td>
                    <td className="num muted">{formatTime(factor.createdAt)}</td>
                    <td className="num muted">{factor.lastUsedAt === null ? "never" : formatTime(factor.lastUsedAt)}</td>
                    <td className="actions">
                      {!(factors.required && count === 1) && (
                        <ConfirmButton small confirmLabel="Remove it" onConfirm={() => void run(() => removeFactor(factor.id))()}>
                          Remove
                        </ConfirmButton>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {adding === "totp" && (
          <AddAuthenticator user={user} first={count === 0} onAdded={added} onCancel={() => setAdding(null)} />
        )}
        {adding === "passkey" && (
          <AddPasskey user={user} first={count === 0} onAdded={added} onCancel={() => setAdding(null)} />
        )}
        {adding === null && (
          <div className="form-row tight">
            {passkeys && (
              <button type="button" className="btn btn-primary" onClick={() => setAdding("passkey")}>
                Add a passkey
              </button>
            )}
            <button type="button" className={passkeys ? "btn" : "btn btn-primary"} onClick={() => setAdding("totp")}>
              {count === 0 ? "Set up an authenticator app" : "Add an authenticator app"}
            </button>
            {count > 0 && (
              <ConfirmButton
                confirmLabel="Replace every code"
                onConfirm={() => void run(async () => setCodes((await regenerateRecoveryCodes()).recoveryCodes))()}
              >
                New recovery codes
              </ConfirmButton>
            )}
          </div>
        )}
        {count > 0 && factors !== null && (
          <p className="field-hint">
            {factors.recoveryCodesLeft} unused recovery {factors.recoveryCodesLeft === 1 ? "code" : "codes"} left.
            {factors.recoveryCodesLeft <= 3 && " Make new ones before you run out."}
          </p>
        )}
        {!passkeys && user.passkeyRpId !== null && (
          <p className="field-hint">
            Passkeys can't be made here: open the dashboard in a browser at <span className="mono">{user.passkeyRpId}</span>{" "}
            to add one.
          </p>
        )}
      </div>
    </section>
  );
}

// Making a passkey for the relay's challenge, and naming it. The first
// factor is confirmed with the password; later ones by stepping up (the
// relay asks, and api.ts takes care of it).
function AddPasskey({
  user,
  first,
  onAdded,
  onCancel,
}: {
  user: User;
  first: boolean;
  onAdded: (recoveryCodes: string[] | null) => void;
  onCancel?: () => void;
}): JSX.Element {
  const [label, setLabel] = useState(DEFAULT_PASSKEY_LABEL);
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [cancelled, setCancelled] = useState(false);
  const [busy, setBusy] = useState(false);
  // The relay's challenge, kept after a cancelled prompt: trying again then
  // goes straight to the browser, inside the click, which Safari insists on
  // (the password's stretching and a request in between can be too long).
  const [options, setOptions] = useState<CreationOptionsJson | null>(null);

  const submit = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setCancelled(false);
    let challenge = options;
    try {
      if (challenge === null) {
        const authKey = first ? await authKeyFor(user, password) : undefined;
        challenge = await passkeySetup(authKey);
      }
      setOptions(null);
      const credential = await createPasskey(challenge);
      const { recoveryCodes } = await addPasskey(credential, label);
      onAdded(recoveryCodes);
    } catch (caught) {
      if (caught instanceof PasskeyCancelled) {
        setCancelled(true);
        setOptions(challenge);
      } else {
        setError(errorMessage(caught));
      }
      setBusy(false);
    }
  };

  return (
    <form className="enroll" style={{ margin: 0 }} onSubmit={(e) => void submit(e)}>
      <p className="prose">
        Your browser will ask where to keep it: this device (Windows Hello, Touch ID), your phone, or a security key.
        {first && " Passkeys don't work in the desktop app, so an authenticator app as well is worth having."}
      </p>
      <label className="field">
        <span className="label">Name</span>
        <input className="input" value={label} maxLength={64} onChange={(e) => setLabel(e.target.value)} required />
        <span className="field-hint">To tell your passkeys apart, e.g. the key or the device it's on.</span>
      </label>
      {first && (
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
          <span className="field-hint">Your account's password, to confirm it's you.</span>
        </label>
      )}
      {cancelled && <p className="field-hint">No passkey was made. Try again when you're ready.</p>}
      {error !== null && <Alert>{error}</Alert>}
      <div className="form-row tight">
        <button type="submit" className="btn btn-primary" disabled={busy}>
          {busy ? "Waiting for your passkey…" : "Make the passkey"}
        </button>
        {onCancel !== undefined && (
          <button type="button" className="btn btn-ghost" onClick={onCancel}>
            Cancel
          </button>
        )}
      </div>
    </form>
  );
}

// Scanning a new seed and proving it with a code. The first factor is
// confirmed with the password; later ones with a code (step-up).
function AddAuthenticator({
  user,
  first,
  onAdded,
  onCancel,
}: {
  user: User;
  first: boolean;
  onAdded: (recoveryCodes: string[] | null) => void;
  onCancel?: () => void;
}): JSX.Element {
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null);
  const [label, setLabel] = useState(DEFAULT_LABEL);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    totpSetup().then(setSetup, (caught: unknown) => setError(errorMessage(caught)));
  }, []);

  const submit = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    if (setup === null) return;
    setBusy(true);
    setError(null);
    try {
      const authKey = first ? await authKeyFor(user, password) : undefined;
      const { recoveryCodes } = await addTotp(setup.secret, code, label, authKey);
      onAdded(recoveryCodes);
    } catch (caught) {
      setError(errorMessage(caught));
      setBusy(false);
    }
  };

  return (
    <form className="enroll" style={{ margin: 0 }} onSubmit={(e) => void submit(e)}>
      {setup === null ? (
        error === null && <p className="muted">Making a key…</p>
      ) : (
        <div className="totp-setup">
          <QrCode value={setup.uri} />
          <div>
            <p className="prose">
              Scan this with an authenticator app (Aegis, 2FAS, Google Authenticator, 1Password…), or type the key in
              by hand.
            </p>
            <CodeBlock value={setup.secret.replace(/(.{4})/g, "$1 ").trim()} />
            <label className="field">
              <span className="label">Name</span>
              <input
                className="input"
                value={label}
                maxLength={64}
                onChange={(e) => setLabel(e.target.value)}
                required
              />
              <span className="field-hint">To tell your authenticators apart, e.g. the phone it's on.</span>
            </label>
          </div>
        </div>
      )}
      {setup !== null && (
        <>
          <CodeField value={code} onChange={setCode} label="Code from the app" hint="The six digits it shows now." />
          {first && (
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
              <span className="field-hint">Your account's password, to confirm it's you.</span>
            </label>
          )}
        </>
      )}
      {error !== null && <Alert>{error}</Alert>}
      <div className="form-row tight">
        <button type="submit" className="btn btn-primary" disabled={busy || setup === null}>
          {busy ? "Checking…" : "Turn on"}
        </button>
        {onCancel !== undefined && (
          <button type="button" className="btn btn-ghost" onClick={onCancel}>
            Cancel
          </button>
        )}
      </div>
    </form>
  );
}

// Shown once, right after they're made: the relay keeps only their hashes.
function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }): JSX.Element {
  const text = codes.join("\n");
  const download = (): void => {
    const url = URL.createObjectURL(new Blob([`Hawk recovery codes for ${window.location.host}\n\n${text}\n`]));
    const link = document.createElement("a");
    link.href = url;
    link.download = `hawk-recovery-codes-${window.location.hostname}.txt`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="enroll" style={{ margin: 0 }}>
      <div className="block-head">
        <span className="prose" style={{ flex: 1, maxWidth: "none" }}>
          <Tag tone="warn">Save these now</Tag> Each one signs you in once if you lose your phone. They won't be
          shown again.
        </span>
      </div>
      <ul className="recovery-codes">
        {codes.map((code) => (
          <li key={code}>{code}</li>
        ))}
      </ul>
      <div className="form-row tight">
        <CopyButton value={text} />
        <button type="button" className="btn" onClick={download}>
          Download
        </button>
        <button type="button" className="btn btn-primary" onClick={onDone}>
          I've saved them
        </button>
      </div>
    </div>
  );
}

// The whole dashboard while the admin requires a second factor this
// account doesn't have: set one up, or log out.
export function MfaSetupPage({
  user,
  onDone,
  onLogOut,
}: {
  user: User;
  onDone: () => void;
  onLogOut: () => void;
}): JSX.Element {
  const [codes, setCodes] = useState<string[] | null>(null);
  const passkeys = passkeysUsable(user.passkeyRpId);
  const [kind, setKind] = useState<"totp" | "passkey">(passkeys ? "passkey" : "totp");
  const onAdded = (recovery: string[] | null): void => setCodes(recovery ?? []);

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
        <div className="auth-panel" style={{ width: "min(520px, 100%)" }}>
          <Corners />
          <h1>Set up two-factor authentication</h1>
          {codes === null ? (
            <>
              <p className="prose">
                This server requires a second factor on top of your password:{" "}
                {passkeys ? "a passkey or a code from an authenticator app" : "a code from an authenticator app"}. Set
                one up to continue as <span className="mono">{user.email}</span>.
              </p>
              {passkeys && (
                <Segmented
                  label="Kind of second factor"
                  value={kind}
                  onChange={setKind}
                  options={[
                    ["passkey", "Passkey"],
                    ["totp", "Authenticator app"],
                  ]}
                />
              )}
              {kind === "passkey" ? (
                <AddPasskey user={user} first onAdded={onAdded} />
              ) : (
                <AddAuthenticator user={user} first onAdded={onAdded} />
              )}
            </>
          ) : (
            <RecoveryCodes codes={codes} onDone={onDone} />
          )}
          <button type="button" className="btn btn-ghost btn-block" onClick={() => void logOut().finally(onLogOut)}>
            Log out
          </button>
        </div>
      </div>
    </main>
  );
}
