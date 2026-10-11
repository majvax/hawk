// The owner's tabs on a machine: who it's shared with, and the machine
// itself (name, key, removal).
//
// Every share is a grant the owner's browser signs, and every revocation
// too: the machine checks those signatures itself, so the relay can't add
// viewers. A recipient's key is pinned the first time it's seen here, and a
// different key later is refused until the owner has checked it with them.
import { type FormEvent, type JSX, useCallback, useEffect, useRef, useState } from "react";

import {
  type Share,
  type ShareTerms,
  type SignedStatement,
  describeShareTerms,
  listShares,
  lookupUserKey,
  removeMachine,
  renameMachine,
  shareMachine,
  unshareMachine,
} from "../api.js";
import { fingerprint, fromBase64 } from "../crypto.js";
import { type EnrollmentCheck, endorse, signGrant, signRevocation } from "../e2e.js";
import type { Identity } from "../keys.js";
import { type PinStatus, checkContact, trustContact } from "../keystore.js";
import type { Machine } from "../protocol.js";
import { Alert, ConfirmButton, Segmented, Tag, errorMessage } from "../ui.js";

const SHARE_ROLES = [
  ["view", "View only"],
  ["control", "Can control"],
] as const;

type Duration = "forever" | "30m" | "1h" | "2h" | "8h" | "1d" | "1w" | "until";

const DURATIONS: [Duration, string][] = [
  ["forever", "Until revoked"],
  ["30m", "For 30 minutes"],
  ["1h", "For 1 hour"],
  ["2h", "For 2 hours"],
  ["8h", "For 8 hours"],
  ["1d", "For 1 day"],
  ["1w", "For 1 week"],
  ["until", "Until a set time…"],
];

const DURATION_SECONDS: Record<Exclude<Duration, "forever" | "until">, number> = {
  "30m": 30 * 60,
  "1h": 60 * 60,
  "2h": 2 * 60 * 60,
  "8h": 8 * 60 * 60,
  "1d": 24 * 60 * 60,
  "1w": 7 * 24 * 60 * 60,
};

// A <input type="datetime-local"> value (local time) as unix seconds.
function fromLocalInput(value: string): number | null {
  const millis = new Date(value).getTime();
  return Number.isNaN(millis) ? null : Math.floor(millis / 1000);
}

// A recipient whose key isn't the one first seen for them.
interface KeyChange {
  email: string;
  publicKey: string;
  pinned: string; // fingerprints
  current: string;
}

class KeyChangedError extends Error {
  constructor(readonly change: KeyChange) {
    super(`${change.email}'s key changed since you first shared with them`);
  }
}

// Signs and stores a grant for `email` on these terms, after checking their
// key against the one pinned for them.
async function signShare(
  identity: Identity,
  machineId: string,
  email: string,
  terms: ShareTerms,
  previous: SignedStatement | null,
): Promise<void> {
  const target = await lookupUserKey(email);
  if (target.publicKey === null) {
    throw new Error("that account hasn't set up its key yet; ask them to log in once, then share again");
  }
  const key = fromBase64(target.publicKey);
  const pin = await checkContact(target.email, key);
  if (pin.kind === "changed") {
    throw new KeyChangedError({
      email: target.email,
      publicKey: target.publicKey,
      pinned: await fingerprint(pin.pinned),
      current: await fingerprint(key),
    });
  }
  const grant = await signGrant(identity, machineId, target.publicKey, terms, previous);
  await shareMachine(machineId, target.email, terms, grant);
}

export function SharingPanel({ machine, identity }: { machine: Machine; identity: Identity }): JSX.Element {
  const [shares, setShares] = useState<Share[] | null>(null);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Share["role"]>("view");
  const [duration, setDuration] = useState<Duration>("forever");
  const [until, setUntil] = useState("");
  const [startLater, setStartLater] = useState(false);
  const [startAt, setStartAt] = useState("");
  const [singleView, setSingleView] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [keyChange, setKeyChange] = useState<KeyChange | null>(null);
  // Shares from before grants, signed once per panel when the key allows.
  const signedLegacyRef = useRef(new Set<number>());

  const refresh = useCallback(async (): Promise<void> => {
    try {
      setShares(await listShares(machine.id));
    } catch (caught) {
      setError(errorMessage(caught));
    }
  }, [machine.id]);

  useEffect(() => {
    void refresh();
    // Temporary shares start, expire and get used up on their own.
    const timer = window.setInterval(() => void refresh(), 30_000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const run = async (action: () => Promise<unknown>): Promise<boolean> => {
    setError(null);
    try {
      await action();
      await refresh();
      return true;
    } catch (caught) {
      if (caught instanceof KeyChangedError) setKeyChange(caught.change);
      setError(errorMessage(caught));
      return false;
    }
  };

  const terms = (share: Share): ShareTerms => ({
    role: share.role,
    startsAt: share.startsAt,
    expiresAt: share.expiresAt,
    singleView: share.singleView,
  });

  // Same person, new terms: a new grant, newer than the one it replaces.
  const reshare = (share: Share, next: ShareTerms): Promise<boolean> =>
    run(() => signShare(identity, machine.id, share.email, next, share.grant));

  const revoke = (share: Share): Promise<boolean> =>
    run(async () => {
      const revocation =
        share.grant !== null && share.publicKey !== null
          ? await signRevocation(identity, machine.id, share.publicKey, share.grant)
          : null;
      await unshareMachine(machine.id, share.userId, revocation);
    });

  // Shares from before grants existed: the machine refuses them until the
  // owner signs one, which happens here as soon as the recipient has a key.
  useEffect(() => {
    for (const share of shares ?? []) {
      if (share.grant !== null || share.publicKey === null || signedLegacyRef.current.has(share.userId)) continue;
      signedLegacyRef.current.add(share.userId);
      void reshare(share, terms(share));
    }
  }, [shares]);

  const trustNewKey = async (change: KeyChange): Promise<void> => {
    await trustContact(change.email, fromBase64(change.publicKey), true);
    setKeyChange(null);
    setError(null);
  };

  const submitShare = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    const startsAt = startLater ? fromLocalInput(startAt) : null;
    const begins = startsAt ?? Math.floor(Date.now() / 1000);
    const expiresAt =
      duration === "forever" ? null : duration === "until" ? fromLocalInput(until) : begins + DURATION_SECONDS[duration];
    // An unreadable date must not quietly become "now" or "until revoked".
    if ((startLater && startsAt === null) || (duration !== "forever" && expiresAt === null)) {
      setError("enter a valid date and time");
      return;
    }
    const existing = shares?.find((share) => share.email === email.trim().toLowerCase())?.grant ?? null;
    const next = { role, startsAt, expiresAt, singleView };
    if (await run(() => signShare(identity, machine.id, email, next, existing))) setEmail("");
  };

  // Pushes a temporary share's end back by an hour (from now if it's close).
  const extend = (share: Share): Promise<boolean> => {
    const from = Math.max(share.expiresAt ?? 0, Math.floor(Date.now() / 1000));
    return reshare(share, { ...terms(share), expiresAt: from + 3600 });
  };

  const now = Date.now() / 1000;

  return (
    <div className="pane-body">
      {error !== null && <Alert>{error}</Alert>}
      {keyChange !== null && (
        <div className="block">
          <Alert>
            {keyChange.email}'s key isn't the one you first shared with. It may be a new device or a reset account,
            or someone between you and them. Compare fingerprints with them by another channel before trusting it.
          </Alert>
          <div className="keys-compare">
            <span className="label faint">First seen</span>
            <code className="mono fingerprint">{keyChange.pinned}</code>
            <span className="label faint">Now</span>
            <code className="mono fingerprint">{keyChange.current}</code>
          </div>
          <div className="form-row tight">
            <button type="button" className="btn" onClick={() => void trustNewKey(keyChange)}>
              They confirmed the new one: trust it
            </button>
            <button type="button" className="btn btn-ghost" onClick={() => setKeyChange(null)}>
              Not now
            </button>
          </div>
        </div>
      )}

      <div className="block">
        <div className="block-head">
          <span className="label">Shared with</span>
          {shares !== null && <span className="num faint">{shares.length}</span>}
        </div>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Account</th>
                <th>Key</th>
                <th>Access</th>
                <th>Window</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {shares !== null && shares.length === 0 && (
                <tr>
                  <td colSpan={5} className="muted">
                    Only you. Share it below.
                  </td>
                </tr>
              )}
              {shares?.map((share) => (
                <tr key={share.userId}>
                  <td>
                    <span className="cell">
                      <span className="truncate">{share.email}</span>
                      {share.startsAt !== null && share.startsAt > now && <Tag tone="idle">Scheduled</Tag>}
                    </span>
                  </td>
                  <td>
                    <RecipientKey share={share} />
                  </td>
                  <td>
                    <Segmented
                      small
                      label={`Access for ${share.email}`}
                      options={SHARE_ROLES}
                      value={share.role}
                      onChange={(next) => void reshare(share, { ...terms(share), role: next })}
                    />
                  </td>
                  <td className="num muted">{describeShareTerms(share) || "until revoked"}</td>
                  <td className="actions">
                    {share.expiresAt !== null && (
                      <button type="button" className="btn btn-sm" onClick={() => void extend(share)}>
                        +1 h
                      </button>
                    )}
                    <ConfirmButton
                      small
                      confirmLabel="Confirm"
                      onConfirm={() => void revoke(share)}
                    >
                      Revoke
                    </ConfirmButton>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <form className="block" onSubmit={(e) => void submitShare(e)}>
        <span className="label">Share with someone</span>
        <div className="form-row">
          <label className="field">
            <span className="label faint">Account email</span>
            <input
              className="input"
              type="email"
              placeholder="name@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </label>
          <div className="field" style={{ flex: "none", minWidth: 0 }}>
            <span className="label faint">Access</span>
            <Segmented label="Access" options={SHARE_ROLES} value={role} onChange={setRole} />
          </div>
          <label className="field" style={{ flex: "none", minWidth: 170 }}>
            <span className="label faint">For how long</span>
            <select className="select" value={duration} onChange={(e) => setDuration(e.target.value as Duration)}>
              {DURATIONS.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          {duration === "until" && (
            <label className="field" style={{ flex: "none", minWidth: 0 }}>
              <span className="label faint">Ends</span>
              <input
                className="input"
                type="datetime-local"
                value={until}
                onChange={(e) => setUntil(e.target.value)}
                required
              />
            </label>
          )}
        </div>
        <div className="form-row tight">
          <label className="check">
            <input type="checkbox" checked={startLater} onChange={(e) => setStartLater(e.target.checked)} />
            Start later
          </label>
          {startLater && (
            <input
              className="input"
              type="datetime-local"
              aria-label="Share starts at"
              value={startAt}
              onChange={(e) => setStartAt(e.target.value)}
              required
            />
          )}
          <label className="check">
            <input type="checkbox" checked={singleView} onChange={(e) => setSingleView(e.target.checked)} />
            One viewing only
          </label>
          <button type="submit" className="btn btn-primary" style={{ marginLeft: 8 }}>
            Share
          </button>
        </div>
        <p className="prose" style={{ fontSize: 12 }}>
          They need an account on this server first. View only can watch the screen but never send input. A
          temporary share is revoked when it runs out, cutting off a live view; one viewing only ends the share once
          they stop watching. Sharing again with the same person replaces the terms. Your browser signs each share,
          and the machine checks the signature itself.
        </p>
      </form>
    </div>
  );
}

// A recipient's key, as this browser knows it: its fingerprint, and whether
// it's the key first seen for them.
function RecipientKey({ share }: { share: Share }): JSX.Element {
  const [state, setState] = useState<{ print: string; pin: PinStatus } | null>(null);
  const { email, publicKey } = share;

  useEffect(() => {
    if (publicKey === null) return;
    const key = fromBase64(publicKey);
    void Promise.all([fingerprint(key), checkContact(email, key)]).then(([print, pin]) => setState({ print, pin }));
  }, [email, publicKey]);

  if (publicKey === null) return <Tag tone="warn" title="They haven't logged in since keys were introduced">No key yet</Tag>;
  if (state === null) return <span className="faint">…</span>;
  const short = state.print.split(" ").slice(0, 2).join(" ");
  return (
    <span className="cell" title={`Fingerprint ${state.print}`}>
      <code className="mono">{short}</code>
      {state.pin.kind === "changed" ? (
        <Tag tone="err">Changed</Tag>
      ) : state.pin.kind === "known" && state.pin.verified ? (
        <Tag tone="ok">Verified</Tag>
      ) : share.grant === null ? (
        <Tag tone="warn">Unsigned</Tag>
      ) : null}
    </span>
  );
}

export function MachineSettings({
  machine,
  identity,
  enrollmentCheck,
  onRemoved,
}: {
  machine: Machine;
  identity: Identity;
  enrollmentCheck: EnrollmentCheck | undefined;
  onRemoved: () => void;
}): JSX.Element {
  const [name, setName] = useState(machine.name);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const run = async (action: () => Promise<unknown>): Promise<boolean> => {
    setError(null);
    setSaved(false);
    try {
      await action();
      return true;
    } catch (caught) {
      setError(errorMessage(caught));
      return false;
    }
  };

  const submitRename = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    if (await run(() => renameMachine(machine.id, name))) setSaved(true);
  };

  return (
    <div className="pane-body">
      {error !== null && <Alert>{error}</Alert>}
      {saved && <Alert ok>Name saved.</Alert>}

      <form className="block" onSubmit={(e) => void submitRename(e)}>
        <span className="label">Name</span>
        <div className="form-row">
          <label className="field">
            <span className="label faint">Display name</span>
            <input
              className="input"
              value={name}
              maxLength={64}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </label>
          <button type="submit" className="btn" disabled={name.trim() === machine.name || name.trim() === ""}>
            Rename
          </button>
        </div>
        <span className="field-hint">Only changes how it's listed here; the host name stays {machine.hostname}.</span>
      </form>

      <div className="block">
        <span className="label">Identity</span>
        <div className="strip" style={{ maxWidth: 520, border: "1px solid var(--line)" }}>
          <div className="metric">
            <span className="label faint">Key storage</span>
            <span className="metric-value">
              <KeyStorage storage={machine.keyStorage} />
            </span>
          </div>
          <div className="metric">
            <span className="label faint">Machine ID</span>
            <span className="metric-value" title={machine.id}>
              {machine.id}
            </span>
          </div>
        </div>
      </div>

      <MachineVerification machine={machine} identity={identity} check={enrollmentCheck} />

      <div className="block">
        <span className="label">Remove</span>
        <div className="danger-zone" style={{ maxWidth: 720 }}>
          <span className="prose" style={{ fontSize: 12 }}>
            Disconnects {machine.name}, revokes everyone it's shared with, and it needs a new enrollment code to come
            back.
          </span>
          <ConfirmButton
            confirmLabel="Confirm removal"
            onConfirm={() => void run(() => removeMachine(machine.id)).then((ok) => ok && onRemoved())}
          >
            Remove machine
          </ConfirmButton>
        </div>
      </div>
    </div>
  );
}

// Whether the owner has vouched for the machine's key. Viewers trust what
// the machine signs only through that endorsement, so until then nobody can
// watch it. It happens on its own in the browser that made the enrollment
// code; anywhere else the owner compares fingerprints with the machine.
function MachineVerification({
  machine,
  identity,
  check,
}: {
  machine: Machine;
  identity: Identity;
  check: EnrollmentCheck | undefined;
}): JSX.Element | null {
  const [print, setPrint] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (machine.publicKey !== null) void fingerprint(fromBase64(machine.publicKey)).then(setPrint);
  }, [machine.publicKey]);

  if (machine.publicKey === null) return null;

  const confirm = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      await endorse(identity, machine);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="block">
      <span className="label">End-to-end encryption</span>
      <div className="keys-compare">
        <span className="label faint">Machine key</span>
        <code className="mono fingerprint">{print ?? "…"}</code>
      </div>
      {machine.endorsement !== null ? (
        <span className="cell">
          <Tag tone="ok">Verified</Tag>
          <span className="muted">You vouched for this key; viewers check every stream against it.</span>
        </span>
      ) : check === "mismatch" ? (
        <Alert>
          This key doesn't match the enrollment code you made, so it may not be your machine. Don't trust it: remove
          the machine and enroll it again with a new code.
        </Alert>
      ) : (
        <>
          <p className="prose" style={{ fontSize: 12 }}>
            Not verified yet, so nobody can watch it. The browser that made its enrollment code verifies it on its
            own. From here, compare this fingerprint with the one on the machine: the line "machine key fingerprint"
            in C:\ProgramData\HawkService\hawk-service.log.
          </p>
          {error !== null && <Alert>{error}</Alert>}
          <div>
            <button type="button" className="btn" disabled={busy} onClick={() => void confirm()}>
              {busy ? "Signing…" : "The fingerprints match"}
            </button>
          </div>
        </>
      )}
    </div>
  );
}

// Where the machine keeps the key it authenticates with, as it reports it.
export function KeyStorage({ storage }: { storage: Machine["keyStorage"] }): JSX.Element {
  if (storage === null) {
    return (
      <Tag tone="err" title="Enrolled before key-based authentication; remove and enroll it again">
        Re-enroll needed
      </Tag>
    );
  }
  return storage === "tpm" ? (
    <span title="Its key lives in the TPM and can't be copied off the machine">TPM</span>
  ) : (
    <span title="No usable TPM: its key is in the Windows software key store">Software</span>
  );
}
