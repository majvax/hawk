// Step-up: actions a stolen session shouldn't be enough for (removing a
// machine, sharing it, controlling it, opening a shell, the Admin tab) ask
// for a fresh second factor: a passkey, offered first when the account has
// one this page can use, or a code from an authenticator. The relay decides
// when; this asks the user, proves it for the session, and lets the action
// go on.
import {
  type FormEvent,
  type JSX,
  type ReactNode,
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";
import qrcode from "qrcode-generator";

import { type User, setStepUpHandler, stepUp, stepUpPasskeyChallenge } from "./api.js";
import { Alert, Corners, errorMessage } from "./ui.js";
import { PasskeyCancelled, getPasskey, passkeysUsable } from "./webauthn.js";

// Resolves true once the session has stepped up, false if the user cancelled.
type RequestStepUp = () => Promise<boolean>;

const StepUpContext = createContext<RequestStepUp>(() => Promise.resolve(false));

export const useStepUp = (): RequestStepUp => useContext(StepUpContext);

// Shows the code prompt whenever the relay asks for one, for API requests
// (through api.ts) and for whatever calls useStepUp. Asks once for several
// requests that need it at the same moment.
export function StepUpProvider({ user, children }: { user: User; children: ReactNode }): JSX.Element {
  const [open, setOpen] = useState(false);
  const pendingRef = useRef<{ promise: Promise<boolean>; resolve: (ok: boolean) => void } | null>(null);

  const request = useCallback((): Promise<boolean> => {
    if (pendingRef.current !== null) return pendingRef.current.promise;
    let resolve: (ok: boolean) => void = () => {};
    const promise = new Promise<boolean>((done) => {
      resolve = done;
    });
    pendingRef.current = { promise, resolve };
    setOpen(true);
    return promise;
  }, []);

  const settle = (ok: boolean): void => {
    pendingRef.current?.resolve(ok);
    pendingRef.current = null;
    setOpen(false);
  };

  useEffect(() => {
    setStepUpHandler(request);
    return () => {
      setStepUpHandler(null);
      pendingRef.current?.resolve(false);
    };
  }, [request]);

  return (
    <StepUpContext.Provider value={request}>
      {children}
      {open && <StepUpDialog user={user} onDone={settle} />}
    </StepUpContext.Provider>
  );
}

function StepUpDialog({ user, onDone }: { user: User; onDone: (ok: boolean) => void }): JSX.Element {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const passkey = user.passkeys && passkeysUsable(user.passkeyRpId);

  useEffect(() => {
    dialogRef.current?.showModal();
  }, []);

  const submit = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await stepUp({ code });
      onDone(true);
    } catch (caught) {
      setError(errorMessage(caught));
      setBusy(false);
    }
  };

  const usePasskey = async (): Promise<void> => {
    await stepUp({ passkey: await getPasskey(await stepUpPasskeyChallenge()) });
    onDone(true);
  };

  return (
    <dialog
      ref={dialogRef}
      className="dialog"
      onCancel={(event) => {
        event.preventDefault();
        onDone(false);
      }}
    >
      <form className="auth-panel" onSubmit={(e) => void submit(e)}>
        <Corners />
        <h1>Confirm it's you</h1>
        <p className="prose">
          {passkey ? "This needs your passkey, or" : "This needs"} a fresh code from your authenticator app. It covers
          this browser's next few minutes.
        </p>
        {passkey && <PasskeyOption onUse={usePasskey} />}
        {!passkey && user.passkeys && <PasskeyElsewhere />}
        <CodeField value={code} onChange={setCode} autoFocus={!passkey} />
        {error !== null && <Alert>{error}</Alert>}
        <div className="form-row tight">
          <button type="submit" className={passkey ? "btn" : "btn btn-primary"} disabled={busy || code.trim() === ""}>
            {busy ? "Checking…" : "Confirm"}
          </button>
          <button type="button" className="btn btn-ghost" onClick={() => onDone(false)}>
            Cancel
          </button>
        </div>
      </form>
    </dialog>
  );
}

// The passkey way to answer, offered above the code. A closed or timed-out
// prompt isn't an error: the code is still there.
export function PasskeyOption({ onUse }: { onUse: () => Promise<void> }): JSX.Element {
  const [busy, setBusy] = useState(false);
  const [cancelled, setCancelled] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const use = async (): Promise<void> => {
    setBusy(true);
    setCancelled(false);
    setError(null);
    try {
      await onUse();
    } catch (caught) {
      if (caught instanceof PasskeyCancelled) setCancelled(true);
      else setError(errorMessage(caught));
    }
    setBusy(false);
  };

  return (
    <>
      <button type="button" className="btn btn-primary btn-block" disabled={busy} onClick={() => void use()} autoFocus>
        {busy ? "Waiting for your passkey…" : "Use a passkey"}
      </button>
      {cancelled && <p className="field-hint">No passkey was used. Try again, or enter a code.</p>}
      {error !== null && <Alert>{error}</Alert>}
      <div className="or-rule label faint">or a code</div>
    </>
  );
}

// For an account with a passkey, on a page that can't use it.
export function PasskeyElsewhere(): JSX.Element {
  return (
    <p className="field-hint">
      Your passkey can't be used here (the desktop app, or a dashboard outside this server's domain): enter a code from
      your authenticator app or a recovery code, or open the dashboard in a browser.
    </p>
  );
}

// A code from an authenticator (or a recovery code, which is why it isn't
// limited to six digits).
export function CodeField({
  value,
  onChange,
  label = "Code",
  hint = "Six digits from your app, or one of your recovery codes.",
  autoFocus = true,
}: {
  value: string;
  onChange: (value: string) => void;
  label?: string;
  hint?: string;
  autoFocus?: boolean;
}): JSX.Element {
  return (
    <label className="field">
      <span className="label">{label}</span>
      <input
        className="input mono"
        autoComplete="one-time-code"
        autoCapitalize="characters"
        spellCheck={false}
        maxLength={24}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        required
        autoFocus={autoFocus}
      />
      <span className="field-hint">{hint}</span>
    </label>
  );
}

// An otpauth:// URI as a QR code, drawn as SVG: dark on white with a quiet
// zone whatever the theme, since that's what phone cameras read.
export function QrCode({ value, size = 184 }: { value: string; size?: number }): JSX.Element {
  const qr = qrcode(0, "M");
  qr.addData(value);
  qr.make();
  const count = qr.getModuleCount();
  const margin = 4;
  const cells: string[] = [];
  for (let row = 0; row < count; row++) {
    for (let col = 0; col < count; col++) {
      if (qr.isDark(row, col)) cells.push(`M${col + margin} ${row + margin}h1v1h-1z`);
    }
  }
  const extent = count + margin * 2;
  return (
    <svg
      className="qr"
      width={size}
      height={size}
      viewBox={`0 0 ${extent} ${extent}`}
      shapeRendering="crispEdges"
      role="img"
      aria-label="QR code for your authenticator app"
    >
      <rect width={extent} height={extent} fill="#fff" />
      <path d={cells.join("")} fill="#000" />
    </svg>
  );
}
