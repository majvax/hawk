// hawk-setup's window (src/installer/src/gui.rs): installs the machine
// service or the desktop app, and updates or removes what's there. Every
// action is a command in gui.rs, the same code the command line runs; its
// progress arrives as "progress" events, one line at a time.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { type FormEvent, type JSX, type ReactNode, useCallback, useEffect, useRef, useState } from "react";

import { Alert, ConfirmButton, Corners, Dot, Logo, Segmented, type Tone, errorMessage } from "../ui.js";

interface ServiceStatus {
  state: string;
  detail: string;
  version: string;
}

interface Status {
  setup_version: string;
  machine: {
    installed: boolean;
    version: string | null;
    service: string | null;
    status: ServiceStatus | null;
    relay: string | null;
    update_policy: string | null;
  };
  status_text: string | null;
  app: string | null;
  feed_configured: boolean;
}

interface Check {
  name: string;
  ok: boolean;
  warning: boolean;
  detail: string;
}

type LineKind = "step" | "detail" | "ok" | "warn";

interface Line {
  kind: LineKind;
  text: string;
}

type Policy = "notify" | "auto" | "off";

type Screen =
  | { kind: "home" }
  | { kind: "machine" }
  | { kind: "working"; title: string }
  | { kind: "done"; title: string; ok: boolean; message: string };

const POLICIES: [Policy, string][] = [
  ["notify", "Ask me"],
  ["auto", "Automatic"],
  ["off", "Never"],
];

const POLICY_HINT: Record<Policy, string> = {
  notify: "New releases show in your dashboard; they install when you say so.",
  auto: "New releases install by themselves, checked against the release signature first.",
  off: "This PC never looks for updates. Run hawk-setup again to update it.",
};

// The relay address from a socket URL, as people type it.
function relayFromUrl(url: string | null): string {
  if (url === null) return "";
  return url.replace(/^wss:\/\//, "").replace(/\/v1\/ws$/, "");
}

export function Setup(): JSX.Element {
  const [status, setStatus] = useState<Status | null>(null);
  const [screen, setScreen] = useState<Screen>({ kind: "home" });
  const [lines, setLines] = useState<Line[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);

  const refresh = useCallback((): void => {
    invoke<Status>("status").then(setStatus, (caught: unknown) => setLoadError(errorMessage(caught)));
  }, []);

  useEffect(refresh, [refresh]);

  useEffect(() => {
    const unlisten = listen<Line>("progress", (event) => setLines((previous) => [...previous, event.payload]));
    return () => void unlisten.then((stop) => stop());
  }, []);

  // Runs one long command, showing its progress, then its outcome.
  const work = async (title: string, command: Promise<unknown>, success: string): Promise<void> => {
    setLines([]);
    setScreen({ kind: "working", title });
    try {
      await command;
      setScreen({ kind: "done", title, ok: true, message: success });
    } catch (caught) {
      setScreen({ kind: "done", title, ok: false, message: errorMessage(caught, "something went wrong") });
    }
    refresh();
  };

  let body: ReactNode;
  if (loadError !== null) {
    body = (
      <Panel title="Setup">
        <Alert>{loadError}</Alert>
      </Panel>
    );
  } else if (status === null) {
    body = (
      <Panel title="Setup">
        <p className="muted">Looking at this PC…</p>
      </Panel>
    );
  } else if (screen.kind === "machine") {
    body = (
      <MachineForm
        status={status}
        onCancel={() => setScreen({ kind: "home" })}
        onInstall={(form) =>
          void work(
            status.machine.installed ? "Updating the setup" : "Setting up this PC",
            invoke("install_machine", { form }),
            form.code === ""
              ? "The service is installed and running."
              : "This PC is enrolled. Open your dashboard and check the machine's key there.",
          )
        }
      />
    );
  } else if (screen.kind === "working" || screen.kind === "done") {
    body = (
      <Panel title={screen.title} wide>
        <ProgressLog lines={lines} />
        {screen.kind === "working" ? (
          <p className="muted setup-busy">Working… keep this window open.</p>
        ) : (
          <>
            {screen.ok ? <Alert ok>{screen.message}</Alert> : <Alert>{screen.message}</Alert>}
            <div className="setup-actions">
              <button type="button" className="btn" onClick={() => setScreen({ kind: "home" })}>
                Back
              </button>
              <button type="button" className="btn btn-primary" onClick={() => void getCurrentWindow().close()}>
                Close
              </button>
            </div>
          </>
        )}
      </Panel>
    );
  } else {
    body = <Home status={status} onSetUp={() => setScreen({ kind: "machine" })} work={work} />;
  }

  return (
    <main className="auth setup">
      <div className="auth-hero">
        <Logo size={220} />
        <div className="auth-wordmark">
          <span className="brand-name">HAWK</span>
          <span className="mono faint">setup {status?.setup_version ?? ""}</span>
        </div>
      </div>
      <div className="auth-side">{body}</div>
    </main>
  );
}

function Panel({ title, wide = false, children }: { title: string; wide?: boolean; children: ReactNode }): JSX.Element {
  return (
    <div className={wide ? "auth-panel setup-panel wide" : "auth-panel setup-panel"}>
      <Corners />
      <h1>{title}</h1>
      {children}
    </div>
  );
}

function Home({
  status,
  onSetUp,
  work,
}: {
  status: Status;
  onSetUp: () => void;
  work: (title: string, command: Promise<unknown>, success: string) => Promise<void>;
}): JSX.Element {
  const { machine } = status;
  const [available, setAvailable] = useState<string | null | undefined>(undefined);
  const [checking, setChecking] = useState(false);
  const [checkError, setCheckError] = useState<string | null>(null);
  const [keepData, setKeepData] = useState(false);

  const check = (): void => {
    setChecking(true);
    setCheckError(null);
    invoke<string | null>("check_update").then(
      (version) => {
        setAvailable(version);
        setChecking(false);
      },
      (caught: unknown) => {
        setCheckError(errorMessage(caught));
        setChecking(false);
      },
    );
  };

  const linked = machine.status?.state === "connected" || machine.status?.state === "enrolled";
  const tone: Tone = machine.service !== "running" ? "err" : linked ? "ok" : "warn";

  return (
    <Panel title={machine.installed ? "This PC" : "Set up Hawk"}>
      {!status.feed_configured && (
        <Alert>This is a development build: it has no release feed to install from.</Alert>
      )}
      {machine.installed ? (
        <>
          <dl className="setup-facts">
            <dt>Version</dt>
            <dd className="mono">{machine.version ?? "unknown"}</dd>
            <dt>Service</dt>
            <dd>
              <Dot tone={tone} /> {status.status_text ?? machine.service ?? "not registered"}
            </dd>
            <dt>Relay</dt>
            <dd className="mono truncate">{relayFromUrl(machine.relay) || "not set"}</dd>
            <dt>Updates</dt>
            <dd>{POLICIES.find(([id]) => id === machine.update_policy)?.[1] ?? "Ask me"}</dd>
          </dl>
          {available === undefined ? (
            <button type="button" className="btn btn-block" disabled={checking} onClick={check}>
              {checking ? "Checking…" : "Check for updates"}
            </button>
          ) : available === null ? (
            <Alert ok>Up to date.</Alert>
          ) : (
            <button
              type="button"
              className="btn btn-accent btn-block"
              onClick={() => void work(`Updating to ${available}`, invoke("update_machine"), `Updated to ${available}.`)}
            >
              Update to {available}
            </button>
          )}
          {checkError !== null && <Alert>{checkError}</Alert>}
          <button type="button" className="btn btn-block" onClick={onSetUp}>
            Change relay or enroll again
          </button>
          <div className="setup-remove">
            <label className="check">
              <input type="checkbox" checked={keepData} onChange={(e) => setKeepData(e.target.checked)} />
              Keep settings and the machine key
            </label>
            <ConfirmButton
              small
              confirmLabel="Remove the service"
              onConfirm={() =>
                void work(
                  "Uninstalling",
                  invoke("uninstall_machine", { keepData }),
                  keepData
                    ? "Removed. Settings and the machine key were kept for a reinstall."
                    : "Removed. Remove the machine in your dashboard too.",
                )
              }
            >
              Uninstall
            </ConfirmButton>
          </div>
        </>
      ) : (
        <>
          <p className="prose">
            Make this PC reachable from your relay. You'll need its address, its key pin and an enrollment code, all
            shown in your dashboard under <span className="mono">Machines → Add machine</span>.
          </p>
          <button type="button" className="btn btn-primary btn-block" onClick={onSetUp}>
            Set up this PC
          </button>
        </>
      )}
      <p className="auth-foot">
        {status.app === null ? (
          <>
            Want to <em>view</em> other machines from here?{" "}
            <button
              type="button"
              className="link"
              onClick={() =>
                void work(
                  "Installing the desktop app",
                  invoke("install_app"),
                  "Installed. Start Hawk from the Start menu.",
                )
              }
            >
              Install the desktop app
            </button>
            .
          </>
        ) : (
          <>Desktop app {status.app} is installed; it updates itself.</>
        )}
      </p>
    </Panel>
  );
}

interface Form {
  relay: string;
  pin: string;
  code: string;
  policy: Policy;
}

function MachineForm({
  status,
  onCancel,
  onInstall,
}: {
  status: Status;
  onCancel: () => void;
  onInstall: (form: Form) => void;
}): JSX.Element {
  const [form, setForm] = useState<Form>({
    relay: relayFromUrl(status.machine.relay),
    pin: "",
    code: "",
    policy: (status.machine.update_policy as Policy | null) ?? "notify",
  });
  const [checks, setChecks] = useState<Check[] | null>(null);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const set = (patch: Partial<Form>): void => {
    setForm((previous) => ({ ...previous, ...patch }));
    if (patch.relay !== undefined || patch.pin !== undefined) setChecks(null);
  };

  const check = (event: FormEvent): void => {
    event.preventDefault();
    setChecking(true);
    setError(null);
    invoke<Check[]>("preflight", { relay: form.relay, pins: form.pin.split(/[\s,]+/) }).then(
      (result) => {
        setChecks(result);
        setChecking(false);
      },
      (caught: unknown) => {
        setError(errorMessage(caught));
        setChecking(false);
      },
    );
  };

  const ready = checks !== null && checks.every((item) => item.ok);

  return (
    <form className="auth-panel setup-panel" onSubmit={check}>
      <Corners />
      <h1>{status.machine.installed ? "Relay and enrollment" : "Set up this PC"}</h1>
      <label className="field">
        <span className="label">Relay address</span>
        <input
          className="input"
          placeholder="relay.example.com"
          spellCheck={false}
          value={form.relay}
          onChange={(e) => set({ relay: e.target.value })}
          required
          autoFocus
        />
      </label>
      <label className="field">
        <span className="label">Relay key pin</span>
        <input
          className="input"
          placeholder="44 characters ending in ="
          spellCheck={false}
          value={form.pin}
          onChange={(e) => set({ pin: e.target.value })}
        />
      </label>
      <label className="field">
        <span className="label">Enrollment code</span>
        <input
          className="input"
          placeholder={status.machine.installed ? "only to enroll again" : "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"}
          spellCheck={false}
          value={form.code}
          onChange={(e) => set({ code: e.target.value.toUpperCase() })}
          required={!status.machine.installed}
        />
      </label>
      <div className="field">
        <span className="label">Updates</span>
        <Segmented label="Updates" options={POLICIES} value={form.policy} onChange={(policy) => set({ policy })} />
        <span className="field-hint">{POLICY_HINT[form.policy]}</span>
      </div>
      {checks !== null && (
        <ul className="setup-checks">
          {checks.map((item) => (
            <li key={item.name}>
              <Dot tone={!item.ok ? "err" : item.warning ? "warn" : "ok"} />
              <span className="setup-check-name">{item.name}</span>
              <span className="setup-check-detail">{item.detail}</span>
            </li>
          ))}
        </ul>
      )}
      {error !== null && <Alert>{error}</Alert>}
      <div className="setup-actions">
        <button type="button" className="btn btn-ghost" onClick={onCancel}>
          Back
        </button>
        {ready ? (
          <button type="button" className="btn btn-primary" onClick={() => onInstall(form)}>
            {status.machine.installed ? "Apply" : "Install"}
          </button>
        ) : (
          <button type="submit" className="btn btn-primary" disabled={checking}>
            {checking ? "Checking…" : "Check"}
          </button>
        )}
      </div>
    </form>
  );
}

const MARK: Record<LineKind, string> = { step: "›", detail: " ", ok: "✓", warn: "!" };

function ProgressLog({ lines }: { lines: Line[] }): JSX.Element {
  const end = useRef<HTMLDivElement | null>(null);
  useEffect(() => end.current?.scrollIntoView({ block: "end" }), [lines]);
  return (
    <div className="setup-log" role="log" aria-live="polite">
      {lines.map((line, index) => (
        <div key={index} className={`setup-line ${line.kind}`}>
          <span className="setup-mark">{MARK[line.kind]}</span>
          <span>{line.text}</span>
        </div>
      ))}
      <div ref={end} />
    </div>
  );
}
