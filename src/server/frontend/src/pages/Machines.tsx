import { type DragEvent, type JSX, type ReactNode, Suspense, lazy, useEffect, useRef, useState } from "react";

import {
  type EnrollmentCode,
  describeShareTerms,
  formatAgo,
  formatElapsed,
  formatTime,
} from "../api.js";
import { createEnrollment } from "../e2e.js";
import { relayHost, relayPageUrl } from "../relay.js";
import type { Identity } from "../keys.js";
import {
  MAX_CLIPBOARD_BYTES,
  MAX_CLIPBOARD_IMAGE_BYTES,
  type Machine,
  type PowerAction,
  type Role,
  canControl as roleCanControl,
  canFiles,
  canShell,
  canView,
} from "../protocol.js";
import { canReadImages, canWriteImages, formatBytes, imageProblem } from "../clipboardImages.js";
import { Alert, CodeBlock, CopyButton, Corners, Dot, Metric, Tag, errorMessage, useNow } from "../ui.js";
import type { Dashboard, ViewSecurity } from "../useDashboard.js";
import { useRemoteInput } from "../useRemoteInput.js";
import { useTouchInput, useTouchKeyboard } from "../useTouchInput.js";
import type { Modifier } from "../touchKeyboard.js";
import { useStepUp } from "../stepUp.js";
import { AnalyticsPanel, ProcessesPanel } from "./AnalyticsPanel.js";
import { ANSWER_TIMEOUT_MS, ConfigPanel } from "./ConfigPanel.js";
import { FilesPanel } from "./FilesPanel.js";
import { QUALITY_PRESETS, describeQuality } from "../quality.js";
import { KeyStorage, MachineSettings, SharingPanel } from "./MachineAccess.js";

// xterm.js is most of a terminal's weight, and most visits never open one:
// it's loaded the first time a terminal is shown.
const ShellPanel = lazy(() => import("./ShellPanel.js").then((module) => ({ default: module.ShellPanel })));

export const ROLE_LABEL: Record<Role, string> = {
  owner: "Owner",
  control: "Can control",
  view: "View only",
  dev: "Shell only",
};


export function formatBitrate(kbps: number): string {
  return kbps >= 1000 ? `${(kbps / 1000).toFixed(1)} Mb/s` : `${kbps} kb/s`;
}

// The same three things hawk-setup's window asks for, as one command for
// a script or a terminal.
function installCommand(enrollment: EnrollmentCode): string {
  const pin = enrollment.relayPin === null ? "" : ` --pin ${enrollment.relayPin}`;
  return `hawk-setup install machine --relay ${relayHost()}${pin} --code ${enrollment.code}`;
}

// "up 02:14:07" while online, "seen 4m ago" otherwise.
function presence(machine: Machine, now: number): string {
  if (machine.online) {
    if (machine.connectedAt === null) return "Online";
    return `up ${formatElapsed((now - Date.parse(machine.connectedAt)) / 1000)}`;
  }
  return machine.lastSeenAt === null ? "Never connected" : `seen ${formatAgo(machine.lastSeenAt, now)}`;
}

// The time limits on a share this user was given, if any.
function accessTerms(machine: Machine): string {
  if (machine.role === "owner") return "";
  return describeShareTerms({ startsAt: null, expiresAt: machine.accessExpiresAt, singleView: machine.singleView });
}

export function MachinesPage({
  dashboard,
  identity,
  visible,
}: {
  dashboard: Dashboard;
  identity: Identity;
  visible: boolean;
}): JSX.Element {
  const { machines, status, viewingId, startView, stopView } = dashboard;
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [tab, setTab] = useState<DetailTab>("screen");
  const [enrollment, setEnrollment] = useState<EnrollmentCode | null>(null);
  const [error, setError] = useState<string | null>(null);
  const now = useNow();

  const selected = machines.find((machine) => machine.id === selectedId) ?? null;
  const viewing = machines.find((machine) => machine.id === viewingId) ?? null;
  const tabs = selected === null ? [] : tabsFor(selected);
  const detailTab = tabs.some(([id]) => id === tab) ? tab : (tabs[0]?.[0] ?? "screen");

  const select = (id: string | null): void => {
    if (id !== selectedId) {
      const machine = machines.find((candidate) => candidate.id === id);
      setTab(machine === undefined ? "screen" : (tabsFor(machine)[0]?.[0] ?? "screen"));
    }
    setSelectedId(id);
  };

  const connect = (machine: Machine): void => {
    if (machine.id !== selectedId) select(machine.id);
    startView(machine.id);
  };

  const addMachine = async (): Promise<void> => {
    setError(null);
    try {
      setEnrollment(await createEnrollment(identity));
    } catch (caught) {
      setError(errorMessage(caught));
    }
  };

  const online = machines.filter((machine) => machine.online).length;

  return (
    <div className="console">
      <aside className="rail" aria-label="Machines">
        <div className="rail-head">
          <span className="label">Machines</span>
          <span className="num faint">
            {online}/{machines.length}
          </span>
          <button type="button" className="btn btn-sm" onClick={() => void addMachine()}>
            Add
          </button>
        </div>
        <div className="rail-list">
          <button
            type="button"
            className="rail-item"
            aria-current={selected === null}
            onClick={() => select(null)}
          >
            <span className="dot tone-neutral" aria-hidden />
            <span className="rail-name">Overview</span>
            <span />
            <span className="rail-meta">
              <span>
                {machines.length} {machines.length === 1 ? "machine" : "machines"}, {online} online
              </span>
            </span>
          </button>
          {machines.map((machine) => (
            <RailItem
              key={machine.id}
              machine={machine}
              selected={machine.id === selectedId}
              live={machine.id === viewingId}
              onSelect={() => select(machine.id)}
            />
          ))}
        </div>
        <div className="rail-foot">Machines shared with you appear here too.</div>
      </aside>

      <section className="pane" aria-label={selected?.name ?? "Overview"}>
        {error !== null && (
          <div style={{ padding: "14px 14px 0" }}>
            <Alert>{error}</Alert>
          </div>
        )}
        {enrollment !== null && <Enrollment enrollment={enrollment} onDone={() => setEnrollment(null)} />}

        {selected === null ? (
          <Overview
            machines={machines}
            viewingId={viewingId}
            now={now}
            onSelect={select}
            onConnect={connect}
            onAdd={() => void addMachine()}
          />
        ) : (
          <>
            <div className="pane-head">
              <div className="pane-title">
                <h1>
                  <span className="truncate">{selected.name}</span>
                  {selected.id === viewingId && (
                    <Tag tone="accent" solid>
                      Live
                    </Tag>
                  )}
                </h1>
                <span className="sub truncate">
                  {selected.hostname}
                  {selected.role !== "owner" && ` · shared by ${selected.ownerEmail}`}
                </span>
              </div>
              <div className="pane-actions">
                {selected.id === viewingId ? (
                  <button type="button" className="btn" onClick={stopView}>
                    Disconnect
                  </button>
                ) : (
                  <button
                    type="button"
                    className="btn btn-accent"
                    disabled={!selected.online}
                    onClick={() => connect(selected)}
                  >
                    Connect
                  </button>
                )}
              </div>
            </div>
            <MachineStrip machine={selected} now={now} onInstallUpdate={dashboard.installUpdate} />
            {tabs.length > 1 && (
              <div className="pane-tabs" role="tablist">
                {tabs.map(([id, label]) => (
                  <button
                    key={id}
                    type="button"
                    role="tab"
                    aria-selected={detailTab === id}
                    onClick={() => setTab(id)}
                  >
                    {label}
                  </button>
                ))}
              </div>
            )}
            {detailTab === "files" && (
              <ToolTab dashboard={dashboard} machine={selected} viewing={viewing} onConnect={connect}>
                {(connected) => (
                  <FilesPanel files={dashboard.files} actions={dashboard.fileActions} connected={connected} />
                )}
              </ToolTab>
            )}
            {(detailTab === "analytics" || detailTab === "processes") && (
              <AnalyticsTab dashboard={dashboard} machine={selected} viewing={viewing} onConnect={connect}>
                {detailTab === "analytics" ? (
                  <AnalyticsPanel metrics={dashboard.metrics} actions={dashboard.metricsActions} />
                ) : (
                  <ProcessesPanel metrics={dashboard.metrics} actions={dashboard.metricsActions} />
                )}
              </AnalyticsTab>
            )}
            {detailTab === "config" && (
              <ConfigTab dashboard={dashboard} machine={selected} viewing={viewing} onConnect={connect} />
            )}
            {detailTab === "sharing" && <SharingPanel key={selected.id} machine={selected} identity={identity} />}
            {detailTab === "machine" && (
              <MachineSettings
                key={selected.id}
                machine={selected}
                identity={identity}
                enrollmentCheck={dashboard.enrollmentChecks[selected.id]}
                onRemoved={() => select(null)}
              />
            )}
          </>
        )}

        {/* Mounted while there are shells, so their terminals keep their
            scrollback while another tab or machine is on show. */}
        <ShellTab
          dashboard={dashboard}
          machine={selected}
          viewing={viewing}
          shown={visible && selected !== null && detailTab === "terminal"}
          onConnect={connect}
        />

        {/* Always mounted: the canvas frames are drawn into lives here, and a
            view keeps running while another machine or tab is on show. */}
        <Viewer
          dashboard={dashboard}
          shown={visible && selected !== null && detailTab === "screen"}
          selected={selected}
          viewing={viewing}
          status={status}
          onConnect={connect}
        />
      </section>
    </div>
  );
}

function RailItem({
  machine,
  selected,
  live,
  onSelect,
}: {
  machine: Machine;
  selected: boolean;
  live: boolean;
  onSelect: () => void;
}): JSX.Element {
  const watchers = machine.viewers?.length ?? 0;
  return (
    <button
      type="button"
      className={machine.online ? "rail-item" : "rail-item offline"}
      aria-current={selected}
      onClick={onSelect}
    >
      <Dot tone={statusTone(machine)} title={statusText(machine)} />
      <span className="rail-name truncate">{machine.name}</span>
      {live ? (
        <Tag tone="accent">Live</Tag>
      ) : machine.role === "owner" && machine.keyStorage === null ? (
        <Tag tone="err">Re-enroll</Tag>
      ) : machine.publicKey !== null && machine.endorsement === null ? (
        <Tag tone="warn" title="Its key hasn't been verified yet, so nobody can watch it">
          Unverified
        </Tag>
      ) : watchers > 0 ? (
        <Tag title={machine.viewers?.join(", ")}>{watchers} watching</Tag>
      ) : (
        <span />
      )}
      <span className="rail-meta">
        <span>{machine.hostname}</span>
        <span>{machine.role === "owner" ? "owner" : machine.role}</span>
        {accessTerms(machine) !== "" && <span>{accessTerms(machine)}</span>}
      </span>
    </button>
  );
}

// Online, offline, or on its way back from a restart it announced.
function statusText(machine: Machine): string {
  if (machine.restarting === true) return machine.online ? "Restarting…" : "Restarting";
  return machine.online ? "Online" : "Offline";
}

function statusTone(machine: Machine): "ok" | "warn" | "idle" {
  if (machine.restarting === true) return "warn";
  return machine.online ? "ok" : "idle";
}

function MachineStrip({
  machine,
  now,
  onInstallUpdate,
}: {
  machine: Machine;
  now: number;
  onInstallUpdate: (deviceId: string) => void;
}): JSX.Element {
  const terms = accessTerms(machine);
  const [installing, setInstalling] = useState<string | null>(null);
  return (
    <div className="strip">
      <Metric label="Status">
        <Dot tone={statusTone(machine)} />
        {statusText(machine)}
      </Metric>
      {machine.online ? (
        <Metric label="Uptime">
          {machine.connectedAt === null ? "—" : formatElapsed((now - Date.parse(machine.connectedAt)) / 1000)}
        </Metric>
      ) : (
        <Metric label="Last seen" dim={machine.lastSeenAt === null}>
          {machine.lastSeenAt === null ? "never" : formatTime(machine.lastSeenAt)}
        </Metric>
      )}
      <Metric label="Access">{ROLE_LABEL[machine.role]}</Metric>
      {terms !== "" && <Metric label="Share ends">{terms}</Metric>}
      {machine.role === "owner" && (
        <Metric label="Machine key">
          <KeyStorage storage={machine.keyStorage} />
        </Metric>
      )}
      {machine.version != null && (
        <Metric label="Version">
          <span className="mono">{machine.version}</span>
          {machine.updateAvailable != null && (
            <button
              type="button"
              className="btn btn-sm btn-accent"
              style={{ marginLeft: 8 }}
              disabled={installing === machine.updateAvailable}
              title="The machine checks the release's signature before installing it, then restarts its service"
              onClick={() => {
                setInstalling(machine.updateAvailable ?? null);
                onInstallUpdate(machine.id);
              }}
            >
              {installing === machine.updateAvailable ? "Installing…" : `Update to ${machine.updateAvailable}`}
            </button>
          )}
        </Metric>
      )}
      {machine.viewers !== null && (
        <Metric label="Watching" dim={machine.viewers.length === 0}>
          <span className="truncate" title={machine.viewers.join(", ")}>
            {machine.viewers.length === 0 ? "nobody" : machine.viewers.join(", ")}
          </span>
        </Metric>
      )}
    </div>
  );
}

function Overview({
  machines,
  viewingId,
  now,
  onSelect,
  onConnect,
  onAdd,
}: {
  machines: Machine[];
  viewingId: string | null;
  now: number;
  onSelect: (id: string) => void;
  onConnect: (machine: Machine) => void;
  onAdd: () => void;
}): JSX.Element {
  const online = machines.filter((machine) => machine.online).length;
  const owned = machines.filter((machine) => machine.role === "owner").length;
  const watchers = machines.reduce((sum, machine) => sum + (machine.viewers?.length ?? 0), 0);

  return (
    <div className="overview">
      <div className="overview-head">
        <h1>Overview</h1>
        <button type="button" className="btn" onClick={onAdd}>
          Add machine
        </button>
      </div>
      <div className="strip">
        <Metric label="Online">
          <Dot tone={online > 0 ? "ok" : "idle"} />
          {online}
        </Metric>
        <Metric label="Offline" dim={machines.length - online === 0}>
          {machines.length - online}
        </Metric>
        <Metric label="Yours">{owned}</Metric>
        <Metric label="Shared with you" dim={machines.length - owned === 0}>
          {machines.length - owned}
        </Metric>
        <Metric label="Watching yours" dim={watchers === 0}>
          {watchers}
        </Metric>
      </div>

      {machines.length === 0 ? (
        <div className="pane-body">
          <div className="block">
            <h2>No machines yet</h2>
            <p className="prose">
              Add a Windows PC by enrolling it with a one-time code, or ask someone on this server to share one of
              theirs with your account.
            </p>
            <div>
              <button type="button" className="btn btn-primary" onClick={onAdd}>
                Add machine
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Machine</th>
                <th>Host</th>
                <th>Status</th>
                <th>Access</th>
                <th>Watching</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {machines.map((machine) => (
                <tr key={machine.id} className="clickable" onClick={() => onSelect(machine.id)}>
                  <td>
                    <span className="cell">
                      <Dot tone={statusTone(machine)} title={statusText(machine)} />
                      <span className="truncate">{machine.name}</span>
                      {machine.id === viewingId && <Tag tone="accent">Live</Tag>}
                      {machine.role === "owner" && machine.keyStorage === null && <Tag tone="err">Re-enroll</Tag>}
                    </span>
                  </td>
                  <td className="mono muted">{machine.hostname}</td>
                  <td className={machine.online ? "num" : "num muted"}>{presence(machine, now)}</td>
                  <td>
                    <span className="cell">
                      {ROLE_LABEL[machine.role]}
                      {machine.role !== "owner" && <span className="muted truncate">{machine.ownerEmail}</span>}
                      {accessTerms(machine) !== "" && <Tag tone="warn">{accessTerms(machine)}</Tag>}
                    </span>
                  </td>
                  <td className="muted">
                    {machine.viewers === null ? "" : machine.viewers.join(", ") || <span className="faint">—</span>}
                  </td>
                  <td className="actions">
                    <button
                      type="button"
                      className="btn btn-sm"
                      disabled={!machine.online || machine.id === viewingId}
                      onClick={(event) => {
                        event.stopPropagation();
                        onConnect(machine);
                      }}
                    >
                      {machine.id === viewingId ? "Live" : "Connect"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function Enrollment({ enrollment, onDone }: { enrollment: EnrollmentCode; onDone: () => void }): JSX.Element {
  return (
    <div className="enroll" role="region" aria-label="Add a machine">
      <div className="block-head">
        <h2 style={{ flex: 1 }}>Add a machine</h2>
        <a className="btn btn-ghost btn-sm" href={relayPageUrl("/docs/machine")} target="_blank" rel="noopener">
          Setup guide
        </a>
        <button type="button" className="btn btn-sm" onClick={onDone}>
          Done
        </button>
      </div>
      <ol className="steps">
        <li>
          <span>
            Enrollment code. It works once and expires at{" "}
            <span className="num">{formatTime(enrollment.expiresAt)}</span>. It won't be shown again.
          </span>
          <CodeBlock value={enrollment.code} big />
        </li>
        <li>
          <span>
            On the PC, run <span className="mono">hawk-setup.exe</span> from the release and enter the relay's address
            and key pin. The code never reaches the relay: it lets your machine and this browser check each other's
            keys.
          </span>
          <dl className="enroll-values">
            <dt>Relay</dt>
            <dd>
              <CodeBlock value={relayHost()} />
            </dd>
            {enrollment.relayPin !== null && (
              <>
                <dt>Key pin</dt>
                <dd>
                  <CodeBlock value={enrollment.relayPin} />
                </dd>
              </>
            )}
          </dl>
          <span className="field-hint">
            Or from an elevated terminal, for a script or a PC without a screen:
          </span>
          <CodeBlock value={installCommand(enrollment)} />
          {enrollment.relayPin !== null && (
            <span className="field-hint">
              The pin makes the machine accept only this relay's TLS key, even from a certificate it would otherwise
              trust.
            </span>
          )}
        </li>
        <li>
          <span>
            The machine shows up in the list once it connects, and this browser verifies its key on its own. Made
            the code elsewhere? Compare fingerprints in the machine's Machine tab instead.
          </span>
          <span />
        </li>
      </ol>
    </div>
  );
}

// The navigator.keyboard slice used here; not in TypeScript's lib.dom yet.
// Chromium only: elsewhere system shortcuts just stay with the browser.
interface KeyboardLock {
  lock?: () => Promise<void>;
  unlock?: () => void;
}
const keyboardLock = (): KeyboardLock | undefined => (navigator as Navigator & { keyboard?: KeyboardLock }).keyboard;

// What the clipboard panel under the screen shows, if anything: text to
// paste typed by hand (when the browser won't hand its clipboard over),
// or the machine's text or picture (when the browser won't take it). A
// picture's object URL is revoked once the panel moves on.
type ClipboardPanel =
  | { kind: "paste"; text: string }
  | { kind: "received"; text: string }
  | { kind: "image"; url: string; width: number; height: number }
  | null;

function byteSize(text: string): number {
  return new TextEncoder().encode(text).length;
}

const formatSize = formatBytes;

// The Power menu. Anything that closes apps asks for a second click.
const POWER_ITEMS: { action: PowerAction; label: string; warning: string | null; sent: (name: string) => string }[] = [
  {
    action: "lock",
    label: "Lock",
    warning: null,
    sent: (name) => `Locked ${name}: its sign-in screen comes up, and the session waits behind it.`,
  },
  {
    action: "sign_out",
    label: "Sign out",
    warning: "Signs out whoever is using it; unsaved work is lost.",
    sent: (name) => `Signing out of ${name}. The view stays, at its sign-in screen.`,
  },
  {
    action: "restart",
    label: "Restart",
    warning: "Every app is closed, saved or not.",
    sent: (name) => `Restarting ${name}. The view comes back by itself, at its sign-in screen.`,
  },
  {
    action: "shut_down",
    label: "Shut down",
    warning: "Every app is closed, and it stays off until someone turns it on.",
    sent: (name) => `Shutting down ${name}.`,
  },
];

// How fingers drive the machine: as a laptop's touchpad (the default on a
// phone, where targets are too small to hit with a finger), or where they
// touch (the default on a tablet). Remembered in this browser.
type TouchControl = "trackpad" | "direct";
const TOUCH_KEY = "hawk.view.touch";

function coarsePointer(): boolean {
  try {
    return window.matchMedia("(pointer: coarse)").matches;
  } catch {
    return false;
  }
}

function loadTouchControl(): TouchControl {
  try {
    const stored = window.localStorage.getItem(TOUCH_KEY);
    if (stored === "trackpad" || stored === "direct") return stored;
  } catch {
    // Storage blocked: the default it is.
  }
  return Math.min(window.screen.width, window.screen.height) < 600 ? "trackpad" : "direct";
}

function saveTouchControl(control: TouchControl): void {
  try {
    window.localStorage.setItem(TOUCH_KEY, control);
  } catch {
    // Not remembered, then.
  }
}

// The extra keys under the screen, for what a phone's keyboard lacks.
const EXTRA_KEYS: { label: string; code: string; modifier?: Modifier }[] = [
  { label: "Esc", code: "Escape" },
  { label: "Tab", code: "Tab" },
  { label: "Ctrl", code: "ControlLeft", modifier: "ControlLeft" },
  { label: "Alt", code: "AltLeft", modifier: "AltLeft" },
  { label: "Shift", code: "ShiftLeft", modifier: "ShiftLeft" },
  { label: "Win", code: "MetaLeft", modifier: "MetaLeft" },
  { label: "←", code: "ArrowLeft" },
  { label: "↑", code: "ArrowUp" },
  { label: "↓", code: "ArrowDown" },
  { label: "→", code: "ArrowRight" },
];

// Keeps a button from taking the focus as it's tapped, so the phone's
// keyboard stays up while the extra keys are used.
function keepFocus(event: { preventDefault: () => void }): void {
  event.preventDefault();
}

function Viewer({
  dashboard,
  shown,
  selected,
  viewing,
  status,
  onConnect,
}: {
  dashboard: Dashboard;
  shown: boolean;
  selected: Machine | null;
  viewing: Machine | null;
  status: Dashboard["status"];
  onConnect: (machine: Machine) => void;
}): JSX.Element {
  const {
    canvasRef,
    picture,
    stats,
    decodeError,
    security,
    clipboard,
    files,
    fileActions,
    sendInput,
    sendClipboard,
    pasteImage,
    sendPower,
    elevated,
    sound,
    setMuted,
    unlockSound,
    sync,
    setSync,
    audioDevices,
    requestAudioDevices,
    selectAudioDevice,
    statsShown,
    setStatsShown,
    setStatsVisible,
    streamQuality,
    setQuality,
    sendSas,
    sasResult,
    clearSasResult,
  } = dashboard;
  const requestStepUp = useStepUp();
  const stageRef = useRef<HTMLDivElement>(null);
  const [fullscreen, setFullscreen] = useState(false);
  const [keysLocked, setKeysLocked] = useState(false);
  const [clipPanel, setClipPanel] = useState<ClipboardPanel>(null);
  const [clipNote, setClipNote] = useState<string | null>(null);
  const [dropping, setDropping] = useState(false);
  const [dropNote, setDropNote] = useState<string | null>(null);
  const [clipMenu, setClipMenu] = useState(false);
  const [powerMenu, setPowerMenu] = useState(false);
  const [soundMenu, setSoundMenu] = useState(false);
  const [qualityMenu, setQualityMenu] = useState(false);
  // The power action waiting for its second click.
  const [armed, setArmed] = useState<PowerAction | null>(null);
  const [powerNote, setPowerNote] = useState<string | null>(null);
  const [sasNote, setSasNote] = useState<string | null>(null);
  // When the Ctrl+Alt+Del waiting for its answer was sent; 0 for none.
  const [sasWaiting, setSasWaiting] = useState(0);

  const onScreen = shown && viewing !== null && selected?.id === viewing.id;
  // Nothing to send input to unless a picture is actually up, and the relay
  // would drop it from a view-only share anyway.
  const canControl =
    onScreen &&
    roleCanControl(viewing.role) &&
    viewing.online &&
    status === "open" &&
    picture !== null &&
    security?.kind === "secured" &&
    roleCanControl(security.role) &&
    elevated;
  // Could control it, once a fresh second factor is proved.
  const controlLocked =
    onScreen &&
    viewing.online &&
    status === "open" &&
    security?.kind === "secured" &&
    roleCanControl(security.role) &&
    !elevated;
  // The machine checks every clipboard request for itself; these only
  // decide which buttons make sense to show.
  const secured = onScreen && viewing.online && status === "open" && security?.kind === "secured";
  const canReadClipboard = secured && clipboard.access !== "off";
  const canPaste = canReadClipboard && roleCanControl(security.role);
  // Lock, sign out, restart, shut down: control, elevated, on a machine new
  // enough to take them. The machine checks the role again.
  const canPower = secured && viewing.power === true && roleCanControl(security.role) && elevated;
  // The machine's output devices: anyone watching sees them; control (or
  // the owner) can choose, elevated, which restarts the stream for a moment.
  const listsDevices = secured && viewing.audioDevices === true;
  const mayChooseDevice = listsDevices && roleCanControl(security.role);
  const canChooseDevice = mayChooseDevice && elevated;
  const chooseHint = mayChooseDevice ? "Confirm it's you first" : "Choosing the device needs control";
  const defaultName = audioDevices?.devices.find((device) => device.default)?.name;
  const soundMenuShown = onScreen && (sound.supported || listsDevices);
  // The stream's quality preset: control (or the owner) picks it for
  // everyone watching, on a machine new enough to take one. No fresh
  // factor: it only changes how the picture is encoded.
  const canChooseQuality = secured && viewing.quality === true && roleCanControl(security.role);
  // Ctrl+Alt+Del: control, elevated, as with input (it's a key press), on a
  // machine new enough to press it. The machine checks the role again.
  const canSas = secured && viewing.sas === true && roleCanControl(security.role) && elevated;

  const canSendFiles = secured && files.enabled && elevated;
  // Dropping files on the screen sends them; the Files tab follows them.
  const onDragOver = (event: DragEvent): void => {
    if (!canSendFiles || !event.dataTransfer.types.includes("Files")) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = "copy";
    setDropping(true);
  };
  const onDrop = (event: DragEvent): void => {
    setDropping(false);
    if (!canSendFiles) return;
    event.preventDefault();
    const dropped = [...event.dataTransfer.files];
    if (dropped.length === 0) return;
    fileActions.upload(dropped);
    setDropNote(
      dropped.length === 1
        ? `Sending ${dropped[0]?.name ?? "a file"}: follow it in the Files tab.`
        : `Sending ${dropped.length} files: follow them in the Files tab.`,
    );
  };

  // A picture shown in the panel is let go of once it's gone from there.
  useEffect(() => {
    if (clipPanel?.kind !== "image") return;
    const url = clipPanel.url;
    return () => URL.revokeObjectURL(url);
  }, [clipPanel]);

  // A new view, or none: whatever the panel held was for the last one.
  useEffect(() => {
    setClipPanel(null);
    setClipNote(null);
    setDropNote(null);
    setClipMenu(false);
  }, [viewing?.id, canReadClipboard]);

  // Pings for the round trip only go out while the overlay is on screen.
  useEffect(() => {
    setStatsVisible(onScreen && statsShown);
    return () => setStatsVisible(false);
  }, [onScreen, setStatsVisible, statsShown]);

  useEffect(() => {
    setPowerMenu(false);
    setSoundMenu(false);
    setQualityMenu(false);
    setArmed(null);
    setPowerNote(null);
    setSasNote(null);
    setSasWaiting(0);
  }, [viewing?.id]);

  // A second click has to come soon after the first.
  useEffect(() => {
    if (armed === null) return;
    const timer = window.setTimeout(() => setArmed(null), 4000);
    return () => window.clearTimeout(timer);
  }, [armed]);

  const choosePower = (action: PowerAction): void => {
    const item = POWER_ITEMS.find((candidate) => candidate.action === action);
    if (item === undefined || viewing === null) return;
    if (item.warning !== null && armed !== action) {
      setArmed(action);
      return;
    }
    setArmed(null);
    setPowerMenu(false);
    if (sendPower(action)) setPowerNote(item.sent(viewing.name));
  };

  const pressSas = (): void => {
    if (!sendSas()) return;
    setSasNote("Pressing Ctrl+Alt+Del…");
    setSasWaiting(Date.now());
  };

  // The relay drops a request it won't pass on without a word, and a
  // machine can go away before answering.
  useEffect(() => {
    if (sasWaiting === 0) return;
    const timer = window.setTimeout(() => {
      setSasWaiting(0);
      setSasNote("No answer from the machine.");
    }, ANSWER_TIMEOUT_MS);
    return () => window.clearTimeout(timer);
  }, [sasWaiting]);

  // The machine's answer: pressed, or why not (most often a policy of
  // Windows that the message says how to change).
  useEffect(() => {
    if (sasResult === null) return;
    setSasNote(
      sasResult.sent
        ? "Pressed Ctrl+Alt+Del: the machine shows its sign-in or security screen."
        : `Ctrl+Alt+Del wasn't pressed. ${sasResult.error}`,
    );
    setSasWaiting(0);
    // Shown once: a view opened later doesn't bring it back.
    clearSasResult();
  }, [sasResult, clearSasResult]);

  // Text or a picture from the machine: straight onto this computer's
  // clipboard where the browser allows it, otherwise shown to copy (or
  // save) by hand.
  const latest = clipboard.latest;
  const images = clipboard.images;
  useEffect(() => {
    if (latest === null) return;
    const what = latest.pushed ? "Copied on the machine" : "The machine's clipboard";
    if (latest.kind === "too_large") {
      setClipNote(
        `${latest.pushed ? "A picture copied on the machine" : "The machine's clipboard holds a picture that"} is ` +
          `too large to send (more than ${formatSize(MAX_CLIPBOARD_IMAGE_BYTES)} as PNG, or past 8K).`,
      );
      return;
    }
    if (latest.kind === "image") {
      const blob = new Blob([latest.png], { type: "image/png" });
      const described = `a ${latest.width}×${latest.height} picture, ${formatSize(latest.png.length)}`;
      const show = (why: string): void => {
        setClipPanel({ kind: "image", url: URL.createObjectURL(blob), width: latest.width, height: latest.height });
        setClipNote(`${what}: ${described}; ${why}`);
      };
      if (!document.hasFocus()) {
        show("copy or save it below.");
        return;
      }
      if (!canWriteImages()) {
        show("this browser won't let the page copy pictures, so right-click it below to copy it, or save it.");
        return;
      }
      navigator.clipboard.write([new ClipboardItem({ "image/png": blob })]).then(
        () => {
          setClipPanel((prev) => (prev?.kind === "image" ? null : prev));
          setClipNote(`${what} is on your clipboard: ${described}.`);
        },
        () => show("this browser wouldn't let the page copy it, so copy or save it below."),
      );
      return;
    }
    if (latest.text === "") {
      if (!latest.pushed) setClipNote(images ? "The machine's clipboard has no text or picture." : "The machine's clipboard has no text.");
      return;
    }
    const size = formatSize(byteSize(latest.text));
    if (!document.hasFocus()) {
      setClipPanel({ kind: "received", text: latest.text });
      setClipNote(`${what} (${size}); copy it below.`);
      return;
    }
    navigator.clipboard.writeText(latest.text).then(
      () => {
        setClipPanel((prev) => (prev?.kind === "received" ? null : prev));
        setClipNote(`${what} is on your clipboard (${size}).`);
      },
      () => {
        setClipPanel({ kind: "received", text: latest.text });
        setClipNote(`${what} (${size}); this browser won't let the page copy it, so copy it below.`);
      },
    );
  }, [latest, images]);

  const pasteText = (text: string): void => {
    if (text === "") {
      setClipNote("There's no text to paste.");
      return;
    }
    const size = byteSize(text);
    if (size > MAX_CLIPBOARD_BYTES) {
      setClipNote(`That's ${formatSize(size)}; the most the machine takes is ${formatSize(MAX_CLIPBOARD_BYTES)}.`);
      return;
    }
    if (sendClipboard(text)) {
      setClipPanel(null);
      setClipNote(`Sent ${formatSize(size)} to the machine's clipboard. Paste it there with Ctrl+V.`);
    }
  };

  // A picture to the machine's clipboard, with a note on how it went.
  // Resolves to whether it's there.
  const pastePicture = async (png: Blob): Promise<boolean> => {
    const bytes = new Uint8Array(await png.arrayBuffer());
    const problem = imageProblem(bytes);
    if (problem !== null) {
      setClipNote(`Not pasted: ${problem}.`);
      return false;
    }
    setClipNote(`Sending a picture (${formatSize(bytes.length)}) to the machine's clipboard…`);
    const result = await pasteImage(bytes);
    setClipNote(
      result.ok
        ? `The picture (${formatSize(bytes.length)}) is on the machine's clipboard. Paste it there with Ctrl+V.`
        : `The picture wasn't pasted: ${result.message}.`,
    );
    return result.ok;
  };

  const pasteFromClipboard = async (): Promise<void> => {
    // Text wins over a picture copied with it, as on the machine. Browsers
    // that hand over only text (or nothing) fall through to that.
    if (clipboard.images && canReadImages()) {
      try {
        const items = await navigator.clipboard.read();
        const text = items.find((item) => item.types.includes("text/plain"));
        const picture = items.find((item) => item.types.includes("image/png"));
        if (text !== undefined) {
          pasteText(await (await text.getType("text/plain")).text());
          return;
        }
        if (picture !== undefined) {
          setClipPanel(null);
          await pastePicture(await picture.getType("image/png"));
          return;
        }
        setClipNote("There's no text or picture to paste.");
        return;
      } catch {
        // Refused, or not for pictures here: try for text alone.
      }
    }
    let text: string;
    try {
      text = await navigator.clipboard.readText();
    } catch {
      // Not allowed, or not supported: let it be pasted in by hand.
      setClipPanel({ kind: "paste", text: "" });
      setClipNote(
        clipboard.images
          ? "This browser won't hand the page your clipboard; paste the text below, or press Ctrl+V on the screen to send a picture."
          : "This browser won't hand the page your clipboard; paste the text below.",
      );
      return;
    }
    pasteText(text);
  };

  // Ctrl+V on the screen: this computer's text goes first, quietly; a
  // problem with it still shows below the screen.
  const pasteOnKey = (text: string): boolean => {
    const size = byteSize(text);
    if (size > MAX_CLIPBOARD_BYTES) {
      setClipNote(`Not pasted: ${formatSize(size)} is more than the machine takes (${formatSize(MAX_CLIPBOARD_BYTES)}).`);
      return false;
    }
    return sendClipboard(text);
  };
  const input = useRemoteInput(
    canvasRef,
    canControl,
    sendInput,
    canPaste ? pasteOnKey : null,
    canSas ? pressSas : null,
    canPaste && clipboard.images ? pastePicture : null,
  );

  // Touch: fingers on the screen, a pinch zooming the picture here, and the
  // phone's keyboard. Shown once this looks like a touch device.
  const screenRef = useRef<HTMLDivElement>(null);
  const viewRef = useRef<HTMLDivElement>(null);
  const cursorRef = useRef<HTMLDivElement>(null);
  const keyboardRef = useRef<HTMLTextAreaElement>(null);
  const [coarse] = useState(coarsePointer);
  const [touchControl, setTouchControl] = useState(loadTouchControl);
  const watching = onScreen && picture !== null;
  const touch = useTouchInput(
    screenRef,
    viewRef,
    canvasRef,
    cursorRef,
    watching,
    canControl ? touchControl : "view",
    sendInput,
    // A finger on the screen takes control as a click does, unless the
    // keyboard is up: taking the focus from it would put it away.
    () => {
      if (document.activeElement !== keyboardRef.current) canvasRef.current?.focus({ preventScroll: true });
    },
  );
  const touchShown = watching && (coarse || touch.touched);
  const keyboard = useTouchKeyboard(keyboardRef, canControl && touchShown, sendInput, viewing?.text === true);
  const controlling = input.active || keyboard.typing;
  const chooseTouchControl = (control: TouchControl): void => {
    setTouchControl(control);
    saveTouchControl(control);
  };
  const releaseControl = (): void => {
    keyboard.close();
    input.release();
  };

  const getClipboard = (): void => {
    if (sendClipboard(null)) setClipNote(null);
  };
  const clipboardMenu = canPaste || canReadClipboard;
  // The menu closes on any click outside it (or its button).
  useEffect(() => {
    if (!clipMenu) return;
    const onPointer = (event: PointerEvent): void => {
      const target = event.target as Element | null;
      if (target?.closest(".stage-menu, [data-clip-menu]") == null) setClipMenu(false);
    };
    document.addEventListener("pointerdown", onPointer);
    return () => document.removeEventListener("pointerdown", onPointer);
  }, [clipMenu]);
  useEffect(() => {
    if (!soundMenu) return;
    const onPointer = (event: PointerEvent): void => {
      const target = event.target as Element | null;
      if (target?.closest(".stage-menu, [data-sound-menu]") == null) setSoundMenu(false);
    };
    document.addEventListener("pointerdown", onPointer);
    return () => document.removeEventListener("pointerdown", onPointer);
  }, [soundMenu]);
  useEffect(() => {
    if (!qualityMenu) return;
    const onPointer = (event: PointerEvent): void => {
      const target = event.target as Element | null;
      if (target?.closest(".stage-menu, [data-quality-menu]") == null) setQualityMenu(false);
    };
    document.addEventListener("pointerdown", onPointer);
    return () => document.removeEventListener("pointerdown", onPointer);
  }, [qualityMenu]);
  useEffect(() => {
    if (!powerMenu) return;
    const onPointer = (event: PointerEvent): void => {
      const target = event.target as Element | null;
      if (target?.closest(".stage-menu, [data-power-menu]") == null) {
        setPowerMenu(false);
        setArmed(null);
      }
    };
    document.addEventListener("pointerdown", onPointer);
    return () => document.removeEventListener("pointerdown", onPointer);
  }, [powerMenu]);

  useEffect(() => {
    const onChange = (): void => {
      const isFull = document.fullscreenElement === stageRef.current && stageRef.current !== null;
      setFullscreen(isFull);
      if (!isFull) {
        keyboardLock()?.unlock?.();
        setKeysLocked(false);
      }
    };
    document.addEventListener("fullscreenchange", onChange);
    return () => document.removeEventListener("fullscreenchange", onChange);
  }, []);

  // Leaving the screen (another machine, another tab) ends fullscreen too.
  useEffect(() => {
    if (!onScreen && document.fullscreenElement !== null) void document.exitFullscreen().catch(() => {});
  }, [onScreen]);

  const toggleFullscreen = async (): Promise<void> => {
    if (document.fullscreenElement !== null) {
      await document.exitFullscreen().catch(() => {});
      return;
    }
    try {
      await stageRef.current?.requestFullscreen();
    } catch {
      return;
    }
    // In fullscreen, Chromium can hand the page the keys it normally keeps
    // (Alt+Tab, Ctrl+W, Esc), so they reach the machine too.
    try {
      await keyboardLock()?.lock?.();
      setKeysLocked(keyboardLock()?.lock !== undefined);
    } catch {
      setKeysLocked(false);
    }
    canvasRef.current?.focus();
  };

  const signal = signalFor({ onScreen, selected, viewing, status, picture, stats, decodeError, security, onConnect });
  const name = selected?.name ?? "";

  return (
    <div className="stage-wrap" hidden={!shown}>
      {/* Any click on the stage lets the browser start the sound. */}
      <div ref={stageRef} className={controlling ? "stage controlling" : "stage"} onPointerDown={unlockSound}>
        <div className="stage-bar">
          {onScreen ? (
            <span className="live">
              <Dot tone={stats?.receiving === false ? "warn" : "accent"} />
              Live
            </span>
          ) : (
            <span>
              <Dot tone="idle" />
              Idle
            </span>
          )}
          <span className="v truncate">{name}</span>
          {onScreen && picture !== null && (
            <span className="wide">
              {picture.width}×{picture.height}
            </span>
          )}
          {onScreen && stats !== null && <span>{String(stats.fps).padStart(2, " ")} fps</span>}
          {/* Shown only when the browser falls behind what arrives. */}
          {onScreen && stats !== null && stats.received - stats.fps > 2 && (
            <span className="wide">{stats.received} in</span>
          )}
          {onScreen && stats !== null && stats.dropped > 0 && <span className="wide">{stats.dropped} dropped</span>}
          {onScreen && stats?.debug != null && <span>{stats.debug}</span>}
          {onScreen && stats !== null && <span className="wide">{formatBitrate(stats.kbps)}</span>}
          <span className="spacer" />
          {onScreen && viewing.role === "view" && <span>View only</span>}
          {controlLocked && (
            <button type="button" onClick={() => void requestStepUp().then((ok) => ok && dashboard.elevate())}>
              Confirm to control
            </button>
          )}
          {canControl && (
            <span className={controlling ? "control live" : "control"}>
              {controlling
                ? keysLocked
                  ? "Input + keyboard lock"
                  : "Input captured"
                : touchShown
                  ? "Tap to control"
                  : "Click to control"}
            </span>
          )}
          {controlling && (
            <button type="button" onClick={releaseControl}>
              Release
            </button>
          )}
          {clipboardMenu && (
            <button
              type="button"
              data-clip-menu
              aria-expanded={clipMenu}
              onClick={() => {
                setPowerMenu(false);
                setSoundMenu(false);
                setQualityMenu(false);
                setClipMenu(!clipMenu);
              }}
            >
              {clipboard.waiting ? "Getting…" : "Clipboard ▾"}
            </button>
          )}
          {canPower && (
            <button
              type="button"
              data-power-menu
              aria-expanded={powerMenu}
              onClick={() => {
                setClipMenu(false);
                setSoundMenu(false);
                setQualityMenu(false);
                setArmed(null);
                setPowerMenu(!powerMenu);
              }}
            >
              Power ▾
            </button>
          )}
          {canSas && (
            <button type="button" title="Or press Ctrl+Alt+End on the screen" onClick={pressSas}>
              Ctrl+Alt+Del
            </button>
          )}
          {onScreen && sound.supported && (
            <button
              type="button"
              aria-pressed={!sound.muted && !sound.blocked}
              title={sound.blocked ? "Your browser holds sound back until you click" : undefined}
              onClick={() => (sound.blocked ? unlockSound() : setMuted(!sound.muted))}
            >
              {sound.blocked ? "Click for sound" : sound.muted ? "Sound off" : "Sound on"}
            </button>
          )}
          {soundMenuShown && (
            <button
              type="button"
              data-sound-menu
              aria-expanded={soundMenu}
              onClick={() => {
                setClipMenu(false);
                setPowerMenu(false);
                setQualityMenu(false);
                setArmed(null);
                // Fresh each time: devices come and go.
                if (!soundMenu && listsDevices) requestAudioDevices();
                setSoundMenu(!soundMenu);
              }}
            >
              Sound ▾
            </button>
          )}
          {canChooseQuality && (
            <button
              type="button"
              data-quality-menu
              aria-expanded={qualityMenu}
              onClick={() => {
                setClipMenu(false);
                setPowerMenu(false);
                setSoundMenu(false);
                setArmed(null);
                setQualityMenu(!qualityMenu);
              }}
            >
              Quality ▾
            </button>
          )}
          {onScreen && (
            <button
              type="button"
              aria-pressed={statsShown}
              title={statsShown ? "Hide the stream stats" : "Show the stream stats over the picture"}
              onClick={() => setStatsShown(!statsShown)}
            >
              Stats
            </button>
          )}
          {onScreen && (
            <button type="button" onClick={() => void toggleFullscreen()}>
              {fullscreen ? "Exit full screen" : "Full screen"}
            </button>
          )}
        </div>
        {clipboardMenu && clipMenu && (
          <div className="stage-menu" role="menu">
            {canPaste && (
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  setClipMenu(false);
                  void pasteFromClipboard();
                }}
              >
                Paste my clipboard to the machine
              </button>
            )}
            {canReadClipboard && (
              <button
                type="button"
                role="menuitem"
                disabled={clipboard.waiting}
                onClick={() => {
                  setClipMenu(false);
                  getClipboard();
                }}
              >
                Copy the machine's clipboard to mine
              </button>
            )}
          </div>
        )}
        {soundMenuShown && soundMenu && (
          <div className="stage-menu" role="menu">
            {sound.supported && (
              <button
                type="button"
                role="menuitemcheckbox"
                aria-checked={sync}
                title={sync ? "The picture waits for the sound" : "Picture and sound each as soon as they arrive"}
                onClick={() => setSync(!sync)}
              >
                {sync ? "✓ " : ""}Sync to sound
              </button>
            )}
            {listsDevices && (
              <>
                <div className="stage-menu-label">Output device on {viewing.name}</div>
                {audioDevices === null ? (
                  <button type="button" disabled>
                    Asking…
                  </button>
                ) : !audioDevices.sound ? (
                  <button type="button" disabled>
                    This machine doesn't send its sound
                  </button>
                ) : (
                  [{ id: "", name: `Default (${defaultName ?? "none"})` }, ...audioDevices.devices].map((device) => (
                    <button
                      key={device.id === "" ? "default" : device.id}
                      type="button"
                      role="menuitemradio"
                      aria-checked={audioDevices.selected === device.id}
                      disabled={!canChooseDevice}
                      title={canChooseDevice ? undefined : chooseHint}
                      onClick={() => {
                        setSoundMenu(false);
                        if (audioDevices.selected !== device.id) selectAudioDevice(device.id);
                      }}
                    >
                      {audioDevices.selected === device.id ? "✓ " : ""}
                      {device.name}
                    </button>
                  ))
                )}
                {audioDevices?.sound === true && mayChooseDevice && !elevated && (
                  <button
                    type="button"
                    onClick={() => void requestStepUp().then((ok) => ok && dashboard.elevate())}
                  >
                    Confirm it's you to choose…
                  </button>
                )}
              </>
            )}
          </div>
        )}
        {canChooseQuality && qualityMenu && (
          <div className="stage-menu" role="menu">
            <div className="stage-menu-label">Quality, for everyone watching</div>
            {QUALITY_PRESETS.map((entry) => (
              <button
                key={entry.preset}
                type="button"
                role="menuitemradio"
                aria-checked={streamQuality?.preset === entry.preset}
                title={entry.hint}
                onClick={() => {
                  setQualityMenu(false);
                  if (streamQuality?.preset !== entry.preset) setQuality(entry.preset);
                }}
              >
                {streamQuality?.preset === entry.preset ? "✓ " : ""}
                {entry.label}
                <span className="stage-menu-hint"> · {entry.hint}</span>
              </button>
            ))}
          </div>
        )}
        {canPower && powerMenu && (
          <div className="stage-menu" role="menu">
            {POWER_ITEMS.map((item) => (
              <button
                key={item.action}
                type="button"
                role="menuitem"
                className={armed === item.action ? "armed" : undefined}
                onClick={() => choosePower(item.action)}
              >
                {armed === item.action ? `${item.label} ${viewing.name}? ${item.warning} Click again.` : item.label}
              </button>
            ))}
          </div>
        )}
        <div
          ref={screenRef}
          className={["stage-screen", dropping && "dropping", watching && "touchable", touchShown && "touch"]
            .filter(Boolean)
            .join(" ")}
          onDragOver={onDragOver}
          onDragLeave={() => setDropping(false)}
          onDrop={onDrop}
        >
          <Corners />
          {/* What a pinch zooms: the picture (and the <video> the MSE
              fallback lays under it), not the marks or the overlays. */}
          <div ref={viewRef} className="stage-view">
            <canvas
              ref={canvasRef}
              className={[
                (!onScreen || picture === null) && "hidden",
                canControl && "controllable",
                input.active && "controlling",
              ]
                .filter(Boolean)
                .join(" ")}
              // Focusable only when it can be controlled: focusing it is what
              // starts sending input, and Tab shouldn't land on a dead screen.
              tabIndex={canControl ? 0 : -1}
              aria-label={onScreen ? `${name} screen` : undefined}
            />
          </div>
          <div
            ref={cursorRef}
            className="touch-cursor"
            hidden={!(canControl && touchControl === "trackpad" && touch.touched)}
          >
            <svg viewBox="0 0 12 18" width="12" height="18" aria-hidden="true">
              <path d="M0.5 0.5 L0.5 14.5 L4 11.2 L6.4 16.8 L8.6 15.9 L6.3 10.4 L11 10.4 Z" />
            </svg>
          </div>
          {canControl && touchShown && (
            <textarea
              ref={keyboardRef}
              className="touch-keyboard"
              aria-label={`Type on ${name}`}
              autoCapitalize="off"
              autoComplete="off"
              autoCorrect="off"
              spellCheck={false}
              tabIndex={-1}
            />
          )}
          {onScreen && statsShown && (
            <StatsOverlay stats={stats} picture={picture} pings={viewing.ping === true} quality={streamQuality} />
          )}
          {signal}
        </div>
        {touchShown && (
          <div className="touch-bar" role="toolbar" aria-label="Touch controls">
            {canControl && (
              <>
                <button
                  type="button"
                  aria-pressed={touchControl === "trackpad"}
                  title="Drag to move the pointer, tap to click"
                  onClick={() => chooseTouchControl("trackpad")}
                >
                  Trackpad
                </button>
                <button
                  type="button"
                  aria-pressed={touchControl === "direct"}
                  title="Tap where you want to click"
                  onClick={() => chooseTouchControl("direct")}
                >
                  Touch
                </button>
                <button
                  type="button"
                  aria-pressed={keyboard.open}
                  onMouseDown={keepFocus}
                  onClick={keyboard.toggle}
                >
                  Keyboard
                </button>
              </>
            )}
            {touch.zoomed && (
              <button type="button" title="Or tap twice with two fingers" onClick={touch.resetZoom}>
                Fit
              </button>
            )}
            {canControl &&
              keyboard.open &&
              EXTRA_KEYS.map((key) => (
                <button
                  key={key.code}
                  type="button"
                  className="key"
                  aria-pressed={key.modifier === undefined ? undefined : keyboard.latched.has(key.modifier)}
                  title={
                    key.modifier === undefined ? undefined : `${key.label} for the next key; twice for ${key.label} alone`
                  }
                  onPointerDown={keepFocus}
                  onMouseDown={keepFocus}
                  onClick={() => {
                    if (key.modifier === undefined) keyboard.press(key.code);
                    else keyboard.latch(key.modifier);
                  }}
                >
                  {key.label}
                </button>
              ))}
          </div>
        )}
      </div>
      {onScreen && (
        <div className="stage-foot">
          {viewing.singleView && (
            <span>
              <Tag tone="warn">One viewing</Tag> Once you disconnect, this machine is no longer shared with you.
            </span>
          )}
          {viewing.role === "view" && <span>View only: you can watch this screen but not send it input.</span>}
          {canControl && !controlling && !touchShown && (
            <span>Click the screen to send it your mouse and keyboard.</span>
          )}
          {canControl && touchShown && (
            <span>
              {touchControl === "trackpad"
                ? "Drag to move the pointer, tap to click, tap with two fingers to right-click, " +
                  "hold then drag to drag, drag two fingers to scroll."
                : "Tap to click, drag to drag, hold to right-click, drag two fingers to scroll."}{" "}
              Pinch to zoom.
            </span>
          )}
          {!canControl && touchShown && <span>Pinch to zoom.</span>}
          {dropNote !== null ? (
            <span>{dropNote}</span>
          ) : (
            canSendFiles && <span>Drop files on the screen to send them to the machine.</span>
          )}
          {canReadClipboard && clipboard.access === "sync" && (
            <span>
              {clipboard.images ? "Text and pictures" : "Text"} copied on the machine come to your clipboard while
              this page has focus.
            </span>
          )}
          {clipNote !== null && <span>{clipNote}</span>}
          {powerNote !== null && <span>{powerNote}</span>}
          {sasNote !== null && <span>{sasNote}</span>}
          {input.active && !touchShown && (
            <span>
              The machine's own pointer isn't in the picture; yours stands in for it.{" "}
              {keysLocked ? (
                <>
                  System shortcuts go to the machine too. Hold <kbd>Esc</kbd> to leave full screen.
                </>
              ) : (
                <>
                  <kbd>Ctrl+W</kbd> <kbd>Alt+Tab</kbd> and <kbd>Ctrl+Alt+Del</kbd> stay on this computer; full
                  screen forwards most of them.
                </>
              )}
              {canSas && (
                <>
                  {" "}
                  <kbd>Ctrl+Alt+End</kbd> presses Ctrl+Alt+Del on the machine.
                </>
              )}
            </span>
          )}
        </div>
      )}
      {onScreen && clipPanel !== null && (
        <div className="clip-panel">
          {clipPanel.kind === "paste" ? (
            <>
              <textarea
                className="input"
                value={clipPanel.text}
                onChange={(e) => setClipPanel({ kind: "paste", text: e.target.value })}
                placeholder="Text for the machine's clipboard"
                aria-label="Text for the machine's clipboard"
                rows={3}
                autoFocus
              />
              <div className="clip-actions">
                <button type="button" className="btn btn-sm btn-primary" onClick={() => pasteText(clipPanel.text)}>
                  Send
                </button>
                <button type="button" className="btn btn-sm btn-ghost" onClick={() => setClipPanel(null)}>
                  Cancel
                </button>
              </div>
            </>
          ) : clipPanel.kind === "image" ? (
            <>
              <img
                className="clip-image"
                src={clipPanel.url}
                width={clipPanel.width}
                height={clipPanel.height}
                alt="The picture on the machine's clipboard"
              />
              <div className="clip-actions">
                <a className="btn btn-sm btn-primary" href={clipPanel.url} download="clipboard.png">
                  Save
                </a>
                <button type="button" className="btn btn-sm btn-ghost" onClick={() => setClipPanel(null)}>
                  Dismiss
                </button>
              </div>
            </>
          ) : (
            <>
              <textarea
                className="input"
                value={clipPanel.text}
                readOnly
                rows={3}
                aria-label="The machine's clipboard"
              />
              <div className="clip-actions">
                <CopyButton value={clipPanel.text} small />
                <button type="button" className="btn btn-sm btn-ghost" onClick={() => setClipPanel(null)}>
                  Dismiss
                </button>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

type DetailTab = "screen" | "terminal" | "files" | "analytics" | "processes" | "config" | "sharing" | "machine";

// The tabs a machine's user gets: only what they can use. A dev share has
// no screen, so it starts on the terminal; analytics is the owner's, or a
// share's the owner allowed it for; control reads the config, and only the
// owner changes it.
function tabsFor(machine: Machine): [DetailTab, string][] {
  const { role } = machine;
  const tabs: [DetailTab, string][] = [];
  if (canView(role)) tabs.push(["screen", "Screen"]);
  if (canShell(role)) tabs.push(["terminal", "Terminal"]);
  if (canFiles(role)) tabs.push(["files", "Files"]);
  if (role === "owner" || machine.analytics === true) tabs.push(["analytics", "Analytics"], ["processes", "Processes"]);
  if (roleCanControl(role)) tabs.push(["config", "Config"]);
  if (role === "owner") tabs.push(["sharing", "Sharing"], ["machine", "Machine"]);
  return tabs;
}

// Where a view stands, for a tab that needs one and doesn't have it yet.
function connectionStatus(security: ViewSecurity | null, online: boolean): string {
  if (!online) return "The machine is offline.";
  switch (security?.kind) {
    case "rejected":
      return `The machine refused this connection: ${security.reason}`;
    case "untrusted":
      return "This machine's key couldn't be verified.";
    case "failed":
      return `The connection couldn't be secured: ${security.message}`;
    default:
      return "Securing the connection…";
  }
}

// Whether the view of `machine` is up and end-to-end secured.
function isSecured(dashboard: Dashboard, machine: Machine, viewing: Machine | null): boolean {
  return (
    viewing?.id === machine.id &&
    machine.online &&
    dashboard.status === "open" &&
    dashboard.security?.kind === "secured"
  );
}

// What a tab that works over the view shows until the view is up: a way to
// connect, or where the connection stands.
function NotConnected({
  dashboard,
  machine,
  viewing,
  onConnect,
}: {
  dashboard: Dashboard;
  machine: Machine;
  viewing: Machine | null;
  onConnect: (machine: Machine) => void;
}): JSX.Element {
  if (viewing?.id !== machine.id) {
    return (
      <div className="empty tool-connect">
        <span>{machine.online ? "Connect to this machine to use it." : "The machine is offline."}</span>
        {machine.online && (
          <button type="button" className="btn btn-sm btn-accent" onClick={() => onConnect(machine)}>
            Connect
          </button>
        )}
      </div>
    );
  }
  return <div className="empty">{connectionStatus(dashboard.security, machine.online)}</div>;
}

// Over a secured view the session hasn't stepped up for: files and shells
// wait for a fresh code.
function StepUpNeeded({ dashboard, what }: { dashboard: Dashboard; what: string }): JSX.Element {
  const requestStepUp = useStepUp();
  return (
    <div className="empty tool-connect">
      <span>{what} needs a fresh code from your authenticator.</span>
      <button
        type="button"
        className="btn btn-sm btn-accent"
        onClick={() => void requestStepUp().then((ok) => ok && dashboard.elevate())}
      >
        Confirm
      </button>
    </div>
  );
}

// The Files tab: the panel once connected; transfers stay on show while the
// view is down, so they can be seen waiting to resume.
function ToolTab({
  dashboard,
  machine,
  viewing,
  onConnect,
  children,
}: {
  dashboard: Dashboard;
  machine: Machine;
  viewing: Machine | null;
  onConnect: (machine: Machine) => void;
  children: (connected: boolean) => ReactNode;
}): JSX.Element {
  const connected = isSecured(dashboard, machine, viewing) && dashboard.files.enabled && dashboard.elevated;
  const watching = viewing?.id === machine.id;
  const hasTransfers = watching && dashboard.files.transfers.length > 0;

  // Fresh listing whenever the tab is opened on a live view.
  const { list } = dashboard.fileActions;
  useEffect(() => {
    if (connected) list();
  }, [connected, list]);

  return (
    <div className="tool-wrap">
      {!isSecured(dashboard, machine, viewing) && (
        <NotConnected dashboard={dashboard} machine={machine} viewing={viewing} onConnect={onConnect} />
      )}
      {isSecured(dashboard, machine, viewing) && !dashboard.files.enabled && (
        <div className="empty">This machine doesn't allow file transfer. Its owner can turn it on in its config.</div>
      )}
      {isSecured(dashboard, machine, viewing) && dashboard.files.enabled && !dashboard.elevated && (
        <StepUpNeeded dashboard={dashboard} what="Transferring files" />
      )}
      {(connected || hasTransfers) && children(connected)}
    </div>
  );
}

// The Analytics and Processes tabs: over the view, like files, but
// read-only, so no second factor is asked for.
function AnalyticsTab({
  dashboard,
  machine,
  viewing,
  onConnect,
  children,
}: {
  dashboard: Dashboard;
  machine: Machine;
  viewing: Machine | null;
  onConnect: (machine: Machine) => void;
  children: ReactNode;
}): JSX.Element {
  const secured = isSecured(dashboard, machine, viewing);
  return (
    <div className="tool-wrap">
      {!secured && <NotConnected dashboard={dashboard} machine={machine} viewing={viewing} onConnect={onConnect} />}
      {secured && !dashboard.metrics.enabled && (
        <div className="empty">
          This machine doesn't share its analytics with you: its config has them off, or your share doesn't include
          them.
        </div>
      )}
      {secured && dashboard.metrics.enabled && children}
    </div>
  );
}

// The Config tab: over the view, like analytics. Reading it needs no second
// factor; the owner's changes do, and the machine checks each one.
function ConfigTab({
  dashboard,
  machine,
  viewing,
  onConnect,
}: {
  dashboard: Dashboard;
  machine: Machine;
  viewing: Machine | null;
  onConnect: (machine: Machine) => void;
}): JSX.Element {
  const secured = isSecured(dashboard, machine, viewing);
  // A machine too old to send its config never shows the editor.
  const supported = machine.config === true;
  const owner = machine.role === "owner";
  const { config, requestConfig, saveConfig } = dashboard;
  // Bumped by Try again; a load the machine never answers stops waiting.
  const [attempt, setAttempt] = useState(0);
  const [loadTimedOut, setLoadTimedOut] = useState(false);
  const waiting = secured && supported && config === null;

  // Fresh whenever the tab is opened on a live view.
  useEffect(() => {
    if (secured && supported) requestConfig();
  }, [secured, supported, requestConfig, attempt]);

  useEffect(() => {
    setLoadTimedOut(false);
    if (!waiting) return;
    const timer = window.setTimeout(() => setLoadTimedOut(true), ANSWER_TIMEOUT_MS);
    return () => window.clearTimeout(timer);
  }, [waiting, attempt]);

  return (
    <div className="tool-wrap">
      {!secured && <NotConnected dashboard={dashboard} machine={machine} viewing={viewing} onConnect={onConnect} />}
      {secured && !supported && (
        <div className="empty">
          This machine's service is too old to show its config here. Update it, or edit config.toml on the machine.
        </div>
      )}
      {secured && supported && owner && !dashboard.elevated && (
        <StepUpNeeded dashboard={dashboard} what="Changing the config" />
      )}
      {waiting && !loadTimedOut && <div className="empty">Loading the config…</div>}
      {waiting && loadTimedOut && (
        <div className="empty tool-connect">
          <span>No answer from the machine.</span>
          <button type="button" className="btn btn-sm" onClick={() => setAttempt((count) => count + 1)}>
            Try again
          </button>
        </div>
      )}
      {secured && supported && config !== null && (
        <ConfigPanel config={config} editable={owner && dashboard.elevated && config.writable} onSave={saveConfig} />
      )}
    </div>
  );
}

// The Terminal tab. Its panel stays mounted while the view has shells, so
// switching tabs or machines keeps every terminal's scrollback.
function ShellTab({
  dashboard,
  machine,
  viewing,
  shown,
  onConnect,
}: {
  dashboard: Dashboard;
  machine: Machine | null;
  viewing: Machine | null;
  shown: boolean;
  onConnect: (machine: Machine) => void;
}): JSX.Element | null {
  const { shells, shellActions } = dashboard;
  const live = viewing !== null && isSecured(dashboard, viewing, viewing) && shells.enabled && dashboard.elevated;
  const mounted = viewing !== null && (live || shells.shells.length > 0);
  const onThisMachine = machine !== null && viewing?.id === machine.id;
  return (
    <div className="tool-wrap" hidden={!shown}>
      {shown && machine !== null && !isSecured(dashboard, machine, viewing) && (
        <NotConnected dashboard={dashboard} machine={machine} viewing={viewing} onConnect={onConnect} />
      )}
      {shown && onThisMachine && isSecured(dashboard, machine, viewing) && !shells.enabled && (
        <div className="empty">This machine doesn't allow shells. Its owner can turn them on in its config.</div>
      )}
      {shown && onThisMachine && isSecured(dashboard, machine, viewing) && shells.enabled && !dashboard.elevated && (
        <StepUpNeeded dashboard={dashboard} what="Opening a shell" />
      )}
      {mounted && (
        <div hidden={!onThisMachine}>
          <Suspense fallback={<div className="empty">Loading the terminal…</div>}>
            <ShellPanel shells={shells} actions={shellActions} connected={live} visible={shown && onThisMachine} />
          </Suspense>
        </div>
      )}
    </div>
  );
}

const BACKEND_LABEL = { webcodecs: "WebCodecs", mse: "MSE (fallback)" } as const;

// "N/A" for what this decoder can't measure.
function orNa(value: number | null, format: (value: number) => string): string {
  return value === null ? "N/A" : format(value);
}

// The stream's numbers over the picture, top left. It takes no clicks, so
// input goes on to the screen under it.
// `pings`: the machine answers pings; an older one has no round trip.
// `quality`: what the machine says it encodes at; an older one doesn't.
function StatsOverlay({
  stats,
  picture,
  pings,
  quality,
}: {
  stats: Dashboard["stats"];
  picture: Dashboard["picture"];
  pings: boolean;
  quality: Dashboard["streamQuality"];
}): JSX.Element {
  const rows: [string, string][] =
    stats === null
      ? [["Stream", "…"]]
      : [
          ["Decoder", stats.backend === null ? "…" : BACKEND_LABEL[stats.backend]],
          ["Picture", picture === null ? "…" : `${picture.width}×${picture.height}`],
          ["Video", formatBitrate(stats.kbps)],
          ["Quality", quality === null ? "N/A" : describeQuality(quality)],
          ["Frames/s", `${stats.received} in · ${orNa(stats.decoded, String)} decoded · ${stats.fps} shown`],
          ["Lost/s", `${stats.dropped} dropped · ${stats.skipped} skipped`],
          ["Waiting", `${stats.pending} decrypting · ${orNa(stats.queue, String)} in decoder`],
          [
            stats.backend === "mse" ? "Behind" : "Decode",
            stats.backend === "mse"
              ? orNa(stats.lagMs, (ms) => `${Math.round(ms)} ms`)
              : orNa(stats.decodeMs, (ms) => `${ms.toFixed(1)} ms`),
          ],
          ["Round trip", !pings ? "N/A" : stats.rttMs === null ? "…" : `${Math.round(stats.rttMs)} ms`],
          ["Sound", stats.audioMs === null ? "none playing" : `${stats.audioMs} ms buffered`],
        ];
  return (
    <dl className="stats-overlay" aria-label="Stream stats">
      {rows.map(([label, value]) => (
        <div key={label}>
          <dt>{label}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

// What covers the screen when there's no live picture to show, if anything.
function signalFor({
  onScreen,
  selected,
  viewing,
  status,
  picture,
  stats,
  decodeError,
  security,
  onConnect,
}: {
  onScreen: boolean;
  selected: Machine | null;
  viewing: Machine | null;
  status: Dashboard["status"];
  picture: Dashboard["picture"];
  stats: Dashboard["stats"];
  decodeError: Dashboard["decodeError"];
  security: ViewSecurity | null;
  onConnect: (machine: Machine) => void;
}): ReactNode {
  if (selected === null) return null;

  if (!onScreen) {
    if (!selected.online && selected.restarting === true) {
      return <Signal label="Restarting">{selected.name} is restarting, and can be connected to once it's back.</Signal>;
    }
    if (!selected.online) {
      return (
        <Signal label="Offline">
          {selected.lastSeenAt === null
            ? `${selected.name} hasn't connected yet.`
            : `${selected.name} was last seen ${formatTime(selected.lastSeenAt)}.`}
        </Signal>
      );
    }
    return (
      <Signal label="Not connected">
        {viewing !== null ? `Connecting ends your view of ${viewing.name}.` : `Connect to see ${selected.name}'s screen.`}
        <button type="button" className="btn btn-accent" onClick={() => onConnect(selected)}>
          Connect
        </button>
      </Signal>
    );
  }

  const over = picture !== null;
  if (status !== "open") {
    return (
      <Signal label="Link down" over={over} searching>
        Lost the connection to the relay. The view resumes once it's back.
      </Signal>
    );
  }
  if (!selected.online) {
    return selected.restarting === true ? (
      <Signal label="Restarting" over={over} searching>
        {selected.name} is restarting. The view resumes when it's back, at its sign-in screen.
      </Signal>
    ) : (
      <Signal label="Machine offline" over={over} searching>
        {selected.name} went offline. The view resumes when it reconnects.
      </Signal>
    );
  }
  const problem = securityProblem(security);
  if (problem !== null) return <Signal label={problem.label}>{problem.detail}</Signal>;
  if (security?.kind === "securing" && picture === null) {
    return (
      <Signal label="Securing" searching>
        Exchanging keys with {selected.name}. The stream is encrypted end to end, so it starts once the machine
        has checked your access.
      </Signal>
    );
  }
  if (decodeError !== null) {
    return <Signal label="Can't decode" over={over}>{decodeError}</Signal>;
  }
  if (picture === null) {
    return (
      <Signal label="Awaiting signal" searching>
        Waiting for the first keyframe from {selected.name}.
      </Signal>
    );
  }
  if (stats !== null && !stats.receiving) {
    return (
      <Signal label="Signal lost" over searching>
        No frames for a few seconds. The machine may be switching desktops.
      </Signal>
    );
  }
  return null;
}

const UNTRUSTED: Record<Extract<ViewSecurity, { kind: "untrusted" }>["reason"], string> = {
  "re-enroll": "This machine was enrolled before end-to-end encryption. Its owner needs to enroll it again.",
  unendorsed:
    "Its owner hasn't verified this machine's key yet, so there's no way to be sure the stream really comes from it.",
  "owner-key-changed":
    "The owner's key isn't the one first seen for them. Someone may be between you and the machine; check with the owner before going on.",
  "bad-endorsement": "The machine's key isn't vouched for by its owner's key. Don't trust this machine.",
};

// Why the open view can't go ahead securely, if it can't.
function securityProblem(security: ViewSecurity | null): { label: string; detail: string } | null {
  switch (security?.kind) {
    case "untrusted":
      return { label: "Not verified", detail: UNTRUSTED[security.reason] };
    case "rejected":
      return { label: "Refused", detail: `The machine refused this view: ${security.reason}.` };
    case "failed":
      return { label: "Insecure answer", detail: `The machine's answer didn't check out (${security.message}).` };
    default:
      return null;
  }
}

function Signal({
  label,
  over = false,
  searching = false,
  children,
}: {
  label: string;
  over?: boolean;
  searching?: boolean;
  children: ReactNode;
}): JSX.Element {
  const className = ["signal", over && "over-frame", searching && "searching"].filter(Boolean).join(" ");
  return (
    <div className={className} role="status">
      <span className="bars" aria-hidden>
        <i />
        <i />
        <i />
      </span>
      <span className="label">{label}</span>
      {children}
    </div>
  );
}
