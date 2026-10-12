import { type DragEvent, type JSX, type ReactNode, Suspense, lazy, useEffect, useRef, useState } from "react";

import {
  type EnrollmentCode,
  describeShareTerms,
  formatAgo,
  formatElapsed,
  formatTime,
} from "../api.js";
import { createEnrollment } from "../e2e.js";
import type { Identity } from "../keys.js";
import {
  MAX_CLIPBOARD_BYTES,
  type Machine,
  type Role,
  canControl as roleCanControl,
  canFiles,
  canShell,
  canView,
} from "../protocol.js";
import { Alert, CodeBlock, CopyButton, Corners, Dot, Metric, Tag, errorMessage, useNow } from "../ui.js";
import type { Dashboard, ViewSecurity } from "../useDashboard.js";
import { useRemoteInput } from "../useRemoteInput.js";
import { useStepUp } from "../stepUp.js";
import { FilesPanel } from "./FilesPanel.js";
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

function installCommand(enrollment: EnrollmentCode): string {
  const pin = enrollment.relayPin === null ? "" : ` -RelayPin ${enrollment.relayPin}`;
  return `powershell -ExecutionPolicy Bypass -File scripts\\install-service.ps1 -EnrollCode ${enrollment.code}${pin}`;
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
  const tabs = selected === null ? [] : tabsFor(selected.role);
  const detailTab = tabs.some(([id]) => id === tab) ? tab : (tabs[0]?.[0] ?? "screen");

  const select = (id: string | null): void => {
    if (id !== selectedId) {
      const machine = machines.find((candidate) => candidate.id === id);
      setTab(machine === undefined ? "screen" : (tabsFor(machine.role)[0]?.[0] ?? "screen"));
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
            <MachineStrip machine={selected} now={now} />
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
      <Dot tone={machine.online ? "ok" : "idle"} title={machine.online ? "Online" : "Offline"} />
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

function MachineStrip({ machine, now }: { machine: Machine; now: number }): JSX.Element {
  const terms = accessTerms(machine);
  return (
    <div className="strip">
      <Metric label="Status">
        <Dot tone={machine.online ? "ok" : "idle"} />
        {machine.online ? "Online" : "Offline"}
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
                      <Dot tone={machine.online ? "ok" : "idle"} />
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
        <a className="btn btn-ghost btn-sm" href="/docs/machine" target="_blank" rel="noopener">
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
            On the PC, run this from an elevated PowerShell in the Hawk folder. The code never reaches the relay: it
            lets your machine and this browser check each other's keys.
          </span>
          <CodeBlock value={installCommand(enrollment)} />
          {enrollment.relayPin !== null && (
            <span className="field-hint">
              -RelayPin makes the machine accept only this relay's TLS key, even from a certificate it would
              otherwise trust.
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
// or the machine's text (when the browser won't take it).
type ClipboardPanel = { kind: "paste"; text: string } | { kind: "received"; text: string } | null;

function byteSize(text: string): number {
  return new TextEncoder().encode(text).length;
}

function formatSize(bytes: number): string {
  return bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KB`;
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
    elevated,
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

  // A new view, or none: whatever the panel held was for the last one.
  useEffect(() => {
    setClipPanel(null);
    setClipNote(null);
    setDropNote(null);
    setClipMenu(false);
  }, [viewing?.id, canReadClipboard]);

  // Text from the machine: straight onto this computer's clipboard where
  // the browser allows it, otherwise shown to copy by hand.
  const latest = clipboard.latest;
  useEffect(() => {
    if (latest === null) return;
    if (latest.text === "") {
      if (!latest.pushed) setClipNote("The machine's clipboard has no text.");
      return;
    }
    const what = latest.pushed ? "Copied on the machine" : "The machine's clipboard";
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
  }, [latest]);

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

  const pasteFromClipboard = async (): Promise<void> => {
    let text: string;
    try {
      text = await navigator.clipboard.readText();
    } catch {
      // Not allowed, or not supported: let it be pasted in by hand.
      setClipPanel({ kind: "paste", text: "" });
      setClipNote("This browser won't hand the page your clipboard; paste the text below.");
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
  const input = useRemoteInput(canvasRef, canControl, sendInput, canPaste ? pasteOnKey : null);

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
      <div ref={stageRef} className={input.active ? "stage controlling" : "stage"}>
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
            <span className={input.active ? "control live" : "control"}>
              {input.active ? (keysLocked ? "Input + keyboard lock" : "Input captured") : "Click to control"}
            </span>
          )}
          {input.active && (
            <button type="button" onClick={input.release}>
              Release
            </button>
          )}
          {clipboardMenu && (
            <button type="button" data-clip-menu aria-expanded={clipMenu} onClick={() => setClipMenu(!clipMenu)}>
              {clipboard.waiting ? "Getting…" : "Clipboard ▾"}
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
        <div
          className={dropping ? "stage-screen dropping" : "stage-screen"}
          onDragOver={onDragOver}
          onDragLeave={() => setDropping(false)}
          onDrop={onDrop}
        >
          <Corners />
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
          {signal}
        </div>
      </div>
      {onScreen && (
        <div className="stage-foot">
          {viewing.singleView && (
            <span>
              <Tag tone="warn">One viewing</Tag> Once you disconnect, this machine is no longer shared with you.
            </span>
          )}
          {viewing.role === "view" && <span>View only: you can watch this screen but not send it input.</span>}
          {canControl && !input.active && <span>Click the screen to send it your mouse and keyboard.</span>}
          {dropNote !== null ? (
            <span>{dropNote}</span>
          ) : (
            canSendFiles && <span>Drop files on the screen to send them to the machine.</span>
          )}
          {canReadClipboard && clipboard.access === "sync" && (
            <span>Text copied on the machine comes to your clipboard while this page has focus.</span>
          )}
          {clipNote !== null && <span>{clipNote}</span>}
          {input.active && (
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

type DetailTab = "screen" | "terminal" | "files" | "sharing" | "machine";

// The tabs a role gets: only what it can use. A dev share has no screen, so
// it starts on the terminal.
function tabsFor(role: Role): [DetailTab, string][] {
  const tabs: [DetailTab, string][] = [];
  if (canView(role)) tabs.push(["screen", "Screen"]);
  if (canShell(role)) tabs.push(["terminal", "Terminal"]);
  if (canFiles(role)) tabs.push(["files", "Files"]);
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
    return (
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
