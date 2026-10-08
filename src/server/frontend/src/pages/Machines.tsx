import { type JSX, type ReactNode, useEffect, useRef, useState } from "react";

import {
  type EnrollmentCode,
  createEnrollmentCode,
  describeShareTerms,
  formatAgo,
  formatElapsed,
  formatTime,
} from "../api.js";
import type { Machine, Role } from "../protocol.js";
import { Alert, CodeBlock, Corners, Dot, Metric, Tag, errorMessage, useNow } from "../ui.js";
import type { Dashboard } from "../useDashboard.js";
import { useRemoteInput } from "../useRemoteInput.js";
import { KeyStorage, MachineSettings, SharingPanel } from "./MachineAccess.js";

export const ROLE_LABEL: Record<Role, string> = { owner: "Owner", control: "Can control", view: "View only" };

type DetailTab = "screen" | "sharing" | "machine";

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

export function MachinesPage({ dashboard, visible }: { dashboard: Dashboard; visible: boolean }): JSX.Element {
  const { machines, status, viewingId, startView, stopView } = dashboard;
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [tab, setTab] = useState<DetailTab>("screen");
  const [enrollment, setEnrollment] = useState<EnrollmentCode | null>(null);
  const [error, setError] = useState<string | null>(null);
  const now = useNow();

  const selected = machines.find((machine) => machine.id === selectedId) ?? null;
  const viewing = machines.find((machine) => machine.id === viewingId) ?? null;
  // Only an owner gets the sharing and machine tabs.
  const detailTab = selected?.role === "owner" ? tab : "screen";

  const select = (id: string | null): void => {
    if (id !== selectedId) setTab("screen");
    setSelectedId(id);
  };

  const connect = (machine: Machine): void => {
    select(machine.id);
    setTab("screen");
    startView(machine.id);
  };

  const addMachine = async (): Promise<void> => {
    setError(null);
    try {
      setEnrollment(await createEnrollmentCode());
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
            {selected.role === "owner" && (
              <div className="pane-tabs" role="tablist">
                {(
                  [
                    ["screen", "Screen"],
                    ["sharing", "Sharing"],
                    ["machine", "Machine"],
                  ] as const
                ).map(([id, label]) => (
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
            {detailTab === "sharing" && <SharingPanel key={selected.id} machine={selected} />}
            {detailTab === "machine" && (
              <MachineSettings key={selected.id} machine={selected} onRemoved={() => select(null)} />
            )}
          </>
        )}

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
          <span>On the PC, run this from an elevated PowerShell in the Hawk folder:</span>
          <CodeBlock value={installCommand(enrollment)} />
          {enrollment.relayPin !== null && (
            <span className="field-hint">
              -RelayPin makes the machine accept only this relay's TLS key, even from a certificate it would
              otherwise trust.
            </span>
          )}
        </li>
        <li>
          <span>The machine shows up in the list once it connects.</span>
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
  const { canvasRef, picture, stats, decodeError, sendInput, stopView } = dashboard;
  const stageRef = useRef<HTMLDivElement>(null);
  const [fullscreen, setFullscreen] = useState(false);
  const [keysLocked, setKeysLocked] = useState(false);

  const onScreen = shown && viewing !== null && selected?.id === viewing.id;
  // Nothing to send input to unless a picture is actually up, and the relay
  // would drop it from a view-only share anyway.
  const canControl =
    onScreen && viewing.role !== "view" && viewing.online && status === "open" && picture !== null;
  const input = useRemoteInput(canvasRef, canControl, sendInput);

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

  const signal = signalFor({ onScreen, selected, viewing, status, picture, stats, decodeError, onConnect });
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
          {onScreen && (
            <button type="button" onClick={() => void toggleFullscreen()}>
              {fullscreen ? "Exit full screen" : "Full screen"}
            </button>
          )}
        </div>
        <div className="stage-screen">
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
  onConnect,
}: {
  onScreen: boolean;
  selected: Machine | null;
  viewing: Machine | null;
  status: Dashboard["status"];
  picture: Dashboard["picture"];
  stats: Dashboard["stats"];
  decodeError: Dashboard["decodeError"];
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
