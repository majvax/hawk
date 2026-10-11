import "@xterm/xterm/css/xterm.css";

import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import { type JSX, useEffect, useRef, useState } from "react";

import type { ShellInfo } from "../shellSessions.js";
import type { ShellActions, ShellsState } from "../useDashboard.js";

// Until the terminal has measured itself; it sends its real size at once.
const INITIAL_COLS = 120;
const INITIAL_ROWS = 30;

// Chromium only: in full screen it can hand the page the keys the browser
// keeps for itself (Ctrl+W, Alt+Tab, Esc), so they reach the shell too.
interface KeyboardLock {
  lock?: () => Promise<void>;
  unlock?: () => void;
}
const keyboardLock = (): KeyboardLock | undefined => (navigator as Navigator & { keyboard?: KeyboardLock }).keyboard;

// One shell's terminal. Kept mounted while it isn't shown, so its
// scrollback survives switching tabs.
function TerminalView({ id, actions, shown }: { id: string; actions: ShellActions; shown: boolean }): JSX.Element {
  const hostRef = useRef<HTMLDivElement>(null);
  const terminalRef = useRef<{ terminal: Terminal; fit: FitAddon } | null>(null);

  useEffect(() => {
    const host = hostRef.current;
    if (host === null) return;
    const terminal = new Terminal({
      fontFamily: '"IBM Plex Mono", "Cascadia Mono", Consolas, monospace',
      fontSize: 13,
      cursorBlink: true,
      scrollback: 5000,
      theme: { background: "#050606" },
    });
    const fit = new FitAddon();
    terminal.loadAddon(fit);
    terminal.open(host);
    terminalRef.current = { terminal, fit };

    const typed = terminal.onData((text) => actions.input(id, text));
    const resized = terminal.onResize(({ cols, rows }) => actions.resize(id, cols, rows));
    // Output is acknowledged once xterm has written it, which is what lets
    // the machine send more.
    actions.setSink(id, (data, written) => terminal.write(data, written));
    // Follows the panel's size, full screen included. Hidden, it has none.
    const observer = new ResizeObserver(() => {
      if (host.offsetWidth > 0 && host.offsetHeight > 0) fit.fit();
    });
    observer.observe(host);

    return () => {
      actions.setSink(id, null);
      observer.disconnect();
      typed.dispose();
      resized.dispose();
      terminal.dispose();
      terminalRef.current = null;
    };
  }, [id, actions]);

  // Shown: fit to the panel and take the keys.
  useEffect(() => {
    const current = terminalRef.current;
    if (!shown || current === null) return;
    current.fit.fit();
    actions.resize(id, current.terminal.cols, current.terminal.rows);
    current.terminal.focus();
  }, [shown, id, actions]);

  return <div ref={hostRef} className="terminal-host" hidden={!shown} />;
}

function tabLabel(shell: ShellInfo): string {
  if (shell.state === "opening") return `${shell.title} (starting)`;
  if (shell.state === "failed") return `${shell.title} (failed)`;
  if (shell.state === "exited") return `${shell.title} (ended)`;
  return shell.title;
}

// Shells on the machine, as tabs of terminals.
export function ShellPanel({
  shells,
  actions,
  connected,
  visible,
}: {
  shells: ShellsState;
  actions: ShellActions;
  connected: boolean;
  visible: boolean;
}): JSX.Element {
  const panelRef = useRef<HTMLDivElement>(null);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [fullscreen, setFullscreen] = useState(false);
  const [keysLocked, setKeysLocked] = useState(false);
  const list = shells.shells;
  const active = list.find((shell) => shell.id === activeId) ?? list[list.length - 1] ?? null;

  const openShell = (): void => {
    const id = actions.open(INITIAL_COLS, INITIAL_ROWS);
    if (id !== null) setActiveId(id);
  };

  // The first time it's shown on a live view with nothing in it, a shell
  // starts on its own.
  const startedRef = useRef(false);
  useEffect(() => {
    if (startedRef.current || !visible || !connected || list.length > 0) return;
    startedRef.current = true;
    openShell();
  }, [visible, connected]);

  useEffect(() => {
    const onChange = (): void => {
      const isFull = panelRef.current !== null && document.fullscreenElement === panelRef.current;
      setFullscreen(isFull);
      if (!isFull) {
        keyboardLock()?.unlock?.();
        setKeysLocked(false);
      }
    };
    document.addEventListener("fullscreenchange", onChange);
    return () => document.removeEventListener("fullscreenchange", onChange);
  }, []);

  // Leaving the tab ends full screen too.
  useEffect(() => {
    if (!visible && document.fullscreenElement === panelRef.current && panelRef.current !== null) {
      void document.exitFullscreen().catch(() => {});
    }
  }, [visible]);

  const toggleFullscreen = async (): Promise<void> => {
    if (document.fullscreenElement !== null) {
      await document.exitFullscreen().catch(() => {});
      return;
    }
    try {
      await panelRef.current?.requestFullscreen();
    } catch {
      return;
    }
    try {
      await keyboardLock()?.lock?.();
      setKeysLocked(keyboardLock()?.lock !== undefined);
    } catch {
      setKeysLocked(false);
    }
  };

  return (
    <div ref={panelRef} className={fullscreen ? "shell-panel fullscreen" : "shell-panel"}>
      <div className="files-head">
        <div className="shell-tabs">
          {list.map((shell) => (
            <button
              key={shell.id}
              type="button"
              className={shell.id === active?.id ? "shell-tab active" : "shell-tab"}
              onClick={() => setActiveId(shell.id)}
            >
              {tabLabel(shell)}
            </button>
          ))}
        </div>
        <span className="spacer" />
        {fullscreen && (
          <span className="muted shell-hint">
            {keysLocked ? (
              <>
                Shortcuts go to the shell. Hold <kbd>Esc</kbd> to leave full screen.
              </>
            ) : (
              <>
                <kbd>Esc</kbd> leaves full screen.
              </>
            )}
          </span>
        )}
        <button type="button" className="btn btn-sm" onClick={openShell} disabled={!connected}>
          New shell
        </button>
        {active !== null && (
          <button type="button" className="btn btn-sm btn-ghost" onClick={() => actions.close(active.id)}>
            Close
          </button>
        )}
        <button type="button" className="btn btn-sm btn-ghost" onClick={() => void toggleFullscreen()}>
          {fullscreen ? "Exit full screen" : "Full screen"}
        </button>
      </div>
      {active !== null && active.state !== "open" && active.state !== "opening" && (
        <div className="shell-status">
          {active.message ?? `The shell exited${active.code !== null ? ` with code ${active.code}` : ""}.`}
        </div>
      )}
      {list.length === 0 && <div className="empty">{connected ? "Starting a shell…" : "Waiting for the machine…"}</div>}
      {list
        .filter((shell) => shell.state !== "failed")
        .map((shell) => (
          <TerminalView key={shell.id} id={shell.id} actions={actions} shown={visible && shell.id === active?.id} />
        ))}
    </div>
  );
}
