import { type RefObject, useCallback, useEffect, useRef, useState } from "react";

import { getSession } from "./api.js";
import { IN_APP } from "./desktop.js";
import { socketProtocols, socketUrl } from "./relay.js";
import {
  type EnrollmentCheck,
  FRAME_AUDIO_FLAG,
  type MachineTrust,
  ViewSession,
  checkEnrollment,
  trustMachine,
} from "./e2e.js";
import {
  FileManager,
  type FileSender,
  type Listing,
  type RemoteFile,
  type Sink,
  type Transfer,
} from "./fileTransfers.js";
import { type OutputSink, type ShellInfo, ShellManager, type ShellSender } from "./shellSessions.js";
import { type ConfigState, type SettingValue, parseConfig } from "./machineConfig.js";
import { ClipboardImageManager, type ImageSender, type PasteResult } from "./clipboardImages.js";
import { EMPTY_METRICS, MetricsManager, type MetricsRange, type MetricsSender, type MetricsState } from "./metrics.js";
import type { Identity } from "./keys.js";
import { MseDecoder, mseSupported } from "./mseDecoder.js";
import { AudioPlayer, type SoundState, soundSupported } from "./audio.js";
import type { SoundMode } from "./soundMode.js";
import { type QualityPreset, type StreamQuality, parseQuality } from "./quality.js";
import { DecodeClock, PingTracker, type Quality, type StreamStats, qualityDelta, summarize } from "./streamStats.js";
import type {
  ClipboardAccess,
  DashboardCommand,
  DashboardEvent,
  InputEvent,
  Machine,
  ParsedVideoFrame,
  PowerAction,
  Role,
} from "./protocol.js";

// "reconnecting": the link dropped and the next attempt is scheduled;
// "closed": the session is over, nothing more will be tried.
export type ConnectionStatus = "connecting" | "open" | "reconnecting" | "closed";

// Reconnect backoff: 1s, 2s, 4s, ... capped at 30s, each with ±25% jitter
// so dashboards don't all hit a restarted relay in the same instant.
const RECONNECT_BASE_MS = 1000;
const RECONNECT_MAX_MS = 30_000;

function reconnectDelay(attempt: number): number {
  const delay = Math.min(RECONNECT_MAX_MS, RECONNECT_BASE_MS * 2 ** attempt);
  return delay * (0.75 + Math.random() * 0.5);
}

// Main profile, level 4.2: what the host's hardware encoder actually emits
// (profile_idc 77, level_idc 42 in its SPS). The stream is Annex-B with the
// SPS/PPS inline on keyframes, so no description is needed out of band.
const DECODER_CODEC = "avc1.4D402A";

// How frames get decoded: WebCodecs where the browser has an H.264 decoder
// (Chromium), MSE through a hidden <video> otherwise (Firefox for Android).
type Backend = "webcodecs" | "mse" | "none";

async function detectBackend(): Promise<Backend> {
  if (typeof VideoDecoder !== "undefined") {
    try {
      const { supported } = await VideoDecoder.isConfigSupported({ codec: DECODER_CODEC, optimizeForLatency: true });
      if (supported) return "webcodecs";
    } catch {
      // Treated as unsupported.
    }
  }
  return mseSupported(DECODER_CODEC) ? "mse" : "none";
}

// The Linux app decodes through the system's GStreamer, whose H.264
// decoder is a separate package on most distributions.
const UNSUPPORTED_MESSAGE =
  IN_APP && navigator.userAgent.includes("Linux")
    ? "This app can't decode H.264: install GStreamer's decoders (Arch: gst-libav gst-plugins-bad; " +
      "Debian and Ubuntu: gstreamer1.0-libav gstreamer1.0-plugins-bad), then restart it."
    : "This browser can't play H.264 video. Try an up-to-date Chrome or Firefox.";

// Decode errors in a row, with no picture in between, before giving up on
// a backend.
const MAX_DECODE_FAILURES = 3;

// What either backend looks like to the dashboard.
interface StreamDecoder {
  decode(frame: ParsedVideoFrame): void;
  close(): void;
  // Frames shown and dropped so far, where the browser counts them itself.
  playbackQuality?(): Quality | null;
  // Frames waiting inside the decoder.
  queued?(): number;
  // Frames thrown away so far rather than decoded (MSE's own backlog).
  discarded?(): number;
  // How far playback runs behind what's buffered (MSE).
  lagMs?(): number | null;
  debugInfo?(): string;
}

// What the machine's answer to a join depends on. A view that was refused
// or couldn't be trusted is only asked for again on its own once one of
// these changes, so a refusal (which itself updates the machine) can't
// turn into a loop of joins.
function admissionKey(machine: Machine): string {
  return [machine.publicKey, machine.ownerPublicKey, machine.endorsement, machine.role, machine.granted, machine.accessExpiresAt].join("|");
}

function sortByName(machines: Machine[]): Machine[] {
  return [...machines].sort((a, b) => a.name.localeCompare(b.name));
}

// A frame gap this long means the stream has stalled: the host encodes on a
// fixed clock, so an idle screen still sends frames.
const STALL_MS = 3000;

// Sync mode on the WebCodecs path: a decoded picture is shown once the
// sound has reached it (within the tolerance), and held otherwise, but
// never longer than the hold cap, so a clock that's off can't freeze it.
const SYNC_TOLERANCE_US = 10_000;
const MAX_HOLD_MS = 300;
const MAX_HELD_FRAMES = 8;

// Frames waiting to be decrypted before new deltas are dropped (until the
// next keyframe): a device too slow to keep up shouldn't build a backlog.
const MAX_PENDING_FRAMES = 30;

// Where the end-to-end handshake for the open view stands.
export type ViewSecurity =
  | { kind: "securing" } // join sent, waiting for the machine's answer
  | { kind: "secured"; role: Role } // the machine answered and its signature checked out
  | { kind: "rejected"; reason: string } // the machine refused this viewer
  | { kind: "untrusted"; reason: Exclude<MachineTrust, { ok: true }>["reason"] }
  | { kind: "failed"; message: string }; // the answer didn't check out

// ?debug in the URL adds the decoder's readout to the stream stats.
const DEBUG = new URLSearchParams(window.location.search).has("debug");

// The latest from the machine's clipboard: text, a picture (PNG), or word
// of a picture too large to send. The answer to a read, or with `pushed` a
// copy made there (sync mode). `id` changes with every new one.
export type ClipboardLatest = { id: number; pushed: boolean } & (
  | { kind: "text"; text: string }
  | { kind: "image"; png: Uint8Array<ArrayBuffer>; width: number; height: number }
  | { kind: "too_large" }
);

// The open view's clipboard: what the machine lets this viewer do with it,
// and the latest it sent.
export interface ClipboardState {
  access: ClipboardAccess;
  // Whether pictures go with it, both ways, as text does.
  images: boolean;
  // Set while a read is on its way.
  waiting: boolean;
  latest: ClipboardLatest | null;
}

const NO_CLIPBOARD: ClipboardState = { access: "off", images: false, waiting: false, latest: null };

// A read the machine hasn't answered by then (hawk-capture still starting,
// or the request was dropped) stops showing as underway.
const CLIPBOARD_WAIT_MS = 5000;

// The open view's file transfers.
export interface FilesState {
  // Whether the machine lets this viewer send and fetch files.
  enabled: boolean;
  listing: Listing | null;
  listingError: string | null;
  transfers: Transfer[];
}

const NO_FILES: FilesState = { enabled: false, listing: null, listingError: null, transfers: [] };

export interface FileActions {
  list: () => void;
  upload: (files: File[]) => void;
  download: (file: RemoteFile, sink: Sink) => void;
  cancel: (id: string) => void;
  retry: (id: string) => void;
  dismiss: (id: string) => void;
}

// The open view's shells.
export interface ShellsState {
  // Whether the machine lets this viewer open shells.
  enabled: boolean;
  shells: ShellInfo[];
}

const NO_SHELLS: ShellsState = { enabled: false, shells: [] };

export interface MetricsActions {
  // A tab showing live numbers opened (true) or closed (false).
  watch: (on: boolean) => void;
  history: (range: MetricsRange) => void;
  processes: () => void;
}

export interface ShellActions {
  // Returns the new shell's id, or null when there's no view to open it on.
  open: (cols: number, rows: number) => string | null;
  input: (id: string, text: string) => void;
  resize: (id: string, cols: number, rows: number) => void;
  close: (id: string) => void;
  setSink: (id: string, sink: OutputSink | null) => void;
}

export interface Dashboard {
  machines: Machine[];
  status: ConnectionStatus;
  // While reconnecting: when the next attempt is due (ms since epoch).
  retryAt: number | null;
  // The machine whose view is open. It stays set while the link or the
  // machine is down, and the stream resumes once both are back.
  viewingId: string | null;
  // Attach to the <canvas> that frames are drawn into.
  canvasRef: RefObject<HTMLCanvasElement>;
  // The size of the picture on the canvas; null until the open view's
  // first frame is drawn.
  picture: { width: number; height: number } | null;
  // Measured once a second while a view is open.
  stats: StreamStats | null;
  // Set when this browser can't decode the stream, or the decoder keeps
  // failing; the view shows it instead of waiting for a picture.
  decodeError: string | null;
  // The open view's end-to-end handshake; null with no view open.
  security: ViewSecurity | null;
  clipboard: ClipboardState;
  files: FilesState;
  fileActions: FileActions;
  shells: ShellsState;
  shellActions: ShellActions;
  // The open view's machine analytics, when this viewer may read them.
  metrics: MetricsState;
  metricsActions: MetricsActions;
  // Owned machines whose enrollment this browser checked: "mismatch" means
  // the key the machine answered with isn't bound to the code made here.
  enrollmentChecks: Record<string, EnrollmentCheck>;
  // Whether the relay passes this view's input, files and shells on. An
  // account with a second factor has to have proved it in the last few
  // minutes; then `elevate` asks again.
  elevated: boolean;
  elevate: () => void;
  // Owner only: tells the machine to install the update it's holding.
  installUpdate: (deviceId: string) => void;
  // The machine's output devices, once asked for (requestAudioDevices),
  // null before that.
  audioDevices: AudioDevicesState | null;
  // Asks the machine for them; anyone watching. False when there's no
  // secured view to ask.
  requestAudioDevices: () => boolean;
  // Has the machine capture another device ("" for its default). The
  // relay drops it unless this view has control and is elevated, and the
  // machine checks the role again. The answer is a fresh list.
  selectAudioDevice: (id: string) => boolean;
  // The machine's config and its schema, once asked for (requestConfig),
  // null before that.
  config: ConfigState | null;
  // Asks the machine for it; control and owner. False when there's no
  // secured view to ask.
  requestConfig: () => boolean;
  // Changes settings, against the version last received. The relay drops
  // it unless this view is the owner's and elevated, and the machine
  // checks the role and every value again. The answer is the config as it
  // now stands, with `saved` or the reason it wasn't.
  saveConfig: (changes: Record<string, SettingValue>) => boolean;
  // Asks the machine being watched to lock, sign out, restart or shut
  // down. The relay drops it unless this view has control and is elevated,
  // and the machine checks the role again. Returns false when there's no
  // secured view with control to send it to.
  sendPower: (action: PowerAction) => boolean;
  startView: (deviceId: string) => void;
  stopView: () => void;
  // Sends one input event to the machine being watched. The relay drops it
  // unless this user may control that machine, so a view-only viewer can
  // call this all it likes and nothing happens.
  sendInput: (event: InputEvent) => void;
  // Pastes text into the machine's clipboard (control only), or with null
  // asks for what's on it; the answer lands in `clipboard.latest`. Returns
  // false when there's no secured view to send it to.
  sendClipboard: (text: string | null) => boolean;
  // Pastes a PNG into the machine's clipboard (control only, while
  // `clipboard.images`): settles once it's there, or with why not.
  pasteImage: (png: Uint8Array) => Promise<PasteResult>;
  // Skip the rest of the backoff and try now.
  reconnectNow: () => void;
  // The machine's sound: whether it can play here, whether the browser is
  // holding it back until a click, and whether it's muted.
  sound: SoundState;
  setMuted: (muted: boolean) => void;
  // Call from a click or key press: lets the browser start the sound.
  unlockSound: () => void;
  // What the open view's stream is encoded at, as the machine last said;
  // null before it has (or from a machine too old to say).
  streamQuality: StreamQuality | null;
  // Picks the stream's preset for everyone watching. The relay drops it
  // unless this view has control, and the machine checks the role again.
  // False when there's no secured view with control to send it to.
  setQuality: (preset: QualityPreset) => boolean;
  // Presses Ctrl+Alt+Del on the machine being watched. The relay drops it
  // unless this view has control and is elevated, as with input, and the
  // machine checks the role again; its answer lands in `sasResult`. False
  // when there's no secured view with control to send it to.
  sendSas: () => boolean;
  sasResult: SasResult | null;
  // Call once `sasResult` is shown, so it isn't shown again.
  clearSasResult: () => void;
  // Prefer sync over latency: the picture waits for the sound (soundMode.ts).
  sync: boolean;
  setSync: (sync: boolean) => void;
  // The stats overlay on the live view; while it's up, the machine is
  // pinged once a second for the round trip. Remembered in the browser.
  statsShown: boolean;
  setStatsShown: (shown: boolean) => void;
  // Whether the overlay is on screen now (the Screen tab is up): pings
  // only go out while it is.
  setStatsVisible: (visible: boolean) => void;
}

// The machine's answer to a Ctrl+Alt+Del: pressed, or why not. Numbered, so
// the same answer twice still counts as new.
export interface SasResult {
  id: number;
  sent: boolean;
  error: string;
}

export interface AudioDevice {
  id: string;
  name: string;
  default: boolean;
}

export interface AudioDevicesState {
  devices: AudioDevice[];
  // The endpoint id captured, "" for the default.
  selected: string;
  // Whether the stream carries sound at all.
  sound: boolean;
  error: string;
}

function parseAudioDevices(header: unknown): AudioDevicesState | null {
  if (typeof header !== "object" || header === null) return null;
  const { devices, selected, sound, error } = header as Record<string, unknown>;
  if (!Array.isArray(devices)) return null;
  return {
    devices: devices.flatMap((device: unknown): AudioDevice[] => {
      if (typeof device !== "object" || device === null) return [];
      const { id, name, default: isDefault } = device as Record<string, unknown>;
      return typeof id === "string" && typeof name === "string" ? [{ id, name, default: isDefault === true }] : [];
    }),
    selected: typeof selected === "string" ? selected : "",
    sound: sound === true,
    error: typeof error === "string" ? error : "",
  };
}

const MUTED_KEY = "hawk.sound.muted";
const SYNC_KEY = "hawk.sound.sync";
const STATS_KEY = "hawk.view.stats";

function loadStatsShown(): boolean {
  try {
    return window.localStorage.getItem(STATS_KEY) === "1";
  } catch {
    return false;
  }
}

function loadSync(): boolean {
  try {
    return window.localStorage.getItem(SYNC_KEY) === "1";
  } catch {
    return false;
  }
}

function loadMuted(): boolean {
  try {
    return window.localStorage.getItem(MUTED_KEY) === "1";
  } catch {
    return false;
  }
}

// Keeps a socket to the relay open for as long as the session lasts. When
// the link drops (relay restart, network loss) it reconnects with a growing
// delay, checking first that the session is still valid; `onSessionEnded`
// runs once it isn't (logged out elsewhere, account disabled).
export function useDashboard(identity: Identity, onSessionEnded: () => void): Dashboard {
  const onSessionEndedRef = useRef(onSessionEnded);
  onSessionEndedRef.current = onSessionEnded;

  const [machines, setMachines] = useState<Machine[]>([]);
  const [status, setStatus] = useState<ConnectionStatus>("connecting");
  const [retryAt, setRetryAt] = useState<number | null>(null);
  const [viewingId, setViewingId] = useState<string | null>(null);
  const [picture, setPicture] = useState<Dashboard["picture"]>(null);
  const [stats, setStats] = useState<StreamStats | null>(null);
  const [decodeError, setDecodeError] = useState<string | null>(null);
  const [security, setSecurity] = useState<ViewSecurity | null>(null);
  const [clipboard, setClipboard] = useState<ClipboardState>(NO_CLIPBOARD);
  // Numbers what the machine sends, so the same text twice still counts
  // as new.
  const clipboardIdRef = useRef(0);
  const [files, setFiles] = useState<FilesState>(NO_FILES);
  const filesEnabledRef = useRef(false);
  // The open view's transfers, kept across a dropped connection so they can
  // resume; replaced when the view moves to another machine.
  const fileManagerRef = useRef<FileManager | null>(null);
  // File messages are opened one at a time, in the order they arrived.
  const fileChainRef = useRef<Promise<void>>(Promise.resolve());
  // Clipboard text and Ctrl+Alt+Del answers share the reply key's counter,
  // so they're opened one at a time, in the order they arrived: otherwise a
  // slow earlier one could be dropped as already seen.
  const replyChainRef = useRef<Promise<void>>(Promise.resolve());
  // Clipboard pictures, on a channel of their own (clipboardImages.ts).
  const imageChainRef = useRef<Promise<void>>(Promise.resolve());
  const imageManagerRef = useRef<ClipboardImageManager | null>(null);
  imageManagerRef.current ??= new ClipboardImageManager({
    received: ({ png, width, height, pushed }) => {
      clipboardIdRef.current += 1;
      const latest: ClipboardLatest = { id: clipboardIdRef.current, kind: "image", png, width, height, pushed };
      setClipboard((prev) => ({ ...prev, waiting: false, latest }));
    },
    skipped: (pushed) => {
      clipboardIdRef.current += 1;
      const latest: ClipboardLatest = { id: clipboardIdRef.current, kind: "too_large", pushed };
      setClipboard((prev) => ({ ...prev, waiting: false, latest }));
    },
  });
  const imageManager = imageManagerRef.current;
  const fileFrameRef = useRef<number | null>(null);
  const [shells, setShells] = useState<ShellsState>(NO_SHELLS);
  const shellsEnabledRef = useRef(false);
  const shellManagerRef = useRef<ShellManager | null>(null);
  const shellChainRef = useRef<Promise<void>>(Promise.resolve());
  const [metrics, setMetrics] = useState<MetricsState>(EMPTY_METRICS);
  const metricsManagerRef = useRef<MetricsManager | null>(null);
  const metricsChainRef = useRef<Promise<void>>(Promise.resolve());
  const audioChainRef = useRef<Promise<void>>(Promise.resolve());
  const [audioDevices, setAudioDevices] = useState<AudioDevicesState | null>(null);
  const [streamQuality, setStreamQuality] = useState<StreamQuality | null>(null);
  const [sasResult, setSasResult] = useState<SasResult | null>(null);
  const sasIdRef = useRef(0);
  const configChainRef = useRef<Promise<void>>(Promise.resolve());
  const [config, setConfig] = useState<ConfigState | null>(null);
  const configRef = useRef<ConfigState | null>(null);
  configRef.current = config;
  const publishShells = useRef((): void => {
    const manager = shellManagerRef.current;
    setShells(manager === null ? NO_SHELLS : { enabled: shellsEnabledRef.current, shells: manager.snapshot() });
  }).current;
  // Progress arrives per chunk; the panel is redrawn at most once a frame.
  const publishFiles = useRef((): void => {
    if (fileFrameRef.current !== null) return;
    fileFrameRef.current = window.requestAnimationFrame(() => {
      fileFrameRef.current = null;
      const manager = fileManagerRef.current;
      setFiles(
        manager === null
          ? NO_FILES
          : {
              enabled: filesEnabledRef.current,
              listing: manager.listing,
              listingError: manager.listingError,
              transfers: manager.snapshot(),
            },
      );
    });
  }).current;
  const [enrollmentChecks, setEnrollmentChecks] = useState<Record<string, EnrollmentCheck>>({});
  const [elevated, setElevated] = useState(false);

  const socketRef = useRef<WebSocket | null>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const decoderRef = useRef<StreamDecoder | null>(null);
  // null until detectBackend() settles; frames before that are dropped.
  const backendRef = useRef<Backend | null>(null);
  const failuresRef = useRef(0);
  const sawKeyframeRef = useRef(false);
  // Read inside the socket's handlers, which are created once per socket.
  const viewingRef = useRef<string | null>(null);
  // The machine start_view was sent for on the current socket; null after a
  // reconnect until the view is resumed.
  const streamingRef = useRef<string | null>(null);
  const reconnectNowRef = useRef<() => void>(() => {});
  // The open view's end-to-end session; null until a join has been sent.
  const sessionRef = useRef<ViewSession | null>(null);
  // Decryption is asynchronous, but frames must reach the decoder in order,
  // and input must reach the machine in the order it was sealed.
  const frameChainRef = useRef<Promise<void>>(Promise.resolve());
  const pendingFramesRef = useRef(0);
  const inputChainRef = useRef<Promise<void>>(Promise.resolve());
  // Machines are read from socket handlers, which are created once.
  const machinesRef = useRef<Machine[]>([]);
  machinesRef.current = machines;
  const checkedEnrollmentsRef = useRef(new Set<string>());
  // Set when the open view was refused or untrusted: the admissionKey it
  // was refused under.
  const blockedRef = useRef<string | null>(null);
  // Ends the open session, so frames waiting on its answer stop waiting.
  const dropSession = useRef((): void => {
    sessionRef.current?.abandon();
    sessionRef.current = null;
    setClipboard(NO_CLIPBOARD);
    imageManagerRef.current?.attach(null);
    // Transfers wait for the view to come back rather than fail; shells
    // end, since the machine closes them.
    fileManagerRef.current?.attach(null);
    shellManagerRef.current?.attach(null);
  }).current;
  // Counted per frame, read and reset by the once-a-second stats sample.
  const framesRef = useRef(0);
  const droppedRef = useRef(0);
  const bytesRef = useRef(0);
  const receivedRef = useRef(0);
  const lastFrameAtRef = useRef(0);
  // Out of the WebCodecs decoder, and thrown away before reaching one.
  const decodedRef = useRef(0);
  const skippedRef = useRef(0);
  const decodeClockRef = useRef(new DecodeClock());
  const pingRef = useRef(new PingTracker());
  const [statsShown, setStatsShownState] = useState(loadStatsShown);
  const statsShownRef = useRef(statsShown);
  const statsVisibleRef = useRef(false);

  const send = useCallback((command: DashboardCommand): boolean => {
    const socket = socketRef.current;
    if (socket?.readyState !== WebSocket.OPEN) return false;
    socket.send(JSON.stringify(command));
    return true;
  }, []);

  // Opens an end-to-end session with the machine: checks its key is the one
  // its owner vouched for, then sends a signed join for it to answer.
  // streamingRef is set at once, so the stream isn't asked for twice while
  // the join is being signed.
  const requestStream = useCallback(
    (deviceId: string, machine?: Machine): void => {
      const target = machine ?? machinesRef.current.find((candidate) => candidate.id === deviceId);
      if (target === undefined || socketRef.current?.readyState !== WebSocket.OPEN) return;
      if (blockedRef.current !== null && blockedRef.current === admissionKey(target)) return;
      blockedRef.current = null;
      streamingRef.current = deviceId;
      dropSession();
      setSecurity({ kind: "securing" });
      void (async () => {
        const trust = await trustMachine(identity, target);
        if (viewingRef.current !== deviceId || streamingRef.current !== deviceId) return;
        if (!trust.ok) {
          streamingRef.current = null;
          blockedRef.current = admissionKey(target);
          setSecurity({ kind: "untrusted", reason: trust.reason });
          return;
        }
        const session = await ViewSession.start(identity, deviceId, trust.machineKey);
        if (viewingRef.current !== deviceId || streamingRef.current !== deviceId) return;
        sessionRef.current = session;
        if (!send({ type: "start_view", deviceId, join: session.join })) streamingRef.current = null;
      })().catch((error: unknown) => {
        if (streamingRef.current === deviceId) streamingRef.current = null;
        setSecurity({ kind: "failed", message: error instanceof Error ? error.message : String(error) });
      });
    },
    [identity, send],
  );

  // One player for as long as the dashboard is open; each new stream
  // starts it over.
  const [sound, setSound] = useState<SoundState>(() => ({
    supported: soundSupported(),
    blocked: false,
    muted: loadMuted(),
  }));
  const audioRef = useRef<AudioPlayer | null>(null);
  const [sync, setSyncState] = useState(loadSync);
  const syncRef = useRef(sync);
  // The sound's clock, while sync mode has the picture follow it.
  const syncClock = useCallback(
    (): number | null => (syncRef.current ? (audioRef.current?.audibleStreamUs() ?? null) : null),
    [],
  );
  const audioPlayer = useCallback((): AudioPlayer => {
    if (audioRef.current === null) {
      audioRef.current = new AudioPlayer(setSound);
      audioRef.current.setMuted(loadMuted());
      audioRef.current.setMode(syncRef.current ? "sync" : "latency");
    }
    return audioRef.current;
  }, []);
  useEffect(() => () => audioRef.current?.close(), []);

  // WebCodecs pictures held for the sound in sync mode, oldest first.
  const heldRef = useRef<Array<{ frame: VideoFrame; heldAt: number }>>([]);
  const presentFrameRef = useRef<number | null>(null);
  // The picture's lead over the sound when last shown, for ?debug.
  const skewMsRef = useRef<number | null>(null);

  const dropHeld = useCallback((): void => {
    for (const { frame } of heldRef.current) frame.close();
    heldRef.current = [];
    if (presentFrameRef.current !== null) cancelAnimationFrame(presentFrameRef.current);
    presentFrameRef.current = null;
  }, []);

  const teardownDecoder = useCallback((): void => {
    dropHeld();
    sawKeyframeRef.current = false;
    const decoder = decoderRef.current;
    decoderRef.current = null;
    decoder?.close();
    decodeClockRef.current.clear();
    audioRef.current?.reset();
  }, [dropHeld]);

  // Sizes the canvas to the picture, lets `draw` paint it, and counts it.
  const paint = useCallback(
    (width: number, height: number, draw: (context: CanvasRenderingContext2D) => void): void => {
      const canvas = canvasRef.current;
      if (canvas === null || width === 0 || height === 0) return;
      if (canvas.width !== width || canvas.height !== height) {
        canvas.width = width;
        canvas.height = height;
        setPicture({ width, height });
      }
      const context = canvas.getContext("2d");
      if (context !== null) draw(context);
      failuresRef.current = 0;
      framesRef.current += 1;
      lastFrameAtRef.current = performance.now();
    },
    [],
  );

  const showFrame = useCallback(
    (frame: VideoFrame): void => {
      paint(frame.displayWidth, frame.displayHeight, (context) => context.drawImage(frame, 0, 0));
      frame.close();
    },
    [paint],
  );

  // Once a display frame: shows the newest held picture the sound has
  // reached, and drops the older ones.
  const presentHeld = useCallback((): void => {
    presentFrameRef.current = null;
    const held = heldRef.current;
    if (held.length === 0) return;
    const clock = syncClock();
    let index = held.length - 1;
    if (clock !== null) {
      index = -1;
      for (const [i, { frame }] of held.entries()) {
        if (frame.timestamp <= clock + SYNC_TOLERANCE_US) index = i;
      }
      const overdue = performance.now() - (held[0]?.heldAt ?? 0) > MAX_HOLD_MS || held.length > MAX_HELD_FRAMES;
      if (index < 0 && overdue) index = 0;
    }
    if (index >= 0) {
      const shown = held.splice(0, index + 1);
      for (const { frame } of shown.slice(0, -1)) {
        frame.close();
        droppedRef.current += 1;
      }
      const frame = shown[shown.length - 1]?.frame;
      if (frame !== undefined) {
        skewMsRef.current = clock === null ? null : (frame.timestamp - clock) / 1000;
        showFrame(frame);
      }
    }
    if (held.length > 0) presentFrameRef.current = requestAnimationFrame(presentHeld);
  }, [showFrame, syncClock]);

  // The decoder's output. Shown at once, unless sync mode has it wait for
  // the sound.
  const drawFrame = useCallback(
    (frame: VideoFrame): void => {
      decodedRef.current += 1;
      decodeClockRef.current.finished(frame.timestamp, performance.now());
      if (!syncRef.current && heldRef.current.length === 0) {
        skewMsRef.current = null;
        showFrame(frame);
        return;
      }
      const held = heldRef.current;
      held.push({ frame, heldAt: performance.now() });
      // A tab in the background runs no display frames: don't pile up.
      while (held.length > MAX_HELD_FRAMES * 2) {
        held.shift()?.frame.close();
        droppedRef.current += 1;
      }
      presentFrameRef.current ??= requestAnimationFrame(presentHeld);
    },
    [presentHeld, showFrame],
  );

  // The <video> shows the picture itself, under the canvas; the canvas is
  // only sized to it, left transparent, and takes the input.
  const sizeToVideo = useCallback(
    (video: HTMLVideoElement): void => {
      paint(video.videoWidth, video.videoHeight, () => {});
    },
    [paint],
  );

  // Blanks the canvas, so one machine's screen never shows under another's
  // name. The next frame drawn sizes it again.
  const clearPicture = useCallback((): void => {
    const canvas = canvasRef.current;
    if (canvas !== null) {
      canvas.width = 0;
      canvas.height = 0;
    }
    setPicture(null);
  }, []);

  // A decoder failed: drop it, and the next keyframe starts a new one. If
  // that keeps happening, move from WebCodecs to MSE, or give up and say so.
  const onDecodeError = useCallback(
    (failed: StreamDecoder, message: string): void => {
      console.error("video decode error:", message);
      if (decoderRef.current !== failed) return; // already replaced
      teardownDecoder();
      failuresRef.current += 1;
      if (failuresRef.current < MAX_DECODE_FAILURES) return;
      failuresRef.current = 0;
      if (backendRef.current === "webcodecs" && mseSupported(DECODER_CODEC)) {
        backendRef.current = "mse";
      } else {
        setDecodeError(`The video decoder keeps failing (${message}).`);
      }
    },
    [teardownDecoder],
  );

  const ensureDecoder = useCallback((): StreamDecoder | null => {
    if (decoderRef.current !== null) return decoderRef.current;
    let decoder: StreamDecoder;
    switch (backendRef.current) {
      case "webcodecs": {
        const videoDecoder = new VideoDecoder({
          output: drawFrame,
          error: (error) => onDecodeError(decoder, error.message),
        });
        videoDecoder.configure({ codec: DECODER_CODEC, optimizeForLatency: true });
        decoder = {
          decode: (frame) => {
            if (videoDecoder.state !== "configured") return;
            decodeClockRef.current.submitted(frame.timestamp, performance.now());
            videoDecoder.decode(
              new EncodedVideoChunk({
                type: frame.isKeyframe ? "key" : "delta",
                timestamp: frame.timestamp,
                data: frame.data,
              }),
            );
          },
          close: () => {
            if (videoDecoder.state !== "closed") videoDecoder.close();
          },
          queued: () => videoDecoder.decodeQueueSize,
          debugInfo: () => {
            const skew = skewMsRef.current;
            return skew === null ? "a/v free" : `a/v ${skew >= 0 ? "+" : ""}${Math.round(skew)}ms`;
          },
        };
        break;
      }
      case "mse": {
        const canvas = canvasRef.current;
        if (canvas === null) return null;
        const mse: StreamDecoder = new MseDecoder(
          canvas,
          sizeToVideo,
          (message) => onDecodeError(mse, message),
          syncClock,
        );
        decoder = mse;
        break;
      }
      default:
        return null;
    }
    decoderRef.current = decoder;
    return decoder;
  }, [drawFrame, sizeToVideo, onDecodeError, syncClock]);

  const decodeFrame = useCallback(
    (frame: ParsedVideoFrame): void => {
      // Decoding can only begin on a keyframe; drop deltas until the first
      // one arrives (e.g. when attaching mid-stream).
      if (!sawKeyframeRef.current && !frame.isKeyframe) {
        skippedRef.current += 1;
        return;
      }
      sawKeyframeRef.current = true;
      ensureDecoder()?.decode(frame);
    },
    [ensureDecoder],
  );

  // Decrypts with the open session, in arrival order. Frames from before
  // the session was accepted, or under a key it doesn't have, are dropped.
  const handleFrame = useCallback(
    (buffer: ArrayBuffer): void => {
      // Frames that come before the machine's answer is checked wait for
      // it in the chain below; without a session there's nothing to wait for.
      const session = sessionRef.current;
      if (session === null) return;
      bytesRef.current += buffer.byteLength;
      const flags = buffer.byteLength > 1 ? (new Uint8Array(buffer, 1, 1)[0] ?? 0) : 0;
      const keyframe = flags & 0x01;
      if ((flags & FRAME_AUDIO_FLAG) === 0) receivedRef.current += 1; // the stats count pictures
      if (pendingFramesRef.current >= MAX_PENDING_FRAMES && !keyframe) {
        sawKeyframeRef.current = false; // a gap: start again at a keyframe
        if ((flags & FRAME_AUDIO_FLAG) === 0) skippedRef.current += 1;
        return;
      }
      pendingFramesRef.current += 1;
      frameChainRef.current = frameChainRef.current
        .then(async () => {
          const frame = await session.openFrame(buffer);
          if (frame !== null && sessionRef.current === session) {
            if (frame.isAudio) audioPlayer().play(frame);
            else decodeFrame(frame);
          } else if (frame === null && (flags & FRAME_AUDIO_FLAG) === 0) {
            sawKeyframeRef.current = false;
          }
        })
        .catch((error: unknown) => console.error("frame:", error))
        .finally(() => {
          pendingFramesRef.current -= 1;
        });
    },
    [audioPlayer, decodeFrame],
  );

  // A new view starts with a clean slate, unless the browser can't decode
  // at all.
  const resetDecodeError = useCallback((): void => {
    failuresRef.current = 0;
    setDecodeError(backendRef.current === "none" ? UNSUPPORTED_MESSAGE : null);
  }, []);

  useEffect(() => {
    let disposed = false;
    void detectBackend().then((backend) => {
      if (disposed) return;
      backendRef.current = backend;
      if (backend === "none") setDecodeError(UNSUPPORTED_MESSAGE);
    });
    return () => {
      disposed = true;
    };
  }, []);

  // Fresh transfers and shells for the machine now being viewed (null: none).
  const resetTools = useCallback(
    (deviceId: string | null): void => {
      fileManagerRef.current?.close();
      fileManagerRef.current = deviceId === null ? null : new FileManager(publishFiles);
      filesEnabledRef.current = false;
      publishFiles();
      shellManagerRef.current?.closeAll();
      shellManagerRef.current = deviceId === null ? null : new ShellManager(publishShells);
      shellsEnabledRef.current = false;
      publishShells();
      metricsManagerRef.current?.close();
      metricsManagerRef.current = deviceId === null ? null : new MetricsManager(setMetrics);
      setMetrics(EMPTY_METRICS);
      setAudioDevices(null);
      setStreamQuality(null);
      setSasResult(null);
      setConfig(null);
    },
    [publishFiles, publishShells],
  );

  // The same for the shell channel.
  const shellSender = useCallback(
    (session: ViewSession, deviceId: string): ShellSender =>
      (op, header, data) => {
        if (sessionRef.current !== session) return false;
        const sealed = session.sealShell(op, header, data);
        if (sealed === null) return false;
        inputChainRef.current = inputChainRef.current
          .then(() => sealed)
          .then((payload) => {
            if (sessionRef.current === session) send({ type: "shell", deviceId, sealed: payload });
          })
          .catch((error: unknown) => console.error("sealing shell message:", error));
        return true;
      },
    [send],
  );

  // The same for metrics requests.
  const metricsSender = useCallback(
    (session: ViewSession, deviceId: string): MetricsSender =>
      (op, header) => {
        if (sessionRef.current !== session) return false;
        const sealed = session.sealMetrics(op, header);
        if (sealed === null) return false;
        inputChainRef.current = inputChainRef.current
          .then(() => sealed)
          .then((payload) => {
            if (sessionRef.current === session) send({ type: "metrics", deviceId, sealed: payload });
          })
          .catch((error: unknown) => console.error("sealing metrics request:", error));
        return true;
      },
    [send],
  );

  // The same for clipboard pictures: requests, and chunks to paste, sealed
  // apart.
  const imageSender = useCallback(
    (session: ViewSession, deviceId: string): ImageSender => {
      const sendSealedImage = (
        type: "clipboard_image" | "clipboard_image_put",
        sealed: Promise<string> | null,
      ): boolean => {
        if (sessionRef.current !== session || sealed === null) return false;
        inputChainRef.current = inputChainRef.current
          .then(() => sealed)
          .then((payload) => {
            if (sessionRef.current === session) send({ type, deviceId, sealed: payload });
          })
          .catch((error: unknown) => console.error("sealing clipboard picture:", error));
        return true;
      };
      return {
        request: (op, header) => sendSealedImage("clipboard_image", session.sealClipboardImage(op, header)),
        put: (op, header, data) => sendSealedImage("clipboard_image_put", session.sealClipboardImagePut(op, header, data)),
      };
    },
    [send],
  );

  // Seals file-channel messages for `session` and sends them in order with
  // input (they share its counter).
  const fileSender = useCallback(
    (session: ViewSession, deviceId: string): FileSender =>
      (op, header, data) => {
        if (sessionRef.current !== session) return false;
        const sealed = session.sealFile(op, header, data);
        if (sealed === null) return false;
        inputChainRef.current = inputChainRef.current
          .then(() => sealed)
          .then((payload) => {
            if (sessionRef.current === session) send({ type: "file", deviceId, sealed: payload });
          })
          .catch((error: unknown) => console.error("sealing file message:", error));
        return true;
      },
    [send],
  );

  // The open view is gone for good: stopped, or the machine was taken away.
  const clearView = useCallback((): void => {
    resetDecodeError();
    setSecurity(null);
    viewingRef.current = null;
    streamingRef.current = null;
    dropSession();
    setElevated(false);
    setViewingId(null);
    teardownDecoder();
    clearPicture();
    resetTools(null);
  }, [clearPicture, resetDecodeError, resetTools, teardownDecoder]);

  const handleEvent = useCallback(
    (payload: DashboardEvent): void => {
      const viewing = viewingRef.current;
      switch (payload.type) {
        case "snapshot": {
          setMachines(sortByName(payload.machines));
          // Fresh socket: resume the view that was open, if it's still ours.
          if (viewing === null) break;
          const machine = payload.machines.find((candidate) => candidate.id === viewing);
          if (machine === undefined) clearView();
          else if (machine.online) requestStream(viewing, machine);
          // Offline: wait for it to come back (machine_updated below).
          break;
        }
        case "machine_updated":
          setMachines((prev) =>
            sortByName([...prev.filter((machine) => machine.id !== payload.machine.id), payload.machine]),
          );
          if (viewing === payload.machine.id && payload.machine.online && streamingRef.current === null) {
            requestStream(viewing, payload.machine);
          }
          break;
        case "machine_removed":
          setMachines((prev) => prev.filter((machine) => machine.id !== payload.id));
          if (viewing === payload.id) clearView();
          break;
        case "capture_ended":
          // The machine dropped off. Keep the view open and pick the stream
          // back up when it reconnects; the decoder restarts on a keyframe.
          if (viewing === payload.deviceId) {
            streamingRef.current = null;
            dropSession();
            teardownDecoder();
          }
          break;
        case "view_accepted": {
          const session = sessionRef.current;
          if (viewing !== payload.deviceId || session === null) break;
          session.accept(payload).then(
            () => {
              if (sessionRef.current === session && session.role !== null) {
                setSecurity({ kind: "secured", role: session.role });
                // A relay from before the clipboard says nothing: none, then.
                // Likewise pictures, from a machine or relay before them.
                const access = payload.clipboard ?? "off";
                const images = access !== "off" && payload.clipboardImages === true;
                setClipboard({ access, images, waiting: false, latest: null });
                imageManagerRef.current?.attach(images ? imageSender(session, payload.deviceId) : null);
                filesEnabledRef.current = payload.files === true;
                const manager = fileManagerRef.current;
                if (manager !== null) {
                  manager.attach(payload.files === true ? fileSender(session, payload.deviceId) : null);
                  if (payload.files === true) manager.list();
                }
                shellsEnabledRef.current = payload.shell === true;
                shellManagerRef.current?.attach(
                  payload.shell === true ? shellSender(session, payload.deviceId) : null,
                );
                metricsManagerRef.current?.attach(
                  payload.analytics === true ? metricsSender(session, payload.deviceId) : null,
                );
              }
            },
            (error: unknown) => {
              if (sessionRef.current !== session) return;
              // Nothing from this machine can be trusted: stop asking.
              send({ type: "stop_view", deviceId: payload.deviceId });
              const machine = machinesRef.current.find((candidate) => candidate.id === payload.deviceId);
              blockedRef.current = machine === undefined ? "" : admissionKey(machine);
              streamingRef.current = null;
              dropSession();
              teardownDecoder();
              setSecurity({ kind: "failed", message: error instanceof Error ? error.message : String(error) });
            },
          );
          break;
        }
        case "stream_key": {
          const session = sessionRef.current;
          if (viewing !== payload.deviceId || session === null) break;
          // Ahead of the frames under it: the relay sends events first.
          frameChainRef.current = frameChainRef.current
            .then(() => session.addStreamKey(payload.wrappedKey))
            .catch((error: unknown) => console.error("stream key:", error));
          break;
        }
        case "clipboard": {
          const session = sessionRef.current;
          if (viewing !== payload.deviceId || session === null) break;
          replyChainRef.current = replyChainRef.current
            .then(() => session.openClipboard(payload.sealed))
            .then((opened) => {
              if (opened === null || sessionRef.current !== session) return;
              clipboardIdRef.current += 1;
              const latest: ClipboardLatest = { id: clipboardIdRef.current, kind: "text", ...opened };
              setClipboard((prev) => ({ ...prev, waiting: false, latest }));
            })
            .catch((error: unknown) => console.error("clipboard message:", error));
          break;
        }
        case "clipboard_image": {
          const session = sessionRef.current;
          if (viewing !== payload.deviceId || session === null) break;
          imageChainRef.current = imageChainRef.current
            .then(() => session.openClipboardImage(payload.sealed))
            .then((opened) => {
              if (opened === null || sessionRef.current !== session) return;
              imageManagerRef.current?.handle(opened.op, opened.header, opened.data);
            })
            .catch((error: unknown) => console.error("clipboard picture:", error));
          break;
        }
        case "clipboard_image_reply": {
          const session = sessionRef.current;
          if (viewing !== payload.deviceId || session === null) break;
          replyChainRef.current = replyChainRef.current
            .then(() => session.openClipboardImageReply(payload.sealed))
            .then((opened) => {
              if (opened === null || sessionRef.current !== session) return;
              imageManagerRef.current?.handle(opened.op, opened.header, opened.data);
            })
            .catch((error: unknown) => console.error("clipboard picture answer:", error));
          break;
        }
        case "file": {
          const session = sessionRef.current;
          if (viewing !== payload.deviceId || session === null) break;
          fileChainRef.current = fileChainRef.current
            .then(() => session.openFile(payload.sealed))
            .then((opened) => {
              if (opened === null || sessionRef.current !== session) return;
              fileManagerRef.current?.handle(opened.op, opened.header, opened.data);
            })
            .catch((error: unknown) => console.error("file message:", error));
          break;
        }
        case "shell": {
          const session = sessionRef.current;
          if (viewing !== payload.deviceId || session === null) break;
          shellChainRef.current = shellChainRef.current
            .then(() => session.openShell(payload.sealed))
            .then((opened) => {
              if (opened === null || sessionRef.current !== session) return;
              shellManagerRef.current?.handle(opened.op, opened.header, opened.data);
            })
            .catch((error: unknown) => console.error("shell message:", error));
          break;
        }
        case "metrics": {
          const session = sessionRef.current;
          if (viewing !== payload.deviceId || session === null) break;
          metricsChainRef.current = metricsChainRef.current
            .then(() => session.openMetrics(payload.sealed))
            .then((opened) => {
              if (opened === null || sessionRef.current !== session) return;
              metricsManagerRef.current?.handle(opened.op, opened.header, opened.data);
            })
            .catch((error: unknown) => console.error("metrics message:", error));
          break;
        }
        case "audio": {
          const session = sessionRef.current;
          if (viewing !== payload.deviceId || session === null) break;
          audioChainRef.current = audioChainRef.current
            .then(() => session.openAudio(payload.sealed))
            .then((opened) => {
              if (opened === null || sessionRef.current !== session) return;
              const state = parseAudioDevices(opened.header);
              if (state !== null) setAudioDevices(state);
            })
            .catch((error: unknown) => console.error("audio devices:", error));
          break;
        }
        case "config": {
          const session = sessionRef.current;
          if (viewing !== payload.deviceId || session === null) break;
          configChainRef.current = configChainRef.current
            .then(() => session.openConfig(payload.sealed))
            .then((opened) => {
              if (opened === null || sessionRef.current !== session) return;
              const state = parseConfig(opened.header);
              if (state !== null) setConfig(state);
            })
            .catch((error: unknown) => console.error("config:", error));
          break;
        }
        case "quality":
          if (viewing === payload.deviceId) setStreamQuality(parseQuality(payload));
          break;
        case "sas": {
          const session = sessionRef.current;
          if (viewing !== payload.deviceId || session === null) break;
          replyChainRef.current = replyChainRef.current
            .then(() => session.openSas(payload.sealed))
            .then((opened) => {
              if (opened === null || sessionRef.current !== session) return;
              sasIdRef.current += 1;
              setSasResult({ id: sasIdRef.current, ...opened });
            })
            .catch((error: unknown) => console.error("Ctrl+Alt+Del answer:", error));
          break;
        }
        case "pong":
          if (viewing === payload.deviceId) pingRef.current.answer(payload.nonce, performance.now());
          break;
        case "elevation":
          if (viewing !== payload.deviceId) break;
          setElevated(payload.elevated);
          // The listing asked for when the view opened went nowhere.
          if (payload.elevated && filesEnabledRef.current) fileManagerRef.current?.list();
          break;
        case "view_rejected":
          if (viewing === payload.deviceId) {
            const machine = machinesRef.current.find((candidate) => candidate.id === payload.deviceId);
            blockedRef.current = machine === undefined ? "" : admissionKey(machine);
            streamingRef.current = null;
            dropSession();
            teardownDecoder();
            setSecurity({ kind: "rejected", reason: payload.reason });
          }
          break;
      }
    },
    [clearView, fileSender, imageSender, metricsSender, requestStream, send, shellSender, teardownDecoder],
  );

  // Owned machines not vouched for yet: if this browser made the code a
  // machine enrolled with, check its key against the code and endorse it.
  useEffect(() => {
    for (const machine of machines) {
      if (machine.role !== "owner" || machine.endorsement !== null || machine.enrollCodeHash === null) continue;
      if (checkedEnrollmentsRef.current.has(machine.id)) continue;
      checkedEnrollmentsRef.current.add(machine.id);
      checkEnrollment(identity, machine).then(
        (result) => setEnrollmentChecks((prev) => ({ ...prev, [machine.id]: result })),
        (error: unknown) => {
          console.error("checking enrollment:", error);
          checkedEnrollmentsRef.current.delete(machine.id);
        },
      );
    }
  }, [identity, machines]);

  useEffect(() => {
    let disposed = false;
    let attempt = 0;
    let timer: number | undefined;

    const connect = (): void => {
      const socket = new WebSocket(socketUrl("/v1/dashboard"), socketProtocols());
      socket.binaryType = "arraybuffer";
      socketRef.current = socket;
      setStatus("connecting");
      setRetryAt(null);

      socket.addEventListener("open", () => setStatus("open"));
      socket.addEventListener("close", () => {
        if (socketRef.current === socket) socketRef.current = null;
        if (disposed) return; // our own teardown
        streamingRef.current = null;
        dropSession();
        teardownDecoder();
        scheduleReconnect();
      });
      socket.addEventListener("message", (event: MessageEvent) => {
        if (event.data instanceof ArrayBuffer) {
          handleFrame(event.data);
          return;
        }
        const payload = JSON.parse(event.data as string) as DashboardEvent;
        // A snapshot means the relay accepted us; start the backoff over.
        if (payload.type === "snapshot") attempt = 0;
        handleEvent(payload);
      });
    };

    const scheduleReconnect = (): void => {
      const delay = reconnectDelay(attempt);
      attempt += 1;
      setStatus("reconnecting");
      setRetryAt(Date.now() + delay);
      timer = window.setTimeout(() => void reconnect(), delay);
    };

    // Checks the session before opening a socket: a dead session ends the
    // dashboard, an unreachable relay just means trying again later.
    const reconnect = async (): Promise<void> => {
      timer = undefined;
      setStatus("connecting");
      setRetryAt(null);
      let session;
      try {
        session = await getSession();
      } catch {
        if (!disposed) scheduleReconnect();
        return;
      }
      if (disposed) return;
      if (session === null) {
        setStatus("closed");
        onSessionEndedRef.current();
        return;
      }
      connect();
    };

    reconnectNowRef.current = () => {
      if (timer === undefined) return; // connected, or an attempt is underway
      window.clearTimeout(timer);
      void reconnect();
    };
    const onOnline = (): void => reconnectNowRef.current();
    window.addEventListener("online", onOnline);

    // The caller has just confirmed the session, so the first socket opens
    // straight away.
    connect();

    return () => {
      disposed = true;
      window.clearTimeout(timer);
      window.removeEventListener("online", onOnline);
      reconnectNowRef.current = () => {};
      teardownDecoder();
      socketRef.current?.close();
      socketRef.current = null;
    };
  }, [handleEvent, handleFrame, teardownDecoder]);

  const startView = useCallback(
    (deviceId: string): void => {
      if (viewingRef.current === deviceId) return;
      if (streamingRef.current !== null) send({ type: "stop_view", deviceId: streamingRef.current });
      streamingRef.current = null;
      teardownDecoder();
      clearPicture();
      resetDecodeError();

      viewingRef.current = deviceId;
      resetTools(deviceId);
      audioPlayer().unlock(); // a click asked for this view: sound may start
      blockedRef.current = null; // asked for by hand: try again
      setViewingId(deviceId);
      requestStream(deviceId); // while disconnected, the snapshot resumes it
    },
    [audioPlayer, clearPicture, requestStream, resetDecodeError, resetTools, send, teardownDecoder],
  );

  const setMuted = useCallback(
    (muted: boolean): void => {
      try {
        window.localStorage.setItem(MUTED_KEY, muted ? "1" : "0");
      } catch {
        // Not remembered, then; it still applies now.
      }
      audioPlayer().setMuted(muted);
    },
    [audioPlayer],
  );
  const unlockSound = useCallback((): void => audioPlayer().unlock(), [audioPlayer]);
  const setSync = useCallback(
    (next: boolean): void => {
      try {
        window.localStorage.setItem(SYNC_KEY, next ? "1" : "0");
      } catch {
        // Not remembered, then; it still applies now.
      }
      syncRef.current = next;
      setSyncState(next);
      const mode: SoundMode = next ? "sync" : "latency";
      audioPlayer().setMode(mode);
    },
    [audioPlayer],
  );
  const setStatsShown = useCallback((next: boolean): void => {
    try {
      window.localStorage.setItem(STATS_KEY, next ? "1" : "0");
    } catch {
      // Not remembered, then; it still applies now.
    }
    statsShownRef.current = next;
    setStatsShownState(next);
  }, []);
  const setStatsVisible = useCallback((visible: boolean): void => {
    statsVisibleRef.current = visible;
  }, []);

  useEffect(() => {
    if (viewingId === null) {
      setStats(null);
      return;
    }
    framesRef.current = 0;
    bytesRef.current = 0;
    receivedRef.current = 0;
    decodedRef.current = 0;
    skippedRef.current = 0;
    lastFrameAtRef.current = 0;
    pingRef.current.reset();
    let last = performance.now();
    // Per decoder, since a new one starts counting from zero.
    let lastDecoder: StreamDecoder | null = null;
    let lastQuality: Quality | null = null;
    let lastDiscarded = 0;
    const timer = window.setInterval(() => {
      const now = performance.now();
      const seconds = (now - last) / 1000;
      last = now;
      const decoder = decoderRef.current;
      const sameDecoder = decoder === lastDecoder;
      lastDecoder = decoder;
      // The browser's own counts where it keeps them (MSE), else the
      // frames drawn here (WebCodecs).
      const quality = decoder?.playbackQuality?.() ?? null;
      const delta = quality === null ? null : qualityDelta(sameDecoder ? lastQuality : null, quality);
      lastQuality = quality;
      const discarded = decoder?.discarded?.() ?? 0;
      const newlyDiscarded = sameDecoder ? Math.max(0, discarded - lastDiscarded) : discarded;
      lastDiscarded = discarded;
      const backend = backendRef.current === "webcodecs" || backendRef.current === "mse" ? backendRef.current : null;
      const audioMs = audioRef.current?.bufferedMs() ?? null;
      setStats(
        summarize({
          seconds,
          bytes: bytesRef.current,
          received: receivedRef.current,
          decoded: backend === "webcodecs" ? decodedRef.current : delta === null ? null : delta.shown + delta.dropped,
          shown: quality === null ? framesRef.current : (delta?.shown ?? 0),
          dropped: quality === null ? droppedRef.current : (delta?.dropped ?? 0),
          skipped: skippedRef.current + newlyDiscarded,
          pending: pendingFramesRef.current,
          queue: decoder?.queued?.() ?? null,
          decodeMs: decodeClockRef.current.takeMeanMs(),
          lagMs: decoder?.lagMs?.() ?? null,
          rttMs: pingRef.current.rttMs(now),
          audioMs: audioMs === null ? null : Math.round(audioMs),
          backend,
          receiving: now - lastFrameAtRef.current < STALL_MS,
          debug: DEBUG ? (decoder?.debugInfo?.() ?? null) : null,
        }),
      );
      framesRef.current = 0;
      droppedRef.current = 0;
      bytesRef.current = 0;
      receivedRef.current = 0;
      decodedRef.current = 0;
      skippedRef.current = 0;
      // Only while the overlay shows it, and to a machine that answers:
      // it echoes it straight back.
      const deviceId = streamingRef.current;
      const answers = machinesRef.current.some((machine) => machine.id === deviceId && machine.ping === true);
      if (
        statsShownRef.current &&
        statsVisibleRef.current &&
        answers &&
        deviceId !== null &&
        sessionRef.current?.accepted === true
      ) {
        send({ type: "ping", deviceId, nonce: pingRef.current.start(now) });
      }
    }, 1000);
    return () => window.clearInterval(timer);
  }, [send, viewingId]);

  const sendInput = useCallback(
    (event: InputEvent): void => {
      // Only once the machine has accepted this viewer with a role that
      // may control it: input to anything else goes nowhere.
      const deviceId = streamingRef.current;
      const session = sessionRef.current;
      if (deviceId === null || session === null || (session.role !== "owner" && session.role !== "control")) return;
      const sealed = session.sealInput(event);
      if (sealed === null) return;
      inputChainRef.current = inputChainRef.current
        .then(() => sealed)
        .then((payload) => {
          if (sessionRef.current === session) send({ type: "input", deviceId, sealed: payload });
        })
        .catch((error: unknown) => console.error("sealing input:", error));
    },
    [send],
  );

  const sendClipboard = useCallback(
    (text: string | null): boolean => {
      const deviceId = streamingRef.current;
      const session = sessionRef.current;
      if (deviceId === null || session === null || !session.accepted) return false;
      const sealed = session.sealClipboard(text);
      if (sealed === null) return false;
      if (text === null) {
        setClipboard((prev) => ({ ...prev, waiting: true }));
        // A large picture can take longer than that: wait while it comes.
        const settle = (): void => {
          if (sessionRef.current !== session) return;
          if (imageManagerRef.current?.receiving === true) window.setTimeout(settle, CLIPBOARD_WAIT_MS);
          else setClipboard((prev) => ({ ...prev, waiting: false }));
        };
        window.setTimeout(settle, CLIPBOARD_WAIT_MS);
      }
      // Through the input chain: both are numbered from one counter, so
      // they must reach the machine in the order they were sealed.
      inputChainRef.current = inputChainRef.current
        .then(() => sealed)
        .then((payload) => {
          if (sessionRef.current === session) send({ type: "clipboard", deviceId, sealed: payload });
        })
        .catch((error: unknown) => console.error("sealing clipboard:", error));
      return true;
    },
    [send],
  );

  const pasteImage = useCallback(
    (png: Uint8Array): Promise<PasteResult> => {
      const role = sessionRef.current?.role;
      if (role !== "owner" && role !== "control") {
        return Promise.resolve({ ok: false, message: "pasting needs control" });
      }
      return imageManager.paste(png);
    },
    [imageManager],
  );

  const fileActions = useRef<FileActions>({
    list: () => fileManagerRef.current?.list(),
    upload: (picked) => {
      for (const file of picked) fileManagerRef.current?.upload(file);
    },
    download: (file, sink) => fileManagerRef.current?.download(file, sink),
    cancel: (id) => fileManagerRef.current?.cancel(id),
    retry: (id) => fileManagerRef.current?.retry(id),
    dismiss: (id) => fileManagerRef.current?.dismiss(id),
  }).current;

  const shellActions = useRef<ShellActions>({
    open: (cols, rows) => shellManagerRef.current?.open(cols, rows) ?? null,
    input: (id, text) => shellManagerRef.current?.input(id, text),
    resize: (id, cols, rows) => shellManagerRef.current?.resize(id, cols, rows),
    close: (id) => shellManagerRef.current?.close(id),
    setSink: (id, sink) => shellManagerRef.current?.setSink(id, sink),
  }).current;

  const metricsActions = useRef<MetricsActions>({
    watch: (on) => metricsManagerRef.current?.watch(on),
    history: (range) => metricsManagerRef.current?.requestHistory(range),
    processes: () => metricsManagerRef.current?.requestProcesses(),
  }).current;

  const stopView = useCallback((): void => {
    if (viewingRef.current === null) return;
    if (streamingRef.current !== null) send({ type: "stop_view", deviceId: streamingRef.current });
    clearView();
  }, [clearView, send]);

  const reconnectNow = useCallback((): void => reconnectNowRef.current(), []);

  const elevate = useCallback((): void => {
    if (streamingRef.current !== null) send({ type: "elevate", deviceId: streamingRef.current });
  }, [send]);

  const installUpdate = useCallback(
    (deviceId: string): void => {
      send({ type: "install_update", deviceId });
    },
    [send],
  );

  const sendPower = useCallback(
    (action: PowerAction): boolean => {
      const deviceId = streamingRef.current;
      const session = sessionRef.current;
      if (deviceId === null || session === null || (session.role !== "owner" && session.role !== "control")) {
        return false;
      }
      const sealed = session.sealPower(action);
      if (sealed === null) return false;
      // Through the input chain: it's numbered from the same counter.
      inputChainRef.current = inputChainRef.current
        .then(() => sealed)
        .then((payload) => {
          if (sessionRef.current === session) send({ type: "power", deviceId, sealed: payload });
        })
        .catch((error: unknown) => console.error("sealing power action:", error));
      return true;
    },
    [send],
  );

  // Seals a request with `seal` and sends it as `type`, through the input
  // chain: it's numbered from the same counter.
  const sendSealed = useCallback(
    (
      type: "audio_devices" | "audio_select" | "config_get" | "config_set" | "quality" | "sas",
      seal: (session: ViewSession) => Promise<string> | null,
    ): boolean => {
      const deviceId = streamingRef.current;
      const session = sessionRef.current;
      if (deviceId === null || session === null) return false;
      const sealed = seal(session);
      if (sealed === null) return false;
      inputChainRef.current = inputChainRef.current
        .then(() => sealed)
        .then((payload) => {
          if (sessionRef.current === session) send({ type, deviceId, sealed: payload });
        })
        .catch((error: unknown) => console.error(`sealing ${type}:`, error));
      return true;
    },
    [send],
  );
  const requestAudioDevices = useCallback(
    (): boolean => sendSealed("audio_devices", (session) => session.sealAudioList()),
    [sendSealed],
  );
  const selectAudioDevice = useCallback(
    (id: string): boolean => {
      const role = sessionRef.current?.role;
      if (role !== "owner" && role !== "control") return false;
      return sendSealed("audio_select", (session) => session.sealAudioSelect(id));
    },
    [sendSealed],
  );
  const requestConfig = useCallback(
    (): boolean => sendSealed("config_get", (session) => session.sealConfigGet()),
    [sendSealed],
  );
  const setQuality = useCallback(
    (preset: QualityPreset): boolean => {
      const role = sessionRef.current?.role;
      if (role !== "owner" && role !== "control") return false;
      return sendSealed("quality", (session) => session.sealQuality(preset));
    },
    [sendSealed],
  );
  const sendSas = useCallback((): boolean => {
    const role = sessionRef.current?.role;
    if (role !== "owner" && role !== "control") return false;
    return sendSealed("sas", (session) => session.sealSas());
  }, [sendSealed]);
  const clearSasResult = useCallback((): void => setSasResult(null), []);
  const saveConfig = useCallback(
    (changes: Record<string, SettingValue>): boolean => {
      const version = configRef.current?.version;
      if (sessionRef.current?.role !== "owner" || version === undefined) return false;
      return sendSealed("config_set", (session) => session.sealConfigSet({ version, changes }));
    },
    [sendSealed],
  );

  return {
    machines,
    status,
    retryAt,
    viewingId,
    canvasRef,
    picture,
    stats,
    decodeError,
    security,
    clipboard,
    files,
    fileActions,
    shells,
    shellActions,
    metrics,
    metricsActions,
    enrollmentChecks,
    elevated,
    elevate,
    installUpdate,
    sendPower,
    audioDevices,
    requestAudioDevices,
    selectAudioDevice,
    config,
    requestConfig,
    saveConfig,
    startView,
    stopView,
    sendInput,
    sendClipboard,
    pasteImage,
    reconnectNow,
    sound,
    setMuted,
    unlockSound,
    streamQuality,
    setQuality,
    sendSas,
    sasResult,
    clearSasResult,
    sync,
    setSync,
    statsShown,
    setStatsShown,
    setStatsVisible,
  };
}
