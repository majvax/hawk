// Mirrors relay/src/protocol.rs. Kept as a plain duplicate rather than a
// shared package since the frontend only ever reads these shapes.

// Bumped with relay/src/protocol.rs PROTOCOL_VERSION when a message changes
// in a way the other side can't follow.
export const PROTOCOL_VERSION = 9;

// What a user may do with a machine. Not a ladder: dev gets a shell and
// files, but neither the screen nor input.
export type Role = "view" | "control" | "dev" | "owner";

// Watches the screen.
export function canView(role: Role): boolean {
  return role !== "dev";
}

// Sends mouse and keyboard input.
export function canControl(role: Role): boolean {
  return role === "control" || role === "owner";
}

// Sends files to the machine and downloads from it.
export function canFiles(role: Role): boolean {
  return role !== "view";
}

// Opens shells on the machine.
export function canShell(role: Role): boolean {
  return role === "dev" || role === "owner";
}

// What the machine's config lets a viewer do with its clipboard: nothing,
// read it when asked (and paste into it, with control), or also have every
// copy made on the machine pushed to them.
export type ClipboardAccess = "off" | "pull" | "sync";

// The most clipboard text sent either way, in UTF-8 bytes.
export const MAX_CLIPBOARD_BYTES = 256 * 1024;

// The most a clipboard picture may be either way: PNG bytes, the longest
// side and the pixels in all (8K). Must match max_clipboard_image_* in
// src/common/clipboard_pipe.hpp. Larger ones are skipped, never cut.
export const MAX_CLIPBOARD_IMAGE_BYTES = 8 * 1024 * 1024;
export const MAX_CLIPBOARD_IMAGE_SIDE = 16384;
export const MAX_CLIPBOARD_IMAGE_PIXELS = 7680 * 4320;

// A machine as the logged-in user sees it.
export interface Machine {
  id: string;
  name: string;
  hostname: string;
  ownerEmail: string;
  role: Role;
  online: boolean;
  connectedAt: string | null; // RFC 3339, while online
  lastSeenAt: number | null; // unix seconds
  keyStorage: "tpm" | "software" | null; // null: must be re-enrolled
  accessExpiresAt: number | null; // unix seconds; when a temporary share ends
  singleView: boolean; // the share is used up by one viewing
  // May read the machine's analytics: always for the owner, for a share
  // only if its owner allowed it. The machine checks the signed grant.
  analytics?: boolean;
  viewers: string[] | null; // who's watching; owner only
  // Base64 keys: the machine's and its owner's identity key; null for a
  // machine that must be re-enrolled.
  publicKey: string | null;
  ownerPublicKey: string | null;
  // The owner's signature over the machine's key, once they've checked it.
  endorsement: string | null;
  // Owner only, until endorsed: which enrollment code the machine used and
  // the HMAC of its key under that code, for the browser that made the code.
  enrollCodeHash: string | null;
  enrollBinding: string | null;
  // Whether the owner has signed a grant for this user (always for the owner).
  granted: boolean;
  // Owner only, while online: the service's release, and a newer one its
  // updater is holding until the owner says to install it.
  version?: string | null;
  updateAvailable?: string | null;
  // The machine said it's restarting and isn't back yet.
  restarting?: boolean;
  // While online: the machine takes power actions, and this user's role
  // may ask for them.
  power?: boolean;
  // While online: the machine lists its output devices (and lets control
  // choose one).
  audioDevices?: boolean;
  // While online: the machine answers pings (the stats' round trip).
  ping?: boolean;
  // While online: the machine shows its config to this user's role
  // (control or owner), and lets the owner change it.
  config?: boolean;
  // While online: the machine takes a quality preset from this user's role
  // (control or owner).
  quality?: boolean;
  // While online: the machine presses Ctrl+Alt+Del for this user's role
  // (control or owner).
  sas?: boolean;
}

// What a viewer with control can ask the machine to do with itself.
export type PowerAction = "lock" | "sign_out" | "restart" | "shut_down";

export type DashboardEvent =
  | { type: "snapshot"; machines: Machine[] }
  | { type: "machine_updated"; machine: Machine }
  | { type: "machine_removed"; id: string }
  | { type: "capture_ended"; deviceId: string }
  // The machine's signed answer to this dashboard's join, and the stream
  // key wrapped for it (see e2e.ts).
  | {
      type: "view_accepted";
      deviceId: string;
      statement: string;
      signature: string;
      wrappedKey: string;
      clipboard?: ClipboardAccess;
      // Whether this viewer may send and fetch files.
      files?: boolean;
      // Whether it may open shells.
      shell?: boolean;
      // Whether it may read the machine's analytics.
      analytics?: boolean;
      // Whether pictures go with its clipboard (clipboardImages.ts); absent
      // from a machine or relay that predates them.
      clipboardImages?: boolean;
    }
  | { type: "view_rejected"; deviceId: string; reason: string }
  // Whether the relay passes on this view's input, files and shells. False
  // until the session has proved a second factor lately (see useStepUp).
  | { type: "elevation"; deviceId: string; elevated: boolean }
  | { type: "stream_key"; deviceId: string; wrappedKey: string }
  // Clipboard text the machine sealed for this viewer (ViewSession.openClipboard).
  | { type: "clipboard"; deviceId: string; sealed: string }
  // An image-channel message the machine sealed for this viewer
  // (ViewSession.openClipboardImage): a chunk of a picture, or how a paste went.
  | { type: "clipboard_image"; deviceId: string; sealed: string }
  // How a paste of a picture went (progress, done, error), or word of one too
  // large to send: sealed on the reply key (ViewSession.openClipboardImageReply)
  // and passed with the events, so never dropped.
  | { type: "clipboard_image_reply"; deviceId: string; sealed: string }
  // A file-channel message the machine sealed for this viewer (ViewSession.openFile).
  | { type: "file"; deviceId: string; sealed: string }
  // A shell-channel message the machine sealed for this viewer (ViewSession.openShell).
  | { type: "shell"; deviceId: string; sealed: string }
  // A metrics-channel message the machine sealed for this viewer (ViewSession.openMetrics).
  | { type: "metrics"; deviceId: string; sealed: string }
  // The machine's output devices, sealed for this viewer (ViewSession.openAudio).
  | { type: "audio"; deviceId: string; sealed: string }
  // The machine's config and schema, sealed for this viewer (ViewSession.openConfig).
  | { type: "config"; deviceId: string; sealed: string }
  // The machine's echo of a ping, for the round trip in the stream stats.
  | { type: "pong"; deviceId: string; nonce: string }
  // What the stream is encoded at: on starting to watch, and on every
  // change (a preset chosen, Auto's next step). See quality.ts.
  | { type: "quality"; deviceId: string; preset: string; bitrate: number; fps: number }
  // Whether the machine pressed this viewer's Ctrl+Alt+Del, sealed for it
  // (ViewSession.openSas).
  | { type: "sas"; deviceId: string; sealed: string };

export type MouseButton = "left" | "right" | "middle";

// One input event on its way to a machine. Positions are a fraction of the
// captured screen, 0..=1 from its top-left corner, so neither side needs the
// other's resolution. Keys are named by `KeyboardEvent.code` — the physical
// key, which the machine then reads through its own keyboard layout.
export type InputEvent =
  | { kind: "mouse_move"; x: number; y: number }
  | { kind: "mouse_button"; button: MouseButton; down: boolean }
  // In WHEEL_DELTA units (120 per notch); positive is up / right.
  | { kind: "wheel"; dx: number; dy: number }
  | { kind: "key"; code: string; down: boolean };

// What Windows counts as one notch of the wheel.
export const WHEEL_DELTA = 120;

// Only acted on while watching the machine with a control (or owner) role;
// the relay drops anything else without a word.
export type DashboardCommand =
  | { type: "start_view"; deviceId: string; join: { statement: string; signature: string } }
  | { type: "stop_view"; deviceId: string }
  // Asks for input, files and shells on this view once the session has
  // stepped up; answered with an elevation event.
  | { type: "elevate"; deviceId: string }
  // Sealed for the machine (ViewSession.sealInput); the relay can't read it.
  | { type: "input"; deviceId: string; sealed: string }
  // A clipboard request, sealed the same way (ViewSession.sealClipboard).
  // Passed on for any role; the machine decides what its config allows.
  | { type: "clipboard"; deviceId: string; sealed: string }
  // An image-channel request (ViewSession.sealClipboardImage): hello, ack,
  // cancel. Passed on for any role, as clipboard requests are.
  | { type: "clipboard_image"; deviceId: string; sealed: string }
  // A chunk of a picture to paste (ViewSession.sealClipboardImagePut);
  // control and owner.
  | { type: "clipboard_image_put"; deviceId: string; sealed: string }
  // A file-channel message (ViewSession.sealFile); control, dev and owner.
  | { type: "file"; deviceId: string; sealed: string }
  // A shell-channel message (ViewSession.sealShell); dev and owner.
  | { type: "shell"; deviceId: string; sealed: string }
  // A metrics request (ViewSession.sealMetrics); owner, and shares with analytics.
  | { type: "metrics"; deviceId: string; sealed: string }
  // A power action (ViewSession.sealPower); control and owner, elevated.
  | { type: "power"; deviceId: string; sealed: string }
  // Asks for the output devices (ViewSession.sealAudioList); anyone watching.
  | { type: "audio_devices"; deviceId: string; sealed: string }
  // Chooses one (ViewSession.sealAudioSelect); control and owner, elevated.
  | { type: "audio_select"; deviceId: string; sealed: string }
  // Asks for the config (ViewSession.sealConfigGet); control and owner.
  | { type: "config_get"; deviceId: string; sealed: string }
  // Changes it (ViewSession.sealConfigSet); the owner, elevated.
  | { type: "config_set"; deviceId: string; sealed: string }
  // Asks the machine to echo `nonce` back (a pong); anyone watching. Not
  // sealed: it carries nothing, and only times the round trip.
  | { type: "ping"; deviceId: string; nonce: string }
  // Picks the stream's quality preset (ViewSession.sealQuality); control and
  // owner, no fresh factor needed. Everyone watching shares the stream.
  | { type: "quality"; deviceId: string; sealed: string }
  // Presses Ctrl+Alt+Del on the machine (ViewSession.sealSas); control and
  // owner, elevated, as input is.
  | { type: "sas"; deviceId: string; sealed: string }
  // Owner only: install the update the machine is holding. The machine
  // checks the release's signature itself.
  | { type: "install_update"; deviceId: string };

// One H.264 access unit, once the frame carrying it has been decrypted
// (ViewSession.openFrame has the frame layout).
export interface ParsedVideoFrame {
  isKeyframe: boolean;
  // An Opus packet of the machine's sound, not video.
  isAudio: boolean;
  timestamp: number; // microseconds
  data: Uint8Array<ArrayBuffer>; // the H.264 access unit, or the Opus packet
}
