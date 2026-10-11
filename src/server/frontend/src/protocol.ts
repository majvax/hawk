// Mirrors relay/src/protocol.rs. Kept as a plain duplicate rather than a
// shared package since the frontend only ever reads these shapes.

export type Role = "view" | "control" | "owner";

// What the machine's config lets a viewer do with its clipboard: nothing,
// read it when asked (and paste into it, with control), or also have every
// copy made on the machine pushed to them.
export type ClipboardAccess = "off" | "pull" | "sync";

// The most clipboard text sent either way, in UTF-8 bytes.
export const MAX_CLIPBOARD_BYTES = 256 * 1024;

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
}

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
    }
  | { type: "view_rejected"; deviceId: string; reason: string }
  | { type: "stream_key"; deviceId: string; wrappedKey: string }
  // Clipboard text the machine sealed for this viewer (ViewSession.openClipboard).
  | { type: "clipboard"; deviceId: string; sealed: string };

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
  // Sealed for the machine (ViewSession.sealInput); the relay can't read it.
  | { type: "input"; deviceId: string; sealed: string }
  // A clipboard request, sealed the same way (ViewSession.sealClipboard).
  // Passed on for any role; the machine decides what its config allows.
  | { type: "clipboard"; deviceId: string; sealed: string };

// One H.264 access unit, once the frame carrying it has been decrypted
// (ViewSession.openFrame has the frame layout).
export interface ParsedVideoFrame {
  isKeyframe: boolean;
  timestamp: number; // microseconds
  data: Uint8Array<ArrayBuffer>; // the H.264 access unit
}
