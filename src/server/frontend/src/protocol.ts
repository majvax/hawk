// Mirrors relay/src/protocol.rs. Kept as a plain duplicate rather than a
// shared package since the frontend only ever reads these shapes.

export type Role = "view" | "control" | "owner";

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
}

export type DashboardEvent =
  | { type: "snapshot"; machines: Machine[] }
  | { type: "machine_updated"; machine: Machine }
  | { type: "machine_removed"; id: string }
  | { type: "capture_ended"; deviceId: string };

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
  | { type: "start_view"; deviceId: string }
  | { type: "stop_view"; deviceId: string }
  | { type: "input"; deviceId: string; event: InputEvent };

// Binary video frame layout produced by src/service/main.cpp (BuildVideoFrame):
//   [0]     u8  kind (VIDEO_FRAME_KIND = H.264 Annex B)
//   [1]     u8  flags (bit 0 = keyframe)
//   [2..9]  i64 timestamp, microseconds, little-endian
//   [10..]      the H.264 access unit
export const VIDEO_FRAME_KIND = 0x01;
export const VIDEO_FRAME_KEYFRAME_FLAG = 0x01;
export const VIDEO_FRAME_HEADER_SIZE = 10;

export interface ParsedVideoFrame {
  isKeyframe: boolean;
  timestamp: number; // microseconds
  data: Uint8Array; // the H.264 access unit
}

// Returns null for anything that isn't a well-formed video frame.
export function parseVideoFrame(buffer: ArrayBuffer): ParsedVideoFrame | null {
  if (buffer.byteLength < VIDEO_FRAME_HEADER_SIZE) return null;
  const view = new DataView(buffer);
  if (view.getUint8(0) !== VIDEO_FRAME_KIND) return null;

  return {
    isKeyframe: (view.getUint8(1) & VIDEO_FRAME_KEYFRAME_FLAG) !== 0,
    timestamp: Number(view.getBigInt64(2, true)),
    data: new Uint8Array(buffer, VIDEO_FRAME_HEADER_SIZE),
  };
}
