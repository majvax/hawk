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
  viewers: string[] | null; // who's watching; owner only
}

export type DashboardEvent =
  | { type: "snapshot"; machines: Machine[] }
  | { type: "machine_updated"; machine: Machine }
  | { type: "machine_removed"; id: string }
  | { type: "capture_ended"; deviceId: string };

export type DashboardCommand =
  | { type: "start_view"; deviceId: string }
  | { type: "stop_view"; deviceId: string };

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
