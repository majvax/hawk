// The live view's stream stats: what arrived, what the decoder made of it,
// and how far away the machine is. Counted by useDashboard as frames go by,
// and turned into rates here once a second. Nothing here touches the DOM.

// How the picture is being decoded (useDashboard's Backend, once known).
export type StatsBackend = "webcodecs" | "mse";

export interface StreamStats {
  fps: number; // frames shown over the last second
  received: number; // frames that arrived over the last second
  dropped: number; // decoded but not shown over the last second
  debug: string | null; // the decoder's own readout, with ?debug in the URL
  kbps: number; // video received over the last second
  receiving: boolean; // frames are arriving
  backend: StatsBackend | null;
  // Frames out of the decoder over the last second; null where the
  // browser doesn't say (MSE without playback quality).
  decoded: number | null;
  // Frames thrown away before decoding over the last second: a backlog
  // waiting to be decrypted or appended, and the deltas after it until
  // the next keyframe.
  skipped: number;
  // Frames waiting to be decrypted, and waiting inside the decoder.
  pending: number;
  queue: number | null;
  // Mean time from handing a frame to the decoder to its picture (WebCodecs).
  decodeMs: number | null;
  // How far playback runs behind what's buffered (MSE).
  lagMs: number | null;
  // Round trip to the machine and back, through the relay; null without an
  // answer lately.
  rttMs: number | null;
  // Sound queued ahead of what's heard; null with no sound playing.
  audioMs: number | null;
}

// What useDashboard counted over one interval, and how things stand at
// its end.
export interface StatsSample {
  seconds: number;
  bytes: number; // encoded video bytes received
  received: number;
  decoded: number | null;
  shown: number;
  dropped: number;
  skipped: number;
  pending: number;
  queue: number | null;
  decodeMs: number | null;
  lagMs: number | null;
  rttMs: number | null;
  audioMs: number | null;
  backend: StatsBackend | null;
  receiving: boolean;
  debug: string | null;
}

export function perSecond(count: number, seconds: number): number {
  return Math.round(count / Math.max(0.001, seconds));
}

export function bitrateKbps(bytes: number, seconds: number): number {
  return Math.round((bytes * 8) / 1000 / Math.max(0.001, seconds));
}

export function summarize(sample: StatsSample): StreamStats {
  const { seconds } = sample;
  return {
    fps: perSecond(sample.shown, seconds),
    received: perSecond(sample.received, seconds),
    dropped: perSecond(sample.dropped, seconds),
    debug: sample.debug,
    kbps: bitrateKbps(sample.bytes, seconds),
    receiving: sample.receiving,
    backend: sample.backend,
    decoded: sample.decoded === null ? null : perSecond(sample.decoded, seconds),
    skipped: perSecond(sample.skipped, seconds),
    pending: sample.pending,
    queue: sample.queue,
    decodeMs: sample.decodeMs,
    lagMs: sample.lagMs,
    rttMs: sample.rttMs,
    audioMs: sample.audioMs,
  };
}

export interface Quality {
  shown: number;
  dropped: number;
}

// The browser's running counts (MSE's getVideoPlaybackQuality) as the
// change since the last reading; null for the first reading of a decoder,
// which counts from its own start.
export function qualityDelta(previous: Quality | null, current: Quality): Quality | null {
  if (previous === null) return null;
  return {
    shown: Math.max(0, current.shown - previous.shown),
    dropped: Math.max(0, current.dropped - previous.dropped),
  };
}

// Frames handed to the decoder but not out of it, by timestamp, past which
// the oldest are forgotten: the decoder dropped them, or was replaced.
const MAX_IN_FLIGHT = 120;

// Times each frame spends in the decoder, from decode() to its picture.
export class DecodeClock {
  private readonly started = new Map<number, number>();
  private totalMs = 0;
  private count = 0;

  submitted(timestamp: number, now: number): void {
    this.started.set(timestamp, now);
    if (this.started.size > MAX_IN_FLIGHT) {
      const oldest = this.started.keys().next().value;
      if (oldest !== undefined) this.started.delete(oldest);
    }
  }

  finished(timestamp: number, now: number): void {
    const at = this.started.get(timestamp);
    if (at === undefined) return;
    this.started.delete(timestamp);
    this.totalMs += now - at;
    this.count += 1;
  }

  // The mean since the last call, then starts over; null with nothing out.
  takeMeanMs(): number | null {
    const mean = this.count === 0 ? null : this.totalMs / this.count;
    this.totalMs = 0;
    this.count = 0;
    return mean;
  }

  clear(): void {
    this.started.clear();
    this.totalMs = 0;
    this.count = 0;
  }
}

// An answer later than this is a lost ping, and an RTT older than it is
// no longer shown.
export const PING_TIMEOUT_MS = 5000;

// Pings to the machine and their answers (ping / pong in protocol.ts).
export class PingTracker {
  private readonly sent = new Map<string, number>();
  private next = 0;
  private lastRttMs: number | null = null;
  private lastAnswerAt = 0;

  // A fresh nonce for a ping sent now.
  start(now: number): string {
    for (const [nonce, at] of this.sent) {
      if (now - at > PING_TIMEOUT_MS) this.sent.delete(nonce);
    }
    this.next += 1;
    const nonce = String(this.next);
    this.sent.set(nonce, now);
    return nonce;
  }

  // The round trip for a pong, or null for one not asked for (or too late).
  answer(nonce: string, now: number): number | null {
    const at = this.sent.get(nonce);
    if (at === undefined) return null;
    this.sent.delete(nonce);
    if (now - at > PING_TIMEOUT_MS) return null;
    this.lastRttMs = now - at;
    this.lastAnswerAt = now;
    return this.lastRttMs;
  }

  // The latest round trip, while it's recent.
  rttMs(now: number): number | null {
    return now - this.lastAnswerAt > PING_TIMEOUT_MS ? null : this.lastRttMs;
  }

  reset(): void {
    this.sent.clear();
    this.lastRttMs = null;
    this.lastAnswerAt = 0;
  }
}
