import { OPUS_SAMPLE_RATE, audioSegment, opusInitSegment } from "./fmp4.js";
import { BUFFERING, CLOCK_IDLE_S, type SoundMode } from "./soundMode.js";

// Plays the sound through Media Source Extensions: Opus packets muxed into
// fragmented MP4 and fed to an <audio> element. The fallback for browsers
// without a WebCodecs AudioDecoder (Firefox for Android), the same way
// MseDecoder is for the picture.
//
// Its own MediaSource, not a second track beside the video's: the machine
// sends nothing while it is quiet, and a silent audio track would stall the
// picture with it. Here a quiet spell only runs the audio buffer dry, and
// the next packet, appended right after the last, plays as it arrives.

const MIME = 'audio/mp4; codecs="opus"';

// Whether this browser can play Opus in fragmented MP4 through MSE.
export function mseSoundSupported(): boolean {
  return typeof MediaSource !== "undefined" && MediaSource.isTypeSupported(MIME);
}

// 20 ms packets, as the machine encodes them.
const PACKET_SAMPLES = OPUS_SAMPLE_RATE / 50;
const PACKET_S = PACKET_SAMPLES / OPUS_SAMPLE_RATE;
// Packets remembered for the clock: a few seconds, what the buffer keeps.
const MAX_ANCHORS = 200;
// Played sound older than this is dropped from the buffer.
const KEEP_BEHIND_S = 3;
// Packets waiting this long for the source buffer means appends can't keep
// up: the oldest go.
const MAX_PENDING = 50;

export class MseAudio {
  private readonly audio = new Audio();
  private readonly mediaSource = new MediaSource();
  private readonly url: string;
  private sourceBuffer: SourceBuffer | null = null;
  private readonly pending: Array<{ packet: Uint8Array; streamUs: number }> = [];
  // Where each appended packet starts on the media timeline, and its
  // machine timestamp; oldest first. Quiet spells vanish from the media
  // timeline, so every packet keeps its own.
  private readonly anchors: Array<{ mediaS: number; streamUs: number }> = [];
  private initialised = false;
  private sequence = 0;
  private decodeTime = 0;
  private closed = false;
  private blockedNow = false;

  constructor(
    muted: boolean,
    private mode: SoundMode,
    // Heard when `blocked` changes.
    private readonly onChange: () => void,
  ) {
    this.audio.muted = muted;
    this.url = URL.createObjectURL(this.mediaSource);
    this.mediaSource.addEventListener("sourceopen", () => this.pump(), { once: true });
    this.audio.src = this.url;
    this.play();
  }

  // The browser holds sound back until someone clicks the page.
  get blocked(): boolean {
    return this.blockedNow;
  }

  setMuted(muted: boolean): void {
    this.audio.muted = muted;
  }

  setMode(mode: SoundMode): void {
    this.mode = mode;
  }

  // The machine timestamp (µs) of what the element plays now, or null when
  // it isn't playing anything.
  audibleStreamUs(): number | null {
    const last = this.anchors.at(-1);
    if (this.closed || this.blockedNow || this.audio.paused || last === undefined) return null;
    const time = this.audio.currentTime;
    if (time > last.mediaS + PACKET_S + CLOCK_IDLE_S) return null;
    let anchor = this.anchors[0] ?? last;
    for (const candidate of this.anchors) {
      if (candidate.mediaS > time) break;
      anchor = candidate;
    }
    return anchor.streamUs + Math.min(time - anchor.mediaS, PACKET_S) * 1_000_000;
  }

  // Call from a click or a key, the only place browsers let sound start.
  unlock(): void {
    if (this.blockedNow || this.audio.paused) this.play();
  }

  push(packet: Uint8Array, streamUs: number): void {
    // Held back, it would only pile up; play() catches up when it's let go.
    if (this.closed || this.blockedNow) return;
    this.pending.push({ packet, streamUs });
    if (this.pending.length > MAX_PENDING) this.pending.splice(0, this.pending.length - MAX_PENDING);
    this.pump();
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.pending.length = 0;
    this.audio.removeAttribute("src");
    this.audio.load();
    URL.revokeObjectURL(this.url);
  }

  private play(): void {
    if (this.closed) return;
    this.audio.play().then(
      () => this.setBlocked(false),
      (error: unknown) => {
        if (error instanceof DOMException && error.name === "NotAllowedError") this.setBlocked(true);
      },
    );
  }

  private setBlocked(blocked: boolean): void {
    if (this.closed || this.blockedNow === blocked) return;
    this.blockedNow = blocked;
    this.onChange();
  }

  private fail(message: string): void {
    console.error("audio:", message);
    this.close();
  }

  // Appends what's waiting, all of it in one fragment, once the source
  // buffer is free.
  private pump(): void {
    if (this.closed || this.mediaSource.readyState !== "open") return;
    if (this.sourceBuffer === null) {
      try {
        this.sourceBuffer = this.mediaSource.addSourceBuffer(MIME);
      } catch (error) {
        this.fail(`can't play Opus: ${(error as Error).message}`);
        return;
      }
      this.sourceBuffer.addEventListener("updateend", () => {
        this.chaseLiveEdge();
        this.pump();
      });
      this.sourceBuffer.addEventListener("error", () => this.fail("source buffer error"));
    }

    const buffer = this.sourceBuffer;
    if (buffer.updating) return;

    // Drop what's been played, now and then, so the buffer stays small.
    const played = this.audio.currentTime - KEEP_BEHIND_S;
    if (buffer.buffered.length > 0 && buffer.buffered.start(0) < played - 1) {
      buffer.remove(0, played);
      return; // updateend pumps again
    }

    let segment: Uint8Array;
    if (!this.initialised) {
      segment = opusInitSegment(2);
      this.initialised = true;
    } else if (this.pending.length > 0) {
      const packets = this.pending.splice(0);
      this.sequence += 1;
      segment = audioSegment(this.sequence, this.decodeTime, PACKET_SAMPLES, packets.map((entry) => entry.packet));
      for (const [index, entry] of packets.entries()) {
        this.anchors.push({ mediaS: (this.decodeTime + index * PACKET_SAMPLES) / OPUS_SAMPLE_RATE, streamUs: entry.streamUs });
      }
      if (this.anchors.length > MAX_ANCHORS) this.anchors.splice(0, this.anchors.length - MAX_ANCHORS);
      this.decodeTime += PACKET_SAMPLES * packets.length;
    } else {
      return;
    }
    try {
      buffer.appendBuffer(segment as Uint8Array<ArrayBuffer>);
    } catch (error) {
      this.fail(`append failed: ${(error as Error).message}`);
    }
  }

  // Live sound, not a recording: further behind the newest packet than
  // the mode's cap, playback jumps forward to its cushion. Every Opus packet
  // decodes on its own, so a seek costs nothing but the skip.
  private chaseLiveEdge(): void {
    const buffered = this.audio.buffered;
    if (buffered.length === 0) return;
    const end = buffered.end(buffered.length - 1);
    const start = buffered.start(buffered.length - 1);
    const { cushionS, maxLatencyS } = BUFFERING[this.mode];
    if (end - this.audio.currentTime > maxLatencyS || this.audio.currentTime < start) {
      this.audio.currentTime = Math.max(start, end - cushionS);
    }
    if (this.audio.paused && !this.blockedNow) this.play();
  }
}
