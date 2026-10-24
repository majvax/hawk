import {
  TIMESCALE,
  codecString,
  findParameterSets,
  initSegment,
  mediaSegment,
  splitNalUnits,
  toAvcSample,
} from "./fmp4.js";
import type { ParsedVideoFrame } from "./protocol.js";

// Plays the stream through Media Source Extensions: each access unit is
// wrapped in an MP4 fragment and fed to a <video> shown under the canvas;
// `onPicture` hears about each new picture. The fallback for browsers without a
// WebCodecs H.264 decoder; it costs a little latency, which `chaseLiveEdge`
// keeps in check.

// Whether this browser can play H.264 in fragmented MP4 through MSE.
export function mseSupported(codec: string): boolean {
  return typeof MediaSource !== "undefined" && MediaSource.isTypeSupported(`video/mp4; codecs="${codec}"`);
}

// How far behind the newest frame playback aims to stay: enough slack that
// network jitter doesn't run the buffer dry, which stalls playback.
const TARGET_LATENCY_S = 0.15;
// Further behind than this, playback speeds up a little until it's back
// within the target. Seeking would get there at once, but a seek restarts
// decoding from the last keyframe and drops frames, so it is kept for when
// playback is far behind.
const CATCH_UP_LATENCY_S = 0.4;
const CATCH_UP_RATE = 1.1;
const SEEK_LATENCY_S = 3;
// Played video older than this is dropped from the buffer.
const KEEP_BEHIND_S = 3;
// A queue this long means appends can't keep up; start over at a keyframe.
const MAX_QUEUED = 60;
// The frame interval assumed until two timestamps give the real one.
const DEFAULT_DURATION_US = 16_667;
// Following the sound's clock (sync mode): the picture this far ahead of
// it slows down, this far behind speeds up, and settles back to normal
// speed within half of it. Further behind the live edge than the cap, the
// sound is ignored and the live edge chased as usual.
const SYNC_BAND_MS = 40;
const SYNC_SLOW_RATE = 0.95;
const SYNC_MAX_LATENCY_S = 1;
// Frames remembered for mapping playback back to machine time: a few
// seconds, what the buffer keeps.
const MAX_ANCHORS = 300;

export class MseDecoder {
  private readonly video: HTMLVideoElement;
  private readonly mediaSource = new MediaSource();
  private readonly url: string;
  private sourceBuffer: SourceBuffer | null = null;
  private codec: string | null = null;
  private sps: Uint8Array | null = null;
  // Segments waiting for the source buffer; an init segment names the
  // codec it starts.
  private readonly queue: Array<{ data: Uint8Array; codec?: string }> = [];
  private bufferCodec: string | null = null;
  private awaitingKeyframe = true;
  private sequence = 0;
  private decodeTime = 0;
  private lastTimestamp: number | null = null;
  private closed = false;
  private frameCallback: number | null = null;
  private animationFrame: number | null = null;
  private lastMediaTime = -1;

  private resizeObserver: ResizeObserver | null = null;
  // Where each frame starts on the media timeline, and its machine
  // timestamp; oldest first.
  private readonly anchors: Array<{ mediaS: number; streamUs: number }> = [];
  private skewMs: number | null = null;

  // Frames thrown away rather than appended (a backlog, and the deltas
  // after it until the next keyframe), for the stream stats.
  private discardedFrames = 0;

  // For the ?debug readout.
  private stalls = 0;
  private seeks = 0;
  private reordered = 0;
  private lastKeyframeAt: number | null = null;
  private keyframeInterval = 0;

  // The <video> is shown itself, laid exactly under `canvas`, which stays
  // on top (transparent) to take the viewer's input. Copying its pictures
  // onto the canvas instead isn't reliable: Firefox for Android decodes
  // into a hardware surface that drawImage reads back as black.
  constructor(
    canvas: HTMLCanvasElement,
    private readonly onPicture: (video: HTMLVideoElement) => void,
    private readonly onError: (message: string) => void,
    // The sound's clock to follow (AudioPlayer.audibleStreamUs), or null to
    // chase the live edge alone.
    private readonly syncClock: () => number | null = () => null,
  ) {
    const video = document.createElement("video");
    video.muted = true;
    video.playsInline = true;
    video.autoplay = true;
    video.disablePictureInPicture = true;
    video.setAttribute("aria-hidden", "true");
    Object.assign(video.style, {
      position: "absolute",
      pointerEvents: "none",
      objectFit: "fill",
      left: "0",
      top: "0",
      width: "0",
      height: "0",
    });
    canvas.before(video);
    // Follow the canvas's box: it is scaled to fit the stage, and pointer
    // positions are read off it, so the picture must sit exactly there.
    const place = (): void => {
      Object.assign(video.style, {
        left: `${canvas.offsetLeft}px`,
        top: `${canvas.offsetTop}px`,
        width: `${canvas.offsetWidth}px`,
        height: `${canvas.offsetHeight}px`,
      });
    };
    this.resizeObserver = new ResizeObserver(place);
    this.resizeObserver.observe(canvas);
    if (canvas.parentElement !== null) this.resizeObserver.observe(canvas.parentElement);
    place();
    video.addEventListener("error", () => this.fail(`video element: ${video.error?.message || "decode error"}`));
    video.addEventListener("waiting", () => (this.stalls += 1));
    this.video = video;

    this.url = URL.createObjectURL(this.mediaSource);
    this.mediaSource.addEventListener("sourceopen", () => this.pump(), { once: true });
    video.src = this.url;
    this.watchPictures();
  }

  decode(frame: ParsedVideoFrame): void {
    if (this.closed) return;
    if (this.awaitingKeyframe && !frame.isKeyframe) {
      if (this.lastTimestamp !== null) this.discardedFrames += 1; // after a backlog, not the stream's start
      return;
    }

    const units = splitNalUnits(frame.data);
    if (frame.isKeyframe) {
      const sets = findParameterSets(units);
      if (sets === null) {
        if (this.sps === null) return; // nothing to start decoding from yet
      } else if (!sameBytes(sets.sps, this.sps)) {
        // First keyframe, or the picture changed (resolution switch): the
        // track needs a fresh init segment.
        this.sps = sets.sps.slice();
        this.codec = codecString(sets.sps);
        this.queue.push({ data: initSegment({ sps: sets.sps, pps: sets.pps }), codec: this.codec });
      }
      this.awaitingKeyframe = false;
    }

    // A frame lasts until the next one; the gap to the previous one is the
    // best guess at that, and it follows the host's real frame rate.
    let duration = DEFAULT_DURATION_US;
    if (this.lastTimestamp !== null && frame.timestamp < this.lastTimestamp) this.reordered += 1;
    if (frame.isKeyframe) {
      if (this.lastKeyframeAt !== null) this.keyframeInterval = frame.timestamp - this.lastKeyframeAt;
      this.lastKeyframeAt = frame.timestamp;
    }
    if (this.lastTimestamp !== null) {
      const gap = frame.timestamp - this.lastTimestamp;
      if (gap > 0 && gap < 1_000_000) duration = gap;
    }
    this.lastTimestamp = frame.timestamp;

    this.anchors.push({ mediaS: this.decodeTime / TIMESCALE, streamUs: frame.timestamp });
    if (this.anchors.length > MAX_ANCHORS) this.anchors.shift();
    this.sequence += 1;
    this.queue.push({
      data: mediaSegment(this.sequence, this.decodeTime, duration, frame.isKeyframe, toAvcSample(units)),
    });
    this.decodeTime += duration;

    if (this.queue.length > MAX_QUEUED) {
      // An init segment may have gone with the rest, so forget the SPS and
      // let the next keyframe send one again.
      this.discardedFrames += this.queue.filter((segment) => segment.codec === undefined).length;
      this.queue.length = 0;
      this.sps = null;
      this.awaitingKeyframe = true;
      return;
    }
    this.pump();
  }

  // Frames shown and frames decoded but thrown away, so far, as the browser
  // counts them. More accurate than counting onPicture calls: Firefox
  // composites video off the main thread, so the page can hear about fewer
  // frames than are actually shown.
  playbackQuality(): { shown: number; dropped: number } | null {
    const quality = this.video.getVideoPlaybackQuality?.();
    if (quality === undefined) return null;
    return { shown: quality.totalVideoFrames - quality.droppedVideoFrames, dropped: quality.droppedVideoFrames };
  }

  // Frames thrown away so far, rather than played.
  discarded(): number {
    return this.discardedFrames;
  }

  // Segments waiting for the source buffer.
  queued(): number {
    return this.queue.length;
  }

  // How far playback runs behind the newest buffered frame, in ms.
  lagMs(): number | null {
    const buffered = this.video.buffered;
    if (buffered.length === 0) return null;
    return Math.max(0, (buffered.end(buffered.length - 1) - this.video.currentTime) * 1000);
  }

  // A one-line account of how playback is going, for ?debug.
  debugInfo(): string {
    const buffered = this.video.buffered;
    const latency = buffered.length > 0 ? buffered.end(buffered.length - 1) - this.video.currentTime : 0;
    return [
      `lag ${Math.round(latency * 1000)}ms`,
      `x${this.video.playbackRate}`,
      `stalls ${this.stalls}`,
      `seeks ${this.seeks}`,
      `reordered ${this.reordered}`,
      `gop ${(this.keyframeInterval / 1_000_000).toFixed(1)}s`,
      ...(this.skewMs === null ? [] : [`a/v ${this.skewMs >= 0 ? "+" : ""}${Math.round(this.skewMs)}ms`]),
    ].join(" · ");
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.queue.length = 0;
    this.resizeObserver?.disconnect();
    if (this.frameCallback !== null) this.video.cancelVideoFrameCallback(this.frameCallback);
    if (this.animationFrame !== null) cancelAnimationFrame(this.animationFrame);
    this.video.removeAttribute("src");
    this.video.load();
    this.video.remove();
    URL.revokeObjectURL(this.url);
  }

  private fail(message: string): void {
    if (this.closed) return;
    this.close();
    this.onError(message);
  }

  // Appends the next queued segment once the source buffer is free.
  private pump(): void {
    if (this.closed || this.mediaSource.readyState !== "open") return;
    if (this.sourceBuffer === null) {
      if (this.codec === null) return; // waiting for the first keyframe
      try {
        this.sourceBuffer = this.mediaSource.addSourceBuffer(`video/mp4; codecs="${this.codec}"`);
        this.bufferCodec = this.codec;
      } catch (error) {
        this.fail(`can't play ${this.codec}: ${(error as Error).message}`);
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
    const played = this.video.currentTime - KEEP_BEHIND_S;
    if (buffer.buffered.length > 0 && buffer.buffered.start(0) < played - 1) {
      buffer.remove(0, played);
      return; // updateend pumps again
    }

    const next = this.queue.shift();
    if (next === undefined) return;
    try {
      // A new profile or level after a resolution switch.
      if (next.codec !== undefined && next.codec !== this.bufferCodec && typeof buffer.changeType === "function") {
        buffer.changeType(`video/mp4; codecs="${next.codec}"`);
        this.bufferCodec = next.codec;
      }
      buffer.appendBuffer(next.data as Uint8Array<ArrayBuffer>);
    } catch (error) {
      this.fail(`append failed: ${(error as Error).message}`);
    }
  }

  // Live video, not a recording: never fall more than a moment behind.
  private chaseLiveEdge(): void {
    const buffered = this.video.buffered;
    if (buffered.length === 0) return;
    const end = buffered.end(buffered.length - 1);
    const latency = end - this.video.currentTime;
    if (latency > SEEK_LATENCY_S || this.video.currentTime < buffered.start(0)) {
      this.video.currentTime = Math.max(buffered.start(buffered.length - 1), end - TARGET_LATENCY_S);
      this.seeks += 1;
    }
    const rate = this.syncRate(latency) ?? this.liveEdgeRate(latency);
    if (this.video.playbackRate !== rate) this.video.playbackRate = rate;
    if (this.video.paused) void this.video.play().catch(() => {});
  }

  // Speed up while behind, back to normal once within the target. The
  // band between the two keeps it from flapping on every frame.
  private liveEdgeRate(latency: number): number {
    return latency > CATCH_UP_LATENCY_S ? CATCH_UP_RATE : latency <= TARGET_LATENCY_S ? 1 : this.video.playbackRate;
  }

  // In sync mode, with sound playing: steer the picture toward the sound's
  // clock instead. Null when there is nothing to follow.
  private syncRate(latency: number): number | null {
    const clock = this.syncClock();
    const shown = this.shownStreamUs();
    if (clock === null || shown === null || latency > SYNC_MAX_LATENCY_S) {
      this.skewMs = null;
      return null;
    }
    const skew = (shown - clock) / 1000; // ms; positive is the picture ahead
    this.skewMs = skew;
    if (skew > SYNC_BAND_MS) return SYNC_SLOW_RATE;
    // Only while there's buffer to spend: speeding up an empty one stalls.
    if (skew < -SYNC_BAND_MS && latency > TARGET_LATENCY_S) return CATCH_UP_RATE;
    if (Math.abs(skew) <= SYNC_BAND_MS / 2) return 1;
    return this.video.playbackRate;
  }

  // The machine timestamp (µs) of the picture on screen now.
  private shownStreamUs(): number | null {
    const time = this.video.currentTime;
    let anchor: { mediaS: number; streamUs: number } | undefined;
    for (const candidate of this.anchors) {
      if (candidate.mediaS > time) break;
      anchor = candidate;
    }
    return anchor === undefined ? null : anchor.streamUs + (time - anchor.mediaS) * 1_000_000;
  }

  // Hands every new picture to onPicture: on each presented frame where the
  // browser reports them, otherwise whenever the playback position moves.
  private watchPictures(): void {
    const video = this.video;
    if (typeof video.requestVideoFrameCallback === "function") {
      const onFrame = (): void => {
        if (this.closed) return;
        this.onPicture(video);
        this.frameCallback = video.requestVideoFrameCallback(onFrame);
      };
      this.frameCallback = video.requestVideoFrameCallback(onFrame);
      return;
    }
    const onAnimationFrame = (): void => {
      if (this.closed) return;
      if (video.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA && video.currentTime !== this.lastMediaTime) {
        this.lastMediaTime = video.currentTime;
        this.onPicture(video);
      }
      this.animationFrame = requestAnimationFrame(onAnimationFrame);
    };
    this.animationFrame = requestAnimationFrame(onAnimationFrame);
  }
}

function sameBytes(a: Uint8Array, b: Uint8Array | null): boolean {
  if (b === null || a.length !== b.length) return false;
  return a.every((byte, i) => byte === b[i]);
}
