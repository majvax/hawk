// Plays the machine's sound: Opus packets (48 kHz stereo, 20 ms) that
// arrive sealed in the same stream as the picture, decoded with WebCodecs
// and scheduled back to back on a WebAudio clock. Without a WebCodecs
// AudioDecoder (Firefox for Android) it goes through MSE instead (MseAudio).
//
// It favours latency: a packet plays as soon as a small cushion allows, and
// if the queue grows past MAX_LATENCY_S (a stall, a tab in the background)
// the late ones are dropped to catch up. Silence on the machine sends
// nothing, so a gap simply starts the next sound afresh.

import { MseAudio, mseSoundSupported } from "./mseAudio.js";
import type { ParsedVideoFrame } from "./protocol.js";

export interface SoundState {
  // This browser can decode and play the sound.
  supported: boolean;
  // The browser holds sound back until someone clicks the page.
  blocked: boolean;
  muted: boolean;
}

const SAMPLE_RATE = 48_000;
const CHANNELS = 2;
// Held before the first packet after a gap, to absorb network jitter.
const CUSHION_S = 0.08;
// Queued further ahead than this, packets are dropped until it's caught up.
const MAX_LATENCY_S = 0.4;

type SoundBackend = "webcodecs" | "mse" | "none";

function soundBackend(): SoundBackend {
  if (typeof AudioDecoder !== "undefined" && typeof AudioContext !== "undefined") return "webcodecs";
  return mseSoundSupported() ? "mse" : "none";
}

export function soundSupported(): boolean {
  return soundBackend() !== "none";
}

export class AudioPlayer {
  private context: AudioContext | null = null;
  private gain: GainNode | null = null;
  private decoder: AudioDecoder | null = null;
  // When the next packet starts, on the context's clock.
  private nextTime = 0;
  private muted = false;
  private readonly backend = soundBackend();
  private readonly supported = this.backend !== "none";
  // The MSE path, in place of the context and decoder above.
  private mse: MseAudio | null = null;

  constructor(private readonly onChange: (state: SoundState) => void) {}

  get state(): SoundState {
    const blocked = this.backend === "mse" ? (this.mse?.blocked ?? false) : this.context?.state === "suspended";
    return { supported: this.supported, blocked, muted: this.muted };
  }

  // Lets the sound start. Browsers only allow that from a click or a key,
  // so call it from one.
  unlock(): void {
    if (this.backend === "mse") {
      this.mse?.unlock();
      return;
    }
    const context = this.ensureContext();
    if (context?.state === "suspended") void context.resume().then(() => this.publish(), () => {});
  }

  setMuted(muted: boolean): void {
    this.muted = muted;
    if (this.gain !== null) this.gain.gain.value = muted ? 0 : 1;
    this.mse?.setMuted(muted);
    if (!muted) this.unlock();
    this.publish();
  }

  // One packet, as it came off the stream.
  play(frame: ParsedVideoFrame): void {
    if (!this.supported) return;
    if (this.backend === "mse") {
      this.mse ??= new MseAudio(this.muted, () => this.publish());
      this.mse.push(frame.data);
      return;
    }
    const context = this.ensureContext();
    const decoder = this.ensureDecoder();
    if (context === null || decoder === null) return;
    try {
      decoder.decode(new EncodedAudioChunk({ type: "key", timestamp: frame.timestamp, data: frame.data }));
    } catch (error) {
      console.error("audio:", error);
      this.resetDecoder();
    }
  }

  // A new stream (another machine, or the same one starting over): drop
  // whatever is queued from the last one.
  reset(): void {
    this.resetDecoder();
    this.nextTime = 0;
    this.closeMse();
  }

  close(): void {
    this.resetDecoder();
    this.closeMse();
    void this.context?.close().catch(() => {});
    this.context = null;
    this.gain = null;
  }

  private publish(): void {
    this.onChange(this.state);
  }

  private closeMse(): void {
    if (this.mse === null) return;
    this.mse.close();
    this.mse = null;
    this.publish();
  }

  private ensureContext(): AudioContext | null {
    if (this.backend !== "webcodecs") return null;
    if (this.context === null) {
      try {
        this.context = new AudioContext({ sampleRate: SAMPLE_RATE, latencyHint: "interactive" });
      } catch {
        this.context = new AudioContext({ latencyHint: "interactive" });
      }
      this.gain = this.context.createGain();
      this.gain.gain.value = this.muted ? 0 : 1;
      this.gain.connect(this.context.destination);
      this.context.addEventListener("statechange", () => this.publish());
      this.publish();
    }
    return this.context;
  }

  private ensureDecoder(): AudioDecoder | null {
    if (this.decoder !== null && this.decoder.state !== "closed") return this.decoder;
    try {
      const decoder = new AudioDecoder({
        output: (data) => this.schedule(data),
        error: (error) => {
          console.error("audio decoder:", error);
          this.decoder = null; // a fresh one next packet
        },
      });
      decoder.configure({ codec: "opus", sampleRate: SAMPLE_RATE, numberOfChannels: CHANNELS });
      this.decoder = decoder;
    } catch (error) {
      console.error("audio decoder:", error);
      this.decoder = null;
    }
    return this.decoder;
  }

  private resetDecoder(): void {
    const decoder = this.decoder;
    this.decoder = null;
    if (decoder !== null && decoder.state !== "closed") decoder.close();
  }

  private schedule(data: AudioData): void {
    const context = this.context;
    const gain = this.gain;
    if (context === null || gain === null || context.state !== "running") {
      data.close();
      return;
    }
    const buffer = context.createBuffer(data.numberOfChannels, data.numberOfFrames, data.sampleRate);
    for (let channel = 0; channel < data.numberOfChannels; channel += 1) {
      const plane = new Float32Array(data.numberOfFrames);
      data.copyTo(plane, { planeIndex: channel, format: "f32-planar" });
      buffer.copyToChannel(plane, channel);
    }
    data.close();

    const now = context.currentTime;
    if (this.nextTime < now) {
      this.nextTime = now + CUSHION_S; // after a gap, or running late: start afresh
    } else if (this.nextTime - now > MAX_LATENCY_S) {
      return; // fallen behind: skip this one to catch up
    }
    const source = context.createBufferSource();
    source.buffer = buffer;
    source.connect(gain);
    source.start(this.nextTime);
    this.nextTime += buffer.duration;
  }
}
