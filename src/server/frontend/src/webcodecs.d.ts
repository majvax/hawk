// Minimal ambient declarations for the slice of the WebCodecs API the
// dashboard viewer uses. The browsers we target (Chromium-based, for
// VideoDecoder) ship the full API; TypeScript's lib.dom does not yet include
// it and there is no @types package installed, so we declare just enough
// here. Not a complete or authoritative typing.

interface VideoFrame {
  readonly displayWidth: number;
  readonly displayHeight: number;
  close(): void;
}

interface EncodedVideoChunkInit {
  type: "key" | "delta";
  timestamp: number; // microseconds
  data: BufferSource;
}
declare class EncodedVideoChunk {
  constructor(init: EncodedVideoChunkInit);
}

interface VideoDecoderConfig {
  codec: string;
  optimizeForLatency?: boolean;
}

interface VideoDecoderInit {
  output: (frame: VideoFrame) => void;
  error: (error: DOMException) => void;
}

declare class VideoDecoder {
  constructor(init: VideoDecoderInit);
  readonly state: "unconfigured" | "configured" | "closed";
  configure(config: VideoDecoderConfig): void;
  decode(chunk: EncodedVideoChunk): void;
  close(): void;
  static isConfigSupported(config: VideoDecoderConfig): Promise<{ supported: boolean }>;
}

// The audio side: Opus packets from the machine (see audio.ts).
interface EncodedAudioChunkInit {
  type: "key" | "delta";
  timestamp: number; // microseconds
  data: BufferSource;
}
declare class EncodedAudioChunk {
  constructor(init: EncodedAudioChunkInit);
}

interface AudioData {
  readonly sampleRate: number;
  readonly numberOfFrames: number;
  readonly numberOfChannels: number;
  readonly timestamp: number; // microseconds
  copyTo(destination: BufferSource, options: { planeIndex: number; format?: "f32-planar" }): void;
  close(): void;
}

interface AudioDecoderConfig {
  codec: string;
  sampleRate: number;
  numberOfChannels: number;
}

interface AudioDecoderInit {
  output: (data: AudioData) => void;
  error: (error: DOMException) => void;
}

declare class AudioDecoder {
  constructor(init: AudioDecoderInit);
  readonly state: "unconfigured" | "configured" | "closed";
  configure(config: AudioDecoderConfig): void;
  decode(chunk: EncodedAudioChunk): void;
  close(): void;
  static isConfigSupported(config: AudioDecoderConfig): Promise<{ supported: boolean }>;
}
