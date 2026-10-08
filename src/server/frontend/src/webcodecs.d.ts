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
