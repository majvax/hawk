// How the sound is buffered, and whether the picture waits for it.
//
// "latency" plays everything as soon as it can, which interactive control
// wants: picture and sound each as early as they arrive, a little apart.
// "sync" holds a deeper cushion so the sound plays steadily, and holds each
// picture back until the sound of the same instant is heard, which watching
// something wants.
export type SoundMode = "latency" | "sync";

export interface Buffering {
  // Held before the first packet after a gap, to absorb network jitter.
  cushionS: number;
  // Queued further ahead than this, the sound catches up by skipping.
  maxLatencyS: number;
}

export const BUFFERING: Record<SoundMode, Buffering> = {
  latency: { cushionS: 0.08, maxLatencyS: 0.4 },
  sync: { cushionS: 0.15, maxLatencyS: 0.6 },
};

// Past the end of the last sound heard by this much, there is no clock to
// follow (the machine went quiet) and the picture runs free.
export const CLOCK_IDLE_S = 0.5;
