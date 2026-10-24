import { describe, expect, test } from "bun:test";
import {
  DecodeClock,
  PING_TIMEOUT_MS,
  PingTracker,
  type StatsSample,
  bitrateKbps,
  perSecond,
  qualityDelta,
  summarize,
} from "./streamStats.js";

function sample(overrides: Partial<StatsSample> = {}): StatsSample {
  return {
    seconds: 1,
    bytes: 0,
    received: 0,
    decoded: null,
    shown: 0,
    dropped: 0,
    skipped: 0,
    pending: 0,
    queue: null,
    decodeMs: null,
    lagMs: null,
    rttMs: null,
    audioMs: null,
    backend: null,
    receiving: false,
    debug: null,
    ...overrides,
  };
}

describe("rates", () => {
  test("perSecond rounds a count over the interval", () => {
    expect(perSecond(60, 1)).toBe(60);
    expect(perSecond(59, 0.98)).toBe(60);
    expect(perSecond(30, 2)).toBe(15);
    expect(perSecond(0, 1)).toBe(0);
  });

  test("bitrateKbps turns bytes into kilobits a second", () => {
    expect(bitrateKbps(125_000, 1)).toBe(1000);
    expect(bitrateKbps(125_000, 2)).toBe(500);
    expect(bitrateKbps(0, 1)).toBe(0);
  });

  test("a zero or negative interval stays finite", () => {
    for (const seconds of [0, -1]) {
      expect(Number.isFinite(perSecond(10, seconds))).toBe(true);
      expect(Number.isFinite(bitrateKbps(10, seconds))).toBe(true);
    }
    expect(perSecond(0, 0)).toBe(0);
  });
});

describe("summarize", () => {
  test("no samples: all zero, nulls kept", () => {
    const stats = summarize(sample());
    expect(stats).toMatchObject({ fps: 0, received: 0, dropped: 0, kbps: 0, skipped: 0, pending: 0 });
    expect(stats.decoded).toBeNull();
    expect(stats.queue).toBeNull();
    expect(stats.decodeMs).toBeNull();
    expect(stats.lagMs).toBeNull();
    expect(stats.rttMs).toBeNull();
    expect(stats.audioMs).toBeNull();
    expect(stats.backend).toBeNull();
    expect(stats.receiving).toBe(false);
  });

  test("zero elapsed gives no NaN or Infinity", () => {
    const stats = summarize(sample({ seconds: 0, bytes: 1000, received: 3, shown: 3, decoded: 3, dropped: 1, skipped: 2 }));
    for (const value of Object.values(stats)) {
      if (typeof value === "number") expect(Number.isFinite(value)).toBe(true);
    }
  });

  test("rates over the interval, gauges as they stand", () => {
    const stats = summarize(
      sample({
        seconds: 2,
        bytes: 250_000,
        received: 120,
        decoded: 118,
        shown: 116,
        dropped: 2,
        skipped: 4,
        pending: 3,
        queue: 1,
        decodeMs: 4.5,
        lagMs: 80,
        rttMs: 21,
        audioMs: 60,
        backend: "webcodecs",
        receiving: true,
        debug: "x",
      }),
    );
    expect(stats).toEqual({
      fps: 58,
      received: 60,
      dropped: 1,
      debug: "x",
      kbps: 1000,
      receiving: true,
      backend: "webcodecs",
      decoded: 59,
      skipped: 2,
      pending: 3,
      queue: 1,
      decodeMs: 4.5,
      lagMs: 80,
      rttMs: 21,
      audioMs: 60,
    });
  });

  test("decoded of zero is a rate, not N/A", () => {
    expect(summarize(sample({ decoded: 0 })).decoded).toBe(0);
  });
});

describe("qualityDelta", () => {
  test("the first reading of a decoder has no delta", () => {
    expect(qualityDelta(null, { shown: 100, dropped: 3 })).toBeNull();
  });

  test("the change since the last reading", () => {
    expect(qualityDelta({ shown: 100, dropped: 3 }, { shown: 160, dropped: 5 })).toEqual({ shown: 60, dropped: 2 });
  });

  test("counts going backwards never go negative", () => {
    expect(qualityDelta({ shown: 100, dropped: 5 }, { shown: 10, dropped: 0 })).toEqual({ shown: 0, dropped: 0 });
  });
});

describe("DecodeClock", () => {
  test("no frames out: null", () => {
    const clock = new DecodeClock();
    expect(clock.takeMeanMs()).toBeNull();
    clock.submitted(1, 0);
    expect(clock.takeMeanMs()).toBeNull();
  });

  test("the mean since the last take, then starts over", () => {
    const clock = new DecodeClock();
    clock.submitted(1, 100);
    clock.submitted(2, 110);
    clock.finished(1, 104);
    clock.finished(2, 118);
    expect(clock.takeMeanMs()).toBe(6);
    expect(clock.takeMeanMs()).toBeNull();
  });

  test("unknown or repeated timestamps are ignored", () => {
    const clock = new DecodeClock();
    clock.finished(9, 50);
    clock.submitted(1, 0);
    clock.finished(1, 10);
    clock.finished(1, 30);
    expect(clock.takeMeanMs()).toBe(10);
  });

  test("forgets the oldest frames past the in-flight cap", () => {
    const clock = new DecodeClock();
    for (let t = 0; t <= 120; t += 1) clock.submitted(t, t);
    clock.finished(0, 500); // forgotten
    expect(clock.takeMeanMs()).toBeNull();
    clock.finished(1, 11);
    expect(clock.takeMeanMs()).toBe(10);
  });

  test("clear drops frames in flight and the running mean", () => {
    const clock = new DecodeClock();
    clock.submitted(1, 0);
    clock.submitted(2, 0);
    clock.finished(1, 5);
    clock.clear();
    clock.finished(2, 5);
    expect(clock.takeMeanMs()).toBeNull();
  });
});

describe("PingTracker", () => {
  test("matches a pong to its ping", () => {
    const ping = new PingTracker();
    const nonce = ping.start(1000);
    expect(ping.rttMs(1000)).toBeNull();
    expect(ping.answer(nonce, 1042)).toBe(42);
    expect(ping.rttMs(1100)).toBe(42);
  });

  test("nonces are distinct and each answers once", () => {
    const ping = new PingTracker();
    const a = ping.start(0);
    const b = ping.start(1000);
    expect(a).not.toBe(b);
    expect(ping.answer(b, 1010)).toBe(10);
    expect(ping.answer(b, 1020)).toBeNull();
    expect(ping.answer(a, 1030)).toBe(1030);
    expect(ping.rttMs(1030)).toBe(1030);
  });

  test("an unknown nonce is ignored", () => {
    const ping = new PingTracker();
    ping.answer(ping.start(0), 20);
    expect(ping.answer("nope", 30)).toBeNull();
    expect(ping.answer("", 30)).toBeNull();
    expect(ping.rttMs(30)).toBe(20);
  });

  test("a pong later than the timeout is a lost ping", () => {
    const ping = new PingTracker();
    const nonce = ping.start(0);
    expect(ping.answer(nonce, PING_TIMEOUT_MS + 1)).toBeNull();
    expect(ping.rttMs(PING_TIMEOUT_MS + 1)).toBeNull();
  });

  test("stale pings are dropped when the next one starts", () => {
    const ping = new PingTracker();
    const old = ping.start(0);
    ping.start(PING_TIMEOUT_MS + 1);
    expect(ping.answer(old, PING_TIMEOUT_MS + 2)).toBeNull();
  });

  test("the last round trip expires once it's old", () => {
    const ping = new PingTracker();
    ping.answer(ping.start(1000), 1050);
    expect(ping.rttMs(1050 + PING_TIMEOUT_MS)).toBe(50);
    expect(ping.rttMs(1051 + PING_TIMEOUT_MS)).toBeNull();
  });

  test("reset forgets pings in flight and the last round trip", () => {
    const ping = new PingTracker();
    ping.answer(ping.start(0), 10);
    const pending = ping.start(20);
    ping.reset();
    expect(ping.rttMs(30)).toBeNull();
    expect(ping.answer(pending, 30)).toBeNull();
    // Nonces keep counting, so a pong from before the reset can't match.
    expect(ping.start(40)).not.toBe(pending);
  });
});
