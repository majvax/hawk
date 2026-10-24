//! The stream's quality presets, and the controller behind Auto.
//!
//! Auto moves the machine's encoder bitrate with what the relay sees of the
//! stream, since the relay sits where congestion shows on both of its legs:
//!
//! - the machine's uplink: each frame carries its capture time in the
//!   clear, so how long a frame took to get here, against the quickest one
//!   lately, is the queue between the encoder and the relay (hawk-capture's
//!   pipe, the service's socket, the network);
//! - each viewer's downlink: frames waiting in that viewer's queue here,
//!   and frames that didn't fit in it.
//!
//! Everything here is plain arithmetic on what it's handed, so it's tested
//! without a socket or a clock.

use serde::{Deserialize, Serialize};

/// What a viewer can pick from the live view, and what the machine says it
/// streams at. The bitrates and frame rates live on the machine
/// (src/service/quality.hpp); Auto's range is mirrored below.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Preset {
    Auto,
    Low,
    Balanced,
    High,
    Max,
}

/// Auto's range, as the machine clamps it (kAutoMinBitrate and
/// kAutoMaxBitrate in src/service/quality.hpp).
pub const AUTO_MIN_BITRATE: u32 = 500_000;
pub const AUTO_MAX_BITRATE: u32 = 12_000_000;

/// How often the controller looks at what it measured.
pub const TICK_US: i64 = 1_000_000;

/// A queue past this many frames (about a sixth of a second at 60 fps, with
/// sound) means the viewer's link isn't keeping up...
const BACKLOG_CONGESTED: usize = 10;
/// ...and one this short that it is.
const BACKLOG_CLEAR: usize = 3;
/// Frames taking this much longer than the quickest lately to reach the
/// relay means the machine's uplink is queueing...
const DELAY_CONGESTED_US: i64 = 250_000;
/// ...and this little that it isn't.
const DELAY_CLEAR_US: i64 = 80_000;
/// The quickest frame is remembered over two windows of this, so a route
/// that got slower for good stops counting as a queue within half a minute.
const BASE_WINDOW_US: i64 = 15_000_000;

/// What the stream looked like over one tick.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Signals {
    /// The longest a frame took over the quickest lately, in microseconds.
    pub delay_us: i64,
    /// The most frames waiting in any viewer's queue.
    pub backlog: usize,
    /// Some viewer's queue was full, and a frame was dropped.
    pub dropped: bool,
    /// Video the machine sent over the tick, in bits per second.
    pub sent_bps: u64,
}

impl Signals {
    pub fn verdict(&self) -> Verdict {
        if self.dropped || self.backlog >= BACKLOG_CONGESTED || self.delay_us >= DELAY_CONGESTED_US {
            Verdict::Congested
        } else if self.backlog <= BACKLOG_CLEAR && self.delay_us <= DELAY_CLEAR_US {
            Verdict::Clear
        } else {
            // Between the two: neither cut nor raise.
            Verdict::Steady
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Congested,
    Steady,
    Clear,
}

/// Gathers [`Signals`] as frames go by, a tick at a time.
#[derive(Debug, Default)]
pub struct Meter {
    /// The quickest frame (arrival minus capture time) in this window and
    /// the last one. The two clocks are unrelated, so only differences from
    /// it mean anything.
    base: Option<i64>,
    previous_base: Option<i64>,
    window_started_us: i64,
    last_timestamp_us: Option<i64>,
    delays: Vec<i64>,
    backlog: usize,
    dropped: bool,
    bytes: u64,
}

impl Meter {
    /// A video frame captured at `timestamp_us` (the machine's stream
    /// clock) arrived at `arrival_us` (the relay's), `bytes` long.
    pub fn frame(&mut self, arrival_us: i64, timestamp_us: i64, bytes: usize) {
        // hawk-capture started over, and its clock with it: what was quick
        // before says nothing now.
        if self.last_timestamp_us.is_some_and(|last| timestamp_us < last) {
            self.base = None;
            self.previous_base = None;
            self.delays.clear();
        }
        self.last_timestamp_us = Some(timestamp_us);
        if arrival_us.saturating_sub(self.window_started_us) >= BASE_WINDOW_US {
            self.previous_base = self.base;
            self.base = None;
            self.window_started_us = arrival_us;
        }
        // Saturating: the timestamp is whatever the machine wrote, and a
        // garbage one mustn't overflow (a panic, in a debug build).
        let transit = arrival_us.saturating_sub(timestamp_us);
        self.base = Some(self.base.map_or(transit, |base| base.min(transit)));
        self.delays.push(transit);
        self.bytes += bytes as u64;
    }

    /// One viewer's queue after a frame was offered to it: how many frames
    /// wait in it, and whether this one didn't fit.
    pub fn queue(&mut self, waiting: usize, dropped: bool) {
        self.backlog = self.backlog.max(waiting);
        self.dropped |= dropped;
    }

    /// What was measured over the last `elapsed_us`, and starts over.
    pub fn take(&mut self, elapsed_us: i64) -> Signals {
        let base = match (self.base, self.previous_base) {
            (Some(base), Some(previous)) => Some(base.min(previous)),
            (base, previous) => base.or(previous),
        };
        let delay_us = base.map_or(0, |base| self.delays.iter().map(|transit| transit.saturating_sub(base)).max().unwrap_or(0).max(0));
        let sent_bps = self.bytes * 8 * 1_000_000 / elapsed_us.max(1).unsigned_abs();
        let signals = Signals { delay_us, backlog: self.backlog, dropped: self.dropped, sent_bps };
        self.delays.clear();
        self.backlog = 0;
        self.dropped = false;
        self.bytes = 0;
        signals
    }
}

/// Cut to this many tenths on congestion...
const DECREASE_TENTHS: u64 = 7;
/// ...then don't cut again for this many ticks, while the queue the cut
/// is meant to drain drains.
const HOLD_TICKS: u32 = 2;
/// Raise only after this many clear ticks in a row...
const CLEAR_TICKS: u32 = 3;
/// ...by this much a tick.
const INCREASE_BPS: u32 = 300_000;

/// AIMD on the encoder's bitrate: a multiplicative cut whenever a tick
/// shows congestion, a slow additive climb once several in a row were
/// clear, within Auto's range. It only climbs while the stream uses most
/// of what it has: an idle screen proves nothing about the link.
#[derive(Debug, Clone)]
pub struct RateController {
    target: u32,
    clear_ticks: u32,
    hold_ticks: u32,
}

impl RateController {
    pub fn new(start: u32) -> Self {
        Self { target: start.clamp(AUTO_MIN_BITRATE, AUTO_MAX_BITRATE), clear_ticks: 0, hold_ticks: 0 }
    }

    pub fn target(&self) -> u32 {
        self.target
    }

    /// Takes one tick's signals; returns the new target.
    pub fn tick(&mut self, signals: &Signals) -> u32 {
        self.hold_ticks = self.hold_ticks.saturating_sub(1);
        match signals.verdict() {
            Verdict::Congested => {
                self.clear_ticks = 0;
                if self.hold_ticks == 0 {
                    let cut = u64::from(self.target) * DECREASE_TENTHS / 10;
                    self.target = u32::try_from(cut).unwrap_or(AUTO_MAX_BITRATE).max(AUTO_MIN_BITRATE);
                    self.hold_ticks = HOLD_TICKS + 1; // counted down at the next tick
                }
            }
            Verdict::Steady => self.clear_ticks = 0,
            Verdict::Clear => {
                self.clear_ticks += 1;
                let using = signals.sent_bps * 2 >= u64::from(self.target);
                if self.clear_ticks >= CLEAR_TICKS && using {
                    self.target = self.target.saturating_add(INCREASE_BPS).min(AUTO_MAX_BITRATE);
                }
            }
        }
        self.target
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const START: u32 = 4_000_000;

    fn clear(sent_bps: u64) -> Signals {
        Signals { sent_bps, ..Signals::default() }
    }

    fn congested() -> Signals {
        Signals { dropped: true, sent_bps: u64::from(START), ..Signals::default() }
    }

    #[test]
    fn verdicts_have_a_dead_band() {
        assert_eq!(Signals::default().verdict(), Verdict::Clear);
        assert_eq!(Signals { dropped: true, ..Signals::default() }.verdict(), Verdict::Congested);
        assert_eq!(Signals { backlog: BACKLOG_CONGESTED, ..Signals::default() }.verdict(), Verdict::Congested);
        assert_eq!(Signals { delay_us: DELAY_CONGESTED_US, ..Signals::default() }.verdict(), Verdict::Congested);
        assert_eq!(Signals { backlog: BACKLOG_CLEAR + 1, ..Signals::default() }.verdict(), Verdict::Steady);
        assert_eq!(Signals { delay_us: DELAY_CLEAR_US + 1, ..Signals::default() }.verdict(), Verdict::Steady);
    }

    #[test]
    fn congestion_cuts_multiplicatively_then_holds() {
        let mut controller = RateController::new(START);
        assert_eq!(controller.tick(&congested()), 2_800_000);
        // The queue is still draining: no second cut straight away.
        assert_eq!(controller.tick(&congested()), 2_800_000);
        assert_eq!(controller.tick(&congested()), 2_800_000);
        assert_eq!(controller.tick(&congested()), 1_960_000);
    }

    #[test]
    fn never_below_the_floor_or_above_the_ceiling() {
        let mut controller = RateController::new(AUTO_MIN_BITRATE + 1);
        for _ in 0..20 {
            controller.tick(&congested());
        }
        assert_eq!(controller.target(), AUTO_MIN_BITRATE);
        let mut controller = RateController::new(AUTO_MAX_BITRATE);
        for _ in 0..20 {
            controller.tick(&clear(u64::from(AUTO_MAX_BITRATE)));
        }
        assert_eq!(controller.target(), AUTO_MAX_BITRATE);
        assert_eq!(RateController::new(u32::MAX).target(), AUTO_MAX_BITRATE);
        assert_eq!(RateController::new(0).target(), AUTO_MIN_BITRATE);
    }

    #[test]
    fn climbs_slowly_after_clear_ticks() {
        let mut controller = RateController::new(START);
        let busy = clear(u64::from(START));
        assert_eq!(controller.tick(&busy), START);
        assert_eq!(controller.tick(&busy), START);
        assert_eq!(controller.tick(&busy), START + INCREASE_BPS);
        assert_eq!(controller.tick(&busy), START + 2 * INCREASE_BPS);
        // Anything short of clear starts the count over.
        controller.tick(&Signals { backlog: BACKLOG_CLEAR + 1, ..busy });
        assert_eq!(controller.tick(&busy), START + 2 * INCREASE_BPS);
    }

    #[test]
    fn an_idle_stream_doesnt_climb() {
        let mut controller = RateController::new(START);
        for _ in 0..10 {
            controller.tick(&clear(u64::from(START) / 4));
        }
        assert_eq!(controller.target(), START);
    }

    #[test]
    fn the_meter_measures_delay_over_the_quickest_frame() {
        let mut meter = Meter::default();
        // The relay's clock runs 5 s ahead of the stream's; frames take
        // 20 ms, then one takes 320 ms.
        meter.frame(5_020_000, 0, 1000);
        meter.frame(5_036_000, 16_000, 1000);
        meter.frame(5_352_000, 32_000, 1000);
        let signals = meter.take(1_000_000);
        assert_eq!(signals.delay_us, 300_000);
        assert_eq!(signals.sent_bps, 24_000);
        assert_eq!(signals.verdict(), Verdict::Congested);
        // The next tick remembers how quick it can be.
        meter.frame(5_068_000, 48_000, 1000);
        assert_eq!(meter.take(1_000_000).delay_us, 0);
    }

    #[test]
    fn the_meter_starts_over_with_capture() {
        let mut meter = Meter::default();
        meter.frame(5_020_000, 0, 1);
        meter.frame(9_020_000, 4_000_000, 1);
        meter.take(1_000_000);
        // hawk-capture restarted: its clock is back at zero.
        meter.frame(12_030_000, 0, 1);
        meter.frame(12_046_000, 16_000, 1);
        assert_eq!(meter.take(1_000_000).delay_us, 0);
    }

    #[test]
    fn the_meter_keeps_the_worst_queue() {
        let mut meter = Meter::default();
        meter.queue(4, false);
        meter.queue(12, false);
        meter.queue(1, true);
        let signals = meter.take(1_000_000);
        assert_eq!((signals.backlog, signals.dropped), (12, true));
        assert_eq!(meter.take(1_000_000), Signals::default());
    }

    /// A link that holds `capacity` b/s: a tick is congested when the
    /// target goes past it, clear (and busy) otherwise.
    fn link(capacity: u32, target: u32) -> Signals {
        if target > capacity { Signals { backlog: 20, sent_bps: u64::from(capacity), ..Signals::default() } } else { clear(u64::from(target)) }
    }

    #[test]
    fn congestion_then_recovery_converges_without_wild_swings() {
        let mut controller = RateController::new(START);
        // The link drops to 1.5 Mb/s: the controller gets under it, then
        // saws gently just under it, never cut below 0.7 of it twice over.
        let capacity = 1_500_000;
        let mut history = Vec::new();
        for _ in 0..120 {
            history.push(controller.tick(&link(capacity, controller.target())));
        }
        let settled = &history[30..];
        let (low, high) = (*settled.iter().min().unwrap(), *settled.iter().max().unwrap());
        assert!(low >= capacity * 7 / 10 * 9 / 10, "cut too deep: {low}");
        assert!(high <= capacity + INCREASE_BPS, "overshot: {high}");
        // Cuts are rare: at most one in every few ticks once settled.
        let cuts = settled.windows(2).filter(|pair| pair[1] < pair[0]).count();
        assert!(cuts <= settled.len() / 4, "{cuts} cuts in {} ticks", settled.len());

        // The link comes back at 10 Mb/s: it climbs all the way, steadily.
        let capacity = 10_000_000;
        let mut previous = controller.target();
        let mut ticks = 0;
        while previous <= capacity {
            let target = controller.tick(&link(capacity, controller.target()));
            assert!(target >= previous, "no cut while under the link's capacity");
            assert!(target - previous <= INCREASE_BPS);
            previous = target;
            ticks += 1;
            assert!(ticks < 40, "too slow to find the room: {previous}");
        }
        // Past it, a single cut back under it, and the same gentle saw.
        let mut history = Vec::new();
        for _ in 0..120 {
            history.push(controller.tick(&link(capacity, controller.target())));
        }
        assert!(*history.iter().min().unwrap() >= capacity * 7 / 10 * 9 / 10);
        assert!(*history.iter().max().unwrap() <= capacity + INCREASE_BPS);
    }

    #[test]
    fn a_floor_link_holds_at_the_floor_and_a_fat_one_at_the_ceiling() {
        let mut controller = RateController::new(START);
        for _ in 0..100 {
            let target = controller.tick(&link(100_000, controller.target()));
            assert!((AUTO_MIN_BITRATE..=AUTO_MAX_BITRATE).contains(&target));
        }
        assert_eq!(controller.target(), AUTO_MIN_BITRATE);
        for _ in 0..100 {
            let target = controller.tick(&link(u32::MAX, controller.target()));
            assert!((AUTO_MIN_BITRATE..=AUTO_MAX_BITRATE).contains(&target));
        }
        assert_eq!(controller.target(), AUTO_MAX_BITRATE);
    }

    #[test]
    fn an_idle_screen_never_climbs_however_long_it_stays_clear() {
        let mut controller = RateController::new(START);
        for _ in 0..1000 {
            controller.tick(&clear(0));
        }
        assert_eq!(controller.target(), START);
        // Just under half of the target counts as idle too.
        for _ in 0..100 {
            controller.tick(&clear(u64::from(START) / 2 - 1));
        }
        assert_eq!(controller.target(), START);
        // Half of it is busy enough.
        for _ in 0..3 {
            controller.tick(&clear(u64::from(START) / 2));
        }
        assert_eq!(controller.target(), START + INCREASE_BPS);
    }

    #[test]
    fn the_hold_band_neither_cuts_nor_raises() {
        let mut controller = RateController::new(START);
        let steady = Signals { delay_us: (DELAY_CLEAR_US + DELAY_CONGESTED_US) / 2, sent_bps: u64::from(START), ..Signals::default() };
        assert_eq!(steady.verdict(), Verdict::Steady);
        for _ in 0..50 {
            assert_eq!(controller.tick(&steady), START);
        }
        // A cut's hold runs out during steady ticks too: the next
        // congestion cuts at once.
        controller.tick(&congested());
        for _ in 0..HOLD_TICKS + 1 {
            controller.tick(&steady);
        }
        assert_eq!(controller.tick(&congested()), START * 49 / 100);
        // Clear ticks interrupted by steady ones never add up to a raise.
        let mut controller = RateController::new(START);
        for _ in 0..30 {
            controller.tick(&clear(u64::from(START)));
            controller.tick(&clear(u64::from(START)));
            controller.tick(&steady);
        }
        assert_eq!(controller.target(), START);
    }

    /// Feeds a tick of 60 frames 16 ms apart, `transit_us` each.
    fn tick_of_frames(meter: &mut Meter, arrival_us: &mut i64, timestamp_us: &mut i64, transit_us: i64) -> Signals {
        for _ in 0..60 {
            *arrival_us += 16_000;
            *timestamp_us += 16_000;
            meter.frame(*arrival_us, *arrival_us - transit_us, 1000);
        }
        meter.take(1_000_000)
    }

    #[test]
    fn garbage_timestamps_never_give_a_negative_or_stuck_delay() {
        let absurd = [i64::MIN, i64::MIN + 1, -1, 0, i64::MAX, i64::MAX - 1, 1 << 62, -(1 << 62)];
        for garbage in absurd {
            let mut meter = Meter::default();
            let (mut arrival, mut timestamp) = (5_000_000_i64, 0_i64);
            tick_of_frames(&mut meter, &mut arrival, &mut timestamp, 20_000);
            arrival += 16_000;
            meter.frame(arrival, garbage, 1000);
            let signals = meter.take(1_000_000);
            assert!(signals.delay_us >= 0, "{garbage}: {}", signals.delay_us);
            // At most a tick or two to forget it, however absurd.
            tick_of_frames(&mut meter, &mut arrival, &mut timestamp, 20_000);
            let signals = tick_of_frames(&mut meter, &mut arrival, &mut timestamp, 20_000);
            assert_eq!(signals.delay_us, 0, "{garbage}: still counting it");
            assert_eq!(signals.verdict(), Verdict::Clear);
        }
    }

    #[test]
    fn a_clock_that_wraps_or_goes_backwards_starts_over_cleanly() {
        let mut meter = Meter::default();
        let (mut arrival, mut timestamp) = (0_i64, i64::MAX - 500_000);
        for _ in 0..30 {
            arrival += 16_000;
            timestamp = timestamp.wrapping_add(16_000); // wraps to negative
            meter.frame(arrival, timestamp, 1000);
            let delay = meter.take(16_000).delay_us;
            assert!(delay >= 0);
        }
        // Then steady frames: nothing left over from before.
        let mut timestamp = 0;
        let signals = tick_of_frames(&mut meter, &mut arrival, &mut timestamp, 30_000);
        assert_eq!(signals.delay_us, 0);
        // Going back a little (capture restarted) is no queue either.
        let signals = tick_of_frames(&mut meter, &mut arrival, &mut 0, 10_000);
        assert!(signals.delay_us >= 0);
    }

    #[test]
    fn a_slower_route_stops_counting_as_a_queue_within_two_windows() {
        let mut meter = Meter::default();
        let (mut arrival, mut timestamp) = (0_i64, 0_i64);
        for _ in 0..20 {
            tick_of_frames(&mut meter, &mut arrival, &mut timestamp, 20_000);
        }
        // The route takes 300 ms more from now on, for good.
        let mut congested = 0;
        for _ in 0..40 {
            if tick_of_frames(&mut meter, &mut arrival, &mut timestamp, 320_000).verdict() == Verdict::Congested {
                congested += 1;
            }
        }
        assert!(congested < 40, "never got over it");
        assert_eq!(tick_of_frames(&mut meter, &mut arrival, &mut timestamp, 320_000).delay_us, 0);
    }
    #[test]
    fn presets_are_snake_case() {
        assert_eq!(serde_json::to_value(Preset::Auto).unwrap(), serde_json::json!("auto"));
        assert_eq!(serde_json::from_str::<Preset>(r#""balanced""#).unwrap(), Preset::Balanced);
        assert!(serde_json::from_str::<Preset>(r#""ultra""#).is_err());
    }
}
