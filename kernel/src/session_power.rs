//! Finite captured-controller latch. Metadata here proves no device I/O; the
//! physical executor must validate actual capabilities, stopped CPUs and every
//! RPC/escrow owner before calling it. No latch reset or deadline renewal exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Intent {
    Shutdown,
    Restart,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Frozen,
    Fenced,
    Complete,
}
/// Metadata only: decoding never proves a real barrier, displayed prompt,
/// confirmation, device operation or permission to change power state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Readiness {
    pub nonce: u64,
    pub frame: u64,
    pub sequence: u32,
    pub main_held: bool,
    pub keypad_held: bool,
    pub main_released: bool,
    pub keypad_released: bool,
    pub pointer_held: u8,
    pub pointer_released: u8,
    pub restart: bool,
}
impl Readiness {
    pub fn decode(nonce: u64, frame: u64, input: u64) -> Option<Self> {
        if matches!(nonce, 0 | u64::MAX)
            || matches!(frame, 0 | u64::MAX)
            || input >> 43 != 0
            || input as u32 == u32::MAX
        {
            return None;
        }
        Some(Self {
            nonce,
            frame,
            sequence: input as u32,
            main_held: input & (1 << 32) != 0,
            keypad_held: input & (1 << 33) != 0,
            main_released: input & (1 << 41) != 0,
            keypad_released: input & (1 << 42) != 0,
            pointer_held: ((input >> 34) & 7) as u8,
            pointer_released: ((input >> 37) & 7) as u8,
            restart: input & (1 << 40) != 0,
        })
    }
}
#[derive(Clone, Copy)]
pub struct Latch {
    phase: Phase,
    intent: Intent,
    diagnostic_reports: u8,
    first: u64,
    cut: u64,
    pair: [u64; 4],
}
impl Default for Latch {
    fn default() -> Self {
        Self::new()
    }
}
impl Latch {
    pub const fn new() -> Self {
        Self {
            phase: Phase::Idle,
            intent: Intent::Shutdown,
            diagnostic_reports: 0,
            first: 0,
            cut: 0,
            pair: [0; 4],
        }
    }
    pub const fn phase(&self) -> Phase {
        self.phase
    }
    pub fn note_dialog_report(&mut self) -> Result<(), u64> {
        if self.active() || self.diagnostic_reports >= 8 {
            return Err(3);
        }
        self.diagnostic_reports += 1;
        Ok(())
    }
    pub const fn active(&self) -> bool {
        !matches!(self.phase, Phase::Idle)
    }
    pub const fn completed_intent(&self) -> Option<Intent> {
        if matches!(self.phase, Phase::Complete) {
            Some(self.intent)
        } else {
            None
        }
    }
    pub fn live(&self, now: u64) -> bool {
        self.phase == Phase::Frozen && now >= self.first && now < self.cut
    }
    pub fn begin(&mut self, pair: [u64; 4], now: u64, cut: u64) -> Result<u64, u64> {
        self.begin_intent(Intent::Shutdown, pair, now, cut)
    }
    pub fn begin_intent(
        &mut self,
        intent: Intent,
        pair: [u64; 4],
        now: u64,
        cut: u64,
    ) -> Result<u64, u64> {
        if self.active() {
            return Err(3);
        }
        if pair.contains(&0) || pair[0] == pair[2] || pair[1] == pair[3] {
            return Err(1);
        }
        if now == u64::MAX || cut == u64::MAX || cut <= now || cut - now > 8192 {
            return Err(4);
        }
        self.pair = pair;
        self.intent = intent;
        self.first = now;
        self.cut = cut;
        self.phase = Phase::Frozen;
        Ok(1)
    }
    pub fn complete(&mut self, pair: [u64; 4], token: u64, now: u64) -> Result<(), u64> {
        if self.phase != Phase::Frozen || pair != self.pair || token != 1 {
            return Err(1);
        }
        if !self.live(now) {
            self.phase = Phase::Fenced;
            return Err(4);
        }
        self.phase = Phase::Complete;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn readiness_is_strict_bounded_and_never_begins_or_completes_power() {
        let packed = 17 | (1 << 32) | (3 << 34) | (7 << 37) | (1 << 40) | (1 << 41);
        let r = Readiness::decode(5, 9, packed).unwrap();
        assert_eq!(
            (
                r.sequence,
                r.main_held,
                r.keypad_held,
                r.pointer_held,
                r.pointer_released,
                r.restart
            ),
            (17, true, false, 3, 7, true)
        );
        assert!(r.main_released && !r.keypad_released);
        for (n, f, i) in [
            (0, 9, 0),
            (u64::MAX, 9, 0),
            (5, 0, 0),
            (5, u64::MAX, 0),
            (5, 9, u32::MAX as u64),
            (5, 9, 1 << 43),
        ] {
            assert!(Readiness::decode(n, f, i).is_none());
        }
        let mut latch = Latch::new();
        for _ in 0..8 {
            assert_eq!(latch.note_dialog_report(), Ok(()));
        }
        assert_eq!(latch.note_dialog_report(), Err(3));
        assert_eq!(latch.phase(), Phase::Idle);
        assert_eq!(latch.completed_intent(), None);
        assert_eq!(latch.begin([1, 2, 3, 4], 100, 200), Ok(1));
        assert_eq!(latch.note_dialog_report(), Err(3));
        assert_eq!(latch.complete([1, 2, 3, 4], 1, 101), Ok(()));
        assert_eq!(latch.completed_intent(), Some(Intent::Shutdown));
    }
    #[test]
    fn original_cut_and_pair_are_sticky_through_failure_and_completion() {
        let pair = [1, 2, 3, 4];
        let mut l = Latch::new();
        assert_eq!(l.begin(pair, 100, 8292), Ok(1));
        assert_eq!(l.begin(pair, 101, 8293), Err(3));
        assert_eq!(l.complete([1, 2, 5, 6], 1, 102), Err(1));
        assert_eq!(l.complete(pair, 2, 102), Err(1));
        assert_eq!(l.complete(pair, 1, 8292), Err(4));
        assert_eq!(l.begin(pair, 8293, 16385), Err(3));
        assert_eq!(l.complete(pair, 1, 103), Err(1));
        let mut good = Latch::new();
        good.begin(pair, 100, 8292).unwrap();
        assert_eq!(good.complete(pair, 1, 103), Ok(()));
        assert_eq!(good.complete(pair, 1, 104), Err(1));
        assert!(l.active());
    }
    #[test]
    fn invalid_initial_request_has_no_effect() {
        for (pair, now, cut) in [
            ([0, 2, 3, 4], 100, 101),
            ([1, 2, 1, 4], 100, 101),
            ([1, 2, 3, 4], 100, 100),
            ([1, 2, 3, 4], 100, 8293),
            ([1, 2, 3, 4], 100, u64::MAX),
        ] {
            let mut l = Latch::new();
            assert!(l.begin(pair, now, cut).is_err());
            assert_eq!(l.phase(), Phase::Idle);
        }
    }
    #[test]
    fn restart_intent_is_captured_once_and_never_changes_on_complete_or_failure() {
        let pair = [1, 2, 3, 4];
        for intent in [Intent::Shutdown, Intent::Restart] {
            let mut latch = Latch::new();
            assert_eq!(latch.completed_intent(), None);
            assert_eq!(latch.begin_intent(intent, pair, 100, 200), Ok(1));
            assert_eq!(latch.begin(pair, 101, 300), Err(3));
            assert_eq!(latch.completed_intent(), None);
            assert_eq!(latch.complete(pair, 2, 102), Err(1));
            assert_eq!(latch.complete(pair, 1, 103), Ok(()));
            assert_eq!(latch.completed_intent(), Some(intent));
            assert_eq!(latch.begin_intent(intent, pair, 104, 300), Err(3));
            assert_eq!(latch.complete(pair, 1, 105), Err(1));
            assert_eq!(latch.completed_intent(), Some(intent));
            let mut expired = Latch::new();
            expired.begin_intent(intent, pair, 100, 200).unwrap();
            assert_eq!(expired.complete(pair, 1, 200), Err(4));
            assert_eq!(expired.completed_intent(), None);
        }
    }
}
