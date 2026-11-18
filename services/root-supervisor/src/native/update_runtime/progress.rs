//! Bounded diagnostic retention only. Neither this queue nor SEND acceptance
//! authorizes storage, UTC, admission or health.
#![forbid(unsafe_code)]
pub const MAX_FRAMES: u8 = 20;
pub const PREACCEPT_TICKS: u64 = 4096;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub bytes: [u8; 8],
    pub issued: u64,
    pub cut: u64,
}
pub struct Reports {
    pending: Option<Entry>,
    created: u8,
    last_attempt: Option<u64>,
    last_clock: u64,
    failed: bool,
}
impl Default for Reports {
    fn default() -> Self {
        Self::new()
    }
}
impl Reports {
    pub const fn new() -> Self {
        Self {
            pending: None,
            created: 0,
            last_attempt: None,
            last_clock: 0,
            failed: false,
        }
    }
    pub fn pending(&self) -> bool {
        self.pending.is_some()
    }
    pub fn failed(&self) -> bool {
        self.failed
    }
    pub fn created(&self) -> u8 {
        self.created
    }
    /// False means the one immutable slot is occupied. True also covers a
    /// recorded diagnostic-only refusal; the operation never waits on logs.
    pub fn push(&mut self, stage: u8, result: u8, progress: u32, issued: u64) -> bool {
        if self.pending.is_some() {
            return false;
        }
        let valid = match (stage, result) {
            (1, 0) => progress == 0,
            (2, 0) => progress > 0 && progress < 7950 && progress.is_multiple_of(512),
            (3, 0) => progress == 7950,
            (4, 0) => progress > 0,
            (5, 1..=6) => progress <= 7950,
            _ => false,
        };
        let cut = issued
            .checked_add(PREACCEPT_TICKS)
            .filter(|v| *v != u64::MAX);
        if !valid || cut.is_none() || self.created == MAX_FRAMES {
            self.failed = true;
            return true;
        }
        let mut bytes = [b'U', b'P', stage, result, 0, 0, 0, 0];
        bytes[4..].copy_from_slice(&progress.to_le_bytes());
        self.created += 1;
        self.pending = Some(Entry {
            bytes,
            issued,
            cut: cut.unwrap(),
        });
        true
    }
    pub fn attempt(&mut self, now: u64) -> Option<Entry> {
        let entry = self.pending?;
        if now < self.last_clock || now < entry.issued || now >= entry.cut || now == u64::MAX {
            self.last_clock = self.last_clock.max(now);
            self.pending = None;
            self.failed = true;
            return None;
        }
        self.last_clock = now;
        if self.last_attempt == Some(now) {
            return None;
        }
        self.last_attempt = Some(now);
        Some(entry)
    }
    /// Actual success is consumed even if preemption crossed the local cut.
    /// Scalar SEND does not carry a Kernel-atomic caller deadline.
    pub fn complete(&mut self, status: u64, value: u64, capability: u64) {
        if self.pending.is_none() {
            return;
        }
        if status == 0 && value == 0 && capability == 0 {
            self.pending = None;
        } else if status != 2 || value != 0 || capability != 0 {
            self.pending = None;
            self.failed = true;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn busy_keeps_exact_frame_and_cut_and_one_attempt_per_actual_tick() {
        let mut r = Reports::new();
        assert!(r.push(1, 0, 0, 7));
        let a = r.attempt(8).unwrap();
        r.complete(2, 0, 0);
        assert!(!r.push(2, 0, 512, 9));
        assert_eq!(r.attempt(8), None);
        assert!(r.pending());
        assert_eq!(r.attempt(9), Some(a));
        assert_eq!(a.cut, 4103);
        r.complete(0, 0, 0);
        assert!(!r.pending());
        assert_eq!(r.created(), 1);
    }
    #[test]
    fn exact_deadline_regression_and_counter_cap_drop_only_diagnostics() {
        for now in [6, 4103, u64::MAX] {
            let mut r = Reports::new();
            r.push(1, 0, 0, 7);
            assert_eq!(r.attempt(now), None);
            assert!(r.failed());
            assert!(!r.pending());
        }
        let mut r = Reports::new();
        for i in 0..MAX_FRAMES {
            assert!(r.push(4, 0, u32::from(i) + 1, u64::from(i)));
            assert!(r.attempt(u64::from(i)).is_some());
            r.complete(0, 0, 0);
        }
        assert!(r.push(4, 0, 21, 21));
        assert_eq!(r.created(), MAX_FRAMES);
        assert!(r.failed());
        assert!(!r.pending());
    }
    #[test]
    fn accepted_send_is_never_replayed_after_crossing_local_cut() {
        let mut r = Reports::new();
        r.push(1, 0, 0, 1);
        let e = r.attempt(4096).unwrap();
        assert_eq!(e.cut, 4097);
        r.complete(0, 0, 0);
        assert_eq!(r.attempt(9000), None);
        assert!(!r.failed());
        r.push(4, 0, 1, 9001);
        assert!(r.attempt(9001).is_some());
        r.complete(2, 0, 9);
        assert!(!r.pending());
        assert!(r.failed());
    }
    #[test]
    fn malformed_shape_overflow_and_clock_rollback_cannot_create_replacement_frames() {
        for (stage, result, progress) in [
            (0, 0, 0),
            (1, 1, 0),
            (2, 0, 513),
            (3, 0, 7949),
            (4, 0, 0),
            (5, 0, 0),
            (5, 7, 0),
        ] {
            let mut r = Reports::new();
            r.push(stage, result, progress, 1);
            assert!(r.failed());
            assert!(!r.pending());
            assert_eq!(r.created(), 0);
        }
        let mut r = Reports::new();
        r.push(1, 0, 0, u64::MAX - 1);
        assert!(r.failed());
        assert_eq!(r.created(), 0);
        let mut r = Reports::new();
        r.push(1, 0, 0, 1);
        r.attempt(20);
        r.complete(2, 0, 0);
        assert_eq!(r.attempt(19), None);
        assert!(r.failed());
        assert!(!r.pending());
    }
}
