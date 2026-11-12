//! Monotonic tick deadlines; no wall time, sentinel infinity or wrapping math.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadline(u64);
impl Deadline {
    pub fn after(now: u64, ticks: u64) -> Option<Self> {
        now.checked_add(ticks).map(Self)
    }
    pub fn reached(self, now: u64) -> bool {
        now >= self.0
    }
    pub fn tick(self) -> u64 {
        self.0
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct ClockStalled;
/// Bootstrap-only polling fallback. The same absolute deadline survives every
/// retry; even a failed clock cannot cause an unbounded number of reads.
pub fn wait_bounded(
    deadline: Deadline,
    polls: u32,
    mut now: impl FnMut() -> u64,
) -> Result<u64, ClockStalled> {
    for _ in 0..polls {
        let tick = now();
        if deadline.reached(tick) {
            return Ok(tick);
        }
        core::hint::spin_loop();
    }
    Err(ClockStalled)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deadlines_preserve_absolute_boundaries_and_reject_overflow() {
        let deadline = Deadline::after(100, 8).unwrap();
        assert_eq!(deadline.tick(), 108);
        assert!(!deadline.reached(107));
        assert!(deadline.reached(108));
        assert!(deadline.reached(109));
        assert!(Deadline::after(100, 0).unwrap().reached(100));
        assert!(Deadline::after(u64::MAX, 1).is_none());
        assert_eq!(Deadline::after(u64::MAX - 1, 1).unwrap().tick(), u64::MAX);
    }
    #[test]
    fn stalled_clock_has_exact_poll_bound_and_retries_cannot_extend_deadline() {
        let deadline = Deadline::after(5, 3).unwrap();
        let mut reads = 0;
        assert_eq!(
            wait_bounded(deadline, 7, || {
                reads += 1;
                5
            }),
            Err(ClockStalled)
        );
        assert_eq!(reads, 7);
        assert_eq!(
            wait_bounded(deadline, 0, || panic!("zero budget must not poll")),
            Err(ClockStalled)
        );
        assert_eq!(wait_bounded(deadline, 1, || 8), Ok(8));
        let mut tick = 5;
        assert_eq!(
            wait_bounded(deadline, 4, || {
                let before = tick;
                tick += 1;
                before
            }),
            Ok(8)
        );
    }
}
