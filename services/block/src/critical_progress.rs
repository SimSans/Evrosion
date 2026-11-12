//! Finite critical-initialization window. The caller must derive live state and
//! readiness from actual lifecycle and authenticated events; this clock policy
//! supplies neither authority nor proof that a service initialized correctly.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Waiting,
    Ready,
    MissingProgress,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    ClockReversed,
    Deadline,
}
pub struct Window {
    stop: u64,
    deadline: Option<u64>,
    last: Option<u64>,
}
impl Window {
    pub const fn new(stop: u64) -> Self {
        Self {
            stop,
            deadline: None,
            last: None,
        }
    }
    /// Called immediately after a fresh actual LIVE observation. The first one
    /// anchors64ticks; later polls/events never reset or extend that deadline.
    pub fn observe_live(&mut self, now: u64, critical_ready: bool) -> Result<Decision, Error> {
        if self.last.is_some_and(|previous| now < previous) {
            return Err(Error::ClockReversed);
        }
        self.last = Some(now);
        let deadline = match self.deadline {
            Some(deadline) => deadline,
            None => {
                let deadline = now.checked_add(64).ok_or(Error::Deadline)?.min(self.stop);
                self.deadline = Some(deadline);
                deadline
            }
        };
        if now >= deadline {
            return Ok(Decision::MissingProgress);
        }
        Ok(if critical_ready {
            Decision::Ready
        } else {
            Decision::Waiting
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn silent_live_peer_reaches_failure_at_original_absolute_deadline() {
        let mut window = Window::new(2048);
        for tick in 100..164 {
            assert_eq!(window.observe_live(tick, false), Ok(Decision::Waiting));
        }
        assert_eq!(
            window.observe_live(164, false),
            Ok(Decision::MissingProgress)
        );
        assert_eq!(
            window.observe_live(170, false),
            Ok(Decision::MissingProgress)
        );
    }
    #[test]
    fn timely_ready_can_pass_but_late_ready_cannot_bless_a_peer() {
        let mut timely = Window::new(2048);
        assert_eq!(timely.observe_live(100, false), Ok(Decision::Waiting));
        assert_eq!(timely.observe_live(163, true), Ok(Decision::Ready));
        let mut late = Window::new(2048);
        assert_eq!(late.observe_live(100, false), Ok(Decision::Waiting));
        assert_eq!(late.observe_live(164, true), Ok(Decision::MissingProgress));
    }
    #[test]
    fn retained_clock_cannot_reverse_or_overflow_the_window() {
        let mut window = Window::new(2048);
        assert_eq!(window.observe_live(100, false), Ok(Decision::Waiting));
        assert_eq!(window.observe_live(99, true), Err(Error::ClockReversed));
        assert_eq!(
            Window::new(u64::MAX).observe_live(u64::MAX - 63, false),
            Err(Error::Deadline)
        );
    }
    #[test]
    fn controller_stop_bounds_the_window_without_extending_it() {
        let mut window = Window::new(120);
        assert_eq!(window.observe_live(100, false), Ok(Decision::Waiting));
        assert_eq!(window.observe_live(119, false), Ok(Decision::Waiting));
        assert_eq!(
            window.observe_live(120, false),
            Ok(Decision::MissingProgress)
        );
    }
}
