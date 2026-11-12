//! Host-monotonic bounds, never guest-clock or physical-hardware latency claims.
//! Integrate timestamps at actual QEMU spawn, bounded serial reads and QMP calls.
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bracket {
    pub earliest_ns: u64,
    pub latest_ns: u64,
}
impl Bracket {
    pub fn new(earliest_ns: u64, latest_ns: u64) -> Result<Self, Error> {
        if earliest_ns > latest_ns {
            return Err(Error::Order);
        }
        Ok(Self {
            earliest_ns,
            latest_ns,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Order,
    State,
    Bound,
    Incomplete,
    Overflow,
}
#[derive(Clone, Copy, Debug)]
struct Pause {
    sent: u64,
    stopped: u64,
    resume_sent: u64,
    running: u64,
}
#[derive(Clone, Copy, Debug)]
enum State {
    Running,
    Stopping {
        sent: u64,
    },
    Stopped {
        sent: u64,
        stopped: u64,
    },
    Resuming {
        sent: u64,
        stopped: u64,
        resume_sent: u64,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Timing {
    pub wall_min_ns: u64,
    pub wall_max_ns: u64,
    /// Running host duration after excluding the conservatively bracketed
    /// QMP-stop intervals. Includes running-VM host scheduling/TCG overhead.
    pub active_min_ns: u64,
    pub active_max_ns: u64,
    pub excluded_pause_min_ns: u64,
    pub excluded_pause_max_ns: u64,
}
pub struct Ledger {
    last: u64,
    state: State,
    pauses: Vec<Pause>,
}
impl Default for Ledger {
    fn default() -> Self {
        Self::new()
    }
}
impl Ledger {
    pub fn new() -> Self {
        Self {
            last: 0,
            state: State::Running,
            pauses: Vec::new(),
        }
    }
    fn check(&self, at: u64) -> Result<(), Error> {
        if at < self.last {
            Err(Error::Order)
        } else {
            Ok(())
        }
    }
    pub fn stop_sent(&mut self, at: u64) -> Result<(), Error> {
        self.check(at)?;
        if !matches!(self.state, State::Running) {
            return Err(Error::State);
        }
        if self.pauses.len() == 128 {
            return Err(Error::Bound);
        }
        self.state = State::Stopping { sent: at };
        self.last = at;
        Ok(())
    }
    /// Call only after a successful query-status confirms !running + paused;
    /// the stop-command acknowledgement alone is not a timing observation.
    pub fn stopped_confirmed(&mut self, at: u64) -> Result<(), Error> {
        self.check(at)?;
        let State::Stopping { sent } = self.state else {
            return Err(Error::State);
        };
        self.state = State::Stopped { sent, stopped: at };
        self.last = at;
        Ok(())
    }
    pub fn resume_sent(&mut self, at: u64) -> Result<(), Error> {
        self.check(at)?;
        let State::Stopped { sent, stopped } = self.state else {
            return Err(Error::State);
        };
        self.state = State::Resuming {
            sent,
            stopped,
            resume_sent: at,
        };
        self.last = at;
        Ok(())
    }
    /// Call only after query-status confirms running; retain the corresponding
    /// QMP transcript and timestamp brackets in the immutable run record.
    pub fn running_confirmed(&mut self, at: u64) -> Result<(), Error> {
        self.check(at)?;
        let State::Resuming {
            sent,
            stopped,
            resume_sent,
        } = self.state
        else {
            return Err(Error::State);
        };
        self.pauses.push(Pause {
            sent,
            stopped,
            resume_sent,
            running: at,
        });
        self.state = State::Running;
        self.last = at;
        Ok(())
    }
    pub fn measure(&self, begin: Bracket, end: Bracket) -> Result<Timing, Error> {
        if !matches!(self.state, State::Running) {
            return Err(Error::Incomplete);
        }
        if begin.earliest_ns > begin.latest_ns
            || end.earliest_ns > end.latest_ns
            || begin.earliest_ns > end.earliest_ns
            || begin.latest_ns > end.latest_ns
        {
            return Err(Error::Order);
        }
        let wall_min_ns = end.earliest_ns.saturating_sub(begin.latest_ns);
        let wall_max_ns = end.latest_ns - begin.earliest_ns;
        let mut pause_max = 0u64;
        let mut pause_min = 0u64;
        for pause in &self.pauses {
            // Largest possible pause overlap uses the outer observation range;
            // guaranteed overlap uses the inner range. Open/failed pauses do
            // not silently become zero and cannot produce accepted metrics.
            pause_max = pause_max
                .checked_add(overlap(
                    begin.earliest_ns,
                    end.latest_ns,
                    pause.sent,
                    pause.running,
                ))
                .ok_or(Error::Overflow)?;
            pause_min = pause_min
                .checked_add(overlap(
                    begin.latest_ns,
                    end.earliest_ns,
                    pause.stopped,
                    pause.resume_sent,
                ))
                .ok_or(Error::Overflow)?;
        }
        Ok(Timing {
            wall_min_ns,
            wall_max_ns,
            active_min_ns: wall_min_ns.saturating_sub(pause_max),
            active_max_ns: wall_max_ns.checked_sub(pause_min).ok_or(Error::Order)?,
            excluded_pause_min_ns: pause_min,
            excluded_pause_max_ns: pause_max,
        })
    }
}
fn overlap(a: u64, b: u64, c: u64, d: u64) -> u64 {
    b.min(d).saturating_sub(a.max(c))
}

pub fn elapsed_ns(origin: Instant, now: Instant) -> Result<u64, Error> {
    let elapsed = now.checked_duration_since(origin).ok_or(Error::Order)?;
    u64::try_from(elapsed.as_nanos()).map_err(|_| Error::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn b(lo: u64, hi: u64) -> Bracket {
        Bracket::new(lo, hi).unwrap()
    }
    fn pause(l: &mut Ledger, a: u64, b: u64, c: u64, d: u64) {
        l.stop_sent(a).unwrap();
        l.stopped_confirmed(b).unwrap();
        l.resume_sent(c).unwrap();
        l.running_confirmed(d).unwrap();
    }
    #[test]
    fn exact_no_pause_interval() {
        let t = Ledger::new().measure(b(10, 10), b(110, 110)).unwrap();
        assert_eq!((t.active_min_ns, t.active_max_ns), (100, 100));
    }
    #[test]
    fn pause_ack_uncertainty_is_retained() {
        let mut l = Ledger::new();
        pause(&mut l, 20, 25, 65, 70);
        let t = l.measure(b(0, 0), b(100, 100)).unwrap();
        assert_eq!((t.active_min_ns, t.active_max_ns), (50, 60));
        assert_eq!((t.excluded_pause_min_ns, t.excluded_pause_max_ns), (40, 50));
    }
    #[test]
    fn serial_poll_uncertainty_is_retained() {
        let t = Ledger::new().measure(b(0, 4), b(100, 107)).unwrap();
        assert_eq!((t.active_min_ns, t.active_max_ns), (96, 107));
    }
    #[test]
    fn partially_overlapping_pause_is_clipped() {
        let mut l = Ledger::new();
        pause(&mut l, 20, 25, 65, 70);
        let t = l.measure(b(30, 35), b(80, 85)).unwrap();
        assert_eq!((t.active_min_ns, t.active_max_ns), (5, 25));
    }
    #[test]
    fn pause_outside_metric_does_not_change_it() {
        let mut l = Ledger::new();
        pause(&mut l, 1, 2, 8, 9);
        let t = l.measure(b(20, 20), b(100, 100)).unwrap();
        assert_eq!((t.active_min_ns, t.active_max_ns), (80, 80));
    }
    #[test]
    fn incomplete_pause_and_replayed_transition_fail() {
        let mut l = Ledger::new();
        l.stop_sent(10).unwrap();
        assert_eq!(l.stop_sent(11), Err(Error::State));
        assert_eq!(l.measure(b(0, 0), b(20, 20)), Err(Error::Incomplete));
        l.stopped_confirmed(12).unwrap();
        assert_eq!(l.running_confirmed(13), Err(Error::State));
        l.resume_sent(14).unwrap();
        l.running_confirmed(15).unwrap();
        assert_eq!(l.running_confirmed(16), Err(Error::State));
    }
    #[test]
    fn decreasing_timestamp_does_not_mutate_state() {
        let mut l = Ledger::new();
        l.stop_sent(10).unwrap();
        assert_eq!(l.stopped_confirmed(9), Err(Error::Order));
        l.stopped_confirmed(11).unwrap();
        l.resume_sent(12).unwrap();
        l.running_confirmed(13).unwrap();
    }
    #[test]
    fn bounded_multiple_disjoint_pauses() {
        let mut l = Ledger::new();
        for n in 0..128 {
            pause(&mut l, n * 10, n * 10 + 1, n * 10 + 2, n * 10 + 3);
        }
        assert_eq!(l.stop_sent(1280), Err(Error::Bound));
        let t = l.measure(b(0, 0), b(1280, 1280)).unwrap();
        assert_eq!((t.active_min_ns, t.active_max_ns), (896, 1152));
    }
    #[test]
    fn reversed_or_unordered_event_brackets_fail() {
        assert_eq!(Bracket::new(2, 1), Err(Error::Order));
        assert_eq!(
            Ledger::new().measure(b(10, 20), b(9, 21)),
            Err(Error::Order)
        );
        assert_eq!(
            Ledger::new().measure(b(10, 20), b(11, 19)),
            Err(Error::Order)
        );
    }
    #[test]
    fn overlapping_poll_brackets_report_zero_lower_bound() {
        let t = Ledger::new().measure(b(0, 20), b(10, 30)).unwrap();
        assert_eq!((t.active_min_ns, t.active_max_ns), (0, 30));
    }
    #[test]
    fn real_monotonic_origin_and_reversed_origin() {
        let a = Instant::now();
        let b = a + std::time::Duration::from_nanos(50);
        assert_eq!(elapsed_ns(a, b), Ok(50));
        assert_eq!(elapsed_ns(b, a), Err(Error::Order));
    }
}
