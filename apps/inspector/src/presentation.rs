//! Bound automatic metric repaint demand behind the actual prior Present.
//! This changes only idle UI scheduling, never a syscall deadline or loan.
use ev_userspace_contract::root_v5::surface::Header;

pub const STATS_IDLE_TICKS: u64 = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Desire {
    Stats,
    Urgent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unavailable;

pub struct Presentation {
    desired: Option<Desire>,
    in_flight: Option<Header>,
    accepted: Option<Header>,
    next_stats: u64,
    last_clock: u64,
    fenced: bool,
}

impl Default for Presentation {
    fn default() -> Self {
        Self::new()
    }
}

impl Presentation {
    pub const fn new() -> Self {
        Self {
            desired: None,
            in_flight: None,
            accepted: None,
            next_stats: 0,
            last_clock: 0,
            fenced: false,
        }
    }

    pub fn stats(&mut self) {
        if !self.fenced && self.desired.is_none() {
            self.desired = Some(Desire::Stats);
        }
    }

    /// Coalesce at most one scene/control/explicit-refresh desire. A pending
    /// exact Present remains held, including across owner or scene changes.
    pub fn urgent(&mut self) {
        if !self.fenced {
            self.desired = Some(Desire::Urgent);
        }
    }

    pub const fn pending(&self) -> bool {
        self.desired.is_some() || self.in_flight.is_some() || self.fenced
    }

    fn clock(&mut self, now: u64) -> bool {
        if now == u64::MAX || now < self.last_clock {
            self.fenced = true;
        } else {
            self.last_clock = now;
        }
        !self.fenced
    }

    pub fn ready(&mut self, now: u64) -> bool {
        self.clock(now)
            && self.in_flight.is_none()
            && self
                .desired
                .is_some_and(|desire| desire == Desire::Urgent || now >= self.next_stats)
    }

    /// Native code supplies the exact immutable header immediately before its
    /// one RPC. No paint, replacement or second begin may cross this credit.
    pub fn begin(&mut self, now: u64, header: Header) -> Result<(), Unavailable> {
        if !self.ready(now) {
            return Err(Unavailable);
        }
        self.desired = None;
        self.in_flight = Some(header);
        Ok(())
    }

    /// Only the native adapter's matching actual completed reply calls this.
    /// A known rejection permits a new scene, never an accepted-frame claim.
    pub fn completed(
        &mut self,
        header: Header,
        accepted: bool,
        now: u64,
    ) -> Result<(), Unavailable> {
        if self.in_flight != Some(header) || !self.clock(now) {
            self.fenced = true;
            return Err(Unavailable);
        }
        if accepted {
            let Some(next) = now.checked_add(STATS_IDLE_TICKS).filter(|n| *n != u64::MAX) else {
                self.fenced = true;
                return Err(Unavailable);
            };
            self.accepted = Some(header);
            self.next_stats = next;
        } else {
            self.urgent();
        }
        self.in_flight = None;
        Ok(())
    }

    /// Unknown completion retains the exact original header forever. This
    /// reducer cannot authorize reuse, retry, debt clearance or reconstruction.
    pub fn uncertain(&mut self) {
        self.fenced = true;
    }

    pub const fn accepted(&self) -> Option<Header> {
        self.accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ev_userspace_contract::root_v5::surface::Producer;

    fn header(view: u64) -> Header {
        Header {
            producer: Producer::Application,
            instance: 4,
            process: 12,
            thread: 13,
            incarnation: 1,
            surface_object: 14,
            surface_generation: 12,
            frame: view + 1,
            view_revision: view,
            model_revision: 3,
            width: 320,
            height: 180,
            stride_bytes: 1280,
            payload_bytes: 230400,
            mapping_epoch: 1,
            protected_scope_nonce: 0,
        }
    }

    #[test]
    fn automatic_updates_coalesce_without_renewing_the_original_idle_due() {
        let mut p = Presentation::new();
        p.stats();
        p.begin(10, header(1)).unwrap();
        p.completed(header(1), true, 100).unwrap();
        for now in [101, 500, 1000, 2000, 2147] {
            p.stats();
            assert!(!p.ready(now));
            assert_eq!(p.accepted(), Some(header(1)));
        }
        assert!(p.ready(2148));
        p.begin(2148, header(6)).unwrap();
        p.completed(header(6), true, 2200).unwrap();
        assert_eq!(p.accepted(), Some(header(6)));
        assert!(!p.pending());
    }

    #[test]
    fn refresh_and_new_scene_cannot_erase_an_exact_in_flight_header() {
        let mut p = Presentation::new();
        p.stats();
        p.begin(10, header(1)).unwrap();
        let mut new = header(2);
        new.model_revision += 1;
        new.process += 1;
        for now in 11..20 {
            p.urgent();
            assert!(!p.ready(now));
            assert!(p.begin(now, new).is_err());
            assert_eq!(p.in_flight, Some(header(1)));
        }
        p.completed(header(1), true, 20).unwrap();
        assert!(p.ready(20));
        p.begin(20, new).unwrap();
        assert_eq!(p.in_flight, Some(new));
        assert_eq!(p.accepted(), Some(header(1)));
    }

    #[test]
    fn unknown_or_mismatched_completion_permanently_retains_original_credit() {
        for mismatch in [false, true] {
            let mut p = Presentation::new();
            p.stats();
            p.begin(10, header(1)).unwrap();
            if mismatch {
                assert!(p.completed(header(2), true, 11).is_err());
            } else {
                p.uncertain();
            }
            p.urgent();
            assert!(!p.ready(100_000));
            assert_eq!(p.in_flight, Some(header(1)));
            assert_eq!(p.accepted(), None);
            assert!(p.completed(header(1), true, 100_000).is_err());
            assert_eq!(p.in_flight, Some(header(1)));
        }
    }

    #[test]
    fn known_refusal_is_not_acceptance_and_clock_failure_never_rearms() {
        let mut p = Presentation::new();
        p.stats();
        p.begin(10, header(1)).unwrap();
        p.completed(header(1), false, 20).unwrap();
        assert_eq!(p.accepted(), None);
        assert!(p.ready(20));
        p.begin(20, header(2)).unwrap();
        assert!(p.completed(header(2), true, 19).is_err());
        assert_eq!(p.in_flight, Some(header(2)));
        assert!(!p.ready(30));
        let mut overflow = Presentation::new();
        overflow.stats();
        overflow.begin(u64::MAX - 100, header(1)).unwrap();
        assert!(overflow.completed(header(1), true, u64::MAX - 99).is_err());
        assert_eq!(overflow.in_flight, Some(header(1)));
    }
}
