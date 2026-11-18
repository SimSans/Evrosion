//! Negative-only actual guard returns. Text, guest counts and reaching a
//! deadline alone cannot enter this sealed two-call accounting state.
use ev_kernel::rpc::Status;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Call {
    pub epoch: u64,
    pub id: u64,
    pub caller: usize,
    pub callee: usize,
    pub wire: usize,
    pub ticket: u64,
    pub deadline: u64,
    pub request: u64,
}
pub(super) struct Returned {
    captured: Option<[Call; 2]>,
    done: u8,
    peer_died: u8,
    required: u8,
}
impl Returned {
    pub const fn new() -> Self {
        Self {
            captured: None,
            done: 0,
            peer_died: 0,
            required: 0,
        }
    }
    pub fn capture(&mut self, inner: Call, outer: Call, cut: u64, victim: usize) -> bool {
        let required = match victim {
            7 => 1,
            8 => 2,
            _ => return false,
        };
        if self.captured.is_some()
            || self.done != 0
            || inner.epoch == 0
            || inner.epoch != outer.epoch
            || inner.id == 0
            || outer.id == 0
            || inner.id == outer.id
            || inner.ticket == 0
            || outer.ticket == 0
            || (inner.caller, inner.callee, inner.wire) != (8, 7, 16)
            || (outer.caller, outer.callee, outer.wire) != (0, 8, 17)
            || inner.deadline > outer.deadline
            || outer.deadline > cut
        {
            return false;
        }
        self.captured = Some([inner, outer]);
        self.required = required;
        true
    }
    /// Called only after actual canonical Pending removal and the guarded
    /// owner is no longer waiting. Deadline/Cancelled count as no-ACK only at
    /// that real quiescence boundary, just like PeerDied; reaching time alone
    /// cannot call this path. An immutable terminal is consumed exactly once.
    pub fn record(&mut self, call: Call, status: Status) -> bool {
        if status == Status::Ok {
            return false;
        }
        let Some(captured) = self.captured else {
            return false;
        };
        let Some(index) = captured.iter().position(|c| *c == call) else {
            return false;
        };
        let bit = 1 << index;
        if self.done & bit != 0 {
            return false;
        }
        self.done |= bit;
        if status == Status::PeerDied {
            self.peer_died |= bit;
        }
        true
    }
    /// Ordinary no-injection cases retain exact calls==replies. An injected
    /// case cannot promote any count until its actual stopped callee has the
    /// mandatory canonical PeerDied return (inner Driver / outer Service).
    pub fn completed_count(&self) -> Option<u64> {
        if self.captured.is_none() {
            Some(0)
        } else if self.peer_died & self.required != 0 {
            Some(u64::from(self.done.count_ones()))
        } else {
            None
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn calls() -> [Call; 2] {
        [
            Call {
                epoch: 501,
                id: 200,
                caller: 8,
                callee: 7,
                wire: 16,
                ticket: 2,
                deadline: 900,
                request: 6,
            },
            Call {
                epoch: 501,
                id: 199,
                caller: 0,
                callee: 8,
                wire: 17,
                ticket: 1,
                deadline: 1000,
                request: 10,
            },
        ]
    }
    #[test]
    fn exact_canonical_non_ok_returns_count_once_only_after_mandatory_peerdied() {
        let [inner, outer] = calls();
        for victim in [7, 8] {
            for optional in [
                Status::PeerDied,
                Status::DeadlineExceeded,
                Status::Cancelled,
            ] {
                let mut r = Returned::new();
                assert_eq!(r.completed_count(), Some(0));
                assert!(!r.record(inner, optional));
                assert!(r.capture(inner, outer, 1500, victim));
                assert!(!r.capture(inner, outer, 1500, victim));
                assert_eq!(r.completed_count(), None);
                let (mandatory, other) = if victim == 7 {
                    (inner, outer)
                } else {
                    (outer, inner)
                };
                assert!(!r.record(mandatory, Status::Ok));
                assert!(r.record(other, optional));
                assert_eq!(r.completed_count(), None);
                assert!(!r.record(other, optional));
                assert!(r.record(mandatory, Status::PeerDied));
                assert_eq!(r.completed_count(), Some(2));
                assert!(!r.record(mandatory, Status::PeerDied));
                assert_eq!(r.completed_count(), Some(2));
            }
        }
    }
    #[test]
    fn one_return_positive_and_terminal_replay_cannot_upgrade_missing_mandatory_death() {
        let [inner, outer] = calls();
        for victim in [7, 8] {
            let mandatory = if victim == 7 { inner } else { outer };
            let mut r = Returned::new();
            assert!(r.capture(inner, outer, 1500, victim));
            assert!(r.record(mandatory, Status::PeerDied));
            assert_eq!(r.completed_count(), Some(1));
            for wrong in [Status::DeadlineExceeded, Status::Cancelled] {
                let mut r = Returned::new();
                assert!(r.capture(inner, outer, 1500, victim));
                assert!(r.record(mandatory, wrong));
                assert_eq!(r.completed_count(), None);
                assert!(!r.record(mandatory, Status::PeerDied));
                assert_eq!(r.completed_count(), None);
            }
        }
    }
    #[test]
    fn foreign_call_epoch_pair_ticket_cut_or_request_cannot_inflate_actual_count() {
        let [inner, outer] = calls();
        let mut r = Returned::new();
        assert!(r.capture(inner, outer, 1500, 7));
        let mutations = [
            Call {
                epoch: 502,
                ..inner
            },
            Call { id: 201, ..inner },
            Call { caller: 0, ..inner },
            Call { callee: 8, ..inner },
            Call { wire: 17, ..inner },
            Call { ticket: 3, ..inner },
            Call {
                deadline: 901,
                ..inner
            },
            Call {
                request: 7,
                ..inner
            },
        ];
        for bad in mutations {
            for status in [
                Status::PeerDied,
                Status::DeadlineExceeded,
                Status::Cancelled,
            ] {
                assert!(!r.record(bad, status));
                assert_eq!(r.completed_count(), None);
            }
        }
        assert!(r.record(inner, Status::PeerDied));
        assert_eq!(r.completed_count(), Some(1));
    }
    #[test]
    fn wrong_capture_relation_victim_or_escaped_cut_never_arms_counting() {
        let [inner, outer] = calls();
        for (i, o, cut, victim) in [
            (inner, outer, 999, 7),
            (
                Call {
                    epoch: 502,
                    ..inner
                },
                outer,
                1500,
                7,
            ),
            (
                Call {
                    id: outer.id,
                    ..inner
                },
                outer,
                1500,
                7,
            ),
            (
                Call {
                    deadline: 1001,
                    ..inner
                },
                outer,
                1500,
                7,
            ),
            (Call { wire: 17, ..inner }, outer, 1500, 7),
            (inner, Call { caller: 8, ..outer }, 1500, 7),
            (inner, outer, 1500, 0),
        ] {
            let mut r = Returned::new();
            assert!(!r.capture(i, o, cut, victim));
            assert!(!r.record(inner, Status::PeerDied));
            assert_eq!(r.completed_count(), Some(0));
        }
    }
}
