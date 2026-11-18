//! Finite source-handler responsiveness, not a second authority or health model.
//! Only exact role-bound local events may precede one possibly blocking event.
use crate::desktop_profile::Child;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Work {
    Local,
    MayBlock,
}
/// Call only after the adapter authenticates the current Actor/control and UI
/// context and reserves ordinary output credit. Bytes do not establish identity.
#[inline(never)]
pub fn classify(child: Child, bytes: [u8; 8]) -> Work {
    let local = match child {
        Child::Shell => matches!(&bytes, b"EVSHRDY1" | b"EVSHCRD1"),
        Child::Input => bytes == *b"EVINRDY1",
        Child::File => bytes == *b"EVFLRDY1",
        Child::Block => bytes == *b"EVBLRDY1",
        Child::Display => bytes == *b"EVGDRDY1",
        Child::App => matches!(&bytes, b"EVGARDY1" | b"EVAPCRD1" | b"EVGADON1"),
        #[cfg(feature = "native-network")]
        Child::NetDriver | Child::NetService => false,
    };
    if local { Work::Local } else { Work::MayBlock }
}
/// One ordinary controller turn can dispatch at most four staged entries and
/// at most one possibly blocking source handler. UI debt or any ready producer output closes this budget;
/// clearing a barrier later in the turn cannot reopen it. No pump runs inside I/O.
pub struct Budget {
    remaining: u8,
    stopped: bool,
}
impl Default for Budget {
    fn default() -> Self {
        Self::new()
    }
}
impl Budget {
    pub const fn new() -> Self {
        Self {
            remaining: 4,
            stopped: false,
        }
    }
    pub fn next(&mut self, ui_debt: bool, ready_output: bool) -> bool {
        if ui_debt || ready_output || self.stopped || self.remaining == 0 {
            self.stopped = true;
            return false;
        }
        self.remaining -= 1;
        true
    }
    pub fn completed(&mut self, work: Work) {
        if work == Work::MayBlock {
            self.stopped = true;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_exact_role_local_tokens_can_continue_the_turn() {
        let cases = [
            (Child::Shell, *b"EVSHRDY1"),
            (Child::Shell, *b"EVSHCRD1"),
            (Child::Input, *b"EVINRDY1"),
            (Child::File, *b"EVFLRDY1"),
            (Child::Block, *b"EVBLRDY1"),
            (Child::Display, *b"EVGDRDY1"),
            (Child::App, *b"EVGARDY1"),
            (Child::App, *b"EVAPCRD1"),
            (Child::App, *b"EVGADON1"),
        ];
        for (child, bytes) in cases {
            assert_eq!(classify(child, bytes), Work::Local);
            for foreign in crate::desktop_profile::graph::CHILDREN {
                if foreign != child {
                    assert_eq!(classify(foreign, bytes), Work::MayBlock);
                }
            }
            let mut unknown = bytes;
            unknown[7] ^= 1;
            assert_eq!(classify(child, unknown), Work::MayBlock);
        }
        for bytes in [
            *b"ND\0\0\0\0\0\0",
            *b"NT\x01\x01\0\0\0\x01",
            *b"EVOPEN01",
            *b"INVALID!",
        ] {
            assert_eq!(classify(Child::App, bytes), Work::MayBlock);
        }
    }
    #[test]
    fn four_locals_or_one_possibly_blocking_transition_close_the_turn() {
        let mut b = Budget::new();
        for _ in 0..4 {
            assert!(b.next(false, false));
            b.completed(Work::Local);
        }
        assert!(!b.next(false, false));
        assert!(!b.next(false, false));
        let mut b = Budget::new();
        assert!(b.next(false, false));
        b.completed(Work::Local);
        assert!(b.next(false, false));
        b.completed(Work::MayBlock);
        assert!(!b.next(false, false));
        let mut b = Budget::new();
        assert!(b.next(false, false));
        b.completed(Work::MayBlock);
        assert!(!b.next(false, false));
    }
    #[test]
    #[cfg(feature = "desktop-root")]
    fn queued_control_keeps_its_512_cut_ahead_of_an_835_tick_store_handler() {
        use crate::desktop_outbox::{Kind, Outbox, Outcome, Peer, Target};
        let target = Target {
            peer: Peer::Shell,
            endpoint: 7,
            control: 90,
            process: 20,
            thread: 21,
        };
        let mut out = Outbox::new();
        let mut turn = Budget::new();
        assert!(turn.next(false, out.pending()));
        // Genuine local AppDone publishes its ordinary finite Shell control.
        out.begin([None, Some(target)], [0, 1]).unwrap();
        let ticket = out.reserved(target).unwrap();
        out.publish(
            ticket,
            ev_desktop::protocol::RootControl::AppRestored(1)
                .encode()
                .unwrap(),
            100 + 512,
            Kind::Control,
        )
        .unwrap();
        out.end();
        turn.completed(Work::Local);
        assert!(
            !turn.next(false, out.pending()),
            "queued output stops before NT/Store"
        );
        let entry = out.next_attempt().unwrap();
        assert_eq!(entry.ticket, ticket);
        assert!(100 < entry.deadline);
        out.finish(ticket, Outcome::Accepted).unwrap();
        assert_eq!(out.stats().accepted, 1);
        let mut waiting = Budget::new();
        assert!(
            !waiting.next(true, out.pending()),
            "real UI debt still blocks Store"
        );
        // Only the actual matching ACK would clear debt. A later ordinary turn
        // can then enter its single Store handler, even if that lasts835 ticks.
        let mut settled = Budget::new();
        assert!(settled.next(false, out.pending()));
        settled.completed(Work::MayBlock);
        let after_store = 101 + 835;
        assert!(after_store >= entry.deadline);
        assert!(!out.pending());
        assert!(!settled.next(false, out.pending()));
        assert!(
            out.next_attempt().is_none(),
            "accepted control is never replayed"
        );
    }
    #[test]
    fn preexisting_ready_output_closes_turn_and_reservation_alone_does_not() {
        use crate::desktop_outbox::{Kind, Outbox, Peer, Target};
        let target = Target {
            peer: Peer::App,
            endpoint: 8,
            control: 91,
            process: 22,
            thread: 23,
        };
        let mut out = Outbox::new();
        out.begin([Some(target), None], [1, 0]).unwrap();
        let ticket = out.reserved(target).unwrap();
        assert!(!out.pending());
        out.publish(ticket, [2; 8], 512, Kind::Data).unwrap();
        out.end();
        let mut b = Budget::new();
        assert!(!b.next(false, out.pending()));
        out.cancel_target(target).unwrap();
        assert!(!out.pending());
        assert!(!b.next(false, out.pending()));
    }
    #[test]
    fn settlement_debt_stops_without_reopening_the_current_budget() {
        let mut b = Budget::new();
        assert!(b.next(false, false));
        b.completed(Work::Local);
        assert!(!b.next(true, false));
        assert!(!b.next(false, false));
        let mut next_turn = Budget::new();
        assert!(next_turn.next(false, false));
    }
}
