//! Protocol-only ev.app.private-data@1 client. Bytes and peer handles allocate
//! no namespace. Root independently binds verified AppId/manifest permission to
//! the actual admitted Process/Thread and replies after durable Set + readback.
//! ND has no nonce: never replace its provider until old accepted requests and
//! RootControl replies have actually drained. This client has no reset/rebind.
#![forbid(unsafe_code)]
use crate::native::SelfFacts;
use core::{
    marker::PhantomData,
    sync::atomic::{AtomicBool, Ordering},
};
use ev_userspace_contract::app_data as wire;

static CLAIMED: AtomicBool = AtomicBool::new(false);

/// Captured once from the selected FileApp's original validated bootstrap.
/// This is an immutable transport peer, not an AppPrivateData permission.
pub struct Peer {
    facts: SelfFacts,
    events: u64,
    control: u64,
    _one_thread: PhantomData<*mut ()>,
}
impl Peer {
    pub(crate) const fn admitted(facts: SelfFacts, events: u64, control: u64) -> Self {
        Self {
            facts,
            events,
            control,
            _one_thread: PhantomData,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Initial,
    Queued,
    AwaitReply,
    Read,
    Set,
    Finished,
    Refused,
    Unsent,
    Uncertain,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acceptance {
    NotAccepted,
    Accepted,
    Unknown,
    Completed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retained {
    pub request: wire::Request,
    pub frame: [u8; wire::WIRE_BYTES],
    pub deadline: u64,
    pub acceptance: Acceptance,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Claimed,
    Peer,
    State,
    Clock,
    Deadline,
    Unchanged,
    Rejected,
    Uncertain,
    Protocol(wire::ClientError),
}
/// Only WouldBlock proves no acceptance and permits another identical send.
/// Unknown includes any transport error whose acceptance cannot be excluded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendResult {
    Accepted,
    WouldBlock,
    Rejected,
    Unknown,
}
pub trait Sender {
    /// The native adapter must report the actual result of sending these exact
    /// bytes on the captured events capability, under the unchanged deadline.
    /// A model implementation establishes protocol behavior, not authority.
    fn try_send(&mut self, events: u64, frame: [u8; 8], deadline: u64) -> SendResult;
}

/// One move-only session for this actual process incarnation. Dropping it never
/// releases the permanent claim, proves reply drain or permits reconstruction.
pub struct Client {
    peer: Peer,
    generated: wire::Client,
    phase: Phase,
    deadline: u64,
    last_clock: u64,
    retained: Option<Retained>,
    value: Option<u32>,
    refusal: Option<wire::Refusal>,
}
impl Client {
    pub fn claim(peer: Peer, now: u64, deadline: u64) -> Result<Self, Error> {
        Self::claim_once(peer, now, deadline, &CLAIMED)
    }
    fn claim_once(
        peer: Peer,
        now: u64,
        deadline: u64,
        claimed: &AtomicBool,
    ) -> Result<Self, Error> {
        if peer.facts.process == 0
            || peer.facts.thread == 0
            || peer.events == 0
            || peer.control == 0
            || peer.events == peer.control
        {
            return Err(Error::Peer);
        }
        if now == u64::MAX || deadline == u64::MAX || now >= deadline {
            return Err(Error::Deadline);
        }
        claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::Claimed)?;
        Ok(Self {
            peer,
            generated: wire::Client::new(),
            phase: Phase::Initial,
            deadline,
            last_clock: now,
            retained: None,
            value: None,
            refusal: None,
        })
    }
    pub const fn phase(&self) -> Phase {
        self.phase
    }
    pub const fn retained(&self) -> Option<Retained> {
        self.retained
    }
    pub const fn refusal(&self) -> Option<wire::Refusal> {
        self.refusal
    }
    pub const fn confirmed_value(&self) -> Option<u32> {
        if matches!(self.phase, Phase::Read | Phase::Set | Phase::Finished) {
            self.value
        } else {
            None
        }
    }
    fn live(&mut self, now: u64) -> Result<(), Error> {
        if now == u64::MAX || now < self.last_clock {
            self.phase = Phase::Uncertain;
            return Err(Error::Clock);
        }
        self.last_clock = now;
        if now >= self.deadline {
            self.phase = if self
                .retained
                .is_some_and(|r| matches!(r.acceptance, Acceptance::Accepted | Acceptance::Unknown))
            {
                Phase::Uncertain
            } else {
                Phase::Unsent
            };
            return Err(Error::Deadline);
        }
        Ok(())
    }
    fn queue(&mut self, request: wire::Request, frame: [u8; 8]) {
        self.retained = Some(Retained {
            request,
            frame,
            deadline: self.deadline,
            acceptance: Acceptance::NotAccepted,
        });
        self.phase = Phase::Queued;
    }
    pub fn begin_read(&mut self, now: u64) -> Result<(), Error> {
        if self.phase != Phase::Initial {
            return Err(Error::State);
        }
        self.live(now)?;
        let frame = self.generated.begin_read().map_err(Error::Protocol)?;
        self.queue(wire::Request::Read, frame);
        Ok(())
    }
    pub fn begin_set(&mut self, value: u32, now: u64) -> Result<(), Error> {
        if self.phase != Phase::Read {
            return Err(Error::State);
        }
        if self.value == Some(value) {
            return Err(Error::Unchanged);
        }
        self.live(now)?;
        let frame = self.generated.begin_set(value).map_err(Error::Protocol)?;
        self.queue(wire::Request::SetValue(value), frame);
        Ok(())
    }
    pub fn try_send(&mut self, now: u64, sender: &mut impl Sender) -> Result<SendResult, Error> {
        if self.phase != Phase::Queued {
            return Err(Error::State);
        }
        self.live(now)?;
        let retained = self.retained.as_mut().ok_or(Error::State)?;
        match sender.try_send(self.peer.events, retained.frame, retained.deadline) {
            SendResult::WouldBlock => Ok(SendResult::WouldBlock),
            SendResult::Accepted => {
                retained.acceptance = Acceptance::Accepted;
                self.phase = Phase::AwaitReply;
                Ok(SendResult::Accepted)
            }
            SendResult::Rejected => {
                self.phase = Phase::Unsent;
                Err(Error::Rejected)
            }
            SendResult::Unknown => {
                retained.acceptance = Acceptance::Unknown;
                self.phase = Phase::Uncertain;
                Err(Error::Uncertain)
            }
        }
    }
    /// Call only for ND frames actually received on the selected RootControl
    /// receiver. Dispatch unrelated UI/A1 protocols separately. receiver is the
    /// actual receive handle, never an ID taken from a packet. The native
    /// bootstrap/transport boundary must preserve that provenance.
    pub fn observe_root_control(
        &mut self,
        receiver: u64,
        bytes: &[u8],
        capabilities: usize,
        now: u64,
    ) -> Result<wire::Response, Error> {
        if receiver != self.peer.control {
            return Err(Error::Peer);
        }
        if self.phase != Phase::AwaitReply {
            if matches!(self.phase, Phase::Queued | Phase::Read | Phase::Set) {
                self.phase = Phase::Uncertain;
            }
            return Err(Error::State);
        }
        self.live(now)?;
        let response = self
            .generated
            .accept(bytes, capabilities)
            .map_err(|error| {
                self.phase = Phase::Uncertain;
                Error::Protocol(error)
            })?;
        match response {
            wire::Response::Value(value) => {
                self.phase = match self.retained.ok_or(Error::State)?.request {
                    wire::Request::Read => Phase::Read,
                    wire::Request::SetValue(_) => Phase::Set,
                };
                self.value = Some(value);
                self.retained.as_mut().ok_or(Error::State)?.acceptance = Acceptance::Completed;
            }
            wire::Response::Refused(reason) => {
                self.phase = Phase::Refused;
                self.refusal = Some(reason);
            }
        }
        Ok(response)
    }
    pub fn poll_deadline(&mut self, now: u64) -> Result<(), Error> {
        if matches!(self.phase, Phase::Queued | Phase::AwaitReply) {
            self.live(now)
        } else {
            Err(Error::State)
        }
    }
    /// A correlated Root Value is only the protocol completion. The real Root
    /// owner must have committed and independently read back a Set before it
    /// sends Value; these client bytes cannot establish target durability.
    pub fn finish(&mut self) -> Result<u32, Error> {
        if !matches!(self.phase, Phase::Read | Phase::Set) {
            return Err(Error::State);
        }
        let value = self.generated.finish().map_err(Error::Protocol)?;
        self.phase = Phase::Finished;
        self.retained = None;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;
    fn peer() -> Peer {
        Peer::admitted(
            SelfFacts {
                process: 7,
                thread: 9,
                registered_incarnation: 1,
            },
            11,
            12,
        )
    }
    fn client() -> Client {
        Client::claim_once(peer(), 0, 100, &AtomicBool::new(false)).unwrap()
    }
    struct Model {
        result: SendResult,
        calls: Vec<(u64, [u8; 8], u64)>,
    }
    impl Sender for Model {
        fn try_send(&mut self, endpoint: u64, frame: [u8; 8], deadline: u64) -> SendResult {
            self.calls.push((endpoint, frame, deadline));
            self.result
        }
    }
    fn sender(result: SendResult) -> Model {
        Model {
            result,
            calls: Vec::new(),
        }
    }
    fn read(c: &mut Client, s: &mut Model, value: u32) {
        c.begin_read(1).unwrap();
        assert_eq!(c.try_send(2, s), Ok(SendResult::Accepted));
        assert_eq!(
            c.observe_root_control(12, &wire::Response::Value(value).encode(), 0, 3),
            Ok(wire::Response::Value(value))
        );
    }
    #[test]
    fn exact_generated_read_then_optional_set_and_unchanged_value_refuses() {
        let mut c = client();
        let mut s = sender(SendResult::Accepted);
        assert_eq!(c.begin_set(1, 0), Err(Error::State));
        read(&mut c, &mut s, u32::MAX);
        assert_eq!(s.calls[0], (11, wire::Request::Read.encode(), 100));
        assert_eq!(c.begin_set(u32::MAX, 4), Err(Error::Unchanged));
        c.begin_set(0, 4).unwrap();
        c.try_send(5, &mut s).unwrap();
        assert_eq!(s.calls[1], (11, wire::Request::SetValue(0).encode(), 100));
        c.observe_root_control(12, &wire::Response::Value(0).encode(), 0, 6)
            .unwrap();
        assert_eq!(c.confirmed_value(), Some(0));
        assert_eq!(c.finish(), Ok(0));
        assert_eq!(c.finish(), Err(Error::State));
        assert_eq!(c.begin_read(7), Err(Error::State));
        assert_eq!(c.begin_set(1, 7), Err(Error::State));
    }
    #[test]
    fn backpressure_repeats_only_identical_unaccepted_bytes_and_never_renews_cut() {
        let mut c = client();
        let mut s = sender(SendResult::WouldBlock);
        c.begin_read(1).unwrap();
        for now in [2, 40, 99] {
            assert_eq!(c.try_send(now, &mut s), Ok(SendResult::WouldBlock));
        }
        assert!(
            s.calls
                .iter()
                .all(|r| *r == (11, wire::Request::Read.encode(), 100))
        );
        assert_eq!(c.retained().unwrap().acceptance, Acceptance::NotAccepted);
        assert_eq!(c.try_send(100, &mut s), Err(Error::Deadline));
        assert_eq!(c.phase(), Phase::Unsent);
        assert_eq!(s.calls.len(), 3);
        assert_eq!(c.try_send(101, &mut s), Err(Error::State));
        assert_eq!(c.begin_read(101), Err(Error::State));
    }
    #[test]
    fn accepted_timeout_and_late_value_retain_the_original_request_forever() {
        let mut c = client();
        let mut s = sender(SendResult::Accepted);
        c.begin_read(1).unwrap();
        c.try_send(2, &mut s).unwrap();
        let original = c.retained();
        assert_eq!(c.try_send(3, &mut s), Err(Error::State));
        assert_eq!(c.poll_deadline(100), Err(Error::Deadline));
        assert_eq!(c.phase(), Phase::Uncertain);
        assert_eq!(c.retained(), original);
        assert_eq!(
            c.observe_root_control(12, &wire::Response::Value(5).encode(), 0, 101),
            Err(Error::State)
        );
        assert_eq!(c.retained(), original);
        assert_eq!(c.finish(), Err(Error::State));
        assert_eq!(c.begin_read(102), Err(Error::State));
        assert_eq!(s.calls.len(), 1);
    }
    #[test]
    fn malformed_caps_unexpected_value_and_unsolicited_reply_fence_the_session() {
        for caps in [0, 1] {
            let mut c = client();
            let mut s = sender(SendResult::Accepted);
            c.begin_read(1).unwrap();
            c.try_send(2, &mut s).unwrap();
            let retained = c.retained();
            let mut bytes = wire::Response::Value(5).encode();
            if caps == 0 {
                bytes[2] = 9;
            }
            assert!(c.observe_root_control(12, &bytes, caps, 3).is_err());
            assert_eq!(c.phase(), Phase::Uncertain);
            assert_eq!(c.retained(), retained);
            assert!(
                c.observe_root_control(12, &wire::Response::Value(5).encode(), 0, 4)
                    .is_err()
            );
        }
        let mut c = client();
        let mut s = sender(SendResult::Accepted);
        read(&mut c, &mut s, 10);
        c.begin_set(11, 4).unwrap();
        c.try_send(5, &mut s).unwrap();
        let retained = c.retained();
        assert!(
            c.observe_root_control(12, &wire::Response::Value(10).encode(), 0, 6)
                .is_err()
        );
        assert_eq!(c.phase(), Phase::Uncertain);
        assert_eq!(c.retained(), retained);
        assert!(c.begin_set(12, 7).is_err());
        let mut c = client();
        c.begin_read(1).unwrap();
        assert!(
            c.observe_root_control(12, &wire::Response::Value(10).encode(), 0, 2)
                .is_err()
        );
        assert_eq!(c.phase(), Phase::Uncertain);
    }
    #[test]
    fn foreign_receiver_never_advances_and_each_actual_root_refusal_is_terminal() {
        for reason in [
            wire::Refusal::Denied,
            wire::Refusal::Malformed,
            wire::Refusal::Busy,
            wire::Refusal::Storage,
        ] {
            let mut c = client();
            let mut s = sender(SendResult::Accepted);
            c.begin_read(1).unwrap();
            c.try_send(2, &mut s).unwrap();
            let retained = c.retained();
            assert_eq!(
                c.observe_root_control(13, &wire::Response::Value(42).encode(), 0, 3),
                Err(Error::Peer)
            );
            assert_eq!(c.phase(), Phase::AwaitReply);
            assert_eq!(c.retained(), retained);
            assert_eq!(
                c.observe_root_control(12, &wire::Response::Refused(reason).encode(), 0, 4),
                Ok(wire::Response::Refused(reason))
            );
            assert_eq!(c.phase(), Phase::Refused);
            assert_eq!(c.refusal(), Some(reason));
            assert_eq!(c.retained(), retained);
            assert_eq!(c.confirmed_value(), None);
            assert!(c.begin_read(5).is_err());
            assert!(c.finish().is_err());
        }
    }
    #[test]
    fn uncertain_send_clock_rollback_and_drop_never_open_a_fresh_client_escape() {
        let guard = AtomicBool::new(false);
        {
            let mut c = Client::claim_once(peer(), 0, 100, &guard).unwrap();
            c.begin_read(1).unwrap();
            let mut s = sender(SendResult::Unknown);
            assert_eq!(c.try_send(2, &mut s), Err(Error::Uncertain));
            assert_eq!(c.retained().unwrap().acceptance, Acceptance::Unknown);
            assert!(c.try_send(3, &mut s).is_err());
        }
        assert!(matches!(
            Client::claim_once(peer(), 3, 200, &guard),
            Err(Error::Claimed)
        ));
        let mut c = client();
        let mut s = sender(SendResult::Accepted);
        c.begin_read(10).unwrap();
        c.try_send(11, &mut s).unwrap();
        let original = c.retained();
        assert_eq!(c.poll_deadline(9), Err(Error::Clock));
        assert_eq!(c.retained(), original);
        assert_eq!(c.phase(), Phase::Uncertain);
        let mut c = client();
        let mut s = sender(SendResult::Rejected);
        c.begin_read(1).unwrap();
        assert_eq!(c.try_send(2, &mut s), Err(Error::Rejected));
        assert_eq!(c.phase(), Phase::Unsent);
        assert!(c.begin_read(3).is_err());
    }
    #[test]
    fn read_only_finish_and_duplicate_reply_before_set_are_distinct_terminal_paths() {
        let mut c = client();
        let mut s = sender(SendResult::Accepted);
        read(&mut c, &mut s, 42);
        assert_eq!(c.finish(), Ok(42));
        assert_eq!(c.retained(), None);
        let mut c = client();
        read(&mut c, &mut s, 42);
        assert!(
            c.observe_root_control(12, &wire::Response::Value(42).encode(), 0, 4)
                .is_err()
        );
        assert_eq!(c.phase(), Phase::Uncertain);
        assert!(c.begin_set(43, 5).is_err());
    }
}
