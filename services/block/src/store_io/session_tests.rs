#![cfg(feature = "test-store-client")]
//! Exercise the public storage adapter with an observable window and transport.
//! These are host policy/ownership checks, not hardware or durability evidence.
extern crate std;
use crate::store_io::{Error, StoreRegion, Window, Wire};
use ev_store::{Sector, SectorIo};
use ev_userspace_contract::block::{Request, Response};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    vec::Vec,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Deadline(u64),
    Store,
    Call(Request, u64),
    Load,
    Busy(Request, u64),
}

struct TransactionWire {
    state: Rc<State>,
    last: Cell<u64>,
    busy: Rc<Cell<usize>>,
}
struct TransactionRuntime {
    state: Rc<State>,
    busy: Rc<Cell<usize>>,
}
impl super::DesktopRuntime for TransactionRuntime {
    fn clock(&mut self) -> ev_userspace_runtime::Reply {
        ev_userspace_runtime::Reply {
            status: 0,
            value: self.state.now.get(),
            capability: 0,
        }
    }
    fn call(&mut self, _: u64, bytes: [u8; 8], deadline: u64) -> ev_userspace_runtime::Reply {
        let request = Request::decode(&bytes).unwrap();
        if self.busy.get() > 0 {
            self.busy.set(self.busy.get() - 1);
            self.state
                .events
                .borrow_mut()
                .push(Event::Busy(request, deadline));
            ev_userspace_runtime::Reply {
                status: 2,
                value: 0,
                capability: 0,
            }
        } else {
            self.state
                .events
                .borrow_mut()
                .push(Event::Call(request, deadline));
            ev_userspace_runtime::Reply {
                status: 0,
                value: u64::from_le_bytes(request.success().encode()),
                capability: 0,
            }
        }
    }
    fn yield_now(&mut self) -> ev_userspace_runtime::Reply {
        self.state.now.set(self.state.now.get() + 1);
        ev_userspace_runtime::Reply {
            status: 0,
            value: 0,
            capability: 0,
        }
    }
}
impl TransactionWire {
    fn runtime(&self) -> TransactionRuntime {
        TransactionRuntime {
            state: self.state.clone(),
            busy: self.busy.clone(),
        }
    }
}
impl Wire for TransactionWire {
    type Error = super::DesktopTransportError;
    fn supports_session(&self) -> bool {
        true
    }
    fn capture_session_deadline(&self, original: u64) -> Option<u64> {
        self.state
            .events
            .borrow_mut()
            .push(Event::Deadline(original));
        let mut last = self.last.get();
        // Host the exact production clock/capture boundary, not copied math.
        let child = super::capture_desktop_deadline(&mut self.runtime(), original, 8192, &mut last);
        self.last.set(last);
        child
    }
    fn call(&mut self, bytes: [u8; 8], child: u64) -> Result<[u8; 8], Self::Error> {
        let mut last = self.last.get();
        let reply = super::desktop_exchange(&mut self.runtime(), 256, bytes, child, 0, &mut last);
        self.last.set(last);
        reply
    }
}
struct SlowWindow {
    state: Rc<State>,
    after_store: u64,
}
impl Window for SlowWindow {
    fn load(&self, out: &mut Sector) {
        ObservedWindow(self.state.clone()).load(out);
    }
    fn store(&self, bytes: &Sector) {
        ObservedWindow(self.state.clone()).store(bytes);
        self.state.now.set(self.after_store);
    }
}
fn transaction_region(
    state: &Rc<State>,
    after_store: u64,
    busy: usize,
) -> StoreRegion<TransactionWire, SlowWindow> {
    StoreRegion::new(
        TransactionWire {
            state: state.clone(),
            last: Cell::new(0),
            busy: Rc::new(Cell::new(busy)),
        },
        SlowWindow {
            state: state.clone(),
            after_store,
        },
        0,
    )
    .unwrap()
}

#[test]
fn aggregate_capture_precedes_publication_and_busy_retries_never_extend_the_child_cut() {
    let state = State::new();
    let mut region = transaction_region(&state, 5600, 3);
    region.write(0, &[0x55; 512], 13_192).unwrap();
    let events = state.events.borrow();
    assert_eq!(events[0], Event::Deadline(13_192));
    assert_eq!(events[1], Event::Store);
    assert_eq!(state.count(|event| matches!(event, Event::Deadline(_))), 1);
    assert_eq!(
        state.count(|event| matches!(event, Event::Busy(_, 6024))),
        3
    );
    assert_eq!(
        state.count(|event| matches!(event, Event::Call(_, 6024))),
        1
    );
    assert_eq!(region.mutations(), 1);
}

#[test]
fn publication_cannot_reopen_an_expired_captured_cut_or_retry_after_poison() {
    let state = State::new();
    let mut region = transaction_region(&state, 5600, 0);
    assert_eq!(
        region.write(0, &[0x55; 512], 5500),
        Err(Error::Transport(super::DesktopTransportError::Deadline))
    );
    assert_eq!(state.count(|event| matches!(event, Event::Deadline(_))), 1);
    assert_eq!(state.count(|event| matches!(event, Event::Call(..))), 0);
    let before = state.events.borrow().clone();
    assert_eq!(
        region.write(0, &[0x66; 512], 9000),
        Err(Error::NeedsRecovery)
    );
    assert_eq!(*state.events.borrow(), before);
}

#[test]
fn aggregate_bound_rollback_and_overflow_refuse_before_publication() {
    for (now, deadline) in [
        (5000, 13_193),
        (5000, 5000),
        (5000, 0),
        (5000, u64::MAX),
        (u64::MAX - 512, u64::MAX - 1),
    ] {
        let state = State::new();
        state.now.set(now);
        let mut region = transaction_region(&state, now, 0);
        assert_eq!(
            region.write(0, &[0x55; 512], deadline),
            Err(Error::Deadline)
        );
        assert_eq!(
            state.count(|event| matches!(event, Event::Call(..) | Event::Store)),
            0
        );
    }
    let state = State::new();
    let wire = TransactionWire {
        state: state.clone(),
        last: Cell::new(0),
        busy: Rc::new(Cell::new(0)),
    };
    assert_eq!(wire.capture_session_deadline(0), None);
    state.now.set(4999);
    assert_eq!(wire.capture_session_deadline(5500), None);
    assert_eq!(wire.last.get(), 5000);
}

#[test]
fn same_capture_boundary_preserves_tight_profile_and_parent_near_expiry() {
    let state = State::new();
    let mut runtime = TransactionRuntime {
        state,
        busy: Rc::new(Cell::new(0)),
    };
    assert_eq!(
        super::capture_desktop_deadline(&mut runtime, 6025, 1024, &mut 0),
        None
    );
    assert_eq!(
        super::capture_desktop_deadline(&mut runtime, 13_192, 8192, &mut 0),
        Some(6024)
    );
    assert_eq!(
        super::capture_desktop_deadline(&mut runtime, 5500, 8192, &mut 0),
        Some(5500)
    );
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplyMode {
    Success,
    Uncertain,
    Malformed,
    WrongReply,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Uncertain;
struct State {
    now: Cell<u64>,
    bytes: RefCell<Sector>,
    events: RefCell<Vec<Event>>,
    mode: Cell<ReplyMode>,
}
impl State {
    fn new() -> Rc<Self> {
        Rc::new(Self {
            now: Cell::new(5000),
            bytes: RefCell::new([0x19; 512]),
            events: RefCell::new(Vec::new()),
            mode: Cell::new(ReplyMode::Success),
        })
    }
    fn count(&self, predicate: impl Fn(&Event) -> bool) -> usize {
        self.events.borrow().iter().filter(|e| predicate(e)).count()
    }
}
struct ObservedWindow(Rc<State>);
impl Window for ObservedWindow {
    fn load(&self, out: &mut Sector) {
        self.0.events.borrow_mut().push(Event::Load);
        *out = *self.0.bytes.borrow();
    }
    fn store(&self, bytes: &Sector) {
        self.0.events.borrow_mut().push(Event::Store);
        *self.0.bytes.borrow_mut() = *bytes;
    }
}
struct SessionWire(Rc<State>);
impl Wire for SessionWire {
    type Error = Uncertain;
    fn supports_session(&self) -> bool {
        true
    }
    fn session_deadline_valid(&self, deadline: u64) -> bool {
        self.0.events.borrow_mut().push(Event::Deadline(deadline));
        // Use the actual shared contract, not a replica of the adapter guard.
        ev_userspace_runtime::execution::accepts_deadline(0, self.0.now.get(), deadline, 1024)
    }
    fn call(&mut self, bytes: [u8; 8], deadline: u64) -> Result<[u8; 8], Self::Error> {
        let request = Request::decode(&bytes).unwrap();
        self.0
            .events
            .borrow_mut()
            .push(Event::Call(request, deadline));
        match self.0.mode.get() {
            ReplyMode::Uncertain => Err(Uncertain),
            ReplyMode::Malformed => Ok([0; 8]),
            ReplyMode::WrongReply => Ok(Response::Flushed.encode()),
            ReplyMode::Success => {
                if matches!(request, Request::Read { .. }) {
                    // A completed backend read wrote the shared sector itself.
                    *self.0.bytes.borrow_mut() = [0x42; 512];
                }
                Ok(request.success().encode())
            }
        }
    }
}
struct DefaultWire(Rc<State>);
impl Wire for DefaultWire {
    type Error = Uncertain;
    fn call(&mut self, bytes: [u8; 8], deadline: u64) -> Result<[u8; 8], Self::Error> {
        SessionWire(self.0.clone()).call(bytes, deadline)
    }
}
struct MissingDeadlineValidator(Rc<State>);
impl Wire for MissingDeadlineValidator {
    type Error = Uncertain;
    fn supports_session(&self) -> bool {
        true
    }
    fn call(&mut self, bytes: [u8; 8], deadline: u64) -> Result<[u8; 8], Self::Error> {
        SessionWire(self.0.clone()).call(bytes, deadline)
    }
}
fn region(state: &Rc<State>) -> StoreRegion<SessionWire, ObservedWindow> {
    StoreRegion::new(SessionWire(state.clone()), ObservedWindow(state.clone()), 0).unwrap()
}

#[test]
fn session_requires_explicit_transport_support_and_an_actual_deadline_validator() {
    let state = State::new();
    assert!(
        StoreRegion::new(DefaultWire(state.clone()), ObservedWindow(state.clone()), 0).is_none()
    );
    let mut region = StoreRegion::new(
        MissingDeadlineValidator(state.clone()),
        ObservedWindow(state.clone()),
        0,
    )
    .unwrap();
    assert_eq!(region.write(0, &[0x55; 512], 5512), Err(Error::Deadline));
    assert!(state.events.borrow().is_empty());
    assert_eq!(*state.bytes.borrow(), [0x19; 512]);
}

#[test]
fn invalid_session_deadlines_touch_neither_window_nor_transport() {
    for deadline in [0, u64::MAX, 4999, 5000, 6025] {
        let state = State::new();
        let mut region = region(&state);
        let mut out = [0x70; 512];
        assert_eq!(region.read(0, &mut out, deadline), Err(Error::Deadline));
        assert_eq!(
            region.write(0, &[0x55; 512], deadline),
            Err(Error::Deadline)
        );
        assert_eq!(region.flush(deadline), Err(Error::Deadline));
        assert_eq!(out, [0x70; 512]);
        assert_eq!(*state.bytes.borrow(), [0x19; 512]);
        assert_eq!(
            state.count(|e| matches!(e, Event::Store | Event::Load | Event::Call(..))),
            0
        );
        assert_eq!(region.mutations(), 0);
    }
}

#[test]
fn valid_write_publishes_once_after_preflight_and_is_accepted_once() {
    let state = State::new();
    let mut region = region(&state);
    region.write(3, &[0x55; 512], 6024).unwrap();
    let events = state.events.borrow();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0], Event::Deadline(6024));
    assert_eq!(events[1], Event::Store);
    assert!(matches!(
        events[2],
        Event::Call(Request::Write { .. }, 6024)
    ));
    assert_eq!(*state.bytes.borrow(), [0x55; 512]);
    assert_eq!(region.mutations(), 1);
}

#[test]
fn read_waits_for_one_completed_reply_before_loading_the_sector() {
    let state = State::new();
    let mut region = region(&state);
    let mut out = [0; 512];
    region.read(0, &mut out, 5512).unwrap();
    let events = state.events.borrow();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0], Event::Deadline(5512));
    assert!(matches!(events[1], Event::Call(Request::Read { .. }, 5512)));
    assert_eq!(events[2], Event::Load);
    assert_eq!(out, [0x42; 512]);
    assert_eq!(region.mutations(), 0);
}

#[test]
fn accepted_uncertainty_poison_prevents_replay_or_later_window_reuse() {
    let state = State::new();
    state.mode.set(ReplyMode::Uncertain);
    let mut region = region(&state);
    assert_eq!(
        region.write(0, &[0x55; 512], 5512),
        Err(Error::Transport(Uncertain))
    );
    assert_eq!(state.count(|e| matches!(e, Event::Call(..))), 1);
    assert_eq!(state.count(|e| *e == Event::Store), 1);
    let before = state.events.borrow().clone();
    state.now.set(1_000_000);
    state.mode.set(ReplyMode::Success);
    let mut out = [0x71; 512];
    assert_eq!(
        region.write(0, &[0x66; 512], 1_000_512),
        Err(Error::NeedsRecovery)
    );
    assert_eq!(
        region.read(0, &mut out, 1_000_512),
        Err(Error::NeedsRecovery)
    );
    assert_eq!(region.flush(1_000_512), Err(Error::NeedsRecovery));
    assert_eq!(*state.events.borrow(), before);
    assert_eq!(*state.bytes.borrow(), [0x55; 512]);
    assert_eq!(out, [0x71; 512]);
    assert_eq!(region.mutations(), 0);
}

#[test]
fn malformed_or_mismatched_completed_response_poison_without_retrying() {
    for mode in [ReplyMode::Malformed, ReplyMode::WrongReply] {
        let state = State::new();
        state.mode.set(mode);
        let mut region = region(&state);
        let result = region.write(0, &[0x55; 512], 5512);
        assert!(matches!(
            result,
            Err(Error::Decode(_)) | Err(Error::UnexpectedReply(_))
        ));
        assert_eq!(state.count(|e| matches!(e, Event::Call(..))), 1);
        assert_eq!(
            region.write(0, &[0x66; 512], 5512),
            Err(Error::NeedsRecovery)
        );
        assert_eq!(state.count(|e| *e == Event::Store), 1);
        assert_eq!(region.mutations(), 0);
    }
}
