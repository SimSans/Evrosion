extern crate std;
use super::*;
use ev_net_driver::control::Initialization;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

#[derive(Clone)]
struct Memory {
    bytes: Rc<RefCell<[u8; 4096]>>,
    writes: Rc<Cell<usize>>,
}
impl Window for Memory {
    type Error = ();
    fn read(&mut self, n: usize) -> Result<u8, ()> {
        self.bytes.borrow().get(n).copied().ok_or(())
    }
    fn write(&mut self, n: usize, byte: u8) -> Result<(), ()> {
        *self.bytes.borrow_mut().get_mut(n).ok_or(())? = byte;
        self.writes.set(self.writes.get() + 1);
        Ok(())
    }
}
#[derive(Clone, Copy)]
enum Reply {
    Good,
    WrongSequence,
    AlteredWindow,
    Unknown,
    Refused,
    Continuation,
    EarlyComplete,
}
struct Peer {
    memory: Memory,
    calls: Rc<Cell<usize>>,
    reply: Reply,
    steps: u16,
}
impl Transport for Peer {
    type Error = ();
    fn call(&mut self, bytes: [u8; 8], deadline: u64) -> Result<[u8; 8], ()> {
        assert_eq!(deadline, 100);
        self.calls.set(self.calls.get() + 1);
        if matches!(self.reply, Reply::Unknown) {
            return Err(());
        }
        let notice = Notice::decode(bytes).unwrap();
        let mut packet = Packet::new();
        packet.read_request(&mut self.memory, notice).unwrap();
        if notice.operation == Operation::Initialize {
            let init = Initialization::parse(packet.data()).unwrap();
            assert_eq!(init.seed, 123);
            assert!(init.scope.allows_name(b"net.evrosion.dev"));
            assert!(init.scope.allows_destination(&[10, 0, 2, 2, 0x90, 0x1f]));
        } else if matches!(
            notice.operation,
            Operation::ShutdownBegin | Operation::ShutdownStep
        ) {
            if notice.operation == Operation::ShutdownBegin {
                assert_eq!(packet.data(), &8192u64.to_le_bytes());
            } else {
                self.steps += 1;
                assert!(packet.data().is_empty());
            }
        } else if cfg!(feature = "native-network-negative")
            && notice.operation == Operation::Connect
        {
            assert_eq!(packet.data(), &[10, 0, 2, 3, 0x90, 0x1f]);
        } else {
            assert_eq!(notice.operation, Operation::Shutdown);
        }
        let status = if matches!(self.reply, Reply::Refused) {
            Status::Refused
        } else if matches!(self.reply, Reply::Continuation | Reply::EarlyComplete) {
            if self.steps == 128 || (self.steps > 0 && matches!(self.reply, Reply::EarlyComplete)) {
                Status::Complete
            } else {
                Status::Pending
            }
        } else {
            Status::Complete
        };
        let mut response = packet.reply(&mut self.memory, notice, status, &[]).unwrap();
        if matches!(self.reply, Reply::WrongSequence) {
            response[4] ^= 1;
        }
        if matches!(self.reply, Reply::AlteredWindow) {
            self.memory.bytes.borrow_mut()[4095] = 1;
        }
        Ok(response)
    }
}
fn policy() -> NetworkPolicy<'static> {
    NetworkPolicy {
        allowed_ipv4: [10, 0, 2, 2],
        remote_port: 8080,
        local_port: 49152,
        dns_name: "net.evrosion.dev",
    }
}
type Fixture = (Client<Memory, Peer>, Rc<Cell<usize>>, Rc<Cell<usize>>);
fn fixture(reply: Reply) -> Fixture {
    let writes = Rc::new(Cell::new(0));
    let calls = Rc::new(Cell::new(0));
    let memory = Memory {
        bytes: Rc::new(RefCell::new([0; 4096])),
        writes: writes.clone(),
    };
    (
        Client::new(
            memory.clone(),
            Peer {
                memory,
                calls: calls.clone(),
                reply,
                steps: 0,
            },
        ),
        writes,
        calls,
    )
}
#[test]
fn exact_existing_codec_and_protected_reply_join_initialize_and_terminal_shutdown() {
    let (mut client, writes, calls) = fixture(Reply::Good);
    client
        .initialize(&123u64.to_le_bytes(), policy(), 1, 100)
        .unwrap();
    assert!(!client.quarantined());
    assert_eq!(calls.get(), 1);
    let before = writes.get();
    assert_eq!(
        client.initialize(&123u64.to_le_bytes(), policy(), 1, 100),
        Err(Error::State)
    );
    assert_eq!(writes.get(), before);
    client.shutdown(2, 100).unwrap();
    let before = writes.get();
    assert_eq!(calls.get(), 2);
    assert_eq!(client.shutdown(3, 100), Err(Error::Quarantined));
    assert_eq!(writes.get(), before);
}
#[test]
fn invalid_cuts_never_publish_or_enter_transport() {
    for (now, cut) in [(1, 0), (1, 1), (1, 1026), (1, u64::MAX)] {
        let (mut client, writes, calls) = fixture(Reply::Good);
        assert_eq!(
            client.initialize(&123u64.to_le_bytes(), policy(), now, cut),
            Err(Error::Clock)
        );
        assert_eq!((writes.get(), calls.get()), (0, 0));
    }
}
#[test]
fn mismatched_response_noncanonical_window_unknown_and_refusal_pin_without_replay() {
    for reply in [Reply::WrongSequence, Reply::AlteredWindow, Reply::Unknown] {
        let (mut client, writes, calls) = fixture(reply);
        assert!(
            client
                .initialize(&123u64.to_le_bytes(), policy(), 1, 100)
                .is_err()
        );
        assert!(client.quarantined());
        let before = writes.get();
        assert_eq!(client.shutdown(2, 100), Err(Error::Quarantined));
        assert_eq!((writes.get(), calls.get()), (before, 1));
    }
}
#[test]
fn explicit_refusal_is_quiescent_and_allows_a_distinct_shutdown_operation() {
    let (mut client, _, calls) = fixture(Reply::Refused);
    assert_eq!(
        client.initialize(&123u64.to_le_bytes(), policy(), 1, 100),
        Err(Error::Remote(Status::Refused))
    );
    assert!(!client.quarantined());
    client.transport.reply = Reply::Good;
    client.shutdown(2, 100).unwrap();
    assert_eq!(calls.get(), 2);
}
#[test]
fn provider_failure_fences_a_previously_usable_client_without_republication() {
    let (mut client, writes, calls) = fixture(Reply::Good);
    client
        .initialize(&123u64.to_le_bytes(), policy(), 1, 100)
        .unwrap();
    client.source_failed();
    let before = writes.get();
    assert_eq!(client.shutdown(2, 100), Err(Error::Quarantined));
    assert_eq!((writes.get(), calls.get()), (before, 1));
}

#[test]
fn failure_metadata_preserves_actual_attempt_and_never_changes_poison_or_republishes() {
    for (reply, class, detail) in [
        (Reply::WrongSequence, 6, 0),
        (Reply::Unknown, 5, 0),
        (Reply::Refused, 7, Status::Refused as u8),
    ] {
        let (mut client, writes, calls) = fixture(reply);
        assert_eq!(client.last_operation(), None);
        let error = client
            .initialize(&123u64.to_le_bytes(), policy(), 1, 100)
            .unwrap_err();
        let before = (writes.get(), calls.get(), client.quarantined());
        let op = client.last_operation().unwrap();
        assert_eq!(op, Operation::Initialize);
        let d = error.diagnostic(op).unwrap();
        assert_eq!(d.encode(), [b'N', b'E', 3, 1, class, detail, 0, 0]);
        assert_eq!((writes.get(), calls.get(), client.quarantined()), before);
    }
}

#[test]
fn bounded_shutdown_uses_one_aggregate_and_128_distinct_acknowledged_chunks() {
    let (mut client, writes, calls) = fixture(Reply::Continuation);
    assert_eq!(client.shutdown_step(1, 100), Err(Error::State));
    assert_eq!(calls.get(), 0);
    client.shutdown_begin(8192, 1, 100).unwrap();
    let before = (writes.get(), calls.get());
    assert_eq!(client.shutdown_begin(8193, 1, 100), Err(Error::State));
    assert_eq!((writes.get(), calls.get()), before);
    assert_eq!(client.shutdown_step(2, 8193), Err(Error::Clock));
    assert_eq!((writes.get(), calls.get()), before);
    assert_eq!(client.status(2, 100), Err(Error::Quarantined));
    assert_eq!((writes.get(), calls.get()), before);
    for n in 1..=128 {
        assert_eq!(client.shutdown_step(2, 100).unwrap(), n == 128);
    }
    assert_eq!(calls.get(), 129);
    assert!(client.stopped);
    let before = (writes.get(), calls.get());
    assert_eq!(client.shutdown_step(2, 100), Err(Error::Quarantined));
    assert_eq!((writes.get(), calls.get()), before);
}

#[test]
fn continuation_unknown_reply_wrong_cursor_or_old_peer_never_retries_accepted_work() {
    for reply in [Reply::Unknown, Reply::EarlyComplete, Reply::Good] {
        let (mut client, writes, calls) = fixture(Reply::Continuation);
        client.shutdown_begin(8192, 1, 100).unwrap();
        client.transport.reply = reply;
        assert!(client.shutdown_step(2, 100).is_err());
        assert!(client.quarantined());
        let before = (writes.get(), calls.get());
        assert!(client.shutdown_step(2, 100).is_err());
        assert!(client.shutdown_begin(8192, 2, 100).is_err());
        assert_eq!((writes.get(), calls.get()), before);
    }
    let (mut old, writes, calls) = fixture(Reply::Refused);
    assert_eq!(
        old.shutdown_begin(8192, 1, 100),
        Err(Error::Remote(Status::Refused))
    );
    assert!(!old.quarantined());
    let before = (writes.get(), calls.get());
    assert!(old.shutdown_step(2, 100).is_err());
    assert_eq!((writes.get(), calls.get()), before);
}

#[cfg(feature = "native-network-negative")]
#[test]
fn raw_forbidden_probe_uses_same_canonical_window_and_never_replays_unknown_work() {
    let (mut client, _, calls) = fixture(Reply::Good);
    let destination = [10, 0, 2, 3, 0x90, 0x1f];
    assert_eq!(
        client.probe_forbidden_destination(destination, 1, 100),
        Err(Error::State)
    );
    assert_eq!(calls.get(), 0);
    client
        .initialize(&123u64.to_le_bytes(), policy(), 1, 100)
        .unwrap();
    client.transport.reply = Reply::Refused;
    assert_eq!(
        client.probe_forbidden_destination(destination, 2, 100),
        Ok(())
    );
    assert!(!client.quarantined());
    assert_eq!(calls.get(), 2);
    client.transport.reply = Reply::Unknown;
    assert_eq!(
        client.probe_forbidden_destination(destination, 3, 100),
        Err(Error::Transport)
    );
    assert!(client.quarantined());
    assert_eq!(calls.get(), 3);
    assert_eq!(
        client.probe_forbidden_destination(destination, 4, 100),
        Err(Error::Quarantined)
    );
    assert_eq!(calls.get(), 3);
}
