//! Production Store/transport/Images continuations over explicit test devices.
//! The clock and physical image IO are models; no guest/UTC/health claim.
extern crate std;
use super::*;
use crate::native_acquisition::tests::Disk;
use ev_net_driver::control::{Notice, Operation, Packet, Status};
use ev_time_contract::{
    Domain, Instant,
    freshness::{QualifiedWindow, UtcInterval},
};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, rc::Rc, vec, vec::Vec};
const TARGETS: &[u8] = include_bytes!("../../fixtures/acquisition/phase-b/targets.bin");
const SNAPSHOT: &[u8] = include_bytes!("../../fixtures/acquisition/phase-b/snapshot.bin");
const TIMESTAMP: &[u8] = include_bytes!("../../fixtures/acquisition/phase-b/timestamp.bin");
const PACKAGE: &[u8] = include_bytes!("../../fixtures/acquisition/phase-b/hello.zion");
#[derive(Clone)]
struct Memory(Rc<RefCell<[u8; 4096]>>);
impl Window for Memory {
    type Error = ();
    fn read(&mut self, at: usize) -> Result<u8, ()> {
        self.0.borrow().get(at).copied().ok_or(())
    }
    fn write(&mut self, at: usize, byte: u8) -> Result<(), ()> {
        *self.0.borrow_mut().get_mut(at).ok_or(())? = byte;
        Ok(())
    }
}
struct Peer {
    memory: Memory,
    seq: u32,
    closed: bool,
    request: Vec<u8>,
    response: Vec<u8>,
    at: usize,
    paths: Rc<RefCell<Vec<Vec<u8>>>>,
    corrupt: bool,
}
type Paths = Rc<RefCell<Vec<Vec<u8>>>>;
impl Transport for Peer {
    type Error = ();
    fn call(&mut self, frame: [u8; 8], cut: u64) -> Result<[u8; 8], ()> {
        assert!(cut > 0 && cut != u64::MAX);
        let notice = Notice::decode(frame).unwrap();
        assert_eq!(notice.sequence, self.seq + 1);
        self.seq = notice.sequence;
        let mut packet = Packet::new();
        packet.read_request(&mut self.memory, notice).unwrap();
        let mut status = Status::Complete;
        let data = match notice.operation {
            Operation::Close => {
                self.closed = true;
                vec![]
            }
            Operation::Status => {
                let mut b = vec![0; 32];
                b[0] = 1;
                b[1] = 1;
                b[2] = if self.closed { 0 } else { 4 };
                b[5] = 24;
                b
            }
            Operation::Resolve => {
                assert_eq!(packet.data(), b"example.org");
                status = Status::Pending;
                vec![]
            }
            Operation::QueryResult => vec![93, 184, 216, 34], // Diagnostic DNS never selects fixed peer.
            Operation::Connect => {
                assert_eq!(packet.data(), &[10, 0, 2, 2, 0x90, 0x1f]);
                self.closed = false;
                self.request.clear();
                self.response.clear();
                self.at = 0;
                status = Status::Pending;
                vec![]
            }
            Operation::Write => {
                let count = packet.data().len().min(19);
                self.request.extend_from_slice(&packet.data()[..count]);
                if self.request.ends_with(b"\r\n\r\n") {
                    let path = self.request.split(|b| *b == b' ').nth(1).unwrap();
                    self.paths.borrow_mut().push(path.to_vec());
                    let body = match path {
                        b"/release/targets.bin" => TARGETS,
                        b"/release/snapshot.bin" => SNAPSHOT,
                        b"/release/timestamp.bin" => TIMESTAMP,
                        b"/artifacts/hello.zion" => PACKAGE,
                        _ => panic!("unexpected path"),
                    };
                    let mut body = body.to_vec();
                    if self.corrupt && path == b"/release/timestamp.bin" {
                        let n = body.len();
                        body[n - 1] ^= 1;
                    }
                    self.response = std::format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .into_bytes();
                    self.response.extend_from_slice(&body);
                }
                (count as u16).to_le_bytes().to_vec()
            }
            Operation::Read => {
                let limit = u16::from_le_bytes(packet.data().try_into().unwrap()) as usize;
                let end = (self.at + limit.min(997)).min(self.response.len());
                let b = self.response[self.at..end].to_vec();
                self.at = end;
                b
            }
            _ => panic!("unexpected operation"),
        };
        packet
            .reply(&mut self.memory, notice, status, &data)
            .map_err(|_| ())
    }
}
struct TestClock {
    calls: u64,
}
impl acq::QualifiedClock for TestClock {
    type Error = ();
    fn fresh(&mut self) -> Result<(QualifiedWindow, Instant), ()> {
        self.calls += 1;
        let envelope = Envelope::parse(TARGETS).unwrap();
        let author = md::Targets::parse(&envelope).unwrap().common().not_before;
        let domain = Domain::new(55).unwrap();
        Ok((
            QualifiedWindow::new(
                domain.at(1),
                domain.at(3),
                UtcInterval::new(author + 1, author + 2).unwrap(),
            )
            .unwrap(),
            domain.at(self.calls),
        ))
    }
}
fn engine() -> Update<Disk> {
    let mut engine = Update::new();
    let mut b = Buffers::empty();
    assert!(
        engine
            .begin(Disk::blank(), update::Command::Initialize, 1)
            .is_ok()
    );
    for _ in 0..2048 {
        engine.step(&mut b, 1);
        engine.observe_after(1);
        if engine.outcome().is_some() {
            break;
        }
    }
    assert!(matches!(
        engine.outcome(),
        Some(update::Outcome::Complete(_))
    ));
    let backend = engine.take_completed().unwrap();
    assert!(
        engine
            .begin(backend.cold(), update::Command::Fetch, 2)
            .is_ok()
    );
    engine
}
fn peer(corrupt: bool) -> (Client<Memory, Peer>, Paths) {
    let memory = Memory(Rc::new(RefCell::new([0; 4096])));
    let paths = Rc::new(RefCell::new(Vec::new()));
    let peer = Peer {
        memory: memory.clone(),
        seq: 0,
        closed: true,
        request: Vec::new(),
        response: Vec::new(),
        at: 0,
        paths: paths.clone(),
        corrupt,
    };
    (Client::new(memory, peer), paths)
}
fn scope() -> NetworkPolicy<'static> {
    NetworkPolicy {
        allowed_ipv4: [10, 0, 2, 2],
        remote_port: 8080,
        local_port: 49152,
        dns_name: "example.org",
    }
}
#[test]
fn actual_streaming_prepares_before_writes_then_publishes_before_register_without_selecting() {
    let mut engine = engine();
    let mut b = Buffers::empty();
    let mut images = crate::native_sources::tests::empty_images();
    let (mut client, paths) = peer(false);
    let mut fetch = Fetch::new();
    fetch.begin(2, None).unwrap();
    let mut proofs = 0;
    let mut preparation = false;
    let mut published = false;
    for now in 2..20_000 {
        match fetch
            .step(&mut engine, &mut client, scope(), &mut images, &mut b, now)
            .unwrap()
        {
            Event::Working => (),
            Event::NeedTime => {
                proofs += 1;
                fetch.time_armed().unwrap();
                fetch.time_finished().unwrap();
            }
            Event::NeedPreparation => {
                assert!(!preparation);
                assert_eq!(proofs, 1);
                assert!(engine.retained_snapshot().unwrap().candidate().is_none());
                assert!(images.bytes(0).is_err());
                assert!(images.registered_capability(0).is_none());
                let (root, bundle) = fetch.preparation_input(&b).unwrap();
                let store = engine.authorization_store().unwrap();
                let head = store.authorization_binding();
                let prepared = store
                    .prepare_metadata(root, bundle, &mut TestClock { calls: 0 })
                    .unwrap();
                assert_eq!(store.authorization_binding(), head);
                fetch.prepared(prepared, &engine).unwrap();
                preparation = true;
            }
            Event::NeedAuthorization => {
                assert!(preparation);
                assert_eq!(proofs, 2);
                assert_eq!(images.bytes(0).unwrap(), PACKAGE);
                assert!(images.registered_capability(0).is_none());
                assert!(engine.retained_snapshot().unwrap().candidate().is_none());
                let remote = fetch.remote(&b, &images).unwrap();
                let (store, workspace) = engine.authorization_parts().unwrap();
                store
                    .authorize_into(remote, &mut TestClock { calls: 0 }, workspace)
                    .unwrap();
                engine.begin_prepared_fetch(now).unwrap();
                fetch.decision_started().unwrap();
            }
            Event::Published { slot } => {
                let content = fetch.published_content().unwrap();
                let snapshot = engine.retained_snapshot().unwrap();
                assert_eq!(snapshot.candidate(), Some(content));
                assert!(snapshot.active().is_none());
                assert!(snapshot.known_good().is_none());
                assert_eq!(content.package, <[u8; 32]>::from(Sha256::digest(PACKAGE)));
                crate::native_sources::Member::capture(&images, slot, snapshot, content).unwrap();
                assert!(images.registered_capability(slot).is_some());
                published = true;
                break;
            }
        }
        engine.observe_after(now);
    }
    assert!(published);
    assert_eq!(proofs, 2);
    assert_eq!(
        *paths.borrow(),
        [
            Path::Timestamp,
            Path::Snapshot,
            Path::Targets,
            Path::Artifact
        ]
        .map(|p| p.bytes().to_vec())
    );
    assert!(engine.take_completed().is_some());
}
#[test]
fn invalid_metadata_never_reserves_artifact_or_consumes_a_permanent_image_slot() {
    let mut engine = engine();
    let mut b = Buffers::empty();
    let mut images = crate::native_sources::tests::empty_images();
    let (mut client, paths) = peer(true);
    let mut fetch = Fetch::new();
    fetch.begin(2, None).unwrap();
    let mut refused = false;
    for now in 2..10_000 {
        match fetch.step(&mut engine, &mut client, scope(), &mut images, &mut b, now) {
            Ok(Event::NeedTime) => {
                fetch.time_armed().unwrap();
                fetch.time_finished().unwrap();
            }
            Ok(Event::NeedPreparation) => {
                let (root, bundle) = fetch.preparation_input(&b).unwrap();
                assert!(
                    engine
                        .authorization_store()
                        .unwrap()
                        .prepare_metadata(root, bundle, &mut TestClock { calls: 0 })
                        .is_err()
                );
                fetch.refuse();
                engine.refuse_fetch(now);
                refused = true;
                break;
            }
            Ok(Event::Working) => (),
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(refused);
    assert_eq!(paths.borrow().len(), 3);
    assert!(images.bytes(0).is_err());
    assert!(images.registered_capability(0).is_none());
    assert!(engine.release_settled_refusal().is_some());
}
