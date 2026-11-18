extern crate std;
use super::*;
use ev_net_driver::control::{Notice, Operation, Packet, Status};
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    rc::Rc,
    vec,
    vec::Vec,
};
const RESPONSE: &[u8] =
    include_bytes!("../../../../../libs/time-proof/tests/fixtures/response.bin");
const NONCE: &[u8; 32] = include_bytes!("../../../../../libs/time-proof/tests/fixtures/nonce.bin");
fn framed(body: &[u8]) -> Vec<u8> {
    let mut bytes = std::format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}
#[test]
fn bounded_private_body_preserves_all_fragmentations_of_actual_public_signed_packet() {
    let bytes = framed(RESPONSE);
    for split in 0..=bytes.len() {
        let mut h = Http::new();
        h.push(&bytes[..split]).unwrap();
        h.push(&bytes[split..]).unwrap();
        h.finish().unwrap();
        assert_eq!(h.body(), RESPONSE);
    }
    let max = vec![0xa5; MAX_BODY];
    let mut h = Http::new();
    for b in framed(&max) {
        h.push(&[b]).unwrap();
    }
    h.finish().unwrap();
    assert_eq!(h.body(), max);
}
#[test]
fn header_smuggling_truncation_overflow_compression_and_extra_body_never_complete() {
    for header in [
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 1\r\n\r\nx".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Encoding: gzip\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 865\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 9999999999999999999999999999999\r\n\r\nx",
        b"HTTP/1.1 200 OK\nContent-Length: 1\n\nx",
    ] {
        assert!(Http::new().push(header).is_err());
    }
    let bytes = framed(RESPONSE);
    for end in 0..bytes.len() {
        let mut h = Http::new();
        if h.push(&bytes[..end]).is_ok() {
            assert!(h.finish().is_err());
        }
    }
    let mut h = Http::new();
    h.push(&bytes).unwrap();
    assert!(h.push(b"x").is_err());
    let mut long = b"HTTP/1.1 200 OK\r\nX:".to_vec();
    long.extend_from_slice(&[b'x'; 129]);
    assert!(Http::new().push(&long).is_err());
}
#[derive(Clone)]
struct Memory(Rc<RefCell<[u8; 4096]>>, Rc<Cell<usize>>);
impl Window for Memory {
    type Error = ();
    fn read(&mut self, n: usize) -> Result<u8, ()> {
        self.1.set(self.1.get() + 1);
        self.0.borrow().get(n).copied().ok_or(())
    }
    fn write(&mut self, n: usize, b: u8) -> Result<(), ()> {
        self.1.set(self.1.get() + 1);
        *self.0.borrow_mut().get_mut(n).ok_or(())? = b;
        Ok(())
    }
}
struct Peer {
    memory: Memory,
    log: Rc<RefCell<Vec<(Operation, u64)>>>,
    written: Rc<RefCell<Vec<u8>>>,
    reads: VecDeque<Vec<u8>>,
    phase: u8,
    seq: u32,
    unknown: bool,
    syn_sent: bool,
}
impl Transport for Peer {
    type Error = ();
    fn call(&mut self, b: [u8; 8], cut: u64) -> Result<[u8; 8], ()> {
        let n = Notice::decode(b).unwrap();
        assert_eq!(n.sequence, self.seq + 1);
        self.seq = n.sequence;
        self.log.borrow_mut().push((n.operation, cut));
        if self.unknown {
            return Err(());
        }
        let mut p = Packet::new();
        p.read_request(&mut self.memory, n).unwrap();
        let mut status = Status::Complete;
        let body = match n.operation {
            Operation::Close => {
                self.phase = 1;
                vec![]
            }
            Operation::Status => {
                let mut b = vec![0; 32];
                b[0] = 1;
                b[1] = 1;
                b[5] = 24;
                b[8..12].copy_from_slice(&[10, 0, 2, 15]);
                b[2] = if self.phase == 1 {
                    0
                } else if self.syn_sent {
                    2
                } else {
                    4
                };
                b
            }
            Operation::Connect => {
                assert_eq!(p.data(), &[10, 0, 2, 2, 0x90, 0x1f]);
                self.phase = 2;
                status = Status::Pending;
                vec![]
            }
            Operation::Write => {
                let count = p.data().len().min(11);
                self.written
                    .borrow_mut()
                    .extend_from_slice(&p.data()[..count]);
                (count as u16).to_le_bytes().to_vec()
            }
            Operation::Read => self.reads.pop_front().unwrap(),
            _ => panic!("unexpected operation"),
        };
        p.reply(&mut self.memory, n, status, &body).map_err(|_| ())
    }
}
fn scope() -> NetworkPolicy<'static> {
    NetworkPolicy {
        allowed_ipv4: [10, 0, 2, 2],
        remote_port: 8080,
        local_port: 49152,
        dns_name: "example.org",
    }
}
type Calls = Rc<RefCell<Vec<(Operation, u64)>>>;
type Written = Rc<RefCell<Vec<u8>>>;
type Fixture = (Client<Memory, Peer>, Calls, Written, Rc<Cell<usize>>);
fn fixture(unknown: bool) -> Fixture {
    fixture_mode(unknown, false)
}
fn fixture_mode(unknown: bool, fragmented: bool) -> Fixture {
    fixture_behavior(unknown, fragmented, false)
}
fn fixture_behavior(unknown: bool, fragmented: bool, syn_sent: bool) -> Fixture {
    let accesses = Rc::new(Cell::new(0));
    let memory = Memory(Rc::new(RefCell::new([0; 4096])), accesses.clone());
    let log = Rc::new(RefCell::new(Vec::new()));
    let written = Rc::new(RefCell::new(Vec::new()));
    let b = framed(RESPONSE);
    let peer = Peer {
        memory: memory.clone(),
        log: log.clone(),
        written: written.clone(),
        reads: if fragmented {
            b.into_iter().map(|v| vec![v]).chain([vec![]]).collect()
        } else {
            VecDeque::from([b[..29].to_vec(), b[29..].to_vec(), vec![]])
        },
        phase: 0,
        seq: 0,
        unknown,
        syn_sent,
    };
    (Client::new(memory, peer), log, written, accesses)
}
#[test]
fn actual_packet_client_close_reconnect_partial_write_original_cut_and_affine_verifier_join() {
    let (mut client, log, written, _) = fixture(false);
    let mut x = Exchange::new();
    x.start(1, 512).unwrap();
    for tick in 1..511 {
        if x.ready() {
            x.publish(NONCE).unwrap();
        }
        x.step(&mut client, scope(), tick).unwrap();
        if x.response().is_some() {
            break;
        }
    }
    assert_eq!(x.response(), Some(RESPONSE));
    let expected = [
        PREFIX,
        &NONCE
            .iter()
            .flat_map(|b| {
                [
                    b"0123456789abcdef"[(b >> 4) as usize],
                    b"0123456789abcdef"[(b & 15) as usize],
                ]
            })
            .collect::<Vec<_>>(),
        SUFFIX,
    ]
    .concat();
    assert_eq!(*written.borrow(), expected);
    let rows = log.borrow();
    assert_eq!(rows[0].0, Operation::Close);
    assert_eq!(rows[1].0, Operation::Status);
    assert!(rows.iter().all(|(_, cut)| *cut == 512));
    struct PublicFixture;
    impl ev_time_proof::NonceSource for PublicFixture {
        type Error = ();
        fn fresh_nonce(&mut self, o: &mut [u8; 32]) -> Result<(), ()> {
            *o = *NONCE;
            Ok(())
        }
    }
    let d = ev_time_contract::Domain::new(7).unwrap();
    let p = ev_time_proof::Policy::new(
        ev_time_proof::ClockModel::one_second_floor(1, 2).unwrap(),
        30,
        60,
        1,
        10,
    )
    .unwrap();
    let mut v = ev_time_proof::Client::new(PublicFixture, d.at(0), p).unwrap();
    let request = v.begin(d.at(0)).unwrap();
    assert!(v.finish(request, d.at(1), x.response().unwrap()).is_ok());
    assert!(!v.has_pending()); //public fixture, not actual entropy proof
}
#[test]
fn expiry_regression_unknown_and_reused_publish_never_replay_or_reuse_unknown_window() {
    let (mut c, log, _, _) = fixture(false);
    let mut x = Exchange::new();
    x.start(1, 3).unwrap();
    x.step(&mut c, scope(), 1).unwrap();
    let count = log.borrow().len();
    assert_eq!(x.step(&mut c, scope(), 3), Err(Error::Expired));
    assert_eq!(log.borrow().len(), count);
    assert!(x.publish(NONCE).is_err());
    let (mut c, log, _, _) = fixture(true);
    let mut x = Exchange::new();
    x.start(1, 30).unwrap();
    assert!(x.step(&mut c, scope(), 1).is_err());
    assert!(c.quarantined());
    let count = log.borrow().len();
    x.step(&mut c, scope(), 2).unwrap();
    assert_eq!(log.borrow().len(), count);
    let (mut c, _, _, _) = fixture(false);
    let mut x = Exchange::new();
    x.start(5, 30).unwrap();
    assert_eq!(x.step(&mut c, scope(), 4), Err(Error::Clock));
}
#[test]
fn quiescent_wait_skips_same_tick_window_and_rpc_until_due_without_renewing_cut() {
    let (mut c, log, _, accesses) = fixture(false);
    let mut x = Exchange::new();
    x.start(1, 512).unwrap();
    x.step(&mut c, scope(), 1).unwrap();
    let count = log.borrow().len();
    let touched = accesses.get();
    assert_eq!(x.calls, 1);
    for now in [1, 2, 64] {
        x.step(&mut c, scope(), now).unwrap();
        assert_eq!(log.borrow().len(), count);
        assert_eq!(accesses.get(), touched);
        assert_eq!(x.calls, 1);
    }
    x.step(&mut c, scope(), 65).unwrap();
    assert!(x.ready());
    assert_eq!(log.borrow().len(), count + 1);
    assert_eq!(x.calls, 2);
    let (mut c, log, _, _) = fixture(false);
    let mut x = Exchange::new();
    x.start(1, 30).unwrap();
    x.step(&mut c, scope(), 1).unwrap();
    x.step(&mut c, scope(), 29).unwrap();
    let count = log.borrow().len();
    assert_eq!(x.step(&mut c, scope(), 30), Err(Error::Expired));
    assert_eq!(log.borrow().len(), count);
    let (mut c, log, _, _) = fixture(false);
    let mut x = Exchange::new();
    x.start(1, 512).unwrap();
    x.step(&mut c, scope(), 1).unwrap();
    x.step(&mut c, scope(), 2).unwrap();
    let count = log.borrow().len();
    assert_eq!(x.step(&mut c, scope(), 1), Err(Error::Clock));
    assert_eq!(log.borrow().len(), count);
}
#[test]
fn positive_public_response_fragments_still_hit_original_work_cap_without_transport_replay() {
    let (mut c, log, _, _) = fixture_mode(false, true);
    let mut x = Exchange::new();
    x.start(1, 2000).unwrap();
    let mut error = None;
    for now in 1..2000 {
        if x.ready() {
            x.publish(NONCE).unwrap();
        }
        match x.step(&mut c, scope(), now) {
            Ok(()) => (),
            Err(e) => {
                error = Some(e);
                break;
            }
        }
    }
    assert_eq!(error, Some(Error::Counter));
    assert_eq!(x.calls, 128);
    let failure = x.failure().unwrap();
    assert_eq!(
        (
            failure.phase(),
            failure.tcp(),
            failure.calls(),
            failure.error()
        ),
        (8, Some(4), 128, (3, 0))
    );
    assert_eq!(log.borrow().len(), 128);
    assert!(!c.quarantined());
    let count = log.borrow().len();
    x.step(&mut c, scope(), 2000).unwrap();
    assert_eq!(log.borrow().len(), count);
}

#[test]
fn failure_snapshot_preserves_actual_synsent_and_has_no_rpc_or_window_side_effects() {
    let (mut c, log, _, accesses) = fixture_behavior(false, false, true);
    let mut x = Exchange::new();
    x.start(1, 512).unwrap();
    x.step(&mut c, scope(), 1).unwrap();
    x.step(&mut c, scope(), 65).unwrap();
    assert!(x.ready());
    x.publish(NONCE).unwrap();
    x.step(&mut c, scope(), 66).unwrap();
    x.step(&mut c, scope(), 130).unwrap();
    assert!(x.failure().is_none());
    let count = log.borrow().len();
    let touched = accesses.get();
    assert_eq!(x.step(&mut c, scope(), 512), Err(Error::Expired));
    let snapshot = x.failure().unwrap();
    assert_eq!(
        (
            snapshot.phase(),
            snapshot.tcp(),
            snapshot.calls(),
            snapshot.error()
        ),
        (6, Some(2), 4, (2, 0))
    );
    for _ in 0..8 {
        assert_eq!(x.failure(), Some(snapshot));
    }
    x.abandon();
    x.step(&mut c, scope(), 513).unwrap();
    assert_eq!(x.failure(), Some(snapshot));
    assert_eq!(log.borrow().len(), count);
    assert_eq!(accesses.get(), touched);
    assert!(!c.quarantined());
    let (mut c, log, _, accesses) = fixture(true);
    let mut x = Exchange::new();
    x.start(1, 512).unwrap();
    assert_eq!(
        x.step(&mut c, scope(), 1),
        Err(Error::Client(ClientError::Transport))
    );
    let count = log.borrow().len();
    let touched = accesses.get();
    let snapshot = x.failure().unwrap();
    assert_eq!(
        (
            snapshot.phase(),
            snapshot.tcp(),
            snapshot.calls(),
            snapshot.error()
        ),
        (2, None, 1, (6, 5))
    );
    assert!(c.quarantined());
    assert_eq!(x.failure(), Some(snapshot));
    assert_eq!(log.borrow().len(), count);
    assert_eq!(accesses.get(), touched);
}
