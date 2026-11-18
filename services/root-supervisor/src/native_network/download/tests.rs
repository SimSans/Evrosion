//! Actual codec/consumer models only; no runtime/network authorization claim.
extern crate std;
use super::*;
use ev_net_driver::control::{Notice, Operation, Packet, Status};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    vec,
    vec::Vec,
};

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
    bytes: Vec<u8>,
    at: usize,
    fragment: usize,
    seq: u32,
    closed: bool,
    log: Rc<RefCell<Vec<(Operation, u64)>>>,
    written: Rc<RefCell<Vec<u8>>>,
    unknown: Rc<Cell<bool>>,
    pending: Rc<Cell<bool>>,
    oversized: Rc<Cell<bool>>,
    lease: Rc<Cell<bool>>,
    address: Rc<Cell<[u8; 4]>>,
}
impl Transport for Peer {
    type Error = ();
    fn call(&mut self, message: [u8; 8], cut: u64) -> Result<[u8; 8], ()> {
        let n = Notice::decode(message).unwrap();
        assert_eq!(n.sequence, self.seq + 1);
        self.seq = n.sequence;
        self.log.borrow_mut().push((n.operation, cut));
        if self.unknown.get() {
            return Err(());
        }
        let mut packet = Packet::new();
        packet.read_request(&mut self.memory, n).unwrap();
        let mut status = Status::Complete;
        let data = match n.operation {
            Operation::Close => {
                self.closed = true;
                vec![]
            }
            Operation::Status => {
                let mut data = vec![0; 32];
                data[0] = 1;
                data[1] = u8::from(self.lease.get());
                data[2] = if self.closed { 0 } else { 4 };
                data[5] = 24;
                data[8..12].copy_from_slice(&[10, 0, 2, 15]);
                data
            }
            Operation::Connect => {
                assert_eq!(packet.data(), &[10, 0, 2, 2, 0x90, 0x1f]);
                self.closed = false;
                status = Status::Pending;
                vec![]
            }
            Operation::Resolve => {
                assert_eq!(packet.data(), b"example.org");
                status = Status::Pending;
                vec![]
            }
            Operation::QueryResult => self.address.get().to_vec(),
            Operation::Write => {
                let count = packet.data().len().min(13);
                self.written
                    .borrow_mut()
                    .extend_from_slice(&packet.data()[..count]);
                (count as u16).to_le_bytes().to_vec()
            }
            Operation::Read => {
                if self.pending.get() {
                    status = Status::Pending;
                    vec![]
                } else {
                    let limit = u16::from_le_bytes(packet.data().try_into().unwrap()) as usize;
                    let count = (self.bytes.len() - self.at)
                        .min(self.fragment)
                        .min(if self.oversized.get() { 1024 } else { limit });
                    let data = self.bytes[self.at..self.at + count].to_vec();
                    self.at += count;
                    data
                }
            }
            _ => panic!("unexpected model operation"),
        };
        packet
            .reply(&mut self.memory, n, status, &data)
            .map_err(|_| ())
    }
}
struct Fixture {
    client: Client<Memory, Peer>,
    log: Rc<RefCell<Vec<(Operation, u64)>>>,
    written: Rc<RefCell<Vec<u8>>>,
    access: Rc<Cell<usize>>,
    unknown: Rc<Cell<bool>>,
    pending: Rc<Cell<bool>>,
    oversized: Rc<Cell<bool>>,
    lease: Rc<Cell<bool>>,
    address: Rc<Cell<[u8; 4]>>,
}
fn framed(body: &[u8]) -> Vec<u8> {
    [std::format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes(),body].concat()
}
fn fixture(bytes: Vec<u8>, fragment: usize) -> Fixture {
    let access = Rc::new(Cell::new(0));
    let memory = Memory(Rc::new(RefCell::new([0; 4096])), access.clone());
    let log = Rc::new(RefCell::new(Vec::new()));
    let written = Rc::new(RefCell::new(Vec::new()));
    let unknown = Rc::new(Cell::new(false));
    let pending = Rc::new(Cell::new(false));
    let oversized = Rc::new(Cell::new(false));
    let lease = Rc::new(Cell::new(true));
    let address = Rc::new(Cell::new([10, 0, 2, 2]));
    let peer = Peer {
        memory: memory.clone(),
        bytes,
        at: 0,
        fragment,
        seq: 0,
        closed: false,
        log: log.clone(),
        written: written.clone(),
        unknown: unknown.clone(),
        pending: pending.clone(),
        oversized: oversized.clone(),
        lease: lease.clone(),
        address: address.clone(),
    };
    Fixture {
        client: Client::new(memory, peer),
        log,
        written,
        access,
        unknown,
        pending,
        oversized,
        lease,
        address,
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
fn exact(body: &[u8]) -> Expectation {
    Expectation::Exact {
        length: body.len() as u64,
        sha256: Sha256::digest(body).into(),
    }
}
fn drive(
    download: &mut Download,
    fixture: &mut Fixture,
    chunk: &mut [u8; 4096],
) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    for now in 1..65537 {
        match download.step(&mut fixture.client, scope(), now, chunk)? {
            Event::Headers { .. } => download.acknowledge_headers(now)?,
            Event::Chunk { offset, length } => {
                assert_eq!(offset, bytes.len() as u64);
                assert!(length == 4096 || offset + length as u64 == download.length().unwrap());
                bytes.extend_from_slice(&chunk[..length]);
                download.consume_chunk(chunk, now)?;
            }
            Event::Complete { length, sha256 } => {
                assert_eq!(length, bytes.len() as u64);
                assert_eq!(sha256, <[u8; 32]>::from(Sha256::digest(&bytes)));
                return Ok(bytes);
            }
            Event::Waiting => (),
            Event::Cancelled => return Err(Error::State),
        }
    }
    panic!("model original bound exhausted")
}

#[test]
fn artifact_requires_exact_bounded_raw_identity_before_any_work() {
    let mut download = Download::new();
    assert_eq!(
        download.begin(Path::Artifact, Expectation::Bounded, 1, 100),
        Err(Error::Length)
    );
    assert_eq!(
        download.begin(
            Path::Artifact,
            Expectation::Exact {
                length: 262145,
                sha256: [1; 32]
            },
            1,
            100
        ),
        Err(Error::Length)
    );
    download
        .begin(
            Path::Artifact,
            Expectation::Exact {
                length: 262144,
                sha256: [1; 32],
            },
            1,
            100,
        )
        .unwrap();
    assert_eq!(download.calls(), 0);
    assert_eq!(
        download.begin(Path::Timestamp, Expectation::Bounded, 2, 101),
        Err(Error::State)
    );
}

#[test]
fn actual_codec_partial_headers_writes_and_body_use_one_checked_private_chunk() {
    let body: Vec<_> = (0..8207).map(|n| (n % 251) as u8).collect();
    for fragment in [7, 67, 1024] {
        let mut peer = fixture(framed(&body), fragment);
        let mut d = Download::new();
        let mut chunk = [0; 4096];
        d.begin(Path::Artifact, exact(&body), 1, 65537).unwrap();
        assert_eq!(drive(&mut d, &mut peer, &mut chunk).unwrap(), body);
        assert_eq!(
            *peer.written.borrow(),
            b"GET /artifacts/hello.zion HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n"
        );
        let log = peer.log.borrow();
        assert_eq!(log[0].0, Operation::Close);
        assert_eq!(log.last().unwrap().0, Operation::Status);
        assert_eq!(log.iter().filter(|r| r.0 == Operation::Close).count(), 2);
        assert!(log.iter().all(|(_, cut)| *cut <= 65537));
    }
    assert!(core::mem::size_of::<Download>() < 1024);
}

#[test]
fn maximum_raw_artifact_streams_through_the_real_affine_store_and_full_readback() {
    use crate::native_acquisition::{Put, Read, tests as store_model};
    let body: Vec<_> = (0..262144).map(|n| (n % 251) as u8).collect();
    let mut peer = fixture(framed(&body), 1024);
    let mut d = Download::new();
    let mut chunk = [0; 4096];
    d.begin(Path::Artifact, exact(&body), 1, 65537).unwrap();
    let mut store = Some(store_model::format());
    let mut put: Option<Put<store_model::Disk>> = None;
    let mut final_tick = 0;
    for now in 1..65537 {
        match d.step(&mut peer.client, scope(), now, &mut chunk).unwrap() {
            Event::Headers { length } => {
                assert_eq!(length, 262144);
                put = Some(
                    store
                        .take()
                        .unwrap()
                        .begin_put(
                            length,
                            Sha256::digest(&body).into(),
                            ev_content_store::TransferCut::new(1, 65537).unwrap(),
                            now,
                        )
                        .unwrap_or_else(|_| panic!("actual append reserve")),
                );
                d.acknowledge_headers(now).unwrap();
            }
            Event::Chunk { length, .. } => {
                put.as_mut()
                    .unwrap()
                    .write_chunk(&chunk[..length], now)
                    .unwrap_or_else(|_| panic!("actual chunk IO"));
                d.consume_chunk(&chunk, now).unwrap();
            }
            Event::Complete { length, sha256 } => {
                assert_eq!(length, body.len() as u64);
                assert_eq!(sha256, <[u8; 32]>::from(Sha256::digest(&body)));
                final_tick = now;
                break;
            }
            Event::Waiting => (),
            Event::Cancelled => panic!("unexpected cancel"),
        }
    }
    assert!(final_tick != 0 && d.calls() < 400);
    let mut read: Read<store_model::Disk> = put
        .take()
        .unwrap()
        .seal(final_tick)
        .unwrap_or_else(|_| panic!("seal actual raw identity"));
    let mut offset = 0;
    while read.remaining() != 0 {
        let n = read
            .read_chunk(&mut chunk, final_tick)
            .unwrap_or_else(|_| panic!("actual readback"));
        assert_eq!(chunk[..n], body[offset..offset + n]);
        offset += n;
    }
    let verified = read
        .finish()
        .unwrap_or_else(|_| panic!("actual full-hash readback"));
    assert_eq!(verified.object.length(), 262144);
    assert_eq!(
        verified.object.sha256(),
        <[u8; 32]>::from(Sha256::digest(&body))
    );
    assert!(verified.store.snapshot().is_none()); // Stored transport bytes do not mint trust.
}

#[test]
fn truncation_wrong_hash_extra_body_and_ambiguous_framing_never_complete() {
    let body = vec![0x42; 100];
    for (bytes,expected) in [
        (framed(&body[..99]),exact(&body)),
        (framed(&[0x43;100]),exact(&body)),
        ([framed(&body),vec![1]].concat(),exact(&body)),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nContent-Length: 100\r\nConnection: close\r\n\r\n".to_vec(),exact(&body)),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec(),exact(&body)),
        (b"HTTP/1.1 302 Found\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx".to_vec(),exact(&body)),
    ] {
        let mut peer=fixture(bytes,1024);let mut d=Download::new();d.begin(Path::Artifact,expected,1,65537).unwrap();assert!(drive(&mut d,&mut peer,&mut[0;4096]).is_err());
    }
    let mut bytes = framed(&body);
    bytes.pop();
    let mut peer = fixture(bytes, 1024);
    let mut d = Download::new();
    d.begin(Path::Artifact, exact(&body), 1, 65537).unwrap();
    assert_eq!(drive(&mut d, &mut peer, &mut [0; 4096]), Err(Error::Http));
}

#[test]
fn quiescent_pending_pacing_and_consumer_waits_never_spend_rpc_or_renew_cut() {
    let body = vec![9; 6000];
    let mut peer = fixture(framed(&body), 1024);
    let mut d = Download::new();
    let mut chunk = [0; 4096];
    d.begin(Path::Artifact, exact(&body), 1, 65537).unwrap();
    let mut at = 0;
    for now in 1..1000 {
        if matches!(
            d.step(&mut peer.client, scope(), now, &mut chunk).unwrap(),
            Event::Headers { .. }
        ) {
            at = now;
            break;
        }
    }
    assert!(at != 0);
    let calls = peer.log.borrow().len();
    d.step(&mut peer.client, scope(), at + 1, &mut chunk)
        .unwrap();
    assert_eq!(calls, peer.log.borrow().len());
    d.acknowledge_headers(at + 1).unwrap();
    peer.pending.set(true);
    d.step(&mut peer.client, scope(), at + 2, &mut chunk)
        .unwrap();
    let calls = peer.log.borrow().len();
    for now in at + 2..at + 66 {
        d.step(&mut peer.client, scope(), now, &mut chunk).unwrap();
        assert_eq!(calls, peer.log.borrow().len());
    }
    d.step(&mut peer.client, scope(), at + 66, &mut chunk)
        .unwrap();
    assert_eq!(calls + 1, peer.log.borrow().len());
    assert_eq!(
        d.step(&mut peer.client, scope(), 65537, &mut chunk),
        Err(Error::Expired)
    );
    let accesses = peer.access.get();
    assert!(d.cancel(65536).is_err());
    assert!(
        d.step(&mut peer.client, scope(), 65538, &mut chunk)
            .is_err()
    );
    assert_eq!(accesses, peer.access.get());
}

#[test]
fn unknown_reply_pins_the_actual_client_and_cancel_never_replays_it() {
    let body = vec![8; 100];
    let mut peer = fixture(framed(&body), 1024);
    peer.unknown.set(true);
    let mut d = Download::new();
    d.begin(Path::Artifact, exact(&body), 1, 1000).unwrap();
    let mut chunk = [0; 4096];
    assert_eq!(
        d.step(&mut peer.client, scope(), 1, &mut chunk),
        Err(Error::Client(ClientError::Transport))
    );
    assert!(peer.client.quarantined());
    let calls = peer.log.borrow().len();
    let accesses = peer.access.get();
    d.cancel(2).unwrap();
    assert_eq!(
        d.step(&mut peer.client, scope(), 2, &mut chunk),
        Err(Error::Client(ClientError::Quarantined))
    );
    assert_eq!(calls, peer.log.borrow().len());
    assert_eq!(accesses, peer.access.get());
}

#[test]
fn canonical_metadata_bounds_and_every_header_split_preserve_raw_body_identity() {
    let body = vec![0xfe; Path::Timestamp.maximum() as usize];
    let bytes = framed(&body);
    for split in 0..bytes.len().min(180) {
        let mut h = http::Http::new();
        let mut chunk = [0; 4096];
        let mut used = 0;
        h.push(
            &bytes[..split],
            Path::Timestamp.maximum(),
            Expectation::Bounded,
            &mut chunk,
            &mut used,
        )
        .unwrap();
        h.push(
            &bytes[split..],
            Path::Timestamp.maximum(),
            Expectation::Bounded,
            &mut chunk,
            &mut used,
        )
        .unwrap();
        h.finish().unwrap();
        assert_eq!(h.length(), Some(body.len() as u64));
        assert_eq!(chunk[..used], body);
    }
    let mut peer = fixture(framed(&body), 31);
    let mut d = Download::new();
    d.begin(Path::Timestamp, Expectation::Bounded, 1, 65537)
        .unwrap();
    assert_eq!(drive(&mut d, &mut peer, &mut [0; 4096]).unwrap(), body);
    let too_large = vec![1; Path::Timestamp.maximum() as usize + 1];
    let mut peer = fixture(framed(&too_large), 1024);
    let mut d = Download::new();
    d.begin(Path::Timestamp, Expectation::Bounded, 1, 65537)
        .unwrap();
    assert!(drive(&mut d, &mut peer, &mut [0; 4096]).is_err());
    assert_eq!(
        Path::Targets.maximum(),
        core::mem::size_of_val(&crate::native_acquisition::Buffers::empty().targets) as u64
    );
}

#[test]
fn cancelled_socket_reaches_actual_closed_once_without_creating_a_complete_object() {
    let body = vec![1; 9000];
    let mut peer = fixture(framed(&body), 1024);
    let mut d = Download::new();
    let mut chunk = [0; 4096];
    d.begin(Path::Artifact, exact(&body), 1, 65537).unwrap();
    let mut at = 0;
    for now in 1..1000 {
        if matches!(
            d.step(&mut peer.client, scope(), now, &mut chunk).unwrap(),
            Event::Headers { .. }
        ) {
            at = now;
            break;
        }
    }
    assert!(at != 0);
    d.cancel(at + 1).unwrap();
    assert_eq!(d.cancel(at + 1), Err(Error::State));
    let mut cancelled = false;
    for now in at + 1..at + 200 {
        match d.step(&mut peer.client, scope(), now, &mut chunk).unwrap() {
            Event::Cancelled => {
                cancelled = true;
                break;
            }
            Event::Waiting => (),
            other => panic!("cancel yielded {other:?}"),
        }
    }
    assert!(cancelled);
    assert_eq!(
        peer.log
            .borrow()
            .iter()
            .filter(|r| r.0 == Operation::Close)
            .count(),
        2
    );
    assert!(d.consume_chunk(&chunk, at + 200).is_err());
}

#[test]
fn altered_chunk_regressed_clock_and_excessive_positive_fragments_never_reenter_transport() {
    let body = vec![7; 5000];
    let mut peer = fixture(framed(&body), 1024);
    let mut d = Download::new();
    let mut chunk = [0; 4096];
    d.begin(Path::Artifact, exact(&body), 1, 65537).unwrap();
    let mut at = 0;
    for now in 1..1000 {
        if matches!(
            d.step(&mut peer.client, scope(), now, &mut chunk).unwrap(),
            Event::Headers { .. }
        ) {
            at = now;
            break;
        }
    }
    d.acknowledge_headers(at).unwrap();
    chunk[0] ^= 1;
    let calls = peer.log.borrow().len();
    assert_eq!(
        d.step(&mut peer.client, scope(), at + 1, &mut chunk),
        Err(Error::Buffer)
    );
    assert_eq!(calls, peer.log.borrow().len());
    let mut peer = fixture(framed(&body), 1024);
    let mut d = Download::new();
    d.begin(Path::Artifact, exact(&body), 5, 65537).unwrap();
    d.step(&mut peer.client, scope(), 5, &mut chunk).unwrap();
    let calls = peer.log.borrow().len();
    assert_eq!(
        d.step(&mut peer.client, scope(), 4, &mut chunk),
        Err(Error::Clock)
    );
    assert!(d.cancel(6).is_err());
    assert!(d.step(&mut peer.client, scope(), 6, &mut chunk).is_err());
    assert_eq!(calls, peer.log.borrow().len());
    let mut peer = fixture(framed(&vec![8; 262144]), 1);
    let mut d = Download::new();
    d.begin(
        Path::Artifact,
        Expectation::Exact {
            length: 262144,
            sha256: [8; 32],
        },
        1,
        65537,
    )
    .unwrap();
    assert_eq!(drive(&mut d, &mut peer, &mut chunk), Err(Error::Counter));
    assert_eq!(peer.log.borrow().len(), usize::from(MAX_CALLS));
    let calls = peer.log.borrow().len();
    assert!(d.cancel(5000).is_err());
    assert_eq!(calls, peer.log.borrow().len());
}

#[test]
fn read_credit_rejects_invalid_limits_before_publication_and_pins_oversized_reply() {
    let mut peer = fixture(framed(&[1; 100]), 1024);
    let accesses = peer.access.get();
    assert!(peer.client.read_limit(0, 1, 100).is_err());
    assert!(peer.client.read_limit(1025, 1, 100).is_err());
    assert_eq!(accesses, peer.access.get());
    assert!(peer.log.borrow().is_empty());
    peer.oversized.set(true);
    assert_eq!(
        peer.client.read_limit(1, 1, 100),
        Err(ClientError::Response)
    );
    assert!(peer.client.quarantined());
    let accesses = peer.access.get();
    assert!(peer.client.close(2, 100).is_err());
    assert_eq!(accesses, peer.access.get());
}
#[test]
fn each_new_connection_needs_live_lease_and_diagnostic_dns_never_changes_fixed_peer() {
    let body = vec![1; 100];
    let mut peer = fixture(framed(&body), 1024);
    peer.lease.set(false);
    let mut d = Download::new();
    d.begin(Path::Artifact, exact(&body), 1, 65537).unwrap();
    assert_eq!(drive(&mut d, &mut peer, &mut [0; 4096]), Err(Error::Lease));
    assert!(!peer.log.borrow().iter().any(|r| r.0 == Operation::Connect));
    let mut peer = fixture(framed(&body), 1024);
    peer.address.set([1, 2, 3, 4]);
    let mut d = Download::new();
    d.begin(Path::Artifact, exact(&body), 1, 65537).unwrap();
    assert_eq!(drive(&mut d, &mut peer, &mut [0; 4096]).unwrap(), body);
    assert_eq!(d.resolved(), Some([1, 2, 3, 4]));
    // Peer::call independently checks Connect remains10.0.2.2:8080 even
    // when the actual profile's diagnostic example.org resolved elsewhere.
    assert!(peer.log.borrow().iter().any(|r| r.0 == Operation::Connect));
    let mut peer = fixture(framed(&body), 1024);
    let mut d = Download::new();
    let mut chunk = [0; 4096];
    d.begin(Path::Artifact, exact(&body), 1, 65537).unwrap();
    let mut at = 0;
    for now in 1..1000 {
        if matches!(
            d.step(&mut peer.client, scope(), now, &mut chunk).unwrap(),
            Event::Headers { .. }
        ) {
            at = now;
            break;
        }
    }
    assert!(at != 0);
    peer.lease.set(false);
    d.cancel(at + 1).unwrap();
    let mut cancelled = false;
    for now in at + 1..at + 200 {
        match d.step(&mut peer.client, scope(), now, &mut chunk).unwrap() {
            Event::Waiting => (),
            Event::Cancelled => {
                cancelled = true;
                break;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(cancelled);
}
