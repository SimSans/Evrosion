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
    sequence: u32,
    statuses: usize,
    queries: usize,
    reads: Rc<RefCell<VecDeque<Vec<u8>>>>,
    written: Rc<RefCell<Vec<u8>>>,
    cuts: Rc<RefCell<Vec<u64>>>,
    failed: Rc<Cell<bool>>,
    pending_tcp: Rc<Cell<bool>>,
    connected: bool,
}
impl Transport for Peer {
    type Error = ();
    fn call(&mut self, bytes: [u8; 8], cut: u64) -> Result<[u8; 8], ()> {
        self.cuts.borrow_mut().push(cut);
        if self.failed.get() {
            return Err(());
        }
        let notice = Notice::decode(bytes).unwrap();
        assert_eq!(notice.sequence, self.sequence + 1);
        self.sequence = notice.sequence;
        let mut packet = Packet::new();
        packet.read_request(&mut self.memory, notice).unwrap();
        let mut status = Status::Complete;
        let body = match notice.operation {
            Operation::Initialize => Vec::new(),
            Operation::Status => {
                let mut b = vec![0; 32];
                b[0] = 1;
                self.statuses += 1;
                if self.statuses >= 2 {
                    b[1] = 1;
                    b[5] = 24;
                    b[8..12].copy_from_slice(&[10, 0, 2, 15]);
                }
                if self.statuses >= 4 {
                    b[2] = 4;
                }
                if self.connected && self.pending_tcp.get() {
                    b[2] = 2; // explicit canonical SynSent in this codec model
                }
                b
            }
            Operation::Resolve => {
                assert_eq!(packet.data(), b"example.org");
                status = Status::Pending;
                Vec::new()
            }
            Operation::QueryResult => {
                self.queries += 1;
                if self.queries == 1 {
                    status = Status::Pending;
                    Vec::new()
                } else {
                    vec![93, 184, 216, 34]
                }
            }
            Operation::Connect => {
                self.connected = true;
                // The returned DNS diagnostic address above is deliberately
                // different. Only the independent catalogue scope is used.
                assert_eq!(packet.data(), &[10, 0, 2, 2, 0x90, 0x1f]);
                status = Status::Pending;
                Vec::new()
            }
            Operation::Write => {
                let remaining = packet.data();
                let n = if self.written.borrow().is_empty() {
                    remaining.len().min(10)
                } else {
                    remaining.len()
                };
                self.written.borrow_mut().extend_from_slice(&remaining[..n]);
                (n as u16).to_le_bytes().to_vec()
            }
            Operation::Read => {
                assert_eq!(packet.data(), &1024u16.to_le_bytes());
                self.reads.borrow_mut().pop_front().unwrap()
            }
            _ => panic!("unexpected control operation"),
        };
        packet
            .reply(&mut self.memory, notice, status, &body)
            .map_err(|_| ())
    }
}
fn policy() -> NetworkPolicy<'static> {
    NetworkPolicy {
        allowed_ipv4: [10, 0, 2, 2],
        remote_port: 8080,
        local_port: 49152,
        dns_name: "example.org",
    }
}
struct Fixture {
    client: Client<Memory, Peer>,
    cuts: Rc<RefCell<Vec<u64>>>,
    written: Rc<RefCell<Vec<u8>>>,
    failed: Rc<Cell<bool>>,
    pending_tcp: Rc<Cell<bool>>,
    reads: Rc<RefCell<VecDeque<Vec<u8>>>>,
    accesses: Rc<Cell<usize>>,
}
fn fixture() -> Fixture {
    let accesses = Rc::new(Cell::new(0));
    let memory = Memory(Rc::new(RefCell::new([0; 4096])), accesses.clone());
    let cuts = Rc::new(RefCell::new(Vec::new()));
    let written = Rc::new(RefCell::new(Vec::new()));
    let failed = Rc::new(Cell::new(false));
    let pending_tcp = Rc::new(Cell::new(false));
    let mut response =
        b"HTTP/1.1 200 OK\r\nContent-Length: 28\r\nConnection: close\r\n\r\n".to_vec();
    response.extend_from_slice(BODY);
    let reads = Rc::new(RefCell::new(VecDeque::from([
        response[..17].to_vec(),
        response[17..].to_vec(),
        Vec::new(),
    ])));
    let peer = Peer {
        memory: memory.clone(),
        sequence: 0,
        statuses: 0,
        queries: 0,
        reads: reads.clone(),
        written: written.clone(),
        cuts: cuts.clone(),
        failed: failed.clone(),
        pending_tcp: pending_tcp.clone(),
        connected: false,
    };
    let mut client = Client::new(memory, peer);
    client
        .initialize(&123u64.to_le_bytes(), policy(), 1, 100)
        .unwrap();
    Fixture {
        client,
        cuts,
        written,
        failed,
        pending_tcp,
        reads,
        accesses,
    }
}
#[test]
fn healthy_pending_status_waits_for_ticks_and_expires_at_original_cut_without_quarantine() {
    // Actual Client/Packet codecs with a model peer held in SynSent. This is
    // not actual network execution or evidence of the failed guest's cause.
    let mut f = fixture();
    f.pending_tcp.set(true);
    let mut t = Transfer::new();
    t.begin(2, 2000).unwrap();
    assert_eq!(t.last_tcp(), None);
    for now in 3..2000 {
        t.step(&mut f.client, policy(), now).unwrap();
    }
    assert!(t.calls() < 128);
    assert_eq!(t.stage(), 4);
    assert_eq!(t.last_tcp(), Some(2));
    let calls = f.cuts.borrow().len();
    assert_eq!(calls, usize::from(t.calls()) + 1); // Initialize + actual requests
    assert_eq!(t.step(&mut f.client, policy(), 2000), Err(Error::Expired));
    assert_eq!(t.last_tcp(), Some(2));
    assert_eq!(f.cuts.borrow().len(), calls);
    assert!(!f.client.quarantined());
    assert!(f.written.borrow().is_empty());
    assert!(t.finished());
}
#[test]
fn same_tick_before_due_expiry_and_regression_never_publish_a_new_request() {
    let mut f = fixture();
    let mut t = Transfer::new();
    t.begin(2, 2000).unwrap();
    assert_eq!(t.step(&mut f.client, policy(), 3), Ok(None));
    let calls = f.cuts.borrow().len();
    assert_eq!(t.calls(), 1);
    let accesses = f.accesses.get();
    for now in [3, 4, 66] {
        assert_eq!(t.step(&mut f.client, policy(), now), Ok(None));
        assert_eq!(f.cuts.borrow().len(), calls);
        assert_eq!(t.calls(), 1);
        assert_eq!(f.accesses.get(), accesses);
    }
    assert_eq!(
        t.step(&mut f.client, policy(), 67).unwrap().unwrap().stage,
        2
    );
    assert_eq!(f.cuts.borrow().len(), calls + 1);
    assert_eq!(t.calls(), 2);
    let mut f = fixture();
    let mut t = Transfer::new();
    t.begin(2, 50).unwrap();
    t.step(&mut f.client, policy(), 3).unwrap();
    let calls = f.cuts.borrow().len();
    assert_eq!(t.step(&mut f.client, policy(), 49), Ok(None));
    assert_eq!(t.step(&mut f.client, policy(), 50), Err(Error::Expired));
    assert_eq!(f.cuts.borrow().len(), calls);
    let mut f = fixture();
    let mut t = Transfer::new();
    t.begin(2, 2000).unwrap();
    t.step(&mut f.client, policy(), 3).unwrap();
    t.step(&mut f.client, policy(), 4).unwrap();
    let calls = f.cuts.borrow().len();
    assert_eq!(t.step(&mut f.client, policy(), 3), Err(Error::Clock));
    assert_eq!(f.cuts.borrow().len(), calls);
}
#[test]
fn positive_fragmented_progress_keeps_the_original_128_request_work_limit() {
    let mut f = fixture();
    let mut response = b"HTTP/1.1 200 OK\r\n".to_vec();
    for _ in 0..3 {
        response.extend_from_slice(b"X-Pad: ");
        response.extend_from_slice(&[b'x'; 100]);
        response.extend_from_slice(b"\r\n");
    }
    response.extend_from_slice(b"Content-Length: 28\r\n\r\n");
    response.extend_from_slice(BODY);
    *f.reads.borrow_mut() = response
        .into_iter()
        .map(|b| vec![b])
        .chain([Vec::new()])
        .collect();
    let mut t = Transfer::new();
    t.begin(2, 2000).unwrap();
    let mut error = None;
    for now in 3..2000 {
        match t.step(&mut f.client, policy(), now) {
            Ok(_) => (),
            Err(e) => {
                error = Some(e);
                break;
            }
        }
    }
    assert_eq!(error, Some(Error::Counter));
    assert_eq!(t.calls(), 128);
    assert_eq!(t.last_tcp(), Some(4));
    assert!(!f.client.quarantined());
    assert_eq!(&*f.written.borrow(), REQUEST);
    assert_eq!(f.cuts.borrow().len(), 129);
}
#[test]
fn actual_codec_flow_preserves_dns_scope_partial_writes_original_cut_and_real_eof() {
    let mut f = fixture();
    let mut t = Transfer::new();
    t.begin(2, 512).unwrap();
    let mut rows = Vec::new();
    for now in 3..500 {
        if let Some(p) = t.step(&mut f.client, policy(), now).unwrap() {
            rows.push(p);
        }
        if t.finished() {
            break;
        }
    }
    assert!(t.finished());
    assert_eq!(
        rows.iter().map(|p| p.stage).collect::<Vec<_>>(),
        [2, 3, 4, 5, 6]
    );
    assert_eq!(rows[0].argument, u32::from_le_bytes([10, 0, 2, 15]));
    assert_eq!(rows[1].argument, u32::from_le_bytes([93, 184, 216, 34]));
    assert_eq!(rows[4].argument, 28);
    assert_eq!(&*f.written.borrow(), REQUEST);
    assert!(f.cuts.borrow()[1..].iter().all(|cut| *cut == 512));
    let calls = f.cuts.borrow().len();
    assert_eq!(t.step(&mut f.client, policy(), 501), Ok(None));
    assert_eq!(f.cuts.borrow().len(), calls);
}
#[test]
fn expiry_regression_and_unknown_result_refuse_without_new_window_or_transport() {
    for clock in [2, 200] {
        let mut f = fixture();
        let mut t = Transfer::new();
        t.begin(3, 200).unwrap();
        let calls = f.cuts.borrow().len();
        assert!(t.step(&mut f.client, policy(), clock).is_err());
        assert!(t.finished());
        assert_eq!(f.cuts.borrow().len(), calls);
    }
    let mut f = fixture();
    let mut t = Transfer::new();
    t.begin(2, 200).unwrap();
    f.failed.set(true);
    assert!(t.step(&mut f.client, policy(), 3).is_err());
    assert!(t.finished() && f.client.quarantined());
    let calls = f.cuts.borrow().len();
    assert_eq!(t.step(&mut f.client, policy(), 4), Ok(None));
    assert_eq!(f.cuts.borrow().len(), calls);
}
#[test]
fn parser_handles_every_fragment_boundary_and_requires_actual_exact_eof() {
    let mut response =
        b"HTTP/1.1 200 OK\r\ncontent-length: 28\r\nConnection: close\r\n\r\n".to_vec();
    response.extend_from_slice(BODY);
    for split in 0..=response.len() {
        let mut h = Http::new();
        h.push(&response[..split]).unwrap();
        if split < response.len() {
            assert_eq!(h.finish(), Err(Error::Http));
        }
        h.push(&response[split..]).unwrap();
        h.finish().unwrap();
    }
    let mut h = Http::new();
    for b in &response {
        h.push(&[*b]).unwrap();
    }
    h.finish().unwrap();
    assert_eq!(h.push(b"x"), Err(Error::Http));
}
#[test]
fn ambiguous_truncated_encoded_oversized_or_wrong_http_never_completes() {
    for header in [
        &b"HTTP/1.1 404 Not Found\r\nContent-Length: 28\r\n\r\n"[..],
        b"HTTP/1.1 200 OK\nContent-Length: 28\n\n",
        b"HTTP/1.1 200 OK\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 28\r\nContent-Length: 28\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 29\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: +28\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 28\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 28\r\nContent-Encoding: gzip\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 28\r\nBad\rHeader: x\r\n\r\n",
    ] {
        let mut h = Http::new();
        assert!(h.push(header).is_err() || h.finish().is_err());
    }
    let mut h = Http::new();
    assert_eq!(h.push(&[b'x'; 129]), Err(Error::Http));
    let mut h = Http::new();
    h.push(b"HTTP/1.1 200 OK\r\nContent-Length: 28\r\n\r\n")
        .unwrap();
    h.push(&BODY[..27]).unwrap();
    assert_eq!(h.finish(), Err(Error::Http));
    assert_eq!(h.push(b"!"), Err(Error::Http));
}
