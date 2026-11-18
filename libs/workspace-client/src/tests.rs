extern crate std;
use super::*;
use std::{collections::VecDeque, vec, vec::Vec};

#[derive(Clone, Copy)]
enum Answer {
    Complete,
    Outcome(Outcome),
    WrongRequest,
    WrongDigest,
    Remote,
}
struct Peer {
    answers: VecDeque<Answer>,
    requests: Vec<Request>,
    now: u64,
    data: Vec<u8>,
    read_count: usize,
}
impl Peer {
    fn new(answers: &[Answer]) -> Self {
        Self {
            answers: answers.iter().copied().collect(),
            requests: Vec::new(),
            now: 10,
            data: b"hello".to_vec(),
            read_count: 0,
        }
    }
}
impl Link for Peer {
    fn now(&mut self) -> Result<u64, TransportError> {
        Ok(self.now)
    }
    fn exchange(
        &mut self,
        id: u64,
        bytes: &[u8; wire::FRAME_BYTES],
        bulk: &[u8],
        deadline: Deadline,
    ) -> Result<[u8; wire::FRAME_BYTES], TransportError> {
        let q = Request::decode(bytes).unwrap();
        assert_eq!(q.request_id, id);
        assert_eq!(q.deadline, deadline);
        self.requests.push(q);
        let answer = self.answers.pop_front().unwrap();
        if matches!(answer, Answer::Remote) {
            return Err(TransportError::Rpc);
        }
        let mut response = Response {
            request_id: id,
            operation_id: q.operation_id,
            outcome: Outcome::Completed,
            revision: q.expected_revision,
            transfer_id: 0,
            offset: 0,
            length: 0,
            file_length: 0,
            digest: [0; 32],
        };
        match q.method {
            Method::Read { offset, length } => {
                let at = offset as usize;
                let end = (at + length as usize).min(self.data.len());
                response.offset = offset;
                response.length = (end - at) as u32;
                response.file_length = self.data.len() as u32;
                response.digest = Sha256::digest(&self.data[at..end]).into();
            }
            Method::BeginWrite { length, digest } => {
                response.transfer_id = 17;
                response.file_length = length;
                response.digest = digest;
            }
            Method::WriteChunk {
                transfer_id,
                offset,
                length,
                digest,
            } => {
                assert_eq!(bulk.len(), length as usize);
                response.transfer_id = transfer_id;
                response.offset = offset;
                response.length = length;
                response.file_length = offset + length;
                response.digest = digest;
            }
            Method::Commit {
                transfer_id,
                length,
                digest,
            } => {
                response.transfer_id = transfer_id;
                response.file_length = length;
                response.digest = digest;
                response.revision += 1;
            }
            Method::Abort { transfer_id } => response.transfer_id = transfer_id,
            Method::Verify {
                transfer_id,
                offset,
                length,
                digest,
            } => {
                response.transfer_id = transfer_id;
                response.offset = (offset + CHUNK_BYTES as u32).min(length);
                response.file_length = length;
                response.digest = digest;
            }
            Method::QueryOperation => unreachable!(),
        }
        match answer {
            Answer::Outcome(outcome) => {
                response.outcome = outcome;
                response.revision = 0;
                response.transfer_id = 0;
                response.offset = 0;
                response.length = 0;
                response.file_length = 0;
                response.digest = [0; 32];
            }
            Answer::WrongRequest => response.request_id += 1,
            Answer::WrongDigest => response.digest[0] ^= 1,
            _ => (),
        }
        response.encode().map_err(|_| TransportError::Correlation)
    }
    fn read_bulk(&mut self, out: &mut [u8]) -> Result<(), TransportError> {
        self.read_count += 1;
        out.copy_from_slice(&self.data[..out.len()]);
        Ok(())
    }
}
fn deadline() -> Deadline {
    Deadline::new(100).unwrap()
}
fn begin() -> Method {
    Method::BeginWrite {
        length: 5,
        digest: Sha256::digest(b"hello").into(),
    }
}

#[test]
fn save_has_distinct_mutation_nonces_and_independent_transfer_identity() {
    let mut c = FileClient::new(Peer::new(&[Answer::Complete; 4]));
    let started = c.issue(7, begin(), deadline(), &[], &mut []).unwrap();
    let transfer = started.response.transfer_id;
    let digest = Sha256::digest(b"hello").into();
    c.issue(
        7,
        Method::WriteChunk {
            transfer_id: transfer,
            offset: 0,
            length: 5,
            digest,
        },
        deadline(),
        b"hello",
        &mut [],
    )
    .unwrap();
    let saved = c
        .issue(
            7,
            Method::Commit {
                transfer_id: transfer,
                length: 5,
                digest,
            },
            deadline(),
            &[],
            &mut [],
        )
        .unwrap();
    assert_eq!(saved.response.revision, 8);
    let mut data = [0; 4096];
    c.issue(
        8,
        Method::Read {
            offset: 0,
            length: 4096,
        },
        deadline(),
        &[],
        &mut data,
    )
    .unwrap();
    assert_eq!(&data[..5], b"hello");
    assert_eq!(
        c.link
            .requests
            .iter()
            .map(|q| q.operation_id)
            .collect::<Vec<_>>(),
        [1, 2, 3, 0]
    );
    assert_eq!(
        c.link
            .requests
            .iter()
            .map(|q| q.request_id)
            .collect::<Vec<_>>(),
        [1, 2, 3, 4]
    );
    assert!(!c.fenced());
}

#[test]
fn uncertain_accepted_stale_corrupt_and_wrong_correlation_hold_same_request() {
    for answer in [
        Answer::Remote,
        Answer::WrongRequest,
        Answer::Outcome(Outcome::Accepted),
        Answer::Outcome(Outcome::Uncertain),
        Answer::Outcome(Outcome::Stale),
        Answer::Outcome(Outcome::Corrupt),
    ] {
        let mut c = FileClient::new(Peer::new(&[answer]));
        let _ = c.issue(1, begin(), deadline(), &[], &mut []);
        assert!(c.fenced());
        let retained = c.retained_request().unwrap();
        assert_eq!(retained.request_id, 1);
        assert_eq!(retained.operation_id, 1);
        assert_eq!(
            c.issue(1, begin(), deadline(), &[], &mut []),
            Err(Error::Fenced)
        );
        assert_eq!(c.link.requests, [retained]);
    }
}

#[test]
fn corrupted_read_bytes_never_clear_retained_request_or_allow_reuse() {
    let mut c = FileClient::new(Peer::new(&[Answer::WrongDigest]));
    let mut out = [0; 5];
    assert_eq!(
        c.issue(
            1,
            Method::Read {
                offset: 0,
                length: 5
            },
            deadline(),
            &[],
            &mut out
        ),
        Err(Error::Digest)
    );
    assert!(c.fenced());
    assert_eq!(c.link.read_count, 1);
}

#[test]
fn pre_delivery_validation_and_expiry_do_not_consume_ids_or_touch_link() {
    let mut c = FileClient::new(Peer::new(&[Answer::Complete]));
    let bad = Method::WriteChunk {
        transfer_id: 7,
        offset: 0,
        length: 5,
        digest: [1; 32],
    };
    assert_eq!(
        c.issue(1, bad, deadline(), b"hello", &mut []),
        Err(Error::Digest)
    );
    assert_eq!(
        c.issue(1, begin(), Deadline::new(10).unwrap(), &[], &mut []),
        Err(Error::Deadline)
    );
    assert_eq!(
        c.issue(
            1,
            Method::Read {
                offset: 0,
                length: 4096
            },
            deadline(),
            &[],
            &mut [0; 5]
        ),
        Err(Error::Bounds)
    );
    assert_eq!(
        c.issue(1, Method::QueryOperation, deadline(), &[], &mut []),
        Err(Error::Bounds)
    );
    assert!(!c.fenced());
    assert!(c.link.requests.is_empty());
    let receipt = c.issue(1, begin(), deadline(), &[], &mut []).unwrap();
    assert_eq!(
        (receipt.request.request_id, receipt.request.operation_id),
        (1, 1)
    );
}

#[test]
fn ordinary_refusal_finishes_control_but_never_claims_save() {
    let mut c = FileClient::new(Peer::new(&[
        Answer::Outcome(Outcome::Denied),
        Answer::Complete,
    ]));
    let result = c.issue(1, begin(), deadline(), &[], &mut []).unwrap();
    assert_eq!(result.response.outcome, Outcome::Denied);
    assert!(!c.fenced());
    let next = c.issue(1, begin(), deadline(), &[], &mut []).unwrap();
    assert_eq!((next.request.request_id, next.request.operation_id), (2, 2));
}

#[test]
fn counter_exhaustion_and_backward_clock_refuse_before_new_delivery() {
    let mut c = FileClient::new(Peer::new(&[Answer::Complete; 2]));
    c.next_request = u64::MAX - 1;
    assert!(c.issue(1, begin(), deadline(), &[], &mut []).is_ok());
    assert_eq!(
        c.issue(1, begin(), deadline(), &[], &mut []),
        Err(Error::Exhausted)
    );
    assert_eq!(c.link.requests.len(), 1);
    let mut c = FileClient::new(Peer::new(&[Answer::Complete; 2]));
    c.issue(1, begin(), deadline(), &[], &mut []).unwrap();
    c.link.now = 9;
    assert_eq!(
        c.issue(1, begin(), deadline(), &[], &mut []),
        Err(Error::Clock)
    );
    assert_eq!(c.link.requests.len(), 1);
}

#[test]
fn empty_file_read_still_observes_transport_and_empty_digest() {
    let mut peer = Peer::new(&[Answer::Complete]);
    peer.data = vec![];
    let mut c = FileClient::new(peer);
    let result = c
        .issue(
            1,
            Method::Read {
                offset: 0,
                length: 1,
            },
            deadline(),
            &[],
            &mut [0],
        )
        .unwrap();
    assert_eq!(result.response.length, 0);
    assert_eq!(result.response.digest, <[u8; 32]>::from(Sha256::digest([])));
    assert_eq!(c.link.read_count, 1);
    assert_eq!(c.link.requests.len(), 1);
}

#[test]
fn distinct_completed_requests_use_new_clamped_cuts_without_extending_the_whole_file() {
    use crate::transfer::{FILE_RPC_TICKS, MAX_TRANSFER_BYTES, Transfer};
    assert_eq!(
        FILE_RPC_TICKS,
        ev_userspace_contract::root_v5::resources::FILE_TRANSACTION_TICKS
    );
    let mut whole = Transfer::capture(10, MAX_TRANSFER_BYTES).unwrap();
    let retained_whole = whole.whole_cut();
    let mut c = FileClient::new(Peer::new(&[Answer::Complete; 3]));
    for now in [10, 10_000, retained_whole.tick() - 1] {
        c.link.now = now;
        let cut = whole.next_request(now).unwrap();
        let complete = c.issue(1, begin(), cut, &[], &mut []).unwrap();
        // Peer::exchange independently decodes the Header and requires its cut
        // to equal the actual transport cut. No accepted request is retried.
        assert_eq!(complete.request.deadline, cut);
        assert_eq!(
            cut.tick(),
            (now + FILE_RPC_TICKS).min(retained_whole.tick())
        );
        assert_eq!(whole.whole_cut(), retained_whole);
    }
    assert_eq!(c.link.requests.len(), 3);
    assert_eq!(c.link.requests[2].deadline, retained_whole);
    assert_eq!((c.next_request, c.next_operation), (4, 4));
}

#[test]
fn a_long_whole_horizon_never_renews_an_accepted_or_uncertain_request() {
    use crate::transfer::{MAX_TRANSFER_BYTES, Transfer};
    for answer in [
        Answer::Remote,
        Answer::WrongRequest,
        Answer::Outcome(Outcome::Accepted),
        Answer::Outcome(Outcome::Uncertain),
    ] {
        let mut whole = Transfer::capture(10, MAX_TRANSFER_BYTES).unwrap();
        let mut c = FileClient::new(Peer::new(&[answer]));
        let original_cut = whole.next_request(10).unwrap();
        let _ = c.issue(7, begin(), original_cut, &[], &mut []);
        let original = c.retained_request().unwrap();
        whole.fence();
        assert_eq!(whole.next_request(11), Err(transfer::Error::Fenced));
        // Even misusing a fresh policy value cannot clear the actual client's
        // retained identity/window or deliver another request with a later cut.
        let later = Transfer::capture(10_000, MAX_TRANSFER_BYTES)
            .unwrap()
            .next_request(10_000)
            .unwrap();
        c.link.now = 10_000;
        assert_eq!(c.issue(7, begin(), later, &[], &mut []), Err(Error::Fenced));
        assert_eq!(c.retained_request(), Some(original));
        assert_eq!(original.deadline, original_cut);
        assert_eq!(c.link.requests, [original]);
        assert_eq!((c.next_request, c.next_operation), (2, 2));
    }
}
