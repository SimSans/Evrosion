use super::*;
use std::{cell::Cell, vec::Vec};

fn stage(
    gateway: &mut Gateway<'_, '_, Memory>,
    route: Binding,
    revision: u64,
    text: &[u8],
) -> (u64, u64) {
    let begin = request(
        1,
        revision,
        wire::Method::BeginWrite {
            length: text.len() as u32,
            digest: hash(text),
        },
    );
    let begin_reply = reply(begin, handle(gateway, route, begin, Loan::None));
    assert_eq!(begin_reply.outcome, Outcome::Completed);
    let mut nonce = 2;
    for (index, bytes) in text.chunks(CHUNK_BYTES).enumerate() {
        let write = request(
            nonce,
            revision,
            wire::Method::WriteChunk {
                transfer_id: begin_reply.transfer_id,
                offset: (index * CHUNK_BYTES) as u32,
                length: bytes.len() as u32,
                digest: hash(bytes),
            },
        );
        assert_eq!(
            reply(write, handle(gateway, route, write, Loan::Write(bytes))).outcome,
            Outcome::Completed
        );
        nonce += 1;
    }
    (begin_reply.transfer_id, nonce)
}
fn verify(nonce: u64, revision: u64, transfer: u64, offset: u32, text: &[u8]) -> wire::Request {
    request(
        nonce,
        revision,
        wire::Method::Verify {
            transfer_id: transfer,
            offset,
            length: text.len() as u32,
            digest: hash(text),
        },
    )
}
fn commit(nonce: u64, revision: u64, transfer: u64, text: &[u8]) -> wire::Request {
    request(
        nonce,
        revision,
        wire::Method::Commit {
            transfer_id: transfer,
            length: text.len() as u32,
            digest: hash(text),
        },
    )
}

#[test]
fn distinct_bounded_verify_requests_read_one_chunk_never_publish_then_commit_and_cold_bytes() {
    let memory = Memory::new();
    let mut ss = Box::new(StoreScratch::empty());
    let mut gs = Box::new(Scratch::empty());
    let (store, object, revision) = dataset(memory.clone(), &mut ss);
    let mut gateway = Gateway::new(store, &mut gs);
    let route = binding(object, 7, Rights::ReadWrite);
    gateway.bind(route).unwrap();
    let text: Vec<u8> = (0..CHUNK_BYTES * 3 + 17)
        .map(|i| b'a' + (i % 26) as u8)
        .collect();
    let (transfer, mut nonce) = stage(&mut gateway, route, revision, &text);
    let stage = gateway.store.pending_stage().unwrap();
    let last_receipt = gateway.backend_receipt().unwrap();
    let metadata = gateway.owner_metadata(object).unwrap();
    let before = memory.counts();
    for offset in (0..text.len()).step_by(CHUNK_BYTES) {
        let verify = verify(nonce, revision, transfer, offset as u32, &text);
        let counts = memory.counts();
        let response = reply(verify, handle(&mut gateway, route, verify, Loan::None));
        assert_eq!(response.outcome, Outcome::Completed);
        assert_eq!(
            response.offset,
            (offset + CHUNK_BYTES).min(text.len()) as u32
        );
        assert_eq!(response.length, 0);
        let after = memory.counts();
        assert!(
            (1..=9).contains(&(after.0 - counts.0)),
            "one chunk header plus at most eight sectors"
        );
        assert_eq!((after.1, after.2), (before.1, before.2));
        assert_eq!(gateway.owner_metadata(object).unwrap(), metadata);
        assert_eq!(gateway.store.pending_stage().unwrap(), stage);
        assert_eq!(gateway.backend_receipt().unwrap(), last_receipt);
        // Exact replay is a scoped RAM reply, not another verification step.
        let replay_before = memory.counts();
        assert_eq!(
            reply(verify, handle(&mut gateway, route, verify, Loan::None)),
            response
        );
        assert_eq!(memory.counts(), replay_before);
        let query = request(nonce, 0, wire::Method::QueryOperation);
        let queried = reply(query, handle(&mut gateway, route, query, Loan::None));
        assert_eq!(
            (queried.offset, queried.file_length, queried.digest),
            (response.offset, text.len() as u32, hash(&text))
        );
        nonce += 1;
    }
    let commit = commit(nonce, revision, transfer, &text);
    assert!(matches!(
        handle(&mut gateway, route, commit, Loan::None),
        Dispatch::Accepted { .. }
    ));
    assert!(gateway.prepared.is_none());
    assert!(gateway.commit.as_ref().unwrap().publish_ready);
    let result = gateway.poll_commit(100).unwrap();
    assert!(
        matches!(result, Dispatch::Complete { .. }),
        "complete private proof avoids the whole-file rescan"
    );
    let response = reply(commit, result);
    assert_eq!(
        (response.revision, response.file_length, response.digest),
        (revision + 1, text.len() as u32, hash(&text))
    );
    drop(gateway);
    let mut cold_scratch = Box::new(StoreScratch::empty());
    let mut cold = Dataset::open(
        Memory::image(memory.snapshot()),
        &mut cold_scratch,
        DEADLINE,
    )
    .unwrap_or_else(|_| panic!("cold"));
    assert_eq!(cold.pending_stage().unwrap(), None);
    let mut actual = vec![0; text.len()];
    for (index, chunk) in actual.chunks_mut(CHUNK_BYTES).enumerate() {
        assert_eq!(
            cold.read(
                object,
                revision + 1,
                (index * CHUNK_BYTES) as u64,
                chunk,
                DEADLINE
            )
            .unwrap(),
            chunk.len()
        );
    }
    assert_eq!(actual, text);
}

#[test]
fn verify_refuses_wrong_prefix_metadata_scope_rights_and_revocation_without_io_or_resetting_progress()
 {
    let memory = Memory::new();
    let mut ss = Box::new(StoreScratch::empty());
    let mut gs = Box::new(Scratch::empty());
    let (store, object, revision) = dataset(memory.clone(), &mut ss);
    let mut gateway = Gateway::new(store, &mut gs);
    let route = binding(object, 7, Rights::ReadWrite);
    let key = gateway.bind(route).unwrap();
    let foreign = binding(object, 8, Rights::ReadWrite);
    gateway.bind(foreign).unwrap();
    let readonly = binding(object, 9, Rights::ReadOnly);
    gateway.bind(readonly).unwrap();
    let text = vec![b'x'; CHUNK_BYTES * 3];
    let (transfer, nonce) = stage(&mut gateway, route, revision, &text);
    let skipped = verify(nonce, revision, transfer, CHUNK_BYTES as u32, &text);
    let before = memory.counts();
    assert_eq!(
        reply(skipped, handle(&mut gateway, route, skipped, Loan::None)).outcome,
        Outcome::Conflict
    );
    assert!(gateway.prepared.is_none());
    let first = verify(nonce, revision, transfer, 0, &text);
    assert_eq!(
        reply(first, handle(&mut gateway, route, first, Loan::None)).outcome,
        Outcome::Completed
    );
    assert_eq!(memory.counts().0 - before.0, 9);
    let current = gateway.prepared.as_ref().unwrap().verifier.progress();
    let before = memory.counts();
    let mut changed_replay = first;
    changed_replay.request_id += 1;
    assert_eq!(
        reply(
            changed_replay,
            handle(&mut gateway, route, changed_replay, Loan::None)
        )
        .outcome,
        Outcome::Conflict
    );
    let stale_revision = verify(nonce + 1, revision + 1, transfer, CHUNK_BYTES as u32, &text);
    assert_eq!(
        reply(
            stale_revision,
            handle(&mut gateway, route, stale_revision, Loan::None)
        )
        .outcome,
        Outcome::Conflict
    );
    let next = verify(nonce + 1, revision, transfer, CHUNK_BYTES as u32, &text);
    let mut wrong_origin = captured(route);
    wrong_origin.caller = Caller::new(77, 1).unwrap();
    assert_eq!(
        reply(
            next,
            gateway
                .handle(wrong_origin, &next.encode().unwrap(), 0, Loan::None)
                .unwrap()
        )
        .outcome,
        Outcome::Denied
    );
    assert_eq!(memory.counts(), before);
    for (binding, method, expected) in [
        (
            route,
            wire::Method::Verify {
                transfer_id: transfer,
                offset: 0,
                length: text.len() as u32,
                digest: hash(&text),
            },
            Outcome::Conflict,
        ),
        (
            route,
            wire::Method::Verify {
                transfer_id: transfer,
                offset: CHUNK_BYTES as u32,
                length: text.len() as u32 - 1,
                digest: hash(&text),
            },
            Outcome::Conflict,
        ),
        (
            route,
            wire::Method::Verify {
                transfer_id: transfer,
                offset: CHUNK_BYTES as u32,
                length: text.len() as u32,
                digest: [7; 32],
            },
            Outcome::Conflict,
        ),
        (
            route,
            wire::Method::Verify {
                transfer_id: transfer + 1,
                offset: CHUNK_BYTES as u32,
                length: text.len() as u32,
                digest: hash(&text),
            },
            Outcome::Denied,
        ),
        (
            foreign,
            wire::Method::Verify {
                transfer_id: transfer,
                offset: CHUNK_BYTES as u32,
                length: text.len() as u32,
                digest: hash(&text),
            },
            Outcome::Denied,
        ),
        (
            readonly,
            wire::Method::Verify {
                transfer_id: transfer,
                offset: CHUNK_BYTES as u32,
                length: text.len() as u32,
                digest: hash(&text),
            },
            Outcome::Denied,
        ),
    ] {
        let request = request(nonce + 1, revision, method);
        assert_eq!(
            reply(request, handle(&mut gateway, binding, request, Loan::None)).outcome,
            expected
        );
        assert_eq!(memory.counts(), before);
        assert_eq!(
            gateway.prepared.as_ref().unwrap().verifier.progress(),
            current
        );
    }
    let incomplete = commit(nonce + 1, revision, transfer, &text);
    assert_eq!(
        reply(
            incomplete,
            handle(&mut gateway, route, incomplete, Loan::None)
        )
        .outcome,
        Outcome::Conflict
    );
    assert_eq!(memory.counts(), before);
    gateway.revoke(key).unwrap();
    let next = verify(nonce + 1, revision, transfer, CHUNK_BYTES as u32, &text);
    assert_eq!(
        reply(next, handle(&mut gateway, route, next, Loan::None)).outcome,
        Outcome::Denied
    );
    assert_eq!(memory.counts(), before);
    assert_eq!(
        gateway.prepared.as_ref().unwrap().verifier.progress(),
        current
    );
    gateway.retire_quiescent(key, DEADLINE).unwrap();
    assert!(gateway.prepared.is_none());
    assert!(gateway.transfer.is_none());
    assert_eq!(gateway.store.pending_stage().unwrap(), None);
    assert_eq!(gateway.owner_metadata(object).unwrap().revision, revision);
}

#[test]
fn empty_verify_and_successful_abort_keep_proof_lifetime_exact() {
    let memory = Memory::new();
    let mut ss = Box::new(StoreScratch::empty());
    let mut gs = Box::new(Scratch::empty());
    let (store, object, revision) = dataset(memory.clone(), &mut ss);
    let mut gateway = Gateway::new(store, &mut gs);
    let route = binding(object, 7, Rights::ReadWrite);
    gateway.bind(route).unwrap();
    let (transfer, nonce) = stage(&mut gateway, route, revision, &[]);
    let verify = verify(nonce, revision, transfer, 0, &[]);
    let before = memory.counts();
    assert_eq!(
        reply(verify, handle(&mut gateway, route, verify, Loan::None)).outcome,
        Outcome::Completed
    );
    assert_eq!(memory.counts(), before);
    assert!(
        gateway
            .prepared
            .as_ref()
            .unwrap()
            .verifier
            .progress()
            .complete
    );
    let abort = request(
        nonce + 1,
        revision,
        wire::Method::Abort {
            transfer_id: transfer,
        },
    );
    assert_eq!(
        reply(abort, handle(&mut gateway, route, abort, Loan::None)).outcome,
        Outcome::Completed
    );
    assert!(gateway.prepared.is_none());
    assert_eq!(gateway.owner_metadata(object).unwrap().revision, revision);
}

#[derive(Clone)]
struct ReadFault {
    memory: Memory,
    fail_after: Rc<Cell<Option<usize>>>,
    deadlines: Rc<RefCell<Vec<u64>>>,
}
impl SectorIo for ReadFault {
    type Error = Fault;
    fn sectors(&self) -> u64 {
        self.memory.sectors()
    }
    fn read(&mut self, sector: u64, out: &mut Sector, deadline: u64) -> Result<(), Fault> {
        self.deadlines.borrow_mut().push(deadline);
        if let Some(left) = self.fail_after.get() {
            self.fail_after.set(left.checked_sub(1));
            if left == 1 {
                return Err(Fault::Injected);
            }
        }
        self.memory.read(sector, out, deadline)
    }
    fn write(&mut self, sector: u64, bytes: &Sector, deadline: u64) -> Result<(), Fault> {
        self.memory.write(sector, bytes, deadline)
    }
    fn flush(&mut self, deadline: u64) -> Result<(), Fault> {
        self.memory.flush(deadline)
    }
}

#[test]
fn verification_read_uncertainty_retains_original_request_cut_stage_and_verifier() {
    let memory = Memory::new();
    let fail = Rc::new(Cell::new(None));
    let deadlines = Rc::new(RefCell::new(Vec::new()));
    let mut ss = Box::new(StoreScratch::empty());
    let mut gs = Box::new(Scratch::empty());
    let (store, object, revision) = dataset(memory.clone(), &mut ss);
    let (stage_id, text) = {
        let mut store = store;
        let text = vec![b'z'; CHUNK_BYTES * 2];
        let begin = store
            .begin_write(
                store.next_operation().unwrap(),
                object,
                revision,
                text.len() as u64,
                hash(&text),
                DEADLINE,
            )
            .unwrap();
        for (index, part) in text.chunks(CHUNK_BYTES).enumerate() {
            store
                .write_chunk(
                    store.next_operation().unwrap(),
                    begin.stage,
                    (index * CHUNK_BYTES) as u64,
                    part,
                    DEADLINE,
                )
                .unwrap();
        }
        (begin.stage, text)
    };
    let mut scratch = Box::new(StoreScratch::empty());
    let device = ReadFault {
        memory: memory.clone(),
        fail_after: fail.clone(),
        deadlines: deadlines.clone(),
    };
    let store = Dataset::open(device, &mut scratch, DEADLINE).unwrap_or_else(|_| panic!("open"));
    let stage = store.pending_stage().unwrap().unwrap();
    assert_eq!(stage.id, stage_id);
    let mut gateway = Gateway::new(store, &mut gs);
    let route = binding(object, 7, Rights::ReadWrite);
    let key = gateway.bind(route).unwrap();
    // This test recreates only the trusted in-RAM transfer association after an
    // independently opened HOST fixture. Native clients cannot bind an orphan.
    gateway.transfer = Some(Transfer {
        owner: key,
        token: 91,
        stage,
    });
    let mut request = verify(1, revision, 91, 0, &text);
    request.deadline = Deadline::new(444).unwrap();
    fail.set(Some(2));
    let read_count = deadlines.borrow().len();
    let before = memory.counts();
    let result = gateway
        .handle(captured(route), &request.encode().unwrap(), 0, Loan::None)
        .unwrap();
    assert!(matches!(result, Dispatch::Retained { .. }));
    assert!(
        deadlines.borrow()[read_count..]
            .iter()
            .all(|&cut| cut == 444)
    );
    assert_eq!((memory.counts().1, memory.counts().2), (before.1, before.2));
    let original = gateway.pending().unwrap();
    assert_eq!(original.request, request);
    assert!(original.uncertain);
    assert!(matches!(
        gateway.store.pending_stage(),
        Err(StoreError::NeedsRecovery)
    ));
    assert_eq!(gateway.transfer.unwrap().stage, stage);
    assert!(gateway.prepared.is_some());
    let before = memory.counts();
    let progress = gateway.prepared.as_ref().unwrap().verifier.progress();
    let mut renewed = request;
    renewed.deadline = Deadline::new(900).unwrap();
    assert!(matches!(
        gateway
            .handle(captured(route), &renewed.encode().unwrap(), 0, Loan::None)
            .unwrap(),
        Dispatch::Retained { .. }
    ));
    assert_eq!(gateway.pending().unwrap(), original);
    assert_eq!(
        gateway.prepared.as_ref().unwrap().verifier.progress(),
        progress
    );
    assert_eq!(memory.counts(), before);
    assert!(gateway.into_storage().is_err());
}

#[test]
fn uncertain_stage_abort_never_discards_the_prepared_proof_or_original_pending_intent() {
    let memory = Memory::new();
    let mut ss = Box::new(StoreScratch::empty());
    let mut gs = Box::new(Scratch::empty());
    let (store, object, revision) = dataset(memory.clone(), &mut ss);
    let mut gateway = Gateway::new(store, &mut gs);
    let route = binding(object, 7, Rights::ReadWrite);
    gateway.bind(route).unwrap();
    let text = vec![b'p'; CHUNK_BYTES * 2];
    let (transfer, nonce) = stage(&mut gateway, route, revision, &text);
    let first = verify(nonce, revision, transfer, 0, &text);
    assert_eq!(
        reply(first, handle(&mut gateway, route, first, Loan::None)).outcome,
        Outcome::Completed
    );
    let progress = gateway.prepared.as_ref().unwrap().verifier.progress();
    let stage = gateway.transfer.unwrap().stage;
    let abort = request(
        nonce + 1,
        revision,
        wire::Method::Abort {
            transfer_id: transfer,
        },
    );
    memory.fail_next_flush_after_persist();
    assert!(matches!(
        handle(&mut gateway, route, abort, Loan::None),
        Dispatch::Retained { .. }
    ));
    let pending = gateway.pending().unwrap();
    assert_eq!(pending.request, abort);
    assert!(pending.uncertain);
    assert_eq!(
        gateway.prepared.as_ref().unwrap().verifier.progress(),
        progress
    );
    assert_eq!(gateway.transfer.unwrap().stage, stage);
    let before = memory.counts();
    let later = verify(nonce + 2, revision, transfer, CHUNK_BYTES as u32, &text);
    assert_eq!(
        reply(later, handle(&mut gateway, route, later, Loan::None)).outcome,
        Outcome::Busy
    );
    assert_eq!(gateway.pending().unwrap(), pending);
    assert_eq!(memory.counts(), before);
}
