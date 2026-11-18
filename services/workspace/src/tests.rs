use super::*;
use ev_userspace_contract::workspace::Deadline;
use ev_workspace_store::{DatasetId, Name, REQUIRED_SECTORS, Scratch as StoreScratch, Sector};
use std::{boxed::Box, cell::RefCell, collections::BTreeMap, rc::Rc, vec};
#[path = "namespace_tests.rs"]
mod namespace_tests;
#[path = "retirement_tests.rs"]
mod retirement_tests;

const DEADLINE: u64 = 100_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Bounds,
    Injected,
}
struct DeviceState {
    stable: BTreeMap<u64, Sector>,
    cache: BTreeMap<u64, Sector>,
    reads: usize,
    writes: usize,
    flushes: usize,
    fail_flush: bool,
}
#[derive(Clone)]
struct Memory(Rc<RefCell<DeviceState>>);
impl Memory {
    fn new() -> Self {
        Self::image(BTreeMap::new())
    }
    fn image(stable: BTreeMap<u64, Sector>) -> Self {
        Self(Rc::new(RefCell::new(DeviceState {
            stable,
            cache: BTreeMap::new(),
            reads: 0,
            writes: 0,
            flushes: 0,
            fail_flush: false,
        })))
    }
    fn snapshot(&self) -> BTreeMap<u64, Sector> {
        self.0.borrow().stable.clone()
    }
    fn counts(&self) -> (usize, usize, usize) {
        let s = self.0.borrow();
        (s.reads, s.writes, s.flushes)
    }
    fn fail_next_flush_after_persist(&self) {
        self.0.borrow_mut().fail_flush = true;
    }
}
impl SectorIo for Memory {
    type Error = Fault;
    fn sectors(&self) -> u64 {
        REQUIRED_SECTORS
    }
    fn read(&mut self, sector: u64, out: &mut Sector, _: u64) -> Result<(), Fault> {
        if sector >= self.sectors() {
            return Err(Fault::Bounds);
        }
        let mut s = self.0.borrow_mut();
        s.reads += 1;
        *out = *s
            .cache
            .get(&sector)
            .or_else(|| s.stable.get(&sector))
            .unwrap_or(&[0; 512]);
        Ok(())
    }
    fn write(&mut self, sector: u64, bytes: &Sector, _: u64) -> Result<(), Fault> {
        if sector >= self.sectors() {
            return Err(Fault::Bounds);
        }
        let mut s = self.0.borrow_mut();
        s.writes += 1;
        s.cache.insert(sector, *bytes);
        Ok(())
    }
    fn flush(&mut self, _: u64) -> Result<(), Fault> {
        let mut s = self.0.borrow_mut();
        s.flushes += 1;
        let cache = core::mem::take(&mut s.cache);
        s.stable.extend(cache);
        if core::mem::take(&mut s.fail_flush) {
            Err(Fault::Injected)
        } else {
            Ok(())
        }
    }
}
fn dataset<'a>(
    memory: Memory,
    scratch: &'a mut StoreScratch,
) -> (Dataset<'a, Memory>, ObjectId, u64) {
    let mut dataset =
        Dataset::format_new(memory, scratch, DatasetId::new([8; 16]).unwrap(), DEADLINE)
            .unwrap_or_else(|e| panic!("{:?}", e.error));
    let receipt = dataset
        .create(
            dataset.next_operation().unwrap(),
            dataset.namespace_revision(),
            ObjectId::ROOT,
            Name::new("Document.txt").unwrap(),
            Kind::File,
            DEADLINE,
        )
        .unwrap();
    let revision = dataset.metadata(receipt.object).unwrap().revision;
    (dataset, receipt.object, revision)
}
fn binding(object: ObjectId, process: u64, rights: Rights) -> Binding {
    Binding {
        endpoint: EndpointId::new(500 + process, 1).unwrap(),
        caller: Caller::new(process, 1).unwrap(),
        lease_epoch: 1,
        object,
        rights,
    }
}
#[test]
fn unsupported_contract_never_binds_or_reads_and_selection2_never_widens_readonly() {
    use ev_workspace_client::selection::{Access, Selection, SelectionV2};
    let memory = Memory::new();
    let mut store = Box::new(StoreScratch::empty());
    let (dataset, object, revision) = dataset(memory.clone(), &mut store);
    let mut scratch = Box::new(Scratch::empty());
    let mut gateway = Gateway::new(dataset, &mut scratch);
    let route = binding(object, 51, Rights::ReadOnly);
    let before = memory.counts();
    for requirement in [
        control::FileRequirement {
            minimum_minor: 2,
            features: 0,
        },
        control::FileRequirement {
            minimum_minor: 1,
            features: 2,
        },
    ] {
        assert_eq!(
            gateway.bind_contract(route, requirement),
            Err(BindError::Unsupported)
        );
        assert_eq!(memory.counts(), before);
    }
    let key = gateway
        .bind_contract(
            route,
            control::FileRequirement {
                minimum_minor: 1,
                features: wire::FEATURE_STAGED_VERIFY,
            },
        )
        .unwrap();
    assert_eq!(key.generation, 1);
    let frame = gateway.bound_selection_v2(key, 17, 19).unwrap();
    let selected = SelectionV2::decode(&frame).unwrap();
    assert_eq!(selected.file, wire::SUPPORT);
    assert_eq!(selected.selection.access, Access::ReadOnly);
    assert!(Selection::decode(&frame).is_err());
    let before = memory.counts();
    let denied = handle(
        &mut gateway,
        route,
        request(
            1,
            revision,
            wire::Method::BeginWrite {
                length: 0,
                digest: Sha256::digest([]).into(),
            },
        ),
        Loan::None,
    );
    assert!(
        matches!(denied,Dispatch::Complete{frame,..} if wire::Response::decode(&frame).unwrap().outcome==Outcome::Denied)
    );
    assert_eq!(memory.counts(), before);
}
fn captured(binding: Binding) -> Captured {
    Captured {
        endpoint: binding.endpoint,
        caller: binding.caller,
        lease_epoch: binding.lease_epoch,
        now: 100,
    }
}
fn request(nonce: u64, revision: u64, method: wire::Method) -> wire::Request {
    wire::Request {
        request_id: nonce
            + if method == wire::Method::QueryOperation {
                20_000
            } else {
                1000
            },
        operation_id: if matches!(method, wire::Method::Read { .. }) {
            0
        } else {
            nonce
        },
        deadline: Deadline::new(DEADLINE).unwrap(),
        expected_revision: if method == wire::Method::QueryOperation {
            0
        } else {
            revision
        },
        method,
    }
}
fn handle(
    gateway: &mut Gateway<'_, '_, Memory>,
    binding: Binding,
    request: wire::Request,
    loan: Loan<'_>,
) -> Dispatch {
    gateway
        .handle(captured(binding), &request.encode().unwrap(), 0, loan)
        .unwrap()
}
fn reply(request: wire::Request, dispatch: Dispatch) -> wire::Response {
    wire::client_decode(request, dispatch.frame(), 0).unwrap()
}

#[test]
fn selection_describes_only_a_live_bound_route_and_exact_durable_metadata() {
    use ev_workspace_client::selection::{Access, Selection};
    let memory = Memory::new();
    let mut store_scratch = Box::new(StoreScratch::empty());
    let mut service_scratch = Box::new(Scratch::empty());
    let (store, object, revision) = dataset(memory.clone(), &mut store_scratch);
    let expected = store.metadata(object).unwrap();
    let mut gateway = Gateway::new(store, &mut service_scratch);
    let mut route = binding(object, 7, Rights::ReadOnly);
    route.caller = Caller::new(7, 0).unwrap();
    let key = gateway.bind(route).unwrap();
    let before = memory.counts();
    let selected = Selection::decode(&gateway.bound_selection(key, 55, 81).unwrap()).unwrap();
    assert!(selected.matches_receiver(55, 7, 81, 0));
    assert_eq!(selected.dataset, [8; 16]);
    assert_eq!(selected.object.slot, object.slot);
    assert_eq!(selected.object.generation, object.generation);
    assert_eq!(selected.revision, revision);
    assert_eq!(selected.length, expected.length as u32);
    assert_eq!(selected.digest, expected.sha256);
    assert_eq!(selected.access, Access::ReadOnly);
    assert_eq!(selected.name.as_bytes(), b"Document.txt");
    assert_eq!(memory.counts(), before);
    assert_eq!(gateway.bound_selection(key, 55, 0), Err(BindError::Invalid));
    gateway.revoke(key).unwrap();
    assert_eq!(gateway.bound_selection(key, 55, 81), Err(BindError::Stale));
    assert_eq!(memory.counts(), before);
}

#[test]
fn full_mebibyte_real_sector_save_streamed_editor_readback_and_cold_bytes() {
    let memory = Memory::new();
    let mut store_scratch = Box::new(StoreScratch::empty());
    let mut service_scratch = Box::new(Scratch::empty());
    let (store, object, revision) = dataset(memory.clone(), &mut store_scratch);
    let mut gateway = Gateway::new(store, &mut service_scratch);
    let route = binding(object, 7, Rights::ReadWrite);
    gateway.bind(route).unwrap();
    let text = vec![b'x'; wire::MAX_FILE_BYTES as usize];
    let mut document = vec![0; text.len()];
    let mut editor = ev_workspace_editor::Editor::open(&mut document, 0, revision, true).unwrap();
    editor.replace(&text).unwrap();
    let proposal = editor.begin_save(1).unwrap();
    let begin = request(
        1,
        revision,
        wire::Method::BeginWrite {
            length: proposal.length as u32,
            digest: proposal.digest,
        },
    );
    let response = reply(begin, handle(&mut gateway, route, begin, Loan::None));
    assert_eq!(response.outcome, Outcome::Completed);
    editor
        .begin_confirmed(
            response.transfer_id,
            u64::from(response.file_length),
            response.digest,
        )
        .unwrap();
    let transfer = response.transfer_id;
    let mut nonce = 2;
    let mut chunk = [0; CHUNK_BYTES];
    while editor.pending().unwrap().staged < proposal.length {
        let part = editor.next_chunk(&mut chunk).unwrap();
        let write = request(
            nonce,
            revision,
            wire::Method::WriteChunk {
                transfer_id: transfer,
                offset: part.offset as u32,
                length: part.length,
                digest: part.digest,
            },
        );
        let response = reply(
            write,
            handle(
                &mut gateway,
                route,
                write,
                Loan::Write(&chunk[..part.length as usize]),
            ),
        );
        assert_eq!(response.outcome, Outcome::Completed);
        editor.chunk_confirmed(transfer, part).unwrap();
        nonce += 1;
    }
    editor.commit_request().unwrap();
    let commit = request(
        nonce,
        revision,
        wire::Method::Commit {
            transfer_id: transfer,
            length: proposal.length as u32,
            digest: proposal.digest,
        },
    );
    assert!(matches!(
        handle(&mut gateway, route, commit, Loan::None),
        Dispatch::Accepted { .. }
    ));
    let before = memory.counts();
    let mut polls = 0;
    let committed = loop {
        polls += 1;
        let result = gateway.poll_commit(100).unwrap();
        if let Dispatch::Complete { .. } = result {
            break reply(commit, result);
        }
        assert!(matches!(result, Dispatch::Accepted { .. }));
        assert_eq!(memory.counts().1, before.1);
        assert_eq!(memory.counts().2, before.2);
        assert!(polls <= 257);
    };
    assert_eq!(polls, 257);
    assert_eq!(committed.revision, revision + 1);
    assert_eq!(committed.file_length, wire::MAX_FILE_BYTES);
    assert_eq!(committed.digest, hash(&text));
    editor
        .commit_confirmed(ev_workspace_editor::Receipt {
            transfer,
            revision: committed.revision,
            length: u64::from(committed.file_length),
            digest: committed.digest,
        })
        .unwrap();
    assert_eq!(editor.status(), ev_workspace_editor::Status::Readback);
    for (index, expected) in text.chunks(CHUNK_BYTES).enumerate() {
        let read = request(
            10000 + index as u64,
            committed.revision,
            wire::Method::Read {
                offset: (index * CHUNK_BYTES) as u32,
                length: expected.len() as u32,
            },
        );
        let response = reply(
            read,
            handle(&mut gateway, route, read, Loan::Read(&mut chunk)),
        );
        assert_eq!(&chunk[..response.length as usize], expected);
        assert_eq!(response.digest, hash(expected));
        editor
            .readback(
                committed.revision,
                u64::from(response.offset),
                &chunk[..response.length as usize],
            )
            .unwrap();
    }
    editor.finish_readback().unwrap();
    assert_eq!(editor.status(), ev_workspace_editor::Status::Saved);
    let before_replay = memory.counts();
    assert_eq!(
        reply(commit, handle(&mut gateway, route, commit, Loan::None)),
        committed
    );
    assert_eq!(memory.counts(), before_replay);
    let store = gateway
        .into_storage()
        .unwrap_or_else(|_| panic!("unexpected pending owner"));
    let _retired = store.into_device();
    let frozen = memory.snapshot();
    let cold_device = Memory::image(frozen.clone());
    let mut cold_scratch = Box::new(StoreScratch::empty());
    let mut cold = Dataset::open(cold_device.clone(), &mut cold_scratch, DEADLINE)
        .unwrap_or_else(|e| panic!("{:?}", e.error));
    assert_eq!(cold.metadata(object).unwrap().revision, revision + 1);
    assert_eq!(cold.metadata(object).unwrap().sha256, hash(&text));
    for (index, expected) in text.chunks(CHUNK_BYTES).enumerate() {
        assert_eq!(
            cold.read(
                object,
                revision + 1,
                (index * CHUNK_BYTES) as u64,
                &mut chunk[..expected.len()],
                DEADLINE
            )
            .unwrap(),
            expected.len()
        );
        assert_eq!(&chunk[..expected.len()], expected);
    }
    assert_eq!(cold_device.snapshot(), frozen);
    assert_eq!(cold_device.counts().1, 0);
}

#[test]
fn two_authenticated_editors_can_both_use_nonce_one_and_cannot_use_each_others_transfer() {
    let memory = Memory::new();
    let mut ss = Box::new(StoreScratch::empty());
    let mut gs = Box::new(Scratch::empty());
    let (store, object, revision) = dataset(memory.clone(), &mut ss);
    let mut gateway = Gateway::new(store, &mut gs);
    let first = binding(object, 7, Rights::ReadWrite);
    let second = binding(object, 8, Rights::ReadWrite);
    gateway.bind(first).unwrap();
    gateway.bind(second).unwrap();
    let begin = request(
        1,
        revision,
        wire::Method::BeginWrite {
            length: 0,
            digest: hash(&[]),
        },
    );
    let one = reply(begin, handle(&mut gateway, first, begin, Loan::None));
    let global_one = gateway.backend_receipt().unwrap().unwrap();
    let before = memory.counts();
    assert_eq!(
        reply(begin, handle(&mut gateway, first, begin, Loan::None)),
        one
    );
    assert_eq!(memory.counts(), before);
    let altered = request(
        1,
        revision,
        wire::Method::BeginWrite {
            length: 1,
            digest: hash(b"x"),
        },
    );
    assert_eq!(
        reply(altered, handle(&mut gateway, first, altered, Loan::None)).outcome,
        Outcome::Conflict
    );
    assert_eq!(memory.counts(), before);
    let stolen = request(
        2,
        revision,
        wire::Method::Abort {
            transfer_id: one.transfer_id,
        },
    );
    assert_eq!(
        reply(stolen, handle(&mut gateway, second, stolen, Loan::None)).outcome,
        Outcome::Denied
    );
    assert_eq!(memory.counts(), before);
    let abort = request(
        2,
        revision,
        wire::Method::Abort {
            transfer_id: one.transfer_id,
        },
    );
    assert_eq!(
        reply(abort, handle(&mut gateway, first, abort, Loan::None)).outcome,
        Outcome::Completed
    );
    let two = reply(begin, handle(&mut gateway, second, begin, Loan::None));
    let global_two = gateway.backend_receipt().unwrap().unwrap();
    assert_eq!(two.outcome, Outcome::Completed);
    assert_ne!(one.transfer_id, two.transfer_id);
    assert!(global_two.operation.get() > global_one.operation.get());
    assert_eq!(global_one.operation.client_request().unwrap().nonce(), 1);
    assert_eq!(global_two.operation.client_request().unwrap().nonce(), 1);
    assert_ne!(
        global_one.operation.client_request().unwrap().caller(),
        global_two.operation.client_request().unwrap().caller()
    );
    let abort_two = request(
        2,
        revision,
        wire::Method::Abort {
            transfer_id: two.transfer_id,
        },
    );
    assert_eq!(
        reply(
            abort_two,
            handle(&mut gateway, second, abort_two, Loan::None)
        )
        .outcome,
        Outcome::Completed
    );
    let same_process_new_endpoint = Binding {
        endpoint: EndpointId::new(900, 1).unwrap(),
        ..first
    };
    gateway.bind(same_process_new_endpoint).unwrap();
    assert_eq!(
        reply(
            begin,
            handle(&mut gateway, same_process_new_endpoint, begin, Loan::None)
        )
        .outcome,
        Outcome::Completed
    );
    let global_three = gateway.backend_receipt().unwrap().unwrap();
    assert_ne!(
        global_three.operation.client_request().unwrap().caller(),
        global_one.operation.client_request().unwrap().caller()
    );
}

#[test]
fn readonly_denial_wrong_origin_stale_binding_and_revocation_do_not_touch_storage() {
    let memory = Memory::new();
    let mut ss = Box::new(StoreScratch::empty());
    let mut gs = Box::new(Scratch::empty());
    let (store, object, revision) = dataset(memory.clone(), &mut ss);
    let mut gateway = Gateway::new(store, &mut gs);
    let read = binding(object, 7, Rights::ReadOnly);
    let key = gateway.bind(read).unwrap();
    let before = memory.counts();
    let begin = request(
        1,
        revision,
        wire::Method::BeginWrite {
            length: 1,
            digest: hash(b"x"),
        },
    );
    assert_eq!(
        reply(begin, handle(&mut gateway, read, begin, Loan::None)).outcome,
        Outcome::Denied
    );
    let wrong = Captured {
        caller: Caller::new(8, 1).unwrap(),
        ..captured(read)
    };
    assert_eq!(
        reply(
            begin,
            gateway
                .handle(wrong, &begin.encode().unwrap(), 0, Loan::None)
                .unwrap()
        )
        .outcome,
        Outcome::Denied
    );
    let stale_object = Binding {
        object: ObjectId {
            generation: object.generation + 1,
            ..object
        },
        ..binding(object, 9, Rights::ReadOnly)
    };
    assert_eq!(gateway.bind(stale_object), Err(BindError::Stale));
    gateway.revoke(key).unwrap();
    assert_eq!(
        reply(begin, handle(&mut gateway, read, begin, Loan::None)).outcome,
        Outcome::Denied
    );
    assert_eq!(gateway.bind(read), Err(BindError::Stale));
    let replacement = Binding {
        lease_epoch: 2,
        ..read
    };
    let next = gateway.bind(replacement).unwrap();
    assert_ne!(key, next);
    assert_eq!(gateway.revoke(key), Err(BindError::Stale));
    assert_eq!(
        reply(begin, handle(&mut gateway, read, begin, Loan::None)).outcome,
        Outcome::Denied
    );
    assert_eq!(memory.counts(), before);
}

#[test]
fn accepted_io_failure_retains_exact_snapshot_and_never_returns_a_normal_completion() {
    let memory = Memory::new();
    let mut ss = Box::new(StoreScratch::empty());
    let mut gs = Box::new(Scratch::empty());
    let (store, object, revision) = dataset(memory.clone(), &mut ss);
    let mut gateway = Gateway::new(store, &mut gs);
    let route = binding(object, 7, Rights::ReadWrite);
    gateway.bind(route).unwrap();
    let bytes = [b'a'; CHUNK_BYTES];
    let begin = request(
        1,
        revision,
        wire::Method::BeginWrite {
            length: CHUNK_BYTES as u32,
            digest: hash(&bytes),
        },
    );
    let transfer = reply(begin, handle(&mut gateway, route, begin, Loan::None)).transfer_id;
    let write = request(
        2,
        revision,
        wire::Method::WriteChunk {
            transfer_id: transfer,
            offset: 0,
            length: CHUNK_BYTES as u32,
            digest: hash(&bytes),
        },
    );
    memory.fail_next_flush_after_persist();
    let result = handle(&mut gateway, route, write, Loan::Write(&bytes));
    assert!(matches!(result, Dispatch::Retained { .. }));
    assert_eq!(reply(write, result).outcome, Outcome::Uncertain);
    assert_eq!(gateway.pending_snapshot().unwrap(), bytes);
    assert_eq!(gateway.pending().unwrap().request, write);
    let counts = memory.counts();
    assert!(matches!(
        handle(
            &mut gateway,
            route,
            write,
            Loan::Write(&[b'b'; CHUNK_BYTES])
        ),
        Dispatch::Retained { .. }
    ));
    assert_eq!(gateway.pending_snapshot().unwrap(), bytes);
    assert_eq!(memory.counts(), counts);
    let expired = Captured {
        now: DEADLINE,
        ..captured(route)
    };
    assert!(matches!(
        gateway
            .handle(expired, &write.encode().unwrap(), 0, Loan::Write(&bytes))
            .unwrap(),
        Dispatch::Retained { .. }
    ));
    assert_eq!(gateway.pending().unwrap().request, write);
    assert_eq!(memory.counts(), counts);
    let query = request(2, 0, wire::Method::QueryOperation);
    assert!(matches!(
        handle(&mut gateway, route, query, Loan::None),
        Dispatch::Retained { .. }
    ));
    assert_eq!(memory.counts(), counts);
    assert!(gateway.into_storage().is_err());
}

#[test]
fn commit_deadline_never_renews_and_query_does_not_release_accepted_work() {
    let memory = Memory::new();
    let mut ss = Box::new(StoreScratch::empty());
    let mut gs = Box::new(Scratch::empty());
    let (store, object, revision) = dataset(memory.clone(), &mut ss);
    let mut gateway = Gateway::new(store, &mut gs);
    let route = binding(object, 7, Rights::ReadWrite);
    gateway.bind(route).unwrap();
    let begin = request(
        1,
        revision,
        wire::Method::BeginWrite {
            length: 0,
            digest: hash(&[]),
        },
    );
    let transfer = reply(begin, handle(&mut gateway, route, begin, Loan::None)).transfer_id;
    let commit = request(
        2,
        revision,
        wire::Method::Commit {
            transfer_id: transfer,
            length: 0,
            digest: hash(&[]),
        },
    );
    assert!(matches!(
        handle(&mut gateway, route, commit, Loan::None),
        Dispatch::Accepted { .. }
    ));
    let query = request(2, 0, wire::Method::QueryOperation);
    assert!(matches!(
        handle(&mut gateway, route, query, Loan::None),
        Dispatch::Accepted { .. }
    ));
    let before = memory.counts();
    assert!(matches!(
        gateway.poll_commit(DEADLINE).unwrap(),
        Dispatch::Retained { .. }
    ));
    assert_eq!(gateway.pending().unwrap().request.deadline.tick(), DEADLINE);
    assert_eq!(memory.counts(), before);
    assert!(matches!(
        gateway.poll_commit(100).unwrap(),
        Dispatch::Retained { .. }
    ));
    assert_eq!(memory.counts(), before);
}

#[test]
fn cold_rebind_same_caller_endpoint_root_lease_and_nonce_is_a_fresh_durable_scope() {
    let memory = Memory::new();
    let mut store_scratch = Box::new(StoreScratch::empty());
    let mut scratch = Box::new(Scratch::empty());
    let (store, object, revision) = dataset(memory.clone(), &mut store_scratch);
    let binding = binding(object, 7, Rights::ReadWrite);
    let mut gateway = Gateway::new(store, &mut scratch);
    gateway.bind(binding).unwrap();
    let begin = request(
        1,
        revision,
        wire::Method::BeginWrite {
            length: 0,
            digest: hash(&[]),
        },
    );
    let transfer = reply(begin, handle(&mut gateway, binding, begin, Loan::None)).transfer_id;
    let original_scope = gateway
        .backend_receipt()
        .unwrap()
        .unwrap()
        .operation
        .client_request()
        .unwrap();
    let commit = request(
        2,
        revision,
        wire::Method::Commit {
            transfer_id: transfer,
            length: 0,
            digest: hash(&[]),
        },
    );
    assert!(matches!(
        handle(&mut gateway, binding, commit, Loan::None),
        Dispatch::Accepted { .. }
    ));
    assert!(matches!(
        gateway.poll_commit(100).unwrap(),
        Dispatch::Accepted { .. }
    ));
    assert!(matches!(
        gateway.poll_commit(100).unwrap(),
        Dispatch::Complete { .. }
    ));
    let previous_global = gateway.backend_receipt().unwrap().unwrap().operation.get();
    let store = gateway
        .into_storage()
        .unwrap_or_else(|_| panic!("pending owner"));
    let _retired = store.into_device();
    let cold_memory = Memory::image(memory.snapshot());
    let mut cold_store_scratch = Box::new(StoreScratch::empty());
    let cold_store = Dataset::open(cold_memory, &mut cold_store_scratch, DEADLINE)
        .unwrap_or_else(|e| panic!("{:?}", e.error));
    let mut cold_gateway_scratch = Box::new(Scratch::empty());
    let mut cold = Gateway::new(cold_store, &mut cold_gateway_scratch);
    cold.bind(binding).unwrap(); // Identical diagnostic origin/endpoint/root lease1.
    let fresh = request(
        1,
        revision + 1,
        wire::Method::BeginWrite {
            length: 1,
            digest: hash(b"x"),
        },
    );
    let response = reply(fresh, handle(&mut cold, binding, fresh, Loan::None));
    assert_eq!(response.outcome, Outcome::Completed);
    assert_eq!(response.file_length, 1);
    let receipt = cold.backend_receipt().unwrap().unwrap();
    assert!(receipt.operation.get() > previous_global);
    let new_scope = receipt.operation.client_request().unwrap();
    assert_eq!(new_scope.nonce(), original_scope.nonce());
    assert_eq!(new_scope.caller(), original_scope.caller());
    assert_ne!(new_scope.lease_epoch(), original_scope.lease_epoch());
    assert!(!receipt.replayed);
}

#[test]
fn malformed_frames_capabilities_and_preacceptance_expiry_are_effect_free_and_routes_bounded() {
    let memory = Memory::new();
    let mut ss = Box::new(StoreScratch::empty());
    let mut gs = Box::new(Scratch::empty());
    let (store, object, revision) = dataset(memory.clone(), &mut ss);
    let mut gateway = Gateway::new(store, &mut gs);
    let route = binding(object, 1, Rights::ReadOnly);
    gateway.bind(route).unwrap();
    let read = request(
        1,
        revision,
        wire::Method::Read {
            offset: 0,
            length: 1,
        },
    );
    let before = memory.counts();
    assert_eq!(
        gateway.handle(captured(route), &read.encode().unwrap(), 1, Loan::None),
        Err(Reject::Protocol(CodecError::CapabilityCount))
    );
    let mut bad = read.encode().unwrap();
    bad[105] = 1;
    assert!(matches!(
        gateway.handle(captured(route), &bad, 0, Loan::None),
        Err(Reject::Protocol(_))
    ));
    let expired = Captured {
        now: DEADLINE,
        ..captured(route)
    };
    assert_eq!(
        reply(
            read,
            gateway
                .handle(expired, &read.encode().unwrap(), 0, Loan::None)
                .unwrap()
        )
        .outcome,
        Outcome::Cancelled
    );
    assert_eq!(memory.counts(), before);
    for process in 2..=MAX_ROUTES as u64 {
        gateway
            .bind(binding(object, process, Rights::ReadOnly))
            .unwrap();
    }
    assert_eq!(
        gateway.bind(binding(object, 99, Rights::ReadOnly)),
        Err(BindError::Capacity)
    );
    assert_eq!(memory.counts(), before);
}

#[path = "verification_tests.rs"]
mod verification_tests;

#[path = "quiesce_tests.rs"]
mod quiesce_tests;
