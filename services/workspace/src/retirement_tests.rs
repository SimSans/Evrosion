use super::*;

fn begin_empty(gateway: &mut Gateway<'_, '_, Memory>, route: Binding, revision: u64) -> u64 {
    let begin = request(
        1,
        revision,
        wire::Method::BeginWrite {
            length: 0,
            digest: hash(&[]),
        },
    );
    let response = reply(begin, handle(gateway, route, begin, Loan::None));
    assert_eq!(response.outcome, Outcome::Completed);
    response.transfer_id
}

#[test]
fn quiescent_retirement_requires_revoke_flushes_and_preserves_exact_committed_identity() {
    let memory = Memory::new();
    let mut ss = Box::new(StoreScratch::empty());
    let mut gs = Box::new(Scratch::empty());
    let (store, object, revision) = dataset(memory.clone(), &mut ss);
    let mut gateway = Gateway::new(store, &mut gs);
    let route = binding(object, 7, Rights::ReadWrite);
    let old = gateway.bind(route).unwrap();
    let before = memory.counts();
    assert_eq!(
        gateway.retire_quiescent(old, DEADLINE),
        Err(RetireError::Active)
    );
    assert_eq!(memory.counts(), before);
    gateway.revoke(old).unwrap();
    gateway.retire_quiescent(old, DEADLINE).unwrap();
    assert_eq!(memory.counts(), (before.0, before.1, before.2 + 1));
    assert_eq!(gateway.owner_metadata(object).unwrap().revision, revision);
    assert_eq!(gateway.owner_name(object).unwrap(), "Document.txt");
    assert_eq!(
        gateway.retire_quiescent(old, DEADLINE),
        Err(RetireError::Stale)
    );
    let mut out = [0xa5];
    let read = request(
        9,
        revision,
        wire::Method::Read {
            offset: 0,
            length: 1,
        },
    );
    assert_eq!(
        reply(
            read,
            handle(&mut gateway, route, read, Loan::Read(&mut out))
        )
        .outcome,
        Outcome::Denied
    );
    assert_eq!(out, [0xa5]);
    let fresh = Binding {
        lease_epoch: 2,
        ..route
    };
    assert_ne!(gateway.bind(fresh).unwrap(), old);
    drop(gateway);
    let mut cold_scratch = Box::new(StoreScratch::empty());
    let cold = Dataset::open(
        Memory::image(memory.snapshot()),
        &mut cold_scratch,
        DEADLINE,
    )
    .unwrap_or_else(|_| panic!("cold"));
    assert_eq!(cold.metadata(object).unwrap().revision, revision);
    assert_eq!(cold.name(object).unwrap(), "Document.txt");
}

#[test]
fn abandoned_known_stage_is_aborted_durably_without_publishing_its_bytes_or_revision() {
    let memory = Memory::new();
    let mut ss = Box::new(StoreScratch::empty());
    let mut gs = Box::new(Scratch::empty());
    let (store, object, revision) = dataset(memory.clone(), &mut ss);
    let mut gateway = Gateway::new(store, &mut gs);
    let route = binding(object, 7, Rights::ReadWrite);
    let key = gateway.bind(route).unwrap();
    let bytes = b"unpublished document";
    let begin = request(
        1,
        revision,
        wire::Method::BeginWrite {
            length: bytes.len() as u32,
            digest: hash(bytes),
        },
    );
    let transfer = reply(begin, handle(&mut gateway, route, begin, Loan::None)).transfer_id;
    let chunk = request(
        2,
        revision,
        wire::Method::WriteChunk {
            transfer_id: transfer,
            offset: 0,
            length: bytes.len() as u32,
            digest: hash(bytes),
        },
    );
    assert_eq!(
        reply(
            chunk,
            handle(&mut gateway, route, chunk, Loan::Write(bytes))
        )
        .outcome,
        Outcome::Completed
    );
    gateway.revoke(key).unwrap();
    gateway.retire_quiescent(key, DEADLINE).unwrap();
    let receipt = gateway.backend_receipt().unwrap().unwrap();
    assert_eq!(receipt.kind, ReceiptKind::Aborted);
    assert_eq!(receipt.object, object);
    assert_eq!(gateway.store.pending_stage().unwrap(), None);
    assert!(gateway.transfer.is_none());
    let metadata = gateway.owner_metadata(object).unwrap();
    assert_eq!(
        (metadata.revision, metadata.length, metadata.sha256),
        (revision, 0, hash(&[]))
    );
    drop(gateway);
    let mut cold_scratch = Box::new(StoreScratch::empty());
    let cold = Dataset::open(
        Memory::image(memory.snapshot()),
        &mut cold_scratch,
        DEADLINE,
    )
    .unwrap_or_else(|_| panic!("cold"));
    assert_eq!(cold.pending_stage().unwrap(), None);
    assert_eq!(cold.metadata(object).unwrap(), metadata);
}

#[test]
fn retiring_another_route_never_discards_a_foreign_stage() {
    let memory = Memory::new();
    let mut ss = Box::new(StoreScratch::empty());
    let mut gs = Box::new(Scratch::empty());
    let (store, object, revision) = dataset(memory.clone(), &mut ss);
    let mut gateway = Gateway::new(store, &mut gs);
    let first = binding(object, 7, Rights::ReadWrite);
    let second = binding(object, 8, Rights::ReadWrite);
    let first_key = gateway.bind(first).unwrap();
    let second_key = gateway.bind(second).unwrap();
    begin_empty(&mut gateway, first, revision);
    let stage = gateway.store.pending_stage().unwrap();
    gateway.revoke(second_key).unwrap();
    let before = memory.counts();
    assert_eq!(
        gateway.retire_quiescent(second_key, DEADLINE),
        Err(RetireError::Busy)
    );
    assert_eq!(memory.counts(), before);
    assert_eq!(gateway.store.pending_stage().unwrap(), stage);
    gateway.revoke(first_key).unwrap();
    gateway.retire_quiescent(first_key, DEADLINE).unwrap();
    gateway.retire_quiescent(second_key, DEADLINE).unwrap();
}

#[test]
fn accepted_or_uncertain_verifier_cannot_be_released_by_retirement_or_a_new_binding() {
    let memory = Memory::new();
    let mut ss = Box::new(StoreScratch::empty());
    let mut gs = Box::new(Scratch::empty());
    let (store, object, revision) = dataset(memory.clone(), &mut ss);
    let mut gateway = Gateway::new(store, &mut gs);
    let route = binding(object, 7, Rights::ReadWrite);
    let key = gateway.bind(route).unwrap();
    let transfer = begin_empty(&mut gateway, route, revision);
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
    gateway.revoke(key).unwrap();
    let before = memory.counts();
    let pending = gateway.pending();
    assert_eq!(
        gateway.retire_quiescent(key, DEADLINE),
        Err(RetireError::Busy)
    );
    assert_eq!(
        gateway.bind(Binding {
            lease_epoch: 2,
            ..route
        }),
        Err(BindError::StorageFenced)
    );
    assert_eq!(gateway.pending(), pending);
    assert_eq!(memory.counts(), before);
    assert!(matches!(
        gateway.poll_commit(DEADLINE).unwrap(),
        Dispatch::Retained { .. }
    ));
    let uncertain = gateway.pending();
    assert_eq!(
        gateway.retire_quiescent(key, DEADLINE),
        Err(RetireError::Busy)
    );
    assert_eq!(gateway.pending(), uncertain);
    assert!(gateway.commit.is_some());
    assert_eq!(memory.counts(), before);
}

#[test]
fn failed_actual_flush_retains_old_route_and_fences_all_future_reuse() {
    let memory = Memory::new();
    let mut ss = Box::new(StoreScratch::empty());
    let mut gs = Box::new(Scratch::empty());
    let (store, object, _) = dataset(memory.clone(), &mut ss);
    let mut gateway = Gateway::new(store, &mut gs);
    let route = binding(object, 7, Rights::ReadWrite);
    let key = gateway.bind(route).unwrap();
    gateway.revoke(key).unwrap();
    memory.fail_next_flush_after_persist();
    assert_eq!(
        gateway.retire_quiescent(key, DEADLINE),
        Err(RetireError::Uncertain)
    );
    let before = memory.counts();
    assert!(gateway.routes[usize::from(key.slot)].is_some());
    assert_eq!(
        gateway.retire_quiescent(key, DEADLINE),
        Err(RetireError::StorageFenced)
    );
    assert_eq!(
        gateway.bind(Binding {
            lease_epoch: 2,
            ..route
        }),
        Err(BindError::StorageFenced)
    );
    assert_eq!(memory.counts(), before);
    assert!(gateway.into_storage().is_err());
}

#[test]
fn cold_orphan_stage_is_preserved_and_never_guessed_to_belong_to_a_new_route() {
    let memory = Memory::new();
    let mut ss = Box::new(StoreScratch::empty());
    let mut gs = Box::new(Scratch::empty());
    let (store, object, revision) = dataset(memory.clone(), &mut ss);
    let mut gateway = Gateway::new(store, &mut gs);
    let route = binding(object, 7, Rights::ReadWrite);
    gateway.bind(route).unwrap();
    begin_empty(&mut gateway, route, revision);
    let stage = gateway.store.pending_stage().unwrap();
    drop(gateway);
    let mut cold_scratch = Box::new(StoreScratch::empty());
    let cold_memory = Memory::image(memory.snapshot());
    let cold = Dataset::open(cold_memory.clone(), &mut cold_scratch, DEADLINE)
        .unwrap_or_else(|_| panic!("cold"));
    let mut gateway = Gateway::new(cold, &mut gs);
    let key = gateway.bind(route).unwrap();
    gateway.revoke(key).unwrap();
    let before = cold_memory.counts();
    assert_eq!(
        gateway.retire_quiescent(key, DEADLINE),
        Err(RetireError::StorageFenced)
    );
    assert_eq!(gateway.store.pending_stage().unwrap(), stage);
    assert_eq!(cold_memory.counts(), before);
}
