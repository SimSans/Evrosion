use super::*;
use ev_userspace_contract::workspace as ns;

fn ns_binding(directory: ObjectId, process: u64, rights: NamespaceRights) -> NamespaceBinding {
    NamespaceBinding {
        endpoint: EndpointId::new(10_000 + process, 1).unwrap(),
        caller: Caller::new(process, 0).unwrap(),
        lease_epoch: 1,
        directory,
        rights,
    }
}
fn ns_capture(binding: NamespaceBinding) -> Captured {
    Captured {
        endpoint: binding.endpoint,
        caller: binding.caller,
        lease_epoch: binding.lease_epoch,
        now: 100,
    }
}
fn req(nonce: u64, operation: ns::Operation) -> ns::Request {
    ns::Request {
        request_id: nonce + 10_000,
        operation_id: if matches!(
            operation,
            ns::Operation::Inspect { .. } | ns::Operation::List { .. }
        ) {
            0
        } else {
            nonce
        },
        deadline: Deadline::new(DEADLINE).unwrap(),
        operation,
    }
}
fn call(
    gateway: &mut Gateway<'_, '_, Memory>,
    binding: NamespaceBinding,
    request: ns::Request,
) -> ns::Response {
    let result = gateway
        .handle_namespace(ns_capture(binding), &request.encode().unwrap(), 0)
        .unwrap();
    let NamespaceDispatch::Complete { frame } = result else {
        panic!("unexpected retained operation")
    };
    ns::client_decode(request, &frame, 0).unwrap()
}
fn wid(object: ObjectId) -> ns::ObjectId {
    ns::ObjectId {
        slot: object.slot,
        generation: object.generation,
    }
}
fn sid(object: ns::ObjectId) -> ObjectId {
    ObjectId::new(object.slot, object.generation).unwrap()
}
fn create(
    gateway: &mut Gateway<'_, '_, Memory>,
    binding: NamespaceBinding,
    nonce: u64,
    parent: ObjectId,
    name: &str,
    kind: ns::Kind,
) -> ns::Response {
    call(
        gateway,
        binding,
        req(
            nonce,
            ns::Operation::Create {
                directory: wid(parent),
                kind,
                name: ns::Name::new(name.as_bytes()).unwrap(),
                expected_namespace_revision: gateway.namespace_revision(),
            },
        ),
    )
}

#[test]
fn root_chooser_reads_actual_revision_after_files_mutations_instead_of_zero_wildcard() {
    let memory = Memory::new();
    let mut scratch = Box::new(StoreScratch::empty());
    let mut service = Box::new(Scratch::empty());
    let (store, _, _) = dataset(memory.clone(), &mut scratch);
    let mut gateway = Gateway::new(store, &mut service);
    let files = ns_binding(ObjectId::ROOT, 88, NamespaceRights::Manage);
    gateway.bind_namespace(files).unwrap();
    assert_eq!(
        create(
            &mut gateway,
            files,
            1,
            ObjectId::ROOT,
            "folder1",
            ns::Kind::Directory
        )
        .outcome,
        Outcome::Completed
    );
    assert_eq!(
        create(
            &mut gateway,
            files,
            2,
            ObjectId::ROOT,
            "note1",
            ns::Kind::File
        )
        .outcome,
        Outcome::Completed
    );
    let root = ns_binding(ObjectId::ROOT, 77, NamespaceRights::Manage);
    gateway.bind_namespace(root).unwrap();
    let counts = memory.counts();
    let wrong = call(
        &mut gateway,
        root,
        req(
            1,
            ns::Operation::List {
                directory: wid(ObjectId::ROOT),
                cursor: 0,
                expected_namespace_revision: 0,
            },
        ),
    );
    assert_eq!(wrong.outcome, Outcome::Conflict);
    let inspected = call(
        &mut gateway,
        root,
        req(
            2,
            ns::Operation::Inspect {
                object: wid(ObjectId::ROOT),
            },
        ),
    );
    assert_eq!(inspected.outcome, Outcome::Completed);
    assert_ne!(inspected.namespace_revision, 0);
    let listed = call(
        &mut gateway,
        root,
        req(
            3,
            ns::Operation::List {
                directory: wid(ObjectId::ROOT),
                cursor: 0,
                expected_namespace_revision: inspected.namespace_revision,
            },
        ),
    );
    assert_eq!(listed.outcome, Outcome::Completed);
    assert_eq!(listed.namespace_revision, inspected.namespace_revision);
    assert!(listed.entry.is_some());
    assert_eq!(memory.counts(), counts); // Read flow never performs a mutation.
}

#[test]
fn real_wire_crud_stable_ids_reversible_trash_and_cold_dynamic_listing() {
    let memory = Memory::new();
    let mut scratch = Box::new(StoreScratch::empty());
    let mut service = Box::new(Scratch::empty());
    let (store, initial, _) = dataset(memory.clone(), &mut scratch);
    let mut gateway = Gateway::new(store, &mut service);
    let route = ns_binding(ObjectId::ROOT, 77, NamespaceRights::Manage);
    gateway.bind_namespace(route).unwrap();
    let folder = create(
        &mut gateway,
        route,
        1,
        ObjectId::ROOT,
        "Folder é",
        ns::Kind::Directory,
    )
    .entry
    .unwrap()
    .object;
    let file = create(
        &mut gateway,
        route,
        2,
        sid(folder),
        "dynamic.txt",
        ns::Kind::File,
    )
    .entry
    .unwrap()
    .object;
    let expected = gateway.namespace_revision();
    let renamed = call(
        &mut gateway,
        route,
        req(
            3,
            ns::Operation::Rename {
                object: file,
                name: ns::Name::new(b"renamed.txt").unwrap(),
                expected_namespace_revision: expected,
            },
        ),
    );
    assert_eq!(renamed.entry.unwrap().object, file);
    assert_eq!(renamed.entry.unwrap().name.as_bytes(), b"renamed.txt");
    let expected = gateway.namespace_revision();
    let moved = call(
        &mut gateway,
        route,
        req(
            4,
            ns::Operation::Move {
                object: file,
                destination: wid(ObjectId::ROOT),
                expected_namespace_revision: expected,
            },
        ),
    );
    assert_eq!(moved.entry.unwrap().object, file);
    assert_eq!(moved.entry.unwrap().parent, wid(ObjectId::ROOT));
    let expected = gateway.namespace_revision();
    let trash = call(
        &mut gateway,
        route,
        req(
            5,
            ns::Operation::Trash {
                object: file,
                expected_namespace_revision: expected,
            },
        ),
    );
    assert_eq!(trash.entry.unwrap().state, ns::EntryState::Trashed);
    let file_route = binding(sid(file), 7, Rights::ReadOnly);
    assert_eq!(gateway.bind(file_route), Err(BindError::Invalid));
    let expected = gateway.namespace_revision();
    let restored = call(
        &mut gateway,
        route,
        req(
            6,
            ns::Operation::Restore {
                object: file,
                destination: wid(ObjectId::ROOT),
                name: ns::Name::new(b"restored.txt").unwrap(),
                expected_namespace_revision: expected,
            },
        ),
    );
    assert_eq!(restored.entry.unwrap().state, ns::EntryState::Live);
    assert_eq!(restored.entry.unwrap().object, file);
    let before = memory.counts();
    let describe = call(
        &mut gateway,
        route,
        req(7, ns::Operation::Inspect { object: file }),
    );
    assert_eq!(describe.entry.unwrap().name.as_bytes(), b"restored.txt");
    assert_eq!(memory.counts(), before);
    // Only owner retirement is modeled here; dropping is not native quiescence.
    drop(gateway.into_storage().unwrap_or_else(|_| panic!("settled")));
    let cold = Memory::image(memory.snapshot());
    let mut cold_scratch = Box::new(StoreScratch::empty());
    let store = Dataset::open(cold, &mut cold_scratch, DEADLINE).unwrap_or_else(|_| panic!("cold"));
    let mut gateway = Gateway::new(store, &mut service);
    gateway.bind_namespace(route).unwrap();
    let mut cursor = 0;
    let mut names = vec![];
    loop {
        let expected = gateway.namespace_revision();
        let response = call(
            &mut gateway,
            route,
            req(
                10 + u64::from(cursor),
                ns::Operation::List {
                    directory: wid(ObjectId::ROOT),
                    cursor,
                    expected_namespace_revision: expected,
                },
            ),
        );
        if response.outcome == Outcome::End {
            break;
        }
        let entry = response.entry.unwrap();
        assert!(entry.object.slot > cursor);
        cursor = response.next_cursor.unwrap();
        names.push(entry.name);
    }
    assert_eq!(names.len(), 3);
    assert!(names.iter().any(|n| n.as_bytes() == b"restored.txt"));
    assert!(names.iter().any(|n| n.as_bytes() == b"Document.txt"));
    assert_eq!(gateway.owner_metadata(initial).unwrap().id, initial);
}

#[test]
fn scoped_metadata_rights_stale_revisions_replay_and_no_blanket_content_authority() {
    let memory = Memory::new();
    let mut scratch = Box::new(StoreScratch::empty());
    let mut service = Box::new(Scratch::empty());
    let (store, file, _) = dataset(memory.clone(), &mut scratch);
    let mut gateway = Gateway::new(store, &mut service);
    let owner = ns_binding(ObjectId::ROOT, 77, NamespaceRights::Manage);
    gateway.bind_namespace(owner).unwrap();
    let folder = create(
        &mut gateway,
        owner,
        1,
        ObjectId::ROOT,
        "scope",
        ns::Kind::Directory,
    )
    .entry
    .unwrap()
    .object;
    let restricted = ns_binding(sid(folder), 88, NamespaceRights::Inspect);
    let key = gateway.bind_namespace(restricted).unwrap();
    let before = memory.counts();
    let denied = create(
        &mut gateway,
        restricted,
        1,
        sid(folder),
        "no.txt",
        ns::Kind::File,
    );
    assert_eq!(denied.outcome, Outcome::Denied);
    let denied = call(
        &mut gateway,
        restricted,
        req(2, ns::Operation::Inspect { object: wid(file) }),
    );
    assert_eq!(denied.outcome, Outcome::Denied);
    let stale = create(
        &mut gateway,
        owner,
        2,
        ObjectId::ROOT,
        "fresh.txt",
        ns::Kind::File,
    );
    assert_eq!(stale.outcome, Outcome::Completed);
    let exact = req(
        3,
        ns::Operation::Create {
            directory: wid(ObjectId::ROOT),
            kind: ns::Kind::File,
            name: ns::Name::new(b"once.txt").unwrap(),
            expected_namespace_revision: gateway.namespace_revision(),
        },
    );
    let applied = call(&mut gateway, owner, exact);
    assert_eq!(applied.outcome, Outcome::Completed);
    let count = memory.counts();
    assert_eq!(call(&mut gateway, owner, exact), applied);
    assert_eq!(memory.counts(), count);
    let changed = ns::Request {
        request_id: exact.request_id + 1,
        ..exact
    };
    assert_eq!(
        call(&mut gateway, owner, changed).outcome,
        Outcome::Conflict
    );
    assert_eq!(memory.counts(), count);
    let stale = req(
        4,
        ns::Operation::Create {
            directory: wid(ObjectId::ROOT),
            kind: ns::Kind::File,
            name: ns::Name::new(b"stale.txt").unwrap(),
            expected_namespace_revision: 0,
        },
    );
    assert_eq!(call(&mut gateway, owner, stale).outcome, Outcome::Conflict);
    assert_eq!(memory.counts(), count);
    let describe = req(5, ns::Operation::Inspect { object: folder });
    let frame = describe.encode().unwrap();
    let mut wrong = ns_capture(restricted);
    wrong.caller = Caller::new(89, 0).unwrap();
    let NamespaceDispatch::Complete { frame: refused } =
        gateway.handle_namespace(wrong, &frame, 0).unwrap()
    else {
        panic!()
    };
    assert_eq!(
        ns::client_decode(describe, &refused, 0).unwrap().outcome,
        Outcome::Denied
    );
    gateway.revoke_namespace(key).unwrap();
    assert_eq!(
        call(&mut gateway, restricted, describe).outcome,
        Outcome::Denied
    );
    assert_eq!(
        gateway.handle_namespace(ns_capture(owner), &frame, 1),
        Err(ns::Error::CapabilityCount)
    );
    let mut malformed = frame;
    malformed[255] = 1;
    assert!(
        gateway
            .handle_namespace(ns_capture(owner), &malformed, 0)
            .is_err()
    );
    // Directory metadata did not install any File endpoint: a matching-looking
    // File frame at that descriptive namespace route is denied before any I/O.
    let read = request(
        10,
        1,
        wire::Method::Read {
            offset: 0,
            length: 1,
        },
    );
    let mut out = [0; 1];
    let NamespaceBinding {
        endpoint,
        caller,
        lease_epoch,
        ..
    } = owner;
    assert_eq!(
        reply(
            read,
            gateway
                .handle(
                    Captured {
                        endpoint,
                        caller,
                        lease_epoch,
                        now: 100
                    },
                    &read.encode().unwrap(),
                    0,
                    Loan::Read(&mut out)
                )
                .unwrap()
        )
        .outcome,
        Outcome::Denied
    );
    assert!(count.1 > before.1);
    assert_eq!(memory.counts(), count);
}

#[test]
fn wire_depth_eight_utf8_name96_and_all256_child_slots_are_real_bounds() {
    let memory = Memory::new();
    let mut scratch = Box::new(StoreScratch::empty());
    let mut service = Box::new(Scratch::empty());
    let (store, _, _) = dataset(memory.clone(), &mut scratch);
    let mut gateway = Gateway::new(store, &mut service);
    let route = ns_binding(ObjectId::ROOT, 77, NamespaceRights::Manage);
    gateway.bind_namespace(route).unwrap();
    let mut parent = ObjectId::ROOT;
    let mut nonce = 1;
    for depth in 1..=8 {
        let name = std::format!("depth{depth}");
        let r = create(
            &mut gateway,
            route,
            nonce,
            parent,
            &name,
            ns::Kind::Directory,
        );
        assert_eq!(r.outcome, Outcome::Completed);
        parent = sid(r.entry.unwrap().object);
        nonce += 1;
    }
    let before = memory.counts();
    assert_eq!(
        create(
            &mut gateway,
            route,
            nonce,
            parent,
            "too-deep",
            ns::Kind::File
        )
        .outcome,
        Outcome::Conflict
    );
    nonce += 1;
    assert_eq!(memory.counts(), before);
    let long = "é".repeat(48);
    assert_eq!(long.len(), 96);
    assert!(ns::Name::new((long.clone() + "x").as_bytes()).is_err());
    let mut last = 0;
    for index in 0..247 {
        let name = if index == 0 {
            long.clone()
        } else {
            std::format!("file{index}")
        };
        let r = create(
            &mut gateway,
            route,
            nonce,
            ObjectId::ROOT,
            &name,
            ns::Kind::File,
        );
        assert_eq!(r.outcome, Outcome::Completed);
        last = r.entry.unwrap().object.slot;
        nonce += 1;
    }
    assert_eq!(last, 256);
    let before = memory.counts();
    assert_eq!(
        create(
            &mut gateway,
            route,
            nonce,
            ObjectId::ROOT,
            "overflow",
            ns::Kind::File
        )
        .outcome,
        Outcome::NoSpace
    );
    assert_eq!(memory.counts(), before);
    let expected = gateway.namespace_revision();
    let end = call(
        &mut gateway,
        route,
        req(
            nonce + 1,
            ns::Operation::List {
                directory: wid(ObjectId::ROOT),
                cursor: 256,
                expected_namespace_revision: expected,
            },
        ),
    );
    assert_eq!(end.outcome, Outcome::End);
}

#[test]
fn accepted_namespace_unknown_retains_original_frame_global_and_blocks_fresh_ids() {
    let memory = Memory::new();
    let mut scratch = Box::new(StoreScratch::empty());
    let mut service = Box::new(Scratch::empty());
    let (store, file, revision) = dataset(memory.clone(), &mut scratch);
    let mut gateway = Gateway::new(store, &mut service);
    let route = ns_binding(ObjectId::ROOT, 77, NamespaceRights::Manage);
    gateway.bind_namespace(route).unwrap();
    let file_route = binding(file, 7, Rights::ReadWrite);
    gateway.bind(file_route).unwrap();
    let request = req(
        1,
        ns::Operation::Create {
            directory: wid(ObjectId::ROOT),
            kind: ns::Kind::File,
            name: ns::Name::new(b"uncertain.txt").unwrap(),
            expected_namespace_revision: gateway.namespace_revision(),
        },
    );
    let frame = request.encode().unwrap();
    memory.fail_next_flush_after_persist();
    assert_eq!(
        gateway.handle_namespace(ns_capture(route), &frame, 0),
        Ok(NamespaceDispatch::Retained)
    );
    let retained = gateway.namespace_pending().unwrap();
    assert_eq!(retained.request, request);
    assert_eq!(retained.frame, frame);
    assert_eq!(retained.fingerprint, hash(&frame));
    assert!(retained.global_operation.is_some());
    let counts = memory.counts();
    let fresh = ns::Request {
        request_id: 55,
        operation_id: 2,
        ..request
    };
    assert_eq!(
        gateway.handle_namespace(ns_capture(route), &fresh.encode().unwrap(), 0),
        Ok(NamespaceDispatch::Retained)
    );
    assert_eq!(gateway.namespace_pending(), Some(retained));
    let expired = Captured {
        now: DEADLINE,
        ..ns_capture(route)
    };
    assert_eq!(
        gateway.handle_namespace(expired, &frame, 0),
        Ok(NamespaceDispatch::Retained)
    );
    assert_eq!(gateway.namespace_pending(), Some(retained));
    let read = super::request(
        20,
        revision,
        wire::Method::Read {
            offset: 0,
            length: 1,
        },
    );
    let mut out = [0x55; 1];
    assert_eq!(
        reply(
            read,
            handle(&mut gateway, file_route, read, Loan::Read(&mut out))
        )
        .outcome,
        Outcome::Busy
    );
    assert_eq!(out, [0x55]);
    assert_eq!(memory.counts(), counts);
    assert!(gateway.into_storage().is_err());
}

#[test]
fn two_namespace_nonce_one_scopes_and_cold_identical_identity_never_alias_receipts() {
    let memory = Memory::new();
    let mut scratch = Box::new(StoreScratch::empty());
    let mut service = Box::new(Scratch::empty());
    let (store, _, _) = dataset(memory.clone(), &mut scratch);
    let mut gateway = Gateway::new(store, &mut service);
    let root = ns_binding(ObjectId::ROOT, 77, NamespaceRights::Manage);
    let files = ns_binding(ObjectId::ROOT, 88, NamespaceRights::Manage);
    gateway.bind_namespace(root).unwrap();
    gateway.bind_namespace(files).unwrap();
    let first = req(
        1,
        ns::Operation::Create {
            directory: wid(ObjectId::ROOT),
            kind: ns::Kind::File,
            name: ns::Name::new(b"Root.txt").unwrap(),
            expected_namespace_revision: gateway.namespace_revision(),
        },
    );
    let a = call(&mut gateway, root, first);
    let b = create(
        &mut gateway,
        files,
        1,
        ObjectId::ROOT,
        "Files.txt",
        ns::Kind::File,
    );
    assert_eq!(a.outcome, Outcome::Completed);
    assert_eq!(b.outcome, Outcome::Completed);
    assert_ne!(a.entry.unwrap().object, b.entry.unwrap().object);
    let counts = memory.counts();
    assert_eq!(call(&mut gateway, root, first), a);
    assert_eq!(memory.counts(), counts);
    let last = gateway.backend_receipt().unwrap().unwrap().operation.get();
    drop(gateway.into_storage().unwrap_or_else(|_| panic!("settled")));
    let cold = Memory::image(memory.snapshot());
    let mut cold_scratch = Box::new(StoreScratch::empty());
    let store = Dataset::open(cold, &mut cold_scratch, DEADLINE).unwrap_or_else(|_| panic!("cold"));
    let mut gateway = Gateway::new(store, &mut service);
    gateway.bind_namespace(root).unwrap();
    let fresh = create(
        &mut gateway,
        root,
        1,
        ObjectId::ROOT,
        "Cold.txt",
        ns::Kind::File,
    );
    assert_eq!(fresh.outcome, Outcome::Completed);
    assert_eq!(
        gateway.backend_receipt().unwrap().unwrap().operation.get(),
        last + 1
    );
    assert_ne!(fresh.entry.unwrap().object, a.entry.unwrap().object);
}

#[test]
fn explicit_retired_namespace_key_allows_only_a_new_exact_binding_and_keeps_root_route() {
    let memory = Memory::new();
    let mut scratch = Box::new(StoreScratch::empty());
    let mut service = Box::new(Scratch::empty());
    let (store, object, _) = dataset(memory.clone(), &mut scratch);
    let mut gateway = Gateway::new(store, &mut service);
    let root = ns_binding(ObjectId::ROOT, 77, NamespaceRights::Manage);
    let files = ns_binding(ObjectId::ROOT, 88, NamespaceRights::Manage);
    gateway.bind_namespace(root).unwrap();
    let key = gateway.bind_namespace(files).unwrap();
    let before = memory.counts();
    assert_eq!(
        gateway.retire_namespace_quiescent(key),
        Err(RetireError::Active)
    );
    gateway.revoke_namespace(key).unwrap();
    gateway.retire_namespace_quiescent(key).unwrap();
    assert_eq!(
        gateway.retire_namespace_quiescent(key),
        Err(RetireError::Stale)
    );
    assert_eq!(memory.counts(), before);
    let replacement = NamespaceBinding {
        caller: Caller::new(99, 0).unwrap(),
        lease_epoch: 2,
        ..files
    };
    assert_ne!(gateway.bind_namespace(replacement).unwrap(), key);
    let inspect = req(
        5,
        ns::Operation::Inspect {
            object: wid(object),
        },
    );
    assert_eq!(call(&mut gateway, files, inspect).outcome, Outcome::Denied);
    assert_eq!(
        call(&mut gateway, replacement, inspect).outcome,
        Outcome::Completed
    );
    assert_eq!(
        call(&mut gateway, root, inspect).outcome,
        Outcome::Completed
    );
    assert_eq!(memory.counts(), before);
}

#[test]
fn namespace_uncertainty_cannot_be_cleared_by_explicit_retirement() {
    let memory = Memory::new();
    let mut scratch = Box::new(StoreScratch::empty());
    let mut service = Box::new(Scratch::empty());
    let (store, _, _) = dataset(memory.clone(), &mut scratch);
    let mut gateway = Gateway::new(store, &mut service);
    let files = ns_binding(ObjectId::ROOT, 88, NamespaceRights::Manage);
    let key = gateway.bind_namespace(files).unwrap();
    let request = req(
        1,
        ns::Operation::Create {
            directory: wid(ObjectId::ROOT),
            kind: ns::Kind::File,
            name: ns::Name::new(b"may-have-published.txt").unwrap(),
            expected_namespace_revision: gateway.namespace_revision(),
        },
    );
    memory.fail_next_flush_after_persist();
    assert_eq!(
        gateway.handle_namespace(ns_capture(files), &request.encode().unwrap(), 0),
        Ok(NamespaceDispatch::Retained)
    );
    let retained = gateway.namespace_pending();
    gateway.revoke_namespace(key).unwrap();
    let before = memory.counts();
    assert!(matches!(
        gateway.retire_namespace_quiescent(key),
        Err(RetireError::Busy | RetireError::StorageFenced)
    ));
    assert_eq!(gateway.namespace_pending(), retained);
    assert_eq!(memory.counts(), before);
    assert_eq!(
        gateway.bind_namespace(NamespaceBinding {
            lease_epoch: 2,
            ..files
        }),
        Err(BindError::StorageFenced)
    );
    assert!(gateway.into_storage().is_err());
}
