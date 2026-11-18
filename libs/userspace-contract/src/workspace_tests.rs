use super::*;
use core::cell::Cell;

fn object(slot: u16) -> ObjectId {
    ObjectId {
        slot,
        generation: if slot == 0 { 1 } else { 7 },
    }
}
fn name() -> Name {
    Name::new("Идеи.txt".as_bytes()).unwrap()
}
fn request(operation: Operation) -> Request {
    Request {
        request_id: 4,
        operation_id: if matches!(
            operation,
            Operation::Inspect { .. } | Operation::List { .. }
        ) {
            0
        } else {
            9
        },
        deadline: Deadline::new(100).unwrap(),
        operation,
    }
}
fn entry() -> Entry {
    Entry {
        object: object(2),
        parent: object(1),
        revision: 3,
        size: MAX_FILE_BYTES,
        kind: Kind::File,
        state: EntryState::Live,
        name: name(),
    }
}
fn response(r: Request) -> Response {
    Response {
        request_id: r.request_id,
        operation_id: r.operation_id,
        outcome: Outcome::Completed,
        namespace_revision: 11,
        dataset: DatasetId([5; 16]),
        entry: Some(entry()),
        next_cursor: None,
    }
}

#[test]
fn all_namespace_operations_have_distinct_canonical_roundtrips() {
    let ops = [
        Operation::Inspect { object: object(2) },
        Operation::List {
            directory: object(1),
            cursor: 255,
            expected_namespace_revision: 11,
        },
        Operation::Create {
            directory: object(1),
            kind: Kind::File,
            name: name(),
            expected_namespace_revision: 11,
        },
        Operation::Rename {
            object: object(2),
            name: name(),
            expected_namespace_revision: 11,
        },
        Operation::Move {
            object: object(2),
            destination: object(1),
            expected_namespace_revision: 11,
        },
        Operation::Trash {
            object: object(2),
            expected_namespace_revision: 11,
        },
        Operation::Restore {
            object: object(2),
            destination: object(1),
            name: name(),
            expected_namespace_revision: 11,
        },
        Operation::QueryOperation,
    ];
    for (i, op) in ops.into_iter().enumerate() {
        let r = request(op);
        let b = r.encode().unwrap();
        assert_eq!(&b[..8], b"EVWSRQ01");
        assert_eq!(b[8], i as u8 + 1);
        assert_eq!(Request::decode(&b), Ok(r));
        assert_eq!(Response::decode(&b), Err(Error::Magic));
    }
}

#[test]
fn names_are_utf8_components_and_empty_is_reserved_for_root_metadata() {
    for bad in [
        &b""[..],
        b".",
        b"..",
        b"a/b",
        b"a\\b",
        b"a\0b",
        b"a\nb",
        &[0xff],
    ] {
        assert_eq!(Name::new(bad), Err(Error::Name));
    }
    assert!(Name::new(&[b'x'; MAX_NAME_BYTES]).is_ok());
    assert_eq!(Name::new(&[b'x'; MAX_NAME_BYTES + 1]), Err(Error::Name));
    assert_eq!(name().as_str(), "Идеи.txt");
    let create = request(Operation::Create {
        directory: object(0),
        kind: Kind::Directory,
        name: Name::root(),
        expected_namespace_revision: 0,
    });
    assert_eq!(create.encode(), Err(Error::Name));
    let r = request(Operation::Inspect { object: object(0) });
    let mut reply = response(r);
    reply.entry = Some(Entry {
        object: object(0),
        parent: object(0),
        revision: 0,
        size: 0,
        kind: Kind::Directory,
        state: EntryState::Live,
        name: Name::root(),
    });
    assert_eq!(Response::decode(&reply.encode().unwrap()), Ok(reply));
}

#[test]
fn finite_deadlines_identity_generations_and_revision_bounds_are_explicit() {
    for n in [0, u64::MAX] {
        assert_eq!(Deadline::new(n), Err(Error::Deadline));
    }
    let d = Deadline::new(100).unwrap();
    assert!(d.is_live(99));
    assert!(!d.is_live(100));
    for id in [
        ObjectId {
            slot: 257,
            generation: 1,
        },
        ObjectId {
            slot: 1,
            generation: 0,
        },
        ObjectId {
            slot: 1,
            generation: u64::MAX,
        },
    ] {
        assert_eq!(
            request(Operation::Inspect { object: id }).encode(),
            Err(Error::Identity)
        );
    }
    let old = request(Operation::Inspect { object: object(1) });
    let new = request(Operation::Inspect {
        object: ObjectId {
            slot: 1,
            generation: 8,
        },
    });
    assert_ne!(old.encode(), new.encode());
    assert_eq!(
        request(Operation::List {
            directory: object(1),
            cursor: 257,
            expected_namespace_revision: 0
        })
        .encode(),
        Err(Error::Bounds)
    );
    assert_eq!(
        request(Operation::Trash {
            object: object(2),
            expected_namespace_revision: u64::MAX
        })
        .encode(),
        Err(Error::Bounds)
    );
}

#[test]
fn reference_has_256_children_besides_root_and_final_listing_cursor() {
    let last = object(256);
    assert_eq!(last.validate(), Ok(()));
    let inspect = request(Operation::Inspect { object: last });
    assert_eq!(Request::decode(&inspect.encode().unwrap()), Ok(inspect));
    let list = request(Operation::List {
        directory: object(0),
        cursor: 256,
        expected_namespace_revision: 11,
    });
    assert_eq!(Request::decode(&list.encode().unwrap()), Ok(list));
    let end = Response {
        outcome: Outcome::End,
        entry: None,
        ..response(list)
    };
    assert_eq!(client_decode(list, &end.encode().unwrap(), 0), Ok(end));
    assert_eq!(
        ObjectId {
            slot: 0,
            generation: 2
        }
        .validate(),
        Err(Error::Identity)
    );
}

#[test]
fn unused_bytes_truncation_wrong_direction_and_capabilities_refuse_before_handler() {
    let r = request(Operation::Inspect { object: object(2) });
    let b = r.encode().unwrap();
    for i in (9..16).chain(40..48).chain(50..56).chain(64..FRAME_BYTES) {
        let mut bad = b;
        bad[i] = 1;
        let called = Cell::new(false);
        assert!(
            server_dispatch(&bad, 0, |_| {
                called.set(true);
                response(r)
            })
            .is_err(),
            "byte {i}"
        );
        assert!(!called.get());
    }
    for len in 0..FRAME_BYTES {
        assert_eq!(Request::decode(&b[..len]), Err(Error::Length));
    }
    assert_eq!(Request::decode(&[0; FRAME_BYTES + 1]), Err(Error::Length));
    let called = Cell::new(false);
    assert_eq!(
        server_dispatch(&b, 1, |_| {
            called.set(true);
            response(r)
        }),
        Err(Error::CapabilityCount)
    );
    assert!(!called.get());
    for opcode in [0, 9, 255] {
        let mut bad = b;
        bad[8] = opcode;
        assert_eq!(Request::decode(&bad), Err(Error::Opcode));
    }
}

#[test]
fn replies_bind_exact_request_operation_and_object_without_minting_authority() {
    let r = request(Operation::Inspect { object: object(2) });
    let reply = response(r);
    let b = reply.encode().unwrap();
    assert_eq!(client_decode(r, &b, 0), Ok(reply));
    assert_eq!(client_decode(r, &b, 1), Err(Error::CapabilityCount));
    for bad in [
        Response {
            request_id: 5,
            ..reply
        },
        Response {
            operation_id: 9,
            ..reply
        },
        Response {
            entry: Some(Entry {
                object: object(3),
                ..entry()
            }),
            ..reply
        },
    ] {
        assert_eq!(
            client_decode(r, &bad.encode().unwrap(), 0),
            Err(Error::Correlation)
        );
    }
    let mut bad = b;
    bad[200] = 1;
    assert_eq!(Response::decode(&bad), Err(Error::Reserved));
    let mut bad = b;
    bad[9] = 2;
    assert_eq!(Response::decode(&bad), Err(Error::Reserved));
    let mut bad = b;
    bad[8] = 13;
    assert_eq!(Response::decode(&bad), Err(Error::Outcome));
    assert_eq!(
        Response {
            dataset: DatasetId([0; 16]),
            ..reply
        }
        .encode(),
        Err(Error::Identity)
    );
    assert_eq!(
        Response {
            outcome: Outcome::Denied,
            ..reply
        }
        .encode(),
        Err(Error::Outcome)
    );
}

#[test]
fn listing_is_revision_pinned_bounded_metadata_and_mutation_uncertainty_is_not_completion() {
    let r = request(Operation::List {
        directory: object(1),
        cursor: 0,
        expected_namespace_revision: 11,
    });
    let reply = Response {
        next_cursor: Some(3),
        ..response(r)
    };
    assert_eq!(client_decode(r, &reply.encode().unwrap(), 0), Ok(reply));
    assert_eq!(
        Response {
            namespace_revision: 12,
            ..reply
        }
        .matches(r),
        Err(Error::Correlation)
    );
    let end = Response {
        outcome: Outcome::End,
        entry: None,
        next_cursor: None,
        ..reply
    };
    assert_eq!(client_decode(r, &end.encode().unwrap(), 0), Ok(end));
    assert_eq!(
        Response {
            namespace_revision: 12,
            ..end
        }
        .matches(r),
        Err(Error::Correlation)
    );
    assert_eq!(
        Response {
            next_cursor: Some(0),
            ..reply
        }
        .matches(r),
        Err(Error::Correlation)
    );
    let r = request(Operation::Trash {
        object: object(2),
        expected_namespace_revision: 11,
    });
    for outcome in [Outcome::Accepted, Outcome::Uncertain] {
        let reply = Response {
            outcome,
            entry: None,
            ..response(r)
        };
        assert!(!outcome.terminal());
        assert_eq!(client_decode(r, &reply.encode().unwrap(), 0), Ok(reply));
    }
}
