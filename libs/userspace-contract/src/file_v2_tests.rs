use super::*;
use core::cell::Cell;

#[test]
fn staged_verify_requires_both_minor_and_feature_without_changing_major_or_legacy_support() {
    let old = Support {
        major: 2,
        minor: 0,
        features: 0,
    };
    assert!(old.supports(VERSION, 0, 0));
    assert!(!old.supports(VERSION, MINOR, FEATURE_STAGED_VERIFY));
    assert_eq!((VERSION, MINOR, FEATURES), (2, 1, 1));
    assert!(SUPPORT.supports(2, 0, 0));
    assert!(SUPPORT.supports(2, 1, FEATURE_STAGED_VERIFY));
    assert!(!SUPPORT.supports(1, 0, 0));
    assert!(!SUPPORT.supports(2, 2, 0));
    assert!(!SUPPORT.supports(2, 1, FEATURE_STAGED_VERIFY | 2));
    assert!(
        !Support {
            features: 0,
            ..SUPPORT
        }
        .supports(2, 1, FEATURE_STAGED_VERIFY)
    );
    assert!(
        !Support {
            minor: 0,
            ..SUPPORT
        }
        .supports(2, 1, FEATURE_STAGED_VERIFY)
    );
}

#[test]
fn minor1_metadata_does_not_appear_in_minor0_begin_wire_records() {
    let r = request(Method::BeginWrite {
        length: 15,
        digest: [9; 32],
    });
    let mut expected = [0; FRAME_BYTES];
    expected[..8].copy_from_slice(b"EVF2RQ01");
    expected[8] = 2;
    for (at, n) in [(16, 31u64), (24, 10), (32, 200), (40, 7)] {
        expected[at..at + 8].copy_from_slice(&n.to_le_bytes());
    }
    expected[68..72].copy_from_slice(&15u32.to_le_bytes());
    expected[72..104].copy_from_slice(&[9; 32]);
    assert_eq!(r.encode().unwrap(), expected);
    assert_eq!(Request::decode(&expected), Ok(r));
}

fn request(method: Method) -> Request {
    Request {
        request_id: 31,
        operation_id: if matches!(method, Method::Read { .. }) {
            0
        } else {
            10
        },
        deadline: Deadline::new(200).unwrap(),
        expected_revision: if method == Method::QueryOperation {
            0
        } else {
            7
        },
        method,
    }
}
fn commit() -> Request {
    request(Method::Commit {
        transfer_id: 19,
        length: MAX_FILE_BYTES,
        digest: [9; 32],
    })
}
fn committed() -> Response {
    Response {
        request_id: 31,
        operation_id: 10,
        outcome: Outcome::Completed,
        revision: 8,
        transfer_id: 19,
        offset: 0,
        length: 0,
        file_length: MAX_FILE_BYTES,
        digest: [9; 32],
    }
}

#[test]
fn staged_verification_is_bounded_exactly_correlated_and_never_a_commit_receipt() {
    for (offset, length) in [
        (0, 0),
        (0, 15),
        (0, 4096),
        (4096, 4097),
        (MAX_FILE_BYTES - 4096, MAX_FILE_BYTES),
    ] {
        let request = request(Method::Verify {
            transfer_id: 19,
            offset,
            length,
            digest: [9; 32],
        });
        let bytes = request.encode().unwrap();
        assert_eq!(bytes[8], 7);
        assert_eq!(Request::decode(&bytes), Ok(request));
        let reply = Response {
            revision: request.expected_revision,
            offset: (offset + 4096).min(length),
            file_length: length,
            ..committed()
        };
        assert!(reply.matches(request).is_ok());
        assert!(
            Response {
                revision: 8,
                ..reply
            }
            .matches(request)
            .is_err()
        );
        assert!(
            Response {
                transfer_id: 20,
                ..reply
            }
            .matches(request)
            .is_err()
        );
        assert!(
            Response {
                digest: [8; 32],
                ..reply
            }
            .matches(request)
            .is_err()
        );
        if length != 0 {
            assert!(Response { offset: 0, ..reply }.matches(request).is_err());
        }
        let mut extra = bytes;
        extra[64] = 1;
        assert!(Request::decode(&extra).is_err());
    }
    for (offset, length) in [(1, 4096), (4096, 4096), (0, MAX_FILE_BYTES + 1), (4096, 0)] {
        assert!(
            request(Method::Verify {
                transfer_id: 19,
                offset,
                length,
                digest: [9; 32]
            })
            .encode()
            .is_err()
        );
    }
}
fn status(outcome: Outcome) -> Response {
    Response {
        outcome,
        revision: 0,
        transfer_id: 0,
        file_length: 0,
        digest: [0; 32],
        ..committed()
    }
}

#[test]
fn each_method_has_a_separate_canonical_record_with_bounded_bulk_metadata() {
    let methods = [
        Method::Read {
            offset: 0,
            length: MAX_CHUNK_BYTES,
        },
        Method::BeginWrite {
            length: MAX_FILE_BYTES,
            digest: [9; 32],
        },
        Method::WriteChunk {
            transfer_id: 19,
            offset: MAX_FILE_BYTES - MAX_CHUNK_BYTES,
            length: MAX_CHUNK_BYTES,
            digest: [8; 32],
        },
        Method::Commit {
            transfer_id: 19,
            length: MAX_FILE_BYTES,
            digest: [9; 32],
        },
        Method::Abort { transfer_id: 19 },
        Method::QueryOperation,
        Method::Verify {
            transfer_id: 19,
            offset: 0,
            length: 4096,
            digest: [9; 32],
        },
    ];
    for (i, method) in methods.into_iter().enumerate() {
        let r = request(method);
        let bytes = r.encode().unwrap();
        assert_eq!(&bytes[..8], b"EVF2RQ01");
        assert_eq!(bytes[8], i as u8 + 1);
        assert_eq!(Request::decode(&bytes), Ok(r));
        assert_eq!(Response::decode(&bytes), Err(Error::Magic));
        assert_eq!(bytes.len(), 256); // Bulk never becomes an inline control payload.
    }
}

#[test]
fn chunk_and_file_limits_integer_overflow_and_invalid_transfer_ids_refuse() {
    for (offset, length) in [
        (0, 0),
        (0, MAX_CHUNK_BYTES + 1),
        (MAX_FILE_BYTES, 1),
        (u32::MAX, 2),
    ] {
        assert_eq!(
            request(Method::Read { offset, length }).encode(),
            Err(Error::Bounds)
        );
    }
    for transfer_id in [0, u64::MAX] {
        assert_eq!(
            request(Method::Commit {
                transfer_id,
                length: 0,
                digest: [0; 32]
            })
            .encode(),
            Err(Error::Identity)
        );
    }
    assert_eq!(
        request(Method::BeginWrite {
            length: MAX_FILE_BYTES + 1,
            digest: [0; 32]
        })
        .encode(),
        Err(Error::Bounds)
    );
    assert!(
        request(Method::BeginWrite {
            length: 0,
            digest: [1; 32]
        })
        .encode()
        .is_ok()
    );
    let mut bytes = commit().encode().unwrap();
    put(&mut bytes, 32, u64::MAX);
    assert_eq!(Request::decode(&bytes), Err(Error::Deadline));
    let mut bytes = commit().encode().unwrap();
    put(&mut bytes, 56, u64::MAX);
    assert_eq!(Request::decode(&bytes), Err(Error::Bounds));
}

#[test]
fn malformed_records_do_not_invoke_handlers_or_accept_inline_capabilities() {
    let r = request(Method::Read {
        offset: 0,
        length: 1,
    });
    let b = r.encode().unwrap();
    for i in (9..16).chain(48..56).chain(60..64).chain(68..FRAME_BYTES) {
        let mut bad = b;
        bad[i] = 1;
        let called = Cell::new(false);
        assert!(
            server_dispatch(&bad, 0, |_| {
                called.set(true);
                status(Outcome::Denied)
            })
            .is_err(),
            "byte {i}"
        );
        assert!(!called.get());
    }
    for len in 0..FRAME_BYTES {
        assert_eq!(Request::decode(&b[..len]), Err(Error::Length));
        assert_eq!(Response::decode(&b[..len]), Err(Error::Length));
    }
    let called = Cell::new(false);
    assert_eq!(
        server_dispatch(&b, 1, |_| {
            called.set(true);
            status(Outcome::Denied)
        }),
        Err(Error::CapabilityCount)
    );
    assert!(!called.get());
    for n in [0, 8, 255] {
        let mut bad = b;
        bad[8] = n;
        assert_eq!(Request::decode(&bad), Err(Error::Opcode));
    }
}

#[test]
fn commit_confirmation_requires_exact_revision_transfer_length_and_digest() {
    let r = commit();
    let reply = committed();
    assert_eq!(client_decode(r, &reply.encode().unwrap(), 0), Ok(reply));
    for bad in [
        Response {
            request_id: 32,
            ..reply
        },
        Response {
            operation_id: 11,
            ..reply
        },
        Response {
            revision: 7,
            ..reply
        },
        Response {
            transfer_id: 20,
            ..reply
        },
        Response {
            file_length: MAX_FILE_BYTES - 1,
            ..reply
        },
        Response {
            digest: [8; 32],
            ..reply
        },
    ] {
        assert_eq!(
            client_decode(r, &bad.encode().unwrap(), 0),
            Err(Error::Correlation)
        );
    }
    assert_eq!(
        client_decode(r, &reply.encode().unwrap(), 1),
        Err(Error::CapabilityCount)
    );
    let mut bad = reply.encode().unwrap();
    bad[32] = 1;
    assert_eq!(Response::decode(&bad), Err(Error::Reserved));
    let mut bad = reply.encode().unwrap();
    bad[8] = 13;
    assert_eq!(Response::decode(&bad), Err(Error::Outcome));
    assert_eq!(
        Response {
            outcome: Outcome::Uncertain,
            ..reply
        }
        .encode(),
        Err(Error::Outcome)
    );
}

#[test]
fn readback_is_exact_revision_and_range_and_does_not_claim_digest_verification() {
    let r = request(Method::Read {
        offset: 4096,
        length: 4096,
    });
    let reply = Response {
        request_id: 31,
        operation_id: 0,
        outcome: Outcome::Completed,
        revision: 7,
        transfer_id: 0,
        offset: 4096,
        length: 4096,
        file_length: 8192,
        digest: [3; 32],
    };
    assert_eq!(client_decode(r, &reply.encode().unwrap(), 0), Ok(reply));
    for bad in [
        Response {
            revision: 8,
            ..reply
        },
        Response {
            offset: 4095,
            ..reply
        },
        Response {
            transfer_id: 19,
            ..reply
        },
    ] {
        assert_eq!(bad.matches(r), Err(Error::Correlation));
    }
    // The actual adapter still hashes the separately owned range. A wire hash
    // is descriptive integrity metadata, not evidence that those bytes exist.
}

#[test]
fn accepted_timeout_and_late_completion_retain_one_exact_pending_request() {
    let r = commit();
    let mut pending = Pending::new(r).unwrap();
    pending
        .observe(&status(Outcome::Accepted).encode().unwrap(), 0)
        .unwrap();
    assert_eq!(pending.state(), WaitState::Accepted);
    pending.timeout();
    assert_eq!(pending.state(), WaitState::Uncertain);
    assert!(!pending.completion_observed());
    assert_eq!(pending.request(), r);
    let bad = Response {
        request_id: 32,
        ..committed()
    };
    assert_eq!(
        pending.observe(&bad.encode().unwrap(), 0),
        Err(Error::Correlation)
    );
    assert_eq!(pending.state(), WaitState::Uncertain);
    pending
        .observe(&status(Outcome::Uncertain).encode().unwrap(), 0)
        .unwrap();
    assert!(!pending.completion_observed());
    for outcome in [Outcome::Stale, Outcome::Corrupt] {
        pending
            .observe(&status(outcome).encode().unwrap(), 0)
            .unwrap();
        assert_eq!(pending.state(), WaitState::Uncertain);
        assert!(!pending.completion_observed());
    }
    pending.observe(&committed().encode().unwrap(), 0).unwrap();
    assert!(pending.completion_observed());
    assert_eq!(
        pending.observe(&committed().encode().unwrap(), 0),
        Err(Error::Correlation)
    );
    pending.timeout();
    assert!(pending.completion_observed());
}

#[test]
fn v1_bytes_are_unchanged_and_neither_major_decoder_guesses_the_other() {
    let old = crate::file::Request::Read.encode();
    assert_eq!(&old[..8], b"EVFRQ001");
    assert_eq!(&old[8..10], &1u16.to_le_bytes());
    assert_eq!(
        crate::file::Request::decode(&old),
        Ok(crate::file::Request::Read)
    );
    assert_eq!(Request::decode(&old), Err(Error::Magic));
    assert!(crate::file::Request::decode(&commit().encode().unwrap()).is_err());
    assert_eq!(
        crate::workspace::Request::decode(&commit().encode().unwrap()),
        Err(Error::Magic)
    );
}

#[test]
fn equal_client_operation_ids_are_not_a_global_sequence_or_caller_identity() {
    let first = Request {
        request_id: 1,
        operation_id: 1,
        ..commit()
    };
    let second_editor = first;
    // Both authenticated clients may independently start at 1. There is no
    // claimed PID/lease field to trust in these bytes. Actual route+incarnation
    // and lease must distinguish equal frames before any backend operation.
    assert_eq!(first.encode().unwrap(), second_editor.encode().unwrap());
    assert_eq!(Request::decode(&first.encode().unwrap()), Ok(first));
    let conflict = Request {
        method: Method::Commit {
            transfer_id: 19,
            length: 5,
            digest: [4; 32],
        },
        ..first
    };
    assert_ne!(first.encode().unwrap(), conflict.encode().unwrap());
    // Shape validation intentionally cannot declare same-ID/new-fingerprint
    // reexecution safe. The service's authenticated replay table must refuse it.
}

#[test]
fn query_retains_original_operation_and_reports_bounded_durable_stage_prefix() {
    let query = request(Method::QueryOperation);
    let reply = Response {
        revision: 7,
        offset: 4096,
        length: 0,
        ..committed()
    };
    assert_eq!(client_decode(query, &reply.encode().unwrap(), 0), Ok(reply));
    let unknown = status(Outcome::Stale);
    assert_eq!(
        client_decode(query, &unknown.encode().unwrap(), 0),
        Ok(unknown)
    );
    assert_eq!(
        Response { length: 1, ..reply }.matches(query),
        Err(Error::Correlation)
    );
}

#[test]
fn single_byte_mutations_of_valid_frames_are_total_and_never_noncanonical() {
    for seed in [commit().encode().unwrap(), committed().encode().unwrap()] {
        for index in 0..FRAME_BYTES {
            for bit in 0..8 {
                let mut bytes = seed;
                bytes[index] ^= 1 << bit;
                if let Ok(value) = Request::decode(&bytes) {
                    assert_eq!(value.encode().unwrap(), bytes);
                }
                if let Ok(value) = Response::decode(&bytes) {
                    assert_eq!(value.encode().unwrap(), bytes);
                }
            }
        }
    }
}

#[test]
fn bounded_arbitrary_control_bytes_are_total_and_canonical_if_accepted() {
    let mut state = 0x7a32_51c9_u32;
    for _ in 0..2048 {
        let mut bytes = [0; FRAME_BYTES];
        for b in &mut bytes {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *b = state as u8;
        }
        if let Ok(value) = Request::decode(&bytes) {
            assert_eq!(value.encode().unwrap(), bytes);
        }
        if let Ok(value) = Response::decode(&bytes) {
            assert_eq!(value.encode().unwrap(), bytes);
        }
        if let Ok(value) = crate::workspace::Request::decode(&bytes) {
            assert_eq!(value.encode().unwrap(), bytes);
        }
        if let Ok(value) = crate::workspace::Response::decode(&bytes) {
            assert_eq!(value.encode().unwrap(), bytes);
        }
    }
}
