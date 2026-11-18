use super::*;
use ev_workspace_client::selection::{Access, Selection};

fn metadata(object: legacy::Object) -> legacy::Metadata {
    legacy::Metadata {
        identity: legacy::Identity::for_object(object),
        counter: 7,
        length: 13,
        digest: [0x5a; 32],
        global_operation: 19,
    }
}
fn inspect(object: legacy::Object) -> Request {
    Request {
        request_id: 47,
        deadline: Deadline::new(100_000).unwrap(),
        command: Command::LegacyInspect {
            object,
            lease_epoch: 17,
        },
    }
}
fn bind() -> LegacyBind {
    LegacyBind {
        slot: 2,
        object: legacy::Object::Private,
        target_process: 0x1_0000_0003,
        target_thread: 0x2_0000_0004,
        target_registered_token: 0,
        lease_epoch: 17,
        expected: metadata(legacy::Object::Private),
    }
}

#[test]
fn legacy_inspection_is_distinct_exact_original_metadata_and_correlated_object() {
    for object in [legacy::Object::Notes, legacy::Object::Private] {
        let request = inspect(object);
        let bytes = request.encode().unwrap();
        assert_eq!(Request::decode(&bytes), Ok(request));
        let response = LegacyResponse {
            request_id: request.request_id,
            lease_epoch: request.lease_epoch(),
            status: Status::Applied,
            metadata: Some(metadata(object)),
        };
        let bytes = response.encode().unwrap();
        assert_eq!(
            LegacyResponse::decode(&bytes).unwrap().matches(request),
            Ok(response)
        );
        assert_eq!(Response::decode(&bytes), Err(Error::Magic));
        assert_eq!(
            ev_userspace_contract::workspace::Response::decode(&bytes),
            Err(ev_userspace_contract::workspace::Error::Magic)
        );
        let other = if object == legacy::Object::Notes {
            legacy::Object::Private
        } else {
            legacy::Object::Notes
        };
        assert_eq!(response.matches(inspect(other)), Err(Error::Correlation));
        for offset in [9, 10, 15, 24, 40, 48, 56, 100, 144, 255] {
            let mut invalid = bytes;
            invalid[offset] = 1;
            assert!(LegacyResponse::decode(&invalid).is_err());
        }
    }
}

#[test]
fn legacy_bind_is_readonly_full_owner_exact_source_and_never_files_namespace_slot() {
    let bind = bind();
    let request = Request {
        command: Command::BindLegacyReadOnly(bind),
        ..inspect(bind.object)
    };
    let bytes = request.encode().unwrap();
    assert_eq!(Request::decode(&bytes), Ok(request));
    let selection = Selection::decode(&bind.selection(request.request_id).unwrap()).unwrap();
    assert!(selection.matches_receiver(47, bind.target_process, bind.target_thread, 0));
    assert_eq!(selection.dataset, legacy::ORIGINAL_VOLUME);
    assert_eq!(selection.object, bind.expected.identity.projected_object);
    assert_eq!(selection.access, Access::ReadOnly);
    assert_eq!(
        (selection.revision, selection.length, selection.digest),
        (7, 13, [0x5a; 32])
    );
    for nonce in [0, u64::from(u32::MAX), u64::from(u32::MAX) + 1] {
        assert_eq!(bind.selection(nonce), Err(Error::Scope));
    }
    for offset in [10, 11, 64, 100, 144, 255] {
        let mut invalid = bytes;
        invalid[offset] ^= if offset == 10 { 3 } else { 1 };
        assert!(Request::decode(&invalid).is_err());
    }
    let invalid = LegacyBind { slot: 0, ..bind };
    assert_eq!(invalid.selection(47), Err(Error::Scope));
    assert_eq!(
        Request {
            command: Command::BindLegacyReadOnly(invalid),
            ..request
        }
        .encode(),
        Err(Error::Scope)
    );
    let ordinary = Request {
        command: Command::Bind(Bind {
            slot: 0,
            dataset: [0x84; 16],
            object: ObjectId {
                slot: 1,
                generation: 1,
            },
            target_process: 1,
            target_thread: 2,
            target_registered_token: 0,
            lease_epoch: 17,
            rights: Rights::ReadWrite,
        }),
        ..request
    };
    assert_eq!(ordinary.encode(), Err(Error::Scope));
    // A different backend ID cannot be smuggled into the readonly command.
    let mut foreign = bind;
    foreign.expected.identity.volume = [0x84; 16];
    assert_eq!(
        Request {
            command: Command::BindLegacyReadOnly(foreign),
            ..request
        }
        .encode(),
        Err(Error::Scope)
    );
}

#[test]
fn unavailable_is_not_empty_and_failure_metadata_or_forged_projection_is_rejected() {
    let request = inspect(legacy::Object::Notes);
    let unavailable = LegacyResponse {
        request_id: 47,
        lease_epoch: 17,
        status: Status::Unavailable,
        metadata: None,
    };
    let bytes = unavailable.encode().unwrap();
    assert_eq!(
        LegacyResponse::decode(&bytes).unwrap().matches(request),
        Ok(unavailable)
    );
    assert!(
        LegacyResponse {
            metadata: Some(metadata(legacy::Object::Notes)),
            ..unavailable
        }
        .encode()
        .is_err()
    );
    assert!(
        LegacyResponse {
            status: Status::Applied,
            ..unavailable
        }
        .encode()
        .is_err()
    );
    for offset in [64, 80, 88, 96, 104, 136] {
        let mut invalid = bytes;
        invalid[offset] = 1;
        assert!(LegacyResponse::decode(&invalid).is_err());
    }
    let mut source = metadata(legacy::Object::Notes);
    source.identity.projected_object.generation = 2;
    assert!(
        LegacyResponse {
            status: Status::Applied,
            metadata: Some(source),
            ..unavailable
        }
        .encode()
        .is_err()
    );
    source = metadata(legacy::Object::Notes);
    source.length = 225;
    assert!(
        LegacyResponse {
            status: Status::Applied,
            metadata: Some(source),
            ..unavailable
        }
        .encode()
        .is_err()
    );
    let mut invalid = request.encode().unwrap();
    invalid[64] ^= 1;
    assert_eq!(Request::decode(&invalid), Err(Error::Reserved));
}
