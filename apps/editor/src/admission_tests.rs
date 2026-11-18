use super::admission::{self, Error};
use ev_userspace_contract::{
    file_v2 as file,
    workspace::{Name, ObjectId},
};
use ev_workspace_client::{
    native::SelfFacts,
    selection::{Access, Selection, SelectionV2},
};

fn selection(access: Access) -> Selection {
    Selection {
        request_id: 11,
        receiver_process: 21,
        receiver_thread: 31,
        registered_incarnation: 41,
        lease_epoch: 51,
        dataset: [84; 16],
        object: ObjectId {
            slot: 2,
            generation: 9,
        },
        access,
        length: 4097,
        revision: 7,
        digest: [8; 32],
        name: Name::new("draft é.txt".as_bytes()).unwrap(),
    }
}
fn facts() -> SelfFacts {
    SelfFacts {
        process: 21,
        thread: 31,
        registered_incarnation: 41,
    }
}

#[test]
fn version2_admission_retains_exact_selected_metadata_and_loaded_feature_tuple() {
    for access in [Access::ReadOnly, Access::ReadWrite] {
        let selected = selection(access);
        let bytes = SelectionV2 {
            selection: selected,
            file: file::SUPPORT,
        }
        .encode()
        .unwrap();
        let before = bytes;
        let admitted = admission::decode(&bytes, 11, facts()).unwrap();
        assert_eq!(admitted.selection, selected);
        assert_eq!(admitted.file, Some(file::SUPPORT));
        assert_eq!(
            admitted.supports_staged_write(),
            access == Access::ReadWrite
        );
        assert_eq!(bytes, before);
        assert!(Selection::decode(&bytes).is_err());
    }
}

#[test]
fn old_server_missing_verify_and_old_workspace_selection_refuse_without_fallback() {
    for access in [Access::ReadOnly, Access::ReadWrite] {
        for support in [
            file::Support {
                major: 2,
                minor: 0,
                features: 0,
            },
            file::Support {
                major: 2,
                minor: 0,
                features: file::FEATURE_STAGED_VERIFY,
            },
            file::Support {
                major: 2,
                minor: 1,
                features: 0,
            },
            file::Support {
                major: 2,
                minor: 1,
                features: 2,
            },
        ] {
            let bytes = SelectionV2 {
                selection: selection(access),
                file: support,
            }
            .encode()
            .unwrap();
            assert_eq!(
                admission::decode(&bytes, 11, facts()),
                Err(Error::MissingStagedVerify)
            );
        }
        let old = selection(access).encode().unwrap();
        assert_eq!(
            admission::decode(&old, 11, facts()),
            Err(Error::OldWorkspaceSelection)
        );
    }
    assert!(!admission::supports_staged_verify(None));
    assert!(!admission::supports_staged_verify(Some(file::Support {
        major: 1,
        minor: 1,
        features: 1
    })));
}

#[test]
fn exact_original_file1_readonly_exception_never_becomes_a_write_destination() {
    for slot in [1, 2] {
        let selected = Selection {
            dataset: *b"EVRO-USERS-VOL01",
            object: ObjectId {
                slot,
                generation: 1,
            },
            ..selection(Access::ReadOnly)
        };
        let old = selected.encode().unwrap();
        let admitted = admission::decode(&old, 11, facts()).unwrap();
        assert_eq!(admitted.selection, selected);
        assert!(admitted.file.is_none());
        assert!(!admitted.supports_staged_write());
        for unsupported in [
            Selection {
                access: Access::ReadWrite,
                ..selected
            },
            Selection {
                dataset: [1; 16],
                ..selected
            },
            Selection {
                object: ObjectId {
                    slot: 3,
                    generation: 1,
                },
                ..selected
            },
            Selection {
                object: ObjectId {
                    slot,
                    generation: 2,
                },
                ..selected
            },
        ] {
            assert_eq!(
                admission::decode(&unsupported.encode().unwrap(), 11, facts()),
                Err(Error::OldWorkspaceSelection)
            );
        }
        assert_eq!(admission::decode(&old, 12, facts()), Err(Error::Receiver));
    }
}

#[test]
fn malformed_or_foreign_version2_cannot_reuse_the_legacy_decoder_or_receiver() {
    let bytes = SelectionV2 {
        selection: selection(Access::ReadWrite),
        file: file::SUPPORT,
    }
    .encode()
    .unwrap();
    for at in [66, 67, 216, 217, 220, 221, 222, 223, 232, 255] {
        let mut bad = bytes;
        bad[at] = 255;
        assert!(admission::decode(&bad, 11, facts()).is_err());
    }
    for length in [0, 7, 8, 215, 255] {
        assert!(admission::decode(&bytes[..length], 11, facts()).is_err());
    }
    let mut disguised = bytes;
    disguised[..8].copy_from_slice(b"EVF2SEL1");
    assert!(admission::decode(&disguised, 11, facts()).is_err());
    let mut unknown = bytes;
    unknown[..8].copy_from_slice(b"EVF2SEL9");
    assert!(admission::decode(&unknown, 11, facts()).is_err());
    for actual in [
        SelfFacts {
            process: 22,
            ..facts()
        },
        SelfFacts {
            thread: 32,
            ..facts()
        },
        SelfFacts {
            registered_incarnation: 42,
            ..facts()
        },
    ] {
        assert_eq!(admission::decode(&bytes, 11, actual), Err(Error::Receiver));
    }
    assert_eq!(admission::decode(&bytes, 12, facts()), Err(Error::Receiver));
}
