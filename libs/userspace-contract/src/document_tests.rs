use super::*;

fn view() -> Snapshot {
    Snapshot {
        state: State::Saved,
        focus: Focus::Text,
        choice: Choice::Notes,
        access: Access::Edit,
        text: Text::new("Aé🙂\n\tZ".as_bytes()).unwrap(),
        cursor: 3,
        anchor: 1,
        revision: 42,
        feedback: Feedback::None,
        dirty: false,
    }
}

#[test]
fn full_text_selection_and_semantics_have_a_canonical_foreign_language_frame() {
    let snapshot = view();
    let bytes = snapshot.encode().unwrap();
    assert_eq!(&bytes[..10], b"EVDOCV01\x01\0");
    assert_eq!(&bytes[20..28], &42u64.to_le_bytes());
    assert_eq!(
        &bytes[32..32 + snapshot.text.len()],
        snapshot.text.as_bytes()
    );
    assert_eq!(Snapshot::decode(&bytes, 0), Ok(snapshot));
    assert_eq!(snapshot.focus.label(), "Document text");
    assert_eq!(snapshot.focus.role(), "text_box");
    assert_eq!(Choice::Notes.label(), "Notes.txt");
    assert!(!snapshot.can_save());
    assert!(snapshot.text_editable());
    let full = Snapshot {
        text: Text::new(&[b'x'; TEXT_BYTES]).unwrap(),
        cursor: 224,
        anchor: 224,
        ..snapshot
    };
    assert_eq!(Snapshot::decode(&full.encode().unwrap(), 0), Ok(full));
}

#[test]
fn text_rejects_invalid_utf8_controls_and_capacity_without_lossy_conversion() {
    for bytes in [
        b"\0".as_slice(),
        b"a\x7fb",
        b"\xc0\xaf",
        b"\xf0\x9f\x99",
        b"\x1b",
    ] {
        assert_eq!(Text::new(bytes), Err(Error::Text));
    }
    assert_eq!(Text::new(&[b'x'; TEXT_BYTES + 1]), Err(Error::Length));
    assert!(Text::new("é🙂\t\r\n".as_bytes()).is_ok());
    assert!(Text::empty().is_empty());
}

#[test]
fn wire_rejects_bad_extent_reserved_tail_version_tags_and_capabilities() {
    let bytes = view().encode().unwrap();
    for length in [0, 1, 31, 32, 255] {
        assert_eq!(Snapshot::decode(&bytes[..length], 0), Err(Error::Length));
    }
    assert_eq!(Snapshot::decode(&[0; 257], 0), Err(Error::Length));
    for count in [1, usize::MAX] {
        assert_eq!(Snapshot::decode(&bytes, count), Err(Error::CapabilityCount));
    }
    for (index, value, error) in [
        (0, 0, Error::Magic),
        (8, 2, Error::Version),
        (10, 255, Error::Tag),
        (11, 0, Error::Tag),
        (12, 9, Error::Tag),
        (13, 3, Error::Tag),
        (28, 10, Error::Tag),
        (29, 2, Error::Reserved),
        (30, 1, Error::Reserved),
        (31, 1, Error::Reserved),
        (255, 1, Error::Reserved),
    ] {
        let mut malformed = bytes;
        malformed[index] = value;
        assert_eq!(
            Snapshot::decode(&malformed, 0),
            Err(error),
            "offset {index}"
        );
    }
    let mut malformed = bytes;
    malformed[14..16].copy_from_slice(&225u16.to_le_bytes());
    assert_eq!(Snapshot::decode(&malformed, 0), Err(Error::Length));
    malformed = bytes;
    malformed[20..28].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(Snapshot::decode(&malformed, 0), Err(Error::Revision));
}

#[test]
fn semantic_state_refuses_false_saved_split_codepoints_and_dirty_read_only_views() {
    let snapshot = view();
    for changed in [
        Snapshot {
            cursor: 2,
            ..snapshot
        },
        Snapshot {
            anchor: 5,
            ..snapshot
        },
        Snapshot {
            cursor: 225,
            ..snapshot
        },
    ] {
        assert_eq!(changed.encode(), Err(Error::Position));
    }
    for changed in [
        Snapshot {
            dirty: true,
            ..snapshot
        },
        Snapshot {
            choice: Choice::None,
            ..snapshot
        },
        Snapshot {
            access: Access::None,
            ..snapshot
        },
        Snapshot {
            state: State::Closed,
            ..snapshot
        },
        Snapshot {
            focus: Focus::Discard,
            ..snapshot
        },
        Snapshot {
            state: State::Dirty,
            ..snapshot
        },
        Snapshot {
            state: State::Dirty,
            access: Access::Read,
            dirty: true,
            ..snapshot
        },
    ] {
        assert_eq!(changed.encode(), Err(Error::State));
    }
    let dirty = Snapshot {
        state: State::Dirty,
        dirty: true,
        ..snapshot
    };
    assert!(dirty.can_save());
    let prompt = Snapshot {
        state: State::ConfirmDiscard,
        focus: Focus::KeepEditing,
        ..dirty
    };
    assert!(!prompt.can_save());
    assert!(!prompt.text_editable());
    assert_eq!(Snapshot::decode(&prompt.encode().unwrap(), 0), Ok(prompt));
}

#[test]
fn bounded_arbitrary_snapshots_decode_totally_and_success_is_canonical() {
    let mut random = 0x7a6e_129fu32;
    for _ in 0..4096 {
        let mut bytes = [0; FRAME_BYTES];
        for byte in &mut bytes {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            *byte = random as u8;
        }
        if let Ok(snapshot) = Snapshot::decode(&bytes, 0) {
            assert_eq!(snapshot.encode().unwrap(), bytes);
        }
    }
    let good = view().encode().unwrap();
    for index in 0..FRAME_BYTES {
        for bit in 0..8 {
            let mut bytes = good;
            bytes[index] ^= 1 << bit;
            if let Ok(snapshot) = Snapshot::decode(&bytes, 0) {
                assert_eq!(snapshot.encode().unwrap(), bytes);
            }
        }
    }
}
