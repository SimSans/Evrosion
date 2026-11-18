use super::*;
fn status(confirm: bool) -> Presentation {
    Presentation {
        revision: 7,
        status: Status {
            connection: Connection::Online,
            update: if confirm {
                Update::Selected
            } else {
                Update::Ready
            },
            app_running: true,
            confirm,
            candidate_available: true,
        },
    }
}
fn barrier(sequence: u32, held: u8) -> SessionBarrierReply {
    SessionBarrierReply {
        sequence,
        enter: ev_input::EnterState::default(),
        pointer: ev_input::PointerState { held, released: 7 },
    }
}
fn key(sequence: u32, key: Key, ready: bool) -> KeyEvent {
    KeyEvent {
        sequence,
        key,
        release_known: key == Key::Enter,
        approval_ready: key == Key::Enter && ready,
    }
}
fn pointer(sequence: u32, buttons: u8) -> PointerEvent {
    PointerEvent {
        sequence,
        dx: 0,
        dy: 0,
        buttons,
    }
}
#[test]
fn old_or_held_input_cannot_confirm_before_actual_present_and_barrier() {
    let mut p = Policy::new(status(true), 10).unwrap();
    assert!(p.barrier(10, barrier(1, 0)).is_err());
    assert_eq!(p.key(key(2, Key::Enter, true)).unwrap(), None);
    assert!(p.displayed(9).is_err());
    p.displayed(10).unwrap();
    p.barrier(10, barrier(3, 1)).unwrap();
    assert!(p.barrier(10, barrier(3, 0)).is_err());
    assert_eq!(p.pointer(pointer(4, 1), 160, 170).unwrap(), None);
    assert_eq!(p.pointer(pointer(5, 0), 160, 170).unwrap(), None);
    let request = p.pointer(pointer(6, 1), 160, 170).unwrap().unwrap();
    assert_eq!(request.operation, Operation::Confirm);
    assert_eq!(request.revision, 7);
    assert_eq!(p.pointer(pointer(7, 1), 160, 170).unwrap(), None);
}
#[test]
fn confirmation_defaults_to_cancel_and_never_infers_that_note_was_saved() {
    let mut p = Policy::new(status(true), 20).unwrap();
    assert_eq!(p.view().focus, Action::Cancel);
    p.displayed(20).unwrap();
    p.barrier(20, barrier(1, 0)).unwrap();
    assert_eq!(
        p.key(key(2, Key::Enter, true)).unwrap().unwrap().operation,
        Operation::Cancel
    );
    assert_eq!(p.key(key(3, Key::Enter, true)).unwrap(), None);
}
#[test]
fn request_codec_is_new_versioned_data_and_rejects_reserved_or_replayed_shape() {
    for operation in [
        Operation::Open,
        Operation::Fetch,
        Operation::SelectNext,
        Operation::Confirm,
        Operation::Cancel,
        Operation::Back,
        Operation::Restart,
    ] {
        let r = Request {
            operation,
            revision: 8,
        };
        assert_eq!(Request::decode(r.encode().unwrap()), Ok(r));
    }
    assert!(
        Request {
            operation: Operation::Fetch,
            revision: 0
        }
        .encode()
        .is_err()
    );
    let b = Request {
        operation: Operation::Fetch,
        revision: 4,
    }
    .encode()
    .unwrap();
    for bad in [
        [b'K', b[1], b[2], b[3], b[4], b[5], b[6], b[7]],
        [b[0], 2, b[2], b[3], b[4], b[5], b[6], b[7]],
        [b[0], b[1], b[2], 1, b[4], b[5], b[6], b[7]],
    ] {
        assert!(Request::decode(bad).is_err());
    }
}
#[test]
fn presentation_codec_preserves_exact_revision_and_rejects_false_confirmation() {
    for confirm in [false, true] {
        let p = status(confirm);
        assert_eq!(Presentation::decode(p.word().unwrap()), Ok(p));
    }
    assert!(Presentation::decode(status(false).word().unwrap() | 3).is_err());
    let mut p = status(true);
    p.status.update = Update::Ready;
    assert!(p.word().is_err());
    let mut p = status(false);
    p.revision = 0x007f_ffff;
    assert!(p.word().is_err());
}
#[test]
fn offline_cached_update_can_activate_but_network_fetch_is_disabled() {
    let mut s = status(false);
    s.status.connection = Connection::Offline;
    let mut p = Policy::new(s, 1).unwrap();
    p.displayed(1).unwrap();
    p.barrier(1, barrier(1, 0)).unwrap();
    assert_eq!(p.pointer(pointer(2, 1), 120, 170).unwrap(), None);
    p.pointer(pointer(3, 0), 220, 170).unwrap();
    assert_eq!(
        p.pointer(pointer(4, 1), 220, 170)
            .unwrap()
            .unwrap()
            .operation,
        Operation::SelectNext
    );
}

#[test]
fn setup_required_code9_allows_only_the_applicable_explicit_preparation_once() {
    for candidate_available in [false, true] {
        let mut view = status(false);
        view.status.update = Update::SetupRequired;
        view.status.app_running = false;
        view.status.candidate_available = candidate_available;
        assert_eq!((view.word().unwrap() >> 2) & 15, 9);
        assert_eq!(Presentation::decode(view.word().unwrap()), Ok(view));
        for code in 10..=15 {
            assert!(Presentation::decode((view.word().unwrap() & !(15 << 2)) | code << 2).is_err());
        }
        assert_eq!(
            connection::enabled(view.status, Action::Fetch),
            !candidate_available
        );
        assert_eq!(
            connection::enabled(view.status, Action::SelectNext),
            candidate_available
        );
        assert!(!connection::enabled(view.status, Action::Restart));
        let mut p = Policy::new(view, 9).unwrap();
        assert_eq!(p.view().focus, Action::Back);
        p.displayed(9).unwrap();
        p.barrier(9, barrier(1, 0)).unwrap();
        assert_eq!(p.key(key(2, Key::Tab, false)).unwrap(), None);
        let operation = if candidate_available {
            Operation::SelectNext
        } else {
            Operation::Fetch
        };
        assert_eq!(
            p.key(key(3, Key::Enter, true)).unwrap().unwrap().operation,
            operation
        );
        assert_eq!(p.key(key(4, Key::Enter, true)).unwrap(), None);
        assert_eq!(p.key(key(5, Key::Tab, false)).unwrap(), None);
    }
}
