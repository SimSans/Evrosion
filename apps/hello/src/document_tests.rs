use super::*;

fn editor(text: &str, counter: u64) -> Editor {
    let mut e = Editor::new();
    e.open(
        Choice::Notes,
        Access::Edit,
        counter,
        &Payload::new(text.as_bytes()).unwrap(),
    )
    .unwrap();
    e
}
fn valid(e: &Editor) {
    let s = e.snapshot();
    assert_eq!(Snapshot::decode(&s.encode().unwrap(), 0), Ok(s));
}
fn ack(e: &mut Editor, proposal: Proposal) {
    e.acknowledge(Response::Replaced {
        counter: proposal.counter,
        replayed: false,
    })
    .unwrap();
}

#[test]
fn selected_document_save_needs_commit_and_exact_readback_before_saved() {
    let mut e = editor("old", 0);
    e.insert(" edit").unwrap();
    let p = e.prepare_save().unwrap();
    assert_eq!(p.counter, 1);
    assert_eq!(
        p.request(),
        Request::Replace {
            counter: 1,
            payload: Payload::new(b"old edit").unwrap()
        }
    );
    assert_eq!(e.snapshot().state, State::Saving);
    valid(&e);
    assert_eq!(
        e.readback(1, &Payload::new(b"old edit").unwrap()),
        Err(Error::State)
    );
    ack(&mut e, p);
    assert_eq!(e.snapshot().state, State::Readback);
    valid(&e);
    e.readback(p.counter, &Payload::new(p.text.as_bytes()).unwrap())
        .unwrap();
    assert_eq!(e.snapshot().state, State::Saved);
    assert_eq!(e.snapshot().revision, 1);
    assert!(!e.snapshot().dirty);
    valid(&e);
    e.closed().unwrap();
    valid(&e);
    e.open(
        Choice::Notes,
        Access::Edit,
        1,
        &Payload::new(b"old edit").unwrap(),
    )
    .unwrap();
    assert_eq!(e.snapshot().text.as_bytes(), b"old edit");
    valid(&e);
}

#[test]
fn edits_during_save_are_preserved_and_remain_dirty_after_older_proposal_commits() {
    let mut e = editor("A", 7);
    e.insert("B").unwrap();
    let p = e.prepare_save().unwrap();
    e.insert("C").unwrap();
    assert_eq!(e.pending(), Some(p));
    assert_eq!(e.snapshot().text.as_bytes(), b"ABC");
    valid(&e);
    ack(&mut e, p);
    e.readback(8, &Payload::new(b"AB").unwrap()).unwrap();
    assert_eq!(e.snapshot().state, State::Dirty);
    assert_eq!(e.snapshot().text.as_bytes(), b"ABC");
    valid(&e);
    assert_eq!(e.prepare_save().unwrap().counter, 9);
}

#[test]
fn uncertain_completion_retains_exact_proposal_and_blocks_retry_navigation_or_frame_reuse() {
    for code in [
        ErrorCode::Io,
        ErrorCode::NeedsRecovery,
        ErrorCode::Conflict,
        ErrorCode::Denied,
    ] {
        let mut e = editor("A", 3);
        e.insert("B").unwrap();
        let p = e.prepare_save().unwrap();
        assert_eq!(e.acknowledge(Response::Error { code }), Err(Error::Reply));
        assert_eq!(e.snapshot().state, State::Unavailable);
        assert_eq!(e.pending(), Some(p));
        assert_eq!(e.prepare_save(), Err(Error::Uncertain));
        assert_eq!(e.insert("C"), Err(Error::Uncertain));
        assert_eq!(e.navigate(Navigation::Close), Err(Error::Busy));
        assert_eq!(e.closed(), Err(Error::State));
        valid(&e);
    }
}

#[test]
fn wrong_commit_revision_or_readback_can_never_publish_saved() {
    let mut e = editor("A", 3);
    e.insert("B").unwrap();
    let p = e.prepare_save().unwrap();
    assert_eq!(
        e.acknowledge(Response::Replaced {
            counter: 3,
            replayed: false
        }),
        Err(Error::Reply)
    );
    assert_eq!(e.snapshot().state, State::Unavailable);
    assert_eq!(e.pending(), Some(p));
    valid(&e);
    for (counter, text) in [(3, b"AB".as_slice()), (4, b"OTHER"), (5, b"AB")] {
        let mut e = editor("A", 3);
        e.insert("B").unwrap();
        let p = e.prepare_save().unwrap();
        ack(&mut e, p);
        assert_eq!(
            e.readback(counter, &Payload::new(text).unwrap()),
            Err(Error::Reply)
        );
        assert_eq!(e.snapshot().state, State::Unavailable);
        assert_eq!(e.pending(), Some(p));
        valid(&e);
    }
}

#[test]
fn utf8_selection_insert_backspace_and_capacity_refusal_preserve_document() {
    let mut e = editor("Aé🙂Z", 1);
    e.move_cursor(1, false).unwrap();
    e.move_cursor(7, true).unwrap();
    assert_eq!(e.move_cursor(2, true), Err(Error::Position));
    e.insert("新").unwrap();
    assert_eq!(e.snapshot().text.as_str(), "A新Z");
    valid(&e);
    e.backspace().unwrap();
    assert_eq!(e.snapshot().text.as_str(), "AZ");
    valid(&e);
    e.move_cursor(2, false).unwrap();
    e.insert("\n\t").unwrap();
    valid(&e);
    let before = e.snapshot();
    assert_eq!(e.insert("\0"), Err(Error::Text));
    assert_eq!(e.snapshot(), before);
    assert_eq!(
        e.insert(core::str::from_utf8(&[b'x'; 224]).unwrap()),
        Err(Error::Full)
    );
    assert_eq!(e.snapshot().text, before.text);
    assert_eq!(e.snapshot().cursor, before.cursor);
    valid(&e);
}

#[test]
fn full_file_is_editable_without_truncation_and_revision_never_wraps() {
    let mut e = editor(core::str::from_utf8(&[b'x'; 224]).unwrap(), u64::MAX - 1);
    assert_eq!(e.insert("y"), Err(Error::Full));
    assert_eq!(e.snapshot().text.len(), 224);
    e.backspace().unwrap();
    e.insert("y").unwrap();
    assert_eq!(e.prepare_save(), Err(Error::Exhausted));
    assert_eq!(e.snapshot().revision, u64::MAX - 1);
    assert_eq!(e.snapshot().state, State::Dirty);
    valid(&e);
}

#[test]
fn read_only_unopened_and_unsupported_documents_do_not_turn_into_writable_empty_files() {
    let mut e = Editor::new();
    assert_eq!(e.insert("x"), Err(Error::ReadOnly));
    valid(&e);
    e.open(
        Choice::Private,
        Access::Read,
        0,
        &Payload::new(b"secret").unwrap(),
    )
    .unwrap();
    assert_eq!(e.insert("x"), Err(Error::ReadOnly));
    assert_eq!(e.prepare_save(), Err(Error::ReadOnly));
    valid(&e);
    let before = e.snapshot();
    assert_eq!(
        e.open(
            Choice::Notes,
            Access::Edit,
            0,
            &Payload::new(b"\xff").unwrap()
        ),
        Err(Error::Text)
    );
    assert_eq!(e.snapshot(), before);
    e.closed().unwrap();
    assert_eq!(
        e.open(
            Choice::Notes,
            Access::Edit,
            u64::MAX,
            &Payload::new(b"x").unwrap()
        ),
        Err(Error::Reply)
    );
    valid(&e);
}

#[test]
fn failed_initial_open_keeps_a_closed_semantic_view_without_fabricating_a_document() {
    let mut e = Editor::new();
    e.selecting().unwrap();
    e.failed(Feedback::Storage);
    assert_eq!(e.snapshot().state, State::Closed);
    assert_eq!(e.snapshot().choice, Choice::None);
    assert_eq!(e.snapshot().access, Access::None);
    assert_eq!(e.snapshot().feedback, Feedback::Storage);
    assert!(e.pending().is_none());
    valid(&e);
}

#[test]
fn dirty_open_close_and_cancel_preserve_edits_until_explicit_discard() {
    for next in [Navigation::Open, Navigation::Close] {
        let mut e = editor("saved", 2);
        e.insert(" changes").unwrap();
        assert_eq!(e.navigate(next), Ok(Navigate::ConfirmDiscard));
        valid(&e);
        assert_eq!(e.insert("x"), Err(Error::State));
        assert_eq!(e.focus(Focus::Text), Err(Error::State));
        e.keep_editing().unwrap();
        assert_eq!(e.snapshot().text.as_bytes(), b"saved changes");
        valid(&e);
        e.navigate(next).unwrap();
        assert_eq!(e.discard(), Ok(next));
        assert_eq!(e.snapshot().text.as_bytes(), b"saved");
        valid(&e);
        if next == Navigation::Open {
            e.selecting().unwrap();
            e.cancel_selection();
            assert_eq!(e.snapshot().text.as_bytes(), b"saved");
        } else {
            e.closed().unwrap();
            assert_eq!(e.snapshot().state, State::Closed);
        }
        valid(&e);
    }
}

#[test]
fn keyboard_selection_and_caret_preserve_utf8_boundaries() {
    let mut e = Editor::new();
    e.open(
        Choice::Notes,
        Access::Edit,
        4,
        &Payload::new("aé界z".as_bytes()).unwrap(),
    )
    .unwrap();
    e.horizontal(false).unwrap();
    assert_eq!(e.snapshot().cursor, 6);
    e.horizontal(false).unwrap();
    assert_eq!(e.snapshot().cursor, 3);
    e.horizontal(true).unwrap();
    assert_eq!(e.snapshot().cursor, 6);
    e.select_all().unwrap();
    assert_eq!((e.snapshot().anchor, e.snapshot().cursor), (0, 7));
    e.insert("new").unwrap();
    assert_eq!(e.snapshot().text.as_str(), "new");
    e.snapshot().valid().unwrap();
}

#[test]
fn readonly_open_control_and_selection_refusal_preserve_confirmed_bytes() {
    let mut e = Editor::new();
    e.focus(Focus::OpenRead).unwrap();
    e.snapshot().valid().unwrap();
    e.selecting().unwrap();
    e.snapshot().valid().unwrap();
    e.selection_refused(Feedback::Denied);
    assert_eq!(e.snapshot().state, State::Closed);
    e.open(
        Choice::Notes,
        Access::Read,
        7,
        &Payload::new(b"keep").unwrap(),
    )
    .unwrap();
    assert_eq!(e.insert("bad"), Err(Error::ReadOnly));
    assert_eq!(e.prepare_save(), Err(Error::ReadOnly));
    e.focus(Focus::OpenRead).unwrap();
    e.selecting().unwrap();
    e.selection_refused(Feedback::Denied);
    assert_eq!(e.snapshot().state, State::Saved);
    assert_eq!(e.snapshot().text.as_str(), "keep");
    assert_eq!(e.snapshot().revision, 7);
    e.snapshot().valid().unwrap();
}
