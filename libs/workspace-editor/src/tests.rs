extern crate std;
use super::*;
use std::vec;

fn stage_all(editor: &mut Editor<'_>, transfer: u64) -> Proposal {
    let proposal = editor.begin_save(1).unwrap();
    editor
        .begin_confirmed(transfer, proposal.length, proposal.digest)
        .unwrap();
    let mut frame = [0; CHUNK_BYTES];
    while editor.pending().unwrap().phase == Phase::Chunks {
        let c = editor.next_chunk(&mut frame).unwrap();
        assert_eq!(editor.next_chunk(&mut frame), Err(Error::Busy));
        editor.chunk_confirmed(transfer, c).unwrap();
    }
    editor.commit_request().unwrap();
    proposal
}
fn receipt(p: Proposal, transfer: u64) -> Receipt {
    Receipt {
        transfer,
        revision: p.revision,
        length: p.length,
        digest: p.digest,
    }
}

#[test]
fn save_as_preserves_source_bytes_selection_and_requires_verified_destination_readback() {
    let source = "owner α\nsecond line".as_bytes();
    let mut buffer = [0; 128];
    buffer[..source.len()].copy_from_slice(source);
    let mut editor = Editor::open(&mut buffer, source.len(), 8, false).unwrap();
    editor.select(5, 0).unwrap();
    assert_eq!(editor.retarget_for_save(3, false), Err(Error::ReadOnly));
    assert_eq!(editor.revision(), 8);
    assert_eq!(editor.bytes(), source);
    editor.retarget_for_save(3, true).unwrap();
    assert_eq!(editor.selection(), 0..5);
    assert_eq!(editor.status(), Status::Dirty);
    assert_eq!(editor.bytes(), source);
    let proposal = stage_all(&mut editor, 40);
    assert_eq!((proposal.base_revision, proposal.revision), (3, 4));
    editor.commit_confirmed(receipt(proposal, 40)).unwrap();
    assert_eq!(editor.status(), Status::Readback);
    assert_eq!(editor.finish_readback(), Err(Error::Busy));
    editor.readback(4, 0, source).unwrap();
    editor.finish_readback().unwrap();
    assert_eq!(editor.status(), Status::Saved);
    editor.retarget_for_save(0, true).unwrap();
    assert_eq!(editor.begin_save(1).unwrap().base_revision, 0);
}

#[test]
fn save_as_cannot_escape_uncertainty_or_reuse_old_pending_work() {
    let mut buffer = [0; 32];
    let mut editor = Editor::open(&mut buffer, 0, 7, true).unwrap();
    editor.replace(b"keep me").unwrap();
    let proposal = editor.begin_save(19).unwrap();
    assert_eq!(editor.retarget_for_save(0, true), Err(Error::Busy));
    assert_eq!(editor.pending().unwrap().proposal, proposal);
    editor.mark_uncertain();
    assert_eq!(editor.retarget_for_save(0, true), Err(Error::Uncertain));
    assert_eq!(editor.pending().unwrap().proposal, proposal);
    assert_eq!(editor.bytes(), b"keep me");
    assert_eq!(editor.revision(), 7);
}

#[test]
fn save_as_refuses_exhausted_revision_without_changing_source_state() {
    let mut buffer = [0; 32];
    let mut editor = Editor::open(&mut buffer, 0, 2, true).unwrap();
    editor.replace(b"keep").unwrap();
    editor.notify_revision(3).unwrap();
    assert_eq!(
        editor.retarget_for_save(u64::MAX - 1, true),
        Err(Error::Exhausted)
    );
    assert_eq!(editor.status(), Status::Conflict);
    assert_eq!(editor.revision(), 2);
    editor.retarget_for_save(0, true).unwrap();
    assert_eq!(editor.bytes(), b"keep");
    assert_eq!(editor.begin_save(1).unwrap().operation, 1);
}

#[test]
fn maximum_document_is_borrowed_and_saved_only_after_exact_streamed_readback() {
    let initial = vec![b'a'; MAX_DOCUMENT_BYTES];
    let mut buffer = initial.clone();
    let mut e = Editor::open(&mut buffer, initial.len(), 37, true).unwrap();
    e.select(MAX_DOCUMENT_BYTES, MAX_DOCUMENT_BYTES - 1)
        .unwrap();
    e.replace(b"z").unwrap();
    let expected = e.bytes().to_vec();
    let p = stage_all(&mut e, 71);
    assert_eq!(p.length, MAX_DOCUMENT_BYTES as u64);
    assert_eq!(e.revision(), 37);
    assert_eq!(e.status(), Status::Saving);
    e.commit_confirmed(receipt(p, 71)).unwrap();
    assert_eq!(e.status(), Status::Readback);
    assert_eq!(e.finish_readback(), Err(Error::Busy));
    for (i, bytes) in expected.chunks(CHUNK_BYTES).enumerate() {
        e.readback(38, (i * CHUNK_BYTES) as u64, bytes).unwrap();
        assert_ne!(e.status(), Status::Saved);
    }
    e.finish_readback().unwrap();
    assert_eq!(e.status(), Status::Saved);
    assert_eq!(e.revision(), 38);
    assert_eq!(e.bytes(), expected);
}
#[test]
fn exact_commit_receipt_is_insufficient_without_readback_and_mismatch_freezes_data() {
    for wrong in 0..4 {
        let mut buf = [0; 64];
        buf[..3].copy_from_slice(b"old");
        let mut e = Editor::open(&mut buf, 3, 4, true).unwrap();
        e.select_all();
        e.replace(b"new value").unwrap();
        let p = stage_all(&mut e, 7);
        let mut r = receipt(p, 7);
        match wrong {
            0 => r.transfer += 1,
            1 => r.revision += 1,
            2 => r.length -= 1,
            _ => r.digest[0] ^= 1,
        }
        assert_eq!(e.commit_confirmed(r), Err(Error::Mismatch));
        assert_eq!(e.status(), Status::Uncertain);
        assert_eq!(e.revision(), 4);
        assert_eq!(e.bytes(), b"new value");
        assert_eq!(e.replace(b"x"), Err(Error::Uncertain));
        assert_eq!(e.begin_save(2), Err(Error::Uncertain));
        assert_eq!(e.pending().unwrap().proposal, p);
    }
}
#[test]
fn wrong_stale_reordered_or_corrupt_readback_never_reports_saved() {
    for wrong in 0..4 {
        let mut buf = [0; 64];
        let mut e = Editor::open(&mut buf, 0, 0, true).unwrap();
        e.replace(b"data").unwrap();
        let p = stage_all(&mut e, 1);
        e.commit_confirmed(receipt(p, 1)).unwrap();
        let bad = match wrong {
            0 => e.readback(0, 0, b"data"),
            1 => e.readback(1, 1, b"data"),
            2 => e.readback(1, 0, b"dAta"),
            _ => e.readback(1, 0, b""),
        };
        assert_eq!(bad, Err(Error::Mismatch));
        assert_eq!(e.status(), Status::Uncertain);
        assert_eq!(e.revision(), 0);
    }
}
#[test]
fn partial_readback_and_interrupted_phase_preserve_exact_proposal() {
    for cut in [
        Phase::Begin,
        Phase::Chunks,
        Phase::CommitReady,
        Phase::CommitSent,
        Phase::Verify,
    ] {
        let mut buf = [0; 64];
        let mut e = Editor::open(&mut buf, 0, 0, true).unwrap();
        e.replace(b"retained").unwrap();
        let p = e.begin_save(8).unwrap();
        if cut != Phase::Begin {
            e.begin_confirmed(6, p.length, p.digest).unwrap();
        }
        if matches!(cut, Phase::CommitReady | Phase::CommitSent | Phase::Verify) {
            let mut f = [0; CHUNK_BYTES];
            let c = e.next_chunk(&mut f).unwrap();
            e.chunk_confirmed(6, c).unwrap();
        }
        if matches!(cut, Phase::CommitSent | Phase::Verify) {
            e.commit_request().unwrap();
        }
        if cut == Phase::Verify {
            e.commit_confirmed(receipt(p, 6)).unwrap();
            e.readback(1, 0, b"ret").unwrap();
        }
        e.mark_uncertain();
        assert_eq!(e.status(), Status::Uncertain);
        assert_eq!(e.pending().unwrap().proposal, p);
        assert_eq!(e.close(), Close::RecoveryRequired);
        assert_eq!(e.bytes(), b"retained");
        assert_eq!(e.rejected_before_delivery(), Err(Error::WrongPhase));
    }
}
#[test]
fn utf8_selection_navigation_capacity_and_rejected_bytes_are_atomic() {
    let mut buf = [0; 16];
    let text = "aé\n🙂z";
    buf[..text.len()].copy_from_slice(text.as_bytes());
    let mut e = Editor::open(&mut buf, text.len(), 3, true).unwrap();
    e.select(3, 3).unwrap();
    e.left(false);
    assert_eq!(e.cursor(), 1);
    e.right(false);
    assert_eq!(e.cursor(), 3);
    assert_eq!(e.select(2, 2), Err(Error::Bounds));
    let before = e.bytes().to_vec();
    assert_eq!(e.replace(&[0xff]), Err(Error::Text));
    assert_eq!(e.replace(&[0]), Err(Error::Text));
    assert_eq!(e.replace(&[b'x'; 16]), Err(Error::Bounds));
    assert_eq!(e.bytes(), before);
    e.select(3, 3).unwrap();
    e.vertical(true, false);
    assert_eq!(e.cursor(), 9);
    e.vertical(false, false);
    assert_eq!(e.cursor(), 3);
    e.line_home(false);
    assert_eq!(e.cursor(), 0);
    e.line_end(false);
    assert_eq!(e.cursor(), 3);
    e.backspace().unwrap();
    assert_eq!(e.text(), "a\n🙂z");
    assert_eq!(e.cursor(), 1);
}
#[test]
fn bounded_ranges_never_split_unicode_scalars_and_do_not_copy_a_full_document() {
    let mut buf = [0; 64];
    let text = "a🙂éz";
    buf[..text.len()].copy_from_slice(text.as_bytes());
    let e = Editor::open(&mut buf, text.len(), 0, false).unwrap();
    let mut out = [0; 4];
    assert_eq!(e.range(1, &mut out).unwrap(), 4);
    assert_eq!(&out, "🙂".as_bytes());
    let mut short = [9; 3];
    assert_eq!(e.range(1, &mut short).unwrap(), 0);
    assert_eq!(short, [9; 3]);
    assert_eq!(e.range(2, &mut out), Err(Error::Bounds));
}
#[test]
fn empty_document_has_real_commit_and_empty_readback_digest() {
    let mut buf = [b'x'; 8];
    let mut e = Editor::open(&mut buf, 1, 1, true).unwrap();
    e.select_all();
    e.replace(b"").unwrap();
    let p = stage_all(&mut e, 8);
    assert_eq!(p.length, 0);
    assert_eq!(p.digest, hash(b""));
    e.commit_confirmed(receipt(p, 8)).unwrap();
    assert_eq!(e.finish_readback(), Err(Error::Busy));
    assert_eq!(e.status(), Status::Readback);
    e.readback(2, 0, b"").unwrap();
    e.finish_readback().unwrap();
    assert_eq!(e.status(), Status::Saved);
    assert_eq!(e.revision(), 2);
}
#[test]
fn readonly_conflict_pre_delivery_and_revoke_do_not_amplify_access_or_retry_uncertainty() {
    let mut buf = [0; 64];
    {
        let mut e = Editor::open(&mut buf, 0, 4, false).unwrap();
        assert_eq!(e.replace(b"x"), Err(Error::ReadOnly));
        assert_eq!(e.begin_save(1), Err(Error::ReadOnly));
    }
    {
        let mut e = Editor::open(&mut buf, 0, 4, true).unwrap();
        e.replace(b"dirty").unwrap();
        e.notify_revision(5).unwrap();
        assert_eq!(e.begin_save(1), Err(Error::Conflict));
        assert_eq!(e.close(), Close::ConfirmDiscard);
    }
    let mut e = Editor::open(&mut buf, 0, 4, true).unwrap();
    e.replace(b"data").unwrap();
    e.begin_save(1).unwrap();
    e.rejected_before_delivery().unwrap();
    assert_eq!(e.status(), Status::Dirty);
    assert_eq!(e.begin_save(1), Err(Error::Exhausted));
    let p = e.begin_save(2).unwrap();
    e.revoke_edit();
    assert_eq!(e.status(), Status::Uncertain);
    assert_eq!(e.pending().unwrap().proposal, p);
    assert_eq!(e.replace(b"z"), Err(Error::Uncertain));
}
#[test]
fn foreign_chunk_ack_and_replay_do_not_advance_or_unfreeze_a_save() {
    let mut buf = vec![0; CHUNK_BYTES + 16];
    let mut e = Editor::open(&mut buf, 0, 0, true).unwrap();
    let data = vec![b'z'; CHUNK_BYTES + 1];
    e.replace(&data).unwrap();
    let p = e.begin_save(1).unwrap();
    e.begin_confirmed(6, p.length, p.digest).unwrap();
    let mut out = [0; CHUNK_BYTES];
    let c = e.next_chunk(&mut out).unwrap();
    assert_eq!(e.chunk_confirmed(7, c), Err(Error::Mismatch));
    assert_eq!(e.pending().unwrap().staged, 0);
    assert_eq!(e.status(), Status::Uncertain);
    assert_eq!(e.chunk_confirmed(6, c), Err(Error::WrongPhase));
}
#[test]
fn open_refuses_unsupported_without_mutating_original_and_engine_is_small() {
    let mut buf = [0xff; 8];
    assert!(matches!(
        Editor::open(&mut buf, 8, 0, true),
        Err(Error::Text)
    ));
    assert_eq!(buf, [0xff; 8]);
    assert!(core::mem::size_of::<Editor<'static>>() < 1024);
    assert!(core::mem::size_of::<Pending>() < 512);
}

#[test]
fn exhausted_edit_sequence_preserves_selection_but_can_save_the_last_valid_edit() {
    let mut bytes = [0; 32];
    let mut e = Editor::open(&mut bytes, 0, 3, true).unwrap();
    e.edit_sequence = u64::MAX - 1;
    e.replace(b"last edit").unwrap();
    let selected = (e.cursor(), e.anchor());
    assert_eq!(e.backspace(), Err(Error::Exhausted));
    assert_eq!((e.cursor(), e.anchor()), selected);
    assert_eq!(e.bytes(), b"last edit");
    let p = stage_all(&mut e, 3);
    e.commit_confirmed(receipt(p, 3)).unwrap();
    e.readback(4, 0, b"last edit").unwrap();
    e.finish_readback().unwrap();
    assert_eq!(e.status(), Status::Saved);
}

#[test]
fn begin_refusal_requires_exact_proposal_and_cannot_clear_any_accepted_stage_or_uncertainty() {
    for phase in [
        Phase::Begin,
        Phase::Chunks,
        Phase::CommitReady,
        Phase::CommitSent,
        Phase::Verify,
        Phase::Uncertain,
    ] {
        let mut bytes = [0; 64];
        let mut editor = Editor::open(&mut bytes, 0, 3, true).unwrap();
        editor.replace(b"frozen bytes").unwrap();
        let proposal = editor.begin_save(7).unwrap();
        if phase != Phase::Begin && phase != Phase::Uncertain {
            editor
                .begin_confirmed(19, proposal.length, proposal.digest)
                .unwrap();
        }
        if matches!(
            phase,
            Phase::CommitReady | Phase::CommitSent | Phase::Verify
        ) {
            let mut out = [0; CHUNK_BYTES];
            let chunk = editor.next_chunk(&mut out).unwrap();
            editor.chunk_confirmed(19, chunk).unwrap();
        }
        if matches!(phase, Phase::CommitSent | Phase::Verify) {
            editor.commit_request().unwrap();
        }
        if phase == Phase::Verify {
            editor.commit_confirmed(receipt(proposal, 19)).unwrap();
        }
        if phase == Phase::Uncertain {
            editor.mark_uncertain();
        }
        let before = editor.pending().unwrap();
        let wrong = Proposal {
            operation: 8,
            ..proposal
        };
        assert!(editor.begin_refused(wrong, BeginRefusal::NoSpace).is_err());
        assert_eq!(editor.pending(), Some(before));
        if phase != Phase::Begin {
            assert_eq!(
                editor.begin_refused(proposal, BeginRefusal::Conflict),
                Err(Error::WrongPhase)
            );
            assert_eq!(editor.pending(), Some(before));
            assert_eq!(editor.close(), Close::RecoveryRequired);
        } else {
            editor
                .begin_refused(proposal, BeginRefusal::NoSpace)
                .unwrap();
            assert_eq!(
                editor.begin_refused(proposal, BeginRefusal::NoSpace),
                Err(Error::WrongPhase)
            );
        }
        assert_eq!(editor.bytes(), b"frozen bytes");
        assert_eq!(editor.revision(), 3);
    }
}
