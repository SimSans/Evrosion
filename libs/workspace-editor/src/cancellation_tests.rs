extern crate std;
use super::*;

fn staged(editor: &mut Editor<'_>) -> Proposal {
    let proposal = editor.begin_save(1).unwrap();
    editor
        .begin_confirmed(17, proposal.length, proposal.digest)
        .unwrap();
    proposal
}

#[test]
fn completed_abort_keeps_bytes_caret_base_and_requires_a_new_explicit_save_nonce() {
    let mut bytes = [0; 64];
    let mut editor = Editor::open(&mut bytes, 0, 7, true).unwrap();
    editor.replace(b"keep my changes").unwrap();
    editor.select(5, 1).unwrap();
    let selection = (editor.cursor(), editor.anchor(), editor.edit_sequence());
    let proposal = staged(&mut editor);
    assert!(editor.can_cancel_save());
    editor.cancel_save(proposal).unwrap();
    assert_eq!(editor.cancel_save(proposal), Err(Error::WrongPhase));
    let request = editor.abort_request(2).unwrap();
    let accepted = editor.pending().unwrap();
    assert_eq!(
        request,
        AbortRequest {
            operation: 2,
            transfer: 17,
            base_revision: 7
        }
    );
    assert_eq!(editor.abort_request(3), Err(Error::WrongPhase));
    assert_eq!(editor.pending(), Some(accepted));
    assert_eq!(editor.close(), Close::RecoveryRequired);
    assert_eq!(editor.replace(b"lost"), Err(Error::Busy));
    editor
        .abort_confirmed(AbortReceipt {
            operation: 2,
            transfer: 17,
            revision: 7,
        })
        .unwrap();
    assert_eq!(editor.status(), Status::Dirty);
    assert_eq!(editor.close(), Close::ConfirmDiscard);
    assert_eq!(editor.cancelled_save(), Some(proposal));
    assert_eq!(editor.bytes(), b"keep my changes");
    assert_eq!(editor.revision(), 7);
    assert_eq!(
        (editor.cursor(), editor.anchor(), editor.edit_sequence()),
        selection
    );
    assert!(editor.pending().is_none());
    assert_eq!(editor.begin_save(2), Err(Error::Exhausted));
    assert_eq!(editor.begin_save(3).unwrap().operation, 3);
    assert!(editor.cancelled_save().is_none());
}

#[test]
fn cancellation_never_drops_inflight_chunks_commit_or_unknown_work() {
    for phase in [
        Phase::Begin,
        Phase::Chunks,
        Phase::CommitSent,
        Phase::Verify,
        Phase::Uncertain,
    ] {
        let mut bytes = [0; 64];
        let mut editor = Editor::open(&mut bytes, 0, 7, true).unwrap();
        editor.replace(b"retained").unwrap();
        let proposal = editor.begin_save(1).unwrap();
        if phase != Phase::Begin {
            editor
                .begin_confirmed(17, proposal.length, proposal.digest)
                .unwrap();
            let mut out = [0; CHUNK_BYTES];
            let chunk = editor.next_chunk(&mut out).unwrap();
            if phase != Phase::Chunks {
                editor.chunk_confirmed(17, chunk).unwrap();
            }
        }
        if matches!(phase, Phase::CommitSent | Phase::Verify) {
            editor.commit_request().unwrap();
        }
        if phase == Phase::Verify {
            editor
                .commit_confirmed(Receipt {
                    transfer: 17,
                    revision: 8,
                    length: proposal.length,
                    digest: proposal.digest,
                })
                .unwrap();
        }
        if phase == Phase::Uncertain {
            editor.mark_uncertain();
        }
        let before = editor.pending().unwrap();
        assert!(!editor.can_cancel_save());
        assert_eq!(editor.cancel_save(proposal), Err(Error::WrongPhase));
        assert_eq!(editor.pending(), Some(before));
        assert!(editor.cancelled_save().is_none());
        assert_eq!(editor.bytes(), b"retained");
        assert_eq!(editor.close(), Close::RecoveryRequired);
    }
}

#[test]
fn abort_identity_mismatch_fences_the_exact_stage_and_cannot_retry_or_retarget() {
    for receipt in [
        AbortReceipt {
            operation: 3,
            transfer: 17,
            revision: 7,
        },
        AbortReceipt {
            operation: 2,
            transfer: 18,
            revision: 7,
        },
        AbortReceipt {
            operation: 2,
            transfer: 17,
            revision: 8,
        },
    ] {
        let mut bytes = [0; 64];
        let mut editor = Editor::open(&mut bytes, 0, 7, true).unwrap();
        editor.replace(b"frozen").unwrap();
        let proposal = staged(&mut editor);
        assert_eq!(
            editor.cancel_save(Proposal {
                operation: 9,
                ..proposal
            }),
            Err(Error::Mismatch)
        );
        assert!(editor.can_cancel_save());
        editor.cancel_save(proposal).unwrap();
        editor.abort_request(2).unwrap();
        let before = editor.pending().unwrap();
        assert_eq!(editor.abort_confirmed(receipt), Err(Error::Mismatch));
        let retained = editor.pending().unwrap();
        assert_eq!(retained.proposal, before.proposal);
        assert_eq!(retained.transfer, before.transfer);
        assert_eq!(retained.abort_operation, Some(2));
        assert_eq!(retained.phase, Phase::Uncertain);
        assert_eq!(editor.abort_request(3), Err(Error::WrongPhase));
        assert_eq!(editor.begin_save(3), Err(Error::Uncertain));
        assert_eq!(editor.retarget_for_save(0, true), Err(Error::Uncertain));
        assert_eq!(editor.close(), Close::RecoveryRequired);
        assert!(editor.cancelled_save().is_none());
        assert_eq!(editor.bytes(), b"frozen");
    }
}
