//! Real State/one-window/Store composition. The media and clock are models;
//! policy refusal never becomes update authority or a transport ACK.
use super::*;
use crate::{native_acquisition as acq, native_update as update};
use ev_app_registry::note_data::{BYTES, NoteDataEnvelope};
use ev_content_store::{Arena, TransferCut};
use ev_userspace_contract::session_note::{Operation, Outcome, Request as NoteRequest};

type Engine = update::Update<native_plan::storage::content::OwnedBackend<Link, Buffer>>;

fn media() -> Rc<RefCell<Media>> {
    let media = composed_disk();
    {
        let mut m = media.borrow_mut();
        m.cache.resize(8192, [0x9b; 512]);
        m.cache[112..126].fill([0; 512]);
        m.cache[128..142].fill([0; 512]);
        m.cache[256..].fill([0; 512]);
        m.durable = m.cache.clone();
    }
    media
}
fn saved(media: Rc<RefCell<Media>>, packages: &Packages<'_>) -> (State<Link, Buffer>, [u8; BYTES]) {
    let mut state = state_network(media);
    state.open(packages, DEADLINE).unwrap();
    state.install(packages, DEADLINE).unwrap();
    transition(&mut state, packages, Change::Activate);
    state.admit(packages, Slot::A, WHO).unwrap();
    assert_eq!(
        state.data_request(packages, WHO, DataRequest::Read, DEADLINE),
        Response::Value(1001)
    );
    assert_eq!(
        state.data_request(packages, WHO, DataRequest::SetValue(2026), DEADLINE),
        Response::Value(2026)
    );
    let old = state.note_request(
        packages,
        WHO,
        NoteRequest::new(Operation::Read, 1).unwrap(),
        None,
        DEADLINE,
    );
    let note = NoteDataEnvelope::decode(&old.bytes.unwrap())
        .unwrap()
        .checked_replace(packages.app(), 0, "saved before an update refusal")
        .unwrap()
        .encode();
    let response = state.note_request(
        packages,
        WHO,
        NoteRequest::new(Operation::Write, 2).unwrap(),
        Some(&note),
        DEADLINE,
    );
    assert_eq!(response.response.outcome(), Outcome::Written);
    // State models the outer authenticated App-replacement boundary. A fresh
    // admitted session has its own one-read ledger; the durable data is shared.
    state.fence();
    state.admit(packages, Slot::A, WHO).unwrap();
    (state, note)
}
fn readable(
    state: &mut State<Link, Buffer>,
    packages: &Packages<'_>,
    note: &[u8; BYTES],
    nonce: u32,
) {
    assert_eq!(
        state.data_request(packages, WHO, DataRequest::Read, DEADLINE),
        Response::Value(2026)
    );
    let response = state.note_request(
        packages,
        WHO,
        NoteRequest::new(Operation::Read, nonce).unwrap(),
        None,
        DEADLINE,
    );
    assert_eq!(response.response.outcome(), Outcome::Read);
    assert_eq!(response.bytes.as_ref(), Some(note));
}
fn inaccessible(state: &mut State<Link, Buffer>, packages: &Packages<'_>) {
    assert_eq!(
        state.data_request(packages, WHO, DataRequest::Read, DEADLINE),
        Response::Refused(Refusal::Denied)
    );
    let response = state.note_request(
        packages,
        WHO,
        NoteRequest::new(Operation::Read, 3).unwrap(),
        None,
        DEADLINE,
    );
    assert!(matches!(response.response.outcome(), Outcome::Refused(_)));
    assert!(response.bytes.is_none());
}
fn run(engine: &mut Engine) -> update::Outcome {
    let mut buffers = acq::Buffers::empty();
    for _ in 0..4096 {
        engine.step(&mut buffers, 100);
        engine.observe_after(100);
        if let Some(outcome) = engine.outcome() {
            return outcome;
        }
    }
    panic!("bounded actual update engine");
}
fn not_blank(state: &mut State<Link, Buffer>) -> Engine {
    let owner = state.take_content_backend(true).unwrap();
    let mut engine = Engine::new();
    assert!(
        engine
            .begin(owner, update::Command::Initialize, 100)
            .is_ok()
    );
    assert_eq!(
        run(&mut engine),
        update::Outcome::Failed(update::Failure::NotBlank)
    );
    engine
}
fn mark_nonblank(media: &Rc<RefCell<Media>>) {
    let mut m = media.borrow_mut();
    m.cache[273] = [0x63; 512];
    m.durable[273] = [0x63; 512];
}
#[test]
fn exact_clean_notblank_restores_same_backend_and_saved_scalar_and_note() {
    let (cat, context, a, b) = crate::native_sources::tests::fixture();
    let packages = Packages::verify_network(&cat, context, &a, &b).unwrap();
    let media = media();
    let (mut state, note) = saved(media.clone(), &packages);
    mark_nonblank(&media);
    let before = media.borrow().durable.clone();
    let writes = media.borrow().writes.len();
    let mut engine = not_blank(&mut state);
    inaccessible(&mut state, &packages);
    assert!(engine.take_completed().is_none());
    assert!(!engine.cancel());
    let owner = engine
        .release_settled_refusal()
        .expect("clean completed read");
    assert!(!engine.busy());
    assert_eq!(
        engine.outcome(),
        Some(update::Outcome::Failed(update::Failure::NotBlank))
    );
    assert!(engine.release_settled_refusal().is_none());
    assert!(state.restore_content_backend(owner).is_ok());
    assert!(!state.content_busy() && !state.recovery_required());
    // The authenticated contention refusal consumed nonce 3. Restoring the
    // backend never retries it; the owner explicitly requests fresh work.
    readable(&mut state, &packages, &note, 4);
    assert_eq!(media.borrow().writes.len(), writes);
    assert_eq!(media.borrow().durable, before);
}
fn inspect_invalid_checkpoint(state: &mut State<Link, Buffer>) -> Engine {
    let mut initialize = Engine::new();
    assert!(
        initialize
            .begin(
                state.take_content_backend(true).unwrap(),
                update::Command::Initialize,
                100
            )
            .is_ok()
    );
    assert!(matches!(run(&mut initialize), update::Outcome::Complete(_)));
    let owner = initialize.take_completed().unwrap();
    let transfer = TransferCut::new(100, 100_000).unwrap();
    let arena = Arena::open(
        owner,
        update::creation_manifest(),
        transfer.metadata(100).unwrap(),
    )
    .unwrap_or_else(|_| panic!("actual initialized arena"));
    let head = arena.head_digest();
    // Generic content publication proves only bytes, never a trusted replay
    // checkpoint. This actual fully verified immutable object is deliberately
    // invalid for the acquisition codec; no authority constructor is used.
    let invalid = [0; acq::CHECKPOINT_BYTES];
    let mut stage = arena
        .begin_owned(
            head,
            invalid.len() as u64,
            Sha256::digest(invalid).into(),
            transfer,
            transfer.metadata(100).unwrap(),
        )
        .unwrap_or_else(|_| panic!("actual immutable reservation"));
    stage
        .write_chunk(&invalid, transfer.child(100, 1024).unwrap())
        .unwrap();
    let expected = stage.reserved_head();
    let mut reader = stage
        .seal(transfer.child(100, 1024).unwrap())
        .unwrap_or_else(|_| panic!("actual header"));
    let mut readback = [1; acq::CHECKPOINT_BYTES];
    reader
        .read_chunk(&mut readback, transfer.child(100, 1024).unwrap())
        .unwrap();
    assert_eq!(readback, invalid);
    let verified = reader
        .finish()
        .unwrap_or_else(|_| panic!("actual full hash"));
    let (arena, _) = verified
        .publish(expected, transfer.metadata(100).unwrap())
        .unwrap_or_else(|_| panic!("syntax-only pointer publication"));
    assert!(state.restore_content_backend(arena.into_backend()).is_ok());
    let mut inspect = Engine::new();
    assert!(
        inspect
            .begin(
                state.take_content_backend(true).unwrap(),
                update::Command::Inspect,
                100
            )
            .is_ok()
    );
    inspect
}

#[test]
fn actual_hash_verified_but_unauthenticated_checkpoint_refusal_preserves_local_data() {
    let (cat, context, a, b) = crate::native_sources::tests::fixture();
    let packages = Packages::verify_network(&cat, context, &a, &b).unwrap();
    let media = media();
    let (mut state, note) = saved(media.clone(), &packages);
    let mut inspect = inspect_invalid_checkpoint(&mut state);
    let before = media.borrow().durable.clone();
    let writes = media.borrow().writes.len();
    assert_eq!(
        run(&mut inspect),
        update::Outcome::Failed(update::Failure::Authentication)
    );
    assert!(inspect.take_completed().is_none());
    let mut snapshot = None;
    assert!(!inspect.snapshot_into(&mut snapshot));
    assert!(snapshot.is_none());
    let owner = inspect
        .release_settled_refusal()
        .expect("settled pure codec refusal");
    assert_eq!(
        inspect.outcome(),
        Some(update::Outcome::Failed(update::Failure::Authentication))
    );
    assert!(state.restore_content_backend(owner).is_ok());
    readable(&mut state, &packages, &note, 3);
    assert_eq!(media.borrow().writes.len(), writes);
    assert_eq!(media.borrow().durable, before);
}
#[test]
fn unknown_read_and_accepted_write_reply_loss_retain_owner_and_never_retry() {
    for accepted_write in [false, true] {
        let (cat, context, a, b) = crate::native_sources::tests::fixture();
        let packages = Packages::verify_network(&cat, context, &a, &b).unwrap();
        let media = media();
        let (mut state, _) = saved(media.clone(), &packages);
        let original = media.borrow().durable.clone();
        let mut engine = Engine::new();
        assert!(
            engine
                .begin(
                    state.take_content_backend(true).unwrap(),
                    update::Command::Initialize,
                    100
                )
                .is_ok()
        );
        let mut buffers = acq::Buffers::empty();
        if accepted_write {
            for _ in 0..2048 {
                engine.step(&mut buffers, 100);
                engine.observe_after(100);
                if engine.stage() == update::Stage::Formatting {
                    break;
                }
            }
            assert_eq!(engine.stage(), update::Stage::Formatting);
            media.borrow_mut().lose_write_reply = true;
        } else {
            media.borrow_mut().fail_next = true;
        }
        assert_eq!(
            run(&mut engine),
            update::Outcome::Failed(update::Failure::Storage)
        );
        let calls = media.borrow().calls.len();
        assert!(engine.take_completed().is_none());
        assert!(engine.release_settled_refusal().is_none());
        assert!(!engine.cancel());
        engine.step(&mut buffers, 101);
        engine.observe_after(101);
        assert_eq!(
            media.borrow().calls.len(),
            calls,
            "accepted/unknown work is never replayed"
        );
        assert!(state.content_busy());
        inaccessible(&mut state, &packages);
        for region in [64..78, 80..94, 112..126] {
            assert_eq!(media.borrow().durable[region.clone()], original[region]);
        }
    }
}
#[test]
fn final_restore_rechecks_current_registry_grant_and_recovery_fences() {
    for guard in 0..3 {
        let (cat, context, a, b) = crate::native_sources::tests::fixture();
        let packages = Packages::verify_network(&cat, context, &a, &b).unwrap();
        let media = media();
        let (mut state, _) = saved(media.clone(), &packages);
        // Retain a genuine Registry intent before the loan, then model its
        // unexpected arrival during the serialized owner's absence. This is a
        // defensive-boundary adversarial state, not a production race claim.
        let intent = if guard == 2 {
            state
                .prepare(
                    &packages,
                    Change::Stage {
                        package: packages.digest(Slot::B),
                    },
                    DEADLINE,
                )
                .unwrap();
            state.pending.take()
        } else {
            None
        };
        mark_nonblank(&media);
        let mut engine = not_blank(&mut state);
        let owner = engine.release_settled_refusal().unwrap();
        match guard {
            0 => state.recovery = true,
            1 => state.grant_fenced = true,
            2 => state.pending = intent,
            _ => unreachable!(),
        }
        let writes = media.borrow().writes.len();
        let _retained_owner = match state.restore_content_backend(owner) {
            Ok(()) => panic!("current State fence cannot be bypassed by old health"),
            Err(owner) => owner,
        };
        assert!(state.content_busy());
        assert_eq!(media.borrow().writes.len(), writes);
        assert_eq!(
            engine.outcome(),
            Some(update::Outcome::Failed(update::Failure::NotBlank))
        );
    }
}

#[test]
fn late_post_refusal_clock_expiry_regression_and_max_permanently_retain_owner() {
    for authentication in [false, true] {
        for clock in 0..3 {
            let (cat, context, a, b) = crate::native_sources::tests::fixture();
            let packages = Packages::verify_network(&cat, context, &a, &b).unwrap();
            let media = media();
            let (mut state, _) = saved(media.clone(), &packages);
            let mut engine = if authentication {
                let mut engine = inspect_invalid_checkpoint(&mut state);
                assert_eq!(
                    run(&mut engine),
                    update::Outcome::Failed(update::Failure::Authentication)
                );
                engine
            } else {
                mark_nonblank(&media);
                not_blank(&mut state)
            };
            let outcome = engine.outcome();
            let cut = engine.original_cut().unwrap();
            let before = media.borrow().durable.clone();
            let calls = media.borrow().calls.len();
            engine.observe_after(match clock {
                0 => cut,
                1 => 99,
                2 => u64::MAX,
                _ => unreachable!(),
            });
            assert_eq!(
                engine.outcome(),
                outcome,
                "preserve the actual semantic failure"
            );
            assert_eq!(engine.original_cut(), Some(cut));
            assert!(engine.release_settled_refusal().is_none());
            engine.observe_after(100);
            assert!(
                engine.release_settled_refusal().is_none(),
                "a later valid sample cannot clear the clock fence"
            );
            assert!(!engine.cancel());
            assert!(engine.busy() && state.content_busy());
            inaccessible(&mut state, &packages);
            assert_eq!(media.borrow().calls.len(), calls);
            assert_eq!(media.borrow().durable, before);
        }
    }
}
