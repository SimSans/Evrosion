extern crate std;
use super::*;
use ev_userspace_contract::{
    file_v2 as wire,
    workspace::{Deadline, Outcome},
};
use ev_workspace_client::{
    Completion, FileClient, Link, TransportError, transfer::Transfer, ui::Command,
};
use ev_workspace_editor::{Close, Error as EditError, Phase, Proposal, Status};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, rc::Rc, vec, vec::Vec};
type Requests = Rc<RefCell<Vec<wire::Request>>>;

#[derive(Clone, Copy)]
enum AbortAnswer {
    Completed,
    Refused(Outcome),
    WrongRequest,
    WrongTransfer,
    WrongRevision,
    Malformed,
    LostReply,
}
struct Peer {
    answer: AbortAnswer,
    total: u32,
    requests: Requests,
}
impl Link for Peer {
    fn now(&mut self) -> Result<u64, TransportError> {
        Ok(101)
    }
    fn exchange(
        &mut self,
        id: u64,
        bytes: &[u8; wire::FRAME_BYTES],
        bulk: &[u8],
        cut: Deadline,
    ) -> Result<[u8; wire::FRAME_BYTES], TransportError> {
        let request = wire::Request::decode(bytes).unwrap();
        assert_eq!((request.request_id, request.deadline), (id, cut));
        self.requests.borrow_mut().push(request);
        let mut response = wire::Response {
            request_id: id,
            operation_id: request.operation_id,
            outcome: Outcome::Completed,
            revision: request.expected_revision,
            transfer_id: 17,
            offset: 0,
            length: 0,
            file_length: 0,
            digest: [0; 32],
        };
        let mut malformed = false;
        match request.method {
            wire::Method::BeginWrite { length, digest } => {
                assert!(bulk.is_empty());
                self.total = length;
                response.file_length = length;
                response.digest = digest;
            }
            wire::Method::WriteChunk {
                transfer_id,
                offset,
                length,
                digest,
            } => {
                assert_eq!(transfer_id, 17);
                assert_eq!(bulk.len(), length as usize);
                assert_eq!(<[u8; 32]>::from(Sha256::digest(bulk)), digest);
                response.offset = offset;
                response.length = length;
                response.file_length = self.total;
                response.digest = digest;
            }
            wire::Method::Abort { transfer_id } => {
                assert_eq!(transfer_id, 17);
                assert!(bulk.is_empty());
                match self.answer {
                    AbortAnswer::Completed => (),
                    AbortAnswer::Refused(outcome) => {
                        response.outcome = outcome;
                        response.revision = 0;
                        response.transfer_id = 0;
                    }
                    AbortAnswer::WrongRequest => response.request_id += 1,
                    AbortAnswer::WrongTransfer => response.transfer_id += 1,
                    AbortAnswer::WrongRevision => response.revision += 1,
                    AbortAnswer::Malformed => malformed = true,
                    AbortAnswer::LostReply => return Err(TransportError::Rpc),
                }
            }
            _ => panic!("cancellation must not Commit, Read or start another transfer"),
        }
        let mut bytes = response.encode().unwrap();
        if malformed {
            bytes[9] = 1;
        }
        Ok(bytes)
    }
    fn read_bulk(&mut self, _: &mut [u8]) -> Result<(), TransportError> {
        panic!("no read during cancellation")
    }
}
fn peer(answer: AbortAnswer) -> (FileClient<Peer>, Requests) {
    let requests = Rc::new(RefCell::new(Vec::new()));
    (
        FileClient::new(Peer {
            answer,
            total: 0,
            requests: requests.clone(),
        }),
        requests,
    )
}
fn stage_one(
    editor: &mut Editor<'_>,
    client: &mut FileClient<Peer>,
    whole: &mut Transfer,
) -> Proposal {
    let p = editor
        .begin_save(client.next_mutation_nonce().unwrap())
        .unwrap();
    let cut = whole.next_request(101).unwrap();
    let reply = client
        .issue(
            p.base_revision,
            wire::Method::BeginWrite {
                length: p.length as u32,
                digest: p.digest,
            },
            cut,
            &[],
            &mut [],
        )
        .unwrap()
        .response;
    editor
        .begin_confirmed(
            reply.transfer_id,
            u64::from(reply.file_length),
            reply.digest,
        )
        .unwrap();
    let mut bytes = [0; 4096];
    let chunk = editor.next_chunk(&mut bytes).unwrap();
    client
        .issue(
            p.base_revision,
            wire::Method::WriteChunk {
                transfer_id: 17,
                offset: chunk.offset as u32,
                length: chunk.length,
                digest: chunk.digest,
            },
            whole.next_request(102).unwrap(),
            &bytes[..chunk.length as usize],
            &mut [],
        )
        .unwrap();
    editor.chunk_confirmed(17, chunk).unwrap();
    p
}
fn issue_abort(
    editor: &mut Editor<'_>,
    client: &mut FileClient<Peer>,
    cut: Deadline,
) -> Result<Completion, ev_workspace_client::Error> {
    let p = editor.pending().unwrap().proposal;
    editor.cancel_save(p).unwrap();
    let abort = editor
        .abort_request(client.next_mutation_nonce().unwrap())
        .unwrap();
    client.issue(
        abort.base_revision,
        wire::Method::Abort {
            transfer_id: abort.transfer,
        },
        cut,
        &[],
        &mut [],
    )
}

#[test]
fn actual_sdk_abort_completion_returns_dirty_only_for_exact_identity_and_original_cut() {
    let (mut client, requests) = peer(AbortAnswer::Completed);
    let mut bytes = vec![b'x'; 4097];
    let mut editor = Editor::open(&mut bytes, 4097, 7, true).unwrap();
    editor.select(1, 0).unwrap();
    editor.replace(b"Z").unwrap();
    let original = (
        editor.bytes().to_vec(),
        editor.cursor(),
        editor.anchor(),
        editor.revision(),
    );
    let mut whole = Transfer::capture(100, 4097).unwrap();
    let whole_cut = whole.whole_cut();
    let proposal = stage_one(&mut editor, &mut client, &mut whole);
    assert_eq!(editor.pending().unwrap().staged, 4096);
    let cut = whole.next_request(103).unwrap();
    let completion = issue_abort(&mut editor, &mut client, cut).unwrap();
    let pending = editor.pending().unwrap();
    assert!(save::confirmed_abort(pending, completion, true, cut).is_none());
    assert!(
        save::confirmed_abort(
            pending,
            completion,
            false,
            Deadline::new(cut.tick() + 1).unwrap()
        )
        .is_none()
    );
    for field in 0..3 {
        let mut foreign = completion;
        match field {
            0 => {
                foreign.request.operation_id += 1;
                foreign.response.operation_id += 1;
            }
            1 => {
                foreign.request.expected_revision += 1;
                foreign.response.revision += 1;
            }
            _ => {
                foreign.request.method = wire::Method::Abort { transfer_id: 18 };
                foreign.response.transfer_id = 18;
            }
        }
        assert!(save::confirmed_abort(pending, foreign, false, cut).is_none());
    }
    let receipt = save::confirmed_abort(pending, completion, client.fenced(), cut).unwrap();
    whole.check(104).unwrap();
    editor.abort_confirmed(receipt).unwrap();
    assert_eq!(editor.status(), Status::Dirty);
    assert_eq!(editor.cancelled_save(), Some(proposal));
    assert_eq!(
        (
            editor.bytes().to_vec(),
            editor.cursor(),
            editor.anchor(),
            editor.revision()
        ),
        original
    );
    assert_eq!(editor.close(), Close::ConfirmDiscard);
    assert!(!client.fenced());
    assert!(editor.pending().is_none());
    assert_eq!(whole.whole_cut(), whole_cut);
    assert_eq!(requests.borrow().len(), 3);
    let abort = requests.borrow()[2];
    assert_eq!(
        (abort.request_id, abort.operation_id, abort.deadline),
        (3, 3, cut)
    );
    assert_eq!(client.next_mutation_nonce().unwrap(), 4);
    assert_eq!(editor.begin_save(4).unwrap().operation, 4);
    assert_eq!(requests.borrow().len(), 3); // user action alone emits no automatic fallback
}

#[test]
fn every_refused_malformed_or_unknown_abort_retains_stage_proposal_ids_and_cut() {
    for answer in [
        AbortAnswer::Refused(Outcome::Busy),
        AbortAnswer::Refused(Outcome::Denied),
        AbortAnswer::Refused(Outcome::Conflict),
        AbortAnswer::Refused(Outcome::NoSpace),
        AbortAnswer::Refused(Outcome::Cancelled),
        AbortAnswer::Refused(Outcome::Unsupported),
        AbortAnswer::Refused(Outcome::Accepted),
        AbortAnswer::Refused(Outcome::Uncertain),
        AbortAnswer::Refused(Outcome::Stale),
        AbortAnswer::Refused(Outcome::Corrupt),
        AbortAnswer::WrongRequest,
        AbortAnswer::WrongTransfer,
        AbortAnswer::WrongRevision,
        AbortAnswer::Malformed,
        AbortAnswer::LostReply,
    ] {
        let (mut client, requests) = peer(answer);
        let mut bytes = vec![b'x'; 4097];
        let mut editor = Editor::open(&mut bytes, 4097, 7, true).unwrap();
        editor.select(1, 0).unwrap();
        editor.replace(b"Z").unwrap();
        let mut whole = Transfer::capture(100, 4097).unwrap();
        let whole_cut = whole.whole_cut();
        let proposal = stage_one(&mut editor, &mut client, &mut whole);
        let cut = whole.next_request(103).unwrap();
        if let Ok(completion) = issue_abort(&mut editor, &mut client, cut) {
            assert!(
                save::confirmed_abort(editor.pending().unwrap(), completion, client.fenced(), cut)
                    .is_none()
            );
        }
        whole.fence();
        editor.mark_uncertain();
        let p = editor.pending().unwrap();
        assert_eq!(
            (p.proposal, p.transfer, p.staged, p.abort_operation),
            (proposal, 17, 4096, Some(3))
        );
        assert_eq!(p.phase, Phase::Uncertain);
        assert!(editor.cancelled_save().is_none());
        assert_eq!(editor.close(), Close::RecoveryRequired);
        assert_eq!(editor.begin_save(4), Err(EditError::Uncertain));
        assert_eq!(editor.replace(b"lost"), Err(EditError::Uncertain));
        assert_eq!(editor.retarget_for_save(0, true), Err(EditError::Uncertain));
        assert_eq!(editor.abort_request(4), Err(EditError::WrongPhase));
        assert_eq!(whole.whole_cut(), whole_cut);
        assert_eq!(requests.borrow().len(), 3);
        if let Some(request) = client.retained_request() {
            assert_eq!(request, requests.borrow()[2]);
        }
    }
}

#[test]
fn expired_original_cut_cannot_gain_an_abort_retry_or_a_dirty_success() {
    for completed_reply in [false, true] {
        let (mut client, requests) = peer(AbortAnswer::Completed);
        let mut bytes = vec![b'x'; 4097];
        let mut editor = Editor::open(&mut bytes, 4097, 7, true).unwrap();
        editor.select(1, 0).unwrap();
        editor.replace(b"Z").unwrap();
        let mut whole = Transfer::capture(100, 4097).unwrap();
        let original_cut = whole.whole_cut();
        let proposal = stage_one(&mut editor, &mut client, &mut whole);
        if completed_reply {
            let cut = whole.next_request(103).unwrap();
            let completion = issue_abort(&mut editor, &mut client, cut).unwrap();
            assert!(
                save::confirmed_abort(editor.pending().unwrap(), completion, client.fenced(), cut)
                    .is_some()
            );
            assert!(whole.check(original_cut.tick()).is_err());
        } else {
            editor.cancel_save(proposal).unwrap();
            assert!(whole.next_request(original_cut.tick()).is_err());
        }
        editor.mark_uncertain();
        assert_eq!(editor.status(), Status::Uncertain);
        assert_eq!(editor.pending().unwrap().proposal, proposal);
        assert_eq!(editor.pending().unwrap().transfer, 17);
        assert!(editor.cancelled_save().is_none());
        assert_eq!(requests.borrow().len(), if completed_reply { 3 } else { 2 });
        assert!(whole.next_request(original_cut.tick() + 1).is_err());
        assert_eq!(whole.whole_cut(), original_cut);
    }
}

#[test]
fn cancel_button_semantics_and_dedicated_intent_never_turn_stale_cancel_into_close() {
    use ev_workspace_client::semantic as a1;
    let mut bytes = [0; 64];
    let mut editor = Editor::open(&mut bytes, 0, 7, true).unwrap();
    editor.replace(b"keep").unwrap();
    let p = editor.begin_save(1).unwrap();
    editor.begin_confirmed(17, p.length, p.digest).unwrap();
    let view = View {
        editor: Some(&editor),
        name: None,
        state: State::Saving,
        start: 0,
        focused: true,
    };
    assert_eq!(fourth_label(view), "Cancel");
    assert_eq!(semantic::actions(view, true, 19), 1);
    for node in [3, 16, 17, 18] {
        assert_eq!(semantic::actions(view, true, node), 0);
    }
    let h = a1::Header {
        nonce: 1,
        page: 0,
        pages: 1,
        model: 1,
        view: 1,
        frame: 1,
        mapping_epoch: 1,
        width: 320,
        height: 180,
        keyboard: 3,
        modal: 0,
    };
    let mut publisher = a1::Publisher::new();
    semantic::publish(&mut publisher, h, view, 4, true).unwrap();
    let mut receiver = a1::Receiver::new();
    receiver.request(0, 1).unwrap();
    while let Some(frame) = publisher.next() {
        receiver.push(frame).unwrap();
        publisher.sent(frame).unwrap();
    }
    let mut snapshot = a1::Snapshot::EMPTY;
    receiver.candidate(&mut snapshot).unwrap();
    let cancel = snapshot.nodes().iter().find(|n| n.local == 19).unwrap();
    assert_eq!(cancel.label.as_str(), "Cancel");
    assert_eq!(cancel.actions, 1);
    assert_eq!(cancel.flags, 0);
    let dedicated = Command::Activate(save::CANCEL_SAVE_ACTION);
    assert_eq!(
        Command::decode(dedicated.encode().unwrap()).unwrap(),
        dedicated
    );
    for label in [false, true] {
        assert!(save::is_cancel_action(dedicated, label));
        assert!(!save::is_cancel_action(
            Command::Close { discard: false },
            label
        ));
    }
    assert!(save::is_cancel_action(Command::Activate(4), true));
    assert!(!save::is_cancel_action(Command::Activate(4), false));
    let mut chunk = [0; 4096];
    let c = editor.next_chunk(&mut chunk).unwrap();
    editor.chunk_confirmed(17, c).unwrap();
    editor.commit_request().unwrap();
    assert_eq!(editor.cancel_save(p), Err(EditError::WrongPhase));
    // The accepted old Cancel label is still cancellation-only after Commit.
    assert!(save::is_cancel_action(Command::Activate(4), true));
    editor
        .commit_confirmed(ev_workspace_editor::Receipt {
            transfer: 17,
            revision: 8,
            length: p.length,
            digest: p.digest,
        })
        .unwrap();
    editor.readback(8, 0, b"keep").unwrap();
    editor.finish_readback().unwrap();
    assert_eq!(editor.status(), Status::Saved);
    assert!(!editor.can_cancel_save());
    assert!(save::is_cancel_action(dedicated, false));
    assert_eq!(editor.cancel_save(p), Err(EditError::WrongPhase));
}
