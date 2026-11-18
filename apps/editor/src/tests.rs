extern crate std;
use super::*;
use ev_workspace_editor::MAX_DOCUMENT_BYTES;
use std::{vec, vec::Vec};

struct Frame {
    width: usize,
    height: usize,
    pixels: Vec<u32>,
}
impl Frame {
    fn new(width: usize, height: usize) -> Self {
        Self {
            width,
            height,
            pixels: vec![0; width * height],
        }
    }
}
impl Pixels for Frame {
    fn dimensions(&self) -> (usize, usize) {
        (self.width, self.height)
    }
    fn write(&mut self, x: usize, y: usize, color: Color) -> Result<(), Error> {
        if x >= self.width || y >= self.height {
            return Err(Error::Bounds);
        }
        self.pixels[y * self.width + x] = color.0;
        Ok(())
    }
}
fn view<'a, 'b>(editor: &'a Editor<'b>, start: usize) -> View<'a, 'b> {
    View {
        editor: Some(editor),
        name: Some("notes α.txt"),
        state: State::Dirty,
        start,
        focused: true,
    }
}

#[test]
fn viewport_of_one_mib_document_is_bounded_and_caret_can_be_reached_without_changing_bytes() {
    let mut buffer = vec![b'x'; MAX_DOCUMENT_BYTES];
    let editor = Editor::open(&mut buffer, MAX_DOCUMENT_BYTES, 8, true).unwrap();
    let mut frame = Frame::new(320, 180);
    let first = render(&mut frame, view(&editor, 0)).unwrap();
    assert!(first.end < 1024);
    assert!(!first.caret_visible);
    let start = around_caret(&editor, 320, 180);
    assert!(MAX_DOCUMENT_BYTES - start < 1024);
    assert!(
        render(&mut frame, view(&editor, start))
            .unwrap()
            .caret_visible
    );
    assert!(editor.bytes().iter().all(|b| *b == b'x'));
    assert_eq!(editor.revision(), 8);
}

#[test]
fn unicode_selection_crlf_tabs_and_tiny_windows_preserve_document_and_bounds() {
    let text = "αβ\r\nA\tZ\nlast 😀";
    let mut buffer = [0; 256];
    buffer[..text.len()].copy_from_slice(text.as_bytes());
    let mut editor = Editor::open(&mut buffer, text.len(), 2, true).unwrap();
    editor.select(4, 0).unwrap();
    let mut frame = Frame::new(80, 80);
    render(&mut frame, view(&editor, 0)).unwrap();
    assert!(frame.pixels.contains(&ACCENT.0));
    assert_eq!(render(&mut frame, view(&editor, 1)), Err(Error::Text));
    assert_eq!(
        render(&mut frame, view(&editor, text.len() + 1)),
        Err(Error::Text)
    );
    editor.select(text.len(), text.len()).unwrap();
    for (width, height) in [(1, 1), (7, 40), (14, 60), (320, 200)] {
        let start = around_caret(&editor, width, height);
        assert!(editor.text().is_char_boundary(start));
        render(&mut Frame::new(width, height), view(&editor, start)).unwrap();
    }
    assert_eq!(editor.bytes(), text.as_bytes());
}

#[test]
fn old_grants_and_release_replays_cannot_unpause_a_bound_window() {
    use ReleaseAction::*;
    let mut handoff = FileHandoff::default();
    assert!(handoff.may_receive());
    handoff.received();
    assert!(!handoff.may_receive());
    assert_eq!(
        handoff.release_action(1, ReleaseMode::KeepDocument),
        Some(Close)
    );
    handoff.released(1, ReleaseMode::KeepDocument);
    assert!(handoff.may_receive());
    assert_eq!(handoff.receive_mode(), Some(ReleaseMode::KeepDocument));
    assert_eq!(
        handoff.release_action(1, ReleaseMode::KeepDocument),
        Some(RepeatAck)
    );
    assert_eq!(handoff.release_action(1, ReleaseMode::Discard), None);
    handoff.received();
    assert!(!handoff.may_receive());
    assert_eq!(handoff.release_action(1, ReleaseMode::KeepDocument), None);
    assert_eq!(handoff.release_action(0, ReleaseMode::Discard), None);
    assert_eq!(handoff.release_action(u32::MAX, ReleaseMode::Discard), None);
    assert_eq!(
        handoff.release_action(2, ReleaseMode::CloseSaved),
        Some(Close)
    );
}

#[test]
fn semantic_snapshot_keeps_full_tuple_unicode_ranges_and_read_only_save_disabled() {
    use ev_workspace_client::semantic as a1;
    let text = "αβ\r\ntext 😀";
    let mut bytes = [0u8; 128];
    bytes[..text.len()].copy_from_slice(text.as_bytes());
    let editor = Editor::open(&mut bytes, text.len(), 7, false).unwrap();
    let mut pixels = Frame::new(320, 180);
    let painted = render(&mut pixels, view(&editor, 0)).unwrap();
    let h = a1::Header {
        nonce: 9,
        page: 0,
        pages: 1,
        model: 0x1_0000_0001,
        view: 0x2_0000_0002,
        frame: 0x3_0000_0003,
        mapping_epoch: 0x4_0000_0004,
        width: 320,
        height: 180,
        keyboard: 3,
        modal: 0,
    };
    let mut publisher = a1::Publisher::new();
    semantic::publish(&mut publisher, h, view(&editor, 0), painted.end, false).unwrap();
    let mut receiver = a1::Receiver::new();
    receiver.request(0, 9).unwrap();
    while let Some(frame) = publisher.next() {
        receiver.push(frame).unwrap();
        publisher.sent(frame).unwrap();
    }
    let mut staged = a1::Snapshot::EMPTY;
    receiver.candidate(&mut staged).unwrap();
    assert_eq!(staged.header(), h);
    assert_eq!(staged.nodes().len(), 9);
    let save = staged.nodes().iter().find(|n| n.local == 17).unwrap();
    assert_eq!((save.flags, save.actions), (1, 0));
    let body = staged.nodes().iter().find(|n| n.local == 3).unwrap();
    assert_eq!(
        body.value,
        a1::Value::TextRange {
            revision: h.view,
            offset: 0,
            length: painted.end as u32,
            total: text.len() as u64
        }
    );
    assert_eq!(editor.bytes(), text.as_bytes());
}

#[test]
fn semantic_snapshot_rejects_unpainted_split_utf8_and_unsupported_page_without_stream() {
    use ev_workspace_client::semantic as a1;
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice("αβ".as_bytes());
    let editor = Editor::open(&mut bytes, 4, 1, true).unwrap();
    let mut publisher = a1::Publisher::new();
    let h = a1::Header {
        nonce: 1,
        page: 0,
        pages: 1,
        model: 1,
        view: 1,
        frame: 2,
        mapping_epoch: 1,
        width: 320,
        height: 180,
        keyboard: 3,
        modal: 0,
    };
    assert_eq!(
        semantic::publish(&mut publisher, h, view(&editor, 0), 3, true),
        Err(a1::Error::Bounds)
    );
    assert!(!publisher.busy());
    assert_eq!(
        semantic::publish(
            &mut publisher,
            a1::Header {
                page: 1,
                pages: 2,
                ..h
            },
            view(&editor, 0),
            4,
            true
        ),
        Err(a1::Error::Bounds)
    );
    assert!(publisher.next().is_none());
    semantic::publish(&mut publisher, h, view(&editor, 0), 4, true).unwrap();
    let first = publisher.next().unwrap();
    assert_eq!(publisher.next(), Some(first));
    assert_eq!(
        semantic::publish(
            &mut publisher,
            a1::Header { nonce: 2, ..h },
            view(&editor, 0),
            4,
            true
        ),
        Err(a1::Error::State)
    );
    assert_eq!(publisher.next(), Some(first));
}

#[test]
fn semantic_full_name_is_a_range_and_save_offers_only_a_real_dirty_write() {
    use ev_workspace_client::semantic as a1;
    let name = "α".repeat(48);
    let h = a1::Header {
        nonce: 7,
        page: 0,
        pages: 1,
        model: 1,
        view: 9,
        frame: 12,
        mapping_epoch: 3,
        width: 80,
        height: 60,
        keyboard: 0,
        modal: 0,
    };
    let empty = View {
        editor: None,
        name: Some(&name),
        state: State::NoFile,
        start: 0,
        focused: false,
    };
    let mut p = a1::Publisher::new();
    semantic::publish(&mut p, h, empty, 0, false).unwrap();
    let mut r = a1::Receiver::new();
    r.request(0, 7).unwrap();
    while let Some(f) = p.next() {
        r.push(f).unwrap();
        p.sent(f).unwrap();
    }
    let mut candidate = a1::Snapshot::EMPTY;
    r.candidate(&mut candidate).unwrap();
    let node = candidate.nodes().iter().find(|n| n.local == 5).unwrap();
    assert_eq!(node.label.as_str(), "File name");
    assert_eq!(
        node.value,
        a1::Value::TextRange {
            revision: 9,
            offset: 0,
            length: 96,
            total: 96
        }
    );
    assert_eq!(a1::operation::text_range(&name, 0, 63).unwrap().len(), 62);
    let mut bytes = [0u8; 32];
    let mut editor = Editor::open(&mut bytes, 0, 1, true).unwrap();
    let saved = View {
        editor: Some(&editor),
        name: None,
        state: State::Saved,
        start: 0,
        focused: true,
    };
    assert_eq!(semantic::actions(saved, true, 17), 0);
    editor.replace(b"new").unwrap();
    let dirty = View {
        editor: Some(&editor),
        state: State::Dirty,
        name: None,
        start: 0,
        focused: true,
    };
    assert_eq!(semantic::actions(dirty, true, 17), 1);
    assert_eq!(semantic::actions(dirty, false, 17), 0);
    assert_eq!(semantic::actions(dirty, true, 99), 0);
}

#[test]
fn whole_transfer_expiry_preserves_the_frozen_save_bytes_and_original_proposal() {
    use ev_workspace_client::transfer::Transfer;
    use ev_workspace_editor::{Close, Error as EditError, Phase, Status};
    let mut bytes = vec![b'x'; MAX_DOCUMENT_BYTES];
    let mut editor = Editor::open(&mut bytes, MAX_DOCUMENT_BYTES, 7, true).unwrap();
    editor.select(1, 0).unwrap();
    editor.replace(b"y").unwrap();
    // The native adapter captures this before begin_save performs whole-file
    // hashing. The proposal freezes the exact bytes, revision and operation.
    let mut whole = Transfer::capture(100, editor.bytes().len() as u64).unwrap();
    let proposal = editor.begin_save(9).unwrap();
    let original_cut = whole.next_request(101).unwrap();
    editor
        .begin_confirmed(33, proposal.length, proposal.digest)
        .unwrap();
    let mut chunk = [0; 4096];
    let first = editor.next_chunk(&mut chunk).unwrap();
    assert_eq!(first.offset, 0);
    assert_eq!(&chunk[..2], b"yx");
    // An expired/unknown native completion cannot become a new Save/retry.
    assert!(whole.check(whole.whole_cut().tick()).is_err());
    editor.mark_uncertain();
    assert_eq!(editor.status(), Status::Uncertain);
    let pending = editor.pending().unwrap();
    assert_eq!(pending.proposal, proposal);
    assert_eq!(pending.in_flight, Some(first));
    assert_eq!(pending.phase, Phase::Uncertain);
    assert_eq!(editor.begin_save(10), Err(EditError::Uncertain));
    assert_eq!(editor.replace(b"lost"), Err(EditError::Uncertain));
    assert_eq!(editor.close(), Close::RecoveryRequired);
    assert_eq!(editor.bytes().len(), MAX_DOCUMENT_BYTES);
    assert_eq!(editor.bytes()[0], b'y');
    assert!(editor.bytes()[1..].iter().all(|b| *b == b'x'));
    assert_eq!(editor.revision(), 7);
    assert_eq!(original_cut.tick(), 101 + 8192);
}

#[derive(Clone, Copy)]
enum BeginAnswer {
    Outcome(ev_userspace_contract::workspace::Outcome),
    WrongRequest,
    LostReply,
}
struct BeginPeer {
    answer: BeginAnswer,
    requests: std::rc::Rc<std::cell::RefCell<Vec<ev_userspace_contract::file_v2::Request>>>,
}
impl ev_workspace_client::Link for BeginPeer {
    fn now(&mut self) -> Result<u64, ev_workspace_client::TransportError> {
        Ok(101)
    }
    fn exchange(
        &mut self,
        request_id: u64,
        control: &[u8; ev_userspace_contract::file_v2::FRAME_BYTES],
        bulk: &[u8],
        deadline: ev_userspace_contract::workspace::Deadline,
    ) -> Result<
        [u8; ev_userspace_contract::file_v2::FRAME_BYTES],
        ev_workspace_client::TransportError,
    > {
        use ev_userspace_contract::{file_v2 as wire, workspace::Outcome};
        let request = wire::Request::decode(control).unwrap();
        assert_eq!(request.request_id, request_id);
        assert_eq!(request.deadline, deadline);
        assert!(bulk.is_empty());
        self.requests.borrow_mut().push(request);
        if matches!(self.answer, BeginAnswer::LostReply) {
            return Err(ev_workspace_client::TransportError::Rpc);
        }
        wire::Response {
            request_id: request_id + u64::from(matches!(self.answer, BeginAnswer::WrongRequest)),
            operation_id: request.operation_id,
            outcome: match self.answer {
                BeginAnswer::Outcome(outcome) => outcome,
                _ => Outcome::NoSpace,
            },
            revision: 0,
            transfer_id: 0,
            offset: 0,
            length: 0,
            file_length: 0,
            digest: [0; 32],
        }
        .encode()
        .map_err(|_| ev_workspace_client::TransportError::Correlation)
    }
    fn read_bulk(&mut self, _: &mut [u8]) -> Result<(), ev_workspace_client::TransportError> {
        panic!("a refused Begin has no read payload")
    }
}

#[test]
fn settled_begin_refusals_keep_dirty_bytes_and_consume_ids_without_automatic_retry() {
    use ev_userspace_contract::{file_v2::Method, workspace::Outcome};
    use ev_workspace_client::{FileClient, transfer::Transfer};
    use ev_workspace_editor::{BeginRefusal, Close, Error as EditError, Status};
    for (outcome, reason) in [
        (Outcome::NoSpace, BeginRefusal::NoSpace),
        (Outcome::Conflict, BeginRefusal::Conflict),
    ] {
        let requests = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let mut client = FileClient::new(BeginPeer {
            answer: BeginAnswer::Outcome(outcome),
            requests: requests.clone(),
        });
        let mut bytes = [0; 64];
        let mut editor = Editor::open(&mut bytes, 0, 4, true).unwrap();
        editor.replace(b"local dirty bytes").unwrap();
        editor.select(5, 1).unwrap();
        let before = (
            editor.bytes().to_vec(),
            editor.cursor(),
            editor.anchor(),
            editor.edit_sequence(),
        );
        let mut whole = Transfer::capture(100, editor.bytes().len() as u64).unwrap();
        let cut = whole.next_request(101).unwrap();
        let proposal = editor
            .begin_save(client.next_mutation_nonce().unwrap())
            .unwrap();
        let completion = client
            .issue(
                4,
                Method::BeginWrite {
                    length: proposal.length as u32,
                    digest: proposal.digest,
                },
                cut,
                &[],
                &mut [],
            )
            .unwrap();
        let pending = editor.pending().unwrap();
        assert!(save::settled_begin_refusal(pending, completion, true, cut).is_none());
        let wrong_cut = ev_userspace_contract::workspace::Deadline::new(cut.tick() + 1).unwrap();
        assert!(save::settled_begin_refusal(pending, completion, false, wrong_cut).is_none());
        let mut foreign = completion;
        foreign.response.request_id += 1;
        assert!(save::settled_begin_refusal(pending, foreign, false, cut).is_none());
        foreign = completion;
        foreign.response.transfer_id = 19;
        assert!(save::settled_begin_refusal(pending, foreign, false, cut).is_none());
        foreign = completion;
        foreign.request.expected_revision += 1;
        assert!(save::settled_begin_refusal(pending, foreign, false, cut).is_none());
        let observed = save::settled_begin_refusal(
            editor.pending().unwrap(),
            completion,
            client.fenced(),
            cut,
        )
        .unwrap();
        assert_eq!(observed, reason);
        editor.begin_refused(proposal, observed).unwrap();
        assert_eq!(
            (
                editor.bytes().to_vec(),
                editor.cursor(),
                editor.anchor(),
                editor.edit_sequence()
            ),
            before
        );
        assert_eq!(editor.revision(), 4);
        assert_eq!(editor.refused_begin().unwrap().proposal, proposal);
        assert!(editor.pending().is_none());
        assert!(!client.fenced());
        assert!(client.retained_request().is_none());
        assert_eq!(editor.close(), Close::ConfirmDiscard);
        assert_eq!(requests.borrow().len(), 1);
        assert_eq!(requests.borrow()[0], completion.request);
        assert_eq!(client.next_mutation_nonce().unwrap(), 2);
        assert_eq!(whole.whole_cut(), cut);
        if reason == BeginRefusal::NoSpace {
            assert_eq!(editor.status(), Status::Dirty);
            assert_eq!(editor.begin_save(1), Err(EditError::Exhausted));
            // A separate explicit retry uses a new operation. Merely handling
            // the refusal above emitted no second SDK request.
            assert_eq!(editor.begin_save(2).unwrap().operation, 2);
        } else {
            assert_eq!(editor.status(), Status::Conflict);
            assert_eq!(editor.begin_save(2), Err(EditError::Conflict));
            editor.replace(b"edited locally").unwrap();
            assert_eq!(editor.status(), Status::Conflict);
            // Pure model event only: native Save As still requires actual old
            // route retirement and a separately authorized destination first.
            editor.retarget_for_save(0, true).unwrap();
            assert!(editor.refused_begin().is_none());
            assert_eq!(editor.status(), Status::Dirty);
        }
        assert_eq!(requests.borrow().len(), 1);
    }
}

#[test]
fn uncertain_and_foreign_begin_results_preserve_the_original_request_proposal_and_cut() {
    use ev_userspace_contract::{file_v2::Method, workspace::Outcome};
    use ev_workspace_client::{FileClient, transfer::Transfer};
    use ev_workspace_editor::{Close, Status};
    for answer in [
        BeginAnswer::Outcome(Outcome::Accepted),
        BeginAnswer::Outcome(Outcome::Uncertain),
        BeginAnswer::Outcome(Outcome::Stale),
        BeginAnswer::Outcome(Outcome::Corrupt),
        BeginAnswer::WrongRequest,
        BeginAnswer::LostReply,
    ] {
        let requests = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let mut client = FileClient::new(BeginPeer {
            answer,
            requests: requests.clone(),
        });
        let mut bytes = [0; 64];
        let mut editor = Editor::open(&mut bytes, 0, 4, true).unwrap();
        editor.replace(b"retained proposal").unwrap();
        let mut whole = Transfer::capture(100, editor.bytes().len() as u64).unwrap();
        let cut = whole.next_request(101).unwrap();
        let proposal = editor
            .begin_save(client.next_mutation_nonce().unwrap())
            .unwrap();
        let result = client.issue(
            4,
            Method::BeginWrite {
                length: proposal.length as u32,
                digest: proposal.digest,
            },
            cut,
            &[],
            &mut [],
        );
        if let Ok(completion) = result {
            assert!(
                save::settled_begin_refusal(
                    editor.pending().unwrap(),
                    completion,
                    client.fenced(),
                    cut
                )
                .is_none()
            );
        }
        assert!(client.fenced());
        let request = client.retained_request().unwrap();
        assert_eq!(request, requests.borrow()[0]);
        assert_eq!(request.deadline, cut);
        assert_eq!(request.operation_id, proposal.operation);
        whole.fence();
        editor.mark_uncertain();
        assert_eq!(editor.pending().unwrap().proposal, proposal);
        assert_eq!(editor.status(), Status::Uncertain);
        assert_eq!(editor.close(), Close::RecoveryRequired);
        assert!(editor.refused_begin().is_none());
        assert_eq!(editor.bytes(), b"retained proposal");
        assert_eq!(whole.whole_cut(), cut);
        assert!(client.next_mutation_nonce().is_err());
        assert_eq!(requests.borrow().len(), 1);
    }
}

#[test]
fn conflict_and_space_status_keep_useful_actions_without_enabling_conflict_save() {
    use ev_workspace_editor::{BeginRefusal, Close};
    for (reason, state, label) in [
        (
            BeginRefusal::NoSpace,
            State::Dirty,
            "No space; changes kept",
        ),
        (
            BeginRefusal::Conflict,
            State::Conflict,
            "Changed elsewhere; Save As",
        ),
    ] {
        let mut bytes = [0; 64];
        let mut editor = Editor::open(&mut bytes, 0, 4, true).unwrap();
        editor.replace(b"keep this").unwrap();
        let p = editor.begin_save(1).unwrap();
        editor.begin_refused(p, reason).unwrap();
        let v = View {
            state,
            ..view(&editor, 0)
        };
        assert_eq!(status_label(v), label);
        assert_eq!(
            semantic::actions(v, true, 17),
            u8::from(state == State::Dirty)
        );
        assert_eq!(semantic::actions(v, false, 17), 0);
        for local in [16, 18, 19] {
            assert_eq!(semantic::actions(v, true, local), 1);
        }
        assert_eq!(semantic::actions(v, true, 3), 0b1110);
        assert_eq!(editor.close(), Close::ConfirmDiscard);
        let mut surface = Frame::new(320, 180);
        render(&mut surface, v).unwrap();
        assert_eq!(editor.bytes(), b"keep this");
    }
}
