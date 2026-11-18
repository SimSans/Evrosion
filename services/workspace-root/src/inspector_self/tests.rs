extern crate std;
use super::*;
use ev_native_inspector::self_tree::reply;
use ev_workspace_client::semantic::{Frame, Header, Label, Node, Rect, Role, Value};
fn binding(reader: bool) -> Binding {
    Binding {
        owner: Identity {
            process: 41,
            thread: 42,
            registered: 9,
        },
        window: WindowId {
            slot: 3,
            generation: 7,
        },
        presented: Presented {
            model: 11,
            view: 12,
            frame: 13,
            mapping_epoch: 14,
            width: 320,
            height: 180,
        },
        context: Context {
            reader,
            phase: u8::from(reader),
            view: 12,
            rights: if reader { 15 } else { 0 },
            target: if reader { 3 } else { 255 },
            provider: None,
            source: None,
            source_presented: None,
        },
    }
}
fn entry_scope() -> EntryScope {
    let b = binding(false);
    EntryScope {
        owner: b.owner,
        window: b.window,
        model: b.presented.model,
    }
}
#[test]
fn stats_refresh_waits_for_matching_action_receipt_then_starts_exactly_one_sample() {
    let mut refresh = StatsRefresh::new();
    assert!(!refresh.ready() && !refresh.started());
    assert!(refresh.request(2));
    // The existing accepted old frame can be observed repeatedly while the
    // ordinary command is queued. It cannot consume this pending request.
    for _ in 0..8 {
        assert!(refresh.pending());
        assert!(!refresh.ready() && !refresh.started());
    }
    assert!(!refresh.request(3));
    assert!(!refresh.accepted_action(1));
    assert!(!refresh.ready());
    assert!(refresh.accepted_action(2));
    assert!(refresh.ready());
    assert!(!refresh.request(2));
    assert!(refresh.started());
    assert!(!refresh.pending() && !refresh.started());
    assert!(!refresh.accepted_action(2));
}
#[test]
fn context_refresh_cannot_replace_a_pending_action_or_restart_a_consumed_sample() {
    let mut refresh = StatsRefresh::new();
    assert!(!refresh.request(0) && !refresh.request(4));
    assert!(refresh.request(3));
    assert!(!refresh.context_ready());
    assert!(refresh.accepted_action(3));
    assert!(refresh.started());
    assert!(refresh.context_ready());
    assert!(!refresh.context_ready());
    assert!(refresh.started());
    assert!(!refresh.started());
    refresh.request(1);
    refresh.clear();
    assert!(!refresh.pending() && !refresh.accepted_action(1));
}
#[test]
fn own_entry_keeps_original_scope_and_cut_until_exact_live_submission() {
    let mut entry = EntryWait::new();
    let scope = entry_scope();
    entry.request(scope, 8192).unwrap();
    for now in [100, 2000, 8191] {
        assert_eq!(entry.current(Some(scope), now), Some(8192));
        assert!(entry.request(scope, now + 8192).is_err());
        assert_eq!(entry.current(Some(scope), now), Some(8192));
    }
    assert_eq!(entry.current(Some(scope), 8192), None);
    assert!(!entry.pending());
    assert_eq!(entry.current(Some(scope), 100), None);
}
#[test]
fn stale_focus_scene_window_or_actor_cancels_only_unsent_entry_desire() {
    let scope = entry_scope();
    let mut variants = std::vec![None];
    let mut changed = scope;
    changed.owner.process += 1;
    variants.push(Some(changed));
    let mut changed = scope;
    changed.owner.thread += 1;
    variants.push(Some(changed));
    let mut changed = scope;
    changed.owner.registered += 1;
    variants.push(Some(changed));
    let mut changed = scope;
    changed.window.generation += 1;
    variants.push(Some(changed));
    let mut changed = scope;
    changed.model += 1;
    variants.push(Some(changed));
    for current in variants {
        let mut entry = EntryWait::new();
        entry.request(scope, 8192).unwrap();
        let mut capture = Capture::new();
        start(&mut capture, binding(false));
        let before = capture.binding();
        assert_eq!(entry.current(current, 100), None);
        assert!(!entry.pending());
        assert_eq!(capture.phase(), Phase::Receiving);
        assert_eq!(capture.binding(), before);
        assert_eq!(entry.current(Some(scope), 101), None);
    }
}
#[test]
fn enter_waits_for_real_complete_current_publication_without_renewing_either_cut() {
    let b = binding(false);
    let mut c = Capture::new();
    start(&mut c, b);
    let mut enter = EnterWait::new();
    enter.request(b, 6000).unwrap();
    for now in [100, 2000, 5000] {
        assert_eq!(enter.ready(Some(b), now, &c, 7, Some(7)), None);
        assert!(enter.request(b, now + 8192).is_err());
        assert_eq!(c.phase(), Phase::Receiving);
        assert_eq!(c.by, 8192);
    }
    assert_eq!(complete(&mut c, b, 17, 0, 0, Some(b)), Outcome::Complete);
    assert_eq!(enter.ready(Some(b), 5001, &c, 0, Some(7)), None);
    assert_eq!(enter.ready(Some(b), 5002, &c, 7, Some(8)), None);
    assert_eq!(enter.ready(Some(b), 5999, &c, 7, Some(7)), Some((2, 6000)));
    // Native transfer to the immutable outbox consumes only this desire.
    enter.cancel();
    assert_eq!(enter.ready(Some(b), 5999, &c, 7, Some(7)), None);
    assert_eq!(c.phase(), Phase::Ready);
    assert_eq!(c.by, 8192);
}
#[test]
fn enter_moves_once_to_actual_outbox_and_busy_delivery_cannot_recreate_it() {
    use crate::outbox::{Outbox, Scene};
    use ev_workspace_client::ui::Command;
    let b = binding(false);
    let mut c = Capture::new();
    start(&mut c, b);
    assert_eq!(complete(&mut c, b, 17, 0, 0, Some(b)), Outcome::Complete);
    let mut enter = EnterWait::new();
    enter.request(b, 7000).unwrap();
    let mut outbox = Outbox::new();
    // Known refusal before an actual owner is configured retains the one
    // desire and its cut; it does not transfer or invent SEND acceptance.
    let (control, by) = enter.ready(Some(b), 100, &c, 7, Some(7)).unwrap();
    assert!(!outbox.input(3, b.owner, b.presented.model, Command::Activate(control)));
    assert_eq!(by, 7000);
    assert!(enter.pending());
    assert!(outbox.scene(
        3,
        Scene {
            identity: b.owner,
            model: b.presented.model,
            width: 320,
            height: 180,
            focused: true,
            mapping_epoch: b.presented.mapping_epoch as u32,
        }
    ));
    while outbox.next(3).is_some() {
        assert!(outbox.accepted(3));
    }
    assert!(outbox.input(3, b.owner, b.presented.model, Command::Activate(control)));
    enter.cancel();
    // Busy/unknown SEND does not advance this immutable outbox word, but the
    // physical desire has been consumed and cannot add a second command.
    for now in [101, 500, 6999] {
        assert_eq!(outbox.next(3), Some(Command::Activate(2)));
        assert_eq!(enter.ready(Some(b), now, &c, 7, Some(7)), None);
    }
    assert!(outbox.accepted(3));
    assert_eq!(outbox.next(3), None);
    assert_eq!(c.phase(), Phase::Ready);
}
#[test]
fn pending_enter_rejects_changed_actual_binding_without_erasing_stream_debt() {
    let b = binding(true);
    let mut variants = std::vec![None];
    for field in 0..12 {
        let mut changed = b;
        match field {
            0 => changed.owner.process += 1,
            1 => changed.owner.thread += 1,
            2 => changed.owner.registered += 1,
            3 => changed.window.generation += 1,
            4 => changed.presented.model += 1,
            5 => changed.presented.frame += 1,
            6 => changed.presented.view += 1,
            7 => changed.presented.mapping_epoch += 1,
            8 => changed.presented.width -= 1,
            9 => changed.context.view += 1,
            10 => changed.context.rights ^= 1,
            _ => changed.context.source_presented = Some(b.presented),
        }
        variants.push(Some(changed));
    }
    for current in variants {
        let mut c = Capture::new();
        start(&mut c, b);
        let mut enter = EnterWait::new();
        enter.request(b, 8000).unwrap();
        assert_eq!(enter.ready(current, 100, &c, 7, Some(7)), None);
        assert!(!enter.pending());
        assert_eq!(c.phase(), Phase::Receiving);
        assert_eq!(c.binding(), Some(b));
        assert_eq!(c.by, 8192);
        assert_eq!(enter.ready(Some(b), 101, &c, 7, Some(7)), None);
    }
}
#[test]
fn enter_expiry_or_cancellation_never_returns_capture_or_abort_credit() {
    let b = binding(false);
    let mut c = Capture::new();
    start(&mut c, b);
    let mut enter = EnterWait::new();
    enter.request(b, 500).unwrap();
    assert_eq!(enter.current(Some(b), 500), None);
    assert_eq!(c.phase(), Phase::Receiving);
    c.tick(8192, 9000);
    assert_eq!(c.phase(), Phase::AbortSend);
    let abort = c.next().unwrap();
    c.sent(abort).unwrap();
    enter.request(b, 8900).unwrap();
    enter.cancel();
    assert_eq!(c.phase(), Phase::Aborting);
    c.tick(8999, 17000);
    assert_eq!(c.phase(), Phase::Aborting);
    c.tick(9000, 18000);
    assert_eq!(c.phase(), Phase::Blocked);
}
#[test]
fn pending_enter_never_activates_disabled_ancestor_or_protected_confirm() {
    for (reader, control, flags, ancestor) in [
        (false, 17, 1, 0),
        (false, 17, 0, 1),
        (true, 204, 2, 0),
        (true, 213, 0, 0),
    ] {
        let b = binding(reader);
        let mut c = Capture::new();
        start(&mut c, b);
        assert_eq!(
            complete(&mut c, b, control, flags, ancestor, Some(b)),
            Outcome::Complete
        );
        let mut enter = EnterWait::new();
        enter.request(b, 1000).unwrap();
        assert_eq!(enter.ready(Some(b), 999, &c, 7, Some(7)), None);
        assert_eq!(enter.current(Some(b), 1000), None);
    }
}
#[test]
fn ordinary_reader_receipt_requires_exact_action_index_view_binding_and_cut() {
    let b = binding(true);
    let intent = Intent {
        kind: IntentKind::ReadDocument,
        index: 2,
        view: b.context.view,
    };
    let receipt = || OrdinaryReceipt::new(b, 208, 2, 4, 500).unwrap();
    assert!(receipt().accept(Some(b), intent, 499));
    assert!(!receipt().accept(Some(b), intent, 500));
    let mut wrong = intent;
    wrong.kind = IntentKind::Activate;
    assert!(!receipt().accept(Some(b), wrong, 100));
    wrong = intent;
    wrong.index += 1;
    assert!(!receipt().accept(Some(b), wrong, 100));
    wrong = intent;
    wrong.view += 1;
    assert!(!receipt().accept(Some(b), wrong, 100));
    let mut changed = b;
    changed.context.rights ^= 4;
    assert!(!receipt().accept(Some(changed), intent, 100));
    assert!(OrdinaryReceipt::new(b, 213, 2, 4, 500).is_none());
    assert!(OrdinaryReceipt::new(binding(false), 208, 2, 4, 500).is_none());
}
#[test]
fn reader_navigation_receipt_pins_wrapped_selection_and_fixed_public_control() {
    let b = binding(true);
    for (control, kind, index) in [
        (201, IntentKind::PreviousNode, 3),
        (202, IntentKind::NextNode, 1),
        (302, IntentKind::AssistiveFocus, 2),
    ] {
        let receipt = OrdinaryReceipt::new(b, control, 0, 4, 500).unwrap();
        assert!(receipt.accept(
            Some(b),
            Intent {
                kind,
                index,
                view: b.context.view
            },
            100
        ));
    }
    assert!(OrdinaryReceipt::new(b, 304, 0, 4, 500).is_none());
    assert!(OrdinaryReceipt::new(b, 201, 255, 255, 500).is_none());
}
fn reader_transfer() -> (
    Binding,
    Capture,
    ReaderTransfer,
    ev_native_inspector::self_tree::ordinary::Scope,
) {
    let b = binding(true);
    let mut c = Capture::new();
    start(&mut c, b);
    assert_eq!(complete(&mut c, b, 201, 0, 0, Some(b)), Outcome::Complete);
    let scope = ev_native_inspector::self_tree::ordinary::Scope {
        header: c.candidate().header(),
        control: 201,
    };
    let mut flow = ReaderTransfer::new();
    flow.begin(b, 7, 201, c.nonce(), 0, 9, 900).unwrap();
    (b, c, flow, scope)
}
fn send_reader_request(
    flow: &mut ReaderTransfer,
    app: &mut ev_native_inspector::self_tree::ordinary::Gate,
    scope: ev_native_inspector::self_tree::ordinary::Scope,
) {
    use ev_native_inspector::self_tree::ordinary::Request;
    for index in 0..4 {
        let bytes = flow.next().unwrap();
        let action = app
            .receive(
                Request::decode(bytes).unwrap(),
                Some(scope),
                100 + index,
                1000,
            )
            .unwrap();
        assert_eq!(action, if index == 3 { Some(201) } else { None });
        flow.sent(bytes, 100 + index).unwrap();
    }
}
#[test]
fn reader_urgent_repaint_is_held_until_actual_original_binding_reply_and_matching_ack() {
    use ev_native_inspector::self_tree::ordinary::{Gate, Reply, Request};
    let (b, c, mut flow, scope) = reader_transfer();
    let mut app = Gate::new();
    send_reader_request(&mut flow, &mut app, scope);
    assert_eq!(flow.phase(), ReaderPhase::AwaitReply);
    let intent = Intent {
        kind: IntentKind::PreviousNode,
        index: 8,
        view: b.context.view,
    };
    app.record_reply(Some(intent), 105).unwrap();
    let mut paint = ev_native_inspector::presentation::Presentation::new();
    paint.urgent();
    // The original bug let this actual urgent desire change the accepted
    // frame before Root observed the queued ordinary callback.
    assert!(paint.ready(106) && app.holding());
    let reply = app.next().unwrap();
    assert_eq!(app.next(), Some(reply)); // actual SEND Busy retains exact word
    app.sent(reply).unwrap();
    assert!(app.holding());
    assert_eq!(
        flow.receive(
            b.owner,
            Reply::decode(reply).unwrap(),
            Some(b),
            Some(7),
            106
        )
        .unwrap(),
        ReaderOutcome::Intent(intent)
    );
    let ack = flow.next().unwrap();
    for time in [107, 300, 899] {
        flow.tick(Some(b), Some(7), time);
        assert_eq!(flow.next(), Some(ack));
        assert_eq!(flow.by(), 900);
        assert!(app.holding());
    }
    flow.sent(ack, 899).unwrap();
    // Only exact accepted Ack delivery transfers its transport custody. App
    // still holds pixels until that same original nonce is actually consumed.
    assert!(!flow.pending() && app.holding());
    app.receive(Request::decode(ack).unwrap(), None, 899, 9000)
        .unwrap();
    assert!(!app.holding() && paint.ready(899));
    assert_eq!(c.phase(), Phase::Ready);
}
#[test]
fn changed_reader_frame_publication_or_scope_rejects_before_transport_ack() {
    use ev_native_inspector::self_tree::ordinary::{Gate, Reply};
    for changed in 0..4 {
        let (b, _, mut flow, scope) = reader_transfer();
        let mut app = Gate::new();
        send_reader_request(&mut flow, &mut app, scope);
        let mut current = b;
        let mut publication = Some(7);
        match changed {
            0 => current.presented.frame += 1,
            1 => current.context.rights ^= 1,
            2 => current.window.generation += 1,
            _ => publication = Some(8),
        }
        let reply = Reply {
            nonce: scope.header.nonce,
            kind: Some(IntentKind::PreviousNode),
            index: 8,
        };
        assert_eq!(
            flow.receive(b.owner, reply, Some(current), publication, 200)
                .unwrap(),
            ReaderOutcome::Rejected
        );
        assert_eq!(flow.phase(), ReaderPhase::Acknowledge);
        assert!(flow.pending() && app.holding());
        assert_eq!(flow.binding(), Some(b));
        assert_eq!(flow.by(), 900);
        assert!(flow.receive(b.owner, reply, Some(b), Some(7), 201).is_err());
        assert_eq!(flow.phase(), ReaderPhase::Blocked);
        assert_eq!(flow.binding(), Some(b));
    }
}
#[test]
fn reader_partial_accept_unknown_and_shutdown_scope_never_return_transport_credit() {
    let (b, _, mut flow, _) = reader_transfer();
    let first = flow.next().unwrap();
    flow.sent(first, 100).unwrap();
    let second = flow.next().unwrap();
    flow.tick(None, None, 200); // physical focus/scene/shutdown changed
    assert_eq!(flow.next(), Some(second));
    assert_eq!(flow.binding(), Some(b));
    assert_eq!(flow.by(), 900);
    flow.failed(); // unclassified actual SEND: no retry or reconstructed slot
    assert_eq!(flow.next(), None);
    flow.tick(Some(b), Some(7), 10000);
    assert_eq!(flow.phase(), ReaderPhase::Blocked);
    assert!(flow.begin(b, 7, 201, 2, 0, 9, 20000).is_err());
    let (_, _, mut unsent, _) = reader_transfer();
    unsent.tick(None, None, 200);
    assert!(!unsent.pending()); // no actual word was accepted
}
#[test]
fn reader_cancel_rejects_same_batch_reply_even_before_actual_frame_changes() {
    use ev_native_inspector::self_tree::ordinary::{Gate, Reply};
    let (b, _, mut flow, scope) = reader_transfer();
    let mut app = Gate::new();
    send_reader_request(&mut flow, &mut app, scope);
    flow.tick(None, None, 150); // actual local-mode leave, before App repaint
    let reply = Reply {
        nonce: scope.header.nonce,
        kind: Some(IntentKind::PreviousNode),
        index: 8,
    };
    assert_eq!(
        flow.receive(b.owner, reply, Some(b), Some(7), 151).unwrap(),
        ReaderOutcome::Rejected
    );
    assert_eq!(flow.phase(), ReaderPhase::Acknowledge);
    assert_eq!(flow.binding(), Some(b));
    assert_eq!(flow.by(), 900);
    assert!(flow.pending() && app.holding());
}
#[test]
fn reader_wrong_nonce_early_reply_and_expiry_cannot_authorize_or_release_another_action() {
    use ev_native_inspector::self_tree::ordinary::{Gate, Reply};
    let (b, _, mut early, scope) = reader_transfer();
    let reply = Reply {
        nonce: scope.header.nonce,
        kind: Some(IntentKind::PreviousNode),
        index: 8,
    };
    assert!(
        early
            .receive(b.owner, reply, Some(b), Some(7), 100)
            .is_err()
    );
    assert_eq!(early.phase(), ReaderPhase::Blocked);
    let (b, _, mut flow, scope) = reader_transfer();
    send_reader_request(&mut flow, &mut Gate::new(), scope);
    flow.tick(Some(b), Some(7), 900);
    assert_eq!(flow.phase(), ReaderPhase::Blocked);
    assert!(flow.receive(b.owner, reply, Some(b), Some(7), 901).is_err());
    assert!(flow.next().is_none());
    assert_eq!(flow.by(), 900);
}
fn snapshot(c: &Capture, b: Binding, control: u16, flags: u8, root_flags: u8) -> Snapshot {
    let mut s = Snapshot::EMPTY;
    let h = Header {
        nonce: c.nonce,
        page: 1,
        pages: if b.context.reader { 5 } else { 4 },
        model: b.presented.model,
        view: b.presented.view,
        frame: b.presented.frame,
        mapping_epoch: b.presented.mapping_epoch,
        width: 320,
        height: 180,
        keyboard: control,
        modal: 0,
    };
    let root = Node {
        local: 1,
        parent: 0,
        role: Role::Window,
        flags: root_flags,
        actions: 0,
        label: Label::new("Inspector").unwrap(),
        bounds: Rect {
            x: 0,
            y: 0,
            width: 320,
            height: 180,
        },
        value: Value::None,
    };
    let child = Node {
        local: control,
        parent: 1,
        role: Role::Button,
        flags,
        actions: 1,
        label: Label::new("Own control").unwrap(),
        bounds: Rect {
            x: 0,
            y: 0,
            width: 30,
            height: 19,
        },
        value: Value::None,
    };
    s.replace(h, &[root, child]).unwrap();
    s
}
fn start(c: &mut Capture, b: Binding) {
    c.begin(b, 1, 8192).unwrap();
    let bytes = c.next().unwrap();
    c.sent(bytes).unwrap();
}
fn complete(
    c: &mut Capture,
    b: Binding,
    control: u16,
    flags: u8,
    root_flags: u8,
    after: Option<Binding>,
) -> Outcome {
    let s = snapshot(c, b, control, flags, root_flags);
    let mut out = Outcome::Ignored;
    for i in 0..s.frames() {
        out = c.receive(b.owner, reply(s.frame(i).unwrap()), after, 9000);
    }
    out
}
#[test]
fn only_actual_sender_complete_current_tuple_and_keyboard_control_are_usable() {
    let b = binding(false);
    let mut c = Capture::new();
    start(&mut c, b);
    let f = reply(Frame { field: 0, word: 1 });
    let mut foreign = b.owner;
    foreign.thread += 1;
    assert_eq!(c.receive(foreign, f, Some(b), 9000), Outcome::Ignored);
    assert_eq!(c.phase(), Phase::Receiving);
    assert!(c.control(b).is_none());
    assert_eq!(complete(&mut c, b, 16, 0, 0, Some(b)), Outcome::Complete);
    assert_eq!(c.control(b), Some(1));
    let mut changed = b;
    changed.owner.registered += 1;
    assert!(c.control(changed).is_none());
}
#[test]
fn every_full_tuple_source_and_provider_change_refuses_stale_publication() {
    let b = binding(true);
    let mut variants = std::vec::Vec::new();
    let mut changed = b;
    changed.presented.frame += 1;
    variants.push(changed);
    let mut changed = b;
    changed.presented.model += 1;
    variants.push(changed);
    let mut changed = b;
    changed.presented.mapping_epoch += 1;
    variants.push(changed);
    let mut changed = b;
    changed.presented.width = 300;
    variants.push(changed);
    let mut changed = b;
    changed.window.generation += 1;
    variants.push(changed);
    let mut changed = b;
    changed.context.rights = 1;
    variants.push(changed);
    let mut changed = b;
    changed.context.source = Some(b.owner);
    variants.push(changed);
    let mut changed = b;
    changed.context.source_presented = Some(b.presented);
    variants.push(changed);
    for after in variants {
        let mut c = Capture::new();
        start(&mut c, b);
        assert_eq!(complete(&mut c, b, 204, 0, 0, Some(after)), Outcome::Stale);
        assert_eq!(c.phase(), Phase::Idle);
        assert!(c.control(b).is_none());
    }
}
#[test]
fn actual_provider_generation_replacement_invalidates_old_ready_control() {
    let mut policy = crate::policy::Policy::new(
        Identity {
            process: 2,
            thread: 3,
            registered: 1,
        },
        Identity {
            process: 4,
            thread: 5,
            registered: 1,
        },
    )
    .unwrap();
    let mut b = binding(true);
    b.context.provider = Some(
        policy
            .desktop
            .provider(
                crate::policy::owner(b.owner),
                ev_workspace_shell::ProviderRights::READ,
            )
            .unwrap(),
    );
    let mut c = Capture::new();
    start(&mut c, b);
    assert_eq!(complete(&mut c, b, 204, 0, 0, Some(b)), Outcome::Complete);
    assert_eq!(c.control(b), Some(204));
    b.context.provider = Some(
        policy
            .desktop
            .provider(
                crate::policy::owner(b.owner),
                ev_workspace_shell::ProviderRights::READ,
            )
            .unwrap(),
    );
    assert!(c.control(b).is_none());
}
#[test]
fn protected_disabled_ancestor_and_confirm_controls_never_become_ordinary_enter() {
    for (reader, id, flags, ancestor) in [
        (true, 213, 0, 0),
        (true, 204, 2, 0),
        (false, 16, 1, 0),
        (false, 16, 0, 2),
        (false, 16, 0, 1),
    ] {
        let b = binding(reader);
        let mut c = Capture::new();
        start(&mut c, b);
        assert_eq!(
            complete(&mut c, b, id, flags, ancestor, Some(b)),
            Outcome::Complete
        );
        assert_eq!(c.control(b), None);
    }
}
#[test]
fn malformed_partial_stream_retains_exact_abort_until_actual_matching_ack() {
    let b = binding(false);
    let mut c = Capture::new();
    start(&mut c, b);
    c.receive(b.owner, reply(Frame { field: 0, word: 1 }), None, 9000);
    assert_eq!(
        c.receive(b.owner, reply(Frame { field: 2, word: 1 }), None, 9000),
        Outcome::Fenced
    );
    assert_eq!(c.phase(), Phase::AbortSend);
    let abort = c.next().unwrap();
    assert_eq!(Request::decode(abort), Ok(Request::Abort { nonce: 1 }));
    c.invalidate(99999);
    assert_eq!(c.by, 9000);
    assert!(c.begin(b, 1, 99999).is_err());
    c.sent(abort).unwrap();
    let mut foreign = b.owner;
    foreign.process += 1;
    let ack = reply(Frame {
        field: a1::ABORT_ACK,
        word: 1,
    });
    assert_eq!(c.receive(foreign, ack, None, 99999), Outcome::Ignored);
    assert_eq!(c.phase(), Phase::Aborting);
    assert_eq!(c.receive(b.owner, ack, None, 99999), Outcome::Aborted);
    assert_eq!(c.phase(), Phase::Idle);
    c.begin(b, 1, 99999).unwrap();
    assert_eq!(
        Request::decode(c.next().unwrap()),
        Ok(Request::Snapshot { page: 1, nonce: 2 })
    );
}
#[test]
fn expiry_never_renews_snapshot_or_drain_and_blocked_receiver_is_not_reconstructed() {
    let b = binding(false);
    let mut c = Capture::new();
    start(&mut c, b);
    c.tick(8192, 9000);
    assert_eq!(c.phase(), Phase::AbortSend);
    c.tick(8193, 99999);
    assert_eq!(c.by, 9000);
    let abort = c.next().unwrap();
    c.sent(abort).unwrap();
    c.tick(9000, 99999);
    assert_eq!(c.phase(), Phase::Blocked);
    assert_eq!(c.binding(), Some(b));
    assert!(c.next().is_none());
    assert!(c.begin(b, 1, 99999).is_err());
}
#[test]
fn unsent_request_cancellation_needs_no_fabricated_abort_and_busy_does_not_advance() {
    let b = binding(false);
    let mut c = Capture::new();
    c.begin(b, 1, 8192).unwrap();
    let held = c.next().unwrap();
    assert_eq!(c.next(), Some(held));
    let mut wrong = held;
    wrong[4] += 1;
    assert!(c.sent(wrong).is_err());
    c.invalidate(9000);
    assert_eq!(c.phase(), Phase::Idle);
    assert!(c.next().is_none());
    c.begin(b, 1, 9000).unwrap();
    assert_eq!(
        Request::decode(c.next().unwrap()),
        Ok(Request::Snapshot { page: 1, nonce: 2 })
    );
}
#[test]
fn nonce_exhaustion_fences_without_wrapping() {
    let b = binding(false);
    let mut c = Capture::new();
    c.nonce = u32::MAX - 1;
    assert!(c.begin(b, 1, 8192).is_err());
    assert_eq!(c.phase(), Phase::Blocked);
    assert!(c.next().is_none());
}

#[test]
fn preabort_inflight_words_are_retained_but_an_unsent_abort_cannot_have_a_valid_ack() {
    let b = binding(false);
    let mut c = Capture::new();
    start(&mut c, b);
    c.invalidate(9000);
    assert_eq!(c.phase(), Phase::AbortSend);
    assert_eq!(
        c.receive(b.owner, reply(Frame { field: 0, word: 1 }), None, 99999),
        Outcome::Receiving
    );
    assert_eq!(c.phase(), Phase::AbortSend);
    assert_eq!(
        c.receive(
            b.owner,
            reply(Frame {
                field: a1::ABORT_ACK,
                word: 1
            }),
            None,
            99999
        ),
        Outcome::Fenced
    );
    assert_eq!(c.phase(), Phase::Blocked);
    assert_eq!(c.binding(), Some(b));
    assert!(c.begin(b, 1, 99999).is_err());
}

#[test]
fn deferred_partial_read_cannot_publish_from_recorded_frame_when_actual_commit_changed() {
    for source_changed in [false, true] {
        let mut b = binding(true);
        b.context.source_presented = Some(b.presented);
        let mut c = Capture::new();
        start(&mut c, b);
        let s = snapshot(&c, b, 201, 0, 0);
        // No authoritative after value is supplied during the partial stream;
        // the native adapter may only keep custody from recorded local scope.
        for n in 0..s.frames() - 1 {
            assert_eq!(
                c.receive(b.owner, reply(s.frame(n).unwrap()), None, 9000),
                Outcome::Receiving
            );
            c.tick(100 + u64::from(n), 9000);
            assert_eq!(c.phase(), Phase::Receiving);
            assert_eq!(c.by, 8192);
            assert_eq!(c.control(b), None);
        }
        let mut actual = b;
        if source_changed {
            actual.context.source_presented.as_mut().unwrap().frame += 1;
        } else {
            actual.presented.frame += 1;
        }
        assert_eq!(
            c.receive(
                b.owner,
                reply(s.frame(s.frames() - 1).unwrap()),
                Some(actual),
                9000
            ),
            Outcome::Stale
        );
        assert_eq!(c.control(b), None);
        assert_eq!(c.by, 8192);
    }
}
#[test]
fn unsent_enter_expires_during_deferred_read_without_acknowledging_its_stream() {
    let b = binding(true);
    let mut c = Capture::new();
    start(&mut c, b);
    let mut enter = EnterWait::new();
    enter.request(b, 500).unwrap();
    for now in [100, 200, 499] {
        enter.expire(now);
        assert_eq!(enter.binding(), Some(b));
    }
    enter.expire(500);
    assert_eq!(enter.binding(), None);
    assert_eq!(c.phase(), Phase::Receiving);
    assert_eq!(c.binding(), Some(b));
    assert_eq!(c.by, 8192);
    c.invalidate(9000);
    c.invalidate(19000);
    assert_eq!(c.phase(), Phase::AbortSend);
    assert_eq!(c.by, 9000);
}

#[test]
fn reader_bounded_burst_and_ack_respect_the_unchanged_app_stage_ceiling() {
    use ev_native_inspector::self_tree::ordinary::{Gate, Reply, Request};
    let (b, _, mut flow, scope) = reader_transfer();
    let mut app = Gate::new();
    // Four already-fixed words need no intervening frame authority query.
    for time in 100..104 {
        let bytes = flow.next().unwrap();
        let action = app
            .receive(Request::decode(bytes).unwrap(), Some(scope), time, 612)
            .unwrap();
        flow.sent(bytes, time).unwrap();
        assert_eq!(action, (time == 103).then_some(201));
        assert_eq!(flow.by(), 900);
    }
    assert_eq!(app.by(), Some(612));
    let intent = Intent {
        kind: IntentKind::PreviousNode,
        index: 8,
        view: b.context.view,
    };
    app.record_reply(Some(intent), 104).unwrap();
    let bytes = app.next().unwrap();
    app.sent(bytes).unwrap();
    assert_eq!(
        flow.receive(
            b.owner,
            Reply::decode(bytes).unwrap(),
            Some(b),
            Some(7),
            105
        )
        .unwrap(),
        ReaderOutcome::Intent(intent)
    );
    let ack = flow.next().unwrap();
    assert!(app.holding());
    flow.sent(ack, 106).unwrap();
    app.receive(Request::decode(ack).unwrap(), None, 107, 10000)
        .unwrap();
    assert!(!app.holding() && !flow.pending());
}
#[test]
fn reader_recorded_metadata_is_only_a_veto_and_cannot_approve_a_changed_actual_frame() {
    use ev_native_inspector::self_tree::ordinary::Reply;
    for cancel in [false, true] {
        let (b, _, mut flow, scope) = reader_transfer();
        for time in 100..104 {
            let bytes = flow.next().unwrap();
            flow.sent(bytes, time).unwrap();
        }
        if cancel {
            flow.retain_recorded_scope(false, Some(7), 110);
        }
        flow.retain_recorded_scope(true, Some(7), 111);
        let mut current = b;
        if !cancel {
            current.presented.frame += 1;
        }
        assert_eq!(
            flow.receive(
                b.owner,
                Reply {
                    nonce: scope.header.nonce,
                    kind: Some(IntentKind::PreviousNode),
                    index: 8
                },
                Some(current),
                Some(7),
                112
            )
            .unwrap(),
            ReaderOutcome::Rejected
        );
        assert_eq!(flow.by(), 900);
        assert_eq!(flow.binding(), Some(b));
        assert_eq!(flow.phase(), ReaderPhase::Acknowledge);
        assert!(flow.retained_reply().is_some());
    }
}
#[test]
fn reader_late_actual_ack_send_retains_exact_delivery_reply_and_original_owner() {
    use ev_native_inspector::self_tree::ordinary::{Gate, Reply};
    let (b, _, mut flow, scope) = reader_transfer();
    send_reader_request(&mut flow, &mut Gate::new(), scope);
    let reply = Reply {
        nonce: scope.header.nonce,
        kind: Some(IntentKind::PreviousNode),
        index: 8,
    };
    assert!(matches!(
        flow.receive(b.owner, reply, Some(b), Some(7), 200).unwrap(),
        ReaderOutcome::Intent(_)
    ));
    let ack = flow.next().unwrap();
    assert!(flow.sent(ack, 900).is_err());
    assert_eq!(flow.phase(), ReaderPhase::Blocked);
    assert_eq!(flow.last_delivery(), Some(ack));
    assert_eq!(flow.retained_reply(), Some(reply));
    assert_eq!(flow.binding(), Some(b));
    assert_eq!(flow.by(), 900);
    assert!(flow.next().is_none());
    flow.retain_recorded_scope(true, Some(7), 901);
    assert!(
        flow.begin(b, 7, 201, scope.header.nonce + 1, 0, 9, 5000)
            .is_err()
    );
}
#[test]
fn reader_late_already_consumed_exact_reply_is_retained_without_ack_or_authority() {
    use ev_native_inspector::self_tree::ordinary::{Gate, Reply};
    let (b, _, mut flow, scope) = reader_transfer();
    let mut app = Gate::new();
    send_reader_request(&mut flow, &mut app, scope);
    let intent = Intent {
        kind: IntentKind::PreviousNode,
        index: 8,
        view: b.context.view,
    };
    app.record_reply(Some(intent), 200).unwrap();
    let bytes = app.next().unwrap();
    app.sent(bytes).unwrap();
    let reply = Reply::decode(bytes).unwrap();
    // Actual receive completed, then the actual full frame probe crossed by.
    assert!(flow.receive(b.owner, reply, Some(b), Some(7), 900).is_err());
    assert_eq!(flow.phase(), ReaderPhase::Blocked);
    assert_eq!(flow.retained_reply(), Some(reply));
    assert_eq!(flow.binding(), Some(b));
    assert_eq!(flow.by(), 900);
    assert!(flow.next().is_none() && app.holding());
    flow.retain_recorded_scope(true, Some(7), 901);
    assert!(
        flow.begin(b, 7, 201, scope.header.nonce + 1, 0, 9, 5000)
            .is_err()
    );
}
