//! Process-private native A1 operation custody. Only Root's selected control
//! channel supplies requests; consumer identities/rights never come from wire.
use super::*;
use a1::operation as op;

// A bounded process-private256-byte response stays resident without an allocator.
#[allow(clippy::large_enum_variant)]
enum Reply {
    Word(a1::Frame),
    Range {
        reply: op::RangeReply,
        ordinal: u16,
        nonce: u32,
    },
    AfterPresent {
        nonce: u32,
        frame: u64,
        cancelled: Option<ev_workspace_editor::Proposal>,
    },
}
pub(super) struct Operations {
    input: op::Receiver,
    pending_snapshot: Option<a1::Header>,
    committed_snapshot: Option<a1::Header>,
    reply: Option<Reply>,
}
impl Operations {
    pub(super) const fn new() -> Self {
        Self {
            input: op::Receiver::new(),
            pending_snapshot: None,
            committed_snapshot: None,
            reply: None,
        }
    }
    pub(super) fn busy(&self) -> bool {
        self.reply.is_some()
    }
    pub(super) fn snapshot_started(&mut self, header: a1::Header) {
        self.pending_snapshot = Some(header);
    }
    pub(super) fn snapshot_sent(&mut self, frame: a1::Frame) {
        if frame.field == a1::COMMIT && self.pending_snapshot.is_some_and(|h| h.nonce == frame.word)
        {
            self.committed_snapshot = self.pending_snapshot.take();
        } else if frame.field == a1::ABORT_ACK {
            self.pending_snapshot = None;
            if self
                .committed_snapshot
                .is_some_and(|h| h.nonce == frame.word)
            {
                self.committed_snapshot = None;
            }
        }
    }
    fn terminal(&mut self, n: u32, r: Result<(), op::Refusal>) {
        self.reply = Some(Reply::Word(op::terminal(n, r)));
    }
    pub(super) fn next(
        &mut self,
        accepted: bool,
        paint: bool,
        current_frame: u64,
        cancelled_save: Option<ev_workspace_editor::Proposal>,
    ) -> Option<a1::Frame> {
        if let Some(Reply::AfterPresent {
            nonce,
            frame,
            cancelled,
        }) = self.reply
            && accepted
            && !paint
            && current_frame > frame
        {
            self.terminal(
                nonce,
                if cancelled.is_none_or(|p| cancelled_save == Some(p)) {
                    Ok(())
                } else {
                    Err(op::Refusal::Busy)
                },
            );
        }
        match self.reply.as_ref() {
            Some(Reply::Word(f)) => Some(*f),
            Some(Reply::Range { reply, ordinal, .. }) => reply.frame(*ordinal),
            _ => None,
        }
    }
    pub(super) fn sent(&mut self, offered: a1::Frame) {
        match self.reply.as_mut() {
            Some(Reply::Word(f)) if *f == offered => self.reply = None,
            Some(Reply::Range { reply, ordinal, .. }) if reply.frame(*ordinal) == Some(offered) => {
                *ordinal += 1;
                if *ordinal == 68 {
                    self.reply = None;
                }
            }
            _ => rt::exit(1425),
        }
    }
}
fn context(app: &App, binding: op::Binding) -> bool {
    let h = app.surface.header;
    app.ops
        .committed_snapshot
        .is_some_and(|s| binding.matches(s))
        && app.semantic_accepted
        && !app.paint
        && app.scene_ready
        && !app.surface.fenced
        && binding.model == h.model_revision
        && binding.view == h.view_revision
        && binding.frame == h.frame
        && binding.mapping_epoch == h.mapping_epoch
}
pub(super) fn control(app: &mut App, frame: a1::Frame, events: u64, bound: u64) {
    // One operation at a time. A second Begin cannot replace a retained reply;
    // Root must finish/drain the original nonce or explicitly abort that nonce.
    if frame.field == 0x8100 && app.ops.reply.is_some() {
        return;
    }
    let result = app.ops.input.push(frame);
    let request = match result {
        Ok(op::Progress::Complete(q)) => q,
        Ok(op::Progress::Aborted(n)) => {
            let owns = match app.ops.reply.as_ref() {
                Some(Reply::Word(f)) => f.word == n,
                Some(Reply::Range { nonce, .. }) | Some(Reply::AfterPresent { nonce, .. }) => {
                    *nonce == n
                }
                None => true,
            };
            if owns {
                app.ops.reply = Some(Reply::Word(a1::Frame {
                    field: op::ABORT_ACK,
                    word: n,
                }));
            }
            // Abort terminates retained protocol work; it cannot undo an action.
            return;
        }
        _ => return,
    };
    if !context(app, request.binding) {
        app.ops.terminal(request.nonce, Err(op::Refusal::Stale));
        return;
    }
    match request.kind {
        op::Kind::Range {
            kind,
            offset,
            length,
        } => {
            if request.binding.text_revision != app.surface.header.view_revision {
                app.ops.terminal(request.nonce, Err(op::Refusal::Stale));
                return;
            }
            let text = match (request.node, kind) {
                (3, op::RangeKind::Document) => app.editor.as_ref().map(Editor::text),
                (5, op::RangeKind::AccessibleLabel) => {
                    app.selection.as_ref().map(|s| s.name.as_str())
                }
                _ => None,
            };
            let reply = text
                .ok_or(a1::Error::Field)
                .and_then(|s| op::text_range(s, offset, length))
                .and_then(|s| op::RangeReply::new(request.nonce, request.node, kind, s));
            match reply {
                Ok(reply) => {
                    app.ops.reply = Some(Reply::Range {
                        reply,
                        ordinal: 0,
                        nonce: request.nonce,
                    })
                }
                Err(_) => app.ops.terminal(request.nonce, Err(op::Refusal::Denied)),
            }
        }
        op::Kind::Action { action, argument } => {
            let view = ev_native_editor::View {
                editor: app.editor.as_ref(),
                name: None,
                state: app.state(),
                start: app.start,
                focused: app.focused,
            };
            let writable = app
                .selection
                .as_ref()
                .is_some_and(|s| s.access == Access::ReadWrite);
            if ev_native_editor::semantic::actions(view, writable, request.node)
                & (1 << (action as u8))
                == 0
            {
                app.ops.terminal(request.nonce, Err(op::Refusal::Denied));
                return;
            }
            let before = app.surface.header.frame;
            let cancelled = (request.node == 19 && app.cancel_presented)
                .then(|| {
                    app.editor
                        .as_ref()
                        .and_then(Editor::pending)
                        .map(|p| p.proposal)
                })
                .flatten();
            let ok = match action {
                op::Action::Activate => match request.node {
                    16 => {
                        notify(events, Event::Open, bound);
                        true
                    }
                    17 => app.start_save(bound).is_ok(),
                    18 => {
                        notify(events, Event::SaveAs, bound);
                        true
                    }
                    19 if app.cancel_presented => app.cancel_save().is_ok(),
                    19 => {
                        match app.editor.as_ref().map_or(Close::Ready, Editor::close) {
                            Close::RecoveryRequired => false,
                            Close::ConfirmDiscard => {
                                notify(events, Event::CloseNeedsDiscard, bound);
                                true
                            }
                            Close::Ready => {
                                if let Some(mut file) = app.file.take()
                                    && file.close_quiescent().is_err()
                                {
                                    app.file = Some(file);
                                    app.failed();
                                    false
                                } else {
                                    notify(events, Event::Closed, bound);
                                    // The local file is closed and the actual Closed intent
                                    // is queued. Root still observes/reaps the real process.
                                    let ack = op::terminal(request.nonce, Ok(()));
                                    let limit = rt::execution::deadline(bound, now(), 512)
                                        .unwrap_or_else(|_| rt::exit(1426));
                                    loop {
                                        let r = rt::send(events, ack.encode());
                                        require(r.value == 0 && r.capability == 0, 1427);
                                        if r.status == 0 {
                                            break;
                                        }
                                        require(r.status == 2 && now() < limit, 1428);
                                        let _ = rt::yield_now();
                                    }
                                    rt::exit(0)
                                }
                            }
                        }
                    }
                    _ => false,
                },
                // Actual window/keyboard focus belongs to Root. This operation
                // only confirms an already focused document; it never steals it.
                op::Action::Focus => request.node == 3 && app.focused,
                op::Action::Select => {
                    let valid = request.node == 3
                        && request.binding.text_revision == app.surface.header.view_revision;
                    let selected = valid
                        && app.editor.as_mut().is_some_and(|e| {
                            e.select((argument >> 32) as usize, argument as u32 as usize)
                                .is_ok()
                        });
                    if selected {
                        app.follow_caret = true;
                        app.bump_view();
                    }
                    selected
                }
                op::Action::Scroll => {
                    app.control(Command::Scroll(argument as i64 as i16), events, bound);
                    true
                }
                _ => false,
            };
            if !ok {
                app.ops.terminal(request.nonce, Err(op::Refusal::Denied));
            } else if app.paint {
                app.ops.reply = Some(Reply::AfterPresent {
                    nonce: request.nonce,
                    frame: before,
                    cancelled,
                });
            } else {
                app.ops.terminal(request.nonce, Ok(()));
            }
        }
    }
}
