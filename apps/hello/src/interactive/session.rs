// SPDX-License-Identifier: GPL-3.0-only
//! Actual note client on the existing protected Root control channel and the
//! retained AppFile page. One loan serializes note exchange and File RPCs.
use super::*;
use ev_app_registry::note_data::NoteDataEnvelope;
use ev_graphics::session::{Focus, SaveState, View};
use ev_input::{pointer::PositionEvent, text::TextEvent};
use ev_native_hello::editor::{Editor, State as EditState};
use ev_userspace_contract::session_note::{Client, Completion, Operation, Outcome};

pub(super) struct State {
    editor: Editor,
    client: Client,
    focus: Focus,
    window: Option<FileWindow>,
    #[cfg(feature = "startup-health")]
    critical_sent: bool,
}
impl State {
    pub(super) const fn new() -> Self {
        Self {
            editor: Editor::new(),
            client: Client::new(),
            focus: Focus::Note,
            window: None,
            #[cfg(feature = "startup-health")]
            critical_sent: false,
        }
    }
}
impl App {
    #[cfg(feature = "document-workflow")]
    pub(super) fn document_startup_ready(&self) -> bool {
        #[cfg(feature = "startup-health")]
        {
            self.session.critical_sent
        }
        #[cfg(not(feature = "startup-health"))]
        {
            true
        }
    }
    pub(super) fn session_paint(&mut self) -> Result<(), ev_graphics::Error> {
        let state = match self.session.editor.state() {
            EditState::Loading => SaveState::Loading,
            EditState::Saved => SaveState::Saved,
            EditState::Unsaved => SaveState::Unsaved,
            EditState::Saving => SaveState::Saving,
            EditState::Unavailable => SaveState::Unavailable,
            EditState::Busy => SaveState::Busy,
        };
        ev_graphics::session::render(
            &mut self.surface,
            View {
                build: ev_native_hello::build(),
                focus: self.session.focus,
                note: self.session.editor.bytes(),
                state,
                file: self.content.as_ref().map(Payload::as_slice),
            },
        )
    }
    fn note_start(&mut self, operation: Operation, proposal: Option<NoteDataEnvelope>) {
        if self.pending || !self.session.client.page_available() {
            return;
        }
        // Independent finite client wait. Expiry quarantines the page; it is
        // not evidence that a received Root request stopped touching it.
        let deadline = match now().checked_add(20_480).filter(|d| *d != u64::MAX) {
            Some(d) => d,
            None => {
                self.session.editor.failed();
                return;
            }
        };
        let request = match self.session.client.prepare(operation, now(), deadline) {
            Ok(r) => r,
            Err(_) => {
                self.session.editor.failed();
                return;
            }
        };
        let window = self.session.window.as_ref().unwrap_or(&self.window);
        window.guards();
        if let Some(proposal) = proposal {
            if let Some(window) = self.session.window.as_mut() {
                window.publish(&proposal.encode());
            } else {
                self.window.publish(&proposal.encode());
            }
        }
        loop {
            let sent = rt::send(self.events, request.encode());
            if sent.capability != 0 || sent.value != 0 {
                self.session.client.quarantine();
                self.session.editor.failed();
                return;
            }
            match sent.status {
                0 => {
                    if self.session.client.accepted(request, now()).is_err() {
                        self.session.editor.failed();
                    }
                    return;
                }
                2 => {
                    if self.session.client.retry_unaccepted(now()).is_err() {
                        self.session.editor.failed();
                        return;
                    }
                    yield_now();
                }
                _ => {
                    let _ = self.session.client.rejected_unaccepted(request, now());
                    self.session.editor.failed();
                    return;
                }
            }
        }
    }
    pub(super) fn session_read(&mut self) {
        self.note_start(Operation::Read, None);
    }
    pub(super) fn session_window(&mut self, record: u64, dedicated: bool) {
        if dedicated {
            self.session.window = Some(FileWindow::note_at(record, true));
        }
    }
    pub(super) fn session_poll(&mut self) {
        if self.session.editor.state() == EditState::Unavailable {
            return;
        }
        if self.session.client.poll(now()).is_err() {
            self.session.editor.failed();
            self.render();
        }
    }
    fn session_activate(&mut self) {
        match self.session.focus {
            Focus::Note => {}
            Focus::Save => {
                if self.pending || !self.session.client.page_available() {
                    return;
                }
                if self.session.editor.retry_read() {
                    self.note_start(Operation::Read, None);
                    self.render();
                } else if let Ok(proposal) = self.session.editor.prepare_save() {
                    self.note_start(Operation::Write, Some(proposal));
                    self.render();
                }
            }
            Focus::OpenFile => {
                if !self.pending && self.session.client.page_available() {
                    self.pending = true;
                    event(self.events, *b"EVOPEN01", self.stop);
                }
            }
            Focus::CrashMe => {
                event(self.events, *b"EVCRASH1", self.stop);
                // SAFETY: deliberate ordinary-user fault in this App's absent
                // aperture. Kernel returns its actual stopped owner before reap.
                let value =
                    unsafe { ((self.base + 4 * 1024 * 1024) as *const u32).read_volatile() };
                rt::exit(846 + u64::from(value));
            }
        }
    }
    pub(super) fn session_control(&mut self, bytes: [u8; 8]) -> bool {
        if bytes[..2] == *b"NT" {
            let proposed = self.session.editor.proposed();
            let window = self.session.window.as_ref().unwrap_or(&self.window);
            let result = self.session.client.accept(&bytes, 0, now(), |outcome| {
                let actual = NoteDataEnvelope::decode(&window.snapshot()).map_err(|_| ())?;
                if actual.app().bytes() != ev_native_hello::APP_ID {
                    return Err(());
                }
                if outcome == Outcome::Written && proposed != Some(actual) {
                    return Err(());
                }
                Ok(actual)
            });
            #[cfg(feature = "startup-health")]
            let mut initial_ready = false;
            let valid = match result {
                Ok(Completion::Read(note)) => {
                    let loaded = self.session.editor.loaded(note).is_ok();
                    #[cfg(feature = "startup-health")]
                    {
                        initial_ready = loaded;
                    }
                    loaded
                }
                Ok(Completion::Written(note)) => self.session.editor.saved(note).is_ok(),
                Ok(Completion::Refused(ev_userspace_contract::session_note::Refusal::Busy)) => {
                    self.session.editor.busy().is_ok()
                }
                _ => false,
            };
            if !valid {
                self.session.editor.failed();
            }
            self.render();
            #[cfg(feature = "startup-health")]
            if initial_ready && !self.session.critical_sent {
                // Startup/grant validation and the scalar read already passed.
                // This Note read is bound to its protected sender/nonce/body;
                // render returned after actual Present completion. Root still
                // requires its own probe and fresh whole-cohort liveness.
                self.session.critical_sent = true;
                event(self.events, *b"EVAPCRD1", self.stop);
            }
            return true;
        }
        if bytes[0] == b'T' {
            let Ok(text) = TextEvent::decode(bytes) else {
                return true;
            };
            if text.sequence <= self.last_key {
                return true;
            }
            self.last_key = text.sequence;
            if self.session.focus == Focus::Note {
                let _ = self.session.editor.edit(text.text);
                self.render();
            }
            return true;
        }
        if bytes[0] == b'M' {
            let Ok(pointer) = PositionEvent::decode(bytes) else {
                return true;
            };
            if pointer.sequence <= self.last_key {
                return true;
            }
            self.last_key = pointer.sequence;
            if pointer.fresh_left_press {
                let view = ev_graphics::composition::SESSION_APP_VIEW;
                let (x, y) = (usize::from(pointer.x), usize::from(pointer.y));
                if view.contains(x, y)
                    && let Some(focus) = ev_graphics::session::hit_test(x - view.x, y - view.y)
                {
                    self.session.focus = focus;
                    self.render();
                    self.session_activate();
                }
            }
            return true;
        }
        if let Ok(ShellCommand::Forward(key)) = ShellCommand::decode(bytes) {
            if key.sequence <= self.last_key {
                return true;
            }
            self.last_key = key.sequence;
            match key.key {
                Key::Tab | Key::Down | Key::Up => {
                    self.session.focus = self.session.focus.next(key.key == Key::Up);
                    self.render();
                }
                Key::Enter => self.session_activate(),
                Key::Escape | Key::Left | Key::Right => {}
            }
            return true;
        }
        false
    }
}
