//! Native document actor. The actual selected endpoint fixes object and access;
//! semantic metadata and counters never grant authority. Frame loans serialize
//! with File calls even on V3, where the semantic and File pages alias.
use super::*;
use ev_input::text::Text;
use ev_native_hello::{
    document::{Editor, Navigate, Navigation},
    document_control::Client,
};
use ev_userspace_contract::{
    document::{Access, Feedback, Focus, State as ViewState},
    document_control::Operation,
};

pub(super) struct State {
    editor: Editor,
    started: bool,
    pub(super) window: Option<FileWindow>,
    client: Client,
    publish_needed: bool,
    save_requested: bool,
    navigation: Option<Navigation>,
    io_quarantined: bool,
    wait_reported: bool,
}
impl State {
    pub const fn new() -> Self {
        Self {
            window: None,
            editor: Editor::new(),
            started: !cfg!(feature = "startup-health"),
            client: Client::new(),
            publish_needed: true,
            save_requested: false,
            navigation: None,
            io_quarantined: false,
            wait_reported: false,
        }
    }
}
impl App {
    pub(super) fn document_paint(&mut self) -> Result<(), ev_graphics::Error> {
        if !self.document.started {
            return self.session_paint();
        }
        let snapshot = self.document.editor.snapshot();
        let result = ev_graphics::document::render(&mut self.surface, &snapshot);
        self.document.publish_needed = true;
        result
    }
    fn document_window(&mut self) -> &mut FileWindow {
        self.document.window.as_mut().unwrap_or(&mut self.window)
    }
    fn document_send(&mut self, bytes: [u8; 8]) {
        // Definitely-unaccepted Busy may retry identical bytes under one cut.
        // Other outcomes retain the client's frame loan until exact ACK/reap.
        let cut = rt::execution::deadline(self.stop, now(), 512).unwrap_or_else(|_| rt::exit(893));
        loop {
            let reply = rt::send(self.events, bytes);
            if reply.status == 0 && reply.value == 0 && reply.capability == 0 {
                return;
            }
            if reply.status != 2 || reply.value != 0 || reply.capability != 0 || now() >= cut {
                self.document.editor.failed(Feedback::Uncertain);
                self.render();
                return;
            }
            yield_now();
        }
    }
    fn document_io(&mut self, cap: u64, request: Request) -> Option<Response> {
        if self.document.io_quarantined || !self.document.client.frame_available() {
            return None;
        }
        self.window.guards();
        self.window.publish(&request.encode());
        let cut = rt::execution::deadline(self.stop, now(), 8192).unwrap_or_else(|_| rt::exit(893));
        match rt::rpc::call(cap, CALL, cut) {
            Ok(reply) if reply == REPLY => {
                self.window.guards();
                match Response::decode(&self.window.snapshot()) {
                    Ok(response) => Some(response),
                    Err(_) => {
                        self.document.io_quarantined = true;
                        None
                    }
                }
            }
            _ => {
                self.document.io_quarantined = true;
                None
            }
        }
    }
    pub(super) fn document_selected(&mut self, bytes: [u8; 8], cap: u64) {
        let granted = self.document.client.grant(&bytes, 1);
        let inspect = rt::inspect(cap, 8);
        let exact = inspect.status == 0
            && inspect.capability == 0
            && [1, 2, 4, 16, 32, 64, 128, 256].into_iter().all(|rights| {
                let r = rt::inspect(cap, rights);
                r.status == 1 && r.value == 0 && r.capability == 0
            });
        let Ok(granted) = granted else {
            let _ = rt::call(rt::syscall::CLOSE, cap, 0, 0);
            return;
        };
        if !exact {
            let _ = rt::call(rt::syscall::CLOSE, cap, 0, 0);
            self.document.editor.failed(Feedback::Denied);
            self.render();
            return;
        }
        match self.document_io(cap, Request::Read) {
            Some(Response::Read { counter, payload }) => {
                if self
                    .document
                    .editor
                    .open(granted.choice(), granted.access(), counter, &payload)
                    .is_ok()
                {
                    if let Some(old) = self.file.replace(cap) {
                        let _ = rt::call(rt::syscall::CLOSE, old, 0, 0);
                    }
                } else {
                    let _ = rt::call(rt::syscall::CLOSE, cap, 0, 0);
                    self.document.editor.failed(Feedback::UnsupportedText);
                }
                event(self.events, *b"EVFILRD1", self.stop);
            }
            _ => {
                // A timeout is not proof that File stopped touching the page.
                // Retain both actual endpoint and page through App retirement.
                if self.document.io_quarantined {
                    self.file = Some(cap);
                } else {
                    let _ = rt::call(rt::syscall::CLOSE, cap, 0, 0);
                }
                self.document.editor.failed(Feedback::Storage);
                event(self.events, *b"EVFILRD1", self.stop);
            }
        }
        self.pending = false;
        self.render();
    }
    pub(super) fn document_poll(&mut self) {
        if !self.document.started {
            return;
        }

        if self.document.client.poll(now()).is_err() {
            if !self.document.wait_reported {
                self.document.wait_reported = true;
                self.document.editor.failed(Feedback::Uncertain);
                self.render();
            }
            return;
        }
        if self.document.client.busy() || self.document.io_quarantined {
            return;
        }
        if let Some(navigation) = self.document.navigation.take() {
            match navigation {
                Navigation::Close => {
                    if let Some(cap) = self.file.take() {
                        let _ = rt::call(rt::syscall::CLOSE, cap, 0, 0);
                    }
                    let _ = self.document.editor.closed();
                    self.render();
                }
                Navigation::Open | Navigation::OpenRead => {
                    if self.document.editor.selecting().is_ok() {
                        // Editing always requests separate explicit consent.
                        if let Ok(request) =
                            self.document
                                .client
                                .open(if navigation == Navigation::OpenRead {
                                    Access::Read
                                } else {
                                    Access::Edit
                                })
                        {
                            self.pending = true;
                            self.document_send(request.encode());
                            self.render();
                        }
                    }
                }
            }
            return;
        }
        if self.document.save_requested {
            self.document.save_requested = false;
            if let (Some(cap), Ok(proposal)) = (self.file, self.document.editor.prepare_save()) {
                self.render();
                match self.document_io(cap, proposal.request()) {
                    Some(response) => {
                        let _ = self.document.editor.acknowledge(response);
                    }
                    None => self.document.editor.failed(Feedback::Uncertain),
                }
                if self.document.editor.snapshot().state == ViewState::Readback {
                    self.render();
                    match self.document_io(cap, Request::Read) {
                        Some(Response::Read { counter, payload }) => {
                            let _ = self.document.editor.readback(counter, &payload);
                        }
                        _ => self.document.editor.failed(Feedback::Uncertain),
                    }
                }
                self.render();
            }
            return;
        }
        if self.document.publish_needed {
            let cut =
                rt::execution::deadline(self.stop, now(), 512).unwrap_or_else(|_| rt::exit(893));
            if let Ok(request) = self.document.client.publish(now(), cut) {
                let bytes = self
                    .document
                    .editor
                    .snapshot()
                    .encode()
                    .unwrap_or_else(|_| rt::exit(894));
                self.document_window().publish(&bytes);
                self.document.publish_needed = false;
                self.document_send(request.encode());
            }
        }
    }
    fn document_activate(&mut self) {
        let view = self.document.editor.snapshot();
        if !ev_graphics::document::enabled(&view, view.focus) {
            return;
        }
        match view.focus {
            Focus::Text => {
                let _ = self.document.editor.insert("\n");
            }
            Focus::SelectAll => {
                let _ = self.document.editor.select_all();
            }
            Focus::Save => self.document.save_requested = true,
            Focus::Open | Focus::OpenRead | Focus::Close => {
                let action = match view.focus {
                    Focus::Open => Navigation::Open,
                    Focus::OpenRead => Navigation::OpenRead,
                    _ => Navigation::Close,
                };
                if let Ok(Navigate::Ready(action)) = self.document.editor.navigate(action) {
                    self.document.navigation = Some(action);
                }
            }
            Focus::KeepEditing => {
                let _ = self.document.editor.keep_editing();
            }
            Focus::Discard => {
                if let Ok(action) = self.document.editor.discard() {
                    self.document.navigation = Some(action);
                }
            }
        }
        self.render();
    }
    pub(super) fn document_control(&mut self, bytes: [u8; 8]) -> bool {
        if ev_userspace_contract::document_test::Command::decode(&bytes, 0).is_ok() {
            event(self.events, *b"EVCRASH1", self.stop);
            // SAFETY: explicit Root-owner diagnostic for THIS ordinary App.
            // The measured App root leaves this device aperture absent; the
            // real contained PF14 is observed independently by the Kernel.
            let value = unsafe { ((self.base + 4 * 1024 * 1024) as *const u32).read_volatile() };
            rt::exit(846 + u64::from(value));
        }
        if bytes[..2] == *b"DA" {
            let opening = self
                .document
                .client
                .pending_request()
                .is_some_and(|r| r.operation() != Operation::Publish);
            if let Ok(completion) = self.document.client.reply(&bytes, 0, now()) {
                self.document.wait_reported = false;
                if opening {
                    self.pending = false;
                    let reason = match completion {
                        ev_native_hello::document_control::Completion::Refused {
                            outcome: ev_userspace_contract::document_control::Outcome::Cancelled,
                            ..
                        } => Feedback::None,
                        ev_native_hello::document_control::Completion::Refused {
                            outcome: ev_userspace_contract::document_control::Outcome::Busy,
                            ..
                        } => Feedback::Busy,
                        _ => Feedback::Denied,
                    };
                    self.document.editor.selection_refused(reason);
                    self.render();
                }
            }
            return true;
        }
        if let Ok(RootControl::InputRestarted(_)) = RootControl::decode(bytes) {
            self.last_key = 0;
            return true;
        }
        let Ok(command) = ShellCommand::decode(bytes) else {
            return false;
        };
        match command {
            ShellCommand::Repaint => {
                if self.document_startup_ready() {
                    self.document.started = true;
                }
                self.render();
            }
            ShellCommand::Forward(key) => {
                if key.sequence <= self.last_key {
                    return true;
                }
                self.last_key = key.sequence;
                let view = self.document.editor.snapshot();
                match key.key {
                    Key::Tab => {
                        let _ = self
                            .document
                            .editor
                            .focus(ev_graphics::document::next_focus(&view, false));
                        self.render();
                    }
                    Key::Enter => self.document_activate(),
                    Key::Left | Key::Right if view.focus == Focus::Text => {
                        let _ = self.document.editor.horizontal(key.key == Key::Right);
                        self.render();
                    }
                    Key::Up | Key::Down if view.focus == Focus::Text => {
                        if let Some(point) =
                            ev_graphics::document::position(&view.text, usize::from(view.cursor))
                        {
                            let row = if key.key == Key::Up {
                                point.row.saturating_sub(1)
                            } else {
                                point.row + 1
                            };
                            let offset =
                                ev_graphics::document::offset_at(&view.text, row, point.column);
                            let _ = self.document.editor.move_cursor(offset, false);
                            self.render();
                        }
                    }
                    _ => (),
                }
            }
            ShellCommand::Text(text) => {
                if text.sequence <= self.last_key {
                    return true;
                }
                self.last_key = text.sequence;
                if self.document.editor.snapshot().focus == Focus::Text {
                    match text.text {
                        Text::Ascii(byte) => {
                            let bytes = [byte];
                            let _ = self
                                .document
                                .editor
                                .insert(core::str::from_utf8(&bytes).unwrap());
                        }
                        Text::Backspace => {
                            let _ = self.document.editor.backspace();
                        }
                    }
                    self.render();
                }
            }
            ShellCommand::Pointer(pointer) => {
                if pointer.sequence <= self.last_key {
                    return true;
                }
                self.last_key = pointer.sequence;
                let area = ev_graphics::composition::SESSION_APP_VIEW;
                let (x, y) = (usize::from(pointer.x), usize::from(pointer.y));
                if pointer.fresh_left_press && area.contains(x, y) {
                    let view = self.document.editor.snapshot();
                    let (x, y) = (x - area.x, y - area.y);
                    if let Some(focus) = ev_graphics::document::hit_test(&view, x, y) {
                        let _ = self.document.editor.focus(focus);
                        if focus == Focus::Text {
                            if let Some(at) = ev_graphics::document::pointer_offset(&view, x, y) {
                                let _ = self.document.editor.move_cursor(at, false);
                            }
                            self.render();
                        } else {
                            self.document_activate();
                        }
                    }
                }
            }
            _ => return false,
        }
        true
    }
}
