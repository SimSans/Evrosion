//! Ordinary native Hello. It starts with no File endpoint and cannot name a
//! file globally. Only actual selected-cap delivery permits the File RPC.
use crate::{event, grant, now, require, yield_now};
use ev_desktop::protocol::{RootControl, ShellCommand};
use ev_graphics::{HelloControl, HelloView, Present, native};
use ev_input::Key;
use ev_userspace_contract::app_data;
use ev_userspace_contract::{
    file::{Payload, Request, Response},
    file_test::{CALL, REPLY},
};
use ev_userspace_graphics::Surface;
use ev_userspace_runtime as rt;
#[cfg(feature = "document-workflow")]
mod document;
#[cfg(feature = "network-negative-probe")]
mod negative;
#[cfg(feature = "native-session")]
mod session;

struct FileWindow {
    address: usize,
}
impl FileWindow {
    fn is_zero(&self) -> bool {
        for index in 0..4096 {
            // SAFETY: exact newly mapped initialized App/File page. No App call
            // has been issued; File is forbidden to access an idle App window.
            if unsafe { (self.address as *const u8).add(index).read_volatile() } != 0 {
                return false;
            }
        }
        true
    }
    fn at(record: u64) -> Self {
        Self {
            address: usize::try_from(record.checked_sub(4096).unwrap_or_else(|| rt::exit(830)))
                .unwrap_or_else(|_| rt::exit(831)),
        }
    }
    #[cfg(feature = "native-session")]
    fn note_at(record: u64, dedicated: bool) -> Self {
        Self {
            address: usize::try_from(
                record
                    .checked_sub(if dedicated { 2 * 4096 } else { 4096 })
                    .unwrap_or_else(|| rt::exit(830)),
            )
            .unwrap_or_else(|_| rt::exit(831)),
        }
    }
    fn publish(&mut self, bytes: &[u8; 256]) {
        for (index, byte) in bytes.iter().copied().enumerate() {
            // SAFETY: exact initialized prebound App/File window, sole App
            // thread, no pending File call or retained shared Rust reference.
            unsafe { (self.address as *mut u8).add(index).write_volatile(byte) };
        }
    }
    fn snapshot(&self) -> [u8; 256] {
        core::array::from_fn(|index| {
            // SAFETY: actual File reply has released this App's fixed window;
            // copy exactly256 bytes into private storage before any next call.
            unsafe { (self.address as *const u8).add(index).read_volatile() }
        })
    }
    fn guards(&self) {
        for index in 256..4096 {
            // SAFETY: remaining initialized bytes in this same retained page.
            require(
                unsafe { (self.address as *const u8).add(index).read_volatile() } == 0,
                832,
            );
        }
    }
    fn read_snapshot(&mut self, cap: u64, stop: u64) -> (u64, Payload) {
        self.guards();
        self.publish(&Request::Read.encode());
        let deadline = rt::execution::deadline(stop, now(), if stop == 0 { 8192 } else { 512 })
            .ok()
            .unwrap_or_else(|| rt::exit(858));
        let reply = rt::rpc::call(cap, CALL, deadline).unwrap_or_else(|_| rt::exit(833));
        require(reply == REPLY, 833);
        self.guards();
        match Response::decode(&self.snapshot()).unwrap_or_else(|_| rt::exit(834)) {
            Response::Read { counter, payload } => (counter, payload),
            _ => rt::exit(835),
        }
    }
    fn read(&mut self, cap: u64, stop: u64) -> Payload {
        self.read_snapshot(cap, stop).1
    }
    fn prove_read_only(&mut self, cap: u64, stop: u64) -> Payload {
        let before = self.read_snapshot(cap, stop);
        self.publish(
            &Request::Replace {
                counter: before
                    .0
                    .checked_add(1)
                    .filter(|n| *n != u64::MAX)
                    .unwrap_or_else(|| rt::exit(870)),
                payload: Payload::new(b"UNAUTHORIZED REPLACEMENT").unwrap(),
            }
            .encode(),
        );
        let deadline = rt::execution::deadline(stop, now(), if stop == 0 { 8192 } else { 512 })
            .ok()
            .unwrap_or_else(|| rt::exit(858));
        let reply = rt::rpc::call(cap, CALL, deadline).unwrap_or_else(|_| rt::exit(871));
        require(reply == REPLY, 872);
        self.guards();
        let denied = Response::decode(&self.snapshot()).unwrap_or_else(|_| rt::exit(873));
        require(ev_native_hello::read_only_refused(denied), 874);
        let after = self.read_snapshot(cap, stop);
        require(ev_native_hello::unchanged_file(&before, &after), 875);
        after.1
    }
}
struct App {
    #[cfg(feature = "document-workflow")]
    document: document::State,
    surface: Surface,
    window: FileWindow,
    present: u64,
    events: u64,
    stop: u64,
    frame: u32,
    focus: HelloControl,
    content: Option<Payload>,
    pending: bool,
    file: Option<u64>,
    last_key: u32,
    base: u64,
    saved_value: u32,
    data: app_data::Client,
    #[cfg(feature = "native-session")]
    session: session::State,
}
impl App {
    fn paint(&mut self) -> Result<(), ev_graphics::Error> {
        #[cfg(feature = "document-workflow")]
        if self.stop == 0 {
            return self.document_paint();
        }
        #[cfg(feature = "native-session")]
        if self.stop == 0 {
            return self.session_paint();
        }
        native::render(
            &mut self.surface,
            native::View {
                hello: HelloView {
                    focus: self.focus,
                    content: self.content.as_ref().map(Payload::as_slice),
                    incarnation: 1,
                },
                build: ev_native_hello::build(),
                saved_value: self.saved_value,
            },
        )
    }
    fn render(&mut self) {
        let frame = self
            .frame
            .checked_add(1)
            .filter(|n| *n != u32::MAX)
            .unwrap_or_else(|| rt::exit(836));
        self.paint().unwrap_or_else(|_| rt::exit(837));
        self.surface
            .publish(u64::from(frame))
            .unwrap_or_else(|_| rt::exit(876));
        require(self.surface.valid_tail(), 877);
        require(
            self.surface
                .try_header()
                .is_ok_and(|h| h.sequence == u64::from(frame)),
            838,
        );
        let present = Present(frame);
        let deadline = rt::execution::deadline(self.stop, now(), 512)
            .ok()
            .unwrap_or_else(|| rt::exit(858));
        let reply = rt::rpc::call(self.present, present.request().unwrap(), deadline)
            .unwrap_or_else(|_| rt::exit(839));
        require(Present::parse_reply(reply) == Ok(present), 839);
        self.frame = frame;
        event(self.events, *b"EVGADON1", self.stop);
    }
    fn selected(&mut self, cap: u64) {
        require(self.pending, 840);
        let inspect = rt::inspect(cap, 8);
        require(inspect.status == 0 && inspect.capability == 0, 841);
        // Selected grants are exactly SEND. App cannot transfer or derive this
        // endpoint, turn it into a write route, or address a sibling file.
        for rights in [1, 2, 4, 16, 32, 64, 128, 256] {
            let denied = rt::inspect(cap, rights);
            require(
                denied.status == 1 && denied.value == 0 && denied.capability == 0,
                842,
            );
        }
        if let Some(old) = self.file.replace(cap) {
            let closed = rt::call(rt::syscall::CLOSE, old, 0, 0);
            require(
                closed.status == 0 && closed.value == 0 && closed.capability == 0,
                843,
            );
        }
        self.content = Some(self.window.prove_read_only(cap, self.stop));
        event(self.events, *b"EVFLRO01", self.stop);
        self.pending = false;
        event(self.events, *b"EVFILRD1", self.stop);
        self.render();
    }
    fn control(&mut self, bytes: [u8; 8]) {
        #[cfg(feature = "document-workflow")]
        if self.stop == 0 && self.document_control(bytes) {
            return;
        }
        #[cfg(feature = "network-negative-probe")]
        if bytes == *b"EVNABUS1" {
            negative::abusive_cpu();
        }
        #[cfg(feature = "native-session")]
        if self.stop == 0 && self.session_control(bytes) {
            return;
        }
        if bytes[..2] == *b"ND" {
            // Completed bootstrap data exchange cannot accept a duplicate or
            // unsolicited reply during normal UI/control processing.
            require(self.data.accept(&bytes, 0).is_ok(), 878);
            rt::exit(879);
        }
        match RootControl::decode(bytes) {
            Ok(RootControl::InputRestarted(_)) => {
                self.last_key = 0;
                return;
            }
            Ok(RootControl::FileRefused(_)) => {
                // The fixed Root channel cancels its one retained request.
                // Existing selected authority survives an unapproved/cancelled
                // replacement; re-read it through the same actual scoped route.
                if self.pending {
                    self.pending = false;
                    if let Some(cap) = self.file {
                        self.content = Some(self.window.read(cap, self.stop));
                    }
                    event(self.events, *b"EVFLCAN1", self.stop);
                    self.render();
                }
                return;
            }
            _ => {}
        }
        match ShellCommand::decode(bytes).unwrap_or_else(|_| rt::exit(844)) {
            ShellCommand::Repaint => self.render(),
            ShellCommand::Forward(key) => {
                require(key.sequence > self.last_key, 845);
                self.last_key = key.sequence;
                match key.key {
                    Key::Tab | Key::Up | Key::Down => {
                        self.focus = if self.focus == HelloControl::OpenFile {
                            HelloControl::CrashMe
                        } else {
                            HelloControl::OpenFile
                        };
                        self.render();
                    }
                    Key::Enter if self.focus == HelloControl::OpenFile => {
                        if !self.pending {
                            self.pending = true;
                            event(self.events, *b"EVOPEN01", self.stop);
                        }
                    }
                    Key::Enter => {
                        event(self.events, *b"EVCRASH1", self.stop);
                        // SAFETY: deliberate ordinary-user read at the absent
                        // device aperture in THIS App root. Contained PF14 is
                        // the Crash Me action; no shared/privileged pointer.
                        let value = unsafe {
                            ((self.base + 4 * 1024 * 1024) as *const u32).read_volatile()
                        };
                        rt::exit(846 + u64::from(value));
                    }
                    Key::Escape | Key::Left | Key::Right => {}
                }
            }
            _ => rt::exit(847),
        }
    }
}
fn bind(cap: u64) {
    let r = rt::call(rt::syscall::BIND_RECEIVER, cap, 0, 0);
    require(r.status == 0 && r.value == 0 && r.capability == 0, 848);
}
fn receive(cap: u64) -> Option<rt::Reply> {
    let r = rt::receive(cap);
    match r.status {
        0 => Some(r),
        2 if r.value == 0 && r.capability == 0 => None,
        _ => rt::exit(849),
    }
}
fn data_reply(control: u64, client: &mut app_data::Client, stop: u64) -> u32 {
    let retry_stop = if stop == 0 {
        rt::execution::deadline(stop, now(), 8192).unwrap_or_else(|_| rt::exit(889))
    } else {
        stop
    };
    loop {
        require(now() < retry_stop, 889);
        if let Some(reply) = receive(control) {
            require(reply.capability == 0, 890);
            return match client
                .accept(&reply.value.to_le_bytes(), 0)
                .unwrap_or_else(|_| rt::exit(891))
            {
                app_data::Response::Value(value) => value,
                app_data::Response::Refused(_) => rt::exit(892),
            };
        }
        yield_now();
    }
}
pub fn run(b: &ev_userspace_contract::Bootstrap<'_>, record: u64, stop: u64) -> ! {
    let dedicated_note = cfg!(feature = "native-session") && b.grants().count() == 7;
    require(b.grants().count() == 6 || dedicated_note, 850);
    if dedicated_note {
        let note = grant(b, 7, 1, 7);
        let access = rt::inspect(note, 7);
        require(access.status == 0 && access.capability == 0, 853);
    }
    #[cfg(feature = "network-negative-probe")]
    require(negative::app_denials(b, stop) == Ok(6), 891);
    let surface = grant(b, 1, 1, 7);
    let present = grant(b, 2, 2, 8);
    let events = grant(b, 3, 2, 8);
    let keys = grant(b, 4, 2, 272);
    let file_window = grant(b, 5, 1, 7);
    let selected = grant(b, 6, 2, 272);
    for cap in [surface, file_window] {
        let r = rt::inspect(cap, 1);
        require(r.status == 0 && r.capability == 0, 851);
    }
    bind(keys);
    bind(selected);
    let denied = rt::call(rt::syscall::DISPLAY_INFO, surface, 1, 0);
    require(
        denied.status == 1 && denied.value == 0 && denied.capability == 0,
        852,
    );
    let denied = rt::call4(rt::syscall::PORT_INPUT, surface, 0x1e8, 1, 0);
    require(
        denied.status != 0 && denied.value == 0 && denied.capability == 0 && denied.serial == 0,
        853,
    );
    // Possessing a surface/transfer window is insufficient to call File/Block.
    let denied = rt::call(
        rt::syscall::RPC_CALL,
        file_window,
        u64::from_le_bytes(CALL),
        rt::execution::deadline(stop, now(), 512)
            .ok()
            .unwrap_or_else(|| rt::exit(858)),
    );
    require(
        denied.status == 1 && denied.value == 0 && denied.capability == 0,
        854,
    );
    // Exercise the real refusal path before the first valid frame. An App with
    // SEND to its Present endpoint can submit malformed data without taking
    // Display or the kernel down, and a refused frame consumes no frame serial.
    let deadline = rt::execution::deadline(stop, now(), 512)
        .ok()
        .unwrap_or_else(|| rt::exit(858));
    let refused =
        rt::rpc::call(present, *b"BADP\0\0\0\0", deadline).unwrap_or_else(|_| rt::exit(859));
    require(refused == *b"EVDE\x03\0\0\0", 860);
    event(events, *b"EVGBAD01", stop);
    let base = record
        .checked_sub(509 * 4096)
        .unwrap_or_else(|| rt::exit(880));
    let address = usize::try_from(
        base.checked_add(384 * 4096)
            .unwrap_or_else(|| rt::exit(881)),
    )
    .unwrap_or_else(|_| rt::exit(882));
    // SAFETY: actual native App profile retains the admitted63-page initialized
    // RW RAM mapping at page384; this one thread owns render credit until its
    // actual Present, and returns to writes only after that real reply. Kernel
    // must stop this process before revocation/unmap; ABI bytes alone do not
    // establish these physical ownership obligations.
    let surface = unsafe { Surface::from_validated_mapping(address, ev_graphics::MAPPED_BYTES) }
        .unwrap_or_else(|_| rt::exit(883));
    let window = FileWindow::at(record);
    let mut data = app_data::Client::new();
    let request = data.begin_read().unwrap_or_else(|_| rt::exit(884));
    event(events, request, stop);
    let read = data_reply(keys, &mut data, stop);
    require(ev_native_hello::allowed_saved_value(read), 885);
    #[cfg(feature = "native-b")]
    if !cfg!(feature = "native-session") && read != ev_native_hello::UPDATED_VALUE {
        let request = data
            .begin_set(ev_native_hello::UPDATED_VALUE)
            .unwrap_or_else(|_| rt::exit(886));
        event(events, request, stop);
        require(
            data_reply(keys, &mut data, stop) == ev_native_hello::UPDATED_VALUE,
            887,
        );
    }
    let saved_value = data.finish().unwrap_or_else(|_| rt::exit(888));
    require(surface.is_zero() && window.is_zero(), 861);
    let mut app = App {
        #[cfg(feature = "document-workflow")]
        document: document::State::new(),
        surface,
        window,
        present,
        events,
        stop,
        frame: 0,
        focus: HelloControl::OpenFile,
        content: None,
        pending: false,
        file: None,
        last_key: 0,
        base,
        saved_value,
        data,
        #[cfg(feature = "native-session")]
        session: session::State::new(),
    };
    #[cfg(feature = "native-session")]
    app.session_window(record, dedicated_note);
    #[cfg(feature = "document-workflow")]
    if dedicated_note {
        app.document.window = Some(FileWindow::note_at(record, true));
    }
    event(events, *b"EVGARDY1", stop);
    // A sustained health subject first reads its real saved Note; the existing
    // validated reply handler renders/Present-ACKs that coherent first frame
    // before Critical. Ordinary and finite sessions keep their loading frame.
    if !cfg!(feature = "startup-health") || stop != 0 {
        app.render();
    }
    #[cfg(feature = "native-session")]
    if stop == 0 && (!cfg!(feature = "document-workflow") || cfg!(feature = "startup-health")) {
        app.session_read();
    }
    loop {
        require(rt::execution::live(stop, now()), 855);
        #[cfg(feature = "native-session")]
        if stop == 0 && (!cfg!(feature = "document-workflow") || cfg!(feature = "startup-health")) {
            app.session_poll();
        }
        #[cfg(feature = "document-workflow")]
        if stop == 0 {
            app.document_poll();
        }
        if let Some(r) = receive(selected) {
            #[cfg(feature = "document-workflow")]
            if stop == 0 && r.capability != 0 {
                app.document_selected(r.value.to_le_bytes(), r.capability);
                continue;
            }
            require(
                r.value.to_le_bytes() == *b"EVREAD01" && r.capability != 0,
                856,
            );
            app.selected(r.capability);
            continue;
        }
        if let Some(r) = receive(keys) {
            require(r.capability == 0, 857);
            app.control(r.value.to_le_bytes());
        }
        yield_now();
    }
}
