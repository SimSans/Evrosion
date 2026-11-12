//! Ordinary native Hello. It starts with no File endpoint and cannot name a
//! file globally. Only actual selected-cap delivery permits the File RPC.
use crate::{event, grant, now, require, surface::Surface, yield_now};
use ev_desktop::protocol::{RootControl, ShellCommand};
use ev_graphics::{HelloControl, HelloView, Present, hello_window};
use ev_input::Key;
use ev_userspace_contract::{
    file::{Payload, Request, Response},
    file_test::{CALL, REPLY},
};
use ev_userspace_runtime as rt;

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
    fn read(&mut self, cap: u64, stop: u64) -> Payload {
        self.guards();
        self.publish(&Request::Read.encode());
        let deadline = stop.checked_add(512).unwrap_or_else(|| rt::exit(858));
        let reply = rt::rpc::call(cap, CALL, deadline).unwrap_or_else(|_| rt::exit(833));
        require(reply == REPLY, 833);
        self.guards();
        match Response::decode(&self.snapshot()).unwrap_or_else(|_| rt::exit(834)) {
            Response::Read { payload, .. } => payload,
            _ => rt::exit(835),
        }
    }
}
struct App {
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
}
impl App {
    fn render(&mut self) {
        let frame = self
            .frame
            .checked_add(1)
            .filter(|n| *n != u32::MAX)
            .unwrap_or_else(|| rt::exit(836));
        hello_window(
            &mut self.surface,
            HelloView {
                focus: self.focus,
                content: self.content.as_ref().map(Payload::as_slice),
                incarnation: 1,
            },
        )
        .unwrap_or_else(|_| rt::exit(837));
        self.surface.publish(u64::from(frame));
        self.surface.tail();
        require(self.surface.header().sequence == u64::from(frame), 838);
        let present = Present(frame);
        let deadline = self.stop.checked_add(512).unwrap_or_else(|| rt::exit(858));
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
        self.content = Some(self.window.read(cap, self.stop));
        self.pending = false;
        event(self.events, *b"EVFILRD1", self.stop);
        self.render();
    }
    fn control(&mut self, bytes: [u8; 8]) {
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
                    Key::Escape => {}
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
pub fn run(b: &ev_userspace_contract::Bootstrap<'_>, record: u64, stop: u64) -> ! {
    require(b.grants().count() == 6, 850);
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
        stop.checked_add(512).unwrap_or_else(|| rt::exit(858)),
    );
    require(
        denied.status == 1 && denied.value == 0 && denied.capability == 0,
        854,
    );
    // Exercise the real refusal path before the first valid frame. An App with
    // SEND to its Present endpoint can submit malformed data without taking
    // Display or the kernel down, and a refused frame consumes no frame serial.
    let deadline = stop.checked_add(512).unwrap_or_else(|| rt::exit(858));
    let refused =
        rt::rpc::call(present, *b"BADP\0\0\0\0", deadline).unwrap_or_else(|_| rt::exit(859));
    require(refused == *b"EVDE\x03\0\0\0", 860);
    event(events, *b"EVGBAD01", stop);
    let surface = Surface::at(record);
    let window = FileWindow::at(record);
    require(surface.is_zero() && window.is_zero(), 861);
    let mut app = App {
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
        base: record.checked_sub(509 * 4096).unwrap(),
    };
    event(events, *b"EVGARDY1", stop);
    app.render();
    loop {
        require(now() < stop, 855);
        if let Some(r) = receive(selected) {
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
