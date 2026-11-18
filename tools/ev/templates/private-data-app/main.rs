#![no_std]
#![no_main]
use core::{arch::global_asm, panic::PanicInfo};
use ev_graphics::{Canvas, Color, Error as PixelError, INK, MUTED, PANEL, Pixels};
use ev_userspace_contract::{
    app_data as nd,
    root_v5::{
        Role, resources,
        surface::{Header, Producer},
    },
};
use ev_userspace_runtime as rt;
use ev_workspace_client::{
    app_data::{Client, Phase, SendResult, Sender},
    native_file_app::{FileApp, SURFACE_ADDRESS},
    ui::{Command, Event, State},
};
const TARGET: u32 = 2026;
// SAFETY: the actual selected FileApp6 loader owns this unique entry and stack.
global_asm!(ev_userspace_runtime::start_assembly!());
// SAFETY: fixed SDK guarded32KiB stack is mapped before this entry.
global_asm!(".text", ".global ev_user_main", "ev_user_main:", "mov rsp,{top}", "and rsp,-16", "call private_main", "ud2", top = const ev_workspace_client::native_file_app::BASE + ((resources::M8_STACK_FIRST_PAGE + resources::M8_STACK_PAGES) as usize)*4096);
fn require(ok: bool, code: u64) {
    if !ok {
        rt::exit(code)
    }
}
fn now() -> u64 {
    let r = rt::monotonic();
    require(r.status == 0 && r.capability == 0, 1500);
    r.value
}
struct NativeSender;
impl Sender for NativeSender {
    fn try_send(&mut self, events: u64, frame: [u8; 8], deadline: u64) -> SendResult {
        if now() >= deadline {
            return SendResult::Rejected;
        }
        let r = rt::call4(rt::syscall::SEND, events, u64::from_le_bytes(frame), 0, 0);
        if r.value != 0 || r.capability != 0 || r.serial != 0 {
            return SendResult::Unknown;
        }
        match r.status {
            0 => SendResult::Accepted,
            2 => SendResult::WouldBlock,
            _ => SendResult::Unknown,
        }
    }
}
struct UiFailure {
    _frame: [u8; 8],
    _original_cut: u64,
}
fn event(app: &FileApp, value: Event) -> Result<(), UiFailure> {
    let frame = value.encode().unwrap();
    let cut = now().checked_add(512).filter(|v| *v != u64::MAX).unwrap();
    loop {
        if now() >= cut {
            return Err(UiFailure {
                _frame: frame,
                _original_cut: cut,
            });
        }
        let r = rt::call4(
            rt::syscall::SEND,
            app.events,
            u64::from_le_bytes(frame),
            0,
            0,
        );
        if r.value != 0 || r.capability != 0 || r.serial != 0 {
            return Err(UiFailure {
                _frame: frame,
                _original_cut: cut,
            });
        }
        match r.status {
            0 => return Ok(()),
            2 => {
                let _ = rt::yield_now();
            }
            _ => {
                return Err(UiFailure {
                    _frame: frame,
                    _original_cut: cut,
                });
            }
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Feedback {
    Loading,
    Stored,
    Existing,
    Uncertain,
}
impl Feedback {
    fn text(self) -> &'static [u8] {
        match self {
            Self::Loading => b"Private data exchange pending",
            Self::Stored => b"Private data committed reply: 2026",
            Self::Existing => b"Private data retained Read: 2026",
            Self::Uncertain => b"Private data uncertain; no retry or Close",
        }
    }
}
struct Surface {
    header: Header,
    fenced: bool,
}
impl Pixels for Surface {
    fn dimensions(&self) -> (usize, usize) {
        (self.header.width as usize, self.header.height as usize)
    }
    fn write(&mut self, x: usize, y: usize, color: Color) -> Result<(), PixelError> {
        if self.fenced || x >= self.header.width as usize || y >= self.header.height as usize {
            return Err(PixelError::Bounds);
        }
        let offset = 256 + y * self.header.stride_bytes as usize + x * 4;
        // SAFETY: actual SDK admission owns the bounded sole-writer surface;
        // no accepted Present loan exists while this adapter paints.
        unsafe { ((SURFACE_ADDRESS + offset) as *mut u32).write_volatile(color.0 & 0x00ff_ffff) };
        Ok(())
    }
}
impl Surface {
    fn text(&mut self, y: usize, bytes: &[u8], color: Color) {
        if y + 7 <= self.header.height as usize && self.header.width >= 8 {
            let count = bytes.len().min((self.header.width as usize - 8) / 6);
            require(
                Canvas::new(self)
                    .text_exact(4, y, &bytes[..count], color)
                    .is_ok(),
                1503,
            );
        }
    }
    fn paint(&mut self, feedback: Feedback, initial: Option<u32>) {
        require(Canvas::new(self).fill(PANEL).is_ok(), 1504);
        self.text(6, b"Private data SDK fixture", INK);
        self.text(26, b"Root Install then separate Run required", MUTED);
        self.text(46, feedback.text(), INK);
        self.text(66, b"Initial private Read returned:", MUTED);
        if let Some(value) = initial {
            let mut digits = [b'0'; 10];
            let mut rest = value;
            let mut start = digits.len();
            loop {
                start -= 1;
                digits[start] = b'0' + (rest % 10) as u8;
                rest /= 10;
                if rest == 0 {
                    break;
                }
            }
            self.text(86, &digits[start..], INK);
        }
        self.text(106, b"No selected-file permissions or client", MUTED);
        self.text(126, b"Value reply is separate from cold proof", MUTED);
    }
    fn present(&mut self, app: &FileApp) -> Result<bool, ()> {
        self.header.frame = self
            .header
            .frame
            .checked_add(1)
            .filter(|n| *n != u64::MAX)
            .ok_or(())?;
        let bytes = self.header.encode().map_err(|_| ())?;
        for (i, b) in bytes.iter().enumerate() {
            // SAFETY: painting finished and this sole owner holds write credit
            // until actual exact endpoint acceptance; no reference crosses RPC.
            unsafe { ((SURFACE_ADDRESS + i) as *mut u8).write_volatile(*b) };
        }
        let cut = now().checked_add(resources::RPC_TICKS).ok_or(())?;
        match rt::rpc::call(app.present, self.header.frame.to_le_bytes(), cut) {
            Ok(r) if u64::from_le_bytes(r) == self.header.frame => Ok(true),
            Ok(r) if u64::from_le_bytes(r) == u64::MAX => Ok(false),
            _ => {
                self.fenced = true;
                Err(())
            }
        }
    }
}
// SAFETY: actual selected entry supplies immutable startup and sole mappings.
#[unsafe(no_mangle)]
extern "C" fn private_main(record: usize, length: usize, bound: u64) -> ! {
    require(bound == 0, 1505);
    // SAFETY: this actual selected entry owns the public SDK six-role mappings.
    let mut app = unsafe { FileApp::from_entry(record, length) }.unwrap_or_else(|_| rt::exit(1506));
    let peer = app.take_app_data_peer().unwrap_or_else(|| rt::exit(1507));
    let start = now();
    let cut = start
        .checked_add(resources::FILE_TRANSACTION_TICKS)
        .filter(|v| *v != u64::MAX)
        .unwrap_or_else(|| rt::exit(1508));
    let mut client = Client::claim(peer, start, cut).unwrap_or_else(|_| rt::exit(1509));
    let facts = app.facts();
    let mut surface = Surface {
        fenced: false,
        header: Header {
            producer: Producer::Application,
            instance: 2,
            process: facts.process,
            thread: facts.thread,
            incarnation: facts.registered_incarnation,
            surface_object: Role::EditorOneSurface as u64,
            surface_generation: facts.process,
            frame: 1,
            view_revision: 1,
            model_revision: 1,
            width: 320,
            height: 180,
            stride_bytes: 1280,
            payload_bytes: 230400,
            mapping_epoch: 1,
            protected_scope_nonce: 0,
        },
    };
    let mut configured = false;
    let mut scene = false;
    let mut low = None;
    let mut paint = true;
    let mut started = false;
    let mut feedback = Feedback::Loading;
    let mut initial = None;
    let mut failed = false;
    let mut ui_failure = None;
    let mut last_state = None;
    loop {
        // Drain the original RootControl even while an accepted ND request is
        // outstanding. ND replies never enter or reset the independent UI pair.
        for _ in 0..16 {
            let r = rt::call4(rt::syscall::RECEIVE, app.control, 0, 0, 0);
            if r.status == 2 && r.value == 0 && r.capability == 0 && r.serial == 0 {
                break;
            }
            if r.status != 0 || r.capability != 0 || r.serial != 0 {
                failed = true;
                break;
            }
            let bytes = r.value.to_le_bytes();
            if &bytes[..2] == b"ND" {
                match client.observe_root_control(app.control, &bytes, 0, now()) {
                    Ok(nd::Response::Value(value)) if client.phase() == Phase::Read => {
                        initial = Some(value);
                        if value == TARGET {
                            if client.finish() == Ok(TARGET) {
                                feedback = Feedback::Existing;
                            } else {
                                failed = true;
                            }
                        } else if client.begin_set(TARGET, now()).is_err() {
                            failed = true;
                        }
                    }
                    Ok(nd::Response::Value(value))
                        if client.phase() == Phase::Set && value == TARGET =>
                    {
                        if client.finish() == Ok(TARGET) {
                            feedback = Feedback::Stored;
                        } else {
                            failed = true;
                        }
                    }
                    _ => failed = true,
                }
                paint = true;
                continue;
            }
            let Ok(command) = Command::decode(bytes) else {
                continue;
            };
            match command {
                Command::Configure {
                    instance,
                    mapping_epoch,
                } if !configured && matches!(instance, 2 | 3) => {
                    surface.header.instance = u16::from(instance);
                    surface.header.surface_object = if instance == 2 {
                        Role::EditorOneSurface as u64
                    } else {
                        Role::EditorTwoSurface as u64
                    };
                    surface.header.mapping_epoch = u64::from(mapping_epoch);
                    configured = true;
                    if let Err(error) = event(&app, Event::Ready(instance)) {
                        ui_failure = Some(error);
                        failed = true;
                    }
                }
                Command::Resize { width, height } => {
                    surface.header.width = u32::from(width);
                    surface.header.height = u32::from(height);
                    surface.header.stride_bytes = u32::from(width) * 4;
                    surface.header.payload_bytes = u32::from(width) * u32::from(height) * 4;
                    scene = false;
                    paint = true;
                }
                Command::ScenePart { high: false, word } => {
                    low = Some(word);
                    scene = false;
                }
                Command::ScenePart { high: true, word } => {
                    if let Some(lo) = low.take() {
                        let revision = (u64::from(word) << 32) | u64::from(lo);
                        if !matches!(revision, 0 | u64::MAX) {
                            surface.header.model_revision = revision;
                            scene = true;
                            paint = true;
                        }
                    }
                }
                Command::Close { .. }
                    if client.phase() == Phase::Finished
                        && !failed
                        && !surface.fenced
                        && ui_failure.is_none() =>
                {
                    match event(&app, Event::Closed) {
                        Ok(()) => rt::exit(0),
                        Err(error) => {
                            ui_failure = Some(error);
                            failed = true;
                        }
                    }
                }
                Command::Close { .. }
                | Command::ReleaseFile { .. }
                | Command::Save
                | Command::Activate(_) => {
                    if ui_failure.is_none()
                        && let Err(error) = event(&app, Event::Refused(7))
                    {
                        ui_failure = Some(error);
                        failed = true;
                    }
                }
                _ => (),
            }
        }
        if configured && !started && !failed {
            started = true;
            if client.begin_read(now()).is_err() {
                failed = true;
            }
        }
        if !failed
            && client.phase() == Phase::Queued
            && client.try_send(now(), &mut NativeSender).is_err()
        {
            failed = true;
        }
        if !failed
            && matches!(client.phase(), Phase::Queued | Phase::AwaitReply)
            && client.poll_deadline(now()).is_err()
        {
            failed = true;
        }
        if (failed || surface.fenced) && feedback != Feedback::Uncertain {
            feedback = Feedback::Uncertain;
            paint = true;
        }
        let state = if feedback == Feedback::Uncertain {
            State::Uncertain
        } else if client.phase() == Phase::Finished {
            State::Saved
        } else {
            State::Loading
        };
        if configured && last_state != Some(state) && ui_failure.is_none() {
            match event(&app, Event::State(state)) {
                Ok(()) => last_state = Some(state),
                Err(error) => {
                    ui_failure = Some(error);
                    failed = true;
                }
            }
        }
        // Do not block original reply draining on Present while ND is pending.
        if paint
            && configured
            && scene
            && !surface.fenced
            && !matches!(client.phase(), Phase::Queued | Phase::AwaitReply)
        {
            surface.header.view_revision = surface
                .header
                .view_revision
                .checked_add(1)
                .filter(|v| *v != u64::MAX)
                .unwrap_or_else(|| rt::exit(1510));
            surface.paint(feedback, initial);
            match surface.present(&app) {
                Ok(true) => paint = false,
                Ok(false) => scene = false,
                Err(_) => failed = true,
            }
        }
        let _ = rt::yield_now();
    }
}
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    rt::exit(1599)
}
