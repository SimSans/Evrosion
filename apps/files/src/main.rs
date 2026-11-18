#![no_std]
#![no_main]
mod native_semantic;

use core::{arch::global_asm, panic::PanicInfo};
use ev_graphics::{Color, Error as GraphicsError, Pixels};
use ev_native_files::{Browser, Profile, Status};
use ev_userspace_contract::{
    root_v5::{
        Role, resources,
        surface::{Header, Producer},
    },
    workspace::Deadline,
};
use ev_userspace_runtime as rt;
use ev_workspace_client::{
    namespace::{Client, NativeLink},
    native::self_facts,
    semantic as a1,
    ui::{Command, Event, State},
};
// SAFETY: the sole executable entry owns the scalar runtime symbols.
global_asm!(ev_userspace_runtime::start_assembly!());
// SAFETY: independently admitted eight RW/NX stack pages480..487 and both
// absent guards are selected by the measured M8 Files loader profile.
global_asm!(
    ".section .text",
    ".global ev_user_main",
    "ev_user_main:",
    "mov rsp,0x80001e8000",
    "and rsp,-16",
    "call ev_files_main",
    "ud2"
);
const BASE: usize = 1 << 39;
const SURFACE: usize = BASE + resources::APP_SURFACE_FIRST_PAGE as usize * 4096;
const FRAME: usize = BASE + resources::APP_FILE_FIRST_PAGE as usize * 4096;
fn require(ok: bool, code: u64) {
    if !ok {
        rt::exit(code);
    }
}
fn now() -> u64 {
    let r = rt::monotonic();
    require(
        r.status == 0 && r.capability == 0 && r.value != u64::MAX,
        1500,
    );
    r.value
}
fn deadline(bound: u64, span: u64) -> u64 {
    rt::execution::deadline(bound, now(), span).unwrap_or_else(|_| rt::exit(1501))
}
fn cut(bound: u64) -> Deadline {
    Deadline::new(deadline(bound, resources::FILE_TRANSACTION_TICKS)).unwrap()
}
fn notify(events: u64, event: Event, bound: u64) {
    let bytes = event.encode().unwrap_or_else(|_| rt::exit(1502));
    let cut = deadline(bound, 512);
    loop {
        let r = rt::send(events, bytes);
        require(r.value == 0 && r.capability == 0, 1503);
        match r.status {
            0 => return,
            2 => {
                require(now() < cut, 1504);
                let _ = rt::yield_now();
            }
            _ => rt::exit(1505),
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
    fn write(&mut self, x: usize, y: usize, color: Color) -> Result<(), GraphicsError> {
        if self.fenced || x >= self.header.width as usize || y >= self.header.height as usize {
            return Err(GraphicsError::Bounds);
        }
        let offset = 256 + y * self.header.stride_bytes as usize + x * 4;
        if offset + 4 > resources::APP_SURFACE_PAGES as usize * 4096 {
            return Err(GraphicsError::Bounds);
        }
        // SAFETY: exact separately admitted RW/NX app surface, one-thread sole
        // writer, checked extent. No write occurs while Present is retained.
        unsafe { ((SURFACE + offset) as *mut u32).write_volatile(color.0 & 0x00ff_ffff) };
        Ok(())
    }
}
impl Surface {
    fn bump(&mut self) {
        self.header.view_revision = self
            .header
            .view_revision
            .checked_add(1)
            .filter(|v| *v != u64::MAX)
            .unwrap_or_else(|| rt::exit(1506));
    }
    fn present(&mut self, endpoint: u64, bound: u64) -> Result<bool, ()> {
        if self.fenced {
            return Err(());
        }
        self.header.frame = self
            .header
            .frame
            .checked_add(1)
            .filter(|v| *v != u64::MAX)
            .ok_or(())?;
        let bytes = self.header.encode().map_err(|_| ())?;
        for (i, byte) in bytes.into_iter().enumerate() {
            // SAFETY: owned initialized256B header before RPC acceptance; no
            // shared Rust reference is retained through the actual syscall.
            unsafe { ((SURFACE + i) as *mut u8).write_volatile(byte) };
        }
        match rt::rpc::call(
            endpoint,
            self.header.frame.to_le_bytes(),
            deadline(bound, resources::RPC_TICKS),
        ) {
            Ok(reply) if u64::from_le_bytes(reply) == self.header.frame => Ok(true),
            Ok(reply) if u64::from_le_bytes(reply) == u64::MAX => Ok(false),
            _ => {
                self.fenced = true;
                Err(())
            }
        }
    }
}
// SAFETY: only the measured scalar entry invokes this symbol. The actual loader
// owns startup/mapping lifetime; parsed IDs alone establish no authority.
#[unsafe(no_mangle)]
extern "C" fn ev_files_main(record: u64, length: u64, bound: u64) -> ! {
    require(
        length == ev_userspace_contract::SIZE as u64 && record as usize == BASE + 509 * 4096,
        1510,
    );
    // SAFETY: exact retained readonly initialized startup extent checked above.
    let bytes = unsafe { core::slice::from_raw_parts(record as *const u8, length as usize) };
    let profile = Profile::parse(bytes).unwrap_or_else(|_| rt::exit(1511));
    let handles = profile.handles;
    for (handle, rights) in handles.into_iter().zip([7, 8, 8, 272, 7, 272, 8]) {
        let r = rt::inspect(handle, rights);
        require(r.status == 0 && r.value == 0 && r.capability == 0, 1514);
    }
    let facts = self_facts().unwrap_or_else(|_| rt::exit(1515));
    require(
        facts.process == profile.process
            && facts.registered_incarnation == profile.registered_incarnation,
        1516,
    );
    // SAFETY: strict V5 Files profile installs this exact2page frame and only
    // Namespace SEND. This admitted thread owns it permanently; no File client
    // or preview is constructed, and Root must not publish Selection into it.
    let link = unsafe { NativeLink::from_admitted_mapping(FRAME, 8192, handles[6]) }
        .unwrap_or_else(|_| rt::exit(1517));
    let mut client = Client::new(link);
    let mut browser = Browser::new();
    let mut surface = Surface {
        header: Header {
            producer: Producer::Application,
            instance: 1,
            process: facts.process,
            thread: facts.thread,
            incarnation: facts.registered_incarnation,
            surface_object: Role::FilesSurface.selector(),
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
        fenced: false,
    };
    let mut configured = false;
    let mut scene_ready = false;
    let mut scene_low = None;
    let mut focused = false;
    let mut paint = false;
    let mut last_state = State::Loading;
    let mut semantics = ev_native_files::semantic::Session::new();
    let mut accepted_surface = false;
    loop {
        require(rt::execution::live(bound, now()), 1518);
        for _ in 0..16 {
            let received = rt::receive(handles[3]);
            if received.status == 2 {
                require(received.value == 0 && received.capability == 0, 1519);
                break;
            }
            require(received.status == 0 && received.capability == 0, 1520);
            let bytes = received.value.to_le_bytes();
            if let Ok(frame) = a1::Frame::decode(&bytes) {
                let available =
                    accepted_surface && !paint && configured && scene_ready && !surface.fenced;
                if let Ok(request) = a1::Request::decode(frame) {
                    let h = surface.header;
                    semantics.request(
                        request,
                        a1::Header {
                            nonce: 1,
                            page: 0,
                            pages: 3,
                            model: h.model_revision,
                            view: h.view_revision,
                            frame: h.frame,
                            mapping_epoch: h.mapping_epoch,
                            width: h.width as u16,
                            height: h.height as u16,
                            keyboard: 0,
                            modal: 0,
                        },
                        available,
                        &browser,
                        focused,
                    );
                } else if (0x8100..=0x81ff).contains(&frame.field)
                    && let Some(request) = semantics.operation(frame)
                {
                    native_semantic::operation(
                        request,
                        native_semantic::Context {
                            browser: &mut browser,
                            client: &mut client,
                            surface: &mut surface,
                            session: &mut semantics,
                            paint: &mut paint,
                            available,
                            focused,
                            events: handles[2],
                            bound,
                        },
                    );
                }
                continue;
            }
            let Ok(command) = Command::decode(bytes) else {
                notify(handles[2], Event::Refused(1), bound);
                continue;
            };
            match command {
                Command::Configure {
                    instance: 1,
                    mapping_epoch,
                } if !configured => {
                    surface.header.mapping_epoch = u64::from(mapping_epoch);
                    configured = true;
                    scene_ready = false;
                    notify(handles[2], Event::Ready(1), bound);
                }
                Command::Configure { .. } => notify(handles[2], Event::Refused(1), bound),
                Command::Resize { width, height } => {
                    surface.header.width = u32::from(width);
                    surface.header.height = u32::from(height);
                    surface.header.stride_bytes = u32::from(width) * 4;
                    surface.header.payload_bytes = u32::from(width) * u32::from(height) * 4;
                    surface.bump();
                    scene_ready = false;
                    paint = true;
                }
                Command::ScenePart { high: false, word } => {
                    scene_low = Some(word);
                    scene_ready = false;
                }
                Command::ScenePart { high: true, word } => {
                    if let Some(low) = scene_low.take() {
                        let revision = (u64::from(word) << 32) | u64::from(low);
                        if !matches!(revision, 0 | u64::MAX) {
                            surface.header.model_revision = revision;
                            scene_ready = true;
                            paint = true;
                        }
                    }
                }
                Command::Focus(value) => {
                    focused = value;
                    surface.bump();
                    paint = true;
                }
                Command::Close { discard } => {
                    if surface.fenced || browser.status() == Status::Uncertain {
                        notify(handles[2], Event::Refused(3), bound);
                        continue;
                    }
                    match browser.close(discard) {
                        ev_native_files::Close::ConfirmDiscard => {
                            notify(handles[2], Event::CloseNeedsDiscard, bound);
                            continue;
                        }
                        ev_native_files::Close::RecoveryRequired => {
                            notify(handles[2], Event::Refused(3), bound);
                            continue;
                        }
                        ev_native_files::Close::Ready => (),
                    }
                    match client.close_quiescent() {
                        Ok(()) => {
                            notify(handles[2], Event::Closed, bound);
                            rt::exit(0)
                        }
                        Err(_) => notify(handles[2], Event::Refused(3), bound),
                    }
                }
                _ if focused && configured && scene_ready && !surface.fenced => {
                    let event = browser.command(&mut client, command, cut(bound));
                    surface.bump();
                    paint = true;
                    if let Some(event) = event {
                        notify(handles[2], event, bound);
                    }
                }
                _ => (),
            }
        }
        // Namespace owns this frame for its whole session. Reject even an
        // actual unsolicited File SEND; never read Selection or construct a
        // competing File NativeLink on the same mapping.
        let inbox = rt::receive(handles[5]);
        match inbox.status {
            0 => {
                require(inbox.capability != 0, 1521);
                let r = rt::call(rt::syscall::CLOSE, inbox.capability, 0, 0);
                require(r.status == 0 && r.value == 0 && r.capability == 0, 1522);
                notify(handles[2], Event::Refused(4), bound);
            }
            2 => require(inbox.value == 0 && inbox.capability == 0, 1523),
            _ => rt::exit(1524),
        }
        if configured && browser.loading() {
            browser.step(&mut client, cut(bound));
            surface.bump();
            paint = true;
        }
        let state = if surface.fenced {
            State::Uncertain
        } else {
            browser.app_state()
        };
        if state != last_state {
            notify(handles[2], Event::State(state), bound);
            last_state = state;
        }
        if paint && configured && scene_ready && !surface.fenced {
            ev_native_files::render(&mut surface, &browser, focused)
                .unwrap_or_else(|_| rt::exit(1525));
            paint = false;
            match surface.present(handles[1], bound) {
                Ok(true) => accepted_surface = true,
                Ok(false) => {
                    accepted_surface = false;
                    scene_ready = false;
                }
                Err(()) => {
                    surface.fenced = true;
                    notify(handles[2], Event::Refused(5), bound);
                }
            }
        }
        if let Some(frame) = semantics.snapshot_next() {
            let r = rt::send(handles[2], frame.encode());
            require(
                r.value == 0 && r.capability == 0 && matches!(r.status, 0 | 2),
                1527,
            );
            if r.status == 0 {
                require(semantics.snapshot_sent(frame).is_ok(), 1528);
            }
        }
        if let Some(frame) = semantics.operation_next(accepted_surface, paint, surface.header.frame)
        {
            let r = rt::send(handles[2], frame.encode());
            require(
                r.value == 0 && r.capability == 0 && matches!(r.status, 0 | 2),
                1529,
            );
            if r.status == 0 {
                require(semantics.operation_sent(frame).is_ok(), 1530);
            }
        }
        let r = rt::yield_now();
        require(r.status == 0 && r.value == 0 && r.capability == 0, 1526);
    }
}
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    rt::exit(1599)
}
