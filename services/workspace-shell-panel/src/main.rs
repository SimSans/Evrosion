#![no_std]
#![no_main]
use core::{arch::global_asm, panic::PanicInfo};
use ev_graphics::{Color, Error as GraphicsError, Pixels};
use ev_userspace_contract::root_v5::{
    Role, resources,
    surface::{Header, Producer},
};
use ev_userspace_runtime as rt;
use ev_workspace_client::{
    native::self_facts,
    ui::{Command, Event},
};
use ev_workspace_shell_panel as panel;
// SAFETY: the sole executable entry owns the scalar runtime symbols.
global_asm!(ev_userspace_runtime::start_assembly!());
// SAFETY: independently admitted eight RW/NX stack pages480..487 and both
// absent guards are selected by the measured selected M8 UI loader profile.
global_asm!(
    ".section .text",
    ".global ev_user_main",
    "ev_user_main:",
    "mov rsp,0x80001e8000",
    "and rsp,-16",
    "call ev_shell_panel_main",
    "ud2"
);
const BASE: usize = 1 << 39;
const SURFACE: usize = BASE + resources::APP_SURFACE_FIRST_PAGE as usize * 4096;
// SAFETY: only the selected measured scalar entry calls this symbol. The actual
// V5 loader retains readonly startup and separately owned Shell surface pages.
#[unsafe(no_mangle)]
extern "C" fn ev_shell_panel_main(record: u64, length: u64, bound: u64) -> ! {
    require(
        length == ev_userspace_contract::SIZE as u64 && record as usize == BASE + 509 * 4096,
        1710,
    );
    // SAFETY: exact initialized retained readonly extent checked above.
    let bytes = unsafe { core::slice::from_raw_parts(record as *const u8, length as usize) };
    let profile = panel::profile(bytes).unwrap_or_else(|| rt::exit(1711));
    let handles = profile.handles;
    for (handle, rights) in handles.into_iter().zip([7, 8, 272, 8]) {
        let r = rt::inspect(handle, rights);
        require(r.status == 0 && r.value == 0 && r.capability == 0, 1712);
    }
    let facts = self_facts().unwrap_or_else(|_| rt::exit(1713));
    require(
        facts.process == profile.process && facts.registered_incarnation == profile.incarnation,
        1714,
    );
    let mut surface = Surface {
        header: Header {
            producer: Producer::Shell,
            instance: 0,
            process: facts.process,
            thread: facts.thread,
            incarnation: facts.registered_incarnation,
            surface_object: Role::ShellSurface.selector(),
            surface_generation: facts.process,
            frame: 1,
            view_revision: 1,
            model_revision: 1,
            width: 640,
            height: 18,
            stride_bytes: 2560,
            payload_bytes: 46080,
            mapping_epoch: 1,
            protected_scope_nonce: 0,
        },
        fenced: false,
    };
    let mut configured = false;
    let mut scene_ready = false;
    let mut scene_low = None;
    let mut paint = false;
    loop {
        require(rt::execution::live(bound, now()), 1715);
        for _ in 0..16 {
            let r = rt::receive(handles[2]);
            if r.status == 2 {
                require(r.value == 0 && r.capability == 0, 1716);
                break;
            }
            require(r.status == 0 && r.capability == 0, 1717);
            let Ok(command) = Command::decode(r.value.to_le_bytes()) else {
                notify(handles[3], Event::Refused(1), bound);
                continue;
            };
            match command {
                Command::Configure {
                    instance: 0,
                    mapping_epoch,
                } if !configured => {
                    surface.header.mapping_epoch = u64::from(mapping_epoch);
                    configured = true;
                    scene_ready = false;
                    notify(handles[3], Event::Ready(0), bound);
                }
                Command::Configure { .. } => notify(handles[3], Event::Refused(1), bound),
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
                Command::Focus(_) => {
                    surface.bump();
                    paint = true;
                }
                // Toolbar actions remain ordinary intents even without taking
                // App keyboard focus. Root authenticates the actual gesture.
                Command::Activate(instance) if configured && scene_ready && !surface.fenced => {
                    if let Some(event) = panel::request(instance) {
                        notify(handles[3], event, bound);
                    }
                }
                Command::Close { .. } => {
                    if surface.fenced {
                        notify(handles[3], Event::Refused(3), bound);
                        continue;
                    }
                    let r = rt::call(rt::syscall::CLOSE, handles[1], 0, 0);
                    require(r.status == 0 && r.value == 0 && r.capability == 0, 1718);
                    notify(handles[3], Event::Closed, bound);
                    rt::exit(0)
                }
                _ => (),
            }
        }
        if paint && configured && scene_ready && !surface.fenced {
            panel::render(&mut surface).unwrap_or_else(|_| rt::exit(1719));
            paint = false;
            match surface.present(handles[1], bound) {
                Ok(true) => (),
                Ok(false) => scene_ready = false,
                Err(()) => {
                    surface.fenced = true;
                    notify(handles[3], Event::Refused(5), bound);
                }
            }
        }
        let r = rt::yield_now();
        require(r.status == 0 && r.value == 0 && r.capability == 0, 1720);
    }
}
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    rt::exit(1799)
}
fn require(ok: bool, code: u64) {
    if !ok {
        rt::exit(code);
    }
}
fn now() -> u64 {
    let r = rt::monotonic();
    require(
        r.status == 0 && r.capability == 0 && r.value != u64::MAX,
        1700,
    );
    r.value
}
fn deadline(bound: u64, span: u64) -> u64 {
    rt::execution::deadline(bound, now(), span).unwrap_or_else(|_| rt::exit(1701))
}
fn notify(events: u64, event: Event, bound: u64) {
    let bytes = event.encode().unwrap_or_else(|_| rt::exit(1702));
    let cut = deadline(bound, 512);
    loop {
        let r = rt::send(events, bytes);
        require(r.value == 0 && r.capability == 0, 1703);
        match r.status {
            0 => return,
            2 => {
                require(now() < cut, 1704);
                let _ = rt::yield_now();
            }
            _ => rt::exit(1705),
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
            .unwrap_or_else(|| rt::exit(1706));
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
