#![no_std]
#![no_main]
use core::{arch::global_asm, panic::PanicInfo};
use ev_graphics::{BACKGROUND, Canvas, Color, Error as PixelError, INK, MUTED, PANEL, Pixels};
use ev_userspace_contract::{
    file_v2::Method,
    root_v5::{
        Role, resources,
        surface::{Header, Producer},
    },
    workspace::{Deadline, Outcome},
};
use ev_userspace_runtime as rt;
use ev_workspace_client::{
    native_file_app::{FileApp, Grant, SURFACE_ADDRESS},
    ui::{Command, Event, ReleaseMode},
};

// SAFETY: this native program owns the public SDK profile's unique entry.
global_asm!(ev_userspace_runtime::start_assembly!());
// SAFETY: the selected loader maps the SDK's guarded32KiB stack before entry.
global_asm!(".text", ".global ev_user_main", "ev_user_main:", "mov rsp,{top}", "and rsp,-16", "call sample_main", "ud2", top = const ev_workspace_client::native_file_app::BASE + ((resources::M8_STACK_FIRST_PAGE + resources::M8_STACK_PAGES) as usize)*4096);

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
fn deadline() -> Deadline {
    Deadline::new(
        now()
            .checked_add(resources::FILE_TRANSACTION_TICKS)
            .unwrap(),
    )
    .unwrap()
}
fn event(app: &FileApp, e: Event) {
    let cut = now().checked_add(512).unwrap();
    loop {
        let r = rt::send(app.events, e.encode().unwrap());
        require(r.value == 0 && r.capability == 0, 1501);
        match r.status {
            0 => return,
            2 if now() < cut => {
                let _ = rt::yield_now();
            }
            _ => rt::exit(1502),
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Feedback {
    Waiting,
    ReadVerified,
    ReadOnlyDenied,
    EditGranted,
    TooLarge,
    Uncertain,
    Refused,
}
impl Feedback {
    fn text(self) -> &'static [u8] {
        match self {
            Self::Waiting => b"Select a file for a verified read",
            Self::ReadVerified => b"Read verified; Probe tests edit access",
            Self::ReadOnlyDenied => b"Read allowed; edit denied by service",
            Self::EditGranted => b"Edit allowed; unchanged probe aborted",
            Self::TooLarge => b"Sample supports up to256 bytes; file kept",
            Self::Uncertain => b"Recovery required; original request retained",
            Self::Refused => b"Operation unavailable; file kept",
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
    fn paint(&mut self, feedback: Feedback, has_file: bool) {
        require(Canvas::new(self).fill(PANEL).is_ok(), 1504);
        self.text(6, b"Open        Probe edit        Close", INK);
        self.text(26, b"Workspace SDK sample", INK);
        self.text(46, feedback.text(), MUTED);
        self.text(
            66,
            if has_file {
                b"Only the selected object is addressable"
            } else {
                b"No file grant is held"
            },
            MUTED,
        );
        self.text(86, b"Process-private scratch;256-byte limit", MUTED);
        self.text(106, b"Probe stages original bytes then aborts", MUTED);
        self.text(126, b"Committed contents stay unchanged", BACKGROUND);
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
fn read(grant: &mut Grant, scratch: &mut [u8; 256]) -> Feedback {
    if grant.selection.length > scratch.len() as u32 {
        return Feedback::TooLarge;
    }
    let n = grant.selection.length;
    let r = grant.file.issue(
        grant.selection.revision,
        Method::Read {
            offset: 0,
            length: n.max(1),
        },
        deadline(),
        &[],
        scratch,
    );
    match r {
        Ok(c)
            if c.response.outcome == Outcome::Completed
                && c.response.length == n
                && c.response.file_length == n
                && c.response.digest == grant.selection.digest =>
        {
            Feedback::ReadVerified
        }
        _ => Feedback::Uncertain,
    }
}
fn probe(grant: &mut Grant) -> Feedback {
    let cut = deadline();
    let r = grant.file.issue(
        grant.selection.revision,
        Method::BeginWrite {
            length: grant.selection.length,
            digest: grant.selection.digest,
        },
        cut,
        &[],
        &mut [],
    );
    let reply = match r {
        Ok(c) => c.response,
        Err(_) => return Feedback::Uncertain,
    };
    if reply.outcome == Outcome::Denied {
        return Feedback::ReadOnlyDenied;
    }
    if reply.outcome != Outcome::Completed {
        return Feedback::Uncertain;
    }
    // This one original deadline covers Begin and Abort; no renewed mutation
    // counter or retry follows uncertainty. The backend chooses transfer IDs.
    match grant.file.issue(
        grant.selection.revision,
        Method::Abort {
            transfer_id: reply.transfer_id,
        },
        cut,
        &[],
        &mut [],
    ) {
        Ok(c) if c.response.outcome == Outcome::Completed => Feedback::EditGranted,
        _ => Feedback::Uncertain,
    }
}

// SAFETY: the actual selected SDK entry passes its immutable bootstrap and
// owns the declared public profile mappings for this process lifetime.
#[unsafe(no_mangle)]
extern "C" fn sample_main(record: usize, length: usize, bound: u64) -> ! {
    require(bound == 0, 1505);
    // SAFETY: the selected entry/loader contract above supplies actual custody;
    // the SDK additionally validates shape, actual self facts and held handles.
    let mut app = unsafe { FileApp::from_entry(record, length) }.unwrap_or_else(|_| rt::exit(1506));
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
    let mut paint = false;
    let mut feedback = Feedback::Waiting;
    let mut grant = None;
    let mut scratch = [0; 256];
    let mut selection_used = false;
    loop {
        for _ in 0..16 {
            let r = rt::receive(app.control);
            if r.status == 2 {
                break;
            }
            require(r.status == 0 && r.capability == 0, 1507);
            let Ok(command) = Command::decode(r.value.to_le_bytes()) else {
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
                    event(&app, Event::Ready(instance));
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
                        let rev = (u64::from(word) << 32) | u64::from(lo);
                        if !matches!(rev, 0 | u64::MAX) {
                            surface.header.model_revision = rev;
                            scene = true;
                            paint = true;
                        }
                    }
                }
                Command::Activate(1) if !surface.fenced && !selection_used => {
                    event(&app, Event::Open)
                }
                Command::Save | Command::Activate(2)
                    if !surface.fenced
                        && matches!(
                            feedback,
                            Feedback::ReadVerified
                                | Feedback::ReadOnlyDenied
                                | Feedback::EditGranted
                        ) =>
                {
                    feedback = grant.as_mut().map_or(Feedback::Refused, probe);
                    paint = true;
                }
                Command::Close { .. } | Command::Activate(4) => {
                    if grant
                        .as_mut()
                        .is_none_or(|g| g.file.close_quiescent().is_ok())
                    {
                        event(&app, Event::Closed);
                        rt::exit(0)
                    }
                    feedback = Feedback::Uncertain;
                    paint = true;
                }
                Command::ReleaseFile {
                    mode: ReleaseMode::KeepDocument,
                    ..
                } => event(&app, Event::Refused(7)),
                Command::ReleaseFile { .. } => event(&app, Event::Refused(7)), // one selection per admitted process
                _ => (),
            }
        }
        if grant.is_none() && !surface.fenced {
            match app.receive_selection() {
                Ok(Some(mut received)) => {
                    selection_used = true;
                    feedback = read(&mut received, &mut scratch);
                    grant = Some(received);
                    paint = true;
                }
                Ok(None) => (),
                Err(_) => {
                    selection_used = true;
                    feedback = Feedback::Uncertain;
                    paint = true;
                }
            }
        }
        if paint && configured && scene && !surface.fenced {
            surface.header.view_revision = surface
                .header
                .view_revision
                .checked_add(1)
                .filter(|n| *n != u64::MAX)
                .unwrap_or_else(|| rt::exit(1508));
            surface.paint(feedback, grant.is_some());
            match surface.present(&app) {
                Ok(true) => paint = false,
                Ok(false) => scene = false,
                Err(_) => event(&app, Event::Refused(5)),
            }
        }
        let _ = rt::yield_now();
    }
}
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    rt::exit(1599)
}
