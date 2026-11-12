//! Full desktop reference executor. Userspace Root owns graph construction and
//! selection policy; this boundary retains actual executable/resource owners.
#[cfg(not(feature = "test-m5-native"))]
use crate::executable_runtime::{LoadedImage, ProcessImage};
use crate::graphics_image::{GraphicsImage, GraphicsProcessImage};
use core::{arch::asm, num::NonZeroU64};
use ev_boot_contract::Framebuffer;
use ev_kernel::{
    bootstrap_binding::CatalogEntry,
    capability::{Authority, Handle, Kind, Rights, SpaceId},
    custodian::Custodian,
    fault::Record,
    incarnation::{Active, Token},
    ipc::{Error as IpcError, Mailbox, Outgoing, Ticket},
    mapping::{ADDRESS_MASK, direct_address},
    memory::{BootstrapFrames, FRAME_SIZE},
    rpc::{CallId, MessageShape, Policy, Rpc, Status},
    scheduler::{JobId, Limits, ProcessId, Resource, Scheduler, State, ThreadId, WaitTicket},
    service::{Metadata, Registry, Role, Running, ServiceImage},
    time::Deadline,
    user_context::{Call, FxState, UserContext, decode},
};
use ev_userspace_contract::root_v2::{
    self,
    graph::{CHILDREN, Channel, Child},
};
use sha2::{Digest, Sha256};
mod backing;
mod checks;
#[cfg(feature = "test-m5-native")]
mod diagnostic;
mod dispatch;
mod executor;
mod world;
#[cfg(not(feature = "test-m5-native"))]
pub use world::prove;
#[cfg(feature = "test-m5-native")]
pub(crate) use world::prove_native;
mod grant;
mod lifecycle;
mod observation;
mod retirement;
mod transport;
use backing::Backing;
#[cfg(feature = "test-m5-native")]
pub(crate) use backing::{Assets as CommonAssets, Profile as CommonProfile};
use lifecycle::Actor;
use transport::{Pending, Wire};
const EPOCH: NonZeroU64 = NonZeroU64::new(501).unwrap();
const CHILD_LIMITS: Limits = Limits::new(16_384, 32, 1, 1);
const RECEIVE: Rights = Rights::from_bits(272).unwrap();
#[cfg(not(feature = "test-m5-native"))]
const WORLD_TICKS: u64 = 16_384;
const TRANSITIONS: u64 = 8_000_000;
#[derive(Clone, Copy)]
pub(super) enum Scalar {
    System,
    File,
    Application,
    Catalogue,
}
#[derive(Clone, Copy)]
struct Hardware {
    offset: u64,
    bits: u8,
    original: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Producer {
    App,
    Shell,
}
#[derive(Clone, Copy)]
pub struct Step {
    pub kind: StepKind,
    pub frame: u64,
    pub width: u32,
    pub height: u32,
    pub app_process: u64,
    pub shell_process: u64,
    pub display_process: u64,
    pub grants: u64,
    pub producer: Producer,
    pub surface_sha256: [u8; 32],
    pub held_ticks: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepKind {
    Frame,
    PickerReady,
    PickerHeld,
}
#[derive(Clone, Copy)]
pub struct Lifecycle {
    pub actor: Producer,
    pub fault: Option<Record>,
    pub process: u64,
    pub thread: u64,
    pub replacement: u64,
    pub display_process: u64,
    pub grants: u64,
}
/// Facts captured at an actual App Exit trap, before ordinary containment.
/// This is a voluntary userspace outcome, never a hardware fault capsule.
pub struct VoluntaryExit {
    pub process: u64,
    pub thread: u64,
    pub code: u64,
    pub instruction: u64,
    pub calls: u64,
    pub replies: u64,
}
pub enum Observation {
    Step(Step),
    Lifecycle(Lifecycle),
    VoluntaryExit(VoluntaryExit),
    #[cfg(feature = "test-m5-native")]
    NativeAction(NativeAction),
    #[cfg(feature = "test-m5-native")]
    NativeState(NativeSnapshot),
    #[cfg(feature = "test-m5-native")]
    NativeManagedRead(NativeManagedRead),
    #[cfg(feature = "test-m5-native")]
    NativeCommonPrefix(NativeCommonPrefix),
    #[cfg(feature = "test-m5-native")]
    NativeMemory(NativeMemory),
    #[cfg(feature = "test-m5-native")]
    NativeCriticalReady(NativeCriticalReady),
    #[cfg(feature = "test-m5-native")]
    NativeSelfIdentity(NativeSelfIdentity),
    #[cfg(feature = "test-m5-native")]
    NativeInhibit(NativeInhibit),
    #[cfg(feature = "test-m5-native")]
    NativeOwnerPrompt(NativeDiagnostic<416>),
    #[cfg(feature = "test-m5-native")]
    NativeCrash(NativeDiagnostic<416>),
    #[cfg(feature = "test-m5-native")]
    NativeJob(NativeDiagnostic<192>),
    #[cfg(feature = "test-m5-native")]
    NativeSystem(NativeDiagnostic<384>),
    #[cfg(feature = "test-m5-native")]
    NativeFault(NativeFault),
    #[cfg(feature = "test-m5-native")]
    NativeJobField(NativeJobField),
}
/// Three allocator snapshots, not a peak or a whole-machine RAM census.
#[cfg(feature = "test-m5-native")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum NativeMemoryPhase {
    Before = 0,
    Held = 1,
    After = 2,
}
#[cfg(feature = "test-m5-native")]
pub struct NativeMemory {
    pub phase: NativeMemoryPhase,
    pub total_frames: u64,
    pub remaining_frames: u64,
}
#[cfg(feature = "test-m5-native")]
pub struct NativeDiagnostic<const N: usize> {
    pub report: u32,
    pub root_process: u64,
    pub root_thread: u64,
    pub bytes: [u8; N],
}
#[cfg(feature = "test-m5-native")]
pub struct NativeFault {
    pub actor: u8,
    pub image_sha256: [u8; 32],
    pub root_epoch: u64,
    pub root_incarnation: u64,
    pub words: [u64; 24],
}
#[cfg(feature = "test-m5-native")]
pub struct NativeJobField {
    pub sequence: u64,
    pub root_process: u64,
    pub root_thread: u64,
    pub capability: u64,
    pub field: u64,
    pub value: u64,
    pub tick: u64,
    pub status: u64,
    pub denial: u8,
}
#[cfg(feature = "test-m5-native")]
#[derive(Clone, Copy)]
pub enum NativeActionKind {
    Start,
    Stop,
    Reap,
}
#[cfg(feature = "test-m5-native")]
pub struct NativeAction {
    pub kind: NativeActionKind,
    pub image_sha256: [u8; 32],
    pub process: u64,
    pub thread: u64,
}
#[cfg(feature = "test-m5-native")]
pub struct NativeSelfIdentity {
    pub sequence: u64,
    pub process: u64,
    pub thread: u64,
    pub root_epoch: u64,
    pub root_incarnation: u64,
    pub root_manifest_sha256: [u8; 32],
    pub tick: u64,
}
#[cfg(feature = "test-m5-native")]
pub struct NativeCriticalReady {
    pub process: u64,
    pub thread: u64,
    pub image_sha256: [u8; 32],
    pub tick: u64,
}
#[cfg(feature = "test-m5-native")]
pub struct NativeCommonPrefix {
    pub mode: u16,
    pub root_process: u64,
    pub root_thread: u64,
    pub root_image_sha256: [u8; 32],
    pub root_epoch: u64,
    pub root_incarnation: u64,
    pub root_manifest_sha256: [u8; 32],
    pub block_process: u64,
    pub block_thread: u64,
    pub block_image_sha256: [u8; 32],
    pub system_endpoint: usize,
    pub root_frames: u64,
    pub block_frames: u64,
}
#[cfg(feature = "test-m5-native")]
pub struct NativeManagedRead {
    pub root_process: u64,
    pub root_thread: u64,
    pub process: u64,
    pub thread: u64,
    pub image_sha256: [u8; 32],
    pub source_endpoint: usize,
    pub inbox_endpoint: usize,
    pub nonce: u32,
    pub ticket: u64,
}
#[cfg(feature = "test-m5-native")]
pub struct NativeInhibit {
    pub root_process: u64,
    pub root_thread: u64,
    pub process: u64,
    pub thread: u64,
    pub image_sha256: [u8; 32],
    pub outbound_pending: u64,
}
#[cfg(feature = "test-m5-native")]
pub struct NativeSnapshot {
    pub report: u32,
    pub snapshot: root_v2::native::report::Snapshot,
    pub actual_process: u64,
    pub actual_thread: u64,
    pub actual_image_sha256: [u8; 32],
    pub identity_matches: bool,
}
#[derive(Default)]
pub struct Proof {
    pub processes: u64,
    pub starts: u64,
    pub faults: u64,
    pub restarts: u64,
    pub calls: u64,
    pub replies: u64,
    pub grants: u64,
    pub frames: bool,
    pub metadata: bool,
    pub guards: bool,
    pub display_survived: bool,
}
#[derive(Default)]
struct Facts {
    created: u64,
    starts: u64,
    stops: u64,
    reaps: u64,
    calls: u64,
    blocks: u64,
    wakes: u64,
    replies: u64,
    mapped: u64,
    max_pending: u64,
    faults: u64,
    grants: u64,
    restarts: u64,
    retired_cpu: u64,
}
struct Root<'a, 'manifest> {
    active: Option<Active<'manifest, RootImage<'a>>>,
    context: UserContext,
    fx: FxState,
    meta: Metadata,
}
/// Explicit retained ownership variants; shared Root execution never copies an
/// inner physical root or forgets the Native owner's additional bank claims.
enum RootImage<'a> {
    #[cfg(not(feature = "test-m5-native"))]
    Desktop(ProcessImage<'a>),
    #[cfg(feature = "test-m5-native")]
    Native(crate::native_runtime::image::NativeProcessImage<'a>),
}
#[cfg(not(feature = "test-m5-native"))]
type RootLoadedImage = LoadedImage;
#[cfg(feature = "test-m5-native")]
type RootLoadedImage = crate::executable_runtime::NativeLoadedImage;
impl RootImage<'_> {
    fn loaded(&self) -> &RootLoadedImage {
        match self {
            #[cfg(not(feature = "test-m5-native"))]
            Self::Desktop(image) => image.loaded,
            #[cfg(feature = "test-m5-native")]
            Self::Native(image) => image.image().loaded(),
        }
    }
}
// SAFETY: both variants retain their original checked non-Clone executable
// owner. Delegating read-only information does not weaken either constructor.
unsafe impl ev_kernel::loaded_image::LoadedExecutable for RootImage<'_> {
    fn information(&self) -> ev_kernel::loaded_image::Information {
        match self {
            #[cfg(not(feature = "test-m5-native"))]
            Self::Desktop(image) => image.information(),
            #[cfg(feature = "test-m5-native")]
            Self::Native(image) => image.information(),
        }
    }
    fn layout(&self) -> ev_kernel::executable::LayoutReservation {
        match self {
            #[cfg(not(feature = "test-m5-native"))]
            Self::Desktop(image) => image.layout(),
            #[cfg(feature = "test-m5-native")]
            Self::Native(image) => image.layout(),
        }
    }
}
struct Runtime<'image, 'state> {
    a: &'state mut Authority,
    s: &'state mut Scheduler,
    registry: &'state mut Registry<'static>,
    rpc: &'state mut Rpc,
    root: Root<'image, 'state>,
    token: Token,
    backing: &'state mut Backing,
    hw: Hardware,
    actors: [Option<Actor<'image>>; 6],
    slots: [Option<&'image mut GraphicsImage>; 6],
    wires: [Option<Wire>; 16],
    pending: [Option<Pending>; 8],
    stop: Deadline,
    facts: Facts,
    dimensions: (u32, u32),
    observations: &'state mut dyn FnMut(Observation),
    last_present: [Option<Step>; 2],
    picker: Option<(Step, u64)>,
    old: [Option<Metadata>; 6],
    barrier: Option<observation::Barrier>,
    request: u32,
    open: Option<(Metadata, u32)>,
    awaiting_open: Option<Metadata>,
    selection: Option<observation::Selection>,
    snapshots: [observation::Snapshot; 2],
    grants: grant::Grants,
    jobs: [Option<JobId>; 16],
    receipts: [Option<ev_kernel::ipc::RetiredMailbox>; 1],
    root_branches: SpaceId,
    boot: JobId,
    restored: Option<(ProcessId, u64)>,
    #[cfg(not(feature = "test-m5-native"))]
    settled: Option<u64>,
    display_original: Option<ProcessId>,
    #[cfg(feature = "test-m5-native")]
    image_shas: [[u8; 32]; 6],
    #[cfg(feature = "test-m5-native")]
    native: Option<crate::native_runtime::State<'state>>,
}
fn scalar(f: &mut UserContext, status: u64, value: u64) {
    f.registers[14] = status;
    f.registers[9] = value;
    f.registers[11] = 0;
}
fn extended(f: &mut UserContext, status: u64, value: u64, nonce: u64) {
    scalar(f, status, value);
    f.registers[5] = nonce;
}
fn kind(tag: u8) -> Kind {
    match tag {
        1 => Kind::Memory,
        2 => Kind::Endpoint,
        3 => Kind::Process,
        4 => Kind::Thread,
        5 => Kind::Job,
        6 => Kind::Mutex,
        7 => Kind::IoPorts,
        8 => Kind::Display,
        _ => panic!("measured kind"),
    }
}
impl Runtime<'_, '_> {
    fn source_identity(&self, index: usize, kind: Kind) -> usize {
        self.a
            .authorize(
                self.backing.custody,
                self.backing.sources[index],
                kind,
                Rights::READ,
            )
            .or_else(|_| {
                self.a.authorize(
                    self.backing.custody,
                    self.backing.sources[index],
                    kind,
                    Rights::CONTROL,
                )
            })
            .unwrap()
            .identity()
    }
    fn metadata(&self, index: usize) -> Option<Metadata> {
        if index == 0 {
            Some(self.root.meta)
        } else {
            self.actors[index - 1].as_ref().map(|a| a.meta)
        }
    }
    fn current(&self, index: usize) -> Metadata {
        let m = self.metadata(index).expect("retained actual actor");
        assert_eq!(self.s.state(m.thread), Ok(State::Running(0)));
        assert_eq!(self.s.thread_process(m.thread), Ok(m.process));
        assert_eq!(self.s.process_job(m.process), Ok(m.job));
        m
    }
    fn index_thread(&self, thread: ThreadId) -> Option<usize> {
        (0..7).find(|&i| self.metadata(i).is_some_and(|m| m.thread == thread))
    }
    fn context_mut(&mut self, index: usize) -> &mut UserContext {
        if index == 0 {
            &mut self.root.context
        } else {
            &mut self.actors[index - 1].as_mut().unwrap().context
        }
    }
    fn on_admitted(&mut self, index: usize) {
        let meta = self.metadata(index).unwrap();
        if index == Child::Display.index() + 1 {
            assert!(self.display_original.is_none());
            self.display_original = Some(meta.process);
        }

        if let Some(old) = self.old[index - 1].take() {
            let display_process = self
                .metadata(Child::Display.index() + 1)
                .unwrap()
                .process
                .diagnostic_id();
            self.facts.restarts += 1;
            (self.observations)(Observation::Lifecycle(Lifecycle {
                actor: if index == Child::App.index() + 1 {
                    Producer::App
                } else {
                    Producer::Shell
                },
                fault: None,
                process: old.process.diagnostic_id(),
                thread: old.thread.diagnostic_id(),
                replacement: meta.process.diagnostic_id(),
                display_process,
                grants: self.facts.grants,
            }));
        }
    }
    fn before_reply(&mut self, p: Pending, value: u64) -> Option<Step> {
        if !matches!(p.wire, 0 | 1) {
            return None;
        }
        let producer = if p.wire == Channel::AppPresent.index() {
            Producer::App
        } else {
            Producer::Shell
        };
        if p.callee != Child::Display.index() + 1
            || p.caller
                != if producer == Producer::App {
                    Child::App.index() + 1
                } else {
                    Child::Shell.index() + 1
                }
        {
            return None;
        }
        let request = p.value.to_le_bytes();
        let reply = value.to_le_bytes();
        if &request[..4] != b"EVP1" || &reply[..4] != b"EVR1" || request[4..] != reply[4..] {
            return None;
        }
        let caller = self.metadata(p.caller).unwrap();
        let actor = self.actors[p.caller - 1].as_ref().unwrap();
        let image = actor.image().unwrap();
        let extent = if producer == Producer::App {
            &self.backing.app
        } else {
            &self.backing.shell
        };
        let lease = image.surface().unwrap();
        assert!(self.s.waiting(p.wait));
        let mut hash = Sha256::new();
        let mut header = [0u8; 64];
        let mut at = 0usize;
        for physical in extent.physical_pages(lease).unwrap() {
            let address = direct_address(self.hw.offset, physical, self.hw.bits).unwrap();
            for byte in 0..FRAME_SIZE as usize {
                // SAFETY: exact retained initialized extent, actual writer remains
                // blocked on this protected Present; no other actor has WRITE.
                let b = unsafe { (address as *const u8).add(byte).read_volatile() };
                if at < 64 {
                    header[at] = b;
                }
                if at >= 64 + 320 * 200 * 4 && b != 0 {
                    return None;
                }
                hash.update([b]);
                at += 1;
            }
        }
        if &header[..8] != b"EVSURF01"
            || u16::from_le_bytes(header[8..10].try_into().unwrap()) != 1
            || u16::from_le_bytes(header[10..12].try_into().unwrap()) != 64
            || u16::from_le_bytes(header[12..14].try_into().unwrap()) != 320
            || u16::from_le_bytes(header[14..16].try_into().unwrap()) != 200
            || u32::from_le_bytes(header[16..20].try_into().unwrap()) != 1280
            || u32::from_le_bytes(header[20..24].try_into().unwrap()) != 1
            || header[32..].iter().any(|&x| x != 0)
        {
            return None;
        }
        let frame = u64::from_le_bytes(header[24..32].try_into().unwrap());
        if frame == 0
            || frame == u64::MAX
            || u32::from_le_bytes(request[4..].try_into().unwrap()) as u64 != frame
        {
            return None;
        }
        let step = Step {
            kind: StepKind::Frame,
            frame,
            width: self.dimensions.0,
            height: self.dimensions.1,
            app_process: self
                .metadata(Child::App.index() + 1)
                .map_or(0, |m| m.process.diagnostic_id()),
            shell_process: self
                .metadata(Child::Shell.index() + 1)
                .map_or(0, |m| m.process.diagnostic_id()),
            display_process: self
                .metadata(Child::Display.index() + 1)
                .unwrap()
                .process
                .diagnostic_id(),
            grants: self.facts.grants,
            producer,
            surface_sha256: hash.finalize().into(),
            held_ticks: 0,
        };
        assert_eq!(
            caller.process.diagnostic_id(),
            if producer == Producer::App {
                step.app_process
            } else {
                step.shell_process
            }
        );
        self.last_present[usize::from(producer == Producer::Shell)] = Some(step);
        #[cfg(not(feature = "test-m5-native"))]
        if producer == Producer::App
            && self
                .restored
                .is_some_and(|(app, tick)| app == caller.process && crate::timer::now() >= tick)
            && self.grants.current_target() == Some(caller)
            && self.facts.grants == 3
        {
            self.settled = Some(crate::timer::now().checked_add(128).unwrap());
        }
        Some(step)
    }
}
