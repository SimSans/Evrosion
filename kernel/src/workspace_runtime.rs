//! Selected V5 physical executor. No V4 selection, source wrapper or artifact
//! provenance is cast into this graph. Actual inputs and resource owners are
//! retained separately from all portable metadata admission receipts.
use core::{arch::asm, num::NonZeroU64};
use ev_kernel::{
    capability::{Authority, Handle, Kind, Rights, SpaceId},
    custodian::Custodian,
    incarnation::{Active, Token},
    ipc::{Mailbox, Outgoing, Ticket},
    memory::BootstrapFrames,
    rpc::{CallId, MessageShape, Policy, Rpc, Status},
    scheduler::{JobId, Limits, ProcessId, Resource, Scheduler, State, ThreadId, WaitTicket},
    service::{Metadata, Registry, Running, ServiceImage},
    time::Deadline,
    user_context::{Call, FxState, UserContext, decode},
};
use ev_userspace_contract::root_v5::{
    self as v5, Role,
    graph::{self, Channel, Child, DeliveryMode, ImageSlot},
};
use sha2::{Digest, Sha256};
mod assets;
mod backing;
#[cfg(feature = "test-m8-workspace-run")]
mod bundle;
mod dispatch;
mod dynamic;
mod executor;
mod grant;
mod image;
mod lifecycle;
mod mapping;
mod pio;
mod power;
mod resident;
mod transport;
mod world;
pub(crate) use assets::{Artifact, Assets};
use backing::Backing;
use core::fmt::Write;
use ev_kernel::ipc::Error as IpcError;
use image::{ImageLease, PhysicalImage};
use transport::{Pending, Wire};
struct Root {
    active: Option<Active<'static, ImageLease<'static>>>,
    meta: Metadata,
    context: UserContext,
    fx: FxState,
}
struct Actor {
    child: Child,
    meta: Metadata,
    control: Handle,
    object: usize,
    running: Option<Running<ImageLease<'static>>>,
    returned: Option<ImageLease<'static>>,
    context: UserContext,
    fx: FxState,
    admitted: bool,
    retired: bool,
    fault: Option<ev_kernel::fault::Record>,
    // Only the extra held File App may begin without a fixed instance binding.
    bound: bool,
    prepared: Option<&'static mut PhysicalImage>,
    dynamic_slot: Option<usize>,
}
#[derive(Default)]
struct BlockTrace {
    attempts: u64,
    accepted: u64,
    replies: u64,
    at: u64,
    done: u64,
    request: u64,
    deadline: u64,
    caller: usize,
    parent: Option<CallId>,
    id: Option<CallId>,
    //0attempt,1accepted,2reply,3deniedbeforeaccept,4Rpcerror,5terminal.
    outcome: u64,
    status: u64,
    response: u64,
    error: Option<ev_kernel::rpc::Error>,
}
#[derive(Default)]
struct Facts {
    created: u64,
    starts: u64,
    stops: u64,
    reaps: u64,
    calls: u64,
    replies: u64,
    grants: u64,
    irq_cpu: u64,
    irq_by_actor: [u64; 13],
    block: BlockTrace,
    pio: pio::Metrics,
}
struct World {
    core: resident::Core,
    hw: Hardware,
    root: Root,
    token: Token,
    custodian: Custodian<'static>,
    root_grants: [Handle; 37],
    actors: [Option<Actor>; 12],
    vacant: [Option<&'static mut PhysicalImage>; 12],
    dynamic: &'static mut dynamic::State,
    spare_claimed: bool,
    wires: [Option<Wire>; 24],
    pending: [Option<Pending>; 8],
    selected: [grant::Selected; 4],
    images: [Artifact; 10],
    jobs: [Option<JobId>; 16],
    stop: Deadline,
    started: u64,
    facts: Facts,
    root_exited: bool,
    power: ev_kernel::session_power::Latch,
    log_retention: crate::session_log::Retention,
}
impl World {
    fn metadata(&self, index: usize) -> Option<Metadata> {
        if index == 0 {
            Some(self.root.meta)
        } else {
            self.actors.get(index - 1)?.as_ref().map(|a| a.meta)
        }
    }
    fn current(&self, index: usize) -> Metadata {
        self.metadata(index).expect("actual dispatched V5 owner")
    }
    fn index_thread(&self, thread: ThreadId) -> Option<usize> {
        (0..13).find(|&i| self.metadata(i).is_some_and(|m| m.thread == thread))
    }
    fn context_mut(&mut self, index: usize) -> &mut UserContext {
        if index == 0 {
            &mut self.root.context
        } else {
            &mut self.actors[index - 1].as_mut().unwrap().context
        }
    }
    fn wire(&self, meta: Metadata, cap: Handle, rights: Rights) -> Option<usize> {
        let id = self
            .core
            .a
            .authorize(meta.domain, cap, Kind::Endpoint, rights)
            .ok()?
            .identity();
        self.wires
            .iter()
            .position(|w| w.as_ref().is_some_and(|w| w.object == id))
    }
    fn find_control(&self, caller: SpaceId, cap: Handle) -> Result<usize, u64> {
        let meta = self
            .core
            .registry
            .metadata(self.core.a, caller, cap)
            .map_err(|_| 1u64)?;
        let object = self
            .core
            .a
            .authorize(caller, cap, Kind::Process, Rights::CONTROL)
            .map_err(|_| 1u64)?
            .identity();
        self.actors
            .iter()
            .position(|a| {
                a.as_ref()
                    .is_some_and(|a| a.meta == meta && a.object == object)
            })
            .map(|i| i + 1)
            .ok_or(1)
    }
    fn event(&self, log: &mut dyn Write, phase: &str, index: usize) {
        if let Some(m) = self.metadata(index) {
            let cpu = self.core.s.usage(m.job, Resource::CpuTicks).unwrap();
            let _ = writeln!(
                log,
                "EVROSION_M8_KERNEL_ACTOR phase={phase} actor={index} process={} thread={} job={} frames={} cpu={cpu} tick={} elapsed={}",
                m.process.diagnostic_id(),
                m.thread.diagnostic_id(),
                m.job.diagnostic_id(),
                m.frames,
                crate::timer::now(),
                crate::timer::now().saturating_sub(self.started)
            );
        }
    }
}
pub(crate) struct Proof {
    pub starts: u64,
    pub calls: u64,
    pub replies: u64,
    pub root_exited: bool,
    pub retained: bool,
    pub checked_shutdown: bool,
    pub checked_restart: bool,
}
#[cfg(feature = "test-m8-workspace-run")]
pub(crate) fn embedded_assets() -> Assets {
    bundle::assets()
}
/// # Safety
/// Actual typed V5 assets and exclusive BSP/allocator/GOP/controller ownership;
/// hardware entry initialized and APs parked. No physical qualification is
/// inferred from compiling this mechanism-only entry point.
pub(crate) unsafe fn run(
    offset: u64,
    frames: &mut BootstrapFrames,
    fb: ev_boot_contract::Framebuffer,
    assets: &Assets,
    max_ticks: u64,
    log: &mut dyn Write,
) -> Proof {
    // SAFETY: forwards exact typed-assets/CPU/allocator ownership conditions.
    unsafe { world::run(offset, frames, fb, assets, max_ticks, log) }
}
#[derive(Clone, Copy)]
pub(crate) struct Hardware {
    offset: u64,
    bits: u8,
    original: u64,
}
pub(crate) const EPOCH: NonZeroU64 = NonZeroU64::new(805).unwrap();
const RECEIVE: Rights = Rights::from_bits(272).unwrap();
fn kind(tag: u8) -> Kind {
    match tag {
        1 => Kind::Memory,
        2 => Kind::Endpoint,
        5 => Kind::Job,
        7 => Kind::IoPorts,
        8 => Kind::Display,
        _ => panic!("V5 measured kind"),
    }
}
fn scalar(frame: &mut UserContext, status: u64, value: u64) {
    frame.registers[14] = status;
    frame.registers[9] = value;
    frame.registers[11] = 0;
}
fn extended(frame: &mut UserContext, status: u64, value: u64, nonce: u64) {
    scalar(frame, status, value);
    frame.registers[5] = nonce;
}
