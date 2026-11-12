//! Ordinary three-slot protected executor. Source-built Ring3 Root chooses all
//! images and route replacement; this module owns mechanisms and diagnostics.
use crate::executable_runtime::{LoadedImage, ProcessImage};
use core::{arch::asm, num::NonZeroU64};
use ev_kernel::{
    bootstrap_binding::CatalogEntry,
    bootstrap_manifest,
    capability::{Authority, Handle, Kind, Rights, SpaceId},
    incarnation::{Active, Bindings, Target, Token},
    ipc::{Error as IpcError, MAX_MESSAGES, Mailbox, Outgoing, Ticket},
    mapping::ADDRESS_MASK,
    memory::BootstrapFrames,
    rpc::{CallId, MessageShape, Policy, Rpc, Status},
    scheduler::{JobId, Limits, ProcessId, Scheduler, State, ThreadId, WaitTicket},
    service::{Metadata, Registry, Role, Running, ServiceImage},
    time::Deadline,
    user_context::{Call, FxState, UserContext, decode},
};
use sha2::{Digest, Sha256};
const EPOCH: NonZeroU64 = NonZeroU64::new(601).unwrap();
const RECEIVE: Rights = Rights::from_bits(272).unwrap();
const CHILD_LIMITS: Limits = Limits::new(16384, 32, 1, 1);
const WORLD_TICKS: u64 = 16384;
pub struct ImageAsset {
    pub bytes: &'static [u8],
    pub sha: [u8; 32],
    pub descriptor: [u8; 32],
    pub roles: &'static [Role],
    pub actor: ActorKind,
}
#[cfg(feature = "test-m5-provider")]
pub struct Assets {
    pub root_image: &'static [u8],
    pub root_manifest: &'static [u8],
    pub root_measurement: [u8; 32],
    pub images: [ImageAsset; 3],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorKind {
    Root,
    Consumer,
    Provider,
}
#[derive(Clone, Copy)]
pub enum LifeKind {
    Start,
    Stop,
    Reap,
    Exit,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub process: u64,
    pub thread: u64,
    pub image_sha256: [u8; 32],
}
pub struct Lifecycle {
    pub actor: ActorKind,
    pub kind: LifeKind,
    pub identity: Identity,
    pub exit_code: Option<u64>,
}
pub struct Binding {
    pub owner: Identity,
    pub endpoint: u64,
    pub target: Identity,
}
pub struct CompletedCall {
    pub nonce: u64,
    pub endpoint: u64,
    pub send_handle: u64,
    pub caller: Identity,
    pub callee: Identity,
    pub request: u64,
    pub reply: u64,
}
pub enum Observation {
    Measurement {
        root: Identity,
        event: measurement::Event,
    },
    Lifecycle(Lifecycle),
    Binding(Binding),
    Call(CompletedCall),
}
#[derive(Default)]
pub struct Proof {
    pub actors: u64,
    pub starts: u64,
    pub stops: u64,
    pub reaps: u64,
    pub exits: u64,
    pub calls: u64,
    pub replies: u64,
    pub bindings: u64,
    pub root_exit: Option<u64>,
    pub consumer_exit: Option<u64>,
    pub outer_ready: u64,
    pub switch_complete: u64,
    pub frames: bool,
    pub metadata: bool,
    pub mappings: bool,
    pub authority: bool,
    pub rejected_calls: u64,
    pub batch_before: Option<measurement::Snapshot>,
    pub batch_after: Option<measurement::Snapshot>,
    pub sample: Option<[u64; 4]>,
    pub batch_finished: u64,
}
struct Root<'a, 'manifest> {
    active: Option<Active<'manifest, ProcessImage<'a>>>,
    meta: Metadata,
    context: UserContext,
    fx: FxState,
    image: [u8; 32],
}
struct Actor<'a> {
    meta: Metadata,
    object: usize,
    image: usize,
    kind: ActorKind,
    image_sha256: [u8; 32],
    vacant: Option<&'a mut LoadedImage>,
    running: Option<Running<ProcessImage<'a>>>,
    returned: Option<ProcessImage<'a>>,
    context: UserContext,
    fx: FxState,
    admitted: bool,
    retired: bool,
    registered: bool,
}
#[cfg(feature = "test-m5-ipc-bench")]
pub struct BenchmarkAssets {
    pub root_image: &'static [u8],
    pub root_manifest: &'static [u8],
    pub root_measurement: [u8; 32],
    pub images: [ImageAsset; 2],
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    ProviderSwitch,
    Measurement,
}
struct SourceAssets<'a> {
    root_image: &'static [u8],
    root_manifest: &'static [u8],
    root_measurement: [u8; 32],
    images: &'a [ImageAsset],
}
struct Runtime<'a, 'b> {
    a: &'b mut Authority,
    s: &'b mut Scheduler,
    registry: &'b mut Registry<'static>,
    rpc: &'b mut Rpc,
    root: Root<'a, 'b>,
    token: Token,
    actors: [Option<Actor<'a>>; 2],
    slots: [Option<&'a mut LoadedImage>; 2],
    wires: [Option<Wire>; 4],
    pending: Option<Pending>,
    jobs: [Option<JobId>; 2],
    sources: [Handle; 6],
    images: [usize; 3],
    assets: &'b SourceAssets<'b>,
    mode: Mode,
    measurement: measurement::Recorder,
    stop: Deadline,
    offset: u64,
    bits: u8,
    original: u64,
    facts: Proof,
    root_exited: bool,
    observations: &'b mut dyn FnMut(Observation),
    custody: SpaceId,
}
mod abi;
pub mod measurement;
use abi::{extended, scalar};
mod transport;
use transport::{Pending, Wire};
mod dispatch;
mod lifecycle;
mod world;
#[cfg(feature = "test-m5-provider")]
pub use world::prove;
#[cfg(feature = "test-m5-ipc-bench")]
pub use world::prove_benchmark;
impl Runtime<'_, '_> {
    fn meta(&self, index: usize) -> Option<Metadata> {
        if index == 0 {
            Some(self.root.meta)
        } else {
            self.actors[index - 1].as_ref().map(|a| a.meta)
        }
    }
    fn current(&self, index: usize) -> Metadata {
        self.meta(index).unwrap()
    }
    fn index_thread(&self, thread: ThreadId) -> Option<usize> {
        (0..3).find(|&i| self.meta(i).is_some_and(|m| m.thread == thread))
    }
    fn context_mut(&mut self, index: usize) -> &mut UserContext {
        if index == 0 {
            &mut self.root.context
        } else {
            &mut self.actors[index - 1].as_mut().unwrap().context
        }
    }
    fn identity(&self, index: usize) -> Identity {
        let m = self.current(index);
        Identity {
            process: m.process.diagnostic_id(),
            thread: m.thread.diagnostic_id(),
            image_sha256: if index == 0 {
                self.root.image
            } else {
                self.actors[index - 1].as_ref().unwrap().image_sha256
            },
        }
    }
    fn observe_life(&mut self, index: usize, kind: LifeKind, code: Option<u64>) {
        let actor = if index == 0 {
            ActorKind::Root
        } else {
            self.actors[index - 1].as_ref().unwrap().kind
        };
        let lifecycle = Lifecycle {
            actor,
            kind,
            identity: self.identity(index),
            exit_code: code,
        };
        (self.observations)(Observation::Lifecycle(lifecycle));
    }
    fn find_control(&self, caller: SpaceId, cap: Handle) -> Result<usize, u64> {
        let m = self
            .registry
            .metadata(self.a, caller, cap)
            .map_err(|_| 1u64)?;
        let object = self
            .a
            .authorize(caller, cap, Kind::Process, Rights::CONTROL)
            .map_err(|_| 1u64)?
            .identity();
        self.actors
            .iter()
            .position(|a| {
                a.as_ref()
                    .is_some_and(|a| a.meta == m && a.object == object)
            })
            .map(|i| i + 1)
            .ok_or(1)
    }
    /// # Safety
    /// Sole restored-CR3 controller and exact retained private/FX owners.
    unsafe fn run(&mut self, frames: &mut BootstrapFrames) {
        // SAFETY: sole initialized PIC/PIT/BSP runtime owner.
        unsafe { crate::timer::start_runtime() };
        for _ in 0..2_000_000u64 {
            let now = crate::timer::now();
            assert!(!self.stop.reached(now), "provider finite world bound");
            assert!(self.rpc.expire(now).unwrap().is_empty());
            self.s.advance(now).unwrap();
            self.drain_outer();
            let dispatch = self
                .s
                .dispatch(0)
                .unwrap()
                .expect("provider runnable actor");
            let index = self
                .index_thread(dispatch.thread)
                .expect("actual retained provider thread");
            assert_eq!(self.current(index).process, dispatch.process);
            let (mut frame, address) = if index == 0 {
                self.root
                    .active
                    .as_ref()
                    .unwrap()
                    .image()
                    .loaded
                    .root
                    .activate();
                // SAFETY: current Root actual private image and context; capture restores CR3/IF0.
                unsafe {
                    crate::user_runtime::resume_context(
                        &self.root.context,
                        &mut self.root.fx,
                        self.original,
                    )
                }
            } else {
                let actor = self.actors[index - 1].as_mut().unwrap();
                actor
                    .running
                    .as_ref()
                    .unwrap()
                    .image()
                    .loaded
                    .root
                    .activate();
                // SAFETY: same exclusive actual actor image/FX/context ownership.
                unsafe {
                    crate::user_runtime::resume_context(
                        &actor.context,
                        &mut actor.fx,
                        self.original,
                    )
                }
            };
            let blocked = match frame.vector {
                32 => {
                    self.s.charge_cpu(0, 1).unwrap();
                    false
                }
                128 => self.syscall(index, &mut frame, frames),
                _ => panic!(
                    "provider unexpected fault actor={index} vector={} error={} ip={:#x} address={address:#x}",
                    frame.vector, frame.error, frame.rip
                ),
            };
            *self.context_mut(index) = frame;
            if !blocked {
                self.s.yield_cpu(0).unwrap();
            }
            self.drain_outer();
            if self.root_exited {
                assert_eq!(self.rpc.outstanding(), 0);
                assert!(self.pending.is_none());
                return;
            }
        }
        panic!("provider finite transitions exhausted");
    }
    fn drain_outer(&mut self) {
        let root = self.root.meta;
        let origin = self.identity(0);
        let wire = self.wires[3].as_mut().unwrap();
        for _ in 0..MAX_MESSAGES {
            match wire.receive(self.a, self.custody, self.sources[1], crate::timer::now()) {
                Ok((delivery, process, thread)) => {
                    assert_eq!((process, thread), (root.process, root.thread));
                    assert_eq!(delivery.capability, None);
                    assert_eq!(delivery.length, 8);
                    let body: &[u8] = &delivery.bytes[..8];
                    if self.mode == Mode::ProviderSwitch {
                        if body == ev_userspace_contract::Event::Ready.encode() {
                            self.facts.outer_ready += 1;
                        } else if body == [b'P', b'R', 1, 3, 0, 0, 0, 0] {
                            self.facts.switch_complete += 1;
                        } else {
                            panic!("unknown actual Root outer event");
                        }
                    } else {
                        let body: [u8; 8] = body.try_into().unwrap();
                        let event = self
                            .measurement
                            .push(
                                body,
                                crate::timer::now(),
                                self.facts.calls,
                                self.facts.replies,
                                self.facts.rejected_calls,
                                self.pending.is_some() || self.rpc.outstanding() != 0,
                            )
                            .expect("actual Root measurement frame order");
                        if let Some(event) = event {
                            match event {
                                measurement::Event::Ready => self.facts.outer_ready += 1,
                                measurement::Event::Snapshot(s) if s.phase == 1 => {
                                    self.facts.batch_before = Some(s)
                                }
                                measurement::Event::Snapshot(s) => self.facts.batch_after = Some(s),
                                measurement::Event::Sample(words) => {
                                    self.facts.sample = Some(words)
                                }
                                measurement::Event::Finish => self.facts.batch_finished += 1,
                            }
                            (self.observations)(Observation::Measurement {
                                root: origin,
                                event,
                            });
                        }
                    }
                }
                Err(IpcError::Empty) => break,
                Err(error) => panic!("provider outer receipt: {error:?}"),
            }
        }
    }
}
