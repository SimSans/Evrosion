//! Measured two-process graphics execution and contained hardware fault worlds.
//! Display owns the device mapping; this controller never paints scanout RAM.
use crate::{
    display_runtime::{DisplayAperture, OwnedDisplayTables},
    graphics_image::{Error as ImageError, GraphicsImage, GraphicsProcessImage},
    supervisor_runtime::bundle,
};
use core::{arch::asm, num::NonZeroU64};
use ev_boot_contract::Framebuffer;
use ev_kernel::{
    capability::{Authority, Error as CapError, Handle, Kind, Rights, SpaceId},
    display::DisplayObject,
    executable::LayoutReservation,
    fault::Record,
    ipc::{Error as IpcError, Mailbox, Outgoing, Ticket},
    mapping::{ADDRESS_MASK, NO_EXECUTE, PRESENT, WRITABLE, direct_address},
    memory::{BootstrapFrames, FRAME_SIZE},
    memory_extent::{Error as ExtentError, ExtentLease, MemoryExtent, RamAccess, UninitializedRam},
    rpc::{CallId, MessageShape, Policy, Rpc, Status},
    scheduler::{Limits, Resource, Scheduler, State, WaitTicket},
    service::{Metadata, Registry, Role, Running, ServiceImage},
    time::Deadline,
    user::USER,
    user_context::{Call, FxState, UserContext, decode},
};
use sha2::{Digest, Sha256};
mod hardware;
mod transport;
use hardware::Hardware;

const LIMITS: Limits = Limits::new(2048, 32, 1, 1);
const RECEIVE: Rights = Rights::from_bits(272).unwrap();
const SURFACE_PAGES: usize = 63;
const SURFACE_BYTES: usize = 64 + 320 * 200 * 4;
const AD: u64 = (1 << 5) | (1 << 6);
const TRANSITIONS: u64 = 100_000;
const EPOCH: NonZeroU64 = NonZeroU64::new(401).unwrap();

pub struct Present {
    pub width: u32,
    pub height: u32,
    pub app_process: u64,
    pub display_process: u64,
    pub surface_sha256: [u8; 32],
}
pub struct Proof {
    pub worlds: u64,
    pub calls: u64,
    pub blocks: u64,
    pub wakes: u64,
    pub replies: u64,
    pub faults: u64,
    pub authority_denied: u64,
    pub mapped: u64,
    pub surface_pages: u64,
    pub display_tables: u64,
    pub peak_frames: u64,
    pub max_pending: u64,
    pub app_fault: Record,
    pub display_fault: Record,
    pub frames: bool,
    pub metadata: bool,
    pub guards: bool,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum World {
    Normal,
    AppFault,
    DisplayFault,
}
#[derive(Default)]
struct Counters {
    calls: u64,
    blocks: u64,
    wakes: u64,
    replies: u64,
    faults: u64,
    denied: u64,
    mapped: u64,
    tables: u64,
    max_pending: u64,
}
struct Outcome {
    counters: Counters,
    fault: Option<Record>,
    peak: u64,
    pages: u64,
    frames: bool,
    metadata: bool,
    guards: bool,
}
struct Actor<'a> {
    running: Option<Running<GraphicsProcessImage<'a>>>,
    meta: Metadata,
    control: Handle,
    context: UserContext,
    fx: FxState,
    dead: bool,
}
#[derive(Clone, Copy)]
struct Pending {
    id: CallId,
    wait: WaitTicket,
    ticket: Ticket,
    request: u64,
    delivered: bool,
}
struct Runtime<'a, 'state> {
    a: &'state mut Authority,
    s: &'state mut Scheduler,
    registry: &'state mut Registry<'static>,
    rpc: &'state mut Rpc,
    actors: [Option<Actor<'a>>; 2],
    app_slot: Option<&'a mut GraphicsImage>,
    meta: [Metadata; 2],
    controls: [Handle; 2],
    custody: SpaceId,
    present_box: &'state mut Mailbox,
    present_object: usize,
    event_box: &'state mut Mailbox,
    event_cap: Handle,
    event_object: usize,
    extent: &'state MemoryExtent,
    device: &'state DisplayObject<DisplayAperture>,
    display_cap: Handle,
    world: World,
    stop: Deadline,
    pending: Option<Pending>,
    counters: Counters,
    ready: [bool; 2],
    done: [bool; 2],
    bound: bool,
    fault: Option<Record>,
    transitions: u64,
}
fn scalar(frame: &mut UserContext, status: u64, value: u64) {
    frame.registers[14] = status;
    frame.registers[9] = value;
    frame.registers[11] = 0;
    // The scalar ABI preserves compiler-live R10, including clock/Yield/RPC22.
}
fn extended(frame: &mut UserContext, status: u64, value: u64, nonce: u64) {
    scalar(frame, status, value);
    frame.registers[5] = nonce;
}
fn role(selector: u64, kind: Kind, rights: u16) -> Role {
    Role {
        selector,
        kind,
        rights: Rights::from_bits(rights).unwrap(),
    }
}
fn identity(a: &Authority, custody: SpaceId, cap: Handle, kind: Kind) -> usize {
    a.authorize(custody, cap, kind, Rights::CONTROL)
        .unwrap()
        .identity()
}
#[allow(clippy::too_many_arguments)] // Explicit typed owner and admission tables.
fn admit<'a>(
    slot: &'a mut GraphicsImage,
    registry: &mut Registry<'static>,
    a: &Authority,
    s: &mut Scheduler,
    custody: SpaceId,
    control: Handle,
    bound: u64,
) -> Actor<'a> {
    let meta = registry.metadata(a, custody, control).unwrap();
    let image = slot.lease().unwrap();
    let running = registry
        .start(a, s, custody, control, EPOCH, image)
        .unwrap_or_else(|rejected| panic!("graphics admission: {:?}", rejected.error));
    let mut context = running.initial_context().unwrap();
    context.registers[11] = bound;
    Actor {
        running: Some(running),
        meta,
        control,
        context,
        fx: FxState::CLEAN,
        dead: false,
    }
}
impl<'a> Runtime<'a, '_> {
    fn actor(&self, index: usize) -> &Actor<'a> {
        self.actors[index].as_ref().expect("actual admitted actor")
    }
    fn current(&self, index: usize) -> Metadata {
        let actor = self.actor(index);
        let m = actor.meta;
        assert_eq!(self.s.state(m.thread), Ok(State::Running(0)));
        assert_eq!(self.s.thread_process(m.thread), Ok(m.process));
        assert_eq!(self.s.process_job(m.process), Ok(m.job));
        assert_eq!(
            self.registry.metadata(self.a, self.custody, actor.control),
            Ok(m)
        );
        m
    }
    fn start_app(&mut self) {
        assert!(self.ready[0] && self.bound && self.actors[1].is_none());
        let actor = admit(
            self.app_slot.take().unwrap(),
            self.registry,
            self.a,
            self.s,
            self.custody,
            self.controls[1],
            self.stop.tick().checked_add(1024).unwrap(),
        );
        assert_eq!(actor.meta, self.meta[1]);
        self.rpc
            .register_thread(
                self.a,
                self.s,
                actor.meta.thread,
                actor.meta.job,
                actor.meta.domain,
                None,
            )
            .unwrap();
        self.actors[1] = Some(actor);
    }
    fn syscall(&mut self, index: usize, frame: &mut UserContext) -> bool {
        let m = self.current(index);
        match decode(frame) {
            Ok(Call::Yield) => scalar(frame, 0, 0),
            Ok(Call::Monotonic) => scalar(frame, 0, crate::timer::now()),
            Ok(Call::Inspect { capability, rights }) => {
                let denied = self
                    .a
                    .authorize(m.domain, capability, Kind::Memory, rights)
                    .is_err();
                self.counters.denied += u64::from(denied);
                scalar(frame, u64::from(denied), 0);
            }
            Ok(Call::DisplayInfo { capability, field }) => {
                match self.device.mapped_information(self.a, m.domain, capability) {
                    Ok(info) => {
                        let value = match field {
                            1 => {
                                self.actor(index)
                                    .running
                                    .as_ref()
                                    .unwrap()
                                    .image()
                                    .image()
                                    .root()
                                    .base()
                                    + 4 * 1024 * 1024
                                    + u64::from(info.byte_offset)
                            }
                            2 => u64::from(info.width),
                            3 => u64::from(info.height),
                            4 => u64::from(info.stride),
                            5 => u64::from(info.byte_length),
                            6 => u64::from(info.format),
                            _ => {
                                scalar(frame, 3, 0);
                                return false;
                            }
                        };
                        scalar(frame, 0, value);
                    }
                    Err(_) => {
                        self.counters.denied += 1;
                        scalar(frame, 1, 0);
                    }
                }
            }
            Ok(Call::Spawn(_)) => {
                // This explicit profile owns exactly one actual thread/actor.
                // No caller-supplied local role can create another RAM writer.
                assert_eq!(
                    self.s.job_limits(m.job).unwrap().limit(Resource::Threads),
                    1
                );
                assert_eq!(self.s.usage(m.job, Resource::Threads), Ok(1));
                self.counters.denied += 1;
                scalar(frame, 1, 0);
            }
            Ok(Call::BindReceiver { endpoint, process }) if process.0 == 0 => {
                let valid = self
                    .a
                    .authorize(m.domain, endpoint, Kind::Endpoint, RECEIVE)
                    .is_ok_and(|access| access.identity() == self.present_object)
                    && m == self.meta[0];
                if !valid {
                    scalar(frame, 1, 0);
                } else {
                    match self.rpc.bind_endpoint(
                        self.a,
                        m.domain,
                        endpoint,
                        m.thread,
                        Policy::new(8, 0).unwrap(),
                    ) {
                        Ok(()) => {
                            self.bound = true;
                            scalar(frame, 0, 0);
                        }
                        Err(_) => scalar(frame, 1, 0),
                    }
                }
            }
            Ok(Call::Send {
                endpoint,
                value,
                capability: None,
            }) => self.event(index, endpoint, value, frame),
            Ok(Call::Rpc {
                endpoint,
                value,
                deadline,
            }) => return self.call(index, endpoint, value, deadline, frame),
            Ok(Call::ReceiveRpc(endpoint)) => self.receive(index, endpoint, frame),
            Ok(Call::ReplyRpc {
                endpoint,
                value,
                serial,
            }) => self.reply(index, endpoint, value, serial, frame),
            Ok(Call::RpcDeadline) => match self
                .rpc
                .serving(m.thread)
                .and_then(|id| self.rpc.context(id).ok())
            {
                Some(context) => scalar(frame, 0, context.deadline.tick()),
                None => scalar(frame, 1, 0),
            },
            Ok(Call::Exit(code)) => panic!(
                "graphics actor exit index={index} code={code} world={:?}",
                self.world
            ),
            _ => scalar(frame, 3, 0),
        }
        false
    }
    fn event(&mut self, index: usize, endpoint: Handle, value: u64, frame: &mut UserContext) {
        let m = self.current(index);
        if !self
            .a
            .authorize(m.domain, endpoint, Kind::Endpoint, Rights::SEND)
            .is_ok_and(|access| access.identity() == self.event_object)
        {
            scalar(frame, 1, 0);
            return;
        }
        let now = crate::timer::now();
        // Actual running identity and exact accepted Ticket remain local across
        // this serialized cap-free send/receive. No payload PID is accepted and
        // no FIFO assumption substitutes for correlation of the real receipt.
        let ticket = match self.event_box.send(
            self.a,
            m.domain,
            endpoint,
            Outgoing {
                bytes: &value.to_le_bytes(),
                capability: None,
                deadline: Deadline::after(self.stop.tick(), 1024).unwrap(),
            },
            now,
        ) {
            Ok(ticket) => ticket,
            Err(IpcError::Full) => {
                scalar(frame, 2, 0);
                return;
            }
            Err(_) => {
                scalar(frame, 1, 0);
                return;
            }
        };
        let delivery = self
            .event_box
            .receive(self.a, self.custody, self.event_cap, now)
            .unwrap();
        assert_eq!(delivery.ticket, ticket);
        assert_eq!((delivery.length, delivery.capability), (8, None));
        assert_eq!(&delivery.bytes[..8], &value.to_le_bytes());
        assert_eq!(self.s.state(m.thread), Ok(State::Running(0)));
        let body = value.to_le_bytes();
        let accepted = if m == self.meta[0] && body == *b"EVGDRDY1" && self.bound && !self.ready[0]
        {
            self.ready[0] = true;
            self.start_app();
            true
        } else if m == self.meta[1] && body == *b"EVGARDY1" && self.ready[0] && !self.ready[1] {
            self.ready[1] = true;
            true
        } else if m == self.meta[0]
            && body == *b"EVGDDON1"
            && self.counters.replies == 1
            && !self.done[0]
        {
            self.done[0] = true;
            true
        } else if m == self.meta[1]
            && body == *b"EVGADON1"
            && self.counters.replies == 1
            && !self.done[1]
        {
            self.done[1] = true;
            true
        } else {
            false
        };
        scalar(frame, if accepted { 0 } else { 3 }, 0);
    }
    fn fault(&mut self, index: usize, frame: &UserContext, address: u64) {
        assert!(frame.ordinary_user_fault());
        let m = self.current(index);
        let base = self
            .actor(index)
            .running
            .as_ref()
            .unwrap()
            .image()
            .image()
            .root()
            .base();
        let expected = match self.world {
            World::AppFault => {
                assert_eq!(index, 1);
                (14, 4, base + 4 * 1024 * 1024)
            }
            World::DisplayFault => {
                assert_eq!(index, 0);
                (14, 7, base + 384 * FRAME_SIZE + 64)
            }
            World::Normal => panic!("unexpected normal graphics fault"),
        };
        assert_eq!((frame.vector, frame.error, address), expected);
        assert!(self.ready.iter().all(|ready| *ready));
        let record = Record {
            process: m.process.diagnostic_id(),
            thread: m.thread.diagnostic_id(),
            vector: frame.vector,
            error: frame.error,
            address,
            instruction: frame.rip,
        };
        assert_eq!(Record::decode(&record.encode()), Some(record));
        if self.world == World::DisplayFault {
            let pending = self.pending.expect("actual delivered Present");
            assert!(pending.delivered && self.s.waiting(pending.wait));
            assert_eq!(self.rpc.serving(m.thread), Some(pending.id));
        } else {
            assert!(self.pending.is_none());
        }
        self.actors[index]
            .as_mut()
            .unwrap()
            .running
            .as_mut()
            .unwrap()
            .stop(self.a, self.s)
            .unwrap();
        self.s.exit(0).unwrap();
        self.s.terminate_process(m.process).unwrap();
        let notifications = self
            .rpc
            .peer_died(self.s, m.thread, crate::timer::now())
            .unwrap();
        for event in notifications.iter().copied() {
            let pending = self.pending.expect("verified dead callee owns reservation");
            assert_eq!(event.call, pending.id);
            assert_eq!(event.caller, self.meta[1].thread);
            assert_eq!(event.status, Status::PeerDied);
            assert!(event.wake_caller && !event.deliver_reply);
            scalar(&mut self.actors[1].as_mut().unwrap().context, 5, 0);
            assert!(self.s.wake(pending.wait));
            assert!(!self.s.wake(pending.wait));
            self.counters.wakes += 1;
            self.pending = None;
        }
        assert_eq!(self.rpc.outstanding(), 0);
        assert!(self.pending.is_none());
        assert_eq!(self.present_box.pending(), 0);
        self.actors[index].as_mut().unwrap().dead = true;
        self.fault = Some(record);
        self.counters.faults += 1;
    }
    /// # Safety
    /// Exclusive BSP/PIC/actual controller root, APs parked, IF0, retained real
    /// RAM and display owners. Capture restores the controller root each time.
    unsafe fn run(&mut self, hw: &Hardware, on_present: &mut impl FnMut(Present)) -> (u64, u64) {
        let started = crate::timer::now();
        let mut hold = None;
        let mut presented_digest = None;
        // SAFETY: initialized IRQ0 boundary and exclusive PIC/PIT ownership.
        unsafe { crate::timer::start_runtime() };
        for _ in 0..TRANSITIONS {
            let now = crate::timer::now();
            assert!(
                !self.stop.reached(now),
                "graphics bound world={:?} calls={} replies={} ready={:?} done={:?} transitions={}",
                self.world,
                self.counters.calls,
                self.counters.replies,
                self.ready,
                self.done,
                self.transitions
            );
            assert!(self.rpc.expire(now).unwrap().is_empty());
            self.s.advance(now).unwrap();
            let dispatch = self
                .s
                .dispatch(0)
                .unwrap()
                .expect("graphics runnable actor");
            let index = self
                .actors
                .iter()
                .position(|a| a.as_ref().is_some_and(|a| a.meta.thread == dispatch.thread))
                .unwrap();
            assert_eq!(dispatch.process, self.actor(index).meta.process);
            let image = self.actor(index).running.as_ref().unwrap().image().image();
            hw.verify_surface(image, self.a, self.extent);
            image.root().activate();
            let actor = self.actors[index].as_mut().unwrap();
            // SAFETY: actual admitted exclusive graphics image/root/FX owner.
            let (mut frame, address) = unsafe {
                crate::user_runtime::resume_context(&actor.context, &mut actor.fx, hw.original)
            };
            self.transitions += 1;
            assert!(
                !self.stop.reached(crate::timer::now()),
                "graphics capture bound world={:?} vector={} ip={:#x} calls={} replies={} transitions={}",
                self.world,
                frame.vector,
                frame.rip,
                self.counters.calls,
                self.counters.replies,
                self.transitions
            );
            let blocked = match frame.vector {
                32 => {
                    self.s.charge_cpu(0, 1).unwrap();
                    false
                }
                128 => self.syscall(index, &mut frame),
                _ => {
                    self.fault(index, &frame, address);
                    true
                }
            };
            self.actors[index].as_mut().unwrap().context = frame;
            self.counters.max_pending =
                self.counters.max_pending.max(self.rpc.outstanding() as u64);
            if !blocked {
                self.s.yield_cpu(0).unwrap();
            }
            if self.fault.is_some() {
                break;
            }
            if self.done.iter().all(|done| *done) {
                assert_eq!(self.world, World::Normal);
                assert!(self.pending.is_none() && self.rpc.outstanding() == 0);
                if hold.is_none() {
                    let app = self.actor(1).running.as_ref().unwrap().image().image();
                    let display = self.actor(0).running.as_ref().unwrap().image().image();
                    hw.verify_surface(app, self.a, self.extent);
                    hw.verify_surface(display, self.a, self.extent);
                    let info = self
                        .device
                        .mapped_information(self.a, self.meta[0].domain, self.display_cap)
                        .unwrap();
                    let surface_sha256 = hw.surface_digest(self.extent, app.surface().unwrap());
                    on_present(Present {
                        width: info.width,
                        height: info.height,
                        app_process: self.meta[1].process.diagnostic_id(),
                        display_process: self.meta[0].process.diagnostic_id(),
                        surface_sha256,
                    });
                    presented_digest = Some(surface_sha256);
                    hold = Some(Deadline::after(crate::timer::now(), 128).unwrap());
                }
                if hold.unwrap().reached(crate::timer::now()) {
                    break;
                }
            }
        }
        // SAFETY: actual controller root and IF0 restored by the last capture.
        unsafe { crate::timer::stop_runtime() };
        assert!(
            self.fault.is_some()
                || hold.is_some_and(|deadline| deadline.reached(crate::timer::now())),
            "graphics transition limit"
        );
        assert!(self.pending.is_none());
        assert_eq!(self.rpc.outstanding(), 0);
        assert_eq!(self.counters.denied, 3);
        assert!(self.bound && self.ready.iter().all(|ready| *ready));
        // CPU capture permits retained readback after revocation too. Every
        // world checks all RAM tail bytes, and the normal frame must remain
        // unchanged through the actual capture-retention interval.
        let app = self.actor(1).running.as_ref().unwrap().image().image();
        let final_digest = hw.surface_digest(self.extent, app.surface().unwrap());
        if let Some(presented) = presented_digest {
            assert_eq!(final_digest, presented);
        }
        let elapsed = crate::timer::now().checked_sub(started).unwrap();
        assert!(elapsed < LIMITS.limit(Resource::CpuTicks));
        (elapsed, self.transitions)
    }
}

/// # Safety
/// Exclusive retained bootstrap RAM/direct-map/GOP/PAT/source tables and the
/// initialized user IRQ/FX boundary. BSP IF0/APs parked; no competing device or
/// user execution. The callback may record/capture but cannot mutate resources.
#[inline(never)]
pub unsafe fn prove(
    offset: u64,
    frames: &mut BootstrapFrames,
    framebuffer: Framebuffer,
    mut on_present: impl FnMut(Present),
) -> Proof {
    // SAFETY: every world returns all CPU/RAM/IPC ownership before the next.
    let normal = unsafe { world(offset, frames, framebuffer, World::Normal, &mut on_present) };
    // SAFETY: previous graph fully retired; these independent worlds preserve
    // fault Records rather than synthesizing successful userspace outcomes.
    let app = unsafe {
        world(
            offset,
            frames,
            framebuffer,
            World::AppFault,
            &mut on_present,
        )
    };
    // SAFETY: same exclusive retained actual hardware owners after full cleanup.
    let display = unsafe {
        world(
            offset,
            frames,
            framebuffer,
            World::DisplayFault,
            &mut on_present,
        )
    };
    let worlds = [&normal, &app, &display];
    let proof = Proof {
        worlds: worlds.len() as u64,
        calls: worlds.iter().map(|w| w.counters.calls).sum(),
        blocks: worlds.iter().map(|w| w.counters.blocks).sum(),
        wakes: worlds.iter().map(|w| w.counters.wakes).sum(),
        replies: worlds.iter().map(|w| w.counters.replies).sum(),
        faults: worlds.iter().map(|w| w.counters.faults).sum(),
        authority_denied: worlds.iter().map(|w| w.counters.denied).sum(),
        mapped: worlds.iter().map(|w| w.counters.mapped).sum(),
        surface_pages: normal.pages,
        display_tables: worlds.iter().map(|w| w.counters.tables).sum(),
        peak_frames: worlds.iter().map(|w| w.peak).max().unwrap(),
        max_pending: worlds.iter().map(|w| w.counters.max_pending).max().unwrap(),
        app_fault: app.fault.unwrap(),
        display_fault: display.fault.unwrap(),
        frames: worlds.iter().all(|w| w.frames),
        metadata: worlds.iter().all(|w| w.metadata),
        guards: worlds.iter().all(|w| w.guards),
    };
    assert_eq!(
        (
            proof.calls,
            proof.blocks,
            proof.wakes,
            proof.replies,
            proof.faults
        ),
        (2, 2, 2, 1, 2)
    );
    assert_eq!(
        (
            proof.authority_denied,
            proof.mapped,
            proof.display_tables,
            proof.max_pending
        ),
        (9, 6, 6, 1)
    );
    assert!(proof.peak_frames <= 128 && proof.frames && proof.metadata && proof.guards);
    assert!(
        worlds
            .iter()
            .all(|world| world.pages == proof.surface_pages)
    );
    proof
}

#[inline(never)]
unsafe fn world(
    offset: u64,
    frames: &mut BootstrapFrames,
    framebuffer: Framebuffer,
    selected: World,
    on_present: &mut impl FnMut(Present),
) -> Outcome {
    // SAFETY: unique actual controller before constructing any user mappings.
    let mut hw = unsafe { Hardware::capture(offset) };
    let before = frames.remaining_frames();
    let mut a = Authority::new();
    let custody = a.create_space().unwrap();
    let common = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE;
    let jobs = core::array::from_fn::<_, 2, _>(|_| {
        a.create_root(custody, Kind::Job, common | Rights::READ | Rights::CONTROL)
            .unwrap()
    });
    let images = core::array::from_fn::<_, 2, _>(|_| {
        a.create_root(custody, Kind::Memory, Rights::READ).unwrap()
    });
    let mut s = Scheduler::new();
    let parent = s
        .create_job_with_limits(Limits::new(4096, 128, 2, 2))
        .unwrap();
    let actual_jobs =
        core::array::from_fn::<_, 2, _>(|_| s.create_child_job(parent, LIMITS).unwrap());
    let mut registry = Registry::with_service_limits(EPOCH, LIMITS).unwrap();
    for index in 0..2 {
        registry
            .register_job(&a, custody, jobs[index], actual_jobs[index])
            .unwrap();
    }
    let ram = UninitializedRam::allocate(frames, &mut s, parent, SURFACE_PAGES)
        .unwrap_or_else(|rejected| panic!("surface allocation: {:?}", rejected.error))
        .initialize(&mut hw)
        .unwrap_or_else(|rejected| panic!("surface initialization: {:?}", rejected.error));
    let (mut extent, surface_cap) = MemoryExtent::publish(&mut a, custody, ram, frames, &s)
        .unwrap_or_else(|rejected| panic!("surface publication: {:?}", rejected.error));
    // SAFETY: actual retained GOP descriptor/source/PAT/no-RAM classification.
    let aperture = unsafe { DisplayAperture::discover(offset, framebuffer, frames) }.unwrap();
    let geometry = aperture.plan().geometry();
    assert_eq!(geometry.width() as usize, framebuffer.width);
    assert_eq!(geometry.height() as usize, framebuffer.height);
    let (mut device, device_cap) = DisplayObject::new(&mut a, custody, aperture)
        .unwrap_or_else(|(error, _owner)| panic!("Display authority: {error:?}"));
    let (present_cap, mut present_box) = registry.create_channel(&mut a, custody, jobs[0]).unwrap();
    let (event_cap, mut event_box) = registry.create_channel(&mut a, custody, jobs[1]).unwrap();
    let display_roles = [
        role(1, Kind::Memory, 5),
        role(2, Kind::Endpoint, 272),
        role(3, Kind::Display, 7),
        role(4, Kind::Endpoint, 8),
    ];
    let app_roles = [
        role(1, Kind::Memory, 7),
        role(2, Kind::Endpoint, 8),
        role(3, Kind::Endpoint, 8),
    ];
    let (display_bytes, display_sha) = if selected == World::DisplayFault {
        (
            bundle::M4_DISPLAY_SERVER_DENIED_IMAGE,
            bundle::M4_DISPLAY_SERVER_DENIED_SHA,
        )
    } else {
        (
            bundle::M4_DISPLAY_SERVER_IMAGE,
            bundle::M4_DISPLAY_SERVER_SHA,
        )
    };
    let (app_bytes, app_sha) = if selected == World::AppFault {
        (
            bundle::M4_DISPLAY_APP_DENIED_IMAGE,
            bundle::M4_DISPLAY_APP_DENIED_SHA,
        )
    } else {
        (bundle::M4_DISPLAY_APP_IMAGE, bundle::M4_DISPLAY_APP_SHA)
    };
    for (index, bytes, sha, roles, layout) in [
        (
            0,
            display_bytes,
            display_sha,
            display_roles.as_slice(),
            LayoutReservation::DisplayApertureV1,
        ),
        (
            1,
            app_bytes,
            app_sha,
            app_roles.as_slice(),
            LayoutReservation::Legacy,
        ),
    ] {
        let image = ServiceImage::verify_layout(bytes, sha, LIMITS, roles, layout).unwrap();
        registry
            .register_image(&a, custody, images[index], image)
            .unwrap();
    }
    let controls = core::array::from_fn::<_, 2, _>(|index| {
        registry
            .create_process(&mut a, &mut s, custody, jobs[index], images[index])
            .unwrap()
    });
    for (index, grants) in [
        (
            0,
            &[
                (surface_cap, 1),
                (present_cap, 2),
                (device_cap, 3),
                (event_cap, 4),
            ][..],
        ),
        (1, &[(surface_cap, 1), (present_cap, 2), (event_cap, 3)][..]),
    ] {
        for &(source, selector) in grants {
            registry
                .delegate(&mut a, custody, controls[index], source, selector)
                .unwrap();
        }
    }
    let meta = controls.map(|cap| registry.metadata(&a, custody, cap).unwrap());
    let receive = registry.grant(&a, custody, controls[0], 2).unwrap();
    present_box
        .rebind_empty(&a, custody, present_cap, meta[0].domain, receive)
        .unwrap();
    let display_cap = registry.grant(&a, custody, controls[0], 3).unwrap();
    let mut display_slot = GraphicsImage::empty();
    let mut app_slot = GraphicsImage::empty();
    let mut mapped = 0;
    for (index, slot, writable) in [(0, &mut display_slot, false), (1, &mut app_slot, true)] {
        let plan = registry.plan(&a, custody, controls[index]).unwrap();
        let startup = registry
            .startup(&a, custody, controls[index], EPOCH)
            .unwrap();
        // SAFETY: real charged held target and unique inactive private slot.
        unsafe {
            slot.load_private(
                &plan,
                meta[index],
                &startup,
                hw.offset,
                hw.bits,
                hw.original,
                frames,
            )
        }
        .unwrap();
        let cap = registry.grant(&a, custody, controls[index], 1).unwrap();
        if !writable {
            assert!(matches!(
                extent.map(&a, meta[index].domain, cap, true),
                Err(ExtentError::Authority(CapError::Denied))
            ));
        }
        let lease = extent.map(&a, meta[index].domain, cap, writable).unwrap();
        let mut empty = GraphicsImage::empty();
        let lease = empty
            .retain_surface(lease)
            .expect_err("empty slot retains refused lease");
        slot.retain_surface(lease).unwrap();
        slot.root().activate();
        // SAFETY: deliberate active-root refusal while held; restore actual
        // controller root before inspecting result or changing any metadata.
        let rejected = unsafe { slot.install_surface(&a, &extent) };
        // SAFETY: original retained controller root; IF0/no concurrent CPU.
        unsafe { asm!("mov cr3, {}", in(reg) hw.original, options(nostack, preserves_flags)) };
        assert!(matches!(rejected, Err(ImageError::Root(_))));
        // SAFETY: held/inactive, same returned lease and exact live RAM owner.
        unsafe { slot.install_surface(&a, &extent) }.unwrap();
        mapped += 1;
        // SAFETY: same held/inactive owner. Occupied installation must refuse
        // before touching existing leaves or losing the retained lease.
        let duplicate = unsafe { slot.install_surface(&a, &extent) };
        assert!(matches!(duplicate, Err(ImageError::Phase)));
        if index == 0 {
            let lease = device.map(&a, meta[0].domain, display_cap).unwrap();
            slot.retain_display(OwnedDisplayTables::uninstalled(lease))
                .unwrap_or_else(|_| panic!("retain fresh Display owner"));
            // SAFETY: exact held V2 plan/lease/source, charged real PT claims.
            unsafe { slot.install_display(&device, &a, &plan, &s, frames, hw.offset) }.unwrap();
        }
        hw.verify_surface(slot, &a, &extent);
    }
    let peak = before.checked_sub(frames.remaining_frames()).unwrap();
    let pages = extent.pages() as u64;
    assert_eq!(pages, SURFACE_PAGES as u64);
    assert_eq!(s.usage(parent, Resource::Frames), Ok(peak));
    assert_eq!(
        peak,
        meta.iter().map(|m| m.frames).sum::<u64>() + SURFACE_PAGES as u64
    );
    assert!(peak <= 128);
    assert_eq!(extent.live_leases(), 2);
    let tables = display_slot.display().unwrap().table_frames() as u64;
    assert_eq!(tables, 2);
    let stop = Deadline::after(crate::timer::now(), 2048).unwrap();
    let display = admit(
        &mut display_slot,
        &mut registry,
        &a,
        &mut s,
        custody,
        controls[0],
        stop.tick() + 1024,
    );
    assert!(s.held_process_job(meta[1].process).is_ok());
    let mut rpc = Rpc::new(EPOCH);
    rpc.register_thread(&a, &s, meta[0].thread, meta[0].job, meta[0].domain, None)
        .unwrap();
    let present_object = identity(&a, custody, present_cap, Kind::Endpoint);
    let event_object = identity(&a, custody, event_cap, Kind::Endpoint);
    let (mut actors, counters, fault) = {
        let mut runtime = Runtime {
            a: &mut a,
            s: &mut s,
            registry: &mut registry,
            rpc: &mut rpc,
            actors: [Some(display), None],
            app_slot: Some(&mut app_slot),
            meta,
            controls,
            custody,
            present_box: &mut present_box,
            present_object,
            event_box: &mut event_box,
            event_cap,
            event_object,
            extent: &extent,
            device: &device,
            display_cap,
            world: selected,
            stop,
            pending: None,
            counters: Counters {
                mapped,
                tables,
                ..Counters::default()
            },
            ready: [false; 2],
            done: [false; 2],
            bound: false,
            fault: None,
            transitions: 0,
        };
        // SAFETY: exact actual graph and retained exclusive hardware resources.
        let (elapsed, transitions) = unsafe { runtime.run(&hw, on_present) };
        let cpu = actual_jobs.map(|job| runtime.s.usage(job, Resource::CpuTicks).unwrap());
        let parent_cpu = runtime.s.usage(parent, Resource::CpuTicks).unwrap();
        assert_eq!(cpu.iter().sum::<u64>(), parent_cpu);
        assert_eq!(elapsed, parent_cpu);
        assert!(
            cpu.iter().all(|cpu| *cpu <= 2048) && parent_cpu <= 4096 && transitions <= TRANSITIONS
        );
        (runtime.actors, runtime.counters, runtime.fault)
    };
    for actor in actors.iter_mut().flatten() {
        if !actor.dead {
            actor
                .running
                .as_mut()
                .unwrap()
                .stop(&mut a, &mut s)
                .unwrap();
            s.terminate_process(actor.meta.process).unwrap();
            assert!(
                rpc.peer_died(&s, actor.meta.thread, crate::timer::now())
                    .unwrap()
                    .is_empty()
            );
            actor.dead = true;
        }
    }
    assert!(actors.iter().all(Option::is_some));
    present_box.receiver_died(meta[0].domain).unwrap();
    event_box.receiver_died(custody).unwrap();
    assert_eq!(
        (
            present_box.pending(),
            event_box.pending(),
            rpc.outstanding()
        ),
        (0, 0, 0)
    );
    for actor in actors.iter_mut().flatten() {
        let image = actor
            .running
            .take()
            .unwrap()
            .finish(&s)
            .unwrap_or_else(|_| panic!("stopped graphics owner retained"))
            .into_image();
        assert!(matches!(
            extent.validate(&a, image.surface().unwrap()),
            Err(ExtentError::Authority(CapError::Revoked))
        ));
        let count = frames.remaining_frames();
        // SAFETY: actual stopped root; refusal must precede any physical free.
        let premature = unsafe { image.retire_private(&s, frames) };
        assert!(matches!(premature, Err(ImageError::LiveClaims)));
        assert_eq!(frames.remaining_frames(), count);
        // SAFETY: real stopped scheduler/CPU ownership after finish; cleanup
        // consumes retained claims without authorizing revoked public grants.
        let lease = unsafe { image.detach_surface(&s, &extent) }.unwrap();
        extent.unmap(lease).unwrap();
        let mut retired = 0;
        if image.display().is_some() {
            // SAFETY: same actual stopped root; all scanout CPU users returned.
            unsafe { image.detach_display(&s) }.unwrap();
            // SAFETY: detached PT claims, retained allocator/direct map.
            let tables = unsafe { image.retire_display_tables(frames) }.unwrap();
            retired += u64::from(tables.returned);
            device
                .unmap(tables.lease)
                .unwrap_or_else(|(error, _lease)| panic!("Display lease return: {error:?}"));
        }
        // SAFETY: both mapping receipts are gone; actual root is fully stopped.
        retired += unsafe { image.retire_private(&s, frames) }.unwrap();
        assert_eq!(retired, actor.meta.frames);
        s.release_frames(actor.meta.job, retired).unwrap();
        registry
            .retire_stopped(&mut a, &s, actor.meta.process)
            .unwrap();
        rpc.forget_thread(&s, actor.meta.thread).unwrap();
        a.close(custody, actor.control).unwrap();
        registry
            .forget_retired(&mut a, &s, actor.meta.process)
            .unwrap();
        s.reclaim_process(actor.meta.process).unwrap();
    }
    assert_eq!(extent.live_leases(), 0);
    assert_eq!(s.usage(parent, Resource::Frames), Ok(SURFACE_PAGES as u64));
    let ram = extent.destroy(&mut a, custody, surface_cap).unwrap();
    ram.release(frames, &mut s, &mut hw)
        .unwrap_or_else(|rejected| panic!("surface retirement: {:?}", rejected.error));
    a.close(custody, surface_cap).unwrap();
    a.destroy(custody, device_cap).unwrap();
    a.close(custody, device_cap).unwrap();
    for cap in [present_cap, event_cap] {
        a.close(custody, cap).unwrap();
    }
    for mailbox in [present_box, event_box] {
        let _receipt = mailbox
            .retire_managed(&mut a)
            .unwrap_or_else(|rejected| panic!("graphics channel retirement: {:?}", rejected.error));
    }
    for job in actual_jobs {
        registry.forget_job(&mut a, &mut s, &rpc, job).unwrap();
    }
    s.reclaim_job(parent).unwrap();
    a.collect_lineage().unwrap();
    a.collect_dead_objects().unwrap();
    // Only immutable source-image/external Job bindings remain. Mutable graph,
    // domains, private metadata, execution references and every RAM claim retired.
    assert_eq!(a.metadata_usage(), (1, 4, 4, 4));
    assert_eq!(registry.metadata_usage(), (0, 2, 0, 4));
    assert_eq!(rpc.metadata_usage(), (0, 0, 0));
    assert_eq!(s.metadata_usage(), (0, 0, 0));
    assert_eq!(frames.remaining_frames(), before);
    assert_eq!(extent.pages(), 0);
    Outcome {
        counters,
        fault,
        peak,
        pages,
        frames: true,
        metadata: true,
        guards: true,
    }
}
