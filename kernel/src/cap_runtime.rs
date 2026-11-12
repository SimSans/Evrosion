//! Actual CPL3 cap_echo client/server worlds using the ordinary trap boundary.
//! Independent bounded development worlds, not production boot/restart policy.
use crate::{
    executable_runtime::{LoadedImage, ProcessImage},
    supervisor_runtime::bundle,
};
use core::{arch::asm, num::NonZeroU64};
use ev_kernel::{
    cap_rpc::{EchoChannel, Error as TransportError, Failed, ReceiveError, Replied},
    capability::{Authority, Handle, Kind, Rights, SpaceId},
    fault::Record,
    mapping::ADDRESS_MASK,
    memory::BootstrapFrames,
    rpc::{CallId, Completion, Error as RpcError, Notifications, Rpc, Status},
    scheduler::{JobId, Limits, Resource, Scheduler, WaitTicket},
    service::{Metadata, Registry, Role, Running, ServiceImage},
    time::Deadline,
    user_context::{Call, FxState, UserContext, decode},
};
use ev_userspace_contract::syscall::{cap_phase, cap_reply_phase};

const ACTOR_LIMITS: Limits = Limits::new(512, 16, 1, 1);
const MEMORY: Rights = Rights::from_bits(Rights::READ.bits() | Rights::TRANSFER.bits()).unwrap();
const DENIED: u64 = 1;
const BUSY: u64 = 2;
const MALFORMED: u64 = 3;
const DEADLINE: u64 = 4;
const PEER_DIED: u64 = 5;
const CANCELLED: u64 = 6;
const EMPTY: u64 = 7;
const STALE: u64 = 8;
const CAPACITY: u64 = 9;
const INTEGRITY: u64 = 10;

#[derive(Default)]
pub struct Proof {
    pub worlds: u64,
    pub accepted: u64,
    pub delivered: u64,
    pub returned: u64,
    pub blocks: u64,
    pub wakes: u64,
    pub preflight_rejected: u64,
    pub busy: u64,
    pub queued_recovered: u64,
    pub queued_invalidated: u64,
    pub queued_pending: u64,
    pub delivered_no_refund: u64,
    pub timeouts: u64,
    pub server_faults: u64,
    pub late: u64,
    pub stale_serial: u64,
    pub wrong_object: u64,
    pub client_exits: u64,
    pub frames_balanced: bool,
    pub metadata_balanced: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum World {
    Normal,
    Timeout,
    DeliveredDeath,
    QueuedTimeout,
    QueuedDeath,
}
impl World {
    fn ordinal(self) -> u64 {
        match self {
            Self::Normal => 1,
            Self::Timeout => 2,
            Self::DeliveredDeath => 3,
            Self::QueuedTimeout => 4,
            Self::QueuedDeath => 5,
        }
    }
    fn images(self) -> (&'static [u8], [u8; 32], &'static [u8], [u8; 32]) {
        match self {
            Self::Normal => (
                bundle::CAP_CLIENT_NORMAL_IMAGE,
                bundle::CAP_CLIENT_NORMAL_SHA,
                bundle::CAP_SERVER_NORMAL_IMAGE,
                bundle::CAP_SERVER_NORMAL_SHA,
            ),
            Self::Timeout => (
                bundle::CAP_CLIENT_TIMEOUT_IMAGE,
                bundle::CAP_CLIENT_TIMEOUT_SHA,
                bundle::CAP_SERVER_DELAY_IMAGE,
                bundle::CAP_SERVER_DELAY_SHA,
            ),
            Self::DeliveredDeath => (
                bundle::CAP_CLIENT_DEATH_IMAGE,
                bundle::CAP_CLIENT_DEATH_SHA,
                bundle::CAP_SERVER_FAULT_IMAGE,
                bundle::CAP_SERVER_FAULT_SHA,
            ),
            Self::QueuedTimeout => (
                bundle::CAP_CLIENT_QUEUED_TIMEOUT_IMAGE,
                bundle::CAP_CLIENT_QUEUED_TIMEOUT_SHA,
                bundle::CAP_SERVER_HOLD_IMAGE,
                bundle::CAP_SERVER_HOLD_SHA,
            ),
            Self::QueuedDeath => (
                bundle::CAP_CLIENT_QUEUED_DEATH_IMAGE,
                bundle::CAP_CLIENT_QUEUED_DEATH_SHA,
                bundle::CAP_SERVER_QUEUED_FAULT_IMAGE,
                bundle::CAP_SERVER_QUEUED_FAULT_SHA,
            ),
        }
    }
}
struct Hardware<'a> {
    offset: u64,
    bits: u8,
    original: u64,
    frames: &'a mut BootstrapFrames,
}
struct Actor<'a> {
    running: Option<Running<ProcessImage<'a>>>,
    meta: Metadata,
    control: Handle,
    dead: bool,
}
#[derive(Clone, Copy)]
struct Pending {
    id: CallId,
    wait: WaitTicket,
    original: Handle,
    object: usize,
    delivered: Option<Handle>,
    waiting: bool,
}
// The world keeps each large metadata table in its original unique local.
// Borrow them through dispatch and cleanup rather than moving a second complete
// aggregate into Runtime on the bounded controller stack.
struct Runtime<'image, 'state> {
    a: &'state mut Authority,
    s: &'state mut Scheduler,
    registry: &'state mut Registry<'static>,
    rpc: &'state mut Rpc,
    actors: [Actor<'image>; 2],
    channel: Option<EchoChannel>,
    contexts: [UserContext; 2],
    fx: [FxState; 2],
    pending: Option<Pending>,
    previous: Option<Pending>,
    proof: Proof,
    world: World,
    global: Deadline,
    client_done: bool,
}
fn reason(error: TransportError) -> u64 {
    match error {
        TransportError::Busy
        | TransportError::Rpc(RpcError::WouldBlock | RpcError::AlreadyWaiting) => BUSY,
        TransportError::Wire(_) | TransportError::Rpc(RpcError::MalformedMessage) => MALFORMED,
        TransportError::Rpc(RpcError::DeadlineExceeded) => DEADLINE,
        TransportError::Rpc(RpcError::PeerDied) => PEER_DIED,
        TransportError::Rpc(RpcError::Cancelled) => CANCELLED,
        TransportError::WrongCall => STALE,
        TransportError::Authority(ev_kernel::capability::Error::Capacity) => CAPACITY,
        TransportError::Integrity => INTEGRITY,
        _ => DENIED,
    }
}
fn status_reason(status: Status) -> u64 {
    match status {
        Status::DeadlineExceeded => DEADLINE,
        Status::PeerDied => PEER_DIED,
        Status::Cancelled => CANCELLED,
        Status::Ok => INTEGRITY,
    }
}
fn cap_result(frame: &mut UserContext, phase: u64, value: u64, capability: u64, serial: u64) {
    frame.registers[14] = phase;
    frame.registers[9] = value;
    frame.registers[11] = capability;
    frame.registers[5] = serial;
}
impl Runtime<'_, '_> {
    fn failed(&mut self, event: Completion, now: u64) {
        let Some(mut pending) = self.pending.filter(|p| p.id == event.call && p.waiting) else {
            return;
        };
        assert_eq!(event.caller, self.actors[0].meta.thread);
        assert!(!event.deliver_reply);
        let result = self
            .channel
            .as_mut()
            .unwrap()
            .failure(
                self.a,
                self.s,
                self.rpc,
                event.caller,
                event.call.serial(),
                now,
            )
            .expect("protected cap cancellation");
        let frame = &mut self.contexts[0];
        match result {
            Failed::QueuedRecovered {
                call,
                status,
                capability,
            } => {
                assert_eq!(call, pending.id);
                assert_eq!(status, event.status);
                assert!(pending.delivered.is_none());
                assert_eq!(
                    self.a
                        .authorize(self.actors[0].meta.domain, capability, Kind::Memory, MEMORY)
                        .unwrap()
                        .identity(),
                    pending.object
                );
                assert!(
                    self.a
                        .authorize(
                            self.actors[0].meta.domain,
                            pending.original,
                            Kind::Memory,
                            MEMORY
                        )
                        .is_err()
                );
                cap_result(
                    frame,
                    cap_phase::QUEUED_RECOVERED,
                    status_reason(status),
                    capability.0,
                    0,
                );
                self.proof.queued_recovered += 1;
            }
            Failed::QueuedInvalidated { call, status } => {
                assert_eq!(call, pending.id);
                assert_eq!(status, event.status);
                assert!(pending.delivered.is_none());
                cap_result(
                    frame,
                    cap_phase::QUEUED_INVALIDATED,
                    status_reason(status),
                    0,
                    0,
                );
                self.proof.queued_invalidated += 1;
            }
            Failed::QueuedPending { call, status } => {
                assert_eq!(call, pending.id);
                assert_eq!(status, event.status);
                assert!(pending.delivered.is_none());
                cap_result(
                    frame,
                    cap_phase::QUEUED_PENDING,
                    status_reason(status),
                    0,
                    call.serial(),
                );
                self.proof.queued_pending += 1;
            }
            Failed::Delivered { call, status } => {
                assert_eq!(call, pending.id);
                assert_eq!(status, event.status);
                let received = pending.delivered.expect("actual capability delivery");
                assert_eq!(
                    self.a
                        .authorize(self.actors[1].meta.domain, received, Kind::Memory, MEMORY)
                        .unwrap()
                        .identity(),
                    pending.object
                );
                assert!(
                    self.a
                        .authorize(
                            self.actors[0].meta.domain,
                            pending.original,
                            Kind::Memory,
                            MEMORY
                        )
                        .is_err()
                );
                cap_result(
                    frame,
                    cap_phase::DELIVERED_FAILURE,
                    status_reason(status),
                    0,
                    0,
                );
                self.proof.delivered_no_refund += 1;
            }
        }
        if event.status == Status::DeadlineExceeded {
            assert!(self.s.waiting(pending.wait));
            self.proof.timeouts += 1;
        } else {
            assert!(self.s.wake(pending.wait));
        }
        self.proof.wakes += 1;
        pending.waiting = false;
        if self.channel.as_ref().unwrap().current().is_none() {
            self.previous = Some(pending);
            self.pending = None;
        } else {
            self.pending = Some(pending);
        }
    }
    fn notifications(&mut self, notifications: Notifications, now: u64) {
        for event in notifications.iter().copied() {
            self.failed(event, now);
        }
        self.s.advance(now).expect("actual monotonic cap scheduler");
    }
    fn expire(&mut self) {
        let now = crate::timer::now();
        let events = self.rpc.expire(now).expect("actual monotonic cap RPC");
        self.notifications(events, now);
    }
    fn call(
        &mut self,
        frame: &mut UserContext,
        endpoint: Handle,
        value: u64,
        absolute: u64,
        capability: Handle,
    ) -> bool {
        let now = crate::timer::now();
        if absolute > self.global.tick() {
            cap_result(frame, cap_phase::REJECTED, MALFORMED, capability.0, 0);
            self.proof.preflight_rejected += 1;
            return false;
        }
        let deadline = Deadline::after(0, absolute).unwrap();
        if let Err(error) = self.s.check_block(0, deadline) {
            let reason = if error == ev_kernel::scheduler::Error::Expired {
                DEADLINE
            } else {
                DENIED
            };
            cap_result(frame, cap_phase::REJECTED, reason, capability.0, 0);
            self.proof.preflight_rejected += 1;
            return false;
        }
        let domain = self.actors[0].meta.domain;
        let object = self
            .a
            .authorize(domain, capability, Kind::Memory, MEMORY)
            .ok()
            .map(|a| a.identity());
        match self.channel.as_mut().unwrap().begin(
            self.a,
            self.rpc,
            self.actors[0].meta.thread,
            endpoint,
            value.to_le_bytes(),
            capability,
            deadline,
            now,
        ) {
            Err(rejected) => {
                assert_eq!(rejected.retained, capability);
                let why = reason(rejected.error);
                if why == BUSY {
                    self.proof.busy += 1;
                } else {
                    self.proof.preflight_rejected += 1;
                }
                cap_result(frame, cap_phase::REJECTED, why, capability.0, 0);
                false
            }
            Ok(accepted) => {
                assert!(self.pending.is_none());
                let object = object.expect("actual accepted attachment authorization");
                assert!(
                    self.a
                        .authorize(domain, capability, Kind::Memory, MEMORY)
                        .is_err()
                );
                let wait = self
                    .s
                    .block(0, deadline)
                    .expect("preflighted real cap wait");
                self.pending = Some(Pending {
                    id: accepted.call,
                    wait,
                    original: capability,
                    object,
                    delivered: None,
                    waiting: true,
                });
                self.proof.accepted += 1;
                self.proof.blocks += 1;
                // This frame is saved but cannot resume until a real tagged
                // failure/reply installs its actual result and wakes its ticket.
                cap_result(frame, 0, 0, 0, 0);
                true
            }
        }
    }
    fn receive(&mut self, frame: &mut UserContext, endpoint: Handle) {
        match self.channel.as_mut().unwrap().receive(
            self.a,
            self.rpc,
            self.actors[1].meta.thread,
            endpoint,
            crate::timer::now(),
        ) {
            Ok(received) => {
                let pending = self.pending.as_mut().expect("accepted cap request");
                assert_eq!(received.call, pending.id);
                assert!(pending.waiting && pending.delivered.is_none());
                assert_eq!(
                    self.a
                        .authorize(
                            self.actors[1].meta.domain,
                            received.capability,
                            Kind::Memory,
                            MEMORY
                        )
                        .unwrap()
                        .identity(),
                    pending.object
                );
                pending.delivered = Some(received.capability);
                self.proof.delivered += 1;
                cap_result(
                    frame,
                    0,
                    u64::from_le_bytes(received.bytes),
                    received.capability.0,
                    received.call.serial(),
                );
            }
            Err(ReceiveError::Rejected(error)) => {
                let why = if error == TransportError::WrongCall {
                    EMPTY
                } else {
                    reason(error)
                };
                cap_result(frame, 1, why, 0, 0);
            }
            Err(ReceiveError::Integrity(_)) => panic!("cap transport private queue corruption"),
        }
    }
    fn reply(
        &mut self,
        frame: &mut UserContext,
        endpoint: Handle,
        value: u64,
        capability: Handle,
        serial: u64,
    ) {
        let before = self.a.metadata_usage();
        match self.channel.as_mut().unwrap().reply(
            self.a,
            self.rpc,
            self.actors[1].meta.thread,
            endpoint,
            serial,
            value.to_le_bytes(),
            capability,
            crate::timer::now(),
        ) {
            Err(rejected) => {
                assert_eq!(self.a.metadata_usage(), before);
                assert_eq!(rejected.retained, capability);
                if rejected.error == TransportError::WrongCall {
                    self.proof.stale_serial += 1;
                }
                if rejected.error == TransportError::WrongObject {
                    self.proof.wrong_object += 1;
                }
                if let Some(old) = self.previous {
                    assert!(!self.s.wake(old.wait));
                    if let Some(current) = self.pending {
                        assert!(self.s.waiting(current.wait));
                    }
                }
                cap_result(
                    frame,
                    cap_reply_phase::REJECTED,
                    reason(rejected.error),
                    capability.0,
                    0,
                );
            }
            Ok(Replied::Returned {
                completion,
                bytes,
                capability: returned,
            }) => {
                let pending = self.pending.take().expect("actual matching call wait");
                assert_eq!(completion.call, pending.id);
                assert_eq!(completion.caller, self.actors[0].meta.thread);
                assert!(completion.wake_caller && completion.deliver_reply && pending.waiting);
                assert_eq!(
                    self.a
                        .authorize(self.actors[0].meta.domain, returned, Kind::Memory, MEMORY)
                        .unwrap()
                        .identity(),
                    pending.object
                );
                assert!(
                    self.a
                        .authorize(self.actors[1].meta.domain, capability, Kind::Memory, MEMORY)
                        .is_err()
                );
                cap_result(
                    &mut self.contexts[0],
                    cap_phase::RETURNED,
                    u64::from_le_bytes(bytes),
                    returned.0,
                    0,
                );
                assert!(self.s.wake(pending.wait));
                self.proof.returned += 1;
                self.proof.wakes += 1;
                self.previous = Some(pending);
                cap_result(frame, cap_reply_phase::ACCEPTED, 0, 0, 0);
            }
            Ok(Replied::Late {
                completion,
                retained,
            }) => {
                let pending = self
                    .pending
                    .take()
                    .expect("actual retained late reservation");
                assert_eq!(completion.call, pending.id);
                assert!(!completion.wake_caller && !completion.deliver_reply && !pending.waiting);
                assert_eq!(retained, capability);
                assert_eq!(self.a.metadata_usage(), before);
                assert!(!self.s.wake(pending.wait));
                assert_eq!(
                    self.a
                        .authorize(self.actors[1].meta.domain, retained, Kind::Memory, MEMORY)
                        .unwrap()
                        .identity(),
                    pending.object
                );
                self.previous = Some(pending);
                self.proof.late += 1;
                cap_result(
                    frame,
                    cap_reply_phase::LATE_RETAINED,
                    status_reason(completion.status),
                    retained.0,
                    0,
                );
            }
        }
    }
    fn reclaim(&mut self, frame: &mut UserContext, serial: u64) {
        let Some(pending) = self
            .pending
            .filter(|p| !p.waiting && p.id.serial() == serial && p.delivered.is_none())
        else {
            cap_result(frame, cap_phase::REJECTED, STALE, 0, 0);
            return;
        };
        match self.channel.as_mut().unwrap().failure(
            self.a,
            self.s,
            self.rpc,
            self.actors[0].meta.thread,
            serial,
            crate::timer::now(),
        ) {
            Ok(Failed::QueuedRecovered { capability, .. }) => {
                assert_eq!(
                    self.a
                        .authorize(self.actors[0].meta.domain, capability, Kind::Memory, MEMORY)
                        .unwrap()
                        .identity(),
                    pending.object
                );
                self.pending = None;
                self.proof.queued_recovered += 1;
                cap_result(frame, cap_phase::QUEUED_RECOVERED, 0, capability.0, 0);
            }
            Ok(Failed::QueuedInvalidated { status, .. }) => {
                self.pending = None;
                cap_result(
                    frame,
                    cap_phase::QUEUED_INVALIDATED,
                    status_reason(status),
                    0,
                    0,
                );
            }
            Ok(Failed::QueuedPending { status, call }) => {
                cap_result(
                    frame,
                    cap_phase::QUEUED_PENDING,
                    status_reason(status),
                    0,
                    call.serial(),
                );
            }
            Ok(Failed::Delivered { .. }) => cap_result(frame, cap_phase::REJECTED, STALE, 0, 0),
            Err(error) => cap_result(frame, cap_phase::REJECTED, reason(error), 0, 0),
        }
    }
    fn syscall(&mut self, index: usize, frame: &mut UserContext) -> bool {
        let domain = self.actors[index].meta.domain;
        match decode(frame) {
            Ok(Call::Yield) => frame.registers[14] = 0,
            Ok(Call::Monotonic) => {
                frame.registers[14] = 0;
                frame.registers[9] = crate::timer::now();
            }
            Ok(Call::RpcDeadline) => {
                match self
                    .rpc
                    .serving(self.actors[index].meta.thread)
                    .and_then(|id| self.rpc.context(id).ok())
                {
                    Some(context) => {
                        frame.registers[14] = 0;
                        frame.registers[9] = context.deadline.tick();
                    }
                    None => {
                        frame.registers[14] = 1;
                        frame.registers[9] = 0;
                    }
                }
            }
            Ok(Call::Inspect { capability, rights }) => {
                frame.registers[14] = u64::from(
                    self.a
                        .authorize(domain, capability, Kind::Memory, rights)
                        .is_err(),
                );
            }
            Ok(Call::Close(capability)) => {
                frame.registers[14] = u64::from(self.a.close(domain, capability).is_err());
            }
            Ok(Call::RpcCap {
                endpoint,
                value,
                deadline,
                capability,
            }) if index == 0 => {
                return self.call(frame, endpoint, value, deadline, capability);
            }
            Ok(Call::ReceiveCap(endpoint)) if index == 1 => self.receive(frame, endpoint),
            Ok(Call::ReplyCap {
                endpoint,
                value,
                capability,
                serial,
            }) if index == 1 => self.reply(frame, endpoint, value, capability, serial),
            Ok(Call::ReclaimCap(serial)) if index == 0 => self.reclaim(frame, serial),
            Ok(Call::Exit(code)) => {
                assert_eq!(
                    (index, code),
                    (0, 0),
                    "cap actor unexpected exit world={:?}",
                    self.world
                );
                assert!(
                    self.pending.is_none() && self.channel.as_ref().unwrap().current().is_none()
                );
                assert_eq!(self.rpc.outstanding(), 0);
                self.actors[index]
                    .running
                    .as_mut()
                    .unwrap()
                    .stop(self.a, self.s)
                    .unwrap();
                assert_eq!(self.s.exit(0), Ok(self.actors[index].meta.thread));
                self.s
                    .terminate_process(self.actors[index].meta.process)
                    .unwrap();
                let notifications = self
                    .rpc
                    .peer_died(self.s, self.actors[index].meta.thread, crate::timer::now())
                    .unwrap();
                assert!(notifications.is_empty());
                self.actors[index].dead = true;
                self.proof.client_exits += 1;
                self.client_done = true;
                return true;
            }
            _ => frame.registers[14] = 3,
        }
        false
    }
    fn fault(&mut self, index: usize, frame: &UserContext, address: u64) {
        assert_eq!(index, 1, "CPL3 cap client fault in {:?}", self.world);
        assert!(matches!(
            self.world,
            World::DeliveredDeath | World::QueuedDeath
        ));
        assert_eq!((frame.vector, frame.error, address), (14, 6, 0));
        let pending = self.pending.expect("server death after accepted request");
        assert_eq!(
            pending.delivered.is_some(),
            self.world == World::DeliveredDeath
        );
        let actor = &mut self.actors[index];
        let record = Record {
            process: actor.meta.process.diagnostic_id(),
            thread: actor.meta.thread.diagnostic_id(),
            vector: frame.vector,
            error: frame.error,
            address,
            instruction: frame.rip,
        };
        assert_eq!(Record::decode(&record.encode()), Some(record));
        actor
            .running
            .as_mut()
            .unwrap()
            .stop(self.a, self.s)
            .unwrap();
        assert_eq!(self.s.exit(0), Ok(actor.meta.thread));
        self.s.terminate_process(actor.meta.process).unwrap();
        let notifications = self
            .rpc
            .peer_died(self.s, actor.meta.thread, crate::timer::now())
            .unwrap();
        actor.dead = true;
        self.proof.server_faults += 1;
        self.notifications(notifications, crate::timer::now());
    }
    unsafe fn run(&mut self, hw: &mut Hardware<'_>) {
        // SAFETY: exclusive BSP PIC owner at IF=0, ordinary user trap boundary.
        unsafe {
            crate::timer::start_runtime();
        }
        for _ in 0..65536 {
            assert!(
                !self.global.reached(crate::timer::now()),
                "cap world deadline {:?}",
                self.world
            );
            self.expire();
            let dispatch = self
                .s
                .dispatch(0)
                .unwrap()
                .expect("cap world has no runnable actor");
            let index = self
                .actors
                .iter()
                .position(|a| a.meta.process == dispatch.process)
                .expect("foreign cap actor");
            assert_eq!(dispatch.thread, self.actors[index].meta.thread);
            assert!(!self.actors[index].dead);
            self.actors[index]
                .running
                .as_ref()
                .unwrap()
                .image()
                .loaded
                .root
                .activate();
            // SAFETY: actual admitted actor root/context/FX; common trap capture
            // restores retained controller CR3 at IF=0 before this owner resumes.
            let (mut frame, address) = unsafe {
                crate::user_runtime::resume_context(
                    &self.contexts[index],
                    &mut self.fx[index],
                    hw.original,
                )
            };
            self.expire();
            let blocked = match frame.vector {
                32 => {
                    self.s
                        .charge_cpu(0, 1)
                        .expect("cap actor finite CPU budget");
                    false
                }
                128 => self.syscall(index, &mut frame),
                _ if frame.ordinary_user_fault() => {
                    self.fault(index, &frame, address);
                    true
                }
                _ => panic!("cap unexpected kernel trap vector={}", frame.vector),
            };
            self.contexts[index] = frame;
            if self.client_done {
                break;
            }
            if !blocked {
                self.s.yield_cpu(0).unwrap();
            }
        }
        // SAFETY: common capture restored controller CR3/IF0; no user entry active.
        unsafe {
            crate::timer::stop_runtime();
        }
        assert!(self.client_done, "cap world exhausted finite trap count");
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn load_actor<'a>(
    registry: &mut Registry<'static>,
    a: &Authority,
    s: &mut Scheduler,
    custody: SpaceId,
    control: Handle,
    epoch: NonZeroU64,
    slot: &'a mut LoadedImage,
    hw: &mut Hardware<'_>,
) -> Actor<'a> {
    let meta = registry.metadata(a, custody, control).unwrap();
    let startup = registry.startup(a, custody, control, epoch).unwrap();
    let plan = registry.plan(a, custody, control).unwrap();
    // SAFETY: exact held measured process, immutable startup and inactive unique slot.
    *slot = unsafe {
        LoadedImage::load_startup(
            hw.offset,
            hw.bits,
            hw.original & ADDRESS_MASK,
            &plan,
            Some(&startup),
            hw.frames,
        )
    }
    .unwrap();
    let running = registry
        .start(
            a,
            s,
            custody,
            control,
            epoch,
            ProcessImage {
                loaded: slot,
                process: meta.process,
                frames: meta.frames,
            },
        )
        .unwrap_or_else(|r| panic!("cap actor admission: {:?}", r.error));
    Actor {
        running: Some(running),
        meta,
        control,
        dead: false,
    }
}

/// # Safety
/// Serialized BSP at IF=0, AP parked, initialized ordinary user trap/FX/PIC
/// boundary, retained direct map/controller root and exclusively owned frames.
pub unsafe fn prove(offset: u64, frames: &mut BootstrapFrames) -> Proof {
    let mut proof = Proof {
        frames_balanced: true,
        metadata_balanced: true,
        ..Proof::default()
    };
    for world in [
        World::Normal,
        World::Timeout,
        World::DeliveredDeath,
        World::QueuedTimeout,
        World::QueuedDeath,
    ] {
        // SAFETY: every independent world stops all actors and returns all actual
        // backing before the next fresh development selection is constructed.
        let one = unsafe { run_world(offset, frames, world) };
        proof.worlds += one.worlds;
        proof.accepted += one.accepted;
        proof.delivered += one.delivered;
        proof.returned += one.returned;
        proof.blocks += one.blocks;
        proof.wakes += one.wakes;
        proof.preflight_rejected += one.preflight_rejected;
        proof.busy += one.busy;
        proof.queued_recovered += one.queued_recovered;
        proof.queued_invalidated += one.queued_invalidated;
        proof.queued_pending += one.queued_pending;
        proof.delivered_no_refund += one.delivered_no_refund;
        proof.timeouts += one.timeouts;
        proof.server_faults += one.server_faults;
        proof.late += one.late;
        proof.stale_serial += one.stale_serial;
        proof.wrong_object += one.wrong_object;
        proof.client_exits += one.client_exits;
        proof.frames_balanced &= one.frames_balanced;
        proof.metadata_balanced &= one.metadata_balanced;
    }
    proof
}
unsafe fn run_world(offset: u64, frames: &mut BootstrapFrames, world: World) -> Proof {
    let before = frames.remaining_frames();
    let original: u64;
    // SAFETY: privileged controller-root read; no user context is active.
    unsafe {
        asm!("mov {}, cr3",out(reg)original,options(nomem,nostack,preserves_flags));
    }
    let bits = (core::arch::x86_64::__cpuid(0x80000008).eax & 255) as u8;
    let mut hw = Hardware {
        offset,
        bits,
        original,
        frames,
    };
    let epoch = NonZeroU64::new(220 + world.ordinal()).unwrap();
    let mut a = Authority::new();
    let custody = a.create_space().unwrap();
    let common = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE;
    let images = [
        a.create_root(custody, Kind::Memory, Rights::READ).unwrap(),
        a.create_root(custody, Kind::Memory, Rights::READ).unwrap(),
    ];
    let creator = a
        .create_root(custody, Kind::Job, common | Rights::READ | Rights::CONTROL)
        .unwrap();
    let sources = [
        a.create_root(custody, Kind::Memory, common | Rights::READ)
            .unwrap(),
        a.create_root(custody, Kind::Memory, common | Rights::READ)
            .unwrap(),
    ];
    let mut s = Scheduler::new();
    let boot_job = s
        .create_job_with_limits(Limits::new(2048, 64, 4, 4))
        .unwrap();
    let mut registry =
        Registry::with_service_limits(NonZeroU64::new(world.ordinal()).unwrap(), ACTOR_LIMITS)
            .unwrap();
    registry
        .register_job(&a, custody, creator, boot_job)
        .unwrap();
    let (client_image, client_sha, server_image, server_sha) = world.images();
    registry
        .register_image(
            &a,
            custody,
            images[0],
            ServiceImage::verify(
                client_image,
                client_sha,
                ACTOR_LIMITS,
                &[
                    Role {
                        selector: 1,
                        kind: Kind::Memory,
                        rights: MEMORY,
                    },
                    Role {
                        selector: 2,
                        kind: Kind::Memory,
                        rights: MEMORY,
                    },
                    Role {
                        selector: 3,
                        kind: Kind::Endpoint,
                        rights: Rights::SEND,
                    },
                    Role {
                        selector: 4,
                        kind: Kind::Endpoint,
                        rights: Rights::RECEIVE | Rights::CONTROL,
                    },
                ],
            )
            .unwrap(),
        )
        .unwrap();
    registry
        .register_image(
            &a,
            custody,
            images[1],
            ServiceImage::verify(
                server_image,
                server_sha,
                ACTOR_LIMITS,
                &[
                    Role {
                        selector: 3,
                        kind: Kind::Endpoint,
                        rights: Rights::RECEIVE | Rights::CONTROL,
                    },
                    Role {
                        selector: 4,
                        kind: Kind::Endpoint,
                        rights: Rights::SEND,
                    },
                ],
            )
            .unwrap(),
        )
        .unwrap();
    let jobs = [
        registry
            .create_job(&mut a, &mut s, custody, creator, 0)
            .unwrap(),
        registry
            .create_job(&mut a, &mut s, custody, creator, 0)
            .unwrap(),
    ];
    let job_ids: [JobId; 2] = jobs.map(|cap| registry.job_id(&a, custody, cap).unwrap());
    let controls = [
        registry
            .create_process(&mut a, &mut s, custody, jobs[0], images[0])
            .unwrap(),
        registry
            .create_process(&mut a, &mut s, custody, jobs[1], images[1])
            .unwrap(),
    ];
    let (request, mut request_mailbox) = registry.create_channel(&mut a, custody, creator).unwrap();
    let (response, mut response_mailbox) =
        registry.create_channel(&mut a, custody, creator).unwrap();
    for (source, selector) in [
        (sources[0], 1),
        (sources[1], 2),
        (request, 3),
        (response, 4),
    ] {
        registry
            .delegate(&mut a, custody, controls[0], source, selector)
            .unwrap();
    }
    for (source, selector) in [(request, 3), (response, 4)] {
        registry
            .delegate(&mut a, custody, controls[1], source, selector)
            .unwrap();
    }
    let metadata = controls.map(|cap| registry.metadata(&a, custody, cap).unwrap());
    let request_control = registry.grant(&a, custody, controls[1], 3).unwrap();
    let response_control = registry.grant(&a, custody, controls[0], 4).unwrap();
    request_mailbox
        .rebind_empty(&a, custody, request, metadata[1].domain, request_control)
        .unwrap();
    response_mailbox
        .rebind_empty(&a, custody, response, metadata[0].domain, response_control)
        .unwrap();
    let mut storage = [LoadedImage::empty(), LoadedImage::empty()];
    let [client_slot, server_slot] = storage.each_mut();
    // SAFETY: each slot is exclusively owned; each actor is still held and has
    // exact measured image/startup and separately charged finite resources.
    let actors = unsafe {
        [
            load_actor(
                &mut registry,
                &a,
                &mut s,
                custody,
                controls[0],
                epoch,
                client_slot,
                &mut hw,
            ),
            load_actor(
                &mut registry,
                &a,
                &mut s,
                custody,
                controls[1],
                epoch,
                server_slot,
                &mut hw,
            ),
        ]
    };
    let contexts = actors
        .each_ref()
        .map(|actor| actor.running.as_ref().unwrap().initial_context().unwrap());
    let mut rpc = Rpc::new(epoch);
    for actor in &actors {
        rpc.register_thread(
            &a,
            &s,
            actor.meta.thread,
            actor.meta.job,
            actor.meta.domain,
            None,
        )
        .unwrap();
    }
    let channel = EchoChannel::bind(
        &a,
        &mut rpc,
        actors[0].meta.thread,
        actors[1].meta.thread,
        request_control,
        response_control,
        request_mailbox,
        response_mailbox,
    )
    .unwrap_or_else(|r| panic!("actual cap channel binding: {:?}", r.error));
    let mut runtime = Runtime {
        a: &mut a,
        s: &mut s,
        registry: &mut registry,
        rpc: &mut rpc,
        actors,
        channel: Some(channel),
        contexts,
        fx: [FxState::CLEAN; 2],
        pending: None,
        previous: None,
        proof: Proof::default(),
        world,
        global: Deadline::after(crate::timer::now(), 512).unwrap(),
        client_done: false,
    };
    // SAFETY: all actor roots/context/FX owners and retained tables belong to this
    // exclusive BSP controller; the common capture returns before any mutation.
    unsafe {
        runtime.run(&mut hw);
    }
    assert_eq!(runtime.proof.client_exits, 1);
    assert!(runtime.pending.is_none());
    assert_eq!(runtime.rpc.outstanding(), 0);
    for actor in &mut runtime.actors {
        actor
            .running
            .as_mut()
            .unwrap()
            .stop(runtime.a, runtime.s)
            .unwrap();
        runtime.s.terminate_process(actor.meta.process).unwrap();
        if !actor.dead {
            assert!(
                runtime
                    .rpc
                    .peer_died(runtime.s, actor.meta.thread, crate::timer::now())
                    .unwrap()
                    .is_empty()
            );
            actor.dead = true;
        }
    }
    let (mut request_mailbox, mut response_mailbox) = runtime
        .channel
        .take()
        .unwrap()
        .into_mailboxes()
        .unwrap_or_else(|_| panic!("cap execution still retained at teardown"));
    request_mailbox.receiver_died(metadata[1].domain).unwrap();
    response_mailbox.receiver_died(metadata[0].domain).unwrap();
    assert_eq!(
        (request_mailbox.pending(), response_mailbox.pending()),
        (0, 0)
    );
    for actor in &mut runtime.actors {
        let ProcessImage { loaded, .. } = actor
            .running
            .take()
            .unwrap()
            .finish(runtime.s)
            .unwrap_or_else(|_| panic!("stopped cap actor retained executable lease"));
        // SAFETY: actual actor stopped, controller CR3 restored, AP parked,
        // queues/RPC drained and its sole executable lease returned above.
        unsafe {
            assert_eq!(
                loaded.root.retire_in_place(hw.frames) as u64,
                actor.meta.frames
            );
        }
        runtime
            .s
            .release_frames(actor.meta.job, actor.meta.frames)
            .unwrap();
        runtime
            .registry
            .retire_stopped(runtime.a, runtime.s, actor.meta.process)
            .unwrap();
        runtime.a.close(custody, actor.control).unwrap();
    }
    for actor in &runtime.actors {
        runtime
            .registry
            .forget_retired(runtime.a, runtime.s, actor.meta.process)
            .unwrap();
        runtime
            .rpc
            .forget_thread(runtime.s, actor.meta.thread)
            .unwrap();
        runtime.s.reclaim_process(actor.meta.process).unwrap();
    }
    runtime.a.close(custody, request).unwrap();
    runtime.a.close(custody, response).unwrap();
    let _retired_mailboxes = [
        request_mailbox
            .retire_managed(runtime.a)
            .unwrap_or_else(|r| panic!("{:?}", r.error)),
        response_mailbox
            .retire_managed(runtime.a)
            .unwrap_or_else(|r| panic!("{:?}", r.error)),
    ];
    for (cap, actual) in jobs.into_iter().zip(job_ids) {
        runtime.a.close(custody, cap).unwrap();
        runtime
            .registry
            .forget_job(runtime.a, runtime.s, runtime.rpc, actual)
            .unwrap();
    }
    runtime.a.collect_lineage().unwrap();
    assert_eq!(runtime.a.metadata_usage(), (1, 5, 5, 5));
    assert_eq!(runtime.registry.metadata_usage(), (1, 2, 0, 4));
    assert_eq!(runtime.rpc.metadata_usage(), (0, 0, 0));
    assert_eq!(runtime.s.metadata_usage(), (1, 0, 0));
    for resource in [Resource::Frames, Resource::Processes, Resource::Threads] {
        assert_eq!(runtime.s.usage(boot_job, resource), Ok(0));
    }
    assert_eq!(hw.frames.remaining_frames(), before);
    runtime.proof.worlds = 1;
    runtime.proof.frames_balanced = true;
    runtime.proof.metadata_balanced = true;
    runtime.proof
}
