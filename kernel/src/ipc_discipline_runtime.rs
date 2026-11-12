//! Actual cap-free protected IPC chain/depth and logical NO_IPC_WAIT mutex.
//! Bounded, independently selected development worlds; no production boot claim.
use crate::{
    executable_runtime::{LoadedImage, ProcessImage},
    supervisor_runtime::bundle,
};
use core::{arch::asm, num::NonZeroU64};
use ev_kernel::{
    capability::{Authority, Handle, Kind, Rights, SpaceId},
    executable::Image,
    ipc::{Error as IpcError, Mailbox, Outgoing, Ticket},
    mapping::ADDRESS_MASK,
    memory::{BootstrapFrames, FRAME_SIZE},
    mutex::{Lease, Registry as Mutexes},
    rpc::{CallId, Error as RpcError, LockClass, MessageShape, Policy, Rpc},
    scheduler::{JobId, Limits, Resource, Scheduler, ThreadId, WaitTicket},
    service::{Metadata, Registry, Role, Running, ServiceImage},
    time::Deadline,
    user::UserPermission,
    user_context::{Call, FxState, UserContext, decode},
};
use ev_userspace_contract::echo;

const BASE: u64 = 1 << 39;
const ROLE_PAGES: [u64; 2] = [BASE + 0x100000, BASE + 0x102000];
const ROLE_TOPS: [u64; 2] = [BASE + 0x101000, BASE + 0x103000];
const GUARDS: [u64; 3] = [BASE + 0xff000, BASE + 0x101000, BASE + 0x103000];
const THREADS: usize = 9;
const ROUTES: usize = 8;
const RECEIVE: Rights = Rights::from_bits(Rights::RECEIVE.bits() | Rights::CONTROL.bits()).unwrap();

#[derive(Default)]
pub struct Proof {
    pub worlds: u64,
    pub accepted: u64,
    pub blocks: u64,
    pub wakes: u64,
    pub delivered: u64,
    pub replies: u64,
    pub contexts_verified: u64,
    pub spawned: u64,
    pub dangerous_lock: u64,
    pub cycle: u64,
    pub deadline_extended: u64,
    pub depth_exceeded: u64,
    pub wrong_thread: u64,
    pub mutex_acquired: u64,
    pub mutex_released: u64,
    pub exits: u64,
    pub max_depth: u8,
    pub stack_policy: bool,
    pub frames_balanced: bool,
    pub metadata_balanced: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum World {
    Chain,
    Depth,
}
impl World {
    fn limits(self) -> Limits {
        Limits::new(512, 16, 1, if self == Self::Depth { 3 } else { 1 })
    }
    fn image(self) -> (&'static [u8], [u8; 32]) {
        match self {
            Self::Chain => (bundle::IPC_CHAIN_IMAGE, bundle::IPC_CHAIN_SHA),
            Self::Depth => (bundle::IPC_DEPTH_IMAGE, bundle::IPC_DEPTH_SHA),
        }
    }
    fn count(self) -> usize {
        if self == Self::Depth { 8 } else { 3 }
    }
    fn inbound(self, rank: usize) -> usize {
        if self == Self::Depth && rank == 0 {
            3
        } else {
            rank
        }
    }
    fn outbound(self, rank: usize) -> usize {
        if self == Self::Chain {
            (rank + 1) % 3
        } else if rank == 8 {
            1
        } else {
            rank + 1
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
    template: UserContext,
    stacks_verified: bool,
}
struct Thread {
    id: ThreadId,
    process: usize,
    role: usize,
    context: UserContext,
    fx: FxState,
}
struct Route {
    rank: usize,
    object: usize,
    control: Handle,
    receive: Handle,
    mailbox: Mailbox,
    bound: bool,
}
#[derive(Clone, Copy)]
struct Pending {
    id: CallId,
    caller: ThreadId,
    callee: ThreadId,
    caller_rank: usize,
    wait: WaitTicket,
    ticket: Ticket,
    route: usize,
    delivered: bool,
}
// One retained mutable owner for each large table stays in run_world. The
// execution controller borrows those exact owners; constructing it cannot keep
// second by-value Authority/Registry/Scheduler/Rpc temporaries on the stack.
struct Runtime<'a, 'tables> {
    a: &'tables mut Authority,
    s: &'tables mut Scheduler,
    registry: &'tables mut Registry<'static>,
    rpc: &'tables mut Rpc,
    mutexes: &'tables mut Mutexes,
    actors: [Actor<'a>; 3],
    threads: [Option<Thread>; THREADS],
    routes: [Option<Route>; ROUTES],
    pending: [Option<Pending>; ev_kernel::rpc::MAX_CALLS],
    proof: Proof,
    world: World,
    global: Deadline,
    done: bool,
}
fn scalar(frame: &mut UserContext, status: u64, value: u64, capability: u64) {
    frame.registers[14] = status;
    frame.registers[9] = value;
    frame.registers[11] = capability;
    // Legacy scalar calls, including CALL22, preserve saved R10 exactly.
}
fn nonce_result(frame: &mut UserContext, status: u64, value: u64, nonce: u64) {
    scalar(frame, status, value, 0);
    frame.registers[5] = nonce;
}
fn error_status(error: RpcError) -> u64 {
    match error {
        RpcError::DangerousLock => 7,
        RpcError::DeadlockDetected => 8,
        RpcError::DepthExceeded => 9,
        RpcError::DeadlineExtended => 10,
        RpcError::WouldBlock | RpcError::AlreadyWaiting | RpcError::Overloaded => 2,
        RpcError::DeadlineExceeded => 4,
        RpcError::PeerDied => 5,
        RpcError::Cancelled => 6,
        RpcError::StaleCall | RpcError::WrongCaller | RpcError::WrongCallee => 11,
        RpcError::MalformedMessage => 3,
        _ => 1,
    }
}
#[inline(never)]
fn verify_stacks(plan: &Image<'_>) {
    assert_eq!(plan.base(), BASE);
    assert_eq!(plan.stack_top(), BASE + 0x200000);
    for address in ROLE_PAGES {
        let mut pages = plan.pages().filter(|p| p.address == address);
        let page = pages.next().expect("declared secondary stack page");
        assert!(pages.next().is_none());
        assert_eq!(page.permission, UserPermission::ReadWrite);
        let mut bytes = [0u8; FRAME_SIZE as usize];
        page.copy_into(&mut bytes);
        assert!(bytes.iter().all(|&b| b == 0));
    }
    for guard in GUARDS {
        assert!(
            !plan.pages().any(|p| p.address == guard),
            "secondary stack guard mapped"
        );
    }
}
impl Runtime<'_, '_> {
    fn rank(&self, id: ThreadId) -> Option<usize> {
        self.threads
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|t| t.id == id))
    }
    fn route_rank(&self, rank: usize) -> Option<usize> {
        self.routes
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|r| r.rank == rank))
    }
    fn route_object(&self, object: usize) -> Option<usize> {
        self.routes
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|r| r.object == object))
    }
    fn bind(&mut self, rank: usize) {
        let Some(index) = self.route_rank(rank) else {
            return;
        };
        let thread = self.threads[rank]
            .as_ref()
            .expect("declared servicing thread");
        let route = self.routes[index].as_mut().unwrap();
        assert!(!route.bound);
        self.rpc
            .bind_endpoint(
                self.a,
                self.actors[thread.process].meta.domain,
                route.receive,
                thread.id,
                Policy::new(8, 0).unwrap(),
            )
            .unwrap();
        route.bound = true;
    }
    fn spawn(&mut self, caller_rank: usize, role: u64, frame: &mut UserContext) {
        let current = self.threads[caller_rank].as_ref().unwrap();
        if self.world != World::Depth || current.role != 0 || !matches!(role, 1 | 2) {
            scalar(frame, 1, 0, 0);
            return;
        }
        let process = current.process;
        let rank = process + 3 * role as usize;
        if self.threads[rank].is_some() {
            scalar(frame, 1, 0, 0);
            return;
        }
        let actor = &self.actors[process];
        assert!(actor.stacks_verified);
        // Fixed bounded profile, held initialized backing, and distinct roles
        // preflight every untrusted admission field before creating a thread.
        if self.s.metadata_usage().2 >= ev_kernel::scheduler::MAX_THREADS
            || self.rpc.metadata_usage().0 >= ev_kernel::scheduler::MAX_THREADS
            || self.rpc.metadata_usage().1 >= ev_kernel::rpc::MAX_ENDPOINTS
            || self.s.usage(actor.meta.job, Resource::Threads).unwrap() >= 3
        {
            scalar(frame, 2, 0, 0);
            return;
        }
        let mut context =
            UserContext::new(actor.template.rip, ROLE_TOPS[role as usize - 1]).unwrap();
        context.registers[8] = actor.template.registers[8];
        context.registers[9] = actor.template.registers[9];
        context.registers[11] = role;
        context.registers[12] = process as u64;
        assert!(context.resumable());
        let id = match self.s.create_thread(actor.meta.process) {
            Ok(id) => id,
            Err(_) => {
                scalar(frame, 2, 0, 0);
                return;
            }
        };
        // This fixed world reserves at most9/16 threads and8/8 routes. The
        // actual freshly-created process/job/domain association is retained;
        // no user PID, stack, entry or readiness flag enters registration.
        self.rpc
            .register_thread(self.a, self.s, id, actor.meta.job, actor.meta.domain, None)
            .unwrap();
        self.threads[rank] = Some(Thread {
            id,
            process,
            role: role as usize,
            context,
            fx: FxState::CLEAN,
        });
        self.bind(rank);
        self.proof.spawned += 1;
        let diagnostic = id.diagnostic_id();
        assert_ne!(
            diagnostic, 0,
            "primaries retain the first three thread slots"
        );
        scalar(frame, 0, diagnostic, 0);
    }
    fn call(
        &mut self,
        rank: usize,
        endpoint: Handle,
        value: u64,
        absolute: u64,
        frame: &mut UserContext,
    ) -> bool {
        let thread = self.threads[rank].as_ref().unwrap();
        let caller = thread.id;
        let domain = self.actors[thread.process].meta.domain;
        if echo::Request::decode(&value.to_le_bytes()).is_err() || absolute > self.global.tick() {
            scalar(frame, 3, 0, 0);
            return false;
        }
        let Some(route_index) = self
            .a
            .authorize(domain, endpoint, Kind::Endpoint, Rights::SEND)
            .ok()
            .and_then(|a| self.route_object(a.identity()))
        else {
            scalar(frame, 1, 0, 0);
            return false;
        };
        let target = self.routes[route_index].as_ref().unwrap();
        if !target.bound || target.mailbox.pending() != 0 {
            scalar(frame, 2, 0, 0);
            return false;
        }
        let callee = self.threads[target.rank].as_ref().unwrap().id;
        let deadline = Deadline::after(0, absolute).unwrap();
        if self.s.check_block(0, deadline).is_err() {
            scalar(frame, 4, 0, 0);
            return false;
        }
        let parent = self
            .rpc
            .serving(caller)
            .map(|id| self.rpc.context(id).unwrap());
        let snapshot = (
            self.a.metadata_usage(),
            self.rpc.metadata_usage(),
            target.mailbox.pending(),
        );
        let now = crate::timer::now();
        let id = match self.rpc.begin(
            self.a,
            caller,
            endpoint,
            deadline,
            MessageShape {
                bytes: 8,
                capabilities: 0,
            },
            now,
        ) {
            Ok(id) => id,
            Err(error) => {
                assert_eq!(
                    (
                        self.a.metadata_usage(),
                        self.rpc.metadata_usage(),
                        self.routes[route_index].as_ref().unwrap().mailbox.pending()
                    ),
                    snapshot
                );
                match error {
                    RpcError::DangerousLock => self.proof.dangerous_lock += 1,
                    RpcError::DeadlockDetected => self.proof.cycle += 1,
                    RpcError::DeadlineExtended => self.proof.deadline_extended += 1,
                    RpcError::DepthExceeded => self.proof.depth_exceeded += 1,
                    _ => (),
                }
                scalar(frame, error_status(error), 0, 0);
                return false;
            }
        };
        let Some(slot) = self.pending.iter().position(Option::is_none) else {
            // Semantic/depth validation is always performed by Rpc FIRST. The
            // depth9 fixture reuses its existing rank1 route: no ninth endpoint
            // or pending slot can turn the required depth rejection into Busy.
            self.rpc.cancel(caller, id, now).unwrap();
            self.rpc.complete(callee, id, now).unwrap();
            scalar(frame, 2, 0, 0);
            return false;
        };
        let context = self.rpc.context(id).unwrap();
        assert_eq!(context.origin_job, self.actors[0].meta.job);
        assert_eq!(context.depth, rank as u8 + 1);
        assert_eq!(context.deadline.tick(), absolute);
        assert_eq!(context.root_incarnation, None);
        match parent {
            Some(parent) => {
                assert_eq!(context.parent_call_id, Some(parent.call_id));
                assert_eq!(context.trace_id, parent.trace_id);
                assert_eq!(context.origin_job, parent.origin_job);
                assert_eq!(context.depth, parent.depth + 1);
                assert!(context.deadline.tick() <= parent.deadline.tick());
            }
            None => {
                assert_eq!(context.parent_call_id, None);
                assert_eq!(context.trace_id.root(), id);
            }
        }
        let ticket = match self.routes[route_index].as_mut().unwrap().mailbox.send(
            self.a,
            domain,
            endpoint,
            Outgoing {
                bytes: &value.to_le_bytes(),
                capability: None,
                deadline,
            },
            now,
        ) {
            Ok(ticket) => ticket,
            Err(_) => {
                self.rpc.cancel(caller, id, now).unwrap();
                self.rpc.complete(callee, id, now).unwrap();
                scalar(frame, 2, 0, 0);
                return false;
            }
        };
        let wait = self
            .s
            .block(0, deadline)
            .expect("actual preflighted IPC wait");
        self.pending[slot] = Some(Pending {
            id,
            caller,
            callee,
            caller_rank: rank,
            wait,
            ticket,
            route: route_index,
            delivered: false,
        });
        self.proof.accepted += 1;
        self.proof.blocks += 1;
        self.proof.contexts_verified += 1;
        self.proof.max_depth = self.proof.max_depth.max(context.depth);
        scalar(frame, 0, 0, 0);
        true
    }
    fn receive(&mut self, rank: usize, endpoint: Handle, frame: &mut UserContext) {
        let thread = self.threads[rank].as_ref().unwrap();
        let domain = self.actors[thread.process].meta.domain;
        let Some(index) = self
            .a
            .authorize(domain, endpoint, Kind::Endpoint, RECEIVE)
            .ok()
            .and_then(|a| self.route_object(a.identity()))
        else {
            nonce_result(frame, 1, 0, 0);
            return;
        };
        let route = self.routes[index].as_ref().unwrap();
        // Same-domain RX authority is insufficient to impersonate another
        // servicing thread. In depth, rank0 aliases the actual rank3 route.
        if route.rank != rank || !route.bound {
            let before = route.mailbox.pending();
            self.proof.wrong_thread += 1;
            assert_eq!(
                self.routes[index].as_ref().unwrap().mailbox.pending(),
                before
            );
            nonce_result(frame, 1, 0, 0);
            return;
        }
        let Some(id) = self.rpc.serving(thread.id) else {
            nonce_result(frame, 2, 0, 0);
            return;
        };
        let Some(slot) = self
            .pending
            .iter()
            .position(|p| p.is_some_and(|p| p.id == id && p.callee == thread.id))
        else {
            nonce_result(frame, 11, 0, 0);
            return;
        };
        if self.pending[slot].unwrap().delivered {
            nonce_result(frame, 11, 0, 0);
            return;
        }
        assert_eq!(self.pending[slot].unwrap().route, index);
        assert_ne!(self.pending[slot].unwrap().ticket.0, 0);
        match self.routes[index].as_mut().unwrap().mailbox.receive(
            self.a,
            domain,
            endpoint,
            crate::timer::now(),
        ) {
            Ok(delivery) => {
                assert_eq!(delivery.length, 8);
                assert_eq!(delivery.capability, None);
                assert!(echo::Request::decode(&delivery.bytes[..delivery.length]).is_ok());
                self.pending[slot].as_mut().unwrap().delivered = true;
                self.proof.delivered += 1;
                nonce_result(
                    frame,
                    0,
                    u64::from_le_bytes(delivery.bytes[..8].try_into().unwrap()),
                    id.serial(),
                );
            }
            Err(IpcError::Empty) => nonce_result(frame, 2, 0, 0),
            Err(_) => nonce_result(frame, 1, 0, 0),
        }
    }
    fn reply(
        &mut self,
        rank: usize,
        endpoint: Handle,
        value: u64,
        serial: u64,
        frame: &mut UserContext,
    ) {
        let thread = self.threads[rank].as_ref().unwrap();
        let domain = self.actors[thread.process].meta.domain;
        let Some(route) = self
            .a
            .authorize(domain, endpoint, Kind::Endpoint, RECEIVE)
            .ok()
            .and_then(|a| self.route_object(a.identity()))
        else {
            nonce_result(frame, 1, 0, 0);
            return;
        };
        if self.routes[route].as_ref().unwrap().rank != rank {
            nonce_result(frame, 1, 0, 0);
            return;
        }
        let Some(id) = self
            .rpc
            .serving(thread.id)
            .filter(|id| id.serial() == serial)
        else {
            nonce_result(frame, 11, 0, 0);
            return;
        };
        let Some(slot) = self
            .pending
            .iter()
            .position(|p| p.is_some_and(|p| p.id == id && p.callee == thread.id && p.delivered))
        else {
            nonce_result(frame, 11, 0, 0);
            return;
        };
        if echo::Response::decode(&value.to_le_bytes()).is_err() {
            nonce_result(frame, 3, 0, 0);
            return;
        }
        let pending = self.pending[slot].unwrap();
        assert!(self.s.waiting(pending.wait));
        match self.rpc.complete(thread.id, id, crate::timer::now()) {
            Ok(completion) => {
                assert_eq!(
                    (completion.call, completion.caller),
                    (pending.id, pending.caller)
                );
                assert!(completion.deliver_reply && completion.wake_caller);
                let caller = self.threads[pending.caller_rank].as_mut().unwrap();
                assert_eq!(caller.id, completion.caller);
                scalar(&mut caller.context, 0, value, 0);
                assert!(self.s.wake(pending.wait));
                assert!(!self.s.wake(pending.wait));
                self.pending[slot] = None;
                self.proof.replies += 1;
                self.proof.wakes += 1;
                nonce_result(frame, 0, 0, 0);
            }
            Err(error) => nonce_result(frame, error_status(error), 0, 0),
        }
    }
    fn expire(&mut self) {
        let now = crate::timer::now();
        let events = self.rpc.expire(now).unwrap();
        assert!(
            events.is_empty(),
            "bounded discipline fixture unexpectedly expired"
        );
        self.s.advance(now).unwrap();
    }
    fn syscall(&mut self, rank: usize, frame: &mut UserContext) -> bool {
        match decode(frame) {
            Ok(Call::Yield) => scalar(frame, 0, 0, 0),
            Ok(Call::Monotonic) => scalar(frame, 0, crate::timer::now(), 0),
            Ok(Call::RpcDeadline) => {
                let id = self.threads[rank].as_ref().unwrap().id;
                match self
                    .rpc
                    .serving(id)
                    .and_then(|id| self.rpc.context(id).ok())
                {
                    Some(context) => scalar(frame, 0, context.deadline.tick(), 0),
                    None => scalar(frame, 1, 0, 0),
                }
            }
            Ok(Call::MutexAcquire(cap)) => {
                match self.mutexes.acquire(self.a, self.s, self.rpc, 0, cap) {
                    Ok(acquired) => {
                        assert!(!acquired.abandoned);
                        self.proof.mutex_acquired += 1;
                        scalar(
                            frame,
                            0,
                            acquired.lease.scalar(),
                            u64::from(acquired.abandoned),
                        );
                    }
                    Err(_) => scalar(frame, 1, 0, 0),
                }
            }
            Ok(Call::MutexRelease(lease)) => {
                match self
                    .mutexes
                    .release(self.s, self.rpc, 0, Lease::from_scalar(lease))
                {
                    Ok(()) => {
                        self.proof.mutex_released += 1;
                        scalar(frame, 0, 0, 0);
                    }
                    Err(_) => scalar(frame, 1, 0, 0),
                }
            }
            Ok(Call::Spawn(role)) => self.spawn(rank, role, frame),
            Ok(Call::Rpc {
                endpoint,
                value,
                deadline,
            }) => return self.call(rank, endpoint, value, deadline, frame),
            Ok(Call::ReceiveRpc(endpoint)) => self.receive(rank, endpoint, frame),
            Ok(Call::ReplyRpc {
                endpoint,
                value,
                serial,
            }) => self.reply(rank, endpoint, value, serial, frame),
            Ok(Call::Exit(code)) => {
                assert_eq!(
                    (rank, code),
                    (0, 0),
                    "discipline actor failed in {:?}",
                    self.world
                );
                assert!(self.pending.iter().all(Option::is_none));
                assert_eq!(self.rpc.outstanding(), 0);
                assert_eq!(self.mutexes.metadata_usage().1, 0);
                assert_eq!(self.s.exit(0), Ok(self.threads[rank].as_ref().unwrap().id));
                self.s
                    .terminate_process(self.actors[0].meta.process)
                    .unwrap();
                self.proof.exits += 1;
                self.done = true;
                return true;
            }
            _ => scalar(frame, 3, 0, 0),
        }
        false
    }
    unsafe fn run(&mut self, hw: &mut Hardware<'_>) {
        // SAFETY: exclusive BSP PIC owner at IF0, AP parked, no user active.
        unsafe {
            crate::timer::start_runtime();
        }
        for _ in 0..65536 {
            assert!(
                !self.global.reached(crate::timer::now()),
                "discipline global deadline"
            );
            self.expire();
            let dispatch = self
                .s
                .dispatch(0)
                .unwrap()
                .expect("no runnable discipline actor");
            let rank = self
                .rank(dispatch.thread)
                .expect("foreign discipline thread");
            let thread = self.threads[rank].as_ref().unwrap();
            assert_eq!(dispatch.process, self.actors[thread.process].meta.process);
            self.actors[thread.process]
                .running
                .as_ref()
                .unwrap()
                .image()
                .loaded
                .root
                .activate();
            let thread = self.threads[rank].as_mut().unwrap();
            // SAFETY: actual registered admitted thread, private retained stack,
            // exact process root and per-thread FX; capture restores CR3/IF0.
            let (mut frame, _) = unsafe {
                crate::user_runtime::resume_context(&thread.context, &mut thread.fx, hw.original)
            };
            self.expire();
            let blocked = match frame.vector {
                32 => {
                    self.s
                        .charge_cpu(0, 1)
                        .expect("finite discipline CPU profile");
                    false
                }
                128 => self.syscall(rank, &mut frame),
                _ => panic!(
                    "discipline user/kernel trap rank={rank} vector={} ip={:#x}",
                    frame.vector, frame.rip
                ),
            };
            self.threads[rank].as_mut().unwrap().context = frame;
            if self.done {
                break;
            }
            if !blocked {
                self.s.yield_cpu(0).unwrap();
            }
        }
        // SAFETY: common capture returned to controller CR3 at IF0.
        unsafe {
            crate::timer::stop_runtime();
        }
        assert!(self.done, "finite discipline trap bound exhausted");
    }
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
unsafe fn load_actor<'a>(
    registry: &mut Registry<'static>,
    a: &Authority,
    s: &mut Scheduler,
    custody: SpaceId,
    cap: Handle,
    epoch: NonZeroU64,
    process: usize,
    slot: &'a mut LoadedImage,
    hw: &mut Hardware<'_>,
) -> Actor<'a> {
    let meta = registry.metadata(a, custody, cap).unwrap();
    let startup = registry.startup(a, custody, cap, epoch).unwrap();
    let plan = registry.plan(a, custody, cap).unwrap();
    verify_stacks(&plan);
    // SAFETY: exact held measured target, immutable startup and unique slot.
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
            cap,
            epoch,
            ProcessImage {
                loaded: slot,
                process: meta.process,
                frames: meta.frames,
            },
        )
        .unwrap_or_else(|r| panic!("discipline admission: {:?}", r.error));
    let mut template = running.initial_context().unwrap();
    template.registers[11] = 0;
    template.registers[12] = process as u64;
    Actor {
        running: Some(running),
        meta,
        control: cap,
        template,
        stacks_verified: true,
    }
}

/// # Safety
/// Exclusive BSP at IF0, AP parked, retained controller/direct-map root, ordinary
/// initialized user trap/FX/PIC boundary and exclusive physical frame ownership.
#[inline(never)]
pub unsafe fn prove(offset: u64, frames: &mut BootstrapFrames) -> Proof {
    let mut proof = Proof {
        stack_policy: true,
        frames_balanced: true,
        metadata_balanced: true,
        ..Proof::default()
    };
    for world in [World::Chain, World::Depth] {
        // SAFETY: every independent world fully stops and retires before reuse.
        let one = unsafe { run_world(offset, frames, world) };
        proof.worlds += one.worlds;
        proof.accepted += one.accepted;
        proof.blocks += one.blocks;
        proof.wakes += one.wakes;
        proof.delivered += one.delivered;
        proof.replies += one.replies;
        proof.contexts_verified += one.contexts_verified;
        proof.spawned += one.spawned;
        proof.dangerous_lock += one.dangerous_lock;
        proof.cycle += one.cycle;
        proof.deadline_extended += one.deadline_extended;
        proof.depth_exceeded += one.depth_exceeded;
        proof.wrong_thread += one.wrong_thread;
        proof.mutex_acquired += one.mutex_acquired;
        proof.mutex_released += one.mutex_released;
        proof.exits += one.exits;
        proof.max_depth = proof.max_depth.max(one.max_depth);
        proof.stack_policy &= one.stack_policy;
        proof.frames_balanced &= one.frames_balanced;
        proof.metadata_balanced &= one.metadata_balanced;
    }
    proof
}
#[inline(never)]
unsafe fn run_world(offset: u64, frames: &mut BootstrapFrames, world: World) -> Proof {
    let before = frames.remaining_frames();
    let original: u64;
    // SAFETY: privileged read; no user process is active in this controller.
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
    let epoch = NonZeroU64::new(if world == World::Chain { 241 } else { 242 }).unwrap();
    let mut a = Authority::new();
    let custody = a.create_space().unwrap();
    let common = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE;
    // Three external sealed Job roots avoid a redundant creator object. The
    // actual private Scheduler parent retains aggregate CPU after Job cleanup.
    let job_caps = core::array::from_fn::<_, 3, _>(|_| {
        a.create_root(custody, Kind::Job, common | Rights::READ | Rights::CONTROL)
            .unwrap()
    });
    let image_cap = a.create_root(custody, Kind::Memory, Rights::READ).unwrap();
    let mutex_cap = (world == World::Chain).then(|| {
        a.create_root(custody, Kind::Mutex, common | Rights::CONTROL)
            .unwrap()
    });
    let mut s = Scheduler::new();
    let parent = s
        .create_job_with_limits(Limits::new(2048, 64, 4, 12))
        .unwrap();
    let jobs: [JobId; 3] =
        core::array::from_fn(|_| s.create_child_job(parent, world.limits()).unwrap());
    let mut registry =
        Registry::with_service_limits(NonZeroU64::new(1).unwrap(), world.limits()).unwrap();
    for (cap, job) in job_caps.into_iter().zip(jobs) {
        registry.register_job(&a, custody, cap, job).unwrap();
    }
    let (bytes, sha) = world.image();
    let roles = [
        Role {
            selector: 1,
            kind: Kind::Endpoint,
            rights: RECEIVE,
        },
        Role {
            selector: 2,
            kind: Kind::Endpoint,
            rights: Rights::SEND,
        },
        Role {
            selector: 3,
            kind: Kind::Endpoint,
            rights: RECEIVE,
        },
        Role {
            selector: 4,
            kind: Kind::Endpoint,
            rights: Rights::SEND,
        },
        Role {
            selector: 5,
            kind: Kind::Endpoint,
            rights: RECEIVE,
        },
        Role {
            selector: 6,
            kind: Kind::Endpoint,
            rights: Rights::SEND,
        },
        Role {
            selector: 7,
            kind: Kind::Mutex,
            rights: Rights::CONTROL,
        },
    ];
    registry
        .register_image(
            &a,
            custody,
            image_cap,
            ServiceImage::verify(
                bytes,
                sha,
                world.limits(),
                &roles[..if world == World::Chain { 7 } else { 6 }],
            )
            .unwrap(),
        )
        .unwrap();
    let controls = job_caps.map(|cap| {
        registry
            .create_process(&mut a, &mut s, custody, cap, image_cap)
            .unwrap()
    });
    let metadata = controls.map(|cap| registry.metadata(&a, custody, cap).unwrap());
    let mut routes: [Option<Route>; ROUTES] = [const { None }; ROUTES];
    for (slot, route) in routes[..world.count()].iter_mut().enumerate() {
        let rank = if world == World::Chain {
            slot
        } else {
            slot + 1
        };
        let (cap, mailbox) = registry
            .create_channel(&mut a, custody, job_caps[0])
            .unwrap();
        let object = a
            .authorize(custody, cap, Kind::Endpoint, Rights::CONTROL)
            .unwrap()
            .identity();
        *route = Some(Route {
            rank,
            object,
            control: cap,
            receive: cap,
            mailbox,
            bound: false,
        });
    }
    for (process, control) in controls.iter().copied().enumerate() {
        for role in 0..3 {
            let rank = if world == World::Chain {
                process
            } else {
                process + 3 * role
            };
            let incoming = routes
                .iter()
                .flatten()
                .find(|r| r.rank == world.inbound(rank))
                .unwrap()
                .control;
            let outgoing = routes
                .iter()
                .flatten()
                .find(|r| r.rank == world.outbound(rank))
                .unwrap()
                .control;
            registry
                .delegate(&mut a, custody, control, incoming, role as u64 * 2 + 1)
                .unwrap();
            registry
                .delegate(&mut a, custody, control, outgoing, role as u64 * 2 + 2)
                .unwrap();
        }
        if let Some(cap) = mutex_cap {
            registry.delegate(&mut a, custody, control, cap, 7).unwrap();
        }
    }
    for route in routes.iter_mut().flatten() {
        let process = route.rank % 3;
        let role = route.rank / 3;
        route.receive = registry
            .grant(&a, custody, controls[process], role as u64 * 2 + 1)
            .unwrap();
        route
            .mailbox
            .rebind_empty(
                &a,
                custody,
                route.control,
                metadata[process].domain,
                route.receive,
            )
            .unwrap();
    }
    // The complete fixture stays within the existing fixed tables; spawned
    // threads share their admitted process domains and measured image pages.
    assert_eq!(
        a.metadata_usage(),
        if world == World::Depth {
            (15, 51, 51, 15)
        } else {
            (10, 53, 53, 11)
        }
    );
    let mut storage = [
        LoadedImage::empty(),
        LoadedImage::empty(),
        LoadedImage::empty(),
    ];
    let [first, second, third] = storage.each_mut();
    // SAFETY: independently held measured processes and exclusive inactive slots.
    let actors = unsafe {
        [
            load_actor(
                &mut registry,
                &a,
                &mut s,
                custody,
                controls[0],
                epoch,
                0,
                first,
                &mut hw,
            ),
            load_actor(
                &mut registry,
                &a,
                &mut s,
                custody,
                controls[1],
                epoch,
                1,
                second,
                &mut hw,
            ),
            load_actor(
                &mut registry,
                &a,
                &mut s,
                custody,
                controls[2],
                epoch,
                2,
                third,
                &mut hw,
            ),
        ]
    };
    let mut threads: [Option<Thread>; THREADS] = [const { None }; THREADS];
    let mut rpc = Rpc::new(epoch);
    for (process, actor) in actors.iter().enumerate() {
        rpc.register_thread(
            &a,
            &s,
            actor.meta.thread,
            actor.meta.job,
            actor.meta.domain,
            None,
        )
        .unwrap();
        threads[process] = Some(Thread {
            id: actor.meta.thread,
            process,
            role: 0,
            context: actor.template,
            fx: FxState::CLEAN,
        });
    }
    let mut mutexes = Mutexes::new();
    if let Some(cap) = mutex_cap {
        mutexes
            .register(
                &a,
                custody,
                cap,
                LockClass {
                    rank: 10,
                    no_ipc_wait: true,
                },
            )
            .unwrap();
    }
    let mut runtime = Runtime {
        a: &mut a,
        s: &mut s,
        registry: &mut registry,
        rpc: &mut rpc,
        mutexes: &mut mutexes,
        actors,
        threads,
        routes,
        pending: [None; ev_kernel::rpc::MAX_CALLS],
        proof: Proof::default(),
        world,
        global: Deadline::after(crate::timer::now(), 1024).unwrap(),
        done: false,
    };
    for rank in 0..3 {
        runtime.bind(rank);
    }
    // SAFETY: only actual admitted threads/roots enter; same serialized controller.
    unsafe {
        runtime.run(&mut hw);
    }
    assert_eq!(runtime.proof.exits, 1);
    assert!(runtime.pending.iter().all(Option::is_none));
    assert_eq!(runtime.rpc.outstanding(), 0);
    assert_eq!(runtime.mutexes.metadata_usage().1, 0);
    for actor in &mut runtime.actors {
        actor
            .running
            .as_mut()
            .unwrap()
            .stop(runtime.a, runtime.s)
            .unwrap();
        runtime.s.terminate_process(actor.meta.process).unwrap();
    }
    for thread in runtime.threads.iter().flatten() {
        assert!(
            runtime
                .rpc
                .peer_died(runtime.s, thread.id, crate::timer::now())
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            runtime
                .mutexes
                .owner_died(runtime.s, runtime.rpc, thread.id),
            Ok(0)
        );
    }
    for route in runtime.routes.iter_mut().flatten() {
        route
            .mailbox
            .receiver_died(metadata[route.rank % 3].domain)
            .unwrap();
        assert_eq!(route.mailbox.pending(), 0);
    }
    for actor in &mut runtime.actors {
        let ProcessImage { loaded, .. } = actor
            .running
            .take()
            .unwrap()
            .finish(runtime.s)
            .unwrap_or_else(|_| panic!("discipline executable lease retained"));
        // SAFETY: ALL process threads stopped, no AP used root, controller CR3
        // active, all RPC/mailboxes empty and unique executable lease returned.
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
    }
    for thread in runtime.threads.iter().flatten() {
        runtime.rpc.forget_thread(runtime.s, thread.id).unwrap();
    }
    for actor in &runtime.actors {
        runtime.s.reclaim_process(actor.meta.process).unwrap();
    }
    let mut retired = [const { None }; ROUTES];
    for (slot, route) in runtime.routes.iter_mut().enumerate() {
        if let Some(route) = route.take() {
            runtime.a.close(custody, route.control).unwrap();
            retired[slot] = Some(
                route
                    .mailbox
                    .retire_managed(runtime.a)
                    .unwrap_or_else(|r| panic!("{:?}", r.error)),
            );
        }
    }
    if let Some(cap) = mutex_cap {
        runtime.mutexes.retire(runtime.a, custody, cap).unwrap();
    }
    assert_eq!(runtime.mutexes.metadata_usage(), (0, 0, 0));
    for job in jobs {
        runtime
            .registry
            .forget_job(runtime.a, runtime.s, runtime.rpc, job)
            .unwrap();
    }
    runtime.a.collect_lineage().unwrap();
    assert_eq!(runtime.a.metadata_usage(), (1, 4, 4, 4));
    assert_eq!(runtime.registry.metadata_usage(), (0, 1, 0, 6));
    assert_eq!(runtime.s.metadata_usage(), (1, 0, 0));
    assert_eq!(runtime.rpc.metadata_usage(), (0, 0, 0));
    for resource in [Resource::Frames, Resource::Processes, Resource::Threads] {
        assert_eq!(runtime.s.usage(parent, resource), Ok(0));
    }
    assert_eq!(hw.frames.remaining_frames(), before);
    runtime.proof.worlds = 1;
    runtime.proof.stack_policy = true;
    runtime.proof.frames_balanced = true;
    runtime.proof.metadata_balanced = true;
    runtime.proof
}
