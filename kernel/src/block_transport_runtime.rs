//! Bounded two-process shared-page PIO fixture. No admitted timeout/cancellation,
//! general shared-buffer transport, device recovery or BAC fence is claimed.
use crate::{
    executable_runtime::{LoadedImage, PREBOUND_SHARED_PAGE, ProcessImage, SharedMapError},
    supervisor_runtime::bundle,
};
use core::{arch::asm, num::NonZeroU64};
#[cfg(feature = "test-m3-file")]
mod file_support;
mod generation_support;
mod lifecycle;
use ev_kernel::events::{Caller as EventCaller, Error as EventError};
use ev_kernel::{
    capability::{Authority, Handle, Kind, Rights, SpaceId},
    fault::Record,
    io_ports::{Caller, Direction, Range, Registry as Ports, Request, Widths},
    ipc::{Error as IpcError, Mailbox, Outgoing, Ticket},
    mapping::{ADDRESS_MASK, direct_address},
    memory::{BootstrapFrames, FRAME_SIZE},
    memory_object::MemoryObject,
    rpc::{CallId, MessageShape, Policy, Rpc},
    scheduler::{Limits, ProcessId, Resource, Scheduler, ThreadId, WaitTicket},
    service::{Metadata, Registry, Role, Running, ServiceImage},
    time::Deadline,
    user::UserPermission,
    user_context::{Call, FxState, UserContext, decode},
};
use ev_userspace_contract::{Event, generation};
use ev_userspace_contract::{
    block,
    store_test::{Completion, Control, Mode},
};
#[cfg(feature = "test-m3-file")]
pub use file_support::FileProof;
/// # Safety
/// Same exclusive initialized BSP/non-DMA/controller/frame ownership as prove;
/// no admitted shared-buffer timeout/cancellation exists in this fixture.
#[cfg(feature = "test-m3-file")]
pub unsafe fn prove_file(offset: u64, frames: &mut BootstrapFrames) -> FileProof {
    // SAFETY: forward the same serialized actual hardware/allocator ownership.
    unsafe { file_support::prove_file(offset, frames) }
}
use sha2::{Digest as _, Sha256};

const LIMITS: Limits = Limits::new(1024, 32, 1, 1);
// Actual generation publication exceeded the two-process fixture's1024-tick
// bound while a third live critical peer remained scheduled.
const GENERATION_LIMITS: Limits = Limits::new(2048, 32, 1, 1);
const OWNER_LIMITS: Limits = Limits::new(65536, 32, 1, 1);
const RECEIVE: Rights = Rights::from_bits(272).unwrap();
const SHARED: Rights = Rights::from_bits(7).unwrap();
const SNAPSHOT_YIELD: u64 = 0x424c_5350;
const FILE_SNAPSHOT_YIELD: u64 = 0x464c_5350;
const ATA: [Range; 3] = [
    Range {
        first: 0x1e8,
        last: 0x1e9,
        widths: Widths::WORD,
        direction: Direction::Both,
    },
    Range {
        first: 0x1e9,
        last: 0x1ef,
        widths: Widths::BYTE,
        direction: Direction::Both,
    },
    Range {
        first: 0x3ee,
        last: 0x3ee,
        widths: Widths::BYTE,
        direction: Direction::Both,
    },
];
#[derive(Default)]
pub struct Proof {
    pub calls: u64,
    pub blocks: u64,
    pub wakes: u64,
    pub replies: u64,
    pub short_deadline_denied: u64,
    pub authority_denied: u64,
    pub malformed: u64,
    pub mapped: u64,
    pub private_copy: bool,
    pub guards: bool,
    pub frames: bool,
    pub metadata: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    Transport,
    Store,
    Generation,
    Progress,
    Owner,
    File,
}
impl Profile {
    fn limits(self) -> Limits {
        match self {
            Self::Owner => OWNER_LIMITS,
            Self::Generation | Self::Progress | Self::File => GENERATION_LIMITS,
            Self::Transport | Self::Store => LIMITS,
        }
    }
    fn ticks(self) -> u64 {
        self.limits().limit(Resource::CpuTicks)
    }
    fn is_generation(self) -> bool {
        self == Self::Generation || self == Self::Progress || self == Self::Owner
    }
    fn parent_cpu(self) -> u64 {
        if self == Self::Owner { 131072 } else { 4096 }
    }
    fn transition_limit(self) -> u64 {
        if self == Self::Owner {
            8_000_000
        } else {
            100_000
        }
    }
}
#[derive(Default)]
struct StoreState {
    control: Option<Control>,
    event: Option<Completion>,
    fault: Option<Record>,
    mutations: u64,
    errors: u64,
    client: Option<(ProcessId, ThreadId)>,
}
#[cfg(feature = "test-m3-store")]
pub struct StoreProof {
    pub control: Control,
    pub event: Option<Completion>,
    pub fault: Option<Record>,
    pub calls: u64,
    pub blocks: u64,
    pub wakes: u64,
    pub replies: u64,
    pub mutations: u64,
    pub client_process: u64,
    pub client_thread: u64,
    pub frames: bool,
    pub metadata: bool,
    pub guards: bool,
}
#[derive(Default)]
struct GenerationState {
    control: Option<generation::Control>,
    report: Option<generation::Completion>,
    ready: u64,
    critical_ready: u64,
    forged: u64,
    accounting: Accounting,
    uart_inputs: u64,
    uart_outputs: u64,
    uart_rx: UartBytes,
}
struct UartBytes {
    bytes: [u8; 128],
    len: usize,
    before_tx: usize,
}
impl Default for UartBytes {
    fn default() -> Self {
        Self {
            bytes: [0; 128],
            len: 0,
            before_tx: 0,
        }
    }
}
#[derive(Default)]
struct Accounting {
    elapsed_ticks: u64,
    cpu_driver: u64,
    cpu_client: u64,
    cpu_critical: u64,
    cpu_parent: u64,
    transitions: u64,
    max_pending: u64,
}
struct CatalogueView<'a> {
    object: &'a MemoryObject,
    data: generation::Catalogue,
    digest: [u8; 32],
    images: [usize; 2],
}
#[cfg(feature = "test-m3-generation")]
pub struct GenerationProof {
    pub report: generation::Completion,
    pub calls: u64,
    pub blocks: u64,
    pub wakes: u64,
    pub replies: u64,
    pub mutations: u64,
    pub starts: u64,
    pub ready: u64,
    pub critical_ready: u64,
    pub faults: u64,
    pub stops: u64,
    pub reaps: u64,
    pub forged: u64,
    pub elapsed_ticks: u64,
    pub cpu_driver: u64,
    pub cpu_client: u64,
    pub cpu_critical: u64,
    pub cpu_parent: u64,
    pub transitions: u64,
    pub max_pending: u64,
    pub progress_start_tick: u64,
    pub progress_observed_tick: u64,
    pub progress_stop_tick: u64,
    pub stopped_live: bool,
    pub catalogue_readonly: bool,
    pub frames: bool,
    pub metadata: bool,
    pub guards: bool,
}
#[cfg(feature = "test-m3-owner")]
pub struct OwnerProof {
    pub generation: GenerationProof,
    pub uart_inputs: u64,
    pub uart_outputs: u64,
    pub uart_rx: [u8; 128],
    pub uart_rx_len: usize,
    pub uart_rx_before_tx: usize,
    pub limit_ticks: u64,
    pub transition_limit: u64,
    pub parent_cpu_limit: u64,
}
struct Actor<'a> {
    running: Option<Running<ProcessImage<'a>>>,
    meta: Metadata,
    control: Handle,
    context: UserContext,
    fx: FxState,
}
#[derive(Clone, Copy)]
struct Pending {
    id: CallId,
    wait: WaitTicket,
    ticket: Ticket,
    request: u64,
    delivered: bool,
    route: usize,
    caller: ThreadId,
    callee: ThreadId,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Block,
    Opaque,
}
struct Route<'a> {
    object: usize,
    receiver: Metadata,
    protocol: Protocol,
    mailbox: &'a mut Mailbox,
}
#[derive(Default)]
struct FileState {
    outer: u64,
    backend: u64,
    nested: u64,
    startup: u64,
    before_delivery: u64,
    delivered_nested: u64,
    contexts: u64,
    report: Option<[u8; 512]>,
    control: Option<[u8; 512]>,
    snapshots: u64,
    block_denied: u64,
    unbound_denied: u64,
    bindings: u64,
}
#[derive(Default)]
struct Progress {
    started: u64,
    last_reply: u64,
    traps: [u64; 3],
    syscalls: [u64; 3],
    last_call: [u64; 3],
    last_ip: [u64; 3],
    transitions: u64,
    max_pending: u64,
}
struct Runtime<'a, 'table> {
    a: &'table mut Authority,
    s: &'table mut Scheduler,
    rpc: &'table mut Rpc,
    ports: &'table Ports,
    ata_object: usize,
    uart_object: Option<usize>,
    object: &'table MemoryObject,
    actors: &'table mut [Actor<'a>],
    routes: &'table mut [Route<'table>],
    alias: *mut u8,
    stop: Deadline,
    pending: [Option<Pending>; 2],
    poisoned: u64,
    inputs: u64,
    outputs: u64,
    done: bool,
    proof: Proof,
    profile: Profile,
    store: StoreState,
    registry: &'table mut Registry<'static>,
    lifecycle: &'table mut lifecycle::Lifecycle<'a>,
    events: Option<&'table mut ev_kernel::events::Channel>,
    catalogue: Option<CatalogueView<'table>>,
    generation: GenerationState,
    progress: Progress,
    application: Option<(&'table MemoryObject, *mut u8)>,
    file: FileState,
}
fn scalar(frame: &mut UserContext, status: u64, value: u64) {
    frame.registers[14] = status;
    frame.registers[9] = value;
    frame.registers[11] = 0;
    // Legacy calls, especially22/clock/yield, preserve compiler-live R10.
}
fn extended(frame: &mut UserContext, status: u64, value: u64, serial: u64) {
    scalar(frame, status, value);
    frame.registers[5] = serial;
}
fn event_status(error: EventError) -> u64 {
    match error {
        EventError::Ipc(IpcError::Empty | IpcError::Full) | EventError::OriginCapacity => 2,
        _ => 1,
    }
}
impl Runtime<'_, '_> {
    #[cold]
    fn stop_failed(&self, stage: &str, now: u64, rank: usize, vector: u64) -> ! {
        panic!(
            "transport stop stage={stage} now={now} start={} stop={} rank={rank} vector={vector} calls={} replies={} mutations={} ports={}/{} pending={:?} critical={}/{}/{} events={}/{} forged={} traps={:?} syscalls={:?} last_call={:?} last_ip={:x?} last_reply={}",
            self.progress.started,
            self.stop.tick(),
            self.proof.calls,
            self.proof.replies,
            self.store.mutations,
            self.inputs,
            self.outputs,
            self.pending
                .map(|entry| entry.map(|p| (p.id.serial(), p.delivered))),
            self.lifecycle.facts.starts,
            self.lifecycle.facts.stops,
            self.lifecycle.facts.reaps,
            self.generation.ready,
            self.generation.critical_ready,
            self.generation.forged,
            self.progress.traps,
            self.progress.syscalls,
            self.progress.last_call,
            self.progress.last_ip,
            self.progress.last_reply,
        )
    }
    fn actor(&self, rank: usize) -> Metadata {
        if rank < self.actors.len() {
            self.actors[rank].meta
        } else {
            self.lifecycle.metadata().expect("actual critical dispatch")
        }
    }
    fn receive_event(&mut self, endpoint: Handle, frame: &mut UserContext, provenance: bool) {
        let result = self.events.as_mut().ok_or(1u64).and_then(|events| {
            events
                .receive(
                    EventCaller {
                        authority: self.a,
                        scheduler: self.s,
                        rpc: self.rpc,
                        cpu: 0,
                    },
                    endpoint,
                    crate::timer::now(),
                )
                .map_err(event_status)
        });
        match result {
            Ok(received) => {
                assert_eq!(
                    (received.delivery.length, received.delivery.capability),
                    (8, None)
                );
                let value = u64::from_le_bytes(received.delivery.bytes[..8].try_into().unwrap());
                if provenance {
                    // These counters audit actual delivered source diagnostics;
                    // they neither authorize a health transition nor alter bytes.
                    let event = Event::decode(&value.to_le_bytes());
                    let source = (received.process, received.thread);
                    let controller = (self.actors[1].meta.process, self.actors[1].meta.thread);
                    if source == controller
                        && matches!(event, Some(Event::Ready | Event::CriticalReady))
                    {
                        self.generation.forged += 1;
                    }
                    if self
                        .lifecycle
                        .facts
                        .last
                        .is_some_and(|m| (m.process, m.thread) == source)
                    {
                        if event == Some(Event::Ready) {
                            self.generation.ready += 1;
                        }
                        if event == Some(Event::CriticalReady)
                            && self
                                .s
                                .state(received.thread)
                                .is_ok_and(|s| s != ev_kernel::scheduler::State::Exited)
                        {
                            self.generation.critical_ready += 1;
                        }
                    }
                    extended(frame, 0, value, received.thread.diagnostic_id());
                    frame.registers[11] = received.process.diagnostic_id();
                } else {
                    scalar(frame, 0, value);
                }
            }
            Err(status) => {
                if provenance {
                    extended(frame, status, 0, 0)
                } else {
                    scalar(frame, status, 0)
                }
            }
        }
    }
    fn validate_generation(&self) {
        let report = self
            .generation
            .report
            .expect("actual userspace generation report");
        let control = self
            .generation
            .control
            .expect("actual disk generation control");
        assert_eq!(report.mode, control.mode);
        assert_eq!(report.mutations, self.store.mutations);
        assert_eq!(self.store.errors, 0);
        assert_eq!(
            (self.proof.calls, self.proof.blocks, self.proof.wakes),
            (self.proof.replies, self.proof.replies, self.proof.replies)
        );
        assert!(self.proof.calls > 0 && self.proof.calls <= 512);
        assert!(self.store.mutations <= 128);
        assert!(
            self.lifecycle.metadata().is_none(),
            "userspace must stop/reap/close before completion"
        );
        let catalogue = self.catalogue.as_ref().unwrap();
        assert_eq!(report.catalogue, catalogue.digest);
        let facts = &self.lifecycle.facts;
        let no_launch = matches!(
            report.mode,
            generation::Mode::Verify | generation::Mode::OwnerPrepare3
        ) || (report.mode == generation::Mode::OwnerRecover
            && report.owner_decision != generation::OwnerDecision::Continue);
        if no_launch {
            assert_eq!(
                (
                    facts.starts,
                    facts.stops,
                    facts.reaps,
                    self.generation.ready,
                    self.generation.critical_ready,
                    self.generation.forged
                ),
                (0, 0, 0, 0, 0, 0)
            );
            assert!(facts.fault.is_none());
            if report.mode != generation::Mode::OwnerPrepare3 {
                assert_eq!(self.store.mutations, 0);
            }
        } else {
            let meta = facts
                .last
                .expect("actual admitted source-built critical service");
            assert_eq!(
                (report.process, report.thread),
                (meta.process.diagnostic_id(), meta.thread.diagnostic_id())
            );
            assert_eq!((facts.starts, facts.stops, facts.reaps), (1, 1, 1));
            assert!(facts.identities >= 2);
            assert_eq!((report.negatives, self.generation.forged), (4, 4));
            let slot = if facts.image == Some(catalogue.images[0]) {
                generation::Slot::A
            } else {
                assert_eq!(facts.image, Some(catalogue.images[1]));
                generation::Slot::B
            };
            assert_eq!(
                report.booted_cohort,
                <[u8; 32]>::from(Sha256::digest(
                    catalogue.data.cohort_input_for(slot, report.booted)
                ))
            );
            assert_eq!(
                report.process_stamp,
                generation_support::expected_stamp(
                    catalogue.data,
                    &report,
                    catalogue.data.image(slot)
                )
            );
            if let Some(fault) = facts.fault {
                assert_eq!(
                    (fault.process, fault.thread),
                    (report.process, report.thread)
                );
                assert_eq!((fault.vector, fault.error), (14, 7));
                assert_eq!(report.failure_reason, 1);
                assert_eq!(self.generation.critical_ready, 0);
                assert!(facts.fault_queries >= 6);
            } else if slot == generation::Slot::B {
                assert_eq!(report.failure_reason, 2);
                assert_eq!(self.generation.critical_ready, 0);
                assert_eq!(facts.fault_queries, 0);
                assert!(facts.stopped_live);
                let first = facts.first_live_observe.expect("actual live observation");
                let observed = facts
                    .last_live_observe
                    .expect("actual deadline live observation");
                let stopped = facts.stop_tick.expect("actual live process stop");
                assert!(observed >= first.checked_add(64).unwrap());
                assert!(stopped >= observed);
            } else {
                assert_eq!(self.generation.critical_ready, 1);
                assert_eq!(facts.fault_queries, 0);
            }
        }
    }
    fn buffer(&self) -> [u8; 512] {
        // SAFETY: initialized retained shared RAM; user CPUs are stopped at IF0.
        core::array::from_fn(|i| unsafe { self.alias.add(i).read_volatile() })
    }
    fn guards(&self) {
        for i in 512..FRAME_SIZE as usize {
            // SAFETY: same retained frame, never reads beyond its4096 bytes.
            let byte = unsafe { self.alias.add(i).read_volatile() };
            assert_eq!(byte, 0, "shared guard byte {i}");
        }
        if let Some((_, alias)) = self.application {
            for i in 512..FRAME_SIZE as usize {
                // SAFETY: separately retained initialized app frame. Backend
                // IO can never address it, and this check stays inside4096B.
                let byte = unsafe { alias.add(i).read_volatile() };
                assert_eq!(byte, 0, "application guard byte {i}");
            }
        }
    }
    fn queues(&self) -> [usize; 3] {
        core::array::from_fn(|i| {
            self.routes
                .get(i)
                .map_or(0, |route| route.mailbox.pending())
        })
    }
    fn application_buffer(&self) -> Option<[u8; 512]> {
        self.application.map(|(_, alias)| {
            // SAFETY: separate initialized application frame retained for this
            // serialized inactive boundary; never reads outside its512 bytes.
            core::array::from_fn(|i| unsafe { alias.add(i).read_volatile() })
        })
    }
    fn route(&self, rank: usize, endpoint: Handle, rights: Rights) -> Option<usize> {
        let actor = self.actor(rank);
        let object = self
            .a
            .authorize(actor.domain, endpoint, Kind::Endpoint, rights)
            .ok()?
            .identity();
        self.routes.iter().position(|route| route.object == object)
    }
    fn reject(&mut self, rank: usize, frame: &mut UserContext, status: u64, counter: u8) {
        let before = (
            self.a.metadata_usage(),
            self.s.metadata_usage(),
            self.rpc.metadata_usage(),
            self.queues(),
            self.buffer(),
            self.application_buffer(),
            self.inputs,
            self.outputs,
        );
        let thread = self.actor(rank).thread;
        let state = self.s.state(thread).unwrap();
        scalar(frame, status, 0);
        assert_eq!(
            (
                self.a.metadata_usage(),
                self.s.metadata_usage(),
                self.rpc.metadata_usage(),
                self.queues(),
                self.buffer(),
                self.application_buffer(),
                self.inputs,
                self.outputs,
            ),
            before
        );
        assert_eq!(self.s.state(thread).unwrap(), state);
        self.guards();
        match counter {
            0 => self.proof.short_deadline_denied += 1,
            1 => self.proof.malformed += 1,
            _ => unreachable!(),
        }
    }
    fn call(
        &mut self,
        rank: usize,
        endpoint: Handle,
        value: u64,
        absolute: u64,
        frame: &mut UserContext,
    ) -> bool {
        if self.profile != Profile::File && rank != 1 {
            scalar(frame, 1, 0);
            return false;
        }
        // Preserve the accepted legacy transport's syntax probes. File service
        // commands are opaque to this kernel transport: userspace owns File
        // identity, method permissions, payload bounds and storage policy.
        if self.profile != Profile::File && block::Request::decode(&value.to_le_bytes()).is_err() {
            self.reject(rank, frame, 3, 1);
            return false;
        }
        if absolute <= self.stop.tick() || absolute > self.stop.tick().checked_add(1024).unwrap() {
            self.reject(rank, frame, 4, 0);
            return false;
        }
        let Some(route) = self.route(rank, endpoint, Rights::SEND) else {
            if self.profile == Profile::File && rank == 2 {
                self.file.block_denied += 1;
            }
            scalar(frame, 1, 0);
            return false;
        };
        if self.profile == Profile::File
            && self.routes[route].protocol == Protocol::Block
            && block::Request::decode(&value.to_le_bytes()).is_err()
        {
            self.reject(rank, frame, 3, 1);
            return false;
        }
        let Some(slot) = self.pending.iter().position(Option::is_none) else {
            scalar(frame, 2, 0);
            return false;
        };
        if self.pending.iter().flatten().any(|p| p.route == route)
            || self.routes[route].mailbox.pending() != 0
        {
            scalar(frame, 2, 0);
            return false;
        }
        let caller = self.actor(rank);
        let callee = self.routes[route].receiver;
        let deadline = Deadline::after(0, absolute).unwrap();
        if self.s.check_block(0, deadline).is_err() {
            scalar(frame, 4, 0);
            return false;
        }
        let parent = self
            .rpc
            .serving(caller.thread)
            .map(|id| self.rpc.context(id).unwrap());
        let now = crate::timer::now();
        let id = match self.rpc.begin(
            self.a,
            caller.thread,
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
                if self.profile == Profile::File
                    && rank == 2
                    && error == ev_kernel::rpc::Error::UnknownEndpoint
                {
                    self.file.unbound_denied += 1;
                }
                scalar(frame, 1, 0);
                return false;
            }
        };
        let context = self.rpc.context(id).unwrap();
        assert_eq!(id.serial(), self.proof.calls + 1);
        assert_eq!(context.deadline, deadline);
        assert_eq!(context.root_incarnation, None);
        if let Some(parent) = parent {
            assert_eq!(self.profile, Profile::File);
            assert!(
                self.pending
                    .iter()
                    .flatten()
                    .any(|p| p.id == parent.call_id && p.callee == caller.thread)
            );
            assert_eq!(context.parent_call_id, Some(parent.call_id));
            assert_eq!(context.origin_job, parent.origin_job);
            assert_eq!(context.trace_id, parent.trace_id);
            assert_eq!(context.depth, 2);
            assert!(context.deadline.tick() <= parent.deadline.tick());
        } else {
            assert_eq!(context.origin_job, caller.job);
            assert_eq!(context.depth, 1);
            assert_eq!(context.parent_call_id, None);
            assert_eq!(context.trace_id.root(), id);
        }
        let ticket = match self.routes[route].mailbox.send(
            self.a,
            caller.domain,
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
                // No actual scheduler wait exists. Retain the independent
                // outer reservation while refunding only this failed send.
                self.rpc.cancel(caller.thread, id, now).unwrap();
                self.rpc.complete(callee.thread, id, now).unwrap();
                scalar(frame, 2, 0);
                return false;
            }
        };
        let wait = self
            .s
            .block(0, deadline)
            .expect("serialized actual wait preflight");
        if self.profile != Profile::File {
            assert_eq!(ticket.0, self.proof.calls + 1);
        }
        self.pending[slot] = Some(Pending {
            id,
            wait,
            ticket,
            request: value,
            delivered: false,
            route,
            caller: caller.thread,
            callee: callee.thread,
        });
        self.proof.calls += 1;
        self.proof.blocks += 1;
        if self.profile == Profile::File {
            if self.routes[route].protocol == Protocol::Opaque {
                self.file.outer += 1;
            } else {
                self.file.backend += 1;
                if let Some(parent) = parent {
                    self.file.nested += 1;
                    if self
                        .pending
                        .iter()
                        .flatten()
                        .any(|p| p.id == parent.call_id && p.delivered)
                    {
                        self.file.delivered_nested += 1;
                    } else {
                        // An incoming reservation exists at acceptance. The
                        // actual callee may still be initializing before it
                        // receives that request; preserve ownership and audit
                        // that distinct causal state without assuming delivery.
                        self.file.before_delivery += 1;
                    }
                } else {
                    self.file.startup += 1;
                }
            }
            self.file.contexts += 1;
        }
        scalar(frame, 0, 0);
        true
    }
    fn receive(&mut self, rank: usize, endpoint: Handle, frame: &mut UserContext) {
        let receiver = self.actor(rank);
        let Some(route) = self
            .route(rank, endpoint, RECEIVE)
            .filter(|index| self.routes[*index].receiver == receiver)
        else {
            extended(frame, 1, 0, 0);
            return;
        };
        let Some(slot) = self.pending.iter().position(|entry| {
            entry.is_some_and(|p| p.route == route && p.callee == receiver.thread)
        }) else {
            extended(frame, 2, 0, 0);
            return;
        };
        let mut pending = self.pending[slot].unwrap();
        if pending.delivered {
            extended(frame, 11, 0, 0);
            return;
        }
        assert_eq!(self.rpc.serving(receiver.thread), Some(pending.id));
        assert!(self.s.waiting(pending.wait));
        match self.routes[route].mailbox.receive(
            self.a,
            receiver.domain,
            endpoint,
            crate::timer::now(),
        ) {
            Ok(delivery) => {
                assert_eq!((delivery.length, delivery.capability), (8, None));
                assert_eq!(delivery.ticket, pending.ticket);
                assert_eq!(&delivery.bytes[..8], &pending.request.to_le_bytes());
                pending.delivered = true;
                self.pending[slot] = Some(pending);
                extended(frame, 0, pending.request, pending.id.serial());
            }
            Err(IpcError::Empty) => extended(frame, 2, 0, 0),
            Err(_) => extended(frame, 1, 0, 0),
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
        let receiver = self.actor(rank);
        let Some(route) = self
            .route(rank, endpoint, RECEIVE)
            .filter(|index| self.routes[*index].receiver == receiver)
        else {
            extended(frame, 1, 0, 0);
            return;
        };
        let Some(slot) = self.pending.iter().position(|entry| {
            entry.is_some_and(|p| {
                p.route == route
                    && p.callee == receiver.thread
                    && p.delivered
                    && p.id.serial() == serial
            })
        }) else {
            extended(frame, 11, 0, 0);
            return;
        };
        let pending = self.pending[slot].unwrap();
        assert_eq!(self.rpc.serving(receiver.thread), Some(pending.id));
        let block = if self.routes[route].protocol == Protocol::Block {
            let Ok(response) = block::Response::decode(&value.to_le_bytes()) else {
                extended(frame, 3, 0, 0);
                return;
            };
            let request = block::Request::decode(&pending.request.to_le_bytes()).unwrap();
            if response != request.success() && !matches!(response, block::Response::Error { .. }) {
                extended(frame, 3, 0, 0);
                return;
            }
            Some((request, response))
        } else {
            None
        };
        assert!(self.s.waiting(pending.wait));
        self.guards();
        let completion = self
            .rpc
            .complete(receiver.thread, pending.id, crate::timer::now())
            .unwrap();
        assert_eq!(completion.caller, pending.caller);
        assert!(completion.deliver_reply && completion.wake_caller);
        if let Some((request, response)) = block
            && self.profile != Profile::Transport
        {
            if matches!(response, block::Response::Error { .. }) {
                self.store.errors += 1;
            } else {
                if self.profile == Profile::File && self.file.control.is_none() {
                    assert_eq!(request, block::Request::Read { sector: 2 });
                    self.file.control = Some(self.buffer());
                }
                if self.proof.replies == 0 && self.profile != Profile::File {
                    assert_eq!(request, block::Request::Read { sector: 2 });
                    if self.profile.is_generation() {
                        self.generation.control = Some(
                            generation::Control::decode(&self.buffer())
                                .expect("actual generation control"),
                        );
                    } else {
                        self.store.control =
                            Some(Control::decode(&self.buffer()).expect("actual disk control"));
                    }
                }
                if matches!(
                    request,
                    block::Request::Write { .. } | block::Request::Flush
                ) {
                    self.store.mutations = self.store.mutations.checked_add(1).unwrap();
                }
            }
        }
        let caller = self
            .actors
            .iter_mut()
            .find(|a| a.meta.thread == pending.caller)
            .expect("actual bound caller frame");
        scalar(&mut caller.context, 0, value);
        assert!(self.s.wake(pending.wait));
        assert!(!self.s.wake(pending.wait));
        self.pending[slot] = None;
        self.proof.replies += 1;
        self.proof.wakes += 1;
        self.progress.last_reply = crate::timer::now();
        extended(frame, 0, 0, 0);
    }
    fn syscall(
        &mut self,
        rank: usize,
        frame: &mut UserContext,
        hw: &Hardware,
        frames: &mut BootstrapFrames,
    ) -> bool {
        match decode(frame) {
            Ok(Call::Yield) => {
                if frame.registers[8] == FILE_SNAPSHOT_YIELD {
                    let valid = self.profile == Profile::File
                        && self.file.snapshots == 0
                        && self
                            .actors
                            .get(1)
                            .is_some_and(|actor| actor.meta.thread == self.actor(rank).thread)
                        && self.pending.iter().flatten().any(|p| {
                            p.callee == self.actor(rank).thread
                                && p.caller == self.actors[2].meta.thread
                                && p.delivered
                                && self.s.waiting(p.wait)
                                && self.routes[p.route].protocol == Protocol::Opaque
                        });
                    let Some((_, alias)) = self.application.filter(|_| valid) else {
                        scalar(frame, 1, 0);
                        return false;
                    };
                    for i in 0..256 {
                        // SAFETY: development-only adversarial hook after the
                        // measured server copied its request, while the actual
                        // sole app thread is blocked. Distinct backend page and
                        // guard bytes are never mutated by this experiment.
                        unsafe { alias.add(i).write_volatile(0x5a) };
                    }
                    self.file.snapshots += 1;
                    self.guards();
                    scalar(frame, 0, 0);
                    return false;
                }
                if frame.registers[8] == SNAPSHOT_YIELD {
                    let Some(pending) = self.pending.iter().flatten().find(|pending| {
                        rank == 0
                            && (self.profile != Profile::Transport
                                || cfg!(feature = "test-m3-pio-write"))
                            && pending.delivered
                            && self.s.waiting(pending.wait)
                            && pending.request.to_le_bytes()[3] == 2
                            && (self.profile != Profile::Transport || self.poisoned == 0)
                    }) else {
                        scalar(frame, 1, 0);
                        return false;
                    };
                    assert_eq!(
                        self.rpc.serving(self.actors[0].meta.thread),
                        Some(pending.id)
                    );
                    if self.profile != Profile::Transport {
                        scalar(frame, 0, 0);
                        return false;
                    }
                    let snapshot = self.buffer();
                    for (i, byte) in snapshot.into_iter().enumerate() {
                        assert_eq!(byte, (i as u8).wrapping_mul(29).wrapping_add(0xa7));
                        // SAFETY: fixture-only adversarial mutation while the
                        // actual one-thread client is blocked; source-built
                        // driver has copied its accepted private sector.
                        unsafe { self.alias.add(i).write_volatile(0x5a) };
                    }
                    self.guards();
                    self.poisoned += 1;
                }
                scalar(frame, 0, 0);
            }
            Ok(Call::Monotonic) => scalar(frame, 0, crate::timer::now()),
            Ok(Call::Inspect { capability, rights }) => {
                let domain = self.actor(rank).domain;
                let status = u64::from(
                    self.a
                        .authorize(domain, capability, Kind::Memory, rights)
                        .is_err(),
                );
                scalar(frame, status, 0);
            }
            Ok(Call::CreateProcess { job, image }) => {
                let domain = self.actor(rank).domain;
                match self
                    .lifecycle
                    .create(self.registry, self.a, self.s, domain, job, image)
                {
                    Ok(cap) => scalar(frame, 0, cap.0),
                    Err(status) => scalar(frame, status, 0),
                }
            }
            Ok(Call::Delegate {
                process,
                source,
                selector,
            }) => {
                let domain = self.actor(rank).domain;
                let status = u64::from(
                    self.registry
                        .delegate(self.a, domain, process, source, selector)
                        .is_err(),
                );
                scalar(frame, status, 0);
            }
            Ok(Call::Start(cap)) => {
                let domain = self.actor(rank).domain;
                // SAFETY: actual controller/allocator owner, exact held target
                // selected by CONTROL capability, and one retained vacant slot.
                let result = unsafe {
                    self.lifecycle.start(
                        self.registry,
                        self.a,
                        self.s,
                        self.rpc,
                        domain,
                        cap,
                        NonZeroU64::new(261).unwrap(),
                        hw,
                        frames,
                    )
                };
                scalar(frame, result.err().unwrap_or(0), 0);
            }
            Ok(Call::Observe(cap)) => {
                let domain = self.actor(rank).domain;
                match self.lifecycle.observe(
                    self.registry,
                    self.a,
                    self.s,
                    domain,
                    cap,
                    crate::timer::now(),
                ) {
                    Ok(done) => scalar(frame, 0, u64::from(done)),
                    Err(status) => scalar(frame, status, 0),
                }
            }
            Ok(Call::ObserveField { process, field }) => {
                let domain = self.actor(rank).domain;
                match self
                    .lifecycle
                    .field(self.registry, self.a, domain, process, field)
                {
                    Ok(value) => scalar(frame, 0, value),
                    Err(status) => scalar(frame, status, 0),
                }
            }
            Ok(Call::ProcessIdentity(cap)) => {
                let domain = self.actor(rank).domain;
                match self.lifecycle.identity(self.registry, self.a, domain, cap) {
                    Ok((process, thread)) => {
                        scalar(frame, 0, process);
                        frame.registers[11] = thread;
                    }
                    Err(status) => scalar(frame, status, 0),
                }
            }
            Ok(Call::StopProcess(cap)) => {
                let domain = self.actor(rank).domain;
                let result = self.lifecycle.stop(
                    self.registry,
                    self.a,
                    self.s,
                    self.rpc,
                    domain,
                    cap,
                    crate::timer::now(),
                );
                scalar(frame, result.err().unwrap_or(0), 0);
            }
            Ok(Call::Reap(cap)) => {
                let domain = self.actor(rank).domain;
                // SAFETY: actual stopped non-device image, selected by its live
                // control capability; retain unique backing until reap commits.
                let result = unsafe {
                    self.lifecycle.reap(
                        self.registry,
                        self.a,
                        self.s,
                        self.rpc,
                        domain,
                        cap,
                        frames,
                    )
                };
                scalar(frame, result.err().unwrap_or(0), 0);
            }
            Ok(Call::Close(cap)) => {
                let domain = self.actor(rank).domain;
                let status = u64::from(self.a.close(domain, cap).is_err());
                if status == 0 {
                    self.lifecycle
                        .collect_closed(self.registry, self.a, self.s)
                        .unwrap();
                }
                scalar(frame, status, 0);
            }
            Ok(Call::Send {
                endpoint,
                value,
                capability: None,
            }) => {
                let result = self.events.as_mut().ok_or(1u64).and_then(|events| {
                    events
                        .send(
                            EventCaller {
                                authority: self.a,
                                scheduler: self.s,
                                rpc: self.rpc,
                                cpu: 0,
                            },
                            endpoint,
                            value.to_le_bytes(),
                            Deadline::after(self.stop.tick(), 512).unwrap(),
                            crate::timer::now(),
                        )
                        .map_err(event_status)
                });
                scalar(frame, result.err().unwrap_or(0), 0);
            }
            Ok(Call::ReceiveEvent(endpoint)) => self.receive_event(endpoint, frame, true),
            Ok(Call::Receive(endpoint)) => self.receive_event(endpoint, frame, false),
            Ok(Call::RpcDeadline) => {
                match self
                    .rpc
                    .serving(self.actor(rank).thread)
                    .and_then(|id| self.rpc.context(id).ok())
                {
                    Some(context) => scalar(frame, 0, context.deadline.tick()),
                    None => scalar(frame, 1, 0),
                }
            }
            Ok(Call::Rpc {
                endpoint,
                value,
                deadline,
            }) => return self.call(rank, endpoint, value, deadline, frame),
            Ok(Call::ReceiveRpc(endpoint)) => self.receive(rank, endpoint, frame),
            Ok(Call::BindReceiver { endpoint, process }) => {
                let caller = self.actor(rank);
                let route = self
                    .route(rank, endpoint, RECEIVE)
                    .filter(|i| self.routes[*i].receiver == caller);
                let valid = process == Handle(0)
                    && route.is_some()
                    && self.s.state(caller.thread) == Ok(ev_kernel::scheduler::State::Running(0))
                    && self.s.thread_process(caller.thread) == Ok(caller.process)
                    && self.s.process_job(caller.process) == Ok(caller.job)
                    && self.a.is_live_space(caller.domain);
                let status = if valid {
                    u64::from(
                        self.rpc
                            .bind_endpoint(
                                self.a,
                                caller.domain,
                                endpoint,
                                caller.thread,
                                Policy::new(8, 0).unwrap(),
                            )
                            .is_err(),
                    )
                } else {
                    1
                };
                if status == 0 && self.profile == Profile::File {
                    self.file.bindings += 1;
                }
                scalar(frame, status, 0);
            }
            Ok(Call::ReplyRpc {
                endpoint,
                value,
                serial,
            }) => self.reply(rank, endpoint, value, serial, frame),
            Ok(Call::PortInput {
                capability,
                port,
                width,
            }) => {
                let caller = Caller {
                    authority: self.a,
                    scheduler: self.s,
                    rpc: self.rpc,
                    cpu: 0,
                };
                match self.ports.input(
                    caller,
                    Request {
                        capability,
                        port,
                        width,
                    },
                ) {
                    Ok(permit) => {
                        let object = permit.object();
                        let uart_data = Some(object) == self.uart_object && permit.port() == 0x3f8;
                        if uart_data
                            && self.generation.uart_rx.len == self.generation.uart_rx.bytes.len()
                        {
                            // Bounded diagnostic storage must refuse before
                            // consuming an unrecordable hardware byte. This
                            // inspects no command content or recovery policy.
                            extended(frame, 1, 0, 0);
                            return false;
                        }
                        // SAFETY: live exact object/range/width permit and IF0 owner.
                        let value = unsafe { crate::port_io::input(permit) };
                        if object == self.ata_object {
                            self.inputs += 1;
                        } else {
                            assert_eq!(Some(object), self.uart_object);
                            self.generation.uart_inputs += 1;
                            if uart_data {
                                if self.generation.uart_outputs == 0 {
                                    self.generation.uart_rx.before_tx += 1;
                                }
                                self.generation.uart_rx.bytes[self.generation.uart_rx.len] =
                                    u8::try_from(value).unwrap();
                                self.generation.uart_rx.len += 1;
                            }
                        }
                        extended(frame, 0, u64::from(value), 0);
                    }
                    Err(_) => {
                        if rank + 1 == self.actors.len() {
                            self.proof.authority_denied += 1;
                        }
                        extended(frame, 1, 0, 0);
                    }
                }
            }
            Ok(Call::PortOutput {
                capability,
                port,
                width,
                value,
            }) => {
                match self.ports.output(
                    Caller {
                        authority: self.a,
                        scheduler: self.s,
                        rpc: self.rpc,
                        cpu: 0,
                    },
                    Request {
                        capability,
                        port,
                        width,
                    },
                    value,
                ) {
                    Ok(permit) => {
                        let object = permit.object();
                        // SAFETY: live exact port/width/value permit, isolated ISA owner.
                        unsafe { crate::port_io::output(permit) };
                        if object == self.ata_object {
                            self.outputs += 1;
                        } else {
                            assert_eq!(Some(object), self.uart_object);
                            self.generation.uart_outputs += 1;
                        }
                        extended(frame, 0, 0, 0);
                    }
                    Err(_) => extended(frame, 1, 0, 0),
                }
            }
            Ok(Call::Exit(code)) => {
                if rank >= self.actors.len() {
                    self.s.exit(0).unwrap();
                    self.lifecycle
                        .stop_owned(self.a, self.s, self.rpc, crate::timer::now())
                        .unwrap();
                    return true;
                }
                let final_rank = if self.profile == Profile::File { 2 } else { 1 };
                assert_eq!((rank, code), (final_rank, 0), "transport actor failure");
                assert!(self.pending.iter().all(Option::is_none));
                assert_eq!(self.rpc.outstanding(), 0);
                if self.profile == Profile::File {
                    self.file.report = self.application_buffer();
                    assert!(self.file.report.is_some());
                } else if self.profile.is_generation() {
                    let control = self.generation.control.expect("actual generation control");
                    let report = generation::Completion::decode(&self.buffer())
                        .expect("actual generation completion");
                    assert_eq!(report.mode, control.mode);
                    assert_eq!(report.mutations, self.store.mutations);
                    self.generation.report = Some(report);
                } else if self.profile == Profile::Store {
                    let control = self
                        .store
                        .control
                        .expect("Store completion requires actual control read");
                    assert_ne!(
                        control.mode,
                        Mode::Cut,
                        "Cut must fault, never report successful Exit"
                    );
                    let event =
                        Completion::decode(&self.buffer()).expect("actual Store completion record");
                    assert_eq!(event.mode, control.mode);
                    assert_eq!(event.mutations, self.store.mutations);
                    let expected = if control.mode == Mode::Init {
                        (1, 0, 1)
                    } else {
                        (7, 1, 2)
                    };
                    assert_eq!((event.flags, event.operation, event.sequence), expected);
                    self.store.event = Some(event);
                }
                self.s.exit(0).unwrap();
                self.s
                    .terminate_process(self.actors[rank].meta.process)
                    .unwrap();
                self.done = true;
                return true;
            }
            _ => {
                if matches!(frame.registers[14], 33..=36) {
                    extended(frame, 1, 0, 0);
                } else {
                    scalar(frame, 1, 0);
                }
            }
        }
        false
    }
    unsafe fn run(&mut self, hw: &Hardware, frames: &mut BootstrapFrames) {
        self.progress.started = crate::timer::now();
        // SAFETY: exclusive initialized PIC owner, IF0, AP parked.
        unsafe { crate::timer::start_runtime() };
        for _ in 0..self.profile.transition_limit() {
            let now = crate::timer::now();
            if self.stop.reached(now) {
                self.stop_failed("dispatch", now, usize::MAX, 0);
            }
            assert!(self.rpc.expire(now).unwrap().is_empty());
            self.s.advance(now).unwrap();
            let dispatch = self
                .s
                .dispatch(0)
                .unwrap()
                .expect("transport runnable actor");
            let rank = self
                .actors
                .iter()
                .position(|a| a.meta.thread == dispatch.thread)
                .unwrap_or_else(|| {
                    assert_eq!(
                        self.lifecycle.metadata().map(|m| m.thread),
                        Some(dispatch.thread)
                    );
                    2
                });
            assert_eq!(dispatch.process, self.actor(rank).process);
            let running = if rank < self.actors.len() {
                self.actors[rank].running.as_ref().unwrap()
            } else {
                self.lifecycle.image().unwrap()
            };
            if rank < self.actors.len() && !(self.profile == Profile::File && rank == 2) {
                running
                    .image()
                    .loaded
                    .root
                    .validate_shared(self.a, self.object)
                    .unwrap();
            }
            #[cfg(feature = "test-m3-file")]
            if self.profile == Profile::File && rank != 0 {
                running
                    .image()
                    .loaded
                    .root
                    .validate_application(self.a, self.application.unwrap().0)
                    .unwrap();
            }
            if rank == 1
                && let Some(catalogue) = &self.catalogue
            {
                running
                    .image()
                    .loaded
                    .root
                    .validate_catalogue(self.a, catalogue.object)
                    .unwrap();
            }
            running.image().loaded.root.activate();
            let (context, fx) = if rank < self.actors.len() {
                let actor = &mut self.actors[rank];
                (&actor.context, &mut actor.fx)
            } else {
                (&self.lifecycle.context, &mut self.lifecycle.fx)
            };
            // SAFETY: actual admitted context/root/FX; capture restores the
            // retained controller CR3/IF0 before any metadata/ownership mutation.
            let (mut frame, address) =
                unsafe { crate::user_runtime::resume_context(context, fx, hw.original) };
            self.progress.traps[rank] += 1;
            self.progress.transitions += 1;
            self.progress.last_ip[rank] = frame.rip;
            if frame.vector == 128 {
                self.progress.syscalls[rank] += 1;
                self.progress.last_call[rank] = frame.registers[14];
            }
            let now = crate::timer::now();
            if self.stop.reached(now) {
                self.stop_failed("capture", now, rank, frame.vector);
            }
            let blocked = match frame.vector {
                32 => {
                    self.s.charge_cpu(0, 1).unwrap();
                    false
                }
                128 => self.syscall(rank, &mut frame, hw, frames),
                _ => {
                    if rank == 2 && self.profile.is_generation() {
                        self.lifecycle.fault(
                            self.a,
                            self.s,
                            self.rpc,
                            &frame,
                            address,
                            crate::timer::now(),
                        );
                        true
                    } else {
                        assert!(
                            self.profile == Profile::Store
                                && rank == 1
                                && frame.ordinary_user_fault(),
                            "block transport fault rank={rank} vector={} error={} address={address:#x} ip={:#x}",
                            frame.vector,
                            frame.error,
                            frame.rip
                        );
                        let control = self
                            .store
                            .control
                            .expect("cut requires actual control read");
                        assert_eq!(control.mode, Mode::Cut);
                        assert_eq!((frame.vector, frame.error), (6, 0));
                        assert_eq!(self.store.mutations, control.cut);
                        assert!(self.pending.iter().all(Option::is_none));
                        assert_eq!(self.rpc.outstanding(), 0);
                        assert_eq!(self.proof.calls, self.proof.replies);
                        let meta = self.actors[1].meta;
                        let record = Record {
                            process: meta.process.diagnostic_id(),
                            thread: meta.thread.diagnostic_id(),
                            vector: frame.vector,
                            error: frame.error,
                            address,
                            instruction: frame.rip,
                        };
                        assert_eq!(Record::decode(&record.encode()), Some(record));
                        self.store.fault = Some(record);
                        self.s.exit(0).unwrap();
                        self.s.terminate_process(meta.process).unwrap();
                        self.done = true;
                        true
                    }
                }
            };
            self.progress.max_pending =
                self.progress.max_pending.max(self.rpc.outstanding() as u64);
            if rank < self.actors.len() {
                self.actors[rank].context = frame;
            } else {
                self.lifecycle.context = frame;
            }
            if self.done {
                break;
            }
            if !blocked {
                self.s.yield_cpu(0).unwrap();
            }
        }
        // SAFETY: capture restored controller root/IF0; no users running.
        unsafe { crate::timer::stop_runtime() };
        assert!(self.done, "transport transition bound");
        if self.profile == Profile::Transport {
            let calls = if cfg!(feature = "test-m3-pio-write") {
                4
            } else {
                2
            };
            assert_eq!(
                (
                    self.proof.calls,
                    self.proof.blocks,
                    self.proof.wakes,
                    self.proof.replies
                ),
                (calls, calls, calls, calls)
            );
            assert_eq!(
                (
                    self.proof.short_deadline_denied,
                    self.proof.authority_denied,
                    self.proof.malformed
                ),
                (1, 1, 2)
            );
            assert_eq!(
                self.poisoned,
                u64::from(cfg!(feature = "test-m3-pio-write"))
            );
            for (i, byte) in self.buffer().iter().enumerate() {
                assert_eq!(*byte, (i as u8).wrapping_mul(29).wrapping_add(0xa7));
            }
            self.guards();
            self.proof.private_copy = true;
            self.proof.guards = true;
        } else if self.profile == Profile::Store {
            let control = self.store.control.expect("actual Store control");
            assert_eq!(self.store.fault.is_some(), control.mode == Mode::Cut);
            assert_eq!(self.store.event.is_some(), control.mode != Mode::Cut);
            self.store.client = Some((self.actors[1].meta.process, self.actors[1].meta.thread));
            let (process, thread) = self.store.client.unwrap();
            assert_eq!(self.s.thread_process(thread), Ok(process));
            assert_eq!(self.store.errors, 0);
            assert_eq!(
                (self.proof.calls, self.proof.blocks, self.proof.wakes),
                (self.proof.replies, self.proof.replies, self.proof.replies)
            );
            assert_eq!(
                (
                    self.proof.short_deadline_denied,
                    self.proof.authority_denied,
                    self.proof.malformed
                ),
                (0, 0, 0)
            );
            assert!(self.proof.calls > 0 && self.proof.calls <= 512);
            assert!(self.store.mutations <= 128);
            self.guards();
            self.proof.guards = true;
        } else if self.profile == Profile::File {
            assert_eq!((self.file.unbound_denied, self.file.bindings), (1, 2));
            assert!(self.file.outer > 0 && self.file.nested > 0);
            assert_eq!(self.file.contexts, self.proof.calls);
            assert_eq!(self.file.outer + self.file.backend, self.proof.calls);
            assert_eq!(self.file.startup + self.file.nested, self.file.backend);
            assert_eq!(
                self.file.before_delivery + self.file.delivered_nested,
                self.file.nested
            );
            assert!(self.file.delivered_nested > 0);
            assert_eq!(self.store.errors, 0);
            assert_eq!(
                self.routes
                    .iter()
                    .filter(|r| r.protocol == Protocol::Opaque)
                    .count(),
                2
            );
            assert_eq!(self.proof.calls, self.proof.replies);
            assert_eq!(self.progress.max_pending, 2);
            assert!(self.file.report.is_some());
            self.guards();
            self.proof.guards = true;
        } else {
            self.validate_generation();
            self.guards();
            self.proof.guards = true;
        }
    }
}

struct Hardware {
    offset: u64,
    bits: u8,
    original: u64,
}
fn shared_failure(error: SharedMapError) -> ! {
    match error {
        SharedMapError::Authority(cause) => panic!("shared authority: {cause:?}"),
        other => panic!("shared hardware ownership: {other:?}"),
    }
}
#[allow(clippy::too_many_arguments)]
unsafe fn load_actor<'a>(
    r: &mut Registry<'static>,
    a: &Authority,
    s: &mut Scheduler,
    custody: SpaceId,
    control: Handle,
    epoch: NonZeroU64,
    slot: &'a mut LoadedImage,
    object: &mut MemoryObject,
    shared: Handle,
    catalogue: Option<(&mut MemoryObject, Handle)>,
    hw: &Hardware,
    frames: &mut BootstrapFrames,
) -> Actor<'a> {
    let meta = r.metadata(a, custody, control).unwrap();
    let plan = r.plan(a, custody, control).unwrap();
    let startup = r.startup(a, custody, control, epoch).unwrap();
    assert!(
        !plan
            .pages()
            .any(|page| page.address == plan.base() + PREBOUND_SHARED_PAGE)
    );
    // SAFETY: exact measured held target and unique inactive controller slot.
    *slot = unsafe {
        LoadedImage::load_startup(
            hw.offset,
            hw.bits,
            hw.original & ADDRESS_MASK,
            &plan,
            Some(&startup),
            frames,
        )
    }
    .unwrap();
    let lease = object.map(a, meta.domain, shared, true).unwrap();
    let mut empty = LoadedImage::empty();
    // SAFETY: empty backing has no hardware. Rejection must retain this exact
    // live map claim, which is reused through the remaining preflight checks.
    let rejected = unsafe { empty.root.map_shared_inactive(a, object, lease) }
        .expect_err("empty root cannot consume a mapping lease");
    assert!(matches!(rejected.error, SharedMapError::Empty));
    let lease = rejected.lease;
    slot.root.activate();
    // SAFETY: held root inherits the retained kernel maps; the checked API must
    // refuse an active CR3 without changing the leaf or consuming ownership.
    let active_rejection = unsafe { slot.root.map_shared_inactive(a, object, lease) };
    // SAFETY: restore the actual retained controller CR3 before inspecting any
    // result, permitting further private-root mutation or returning an error.
    unsafe { asm!("mov cr3, {}",in(reg)hw.original,options(nostack,preserves_flags)) };
    let rejected = active_rejection.expect_err("active root must reject shared binding");
    assert!(matches!(rejected.error, SharedMapError::Active));
    let lease = rejected.lease;
    // SAFETY: held never-admitted root, exact installed role and retained frame.
    unsafe { slot.root.map_shared_inactive(a, object, lease) }
        .unwrap_or_else(|r| shared_failure(r.error));
    slot.root.validate_shared(a, object).unwrap();
    let duplicate = object.map(a, meta.domain, shared, true).unwrap();
    // SAFETY: inactive initialized root; occupied fixed page must reject before
    // touching the existing mapping, and return the additional claim intact.
    let rejected = unsafe { slot.root.map_shared_inactive(a, object, duplicate) }
        .expect_err("occupied prebound page must reject");
    assert!(matches!(rejected.error, SharedMapError::Unavailable));
    object.unmap(rejected.lease).unwrap();
    slot.root.validate_shared(a, object).unwrap();
    if let Some((catalogue, cap)) = catalogue {
        assert!(
            catalogue.map(a, meta.domain, cap, true).is_err(),
            "catalogue role has no WRITE authority"
        );
        let lease = catalogue.map(a, meta.domain, cap, false).unwrap();
        // SAFETY: held inactive image, separate initialized readonly object,
        // exact role8 capability and one remaining bounded shared-map slot.
        unsafe { slot.root.map_catalogue_inactive(a, catalogue, lease) }
            .unwrap_or_else(|r| shared_failure(r.error));
        slot.root.validate_catalogue(a, catalogue).unwrap();
    }
    let running = r
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
        .unwrap_or_else(|r| panic!("transport admission: {:?}", r.error));
    let context = running.initial_context().unwrap();
    Actor {
        running: Some(running),
        meta,
        control,
        context,
        fx: FxState::CLEAN,
    }
}

/// # Safety
/// Exclusive initialized BSP/controller/PIC/direct-map/frame owner, IF0, AP
/// parked. Dedicated QEMU ISA non-DMA channel; standalone disk proof completed.
#[inline(never)]
pub unsafe fn prove(offset: u64, frames: &mut BootstrapFrames) -> Proof {
    // SAFETY: forwards the exact serialized hardware owner to the common world.
    unsafe { run_world(offset, frames, Profile::Transport) }.0
}
/// # Safety
/// Same exclusive BSP/allocator/non-DMA conditions as prove. Control sector2
/// selects only the source-built Store experiment; no application authority.
#[cfg(feature = "test-m3-store")]
#[inline(never)]
pub unsafe fn prove_store(offset: u64, frames: &mut BootstrapFrames) -> StoreProof {
    // SAFETY: same actual retained hardware and table ownership.
    let (proof, store, _, _) = unsafe { run_world(offset, frames, Profile::Store) };
    let (process, thread) = store.client.expect("actual retained Store identity");
    StoreProof {
        control: store.control.unwrap(),
        event: store.event,
        fault: store.fault,
        calls: proof.calls,
        blocks: proof.blocks,
        wakes: proof.wakes,
        replies: proof.replies,
        mutations: store.mutations,
        client_process: process.diagnostic_id(),
        client_thread: thread.diagnostic_id(),
        frames: proof.frames,
        metadata: proof.metadata,
        guards: proof.guards,
    }
}
/// # Safety
/// Same serialized BSP/device/frame conditions as prove; execute only the
/// measured userspace catalogue/lifecycle experiment over this retained world.
#[cfg(all(feature = "test-m3-generation", not(feature = "test-m3-progress")))]
#[inline(never)]
pub unsafe fn prove_generation(offset: u64, frames: &mut BootstrapFrames) -> GenerationProof {
    // SAFETY: exact retained hardware and bounded table owners below.
    let (proof, store, generation, facts) =
        unsafe { run_world(offset, frames, Profile::Generation) };
    generation_proof(proof, store, generation, facts)
}
/// # Safety
/// Same retained hardware/allocator ownership as prove_generation; selected B
/// is the separately measured silent service, never a fabricated fault record.
#[cfg(feature = "test-m3-progress")]
#[inline(never)]
pub unsafe fn prove_progress(offset: u64, frames: &mut BootstrapFrames) -> GenerationProof {
    // SAFETY: same sole BSP/physical owner with exact measured progress assets.
    let (proof, store, generation, facts) = unsafe { run_world(offset, frames, Profile::Progress) };
    generation_proof(proof, store, generation, facts)
}
#[cfg(feature = "test-m3-owner")]
/// # Safety
/// Same retained BSP/device/frame ownership as prove_generation; UART access
/// additionally requires the exact registered owner-console capability.
#[inline(never)]
pub unsafe fn prove_owner(offset: u64, frames: &mut BootstrapFrames) -> OwnerProof {
    // SAFETY: same single controller/allocator owner and actual source artifacts.
    let (proof, store, generation, facts) = unsafe { run_world(offset, frames, Profile::Owner) };
    let uart_inputs = generation.uart_inputs;
    let uart_outputs = generation.uart_outputs;
    let uart_rx = generation.uart_rx.bytes;
    let uart_rx_len = generation.uart_rx.len;
    let uart_rx_before_tx = generation.uart_rx.before_tx;
    OwnerProof {
        generation: generation_proof(proof, store, generation, facts),
        uart_inputs,
        uart_outputs,
        uart_rx,
        uart_rx_len,
        uart_rx_before_tx,
        limit_ticks: Profile::Owner.ticks(),
        transition_limit: Profile::Owner.transition_limit(),
        parent_cpu_limit: Profile::Owner.parent_cpu(),
    }
}
#[cfg(feature = "test-m3-generation")]
fn generation_proof(
    proof: Proof,
    store: StoreState,
    generation: GenerationState,
    facts: lifecycle::Facts,
) -> GenerationProof {
    GenerationProof {
        report: generation.report.unwrap(),
        calls: proof.calls,
        blocks: proof.blocks,
        wakes: proof.wakes,
        replies: proof.replies,
        mutations: store.mutations,
        starts: facts.starts,
        ready: generation.ready,
        critical_ready: generation.critical_ready,
        faults: u64::from(facts.fault.is_some()),
        stops: facts.stops,
        reaps: facts.reaps,
        forged: generation.forged,
        elapsed_ticks: generation.accounting.elapsed_ticks,
        cpu_driver: generation.accounting.cpu_driver,
        cpu_client: generation.accounting.cpu_client,
        cpu_critical: generation.accounting.cpu_critical,
        cpu_parent: generation.accounting.cpu_parent,
        transitions: generation.accounting.transitions,
        max_pending: generation.accounting.max_pending,
        progress_start_tick: facts.first_live_observe.unwrap_or(0),
        progress_observed_tick: facts.last_live_observe.unwrap_or(0),
        progress_stop_tick: facts.stop_tick.unwrap_or(0),
        stopped_live: facts.stopped_live,
        catalogue_readonly: true,
        frames: proof.frames,
        metadata: proof.metadata,
        guards: proof.guards,
    }
}

#[inline(never)]
unsafe fn run_world(
    offset: u64,
    frames: &mut BootstrapFrames,
    profile: Profile,
) -> (Proof, StoreState, GenerationState, lifecycle::Facts) {
    assert_ne!(
        profile,
        Profile::File,
        "File has its own exact three-process resource constructor"
    );
    let limits = profile.limits();
    let before = frames.remaining_frames();
    let original: u64;
    // SAFETY: privileged retained root read before user execution.
    unsafe { asm!("mov {}, cr3",out(reg)original,options(nomem,nostack,preserves_flags)) };
    let hw = Hardware {
        offset,
        bits: (core::arch::x86_64::__cpuid(0x80000008).eax & 255) as u8,
        original,
    };
    let mut a = Authority::new();
    let custody = a.create_space().unwrap();
    let common = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE;
    let jobs = [
        a.create_root(custody, Kind::Job, common | Rights::READ | Rights::CONTROL)
            .unwrap(),
        a.create_root(custody, Kind::Job, common | Rights::READ | Rights::CONTROL)
            .unwrap(),
    ];
    let images = [
        a.create_root(custody, Kind::Memory, Rights::READ).unwrap(),
        a.create_root(custody, Kind::Memory, Rights::READ).unwrap(),
    ];
    let port_cap = a
        .create_root(
            custody,
            Kind::IoPorts,
            common | Rights::READ | Rights::WRITE | Rights::CONTROL,
        )
        .unwrap();
    let mut ports = Ports::new();
    ports.register(&a, custody, port_cap, &ATA).unwrap();
    let ata_object = a
        .authorize(custody, port_cap, Kind::IoPorts, Rights::CONTROL)
        .unwrap()
        .identity();
    let mut s = Scheduler::new();
    let parent = s
        .create_job_with_limits(Limits::new(
            profile.parent_cpu(),
            65,
            if profile.is_generation() { 3 } else { 2 },
            if profile.is_generation() { 3 } else { 2 },
        ))
        .unwrap();
    let actual_jobs = [
        s.create_child_job(parent, limits).unwrap(),
        s.create_child_job(parent, limits).unwrap(),
    ];
    let mut registry = Registry::with_service_limits(NonZeroU64::new(1).unwrap(), limits).unwrap();
    for i in 0..2 {
        registry
            .register_job(&a, custody, jobs[i], actual_jobs[i])
            .unwrap();
    }
    s.charge_frames(parent, 1).unwrap();
    let backing = frames.allocate().unwrap();
    let alias = direct_address(offset, backing.start(), hw.bits).unwrap() as *mut u8;
    for i in 0..FRAME_SIZE as usize {
        // SAFETY: sole initialized backing owner before any capability publishes it.
        unsafe { alias.add(i).write_volatile(0) };
    }
    let (mut object, shared_cap) = MemoryObject::new(&mut a, custody, backing).unwrap();
    let (endpoint_cap, mut mailbox) = registry.create_channel(&mut a, custody, jobs[0]).unwrap();
    let endpoint = a
        .authorize(custody, endpoint_cap, Kind::Endpoint, Rights::CONTROL)
        .unwrap()
        .identity();
    let driver_roles = [
        Role {
            selector: 1,
            kind: Kind::IoPorts,
            rights: Rights::from_bits(3).unwrap(),
        },
        Role {
            selector: 2,
            kind: Kind::Memory,
            rights: SHARED,
        },
        Role {
            selector: 3,
            kind: Kind::Endpoint,
            rights: RECEIVE,
        },
    ];
    // No extra resources exist in the already accepted two-process profiles.
    let mut generation_resources = if profile.is_generation() {
        // SAFETY: initialized immutable catalogue, retained frame/allocator and
        // exact external Job/image bindings; source is checked before mapping.
        Some(unsafe {
            generation_support::create(
                &mut a,
                &mut s,
                &mut registry,
                custody,
                parent,
                jobs[1],
                profile,
                &mut ports,
                &hw,
                frames,
            )
        })
    } else {
        None
    };
    let mut generation_roles = [
        Role {
            selector: 1,
            kind: Kind::Memory,
            rights: Rights::from_bits(231).unwrap(),
        },
        Role {
            selector: 2,
            kind: Kind::Endpoint,
            rights: Rights::SEND,
        },
        Role {
            selector: 3,
            kind: Kind::Job,
            rights: Rights::CONTROL,
        },
        Role {
            selector: 4,
            kind: Kind::Memory,
            rights: Rights::READ,
        },
        Role {
            selector: 5,
            kind: Kind::Memory,
            rights: Rights::READ,
        },
        Role {
            selector: 6,
            kind: Kind::Endpoint,
            rights: RECEIVE,
        },
        Role {
            selector: 7,
            kind: Kind::Endpoint,
            rights: Rights::from_bits(232).unwrap(),
        },
        Role {
            selector: 8,
            kind: Kind::Memory,
            rights: Rights::READ | Rights::MAP,
        },
    ];
    if profile == Profile::Owner {
        generation_roles[5].rights = Rights::from_bits(504).unwrap();
        generation_roles[6].kind = Kind::IoPorts;
        generation_roles[6].rights = Rights::READ | Rights::WRITE;
    }
    let client_roles = [
        Role {
            selector: 1,
            kind: Kind::Memory,
            rights: SHARED,
        },
        Role {
            selector: 2,
            kind: Kind::Endpoint,
            rights: Rights::SEND,
        },
    ];
    let client_roles: &[Role] = if profile.is_generation() {
        &generation_roles
    } else {
        &client_roles
    };
    let (client_image, client_sha) = if profile.is_generation() {
        generation_support::client(profile)
    } else if profile == Profile::Store {
        store_image()
    } else if cfg!(feature = "test-m3-pio-write") {
        (
            bundle::M3_BLOCK_CLIENT_WRITE_IMAGE,
            bundle::M3_BLOCK_CLIENT_WRITE_SHA,
        )
    } else {
        (
            bundle::M3_BLOCK_CLIENT_VERIFY_IMAGE,
            bundle::M3_BLOCK_CLIENT_VERIFY_SHA,
        )
    };
    registry
        .register_image(
            &a,
            custody,
            images[0],
            ServiceImage::verify(
                bundle::M3_BLOCK_DRIVER_IMAGE,
                bundle::M3_BLOCK_DRIVER_SHA,
                limits,
                &driver_roles,
            )
            .unwrap(),
        )
        .unwrap();
    registry
        .register_image(
            &a,
            custody,
            images[1],
            ServiceImage::verify(client_image, client_sha, limits, client_roles).unwrap(),
        )
        .unwrap();
    let controls = [
        registry
            .create_process(&mut a, &mut s, custody, jobs[0], images[0])
            .unwrap(),
        registry
            .create_process(&mut a, &mut s, custody, jobs[1], images[1])
            .unwrap(),
    ];
    for (source, selector) in [(port_cap, 1), (shared_cap, 2), (endpoint_cap, 3)] {
        registry
            .delegate(&mut a, custody, controls[0], source, selector)
            .unwrap();
    }
    for (source, selector) in [(shared_cap, 1), (endpoint_cap, 2)] {
        registry
            .delegate(&mut a, custody, controls[1], source, selector)
            .unwrap();
    }
    if let Some(resources) = &generation_resources {
        for (source, selector) in [
            (resources.job_cap, 3),
            (resources.images[0], 4),
            (resources.images[1], 5),
            (resources.event_cap, 6),
            (resources.uart_cap.unwrap_or(resources.event_cap), 7),
            (resources.cap, 8),
        ] {
            registry
                .delegate(&mut a, custody, controls[1], source, selector)
                .unwrap();
        }
    }
    if let Some(resources) = &mut generation_resources {
        let receive = registry.grant(&a, custody, controls[1], 6).unwrap();
        let destination = registry.metadata(&a, custody, controls[1]).unwrap().domain;
        resources
            .events
            .rebind_empty(&a, custody, resources.event_cap, destination, receive)
            .unwrap();
    }
    let shared_grants = [
        registry.grant(&a, custody, controls[0], 2).unwrap(),
        registry.grant(&a, custody, controls[1], 1).unwrap(),
    ];
    let receive = registry.grant(&a, custody, controls[0], 3).unwrap();
    let driver_domain = registry.metadata(&a, custody, controls[0]).unwrap().domain;
    mailbox
        .rebind_empty(&a, custody, endpoint_cap, driver_domain, receive)
        .unwrap();
    // Image plans belong to held preparation; validate the declared stack
    // before either actual process is admitted or any image lease is moved.
    if profile != Profile::Transport {
        verify_store_stack(&registry.plan(&a, custody, controls[1]).unwrap());
    }
    if let Some(resources) = &generation_resources {
        let total = registry.metadata(&a, custody, controls[0]).unwrap().frames
            + registry.metadata(&a, custody, controls[1]).unwrap().frames
            + resources.max_frames
            + 2;
        assert!(total <= s.job_limits(parent).unwrap().limit(Resource::Frames));
    }
    let mut driver_slot = LoadedImage::empty();
    let mut client_slot = LoadedImage::empty();
    let epoch = NonZeroU64::new(261).unwrap();
    // SAFETY: exact held targets and distinct initialized inactive roots.
    let driver = unsafe {
        load_actor(
            &mut registry,
            &a,
            &mut s,
            custody,
            controls[0],
            epoch,
            &mut driver_slot,
            &mut object,
            shared_grants[0],
            None,
            &hw,
            frames,
        )
    };
    let catalogue_grant = generation_resources
        .as_ref()
        .map(|_| registry.grant(&a, custody, controls[1], 8).unwrap());
    // SAFETY: same ownership, disjoint image slot and second exact map lease.
    let client = unsafe {
        load_actor(
            &mut registry,
            &a,
            &mut s,
            custody,
            controls[1],
            epoch,
            &mut client_slot,
            &mut object,
            shared_grants[1],
            generation_resources
                .as_mut()
                .zip(catalogue_grant)
                .map(|(resources, grant)| (&mut resources.object, grant)),
            &hw,
            frames,
        )
    };
    let mut actors = [driver, client];
    let stop = Deadline::after(crate::timer::now(), profile.ticks()).unwrap();
    actors[1].context.registers[11] = stop.tick(); // Informational fixture metadata, not authority.
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
        assert_eq!(
            s.job_limits(actor.meta.job)
                .unwrap()
                .limit(Resource::Threads),
            1
        );
    }
    rpc.bind_endpoint(
        &a,
        actors[0].meta.domain,
        receive,
        actors[0].meta.thread,
        Policy::new(8, 0).unwrap(),
    )
    .unwrap();
    let mut critical_slot = LoadedImage::empty();
    let mut lifecycle = lifecycle::Lifecycle::new(&mut critical_slot);
    let critical_job = generation_resources.as_ref().map(|resources| resources.job);
    let uart_object = generation_resources
        .as_ref()
        .and_then(|resources| resources.uart_object);
    let (catalogue, event_channel) = match &mut generation_resources {
        Some(resources) => (
            Some(CatalogueView {
                object: &resources.object,
                data: resources.catalogue,
                digest: resources.digest,
                images: resources.image_objects,
            }),
            Some(&mut resources.events),
        ),
        None => (None, None),
    };
    let mut routes = [Route {
        object: endpoint,
        receiver: actors[0].meta,
        protocol: Protocol::Block,
        mailbox: &mut mailbox,
    }];
    let mut runtime = Runtime {
        a: &mut a,
        s: &mut s,
        rpc: &mut rpc,
        ports: &ports,
        ata_object,
        uart_object,
        object: &object,
        actors: &mut actors,
        routes: &mut routes,
        alias,
        stop,
        pending: [None; 2],
        poisoned: 0,
        inputs: 0,
        outputs: 0,
        done: false,
        proof: Proof::default(),
        profile,
        store: StoreState::default(),
        registry: &mut registry,
        lifecycle: &mut lifecycle,
        events: event_channel,
        catalogue,
        generation: GenerationState::default(),
        progress: Progress::default(),
        application: None,
        file: FileState::default(),
    };
    // SAFETY: exact retained hardware and serialized table owners through stop.
    unsafe { runtime.run(&hw, frames) };
    if let Some(critical_job) = critical_job {
        // Capture cumulative Job charges before graph/domain/frame teardown.
        // Only captured IRQ0 advances this clock during the runtime, and each
        // such capture charges one actual actor and its retained parent.
        let accounting = Accounting {
            elapsed_ticks: crate::timer::now()
                .checked_sub(runtime.progress.started)
                .unwrap(),
            cpu_driver: runtime.s.usage(actual_jobs[0], Resource::CpuTicks).unwrap(),
            cpu_client: runtime.s.usage(actual_jobs[1], Resource::CpuTicks).unwrap(),
            cpu_critical: runtime.s.usage(critical_job, Resource::CpuTicks).unwrap(),
            cpu_parent: runtime.s.usage(parent, Resource::CpuTicks).unwrap(),
            transitions: runtime.progress.transitions,
            max_pending: runtime.progress.max_pending,
        };
        assert_eq!(
            accounting.cpu_driver + accounting.cpu_client + accounting.cpu_critical,
            accounting.cpu_parent
        );
        assert_eq!(accounting.elapsed_ticks, accounting.cpu_parent);
        assert!(accounting.elapsed_ticks < profile.ticks());
        for cpu in [
            accounting.cpu_driver,
            accounting.cpu_client,
            accounting.cpu_critical,
        ] {
            assert!(cpu <= limits.limit(Resource::CpuTicks));
        }
        assert!(accounting.cpu_parent <= profile.parent_cpu());
        assert!(accounting.transitions > 0 && accounting.transitions <= profile.transition_limit());
        assert_eq!(accounting.max_pending, 1);
        runtime.generation.accounting = accounting;
    }
    let Runtime {
        mut proof,
        store,
        generation,
        ..
    } = runtime;
    let facts = core::mem::take(&mut lifecycle.facts);
    proof.mapped = 2;
    for actor in &mut actors {
        actor
            .running
            .as_mut()
            .unwrap()
            .stop(&mut a, &mut s)
            .unwrap();
        s.terminate_process(actor.meta.process).unwrap();
    }
    for actor in &actors {
        assert!(
            rpc.peer_died(&s, actor.meta.thread, crate::timer::now())
                .unwrap()
                .is_empty()
        );
    }
    mailbox.receiver_died(driver_domain).unwrap();
    assert_eq!(mailbox.pending(), 0);
    let actors_generation_domain = actors[1].meta.domain;
    for actor in &mut actors {
        let ProcessImage { loaded, .. } = actor
            .running
            .take()
            .unwrap()
            .finish(&s)
            .unwrap_or_else(|_| panic!("transport retained owner"));
        if actor.meta.domain == actors_generation_domain
            && let Some(resources) = &mut generation_resources
        {
            // SAFETY: actual stopped client returned its unique image lease;
            // readonly catalogue has no other process mapping or writable alias.
            unsafe { loaded.root.unmap_catalogue_inactive(&mut resources.object) }.unwrap();
        }
        // SAFETY: both processes stopped; actual controller CR3 restored and no
        // active leases remain in a Running owner. Return each shared claim first.
        unsafe { loaded.root.unmap_shared_inactive(&mut object) }.unwrap();
        // SAFETY: the same stopped root now has no mapping; refusal must not
        // invent a second returned lease or release the shared physical owner.
        let repeated = unsafe { loaded.root.unmap_shared_inactive(&mut object) };
        assert!(matches!(repeated, Err(SharedMapError::Missing)));
        // SAFETY: private frames no longer have shared mappings, CPUs, RPC or DMA aliases.
        let reclaimed = unsafe { loaded.root.retire_in_place(frames) };
        assert_eq!(reclaimed as u64, actor.meta.frames);
        s.release_frames(actor.meta.job, actor.meta.frames).unwrap();
        registry
            .retire_stopped(&mut a, &s, actor.meta.process)
            .unwrap();
        a.close(custody, actor.control).unwrap();
        registry
            .forget_retired(&mut a, &s, actor.meta.process)
            .unwrap();
        rpc.forget_thread(&s, actor.meta.thread).unwrap();
        s.reclaim_process(actor.meta.process).unwrap();
    }
    assert_eq!(
        s.usage(parent, Resource::Frames),
        Ok(if generation_resources.is_some() { 2 } else { 1 })
    );
    let backing = object.destroy(&mut a, custody, shared_cap).unwrap();
    for i in 0..FRAME_SIZE as usize {
        // SAFETY: both mapping leases returned; sole physical frame owner.
        unsafe { alias.add(i).write_volatile(0) };
    }
    for i in 0..FRAME_SIZE as usize {
        // SAFETY: retained frame until readback completes before allocator handoff.
        assert_eq!(unsafe { alias.add(i).read_volatile() }, 0);
    }
    frames.reclaim(backing).unwrap();
    s.release_frames(parent, 1).unwrap();
    a.close(custody, shared_cap).unwrap();
    a.close(custody, endpoint_cap).unwrap();
    let _receipt = mailbox
        .retire_managed(&mut a)
        .unwrap_or_else(|r| panic!("channel retirement: {:?}", r.error));
    if let Some(mut resources) = generation_resources {
        let frame = resources
            .object
            .destroy(&mut a, custody, resources.cap)
            .unwrap();
        for i in 0..FRAME_SIZE as usize {
            // SAFETY: catalogue lease returned, sole initialized physical owner.
            unsafe { resources.alias.add(i).write_volatile(0) };
        }
        for i in 0..FRAME_SIZE as usize {
            // SAFETY: retained until scrub/readback completes before reclaim.
            let byte = unsafe { resources.alias.add(i).read_volatile() };
            assert_eq!(byte, 0);
        }
        frames.reclaim(frame).unwrap();
        s.release_frames(parent, 1).unwrap();
        a.close(custody, resources.cap).unwrap();
        resources
            .events
            .receiver_died(actors_generation_domain)
            .unwrap();
        resources
            .events
            .discard_dead_senders(&mut a, crate::timer::now())
            .unwrap();
        assert_eq!(resources.events.metadata_usage(), (0, 0));
        a.close(custody, resources.event_cap).unwrap();
        let mailbox = resources
            .events
            .into_empty()
            .unwrap_or_else(|_| panic!("event provenance still retained"));
        let _receipt = mailbox
            .retire_managed(&mut a)
            .unwrap_or_else(|r| panic!("event retirement: {:?}", r.error));
        if let Some(uart) = resources.uart_cap {
            ports.retire(&mut a, custody, uart).unwrap();
        }
        registry
            .forget_job(&mut a, &mut s, &rpc, resources.job)
            .unwrap();
    }
    ports.retire(&mut a, custody, port_cap).unwrap();
    for job in actual_jobs {
        registry.forget_job(&mut a, &mut s, &rpc, job).unwrap();
    }
    s.reclaim_job(parent).unwrap();
    a.collect_lineage().unwrap();
    a.collect_dead_objects().unwrap();
    assert_eq!(
        a.metadata_usage(),
        if profile.is_generation() {
            (1, 7, 7, 7)
        } else {
            (1, 4, 4, 4)
        }
    );
    assert_eq!(
        registry.metadata_usage(),
        if profile.is_generation() {
            (0, 4, 0, if facts.starts > 0 { 6 } else { 4 })
        } else {
            (0, 2, 0, 4)
        }
    );
    assert_eq!(rpc.metadata_usage(), (0, 0, 0));
    assert_eq!(s.metadata_usage(), (0, 0, 0));
    assert_eq!(ports.registered(), 0);
    assert_eq!(frames.remaining_frames(), before);
    proof.frames = true;
    proof.metadata = true;
    (proof, store, generation, facts)
}

#[cfg(feature = "test-m3-store")]
fn store_image() -> (&'static [u8], [u8; 32]) {
    (bundle::M3_STORE_CLIENT_IMAGE, bundle::M3_STORE_CLIENT_SHA)
}
#[cfg(not(feature = "test-m3-store"))]
fn store_image() -> (&'static [u8], [u8; 32]) {
    panic!("Store profile was not compiled")
}
fn verify_store_stack(plan: &ev_kernel::executable::Image<'_>) {
    let base = plan.base();
    for relative in (0x100000..0x104000).step_by(FRAME_SIZE as usize) {
        let page = plan
            .pages()
            .find(|p| p.address == base + relative)
            .expect("declared Store stack page");
        assert_eq!(page.permission, UserPermission::ReadWrite);
        let mut bytes = [0u8; FRAME_SIZE as usize];
        page.copy_into(&mut bytes);
        assert!(bytes.iter().all(|b| *b == 0));
    }
    for relative in [0xff000, 0x104000] {
        assert!(
            !plan.pages().any(|p| p.address == base + relative),
            "Store stack guard"
        );
    }
}
