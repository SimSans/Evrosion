//! Actual whole-graph Root replacement and independent recovery execution.
//! Serialized BSP development integration; production generation trust is separate.
use crate::{
    executable_runtime::{LoadedImage, ProcessImage},
    service_runtime::{Channel, PendingCall, RpcProof, expire},
    supervisor_runtime::bundle,
};
use core::{arch::asm, num::NonZeroU64};
use ev_kernel::{
    bootstrap_binding::CatalogEntry,
    bootstrap_manifest,
    capability::{Authority, Handle, Kind, Rights, SpaceId},
    custodian::{Custodian, QuiescentIncarnation},
    fault::Record,
    incarnation::{Active, Bindings, Target, Token},
    ipc::{Error as IpcError, MAX_MESSAGES, Mailbox, Outgoing, Reclaimed, RetiredMailbox, Ticket},
    mapping::ADDRESS_MASK,
    memory::BootstrapFrames,
    rpc::{CallId, Error as RpcError, MessageShape, Policy, Rpc},
    scheduler::{Dispatch, JobId, Limits, Resource, Scheduler, ThreadId, WaitTicket},
    service::{Metadata, Registry, Role, Running, SERVICE_LIMITS, ServiceImage},
    time::Deadline,
    user_context::{Call, FxState, UserContext, decode},
};
use ev_userspace_contract::{ABI, Event};

/// Captured termination evidence. Exit/watchdog have their own truthful shape;
/// neither is represented by an invented processor fault vector or address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootFailure {
    Integrity(IntegrityReason),
    Fault(Record),
    FatalExit {
        process: ev_kernel::scheduler::ProcessId,
        thread: ThreadId,
        code: u64,
        instruction: u64,
    },
    Watchdog {
        process: ev_kernel::scheduler::ProcessId,
        thread: ThreadId,
        deadline: u64,
        observed: u64,
        instruction: u64,
        dispatches: u64,
        cpu_ticks: u64,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionCase {
    CorruptManifest,
    CorruptImage,
    WrongAuthority,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegrityReason {
    Manifest(bootstrap_manifest::Error),
    Image(bootstrap_manifest::Error),
    Authority(ev_kernel::custodian::Recovery),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interruption {
    Admission,
    HeldTarget,
    GrantPreparation,
    ImageLoad,
    Activation,
    Confirmation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fixture {
    Nominal,
    FatalExit,
    Watchdog,
    Interrupted(Interruption),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NegativeCase {
    FatalExit,
    Watchdog,
    Interrupted(Interruption),
    Selection(SelectionCase),
}
pub const NEGATIVE_CASES: [NegativeCase; 11] = [
    NegativeCase::FatalExit,
    NegativeCase::Watchdog,
    NegativeCase::Interrupted(Interruption::Admission),
    NegativeCase::Interrupted(Interruption::HeldTarget),
    NegativeCase::Interrupted(Interruption::GrantPreparation),
    NegativeCase::Interrupted(Interruption::ImageLoad),
    NegativeCase::Interrupted(Interruption::Activation),
    NegativeCase::Interrupted(Interruption::Confirmation),
    NegativeCase::Selection(SelectionCase::CorruptManifest),
    NegativeCase::Selection(SelectionCase::CorruptImage),
    NegativeCase::Selection(SelectionCase::WrongAuthority),
];
#[derive(Default)]
pub struct NegativeProof {
    pub integrity_failures: u64,
    pub integrity_reason: Option<IntegrityReason>,
    pub held_targets: u64,
    pub refused_before_dispatch: bool,
    pub no_speculative_grants: bool,
    pub fault_records: u64,
    pub fatal_exits: u64,
    pub watchdogs: u64,
    pub interrupted: u64,
    pub attempts: u64,
    pub restart_charges: u64,
    pub active_incarnations: u64,
    pub execution_admissions: u64,
    pub graphs: u64,
    pub service_starts: u64,
    pub service_replies: u64,
    pub accepted_transfers: u64,
    pub rejected_transfers: u64,
    pub invalidated_transfers: u64,
    pub recovery_entries: u64,
    pub last_failure: Option<RootFailure>,
    pub interrupted_at: Option<Interruption>,
    pub interrupted_attempt: Option<u64>,
    pub failed_token: Option<Token>,
    pub recovery_reason: Option<ev_kernel::custodian::Recovery>,
    pub no_duplicate: bool,
    pub budget_charged: bool,
    pub retired: bool,
    pub frames_balanced: bool,
}
struct FixtureResult {
    nominal: Proof,
    negative: NegativeProof,
}
#[derive(Default)]
pub struct NegativeSuiteProof {
    pub cases: u64,
    pub fault_records: u64,
    pub fatal_exits: u64,
    pub watchdogs: u64,
    pub interrupted: u64,
    pub integrity_failures: u64,
    pub attempts: u64,
    pub restart_charges: u64,
    pub held_targets: u64,
    pub execution_admissions: u64,
    pub active_incarnations: u64,
    pub graphs: u64,
    pub service_starts: u64,
    pub service_replies: u64,
    pub accepted_transfers: u64,
    pub rejected_transfers: u64,
    pub invalidated_transfers: u64,
    pub recovery_entries: u64,
    pub retired: bool,
    pub frames_balanced: bool,
    pub no_duplicate: bool,
    pub budget_charged: bool,
    pub selection_refused: bool,
    pub no_speculative_grants: bool,
    pub results: [NegativeProof; 11],
}

/// # Safety
/// Same exclusive controller/allocator ownership as prove(). The eleven explicit
/// development worlds retire completely between cases; a failed custodian is
/// never reset/replaced inside a case to escape its retained budget or failure.
#[inline(never)] // Retain only suite results here; each large fixture has its own lifetime.
pub unsafe fn prove_negatives(offset: u64, frames: &mut BootstrapFrames) -> NegativeSuiteProof {
    let mut suite = NegativeSuiteProof::default();
    for (index, case) in NEGATIVE_CASES.into_iter().enumerate() {
        // SAFETY: prior case returned every actual image frame and stopped all
        // contexts before the next explicit isolated fixture is constructed.
        let result = unsafe { prove_case(offset, frames, case) };
        assert_eq!(result.recovery_entries, 1);
        match case {
            NegativeCase::Selection(selection) => {
                let expected = match selection {
                    SelectionCase::CorruptManifest => {
                        IntegrityReason::Manifest(bootstrap_manifest::Error::ManifestDigest)
                    }
                    SelectionCase::CorruptImage => {
                        IntegrityReason::Image(bootstrap_manifest::Error::ImageDigest)
                    }
                    SelectionCase::WrongAuthority => {
                        IntegrityReason::Authority(ev_kernel::custodian::Recovery::Preparation(
                            ev_kernel::incarnation::Error::Binding(
                                ev_kernel::bootstrap_binding::Error::AuthorityDigest,
                            ),
                        ))
                    }
                };
                assert_eq!(result.integrity_reason, Some(expected));
                assert_eq!(result.last_failure, Some(RootFailure::Integrity(expected)));
                assert_eq!(result.failed_token, None);
            }
            NegativeCase::FatalExit | NegativeCase::Watchdog | NegativeCase::Interrupted(_) => {
                let token = result.failed_token.unwrap();
                assert_eq!(
                    result.recovery_reason,
                    Some(ev_kernel::custodian::Recovery::Restart(
                        ev_kernel::restart::RecoveryRequired::BudgetExhausted
                    ))
                );
                match (case, result.last_failure.unwrap()) {
                    (NegativeCase::FatalExit, RootFailure::FatalExit { process, code, .. }) => {
                        assert_eq!(process, token.process());
                        assert_eq!((token.number(), code), (4, 0x4355_5354_4f44_5902));
                    }
                    (
                        NegativeCase::Watchdog,
                        RootFailure::Watchdog {
                            process,
                            deadline,
                            observed,
                            ..
                        },
                    ) => {
                        assert_eq!(process, token.process());
                        assert_eq!(token.number(), 4);
                        assert!(observed >= deadline);
                    }
                    (NegativeCase::Interrupted(stage), RootFailure::Fault(record)) => {
                        assert_eq!(record.process, token.process().diagnostic_id());
                        assert_eq!(
                            (token.number(), record.vector, record.error, record.address),
                            (1, 14, 6, 0)
                        );
                        assert_eq!(result.interrupted_at, Some(stage));
                        assert_eq!(result.interrupted_attempt, Some(2));
                    }
                    _ => panic!("actual failure does not match explicit negative fixture"),
                }
            }
        }
        suite.cases += 1;
        suite.fault_records += result.fault_records;
        suite.fatal_exits += result.fatal_exits;
        suite.watchdogs += result.watchdogs;
        suite.interrupted += result.interrupted;
        suite.integrity_failures += result.integrity_failures;
        suite.attempts += result.attempts;
        suite.restart_charges += result.restart_charges;
        suite.held_targets += result.held_targets;
        suite.execution_admissions += result.execution_admissions;
        suite.active_incarnations += result.active_incarnations;
        suite.graphs += result.graphs;
        suite.service_starts += result.service_starts;
        suite.service_replies += result.service_replies;
        suite.accepted_transfers += result.accepted_transfers;
        suite.rejected_transfers += result.rejected_transfers;
        suite.invalidated_transfers += result.invalidated_transfers;
        suite.recovery_entries += result.recovery_entries;
        suite.results[index] = result;
    }
    assert_eq!(
        (
            suite.cases,
            suite.fault_records,
            suite.fatal_exits,
            suite.watchdogs,
            suite.interrupted,
            suite.integrity_failures
        ),
        (11, 6, 4, 4, 6, 3)
    );
    assert_eq!(
        (
            suite.attempts,
            suite.restart_charges,
            suite.held_targets,
            suite.execution_admissions,
            suite.active_incarnations
        ),
        (33, 24, 20, 16, 15)
    );
    assert_eq!(
        (suite.graphs, suite.service_starts, suite.service_replies),
        (14, 28, 28)
    );
    assert_eq!(
        (
            suite.accepted_transfers,
            suite.rejected_transfers,
            suite.invalidated_transfers,
            suite.recovery_entries
        ),
        (14, 14, 14, 11)
    );
    suite.retired = suite.results.iter().all(|result| result.retired);
    suite.frames_balanced = suite.results.iter().all(|result| result.frames_balanced);
    suite.no_duplicate = suite.results.iter().all(|result| result.no_duplicate);
    suite.budget_charged = suite.results[..8]
        .iter()
        .all(|result| result.budget_charged);
    suite.selection_refused = suite.results[8..]
        .iter()
        .all(|result| result.refused_before_dispatch);
    suite.no_speculative_grants = suite.results[8..]
        .iter()
        .all(|result| result.no_speculative_grants);
    assert!(
        suite.retired
            && suite.frames_balanced
            && suite.no_duplicate
            && suite.budget_charged
            && suite.selection_refused
            && suite.no_speculative_grants
    );
    suite
}
/// # Safety
/// Same retained controller/trap/allocator conditions as prove_negatives().
#[inline(never)] // Never inline selection-world State storage into the retained suite frame.
pub unsafe fn prove_case(
    offset: u64,
    frames: &mut BootstrapFrames,
    case: NegativeCase,
) -> NegativeProof {
    // SAFETY: every branch forwards the same exclusive hardware preconditions.
    unsafe {
        match case {
            NegativeCase::FatalExit => prove_negative(offset, frames, Fixture::FatalExit),
            NegativeCase::Watchdog => prove_negative(offset, frames, Fixture::Watchdog),
            NegativeCase::Interrupted(stage) => {
                prove_negative(offset, frames, Fixture::Interrupted(stage))
            }
            NegativeCase::Selection(selection) => prove_selection(offset, frames, selection),
        }
    }
}
/// Development fixture liveness contract: after the graph-complete event, Root
/// must make progress within eight independent timer ticks. Actual Root IRQ0
/// capture plus increased scheduler dispatch/CPU counters confirms opportunity
/// to run; a blocked or never-dispatched process cannot manufacture this report.
struct Watchdog {
    deadline: Option<Deadline>,
    dispatches: u64,
    cpu_ticks: u64,
}
impl Watchdog {
    fn new() -> Self {
        Self {
            deadline: None,
            dispatches: 0,
            cpu_ticks: 0,
        }
    }
    fn arm(&mut self, now: u64, scheduler: &Scheduler, job: JobId) {
        self.deadline = Some(Deadline::after(now, 8).unwrap());
        self.dispatches = scheduler.dispatches(job).unwrap();
        self.cpu_ticks = scheduler.usage(job, Resource::CpuTicks).unwrap();
    }
}

#[derive(Default)]
pub struct Proof {
    pub incarnations: u64,
    pub replacements: u64,
    pub root_faults: u64,
    pub graphs: u64,
    pub service_starts: u64,
    pub service_replies: u64,
    pub accepted_transfers: u64,
    pub rejected_transfers: u64,
    pub invalidated_transfers: u64,
    pub recovery_entries: u64,
    pub stale: u64,
    pub frames_balanced: bool,
    pub metadata_balanced: bool,
    pub unique_active: bool,
    pub budget_latched: bool,
    pub authority_equal: bool,
    pub graph_retired: bool,
    pub recovery_independent: bool,
    pub last_fault: Option<Record>,
    pub failed_token: Option<Token>,
    pub recovery_reason: Option<ev_kernel::custodian::Recovery>,
}
type Snapshot = (
    (usize, usize, usize, usize),
    (usize, usize, usize),
    (usize, usize, usize, usize),
    (usize, usize, usize),
    u64,
);
struct Hardware<'a> {
    offset: u64,
    bits: u8,
    original: u64,
    frames: &'a mut BootstrapFrames,
}
enum RecoveryDomains {
    Fresh,
    Reuse {
        branches: SpaceId,
        destination: SpaceId,
    },
}
impl From<Target> for RecoveryDomains {
    fn from(target: Target) -> Self {
        Self::Reuse {
            branches: target.branches,
            destination: target.destination,
        }
    }
}
fn root_catalog(roots: [Handle; 6]) -> [CatalogEntry; 4] {
    let kinds = [Kind::Memory, Kind::Endpoint, Kind::Job, Kind::Memory];
    core::array::from_fn(|i| CatalogEntry {
        selector: i as u64 + 1,
        root: roots[i],
        kind: kinds[i],
    })
}
fn recovery_catalog(roots: [Handle; 6]) -> [CatalogEntry; 2] {
    [
        CatalogEntry {
            selector: 1,
            root: roots[4],
            kind: Kind::Memory,
        },
        CatalogEntry {
            selector: 2,
            root: roots[5],
            kind: Kind::Endpoint,
        },
    ]
}
// Keep initialization temporaries separate from execution. The four uniquely
// owned tables stay in their world; this helper returns only small dependent
// mailbox/domain metadata and exclusive borrows, never a second table aggregate.
#[inline(never)]
fn fresh_state<'state>(
    epoch: NonZeroU64,
    services: bool,
    a: &'state mut Authority,
    s: &'state mut Scheduler,
    registry: &'state mut Registry<'static>,
    rpc: &'state mut Rpc,
) -> State<'state> {
    let custody = a.create_space().unwrap();
    let common = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE;
    let roots = [
        a.create_root(custody, Kind::Memory, common | Rights::READ)
            .unwrap(),
        a.create_root(
            custody,
            Kind::Endpoint,
            common | Rights::SEND | Rights::RECEIVE | Rights::CONTROL,
        )
        .unwrap(),
        a.create_root(custody, Kind::Job, common | Rights::CONTROL)
            .unwrap(),
        a.create_root(custody, Kind::Memory, common | Rights::READ)
            .unwrap(),
        a.create_root(custody, Kind::Memory, common | Rights::READ)
            .unwrap(),
        a.create_root(
            custody,
            Kind::Endpoint,
            common | Rights::SEND | Rights::RECEIVE | Rights::CONTROL,
        )
        .unwrap(),
    ];
    let events = Mailbox::new(a, custody, roots[1]).unwrap();
    let recovery_events = Mailbox::new(a, custody, roots[5]).unwrap();
    let boot_job = s
        .create_job_with_limits(Limits::new(8192, 128, 8, 16))
        .unwrap();
    if services {
        registry
            .register_image(
                a,
                custody,
                roots[3],
                ServiceImage::verify(
                    bundle::ECHO_IMAGE,
                    bundle::ECHO_SHA,
                    SERVICE_LIMITS,
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
    }
    State {
        a,
        s,
        registry,
        rpc,
        epoch,
        custody,
        roots,
        events,
        recovery_events,
        boot_job,
        receipts: [const { None }; 4],
        baseline: None,
        cpu: 0,
        history: None,
        proof: Proof::default(),
        global: Deadline::after(crate::timer::now(), 2048).unwrap(),
        execution_admissions: 0,
        held_targets: 0,
    }
}
struct State<'state> {
    a: &'state mut Authority,
    s: &'state mut Scheduler,
    registry: &'state mut Registry<'static>,
    rpc: &'state mut Rpc,
    epoch: NonZeroU64,
    custody: SpaceId,
    roots: [Handle; 6],
    events: Mailbox,
    recovery_events: Mailbox,
    boot_job: JobId,
    receipts: [Option<RetiredMailbox>; 4],
    baseline: Option<Snapshot>,
    cpu: u64,
    history: Option<History>,
    proof: Proof,
    global: Deadline,
    execution_admissions: u64,
    held_targets: u64,
}
#[derive(Clone, Copy)]
struct LastCall {
    id: CallId,
    wait: WaitTicket,
    ticket: Ticket,
}
#[derive(Clone, Copy)]
struct OldChild {
    metadata: Metadata,
    control: Option<Handle>,
    object: Option<usize>,
    receive: Option<Handle>,
    call: Option<LastCall>,
}
#[derive(Clone, Copy)]
struct History {
    token: Token,
    target: Target,
    thread: ThreadId,
    grants: [Handle; 4],
    children: [Option<OldChild>; 2],
    transfer_ticket: Option<Ticket>,
}
struct Child<'a> {
    vacant: Option<&'a mut LoadedImage>,
    running: Option<Running<ProcessImage<'a>>>,
    metadata: Option<Metadata>,
    control: Option<Handle>,
    object: Option<usize>,
    receive: Option<Handle>,
    request: Option<usize>,
    response: Option<usize>,
    last: Option<LastCall>,
    rpc_registered: bool,
}
impl<'a> Child<'a> {
    fn new(backing: &'a mut LoadedImage) -> Self {
        Self {
            vacant: Some(backing),
            running: None,
            metadata: None,
            control: None,
            object: None,
            receive: None,
            request: None,
            response: None,
            last: None,
            rpc_registered: false,
        }
    }
}
struct Transfer {
    channel: usize,
    sender: SpaceId,
    ticket: Ticket,
    endpoint: Handle,
}
struct Graph<'m, 's> {
    root: Active<'m, ProcessImage<'s>>,
    target: Target,
    thread: ThreadId,
    grants: [Handle; 4],
    children: [Child<'s>; 2],
    jobs: [Option<JobId>; 2],
    channels: [Option<Channel>; 4],
    contexts: [UserContext; 3],
    fx: [FxState; 3],
    pending: Option<PendingCall>,
    transport: RpcProof,
    ready: bool,
    responded: bool,
    replies: [u64; 2],
    transfer: Option<Transfer>,
    captured: Option<ThreadId>,
    root_rpc_registered: bool,
}
/// Private consumed receipt. Its only construction follows full teardown below.
struct PhysicalReceipt(Token);
// SAFETY: this BSP controller constructs the receipt only after every graph
// context is inhibited/retired, controller CR3 restored, AP parked, all IPC/RPC
// retired, image leases returned and actual backing scrubbed/released. This
// fixture grants no DMA/device authority. Authority/Scheduler remain retained.
unsafe impl QuiescentIncarnation for PhysicalReceipt {
    fn token(&self) -> Token {
        self.0
    }
}

impl Graph<'_, '_> {
    fn channel(&self, identity: usize) -> Option<usize> {
        self.channels
            .iter()
            .position(|c| c.as_ref().is_some_and(|c| c.identity == identity))
    }
    fn child(&self, process: ev_kernel::scheduler::ProcessId) -> Option<usize> {
        self.children
            .iter()
            .position(|c| c.metadata.is_some_and(|m| m.process == process))
    }
    fn create_endpoint(&mut self, state: &mut State<'_>, creator: Handle) -> (u64, u64) {
        let Some(which) = self.channels.iter().position(Option::is_none) else {
            return (2, 0);
        };
        let result = if let Some(receipt) = state.receipts[which].take() {
            match state.registry.create_channel_reusing(
                state.a,
                self.target.destination,
                creator,
                receipt,
            ) {
                Ok(value) => Ok(value),
                Err(rejected) => {
                    state.receipts[which] = Some(rejected.receipt);
                    Err(rejected.error)
                }
            }
        } else {
            state
                .registry
                .create_channel(state.a, self.target.destination, creator)
        };
        match result {
            Err(_) => (1, 0),
            Ok((cap, mailbox)) => {
                let identity = state
                    .a
                    .authorize(
                        self.target.destination,
                        cap,
                        Kind::Endpoint,
                        Rights::CONTROL,
                    )
                    .unwrap()
                    .identity();
                self.channels[which] = Some(Channel {
                    identity,
                    receiver: self.target.destination,
                    mailbox,
                    tickets: [None; MAX_MESSAGES],
                });
                (0, cap.0)
            }
        }
    }
    fn create_process(&mut self, state: &mut State<'_>, job: Handle, image: Handle) -> (u64, u64) {
        let Some(which) = self.children.iter().position(|c| c.metadata.is_none()) else {
            return (2, 0);
        };
        match state
            .registry
            .create_process(state.a, state.s, self.target.destination, job, image)
        {
            Err(_) => (1, 0),
            Ok(cap) => {
                let metadata = state
                    .registry
                    .metadata(state.a, self.target.destination, cap)
                    .unwrap();
                let object = state
                    .a
                    .authorize(self.target.destination, cap, Kind::Process, Rights::CONTROL)
                    .unwrap()
                    .identity();
                self.children[which].metadata = Some(metadata);
                self.children[which].object = Some(object);
                self.children[which].control = Some(cap);
                (0, cap.0)
            }
        }
    }
    fn bind(&mut self, state: &mut State<'_>, endpoint: Handle, process: Handle) -> u64 {
        let prepared = (|| -> Result<_, ev_kernel::service::Error> {
            let meta = state
                .registry
                .metadata(state.a, self.target.destination, process)?;
            let receive = state
                .registry
                .grant(state.a, self.target.destination, process, 3)?;
            let identity = state
                .a
                .authorize(
                    self.target.destination,
                    endpoint,
                    Kind::Endpoint,
                    Rights::CONTROL,
                )?
                .identity();
            Ok((meta, receive, identity))
        })();
        let Ok((meta, receive, identity)) = prepared else {
            return 1;
        };
        let Some(which) = self.channel(identity) else {
            return 1;
        };
        let channel = self.channels[which].as_mut().unwrap();
        if channel
            .mailbox
            .rebind_empty(
                state.a,
                self.target.destination,
                endpoint,
                meta.domain,
                receive,
            )
            .is_err()
        {
            return 1;
        }
        channel.receiver = meta.domain;
        0
    }
    fn start(&mut self, state: &mut State<'_>, hw: &mut Hardware<'_>, process: Handle) -> u64 {
        let setup = (|| -> Result<_, ev_kernel::service::Error> {
            let meta = state
                .registry
                .metadata(state.a, self.target.destination, process)?;
            let record =
                state
                    .registry
                    .startup(state.a, self.target.destination, process, state.epoch)?;
            assert_eq!(
                ev_userspace_contract::Bootstrap::parse(&record)
                    .unwrap()
                    .incarnation(),
                self.root.token().number()
            );
            let plan = state
                .registry
                .plan(state.a, self.target.destination, process)?;
            let receive = state
                .registry
                .grant(state.a, self.target.destination, process, 3)?;
            let send = state
                .registry
                .grant(state.a, self.target.destination, process, 4)?;
            let request = state
                .a
                .authorize(
                    meta.domain,
                    receive,
                    Kind::Endpoint,
                    Rights::RECEIVE | Rights::CONTROL,
                )?
                .identity();
            let response = state
                .a
                .authorize(meta.domain, send, Kind::Endpoint, Rights::SEND)?
                .identity();
            if request == response
                || !self.channels.iter().flatten().any(|c| {
                    c.identity == request && c.receiver == meta.domain && c.mailbox.pending() == 0
                })
                || !self.channels.iter().flatten().any(|c| {
                    c.identity == response
                        && c.receiver == self.target.destination
                        && c.mailbox.pending() == 0
                })
            {
                return Err(ev_kernel::service::Error::Descriptor);
            }
            Ok((meta, record, plan, receive, request, response))
        })();
        let Ok((meta, record, plan, receive, request, response)) = setup else {
            return 1;
        };
        let Some(which) = self.child(meta.process) else {
            return 1;
        };
        let slot = &mut self.children[which];
        if slot.running.is_some() || slot.vacant.is_none() {
            return 1;
        }
        let loaded = slot.vacant.take().unwrap();
        // SAFETY: held exact measured process and inactive exclusively owned slot.
        match unsafe {
            LoadedImage::load_startup(
                hw.offset,
                hw.bits,
                hw.original & ADDRESS_MASK,
                &plan,
                Some(&record),
                hw.frames,
            )
        } {
            Ok(image) => *loaded = image,
            Err(_) => {
                slot.vacant = Some(loaded);
                return 2;
            }
        }
        let owner = ProcessImage {
            loaded,
            process: meta.process,
            frames: meta.frames,
        };
        let running = match state.registry.start(
            state.a,
            state.s,
            self.target.destination,
            process,
            state.epoch,
            owner,
        ) {
            Ok(running) => running,
            Err(rejected) => {
                let ProcessImage { loaded, .. } = rejected.image;
                slot.vacant = Some(loaded);
                return 1;
            }
        };
        self.contexts[which + 1] = running.initial_context().unwrap();
        slot.running = Some(running);
        slot.receive = Some(receive);
        slot.request = Some(request);
        slot.response = Some(response);
        if let Some(old) = state.history.and_then(|old| old.children[which]) {
            assert_ne!(old.metadata.process, meta.process);
            assert_ne!(old.metadata.thread, meta.thread);
            assert_ne!(old.metadata.domain, meta.domain);
            state.proof.stale += 3;
            if let Some(object) = old.object {
                assert_ne!(Some(object), slot.object);
                state.proof.stale += 1;
            }
            if let Some(control) = old.control {
                assert!(
                    state
                        .registry
                        .metadata(state.a, self.target.destination, control)
                        .is_err()
                );
                state.proof.stale += 1;
            }
            if let Some(receive) = old.receive {
                assert!(
                    state
                        .a
                        .authorize(meta.domain, receive, Kind::Endpoint, Rights::RECEIVE)
                        .is_err()
                );
                state.proof.stale += 1;
            }
        }
        state
            .rpc
            .register_thread(
                state.a,
                state.s,
                meta.thread,
                meta.job,
                meta.domain,
                Some(self.root.token()),
            )
            .unwrap();
        slot.rpc_registered = true;
        state
            .rpc
            .bind_endpoint(
                state.a,
                meta.domain,
                receive,
                meta.thread,
                Policy::new(8, 0).unwrap(),
            )
            .unwrap();
        state.proof.service_starts += 1;
        if self.children.iter().all(|c| c.running.is_some()) {
            state.a.collect_lineage().unwrap();
            let snapshot = (
                state.a.metadata_usage(),
                state.s.metadata_usage(),
                state.registry.metadata_usage(),
                state.rpc.metadata_usage(),
                hw.frames.remaining_frames(),
            );
            if let Some(expected) = state.baseline {
                assert_eq!(snapshot, expected, "custodian graph metadata/frame drift");
            } else {
                state.baseline = Some(snapshot);
            }
            let cpu = state.s.usage(state.boot_job, Resource::CpuTicks).unwrap();
            assert!(cpu >= state.cpu);
            state.cpu = cpu;
            state.proof.graphs += 1;
        }
        0
    }
    fn rpc_call(
        &mut self,
        state: &mut State<'_>,
        endpoint: Handle,
        value: u64,
        absolute: u64,
    ) -> (u64, bool) {
        let domain = self.target.destination;
        let now = crate::timer::now();
        let Some(which) = state
            .a
            .authorize(domain, endpoint, Kind::Endpoint, Rights::SEND)
            .ok()
            .and_then(|a| {
                self.children
                    .iter()
                    .position(|c| c.request == Some(a.identity()))
            })
        else {
            return (1, false);
        };
        let meta = self.children[which].metadata.unwrap();
        if self.children[which].running.is_none() {
            return (5, false);
        }
        if absolute <= now {
            return (4, false);
        }
        if absolute > state.global.tick() {
            return (3, false);
        }
        let channel = self.channel(self.children[which].request.unwrap()).unwrap();
        let channel = self.channels[channel].as_mut().unwrap();
        if self.pending.is_some() || channel.mailbox.pending() != 0 {
            return (2, false);
        }
        let deadline = Deadline::after(0, absolute).unwrap();
        if state.s.check_block(0, deadline).is_err() {
            return (1, false);
        }
        let id = match state.rpc.begin(
            state.a,
            self.thread,
            endpoint,
            deadline,
            MessageShape {
                bytes: 8,
                capabilities: 0,
            },
            now,
        ) {
            Ok(id) => id,
            Err(RpcError::DeadlineExceeded) => return (4, false),
            Err(RpcError::WouldBlock | RpcError::AlreadyWaiting) => return (2, false),
            Err(_) => return (1, false),
        };
        let ticket = match channel.send_ticket(state.a, domain, endpoint, value, deadline, now) {
            Ok(ticket) => ticket,
            Err(_) => {
                state.rpc.cancel(self.thread, id, now).unwrap();
                state.rpc.complete(meta.thread, id, now).unwrap();
                return (2, false);
            }
        };
        let wait = state.s.block(0, deadline).unwrap();
        if let Some(history) = state.history
            && let Some(old) = history.children[which].and_then(|child| child.call)
        {
            assert_eq!(
                state.rpc.complete(meta.thread, old.id, now),
                Err(RpcError::StaleCall)
            );
            assert!(!state.s.wake(old.wait));
            assert!(state.s.waiting(wait));
            assert_eq!(
                channel.reclaim(state.a, history.target.destination, old.ticket, now),
                Err(IpcError::InvalidTicket)
            );
            state.proof.stale += 3;
        }
        self.pending = Some(PendingCall {
            id,
            caller: self.thread,
            callee: meta.thread,
            wait,
            waiting: true,
            request: ticket,
            delivered: false,
        });
        self.transport.blocks += 1;
        (0, true)
    }
    fn receive(
        &mut self,
        state: &mut State<'_>,
        index: usize,
        endpoint: Handle,
        frame: &mut UserContext,
    ) -> u64 {
        if index == 0 {
            return 3;
        }
        let meta = self.children[index - 1].metadata.unwrap();
        let Ok(access) = state
            .a
            .authorize(meta.domain, endpoint, Kind::Endpoint, Rights::RECEIVE)
        else {
            return 1;
        };
        let Some(channel) = self.channel(access.identity()) else {
            return 1;
        };
        if self.channels[channel].as_ref().unwrap().receiver != meta.domain {
            return 1;
        }
        match self.channels[channel].as_mut().unwrap().receive(
            state.a,
            meta.domain,
            endpoint,
            crate::timer::now(),
        ) {
            Err(IpcError::Empty) => 2,
            Err(_) => 1,
            Ok(message) => {
                let Some(pending) = self.pending.as_mut().filter(|p| {
                    p.callee == meta.thread
                        && !p.delivered
                        && state.rpc.serving(meta.thread) == Some(p.id)
                }) else {
                    return 3;
                };
                assert_eq!(message.capability, None);
                pending.delivered = true;
                frame.registers[9] = u64::from_le_bytes(message.bytes[..8].try_into().unwrap());
                frame.registers[11] = 0;
                0
            }
        }
    }
    fn send(
        &mut self,
        state: &mut State<'_>,
        index: usize,
        endpoint: Handle,
        value: u64,
        capability: Option<Handle>,
    ) -> u64 {
        let domain = if index == 0 {
            self.target.destination
        } else {
            self.children[index - 1].metadata.unwrap().domain
        };
        let Ok(access) = state
            .a
            .authorize(domain, endpoint, Kind::Endpoint, Rights::SEND)
        else {
            return 1;
        };
        let identity = access.identity();
        if let Some(capability) = capability {
            if index != 0
                || !self.responded
                || self.transfer.is_some()
                || self.pending.is_some()
                || state.rpc.outstanding() != 0
            {
                return 3;
            }
            let source = &self.children[0];
            if source.control != Some(capability) || self.children[0].response != Some(identity) {
                return 1;
            }
            let Ok(metadata) = state.registry.metadata(state.a, domain, capability) else {
                return 1;
            };
            if Some(metadata) != source.metadata {
                return 1;
            }
            let Some(which) = self.channel(identity) else {
                return 1;
            };
            let channel = self.channels[which].as_mut().unwrap();
            if channel.receiver != domain || channel.mailbox.pending() != 0 {
                return 2;
            }
            let bytes = value.to_le_bytes();
            let ticket = match channel.mailbox.send(
                state.a,
                domain,
                endpoint,
                Outgoing {
                    bytes: &bytes,
                    capability: Some(capability),
                    deadline: state.global,
                },
                crate::timer::now(),
            ) {
                Ok(ticket) => ticket,
                Err(_) => return 1,
            };
            self.transfer = Some(Transfer {
                channel: which,
                sender: domain,
                ticket,
                endpoint,
            });
            if let Some(old) = state.history
                && let Some(old_ticket) = old.transfer_ticket
            {
                assert!(ticket.0 > old_ticket.0);
                assert!(
                    channel
                        .mailbox
                        .reclaim(
                            state.a,
                            old.target.destination,
                            old_ticket,
                            crate::timer::now()
                        )
                        .is_err()
                );
                assert_eq!(channel.mailbox.pending(), 1);
                state.proof.stale += 2;
            }
            state.proof.accepted_transfers += 1;
            return 0;
        }
        let event_identity = state
            .a
            .authorize(
                state.custody,
                state.roots[1],
                Kind::Endpoint,
                Rights::RECEIVE,
            )
            .unwrap()
            .identity();
        if identity == event_identity {
            let event = Event::decode(&value.to_le_bytes());
            let allowed = index == 0
                && match event {
                    Some(Event::Ready) => !self.ready,
                    Some(Event::ServiceResponded) => {
                        self.ready
                            && !self.responded
                            && self.replies == [1, 1]
                            && self.pending.is_none()
                            && state.rpc.outstanding() == 0
                    }
                    _ => false,
                };
            if !allowed {
                return 3;
            }
            let bytes = value.to_le_bytes();
            state
                .events
                .send(
                    state.a,
                    domain,
                    endpoint,
                    Outgoing {
                        bytes: &bytes,
                        capability: None,
                        deadline: state.global,
                    },
                    crate::timer::now(),
                )
                .unwrap();
            let message = state
                .events
                .receive(state.a, state.custody, state.roots[1], crate::timer::now())
                .unwrap();
            assert_eq!(Event::decode(&message.bytes[..message.length]), event);
            if event == Some(Event::Ready) {
                self.ready = true;
            } else {
                self.responded = true;
            }
            return 0;
        }
        if index == 0 || self.children[index - 1].response != Some(identity) {
            return 1;
        }
        let thread = self.children[index - 1].metadata.unwrap().thread;
        let Some(wait) = self.pending.as_ref().filter(|p| {
            p.callee == thread && p.delivered && state.rpc.serving(thread) == Some(p.id)
        }) else {
            return 3;
        };
        let completion = state
            .rpc
            .complete(thread, wait.id, crate::timer::now())
            .unwrap();
        let wait = self.pending.take().unwrap();
        if completion.deliver_reply {
            self.contexts[0].registers[14] = 0;
            self.contexts[0].registers[9] = value;
            self.contexts[0].registers[11] = 0;
            assert!(state.s.wake(wait.wait));
            self.replies[index - 1] += 1;
            self.transport.successes += 1;
            self.transport.wakes += 1;
            state.proof.service_replies += 1;
        }
        self.children[index - 1].last = Some(LastCall {
            id: wait.id,
            wait: wait.wait,
            ticket: wait.request,
        });
        0
    }
    fn syscall(
        &mut self,
        state: &mut State<'_>,
        hw: &mut Hardware<'_>,
        dispatch: Dispatch,
        index: usize,
        domain: SpaceId,
        frame: &mut UserContext,
    ) -> bool {
        let mut blocked = false;
        frame.registers[14] = match decode(frame) {
            Ok(Call::Yield) => 0,
            Ok(Call::Monotonic) => {
                frame.registers[9] = crate::timer::now();
                0
            }
            Ok(Call::Inspect { capability, rights }) => u64::from(
                state
                    .a
                    .authorize(domain, capability, Kind::Memory, rights)
                    .is_err(),
            ),
            Ok(Call::CreateJob { creator, template }) if index == 0 => {
                if let Some(slot) = self.jobs.iter_mut().find(|j| j.is_none()) {
                    match state
                        .registry
                        .create_job(state.a, state.s, domain, creator, template)
                    {
                        Err(_) => 1,
                        Ok(cap) => {
                            *slot = Some(state.registry.job_id(state.a, domain, cap).unwrap());
                            frame.registers[9] = cap.0;
                            0
                        }
                    }
                } else {
                    2
                }
            }
            Ok(Call::CreateEndpoint(creator)) if index == 0 => {
                let (status, cap) = self.create_endpoint(state, creator);
                frame.registers[9] = cap;
                status
            }
            Ok(Call::CreateProcess { job, image }) if index == 0 => {
                let (status, cap) = self.create_process(state, job, image);
                frame.registers[9] = cap;
                status
            }
            Ok(Call::Delegate {
                process,
                source,
                selector,
            }) if index == 0 => u64::from(
                state
                    .registry
                    .delegate(state.a, domain, process, source, selector)
                    .is_err(),
            ),
            Ok(Call::BindReceiver { endpoint, process }) if index == 0 => {
                self.bind(state, endpoint, process)
            }
            Ok(Call::Start(process)) if index == 0 => self.start(state, hw, process),
            Ok(Call::Rpc {
                endpoint,
                value,
                deadline,
            }) if index == 0 => {
                assert_eq!(dispatch.thread, self.thread);
                let (status, did_block) = self.rpc_call(state, endpoint, value, deadline);
                blocked = did_block;
                status
            }
            Ok(Call::Receive(endpoint)) => self.receive(state, index, endpoint, frame),
            Ok(Call::Send {
                endpoint,
                value,
                capability,
            }) => self.send(state, index, endpoint, value, capability),
            Ok(Call::Exit(code)) => panic!("custody artifact exited index={index} code={code}"),
            _ => 3,
        };
        blocked
    }
    unsafe fn run(
        &mut self,
        state: &mut State<'_>,
        hw: &mut Hardware<'_>,
        mut watchdog: Option<&mut Watchdog>,
    ) -> RootFailure {
        // SAFETY: exclusive initialized PIC owner at IF=0; AP remains parked.
        unsafe {
            crate::timer::start_runtime();
        }
        for _ in 0..32768 {
            let now = crate::timer::now();
            assert!(!state.global.reached(now), "custodian graph deadline");
            expire(
                state.rpc,
                state.s,
                &mut self.pending,
                &mut self.contexts[0],
                &mut self.transport,
                now,
            );
            let dispatch = state
                .s
                .dispatch(0)
                .unwrap()
                .expect("custody graph has no runnable thread");
            let (index, domain) = if dispatch.process == self.target.process {
                assert_eq!(dispatch.thread, self.thread);
                self.root.image().loaded.root.activate();
                (0, self.target.destination)
            } else {
                let which = self
                    .child(dispatch.process)
                    .expect("foreign custody dispatch");
                let running = self.children[which]
                    .running
                    .as_ref()
                    .expect("held service dispatched");
                assert_eq!(running.metadata().thread, dispatch.thread);
                running.image().loaded.root.activate();
                (which + 1, running.metadata().domain)
            };
            // SAFETY: exact selected owned user root/context/FX; the common trap
            // entry returns at IF=0 with retained controller CR3 restored.
            let (mut frame, address) = unsafe {
                crate::user_runtime::resume_context(
                    &self.contexts[index],
                    &mut self.fx[index],
                    hw.original,
                )
            };
            self.captured = Some(dispatch.thread);
            expire(
                state.rpc,
                state.s,
                &mut self.pending,
                &mut self.contexts[0],
                &mut self.transport,
                crate::timer::now(),
            );
            let blocked = match frame.vector {
                32 => {
                    state
                        .s
                        .charge_cpu(0, 1)
                        .expect("custody finite CPU budget exhausted");
                    if index == 0
                        && let Some(watchdog) = watchdog.as_mut()
                        && let Some(deadline) = watchdog.deadline
                        && deadline.reached(crate::timer::now())
                    {
                        let dispatches = state.s.dispatches(self.target.job).unwrap();
                        let cpu_ticks = state.s.usage(self.target.job, Resource::CpuTicks).unwrap();
                        assert!(dispatches > watchdog.dispatches && cpu_ticks > watchdog.cpu_ticks);
                        assert_eq!(
                            state.s.state(self.thread),
                            Ok(ev_kernel::scheduler::State::Running(0))
                        );
                        // SAFETY: actual IRQ capture restored controller CR3 at
                        // IF=0; watchdog failure owns this stopped CPU boundary.
                        unsafe {
                            crate::timer::stop_runtime();
                        }
                        return RootFailure::Watchdog {
                            process: self.target.process,
                            thread: self.thread,
                            deadline: deadline.tick(),
                            observed: crate::timer::now(),
                            instruction: frame.rip,
                            dispatches,
                            cpu_ticks,
                        };
                    }
                    false
                }
                128 => {
                    if index == 0
                        && let Ok(Call::Exit(code)) = decode(&frame)
                    {
                        // SAFETY: the actual userspace exit trap returned to
                        // controller CR3/IF=0; no fabricated fault is involved.
                        unsafe {
                            crate::timer::stop_runtime();
                        }
                        return RootFailure::FatalExit {
                            process: dispatch.process,
                            thread: dispatch.thread,
                            code,
                            instruction: frame.rip,
                        };
                    }
                    let blocked = self.syscall(state, hw, dispatch, index, domain, &mut frame);
                    if self.responded
                        && let Some(watchdog) = watchdog.as_mut()
                        && watchdog.deadline.is_none()
                    {
                        watchdog.arm(crate::timer::now(), state.s, self.target.job);
                    }
                    blocked
                }
                _ if index == 0 && frame.ordinary_user_fault() => {
                    let record = Record {
                        process: dispatch.process.diagnostic_id(),
                        thread: dispatch.thread.diagnostic_id(),
                        vector: frame.vector,
                        error: frame.error,
                        address,
                        instruction: frame.rip,
                    };
                    assert_eq!(Record::decode(&record.encode()), Some(record));
                    // SAFETY: capture restored controller CR3 and IF=0; no user
                    // context may execute while this graph starts revocation.
                    unsafe {
                        crate::timer::stop_runtime();
                    }
                    state.proof.root_faults += 1;
                    return RootFailure::Fault(record);
                }
                _ => panic!(
                    "unexpected custody fault index={index} vector={} ip={:#x}",
                    frame.vector, frame.rip
                ),
            };
            self.contexts[index] = frame;
            if !blocked {
                state.s.yield_cpu(0).unwrap();
            }
        }
        panic!("custody trap budget exhausted")
    }
}

/// # Safety
/// Exclusive BSP controller at IF=0 with parked AP, initialized ordinary user
/// trap/FX/IRQ boundary, retained direct map/controller CR3 and exclusive frames.
pub unsafe fn prove(offset: u64, frames: &mut BootstrapFrames) -> Proof {
    // SAFETY: forwards the ordinary retained controller ownership preconditions.
    unsafe { run_fixture(offset, frames, Fixture::Nominal) }.nominal
}
/// # Safety
/// Same exclusive retained controller/trap/allocator ownership as prove().
/// Each explicit fixture retains its own once-created custody/tables throughout.
pub unsafe fn prove_negative(
    offset: u64,
    frames: &mut BootstrapFrames,
    fixture: Fixture,
) -> NegativeProof {
    assert_ne!(fixture, Fixture::Nominal);
    // SAFETY: forwards the same hardware preconditions; no fixture resets custody.
    unsafe { run_fixture(offset, frames, fixture) }.negative
}

/// # Safety
/// Exclusive retained BSP/trap/allocator ownership. This creates one explicit
/// fresh boot-selection fixture, never a reset of an existing failed Custodian.
#[inline(never)] // This State is exclusive to this case, separate from the suite/graph lifetime.
pub unsafe fn prove_selection(
    offset: u64,
    frames: &mut BootstrapFrames,
    selection: SelectionCase,
) -> NegativeProof {
    let epoch = NonZeroU64::new(match selection {
        SelectionCase::CorruptManifest => 120,
        SelectionCase::CorruptImage => 121,
        SelectionCase::WrongAuthority => 122,
    })
    .unwrap();
    // Recovery depends on neither the rejected Root selection nor Echo services.
    // The world retains the only four table owners; State merely borrows them.
    // Const initialization is an empty metadata template, never live authority.
    let mut authority = const { Authority::new() };
    let mut scheduler = Scheduler::new();
    let mut registry = Registry::new();
    let mut rpc = Rpc::new(epoch);
    let mut state = fresh_state(
        epoch,
        false,
        &mut authority,
        &mut scheduler,
        &mut registry,
        &mut rpc,
    );
    let catalog = root_catalog(state.roots);
    let recovery_catalog = recovery_catalog(state.roots);
    let recovery_manifest = bootstrap_manifest::verify(
        bundle::RECOVERY_MANIFEST,
        bundle::RECOVERY_MEASUREMENT,
        bundle::RECOVERY_IMAGE,
        ABI,
    )
    .unwrap();
    let original: u64;
    // SAFETY: privileged read of the retained controller root, no user running.
    unsafe {
        asm!("mov {}, cr3",out(reg)original,options(nomem,nostack,preserves_flags));
    }
    let bits = (core::arch::x86_64::__cpuid(0x80000008).eax & 255) as u8;
    let before = frames.remaining_frames();
    let mut hardware = Hardware {
        offset,
        bits,
        original,
        frames,
    };
    let mut slot = LoadedImage::empty();
    let mut proof = NegativeProof::default();
    match selection {
        SelectionCase::CorruptManifest | SelectionCase::CorruptImage => {
            let checked = match selection {
                SelectionCase::CorruptManifest => bootstrap_manifest::verify(
                    bundle::CUSTODY_CORRUPT_MANIFEST,
                    bundle::CUSTODY_GRAPH_MEASUREMENT,
                    bundle::CUSTODY_GRAPH_IMAGE,
                    ABI,
                ),
                SelectionCase::CorruptImage => bootstrap_manifest::verify(
                    bundle::CUSTODY_GRAPH_MANIFEST,
                    bundle::CUSTODY_GRAPH_MEASUREMENT,
                    bundle::CUSTODY_CORRUPT_IMAGE,
                    ABI,
                ),
                SelectionCase::WrongAuthority => unreachable!(),
            };
            let error = checked.err().expect("corrupt selected bytes accepted");
            let reason = match selection {
                SelectionCase::CorruptManifest => {
                    assert_eq!(error, bootstrap_manifest::Error::ManifestDigest);
                    IntegrityReason::Manifest(error)
                }
                SelectionCase::CorruptImage => {
                    assert_eq!(error, bootstrap_manifest::Error::ImageDigest);
                    IntegrityReason::Image(error)
                }
                SelectionCase::WrongAuthority => unreachable!(),
            };
            proof.integrity_reason = Some(reason);
            proof.last_failure = Some(RootFailure::Integrity(reason));
            // No Root permit, Job, process, grants or executable owner exists.
            assert_eq!(state.a.metadata_usage(), (3, 6, 6, 6));
            assert_eq!(state.s.metadata_usage(), (1, 0, 0));
            for cpu in 0..ev_kernel::scheduler::MAX_CPUS {
                assert_eq!(state.s.dispatch(cpu), Ok(None));
            }
            // SAFETY: no failed Root executable was admitted or loaded; this is
            // the independently measured recovery selection in the same tables.
            unsafe {
                run_recovery(
                    &mut state,
                    &mut hardware,
                    &mut slot,
                    &recovery_manifest,
                    &recovery_catalog,
                    RecoveryDomains::Fresh,
                );
            }
        }
        SelectionCase::WrongAuthority => {
            // These deliberately wrong expected-set bytes have THEIR OWN
            // producer-selected measurement; the kernel never authenticates an
            // untrusted manifest by hashing it and trusting that computed value.
            let manifest = bootstrap_manifest::verify(
                bundle::CUSTODY_WRONG_AUTHORITY_MANIFEST,
                bundle::CUSTODY_WRONG_AUTHORITY_MEASUREMENT,
                bundle::CUSTODY_GRAPH_IMAGE,
                ABI,
            )
            .unwrap();
            let mut custodian = Custodian::new(epoch, &manifest, state.custody, &catalog);
            let permit = custodian.begin(crate::timer::now()).unwrap();
            let job = state
                .s
                .create_child_job(state.boot_job, manifest.limits())
                .unwrap();
            let process = state.s.create_held_process(job).unwrap();
            state.held_targets += 1;
            let thread = state.s.create_thread(process).unwrap();
            let target = Target {
                job,
                process,
                branches: state.a.create_space().unwrap(),
                destination: state.a.create_space().unwrap(),
            };
            state
                .registry
                .register_job(state.a, state.custody, state.roots[2], job)
                .unwrap();
            let authority_before = state.a.metadata_usage();
            let expected = ev_kernel::custodian::Recovery::Preparation(
                ev_kernel::incarnation::Error::Binding(
                    ev_kernel::bootstrap_binding::Error::AuthorityDigest,
                ),
            );
            assert_eq!(
                custodian.prepare(permit, state.a, state.s, target).err(),
                Some(ev_kernel::custodian::Error::RecoveryRequired(expected))
            );
            assert_eq!(state.a.metadata_usage(), authority_before);
            assert_eq!(authority_before, (5, 6, 6, 6));
            assert_eq!(custodian.current(), None);
            assert_eq!(
                custodian.phase(),
                ev_kernel::custodian::Phase::RecoveryRequired
            );
            assert_eq!(state.s.held_process_job(process), Ok(job));
            assert_eq!(
                state.s.state(thread),
                Ok(ev_kernel::scheduler::State::Ready)
            );
            for cpu in 0..ev_kernel::scheduler::MAX_CPUS {
                assert_eq!(state.s.dispatch(cpu), Ok(None));
            }
            // Failed preparation never published a binding/token or grants.
            // Clean the retained held target directly; a latched custodian is
            // neither reset nor asked to mint speculative replacement authority.
            state.s.terminate_process(process).unwrap();
            state.a.close_space(target.destination).unwrap();
            state.a.close_space(target.branches).unwrap();
            state.s.reclaim_process(process).unwrap();
            state
                .registry
                .forget_job(state.a, state.s, state.rpc, job)
                .unwrap();
            assert_eq!(state.a.metadata_usage(), (3, 6, 6, 6));
            assert_eq!(state.s.metadata_usage(), (1, 0, 0));
            let reason = IntegrityReason::Authority(expected);
            proof.integrity_reason = Some(reason);
            proof.last_failure = Some(RootFailure::Integrity(reason));
            proof.recovery_reason = Some(expected);
            proof.attempts = custodian.last_attempt();
            proof.held_targets = 1;
            // SAFETY: no Root backing/grants survived rejection; this executes
            // independent recovery while the SAME failed custodian stays latched.
            unsafe {
                run_recovery(
                    &mut state,
                    &mut hardware,
                    &mut slot,
                    &recovery_manifest,
                    &recovery_catalog,
                    target.into(),
                );
            }
            assert_eq!(custodian.recovery_required(), Some(expected));
            assert_eq!(
                custodian.begin(crate::timer::now()).err(),
                Some(ev_kernel::custodian::Error::RecoveryRequired(expected))
            );
            assert_eq!(custodian.last_attempt(), 1);
        }
    }
    for (i, entry) in catalog.iter().enumerate() {
        let rights = [Rights::READ, Rights::SEND, Rights::CONTROL, Rights::READ][i];
        assert!(
            state
                .a
                .authorize(state.custody, entry.root, entry.kind, rights)
                .is_ok()
        );
    }
    state.events.receiver_died(state.custody).unwrap();
    state.events.retire_empty(state.a).unwrap();
    state.recovery_events.receiver_died(state.custody).unwrap();
    state.recovery_events.retire_empty(state.a).unwrap();
    state.a.collect_lineage().unwrap();
    assert_eq!(state.a.metadata_usage(), (1, 6, 6, 6));
    assert_eq!(state.s.metadata_usage(), (1, 0, 0));
    assert_eq!(state.registry.metadata_usage(), (0, 0, 0, 0));
    assert_eq!(state.rpc.metadata_usage(), (0, 0, 0));
    assert_eq!(hardware.frames.remaining_frames(), before);
    assert_eq!(state.execution_admissions, 0);
    assert_eq!(state.proof.recovery_entries, 1);
    proof.held_targets = state.held_targets;
    proof.integrity_failures = 1;
    proof.refused_before_dispatch = true;
    proof.no_speculative_grants = true;
    proof.recovery_entries = state.proof.recovery_entries;
    proof.no_duplicate = true;
    proof.retired = true;
    proof.frames_balanced = true;
    assert_eq!(
        (
            proof.fault_records,
            proof.fatal_exits,
            proof.watchdogs,
            proof.active_incarnations,
            proof.execution_admissions,
            proof.graphs,
            proof.service_starts,
            proof.service_replies
        ),
        (0, 0, 0, 0, 0, 0, 0, 0)
    );
    proof
}
#[inline(never)] // Bound the retained graph world independently of its caller's fixture choice.
unsafe fn run_fixture(
    offset: u64,
    frames: &mut BootstrapFrames,
    fixture: Fixture,
) -> FixtureResult {
    let (manifest_bytes, measurement, image) = match fixture {
        Fixture::FatalExit => (
            bundle::CUSTODY_EXIT_MANIFEST,
            bundle::CUSTODY_EXIT_MEASUREMENT,
            bundle::CUSTODY_EXIT_IMAGE,
        ),
        Fixture::Watchdog => (
            bundle::CUSTODY_WATCHDOG_MANIFEST,
            bundle::CUSTODY_WATCHDOG_MEASUREMENT,
            bundle::CUSTODY_WATCHDOG_IMAGE,
        ),
        Fixture::Nominal | Fixture::Interrupted(_) => (
            bundle::CUSTODY_GRAPH_MANIFEST,
            bundle::CUSTODY_GRAPH_MEASUREMENT,
            bundle::CUSTODY_GRAPH_IMAGE,
        ),
    };
    let manifest = bootstrap_manifest::verify(manifest_bytes, measurement, image, ABI).unwrap();
    let recovery_manifest = bootstrap_manifest::verify(
        bundle::RECOVERY_MANIFEST,
        bundle::RECOVERY_MEASUREMENT,
        bundle::RECOVERY_IMAGE,
        ABI,
    )
    .unwrap();
    let epoch_number = match fixture {
        Fixture::Nominal => 104,
        Fixture::FatalExit => 105,
        Fixture::Watchdog => 106,
        Fixture::Interrupted(Interruption::Admission) => 110,
        Fixture::Interrupted(Interruption::HeldTarget) => 111,
        Fixture::Interrupted(Interruption::GrantPreparation) => 112,
        Fixture::Interrupted(Interruption::ImageLoad) => 113,
        Fixture::Interrupted(Interruption::Activation) => 114,
        Fixture::Interrupted(Interruption::Confirmation) => 115,
    };
    let epoch = NonZeroU64::new(epoch_number).unwrap(); // Explicit isolated development selection.
    // The world retains the only four table owners; State merely borrows them.
    // Const initialization is an empty metadata template, never live authority.
    let mut authority = const { Authority::new() };
    let mut scheduler = Scheduler::new();
    let mut registry = Registry::new();
    let mut rpc = Rpc::new(epoch);
    let mut state = fresh_state(
        epoch,
        true,
        &mut authority,
        &mut scheduler,
        &mut registry,
        &mut rpc,
    );
    let custody = state.custody;
    let roots = state.roots;
    let boot_job = state.boot_job;
    let catalog = root_catalog(roots);
    let recovery_catalog = recovery_catalog(roots);
    let mut custodian = Custodian::new(epoch, &manifest, custody, &catalog);
    let original: u64;
    // SAFETY: retained privileged controller root read, no user entry active.
    unsafe {
        asm!("mov {}, cr3",out(reg)original,options(nomem,nostack,preserves_flags));
    }
    let bits = (core::arch::x86_64::__cpuid(0x80000008).eax & 255) as u8;
    let before = frames.remaining_frames();
    let mut hardware = Hardware {
        offset,
        bits,
        original,
        frames,
    };
    let mut storage = [
        LoadedImage::empty(),
        LoadedImage::empty(),
        LoadedImage::empty(),
    ];
    let mut previous: Option<Target> = None;
    let mut capsules: [Option<(Token, Record)>; 4] = [None; 4];
    let mut failures: [Option<(Token, RootFailure)>; 4] = [None; 4];
    let mut negative = NegativeProof::default();
    for number in 1..=4 {
        let attempt = custodian.begin(crate::timer::now()).unwrap();
        assert_eq!(attempt.number(), number);
        if number == 2
            && let Fixture::Interrupted(stage) = fixture
        {
            state
                .registry
                .advance_incarnation(NonZeroU64::new(number).unwrap())
                .unwrap();
            // SAFETY: first actual Root graph is fully quiescent; only this
            // admitted replacement attempt may allocate or own target backing.
            previous = Some(unsafe {
                interrupt_replacement(
                    stage,
                    attempt,
                    &mut state,
                    &mut hardware,
                    &mut custodian,
                    &mut storage,
                    Replacement {
                        previous: previous.unwrap(),
                        limits: manifest.limits(),
                    },
                )
            });
            assert_eq!(hardware.frames.remaining_frames(), before);
            assert_eq!(state.a.metadata_usage(), (3, 6, 6, 6));
            assert_eq!(state.s.metadata_usage(), (1, 0, 0));
            assert_eq!(state.registry.metadata_usage(), (0, 1, 0, 4));
            negative.interrupted = 1;
            negative.interrupted_at = Some(stage);
            negative.interrupted_attempt = Some(number);
            for charged in 3..=4 {
                let permit = custodian.begin(crate::timer::now()).unwrap();
                assert_eq!(permit.number(), charged);
                state
                    .registry
                    .advance_incarnation(NonZeroU64::new(charged).unwrap())
                    .unwrap();
                custodian.abandon_unprepared(permit).unwrap();
            }
            break;
        }
        if number > 1 {
            state
                .registry
                .advance_incarnation(NonZeroU64::new(number).unwrap())
                .unwrap();
        }
        let (branches, destination) = if let Some(old) = previous {
            (
                state.a.recycle_space(old.branches).unwrap(),
                state.a.recycle_space(old.destination).unwrap(),
            )
        } else {
            (
                state.a.create_space().unwrap(),
                state.a.create_space().unwrap(),
            )
        };
        let job = state
            .s
            .create_child_job(boot_job, manifest.limits())
            .unwrap();
        let process = state.s.create_held_process(job).unwrap();
        state.held_targets += 1;
        let thread = state.s.create_thread(process).unwrap();
        let target = Target {
            process,
            job,
            destination,
            branches,
        };
        state
            .registry
            .register_job(state.a, custody, roots[2], job)
            .unwrap();
        let (mut binding, token) = custodian
            .prepare(attempt, state.a, state.s, target)
            .unwrap();
        let grants: [Handle; 4] = binding.grants(token).unwrap().try_into().unwrap();
        let startup = binding.bootstrap_record(token).unwrap().unwrap();
        assert_eq!(
            &startup[104..136],
            manifest.expected_authority_digest().as_slice()
        );
        assert_eq!(
            ev_userspace_contract::Bootstrap::parse(&startup)
                .unwrap()
                .incarnation(),
            number
        );
        let plan = binding.executable(token).unwrap();
        state.s.charge_frames(job, plan.required_frames()).unwrap();
        let [root_slot, first, second] = storage.each_mut();
        // SAFETY: held exact Root target and measured immutable startup/image;
        // slot is physically empty after prior complete graph quiescence.
        *root_slot = unsafe {
            LoadedImage::load_startup(
                offset,
                bits,
                original & ADDRESS_MASK,
                &plan,
                Some(&startup),
                hardware.frames,
            )
        }
        .unwrap();
        let owner = ProcessImage {
            loaded: root_slot,
            process,
            frames: plan.required_frames(),
        };
        let root = binding
            .activate(state.a, state.s, token, thread, owner)
            .unwrap_or_else(|r| panic!("custody Root admission: {:?}", r.error));
        state.execution_admissions += 1;
        custodian.confirm_active(&root).unwrap();
        assert_eq!(custodian.current(), Some(token));
        assert_eq!(custodian.phase(), ev_kernel::custodian::Phase::Active);
        assert!(custodian.begin(crate::timer::now()).is_err());
        assert_eq!(custodian.last_attempt(), number);
        state.proof.incarnations += 1;
        state.proof.replacements += u64::from(number > 1);
        if let Some(old) = state.history {
            assert_eq!(
                custodian.begin_revocation(old.token),
                Err(ev_kernel::custodian::Error::StaleToken)
            );
            assert_ne!(old.target.process, process);
            assert_ne!(old.target.job, job);
            assert_ne!(old.thread, thread);
            assert_ne!(old.target.destination, destination);
            assert!(state.s.process_job(old.target.process).is_err());
            assert!(state.s.state(old.thread).is_err());
            assert!(state.s.job_limits(old.target.job).is_err());
            assert!(
                state
                    .a
                    .authorize(
                        old.target.destination,
                        old.grants[0],
                        Kind::Memory,
                        Rights::READ
                    )
                    .is_err()
            );
            assert!(
                state
                    .a
                    .authorize(destination, old.grants[0], Kind::Memory, Rights::READ)
                    .is_err()
            );
            state.proof.stale += 10;
        }
        state
            .rpc
            .register_thread(state.a, state.s, thread, job, destination, Some(token))
            .unwrap();
        let context = root.initial_context().unwrap();
        let mut graph = Graph {
            root,
            target,
            thread,
            grants,
            children: [Child::new(first), Child::new(second)],
            jobs: [None; 2],
            channels: [const { None }; 4],
            contexts: [context, UserContext::ZERO, UserContext::ZERO],
            fx: [FxState::CLEAN; 3],
            pending: None,
            transport: RpcProof::default(),
            ready: false,
            responded: false,
            replies: [0; 2],
            transfer: None,
            captured: None,
            root_rpc_registered: true,
        };
        let mut watchdog = Watchdog::new();
        // SAFETY: graph owns every executable lease; same exclusive hardware/tables.
        let failure = unsafe {
            graph.run(
                &mut state,
                &mut hardware,
                if fixture == Fixture::Watchdog {
                    Some(&mut watchdog)
                } else {
                    None
                },
            )
        };
        failures[number as usize - 1] = Some((token, failure));
        if let RootFailure::Fault(fault) = failure {
            capsules[number as usize - 1] = Some((token, fault));
        }
        let complete_graph = graph.ready
            && graph.responded
            && graph.replies == [1, 1]
            && graph.transfer.is_some()
            && graph
                .children
                .iter()
                .all(|child| child.running.is_some() && child.rpc_registered)
            && graph.channels.iter().all(Option::is_some);
        // SAFETY: actual capture returned to retained controller at IF=0; this
        // consuming teardown owns all managed execution and reference lifetimes.
        let (binding, receipt, history) =
            unsafe { graph.quiesce(&mut state, &mut hardware, &mut custodian) };
        custodian
            .accept_quiescence(state.s, binding, receipt)
            .unwrap_or_else(|r| panic!("physical incarnation receipt: {:?}", r.error));
        assert_eq!(custodian.phase(), ev_kernel::custodian::Phase::Quiescent);
        assert_eq!(custodian.current(), None);
        state.s.reclaim_process(process).unwrap();
        state
            .registry
            .forget_job(state.a, state.s, state.rpc, job)
            .unwrap();
        // The fixed proof artifact must complete its full graph. Unexpected
        // early faults still retire their partial graph before this assertion.
        assert!(
            complete_graph,
            "custody artifact faulted before graph completion"
        );
        match (fixture, failure) {
            (Fixture::Nominal | Fixture::Interrupted(_), RootFailure::Fault(fault)) => {
                assert_eq!((fault.vector, fault.error, fault.address), (14, 6, 0))
            }
            (
                Fixture::FatalExit,
                RootFailure::FatalExit {
                    process: actual,
                    thread: actual_thread,
                    code,
                    instruction,
                },
            ) => {
                assert_eq!((actual, actual_thread), (process, thread));
                assert_eq!(code, 0x4355_5354_4f44_5902);
                assert!(instruction >= 4096);
                negative.fatal_exits += 1;
            }
            (
                Fixture::Watchdog,
                RootFailure::Watchdog {
                    process: actual,
                    thread: actual_thread,
                    deadline,
                    observed,
                    instruction,
                    dispatches,
                    cpu_ticks,
                },
            ) => {
                assert_eq!((actual, actual_thread), (process, thread));
                assert!(
                    observed >= deadline && instruction >= 4096 && dispatches > 0 && cpu_ticks > 0
                );
                negative.watchdogs += 1;
            }
            _ => panic!(
                "unexpected actual Root outcome for explicit fixture: {fixture:?} {failure:?}"
            ),
        }
        assert!(history.transfer_ticket.is_some());
        assert!(
            history
                .children
                .iter()
                .all(|child| child.is_some_and(|child| {
                    child.control.is_some()
                        && child.object.is_some()
                        && child.receive.is_some()
                        && child.call.is_some()
                }))
        );
        assert_eq!(state.registry.metadata_usage(), (0, 1, 0, 4));
        assert_eq!(state.s.metadata_usage(), (1, 0, 0));
        assert_eq!(hardware.frames.remaining_frames(), before);
        let cpu = state.s.usage(boot_job, Resource::CpuTicks).unwrap();
        assert!(cpu >= state.cpu);
        state.cpu = cpu;
        state.history = Some(history);
        previous = Some(target);
    }
    let reason = ev_kernel::custodian::Recovery::Restart(
        ev_kernel::restart::RecoveryRequired::BudgetExhausted,
    );
    assert_eq!(
        custodian.begin(crate::timer::now()).err(),
        Some(ev_kernel::custodian::Error::RecoveryRequired(reason))
    );
    assert_eq!(custodian.last_attempt(), 4);
    assert_eq!(custodian.current(), None);
    state.proof.budget_latched = true;
    state.proof.last_fault = capsules
        .iter()
        .rev()
        .flatten()
        .next()
        .map(|(_, fault)| *fault);
    state.proof.failed_token = failures
        .iter()
        .rev()
        .flatten()
        .next()
        .map(|(token, _)| *token);
    negative.last_failure = failures
        .iter()
        .rev()
        .flatten()
        .next()
        .map(|(_, failure)| *failure);
    state.proof.recovery_reason = Some(reason);
    // Independent recovery has its own immutable measured selection and sealed
    // roots4/5. It never recreates or resets the failed Root Custodian.
    // SAFETY: all old graph backing is retired; same retained controller/tables.
    unsafe {
        run_recovery(
            &mut state,
            &mut hardware,
            &mut storage[0],
            &recovery_manifest,
            &recovery_catalog,
            previous.unwrap().into(),
        );
    }
    let expected_faults = match fixture {
        Fixture::Nominal => 4,
        Fixture::Interrupted(_) => 1,
        Fixture::FatalExit | Fixture::Watchdog => 0,
    };
    assert_eq!(capsules.iter().flatten().count(), expected_faults);
    assert_eq!(custodian.recovery_required(), Some(reason));
    assert_eq!(
        custodian.phase(),
        ev_kernel::custodian::Phase::RecoveryRequired
    );
    assert!(custodian.begin(crate::timer::now()).is_err());
    assert_eq!(custodian.last_attempt(), 4);
    state.events.receiver_died(custody).unwrap();
    state.events.retire_empty(state.a).unwrap();
    state.recovery_events.receiver_died(custody).unwrap();
    state.recovery_events.retire_empty(state.a).unwrap();
    state.a.collect_lineage().unwrap();
    assert_eq!(state.a.metadata_usage(), (1, 6, 6, 6));
    assert_eq!(state.s.metadata_usage(), (1, 0, 0));
    assert_eq!(state.rpc.metadata_usage(), (0, 0, 0));
    assert_eq!(hardware.frames.remaining_frames(), before);
    for resource in [Resource::Frames, Resource::Processes, Resource::Threads] {
        assert_eq!(state.s.usage(boot_job, resource), Ok(0));
    }
    state.proof.frames_balanced = true;
    state.proof.metadata_balanced = state.baseline.is_some();
    state.proof.unique_active = true;
    state.proof.authority_equal = true;
    state.proof.graph_retired = true;
    state.proof.recovery_independent = true;
    negative.fault_records = state.proof.root_faults;
    negative.execution_admissions = state.execution_admissions;
    negative.graphs = state.proof.graphs;
    negative.service_starts = state.proof.service_starts;
    negative.service_replies = state.proof.service_replies;
    negative.accepted_transfers = state.proof.accepted_transfers;
    negative.rejected_transfers = state.proof.rejected_transfers;
    negative.invalidated_transfers = state.proof.invalidated_transfers;
    negative.failed_token = state.proof.failed_token;
    negative.recovery_reason = state.proof.recovery_reason;
    negative.held_targets = state.held_targets;
    negative.attempts = custodian.last_attempt();
    negative.restart_charges = custodian.last_attempt().saturating_sub(1);
    negative.active_incarnations = state.proof.incarnations;
    negative.recovery_entries = state.proof.recovery_entries;
    negative.no_duplicate = true;
    negative.budget_charged = state.proof.budget_latched;
    negative.retired = state.proof.graph_retired;
    negative.frames_balanced = state.proof.frames_balanced;
    assert_eq!((negative.attempts, negative.recovery_entries), (4, 1));
    let expected_active = match fixture {
        Fixture::Interrupted(Interruption::Confirmation) => 2,
        Fixture::Interrupted(_) => 1,
        Fixture::Nominal | Fixture::FatalExit | Fixture::Watchdog => 4,
    };
    assert_eq!(negative.active_incarnations, expected_active);
    let expected_admitted = match fixture {
        Fixture::Interrupted(Interruption::Activation | Interruption::Confirmation) => 2,
        Fixture::Interrupted(_) => 1,
        Fixture::Nominal | Fixture::FatalExit | Fixture::Watchdog => 4,
    };
    assert_eq!(negative.execution_admissions, expected_admitted);
    let expected_graphs = if matches!(fixture, Fixture::Interrupted(_)) {
        1
    } else {
        4
    };
    assert_eq!(
        (
            negative.graphs,
            negative.service_starts,
            negative.service_replies
        ),
        (expected_graphs, expected_graphs * 2, expected_graphs * 2)
    );
    assert_eq!(
        (
            negative.accepted_transfers,
            negative.rejected_transfers,
            negative.invalidated_transfers
        ),
        (expected_graphs, expected_graphs, expected_graphs)
    );
    match fixture {
        Fixture::FatalExit => assert_eq!(
            (
                negative.fatal_exits,
                negative.watchdogs,
                negative.interrupted
            ),
            (4, 0, 0)
        ),
        Fixture::Watchdog => assert_eq!(
            (
                negative.fatal_exits,
                negative.watchdogs,
                negative.interrupted
            ),
            (0, 4, 0)
        ),
        Fixture::Interrupted(_) => assert_eq!(
            (
                negative.fatal_exits,
                negative.watchdogs,
                negative.interrupted
            ),
            (0, 0, 1)
        ),
        Fixture::Nominal => (),
    }
    FixtureResult {
        nominal: state.proof,
        negative,
    }
}

unsafe fn run_recovery<'m>(
    state: &mut State<'_>,
    hw: &mut Hardware<'_>,
    slot: &mut LoadedImage,
    manifest: &'m bootstrap_manifest::Manifest<'m>,
    catalog: &'m [CatalogEntry],
    domains: RecoveryDomains,
) {
    let (branches, destination) = match domains {
        RecoveryDomains::Fresh => (
            state.a.create_space().unwrap(),
            state.a.create_space().unwrap(),
        ),
        RecoveryDomains::Reuse {
            branches,
            destination,
        } => (
            state.a.recycle_space(branches).unwrap(),
            state.a.recycle_space(destination).unwrap(),
        ),
    };
    let job = state
        .s
        .create_child_job(state.boot_job, manifest.limits())
        .unwrap();
    let process = state.s.create_held_process(job).unwrap();
    let thread = state.s.create_thread(process).unwrap();
    let mut binding = Bindings::new(state.epoch, manifest, state.custody, catalog);
    let token = binding
        .prepare(
            state.a,
            state.s,
            Target {
                process,
                job,
                destination,
                branches,
            },
        )
        .unwrap();
    let startup = binding.bootstrap_record(token).unwrap().unwrap();
    let plan = binding.executable(token).unwrap();
    state.s.charge_frames(job, plan.required_frames()).unwrap();
    // SAFETY: old graph has no live executable backing; independent measured
    // recovery target is held and owns this vacant slot and exclusive frames.
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
    let owner = ProcessImage {
        loaded: slot,
        process,
        frames: plan.required_frames(),
    };
    let mut active = binding
        .activate(state.a, state.s, token, thread, owner)
        .unwrap_or_else(|r| panic!("independent recovery admission: {:?}", r.error));
    let mut context = active.initial_context().unwrap();
    let mut fx = FxState::CLEAN;
    let mut ready = false;
    let mut stopped = false;
    // SAFETY: controller retains ordinary IRQ ownership, no old context runnable.
    unsafe {
        crate::timer::start_runtime();
    }
    for _ in 0..2048 {
        assert!(
            !state.global.reached(crate::timer::now()),
            "independent recovery deadline"
        );
        let dispatch = state.s.dispatch(0).unwrap().unwrap();
        assert_eq!((dispatch.process, dispatch.thread), (process, thread));
        active.image().loaded.root.activate();
        // SAFETY: exact independently admitted owned recovery root/context/FX;
        // common capture restores controller CR3/IF=0 before any mutation.
        let (mut frame, _) =
            unsafe { crate::user_runtime::resume_context(&context, &mut fx, hw.original) };
        match frame.vector {
            32 => state
                .s
                .charge_cpu(0, 1)
                .expect("recovery finite CPU budget"),
            128 => {
                frame.registers[14] = match decode(&frame) {
                    Ok(Call::Yield) => {
                        if ready {
                            stopped = true;
                        }
                        0
                    }
                    Ok(Call::Inspect { capability, rights }) => u64::from(
                        state
                            .a
                            .authorize(destination, capability, Kind::Memory, rights)
                            .is_err(),
                    ),
                    Ok(Call::Send {
                        endpoint,
                        value,
                        capability: None,
                    }) => {
                        let actual = state
                            .a
                            .authorize(destination, endpoint, Kind::Endpoint, Rights::SEND)
                            .map(|a| a.identity());
                        let expected = state
                            .a
                            .authorize(
                                state.custody,
                                state.roots[5],
                                Kind::Endpoint,
                                Rights::RECEIVE,
                            )
                            .unwrap()
                            .identity();
                        if ready
                            || actual != Ok(expected)
                            || Event::decode(&value.to_le_bytes()) != Some(Event::RecoveryReady)
                        {
                            3
                        } else {
                            let bytes = value.to_le_bytes();
                            state
                                .recovery_events
                                .send(
                                    state.a,
                                    destination,
                                    endpoint,
                                    Outgoing {
                                        bytes: &bytes,
                                        capability: None,
                                        deadline: state.global,
                                    },
                                    crate::timer::now(),
                                )
                                .unwrap();
                            let message = state
                                .recovery_events
                                .receive(
                                    state.a,
                                    state.custody,
                                    state.roots[5],
                                    crate::timer::now(),
                                )
                                .unwrap();
                            assert_eq!(
                                Event::decode(&message.bytes[..message.length]),
                                Some(Event::RecoveryReady)
                            );
                            ready = true;
                            state.proof.recovery_entries += 1;
                            0
                        }
                    }
                    Ok(Call::Exit(code)) => panic!("recovery artifact exit={code}"),
                    _ => 3,
                };
            }
            _ => panic!(
                "independent recovery fault vector={} ip={:#x}",
                frame.vector, frame.rip
            ),
        }
        if stopped {
            break;
        }
        context = frame;
        state.s.yield_cpu(0).unwrap();
    }
    // SAFETY: captured controller CR3 at IF=0, no user executes during retirement.
    unsafe {
        crate::timer::stop_runtime();
    }
    assert!(ready && stopped);
    active.revoke(state.a, state.s, token).unwrap();
    state.s.exit(0).unwrap();
    state.s.terminate_process(process).unwrap();
    let (_, lease) = active
        .finish(state.s, token)
        .unwrap_or_else(|_| panic!("recovery retained after stop"));
    let ProcessImage { loaded, .. } = lease;
    // SAFETY: actual recovery stopped, sole lease returned, controller CR3,
    // parked AP, event queue drained and no device or DMA authority exists.
    unsafe {
        assert_eq!(
            loaded.root.retire_in_place(hw.frames) as u64,
            plan.required_frames()
        );
    }
    state.s.release_frames(job, plan.required_frames()).unwrap();
    state.a.close_space(destination).unwrap();
    state.a.close_space(branches).unwrap();
    state.s.reclaim_process(process).unwrap();
    state.s.reclaim_job(job).unwrap();
}

struct Replacement {
    previous: Target,
    limits: Limits,
}
/// Interrupt the ACTUAL admitted second attempt, retaining all previous
/// Authority/Scheduler/RPC/Custodian generations and its charged restart budget.
unsafe fn interrupt_replacement<'m>(
    stage: Interruption,
    attempt: ev_kernel::custodian::Attempt,
    state: &mut State<'_>,
    hw: &mut Hardware<'_>,
    custodian: &mut Custodian<'m>,
    storage: &mut [LoadedImage; 3],
    replacement: Replacement,
) -> Target {
    let Replacement { previous, limits } = replacement;
    assert_eq!(attempt.number(), 2);
    assert_eq!(custodian.current(), None);
    assert_eq!(state.rpc.metadata_usage(), (0, 0, 0));
    assert_eq!(state.registry.metadata_usage(), (0, 1, 0, 4));
    if stage == Interruption::Admission {
        custodian.abandon_unprepared(attempt).unwrap();
        return previous;
    }
    let branches = state.a.recycle_space(previous.branches).unwrap();
    let destination = state.a.recycle_space(previous.destination).unwrap();
    let job = state.s.create_child_job(state.boot_job, limits).unwrap();
    let process = state.s.create_held_process(job).unwrap();
    state.held_targets += 1;
    let thread = state.s.create_thread(process).unwrap();
    let target = Target {
        job,
        process,
        branches,
        destination,
    };
    state
        .registry
        .register_job(state.a, state.custody, state.roots[2], job)
        .unwrap();
    // No old process is runnable; the newly constructed target remains held.
    for cpu in 0..ev_kernel::scheduler::MAX_CPUS {
        assert_eq!(state.s.dispatch(cpu), Ok(None));
    }
    if stage == Interruption::HeldTarget {
        assert_eq!(state.a.metadata_usage(), (5, 6, 6, 6));
        state.s.terminate_process(process).unwrap();
        state.a.close_space(destination).unwrap();
        state.a.close_space(branches).unwrap();
        state.s.reclaim_process(process).unwrap();
        state
            .registry
            .forget_job(state.a, state.s, state.rpc, job)
            .unwrap();
        custodian.abandon_unprepared(attempt).unwrap();
        return target;
    }
    let (mut binding, token) = custodian
        .prepare(attempt, state.a, state.s, target)
        .unwrap();
    assert_eq!(token.number(), 2);
    let grants: [Handle; 4] = binding.grants(token).unwrap().try_into().unwrap();
    let record = binding.bootstrap_record(token).unwrap().unwrap();
    assert_eq!(state.s.dispatch(0), Ok(None));
    if stage == Interruption::GrantPreparation {
        // SAFETY: target never left its scheduler hold and owns no physical
        // backing or external references; the binding owns all derived grants.
        unsafe {
            retire_prepared(state, hw, custodian, binding, token, target, None);
        }
        return target;
    }
    let plan = binding.executable(token).unwrap();
    state.s.charge_frames(job, plan.required_frames()).unwrap();
    let [root_slot, first, second] = storage.each_mut();
    // SAFETY: exact held measured Root target and physically empty private slot,
    // exclusive allocator/controller root and no dispatch has occurred.
    *root_slot = unsafe {
        LoadedImage::load_startup(
            hw.offset,
            hw.bits,
            hw.original & ADDRESS_MASK,
            &plan,
            Some(&record),
            hw.frames,
        )
    }
    .unwrap();
    let owner = ProcessImage {
        loaded: root_slot,
        process,
        frames: plan.required_frames(),
    };
    if stage == Interruption::ImageLoad {
        // SAFETY: image is actually loaded but never admitted/executed; its sole
        // typed owner and matching held binding are consumed by real retirement.
        unsafe {
            retire_prepared(state, hw, custodian, binding, token, target, Some(owner));
        }
        return target;
    }
    let root = binding
        .activate(state.a, state.s, token, thread, owner)
        .unwrap_or_else(|r| panic!("interrupted activation: {:?}", r.error));
    state.execution_admissions += 1;
    assert_eq!(
        state.s.state(thread),
        Ok(ev_kernel::scheduler::State::Ready)
    );
    if stage == Interruption::Confirmation {
        custodian.confirm_active(&root).unwrap();
        state.proof.incarnations += 1;
        state.proof.replacements += 1;
    } else {
        assert_eq!(stage, Interruption::Activation);
    }
    let context = root.initial_context().unwrap();
    let graph = Graph {
        root,
        target,
        thread,
        grants,
        children: [Child::new(first), Child::new(second)],
        jobs: [None; 2],
        channels: [const { None }; 4],
        contexts: [context, UserContext::ZERO, UserContext::ZERO],
        fx: [FxState::CLEAN; 3],
        pending: None,
        transport: RpcProof::default(),
        ready: false,
        responded: false,
        replies: [0; 2],
        transfer: None,
        captured: None,
        root_rpc_registered: false,
    };
    // SAFETY: admitted ownership is real but this attempt was never dispatched;
    // the same consuming graph path stops it and returns actual physical backing.
    let (binding, receipt, history) = unsafe { graph.quiesce(state, hw, custodian) };
    assert!(history.children.iter().all(Option::is_none));
    assert!(history.transfer_ticket.is_none());
    custodian
        .accept_quiescence(state.s, binding, receipt)
        .unwrap_or_else(|r| panic!("interrupted admitted receipt: {:?}", r.error));
    state.s.reclaim_process(process).unwrap();
    state
        .registry
        .forget_job(state.a, state.s, state.rpc, job)
        .unwrap();
    assert_eq!(state.a.metadata_usage(), (3, 6, 6, 6));
    assert_eq!(state.s.metadata_usage(), (1, 0, 0));
    target
}

/// Pre-activation counterpart to Graph::quiesce. The binding and optional
/// loaded owner remain uniquely retained until their held process is stopped.
unsafe fn retire_prepared<'m>(
    state: &mut State<'_>,
    hw: &mut Hardware<'_>,
    custodian: &mut Custodian<'m>,
    mut binding: Bindings<'m>,
    token: Token,
    target: Target,
    owner: Option<ProcessImage<'_>>,
) {
    custodian.begin_revocation(token).unwrap();
    binding.revoke(state.a, token).unwrap();
    assert_eq!(state.s.dispatch(0), Ok(None));
    state.s.terminate_process(target.process).unwrap();
    if let Some(owner) = owner {
        let charged = owner.frames;
        let ProcessImage { loaded, .. } = owner;
        // SAFETY: actual held image was never entered, controller CR3 current,
        // no IPC/device consumers, and its sole lease is consumed here.
        unsafe {
            assert_eq!(loaded.root.retire_in_place(hw.frames) as u64, charged);
        }
        state.s.release_frames(target.job, charged).unwrap();
    }
    state.a.close_space(target.destination).unwrap();
    state.a.close_space(target.branches).unwrap();
    state.a.collect_lineage().unwrap();
    assert_eq!(state.a.metadata_usage(), (3, 6, 6, 6));
    assert_eq!(state.rpc.metadata_usage(), (0, 0, 0));
    for resource in [Resource::Frames, Resource::Processes, Resource::Threads] {
        assert_eq!(state.s.usage(target.job, resource), Ok(0));
    }
    // PhysicalReceipt is private: all actual owned backing and grants are now
    // retired; only exact terminated scheduler metadata remains for BAC checking.
    custodian
        .accept_quiescence(state.s, binding, PhysicalReceipt(token))
        .unwrap_or_else(|r| panic!("interrupted prepared receipt: {:?}", r.error));
    state.s.reclaim_process(target.process).unwrap();
    state
        .registry
        .forget_job(state.a, state.s, state.rpc, target.job)
        .unwrap();
}
impl<'m, 's> Graph<'m, 's> {
    unsafe fn quiesce(
        mut self,
        state: &mut State<'_>,
        hw: &mut Hardware<'_>,
        custodian: &mut Custodian<'m>,
    ) -> (Bindings<'m>, PhysicalReceipt, History) {
        let token = self.root.token();
        let transfer = self.transfer.take();
        let history = History {
            token,
            target: self.target,
            thread: self.thread,
            grants: self.grants,
            children: core::array::from_fn(|i| {
                let child = &self.children[i];
                child.metadata.map(|metadata| OldChild {
                    metadata,
                    control: child.control,
                    object: child.object,
                    receive: child.receive,
                    call: child.last,
                })
            }),
            transfer_ticket: transfer.as_ref().map(|transfer| transfer.ticket),
        };
        custodian.begin_revocation(token).unwrap();
        self.root.revoke(state.a, state.s, token).unwrap();
        // Every running child is inhibited before any subsequent dispatch. Held
        // children already retain admission; Root-created unstarted Jobs are
        // retained independently in jobs[] for bottom-up metadata cleanup.
        for child in &mut self.children {
            if let Some(running) = child.running.as_mut() {
                running.stop(state.a, state.s).unwrap();
            }
        }
        for (i, kind, rights) in [
            (0, Kind::Memory, Rights::READ),
            (1, Kind::Endpoint, Rights::SEND),
            (2, Kind::Job, Rights::CONTROL),
            (3, Kind::Memory, Rights::READ),
        ] {
            assert_eq!(
                state
                    .a
                    .authorize(self.target.destination, self.grants[i], kind, rights)
                    .err(),
                Some(ev_kernel::capability::Error::Revoked)
            );
            assert!(
                state
                    .a
                    .authorize(state.custody, state.roots[i], kind, rights)
                    .is_ok()
            );
            state.proof.stale += 1;
        }
        for child in &self.children {
            if let (Some(meta), Some(receive)) = (child.metadata, child.receive) {
                assert_eq!(
                    state
                        .a
                        .authorize(meta.domain, receive, Kind::Endpoint, Rights::RECEIVE)
                        .err(),
                    Some(ev_kernel::capability::Error::Revoked)
                );
                state.proof.stale += 1;
            }
        }
        // Serialized acceptance/revocation ordering: a real userspace Process
        // move was accepted before failure. The next transfer loses to Root
        // revocation, leaves its source installed and cannot change the queue.
        if let Some(transfer) = transfer {
            let channel = self.channels[transfer.channel].as_mut().unwrap();
            assert_eq!(channel.mailbox.pending(), 1);
            let authority_before = state.a.metadata_usage();
            let bytes = [0u8; 8];
            assert_eq!(
                channel.mailbox.send(
                    state.a,
                    transfer.sender,
                    transfer.endpoint,
                    Outgoing {
                        bytes: &bytes,
                        capability: self.children[1].control,
                        deadline: state.global
                    },
                    crate::timer::now()
                ),
                Err(IpcError::Authority(ev_kernel::capability::Error::Revoked))
            );
            assert_eq!(state.a.metadata_usage(), authority_before);
            assert_eq!(channel.mailbox.pending(), 1);
            state.proof.rejected_transfers += 1;
            channel.mailbox.receiver_died(channel.receiver).unwrap();
            assert_eq!(
                channel.mailbox.reclaim(
                    state.a,
                    transfer.sender,
                    transfer.ticket,
                    crate::timer::now()
                ),
                Ok(Reclaimed::Invalidated)
            );
            assert_eq!(channel.mailbox.pending(), 0);
            state.proof.invalidated_transfers += 1;
        }
        // Root was the actual captured runner. Every other process is inhibited
        // and no AP has ever loaded these roots; retire all execution together.
        if let Some(captured) = self.captured
            && state.s.state(captured) == Ok(ev_kernel::scheduler::State::Running(0))
        {
            assert_eq!(state.s.exit(0), Ok(captured));
        }
        state.s.terminate_process(self.target.process).unwrap();
        for child in &self.children {
            if let Some(meta) = child.metadata {
                state.s.terminate_process(meta.process).unwrap();
            }
        }
        // Global shutdown never wakes an Exited old Root. Callee retirement
        // releases actual execution reservations before any peer is forgotten.
        if self.root_rpc_registered {
            state
                .rpc
                .peer_died(state.s, self.thread, crate::timer::now())
                .unwrap();
        }
        for child in &self.children {
            if let Some(meta) = child.metadata
                && child.rpc_registered
            {
                state
                    .rpc
                    .peer_died(state.s, meta.thread, crate::timer::now())
                    .unwrap();
            }
        }
        self.pending = None;
        assert_eq!(state.rpc.outstanding(), 0);
        for channel in self.channels.iter_mut().flatten() {
            channel.close(state.a, crate::timer::now()).unwrap();
            assert_eq!(channel.mailbox.pending(), 0);
        }
        for child in &mut self.children {
            let Some(meta) = child.metadata else {
                continue;
            };
            let loaded = if let Some(running) = child.running.take() {
                let ProcessImage { loaded, .. } = running
                    .finish(state.s)
                    .unwrap_or_else(|_| panic!("custody child retained after stop"));
                loaded
            } else {
                child.vacant.take().unwrap()
            };
            let was_loaded = loaded.root.root() != 0;
            // SAFETY: all contexts stopped, controller CR3 current, AP parked,
            // IPC/RPC drained, and the unique executable owner returned its lease.
            let reclaimed = unsafe { loaded.root.retire_in_place(hw.frames) };
            assert_eq!(reclaimed as u64, if was_loaded { meta.frames } else { 0 });
            state.s.release_frames(meta.job, meta.frames).unwrap();
            state
                .registry
                .retire_stopped(state.a, state.s, meta.process)
                .unwrap();
            child.vacant = Some(loaded);
        }
        state.a.close_space(self.target.destination).unwrap();
        state.a.close_space(self.target.branches).unwrap();
        for child in &self.children {
            if let Some(meta) = child.metadata {
                state
                    .registry
                    .forget_retired(state.a, state.s, meta.process)
                    .unwrap();
                if child.rpc_registered {
                    state.rpc.forget_thread(state.s, meta.thread).unwrap();
                }
                state.s.reclaim_process(meta.process).unwrap();
            }
        }
        if self.root_rpc_registered {
            state.rpc.forget_thread(state.s, self.thread).unwrap();
        }
        for (i, channel) in self.channels.iter_mut().enumerate() {
            if let Some(channel) = channel.take() {
                assert!(state.receipts[i].is_none());
                state.receipts[i] = Some(
                    channel
                        .mailbox
                        .retire_managed(state.a)
                        .unwrap_or_else(|r| panic!("managed channel retirement: {:?}", r.error)),
                );
            }
        }
        for job in self.jobs.into_iter().flatten() {
            state
                .registry
                .forget_job(state.a, state.s, state.rpc, job)
                .unwrap();
        }
        let (binding, lease) = self
            .root
            .finish(state.s, token)
            .unwrap_or_else(|_| panic!("custody Root retained after stop"));
        let root_frames = lease.frames;
        let ProcessImage { loaded, .. } = lease;
        // SAFETY: entire managed graph is stopped and drained; every child image
        // is scrubbed/released, Root's sole lease returned, original CR3 current.
        unsafe {
            assert_eq!(loaded.root.retire_in_place(hw.frames) as u64, root_frames);
        }
        state
            .s
            .release_frames(self.target.job, root_frames)
            .unwrap();
        for resource in [Resource::Frames, Resource::Processes, Resource::Threads] {
            assert_eq!(state.s.usage(self.target.job, resource), Ok(0));
        }
        assert_eq!(state.rpc.metadata_usage(), (0, 0, 0));
        state.a.collect_lineage().unwrap();
        assert_eq!(state.a.metadata_usage(), (3, 6, 6, 6));
        let (jobs, images, processes, pooled_domains) = state.registry.metadata_usage();
        assert_eq!((jobs, images, processes), (1, 1, 0));
        assert!(pooled_domains <= 4);
        // The remaining Root scheduler metadata is intentionally retained for
        // Custodian::accept_quiescence; it is not live authority or backing.
        (binding, PhysicalReceipt(token), history)
    }
}
