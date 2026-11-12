//! Supervisor-controlled child creation and generated userspace echo.
//! One retained development graph; no replacement/descriptors reuse claim yet.
use crate::{
    executable_runtime::{LoadedImage, ProcessImage},
    supervisor_runtime::bundle,
};
use core::{arch::asm, num::NonZeroU64};
use ev_kernel::{
    bootstrap_binding::CatalogEntry,
    bootstrap_manifest,
    capability::{Authority, Handle, Kind, Rights, SpaceId},
    fault::Record as FaultRecord,
    incarnation::{Bindings, Phase, Target},
    ipc::{Delivery, Error as IpcError, MAX_MESSAGES, Mailbox, Outgoing, Reclaimed, Ticket},
    mapping::ADDRESS_MASK,
    memory::BootstrapFrames,
    rpc::{CallId, Completion, Error as RpcError, MessageShape, Policy, Rpc, Status},
    scheduler::{Resource, Scheduler, ThreadId, WaitTicket},
    service::{Registry, Role, Running, SERVICE_LIMITS, ServiceImage},
    time::Deadline,
    user_context::{Call, FxState, UserContext, decode},
};
use ev_userspace_contract::{ABI, Event};
pub(crate) struct Channel {
    pub(crate) identity: usize,
    pub(crate) receiver: SpaceId,
    pub(crate) mailbox: Mailbox,
    pub(crate) tickets: [Option<(SpaceId, Ticket)>; MAX_MESSAGES],
}
impl Channel {
    fn send(
        &mut self,
        a: &mut Authority,
        sender: SpaceId,
        endpoint: ev_kernel::capability::Handle,
        value: u64,
        deadline: Deadline,
        now: u64,
    ) -> Result<(), IpcError> {
        self.send_ticket(a, sender, endpoint, value, deadline, now)
            .map(|_| ())
    }
    pub(crate) fn send_ticket(
        &mut self,
        a: &mut Authority,
        sender: SpaceId,
        endpoint: Handle,
        value: u64,
        deadline: Deadline,
        now: u64,
    ) -> Result<Ticket, IpcError> {
        let slot = self
            .tickets
            .iter()
            .position(Option::is_none)
            .ok_or(IpcError::Full)?;
        let bytes = value.to_le_bytes();
        let ticket = self.mailbox.send(
            a,
            sender,
            endpoint,
            Outgoing {
                bytes: &bytes,
                capability: None,
                deadline,
            },
            now,
        )?;
        self.tickets[slot] = Some((sender, ticket));
        Ok(ticket)
    }
    pub(crate) fn receive(
        &mut self,
        a: &mut Authority,
        owner: SpaceId,
        endpoint: ev_kernel::capability::Handle,
        now: u64,
    ) -> Result<Delivery, IpcError> {
        let delivery = self.mailbox.receive(a, owner, endpoint, now)?;
        let oldest = self
            .tickets
            .iter()
            .enumerate()
            .filter_map(|(i, t)| t.map(|(_, ticket)| (i, ticket.0)))
            .min_by_key(|&(_, sequence)| sequence)
            .expect("accepted channel message has a ticket")
            .0;
        self.tickets[oldest] = None;
        Ok(delivery)
    }
    pub(crate) fn close(&mut self, a: &mut Authority, now: u64) -> Result<usize, IpcError> {
        self.mailbox.receiver_died(self.receiver)?;
        let mut cancelled = 0;
        for entry in &mut self.tickets {
            if let Some((sender, ticket)) = entry.take() {
                // This transport accepts cap-free payloads only. Reclamation
                // uses the actual sender domain retained at queue acceptance.
                if a.is_live_space(sender) {
                    assert_eq!(
                        self.mailbox.reclaim(a, sender, ticket, now)?,
                        Reclaimed::NoCapability
                    );
                    cancelled += 1;
                }
            }
        }
        cancelled += self.mailbox.reap_dead_senders(a, now)?;
        Ok(cancelled)
    }
    pub(crate) fn reclaim(
        &mut self,
        a: &mut Authority,
        sender: SpaceId,
        ticket: Ticket,
        now: u64,
    ) -> Result<(), IpcError> {
        let slot = self
            .tickets
            .iter()
            .position(|t| *t == Some((sender, ticket)))
            .ok_or(IpcError::InvalidTicket)?;
        match self.mailbox.reclaim(a, sender, ticket, now)? {
            Reclaimed::NoCapability => {
                self.tickets[slot] = None;
                Ok(())
            }
            _ => Err(IpcError::NotReclaimable),
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct RpcProof {
    pub successes: u64,
    pub blocks: u64,
    pub wakes: u64,
    pub denied: u64,
    pub expired: u64,
    pub timeouts: u64,
    pub busy: u64,
    pub late: u64,
    pub stale: u64,
    pub frames_balanced: bool,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Async,
    Fault,
    Rpc,
    RpcTimeout,
}
pub(crate) struct PendingCall {
    pub(crate) id: CallId,
    pub(crate) caller: ThreadId,
    pub(crate) callee: ThreadId,
    pub(crate) wait: WaitTicket,
    pub(crate) waiting: bool,
    pub(crate) request: Ticket,
    pub(crate) delivered: bool,
}
fn rpc_status(status: Status) -> u64 {
    match status {
        Status::Ok => 0,
        Status::DeadlineExceeded => 4,
        Status::PeerDied => 5,
        Status::Cancelled => 6,
    }
}
pub(crate) fn notify(
    event: Completion,
    scheduler: &mut Scheduler,
    pending: &mut Option<PendingCall>,
    caller: &mut UserContext,
    proof: &mut RpcProof,
    deadline_wake: bool,
) {
    let Some(wait) = pending
        .as_mut()
        .filter(|p| p.id == event.call && p.caller == event.caller && p.waiting)
    else {
        return;
    };
    if !event.wake_caller {
        return;
    }
    caller.registers[14] = rpc_status(event.status);
    caller.registers[9] = 0;
    caller.registers[11] = 0;
    if deadline_wake {
        // scheduler.advance below performs this exact wait's deadline transition.
        assert!(scheduler.waiting(wait.wait));
    } else {
        assert!(scheduler.wake(wait.wait));
    }
    wait.waiting = false;
    proof.wakes += 1;
    if event.status == Status::DeadlineExceeded {
        proof.timeouts += 1;
    }
}
pub(crate) fn expire(
    rpc: &mut Rpc,
    scheduler: &mut Scheduler,
    pending: &mut Option<PendingCall>,
    caller: &mut UserContext,
    proof: &mut RpcProof,
    now: u64,
) {
    for event in rpc
        .expire(now)
        .expect("serialized monotonic RPC clock")
        .iter()
        .copied()
    {
        notify(event, scheduler, pending, caller, proof, true);
    }
    scheduler
        .advance(now)
        .expect("serialized monotonic scheduler clock");
}

/// # Safety
/// Serialized BSP, IF=0, AP parked, retained direct map and exclusive frames;
/// initialized ordinary user trap/FX/PIC boundary. No other user process runs.
pub unsafe fn prove(offset: u64, frames: &mut BootstrapFrames) {
    // SAFETY: independent graphs are fully stopped/retired before the next one.
    unsafe {
        run(offset, frames, Scenario::Async);
        run(offset, frames, Scenario::Fault);
    }
}
/// Actual generated userspace synchronous calls, followed by an independent
/// accepted-timeout/late-reply graph. These are not the complete AF-IPC gate.
/// # Safety
/// Same retained BSP/direct-map/IRQ ownership as prove; each graph retires fully.
pub unsafe fn prove_rpc(offset: u64, frames: &mut BootstrapFrames) -> (RpcProof, RpcProof) {
    // SAFETY: both independent graphs preserve prove's serialized hardware ownership.
    unsafe {
        (
            run(offset, frames, Scenario::Rpc),
            run(offset, frames, Scenario::RpcTimeout),
        )
    }
}
/// # Safety
/// Same controller ownership and hardware preconditions as prove().
unsafe fn run(offset: u64, frames: &mut BootstrapFrames, scenario: Scenario) -> RpcProof {
    let inject_fault = scenario == Scenario::Fault;
    let rpc_mode = matches!(scenario, Scenario::Rpc | Scenario::RpcTimeout);
    let mut proof = RpcProof::default();
    assert!(!bundle::GRAPH_IMAGE.is_empty() && !bundle::ECHO_IMAGE.is_empty());
    let (root_image, root_manifest, root_sha, echo_image, echo_sha) =
        if scenario == Scenario::RpcTimeout {
            (
                bundle::GRAPH_RPC_TIMEOUT_IMAGE,
                bundle::GRAPH_RPC_TIMEOUT_MANIFEST,
                bundle::GRAPH_RPC_TIMEOUT_MEASUREMENT,
                bundle::ECHO_DELAY_IMAGE,
                bundle::ECHO_DELAY_SHA,
            )
        } else if rpc_mode {
            (
                bundle::GRAPH_RPC_IMAGE,
                bundle::GRAPH_RPC_MANIFEST,
                bundle::GRAPH_RPC_MEASUREMENT,
                bundle::ECHO_IMAGE,
                bundle::ECHO_SHA,
            )
        } else if inject_fault {
            (
                bundle::GRAPH_FAULT_IMAGE,
                bundle::GRAPH_FAULT_MANIFEST,
                bundle::GRAPH_FAULT_MEASUREMENT,
                bundle::ECHO_FAULT_IMAGE,
                bundle::ECHO_FAULT_SHA,
            )
        } else {
            (
                bundle::GRAPH_IMAGE,
                bundle::GRAPH_MANIFEST,
                bundle::GRAPH_MEASUREMENT,
                bundle::ECHO_IMAGE,
                bundle::ECHO_SHA,
            )
        };
    // Distinct deterministic fixture epochs keep the two Rpc allocators' call
    // identities disjoint; production boot-epoch generation remains separate.
    let epoch = NonZeroU64::new(match scenario {
        Scenario::Rpc => 103,
        Scenario::RpcTimeout => 104,
        _ => 102,
    })
    .unwrap();
    let manifest = bootstrap_manifest::verify(root_manifest, root_sha, root_image, ABI).unwrap();
    let mut authority = Authority::new();
    let custody = authority.create_space().unwrap();
    let branches = authority.create_space().unwrap();
    let root_domain = authority.create_space().unwrap();
    let common = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE;
    let probe = authority
        .create_root(custody, Kind::Memory, common | Rights::READ)
        .unwrap();
    let events = authority
        .create_root(
            custody,
            Kind::Endpoint,
            common | Rights::SEND | Rights::RECEIVE | Rights::CONTROL,
        )
        .unwrap();
    let creator = authority
        .create_root(custody, Kind::Job, common | Rights::READ | Rights::CONTROL)
        .unwrap();
    let executable = authority
        .create_root(custody, Kind::Memory, common | Rights::READ)
        .unwrap();
    let catalog = [
        CatalogEntry {
            selector: 1,
            root: probe,
            kind: Kind::Memory,
        },
        CatalogEntry {
            selector: 2,
            root: events,
            kind: Kind::Endpoint,
        },
        CatalogEntry {
            selector: 3,
            root: creator,
            kind: Kind::Job,
        },
        CatalogEntry {
            selector: 4,
            root: executable,
            kind: Kind::Memory,
        },
    ];
    let mut event_mailbox = Mailbox::new(&mut authority, custody, events).unwrap();
    let mut scheduler = Scheduler::new();
    let root_job = scheduler.create_job_with_limits(manifest.limits()).unwrap();
    let root_process = scheduler.create_held_process(root_job).unwrap();
    let root_thread = scheduler.create_thread(root_process).unwrap();
    let mut registry = Registry::for_incarnation(NonZeroU64::new(1).unwrap());
    registry
        .register_job(&authority, custody, creator, root_job)
        .unwrap();
    let service = ServiceImage::verify(
        echo_image,
        echo_sha,
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
    .unwrap();
    registry
        .register_image(&authority, custody, executable, service)
        .unwrap();
    let mut binding = Bindings::new(epoch, &manifest, custody, &catalog);
    let token = binding
        .prepare(
            &mut authority,
            &scheduler,
            Target {
                process: root_process,
                job: root_job,
                branches,
                destination: root_domain,
            },
        )
        .unwrap();
    let image = binding.executable(token).unwrap();
    let startup = binding.bootstrap_record(token).unwrap().unwrap();
    scheduler
        .charge_frames(root_job, image.required_frames())
        .unwrap();
    let original: u64;
    // SAFETY: privileged read of retained controller CR3; no active user entry.
    unsafe {
        asm!("mov {}, cr3",out(reg)original,options(nomem,nostack,preserves_flags));
    }
    let bits = (core::arch::x86_64::__cpuid(0x80000008).eax & 255) as u8;
    let before = frames.remaining_frames();
    // SAFETY: immutable measured plan/token record, exclusive inactive backing.
    let mut root_loaded = unsafe {
        LoadedImage::load_startup(
            offset,
            bits,
            original & ADDRESS_MASK,
            &image,
            Some(&startup),
            frames,
        )
    }
    .unwrap();
    let root_lease = ProcessImage {
        loaded: &mut root_loaded,
        process: root_process,
        frames: image.required_frames(),
    };
    let mut root = binding
        .activate(&authority, &mut scheduler, token, root_thread, root_lease)
        .unwrap_or_else(|r| panic!("service Root activation: {:?}", r.error));
    let mut rpc = Rpc::new(epoch);
    if rpc_mode {
        rpc.register_thread(
            &authority,
            &scheduler,
            root_thread,
            root_job,
            root_domain,
            Some(token),
        )
        .unwrap();
    }
    let mut child_storage = None;
    let (meta, child_frames) = {
        // Move the one initialization reference into admission once. Loaded backing
        // stays in this controller slot; Result/Running move only its small lease.
        let mut insertion = Some(&mut child_storage);
        let mut contexts = [root.initial_context().unwrap(), UserContext::ZERO];
        let mut fx = [FxState::CLEAN; 2];
        let mut child: Option<Running<ProcessImage<'_>>> = None;
        let mut retired = None;
        let mut child_metadata = None;
        let mut fault_record = None;
        let mut exit_code = None;
        let mut channels: [Option<Channel>; 2] = [None, None];
        let (mut ready, mut completed, mut requests, mut responses) = (0, 0, 0, 0);
        let (mut control_denied, mut service_denied, mut jobs, mut processes, mut delegated) =
            (0, 0, 0, 0, 0);
        let mut child_frames = 0;
        let mut event_denied = 0;
        let mut cancelled = 0;
        let mut pending: Option<PendingCall> = None;
        let mut last_call: Option<(CallId, WaitTicket)> = None;
        let mut rpc_request = None;
        let mut rpc_response = None;
        let deadline = Deadline::after(crate::timer::now(), 100).unwrap();
        let mut stopped = false;
        // SAFETY: exclusive initialized PIC at IF=0; IRET enables bounded user ticks.
        unsafe {
            crate::timer::start_runtime();
        }
        for _ in 0..if rpc_mode { 8192 } else { 512 } {
            if rpc_mode {
                expire(
                    &mut rpc,
                    &mut scheduler,
                    &mut pending,
                    &mut contexts[0],
                    &mut proof,
                    crate::timer::now(),
                );
            }
            assert!(
                !deadline.reached(crate::timer::now()),
                "service graph deadline"
            );
            let dispatch = scheduler.dispatch(0).unwrap().unwrap();
            let (index, domain) = if dispatch.process == root_process {
                assert_eq!(dispatch.thread, root_thread);
                root.image().loaded.root.activate();
                (0, root_domain)
            } else {
                let owner = child
                    .as_ref()
                    .expect("held child dispatched before admission");
                let meta = owner.metadata();
                assert_eq!(
                    (dispatch.process, dispatch.thread),
                    (meta.process, meta.thread)
                );
                owner.image().loaded.root.activate();
                (1, meta.domain)
            };
            // SAFETY: selected owned root/context/FX state remain live. Runner
            // restores controller CR3 at IF=0 before every mutation below.
            let (mut frame, address) = unsafe {
                crate::user_runtime::resume_context(&contexts[index], &mut fx[index], original)
            };
            if rpc_mode {
                expire(
                    &mut rpc,
                    &mut scheduler,
                    &mut pending,
                    &mut contexts[0],
                    &mut proof,
                    crate::timer::now(),
                );
            }
            let mut retire_current = false;
            let mut blocked_current = false;
            match frame.vector {
                32 => scheduler.charge_cpu(0, 1).expect("service CPU budget"),
                128 => {
                    frame.registers[14] = match decode(&frame) {
                        Ok(Call::Yield) => {
                            if index == 0 && completed == 1 {
                                stopped = true;
                            }
                            0
                        }
                        Ok(Call::Inspect { capability, rights }) => {
                            if authority
                                .authorize(domain, capability, Kind::Memory, rights)
                                .is_ok()
                            {
                                0
                            } else {
                                if index == 1 {
                                    service_denied += 1;
                                }
                                1
                            }
                        }
                        Ok(Call::Send {
                            endpoint,
                            value,
                            capability: None,
                        }) => {
                            match authority
                                .authorize(domain, endpoint, Kind::Endpoint, Rights::SEND)
                                .map(|a| a.identity())
                            {
                                Err(_) => {
                                    if index == 1 {
                                        service_denied += 1;
                                    }
                                    1
                                }
                                Ok(identity) => {
                                    let payload = value.to_le_bytes();
                                    let outgoing = Outgoing {
                                        bytes: &payload,
                                        capability: None,
                                        deadline,
                                    };
                                    if identity
                                        == authority
                                            .authorize(
                                                custody,
                                                events,
                                                Kind::Endpoint,
                                                Rights::RECEIVE,
                                            )
                                            .unwrap()
                                            .identity()
                                    {
                                        let event = Event::decode(&payload);
                                        let permitted = index == 0
                                            && match event {
                                                Some(Event::Ready) => ready == 0 && completed == 0,
                                                Some(Event::ServiceResponded) => {
                                                    ready == 1
                                                        && completed == 0
                                                        && child.is_some()
                                                        && if rpc_mode {
                                                            proof.successes
                                                                == if scenario
                                                                    == Scenario::RpcTimeout
                                                                {
                                                                    4
                                                                } else {
                                                                    3
                                                                }
                                                                && rpc.outstanding() == 0
                                                                && pending.is_none()
                                                        } else {
                                                            requests == 3 && responses == 3
                                                        }
                                                }
                                                Some(Event::ServiceStopped) => {
                                                    ready == 1
                                                        && completed == 0
                                                        && retired.is_some()
                                                        && requests > 0
                                                        && responses <= requests
                                                }
                                                _ => false,
                                            };
                                        if !permitted {
                                            event_denied += 1;
                                            frame.registers[14] = 3;
                                            contexts[index] = frame;
                                            scheduler.yield_cpu(0).unwrap();
                                            continue;
                                        }
                                        event_mailbox
                                            .send(
                                                &mut authority,
                                                domain,
                                                endpoint,
                                                outgoing,
                                                crate::timer::now(),
                                            )
                                            .unwrap();
                                        let event = event_mailbox
                                            .receive(
                                                &mut authority,
                                                custody,
                                                events,
                                                crate::timer::now(),
                                            )
                                            .unwrap();
                                        match Event::decode(&event.bytes[..event.length]) {
                                            Some(Event::Ready) => {
                                                ready += 1;
                                                assert_eq!(ready, 1);
                                            }
                                            Some(Event::ServiceResponded) => {
                                                completed += 1;
                                                assert_eq!(completed, 1);
                                            }
                                            Some(Event::ServiceStopped) => {
                                                completed += 1;
                                                assert_eq!(completed, 1);
                                            }
                                            _ => panic!("malformed service graph event"),
                                        }
                                        0
                                    } else if let Some(channel) = channels
                                        .iter_mut()
                                        .flatten()
                                        .find(|c| c.identity == identity)
                                    {
                                        if rpc_mode && Some(identity) == rpc_response {
                                            if index != 1 {
                                                1
                                            } else if let Some(wait) =
                                                pending.as_ref().filter(|p| {
                                                    p.callee == dispatch.thread
                                                        && p.delivered
                                                        && rpc.serving(dispatch.thread)
                                                            == Some(p.id)
                                                })
                                            {
                                                let id = wait.id;
                                                // Explicit test transport backpressure holds the
                                                // first late response until the real caller has
                                                // exercised the retained non-reentrant reservation.
                                                // This removes a scheduling race in the proof: a
                                                // fast late completion could otherwise precede that
                                                // probe. No response is accepted or reservation freed.
                                                if scenario == Scenario::RpcTimeout
                                                    && !wait.waiting
                                                    && proof.busy == 0
                                                {
                                                    2
                                                } else {
                                                    match rpc.complete(
                                                        dispatch.thread,
                                                        id,
                                                        crate::timer::now(),
                                                    ) {
                                                        Ok(event) => {
                                                            let wait = pending.take().unwrap();
                                                            assert_eq!(
                                                                (event.call, event.caller),
                                                                (wait.id, wait.caller)
                                                            );
                                                            if event.deliver_reply {
                                                                assert!(
                                                                    wait.waiting
                                                                        && event.wake_caller
                                                                );
                                                                contexts[0].registers[14] = 0;
                                                                contexts[0].registers[9] = value;
                                                                contexts[0].registers[11] = 0;
                                                                assert!(scheduler.wake(wait.wait));
                                                                proof.successes += 1;
                                                                proof.wakes += 1;
                                                            } else {
                                                                // A late callee acknowledgement releases execution,
                                                                // but cannot deliver data or wake a newer wait.
                                                                assert!(
                                                                    !wait.waiting
                                                                        && !event.wake_caller
                                                                );
                                                                proof.late += 1;
                                                            }
                                                            last_call = Some((wait.id, wait.wait));
                                                            responses += 1;
                                                            0
                                                        }
                                                        Err(_) => 3,
                                                    }
                                                }
                                            } else {
                                                3
                                            }
                                        } else if rpc_mode && Some(identity) == rpc_request {
                                            // A synchronous endpoint cannot be bypassed through raw async Send.
                                            3
                                        } else {
                                            match channel.send(
                                                &mut authority,
                                                domain,
                                                endpoint,
                                                value,
                                                deadline,
                                                crate::timer::now(),
                                            ) {
                                                Ok(_) => {
                                                    if index == 0 {
                                                        requests += 1;
                                                    } else {
                                                        responses += 1;
                                                    }
                                                    0
                                                }
                                                Err(IpcError::Full) => 2,
                                                Err(_) => 1,
                                            }
                                        }
                                    } else {
                                        1
                                    }
                                }
                            }
                        }
                        Ok(Call::Receive(endpoint)) => {
                            match authority
                                .authorize(domain, endpoint, Kind::Endpoint, Rights::RECEIVE)
                                .map(|a| a.identity())
                            {
                                Err(_) => {
                                    if index == 1 {
                                        service_denied += 1;
                                    }
                                    1
                                }
                                Ok(identity) => match channels
                                    .iter_mut()
                                    .flatten()
                                    .find(|c| c.identity == identity)
                                {
                                    Some(channel) => match channel.receive(
                                        &mut authority,
                                        domain,
                                        endpoint,
                                        crate::timer::now(),
                                    ) {
                                        Ok(delivery) => {
                                            if rpc_mode && Some(identity) == rpc_request {
                                                let wait = pending.as_mut().filter(|p| p.callee == dispatch.thread && !p.delivered && rpc.serving(dispatch.thread) == Some(p.id)).expect("only protected RPC requests enter this channel");
                                                wait.delivered = true;
                                            }
                                            assert_eq!(delivery.length, 8);
                                            frame.registers[9] = u64::from_le_bytes(
                                                delivery.bytes[..8].try_into().unwrap(),
                                            );
                                            frame.registers[11] =
                                                delivery.capability.map_or(0, |h| h.0);
                                            0
                                        }
                                        Err(IpcError::Empty) => 2,
                                        Err(IpcError::Expired)
                                            if rpc_mode && Some(identity) == rpc_request =>
                                        {
                                            // The actual callee acknowledges a queued request that
                                            // expired before dispatch. It never sees expired payload.
                                            if let Some(wait) = pending.as_ref().filter(|p| {
                                                p.callee == dispatch.thread
                                                    && !p.delivered
                                                    && !p.waiting
                                            }) {
                                                let id = wait.id;
                                                let ticket = wait.request;
                                                if channel
                                                    .reclaim(
                                                        &mut authority,
                                                        root_domain,
                                                        ticket,
                                                        crate::timer::now(),
                                                    )
                                                    .is_ok()
                                                {
                                                    let event = rpc
                                                        .complete(
                                                            dispatch.thread,
                                                            id,
                                                            crate::timer::now(),
                                                        )
                                                        .unwrap();
                                                    let wait = pending.take().unwrap();
                                                    assert!(
                                                        !event.deliver_reply && !event.wake_caller
                                                    );
                                                    last_call = Some((wait.id, wait.wait));
                                                    2
                                                } else {
                                                    1
                                                }
                                            } else {
                                                2
                                            }
                                        }
                                        Err(_) => {
                                            if index == 1 {
                                                service_denied += 1;
                                            }
                                            1
                                        }
                                    },
                                    None => 1,
                                },
                            }
                        }
                        Ok(Call::CreateJob { creator, template }) => match registry.create_job(
                            &mut authority,
                            &mut scheduler,
                            domain,
                            creator,
                            template,
                        ) {
                            Ok(cap) => {
                                frame.registers[9] = cap.0;
                                jobs += 1;
                                0
                            }
                            Err(_) => {
                                control_denied += 1;
                                1
                            }
                        },
                        Ok(Call::CreateProcess { job, image }) => {
                            if processes != 0 {
                                2
                            } else {
                                match registry.create_process(
                                    &mut authority,
                                    &mut scheduler,
                                    domain,
                                    job,
                                    image,
                                ) {
                                    Ok(cap) => {
                                        frame.registers[9] = cap.0;
                                        processes += 1;
                                        0
                                    }
                                    Err(_) => {
                                        control_denied += 1;
                                        1
                                    }
                                }
                            }
                        }
                        Ok(Call::Close(cap)) => match authority.close(domain, cap) {
                            Ok(()) => 0,
                            Err(_) => 1,
                        },
                        Ok(Call::CreateEndpoint(creator)) => {
                            if let Some(slot) = channels.iter_mut().find(|c| c.is_none()) {
                                match registry.create_channel(&mut authority, domain, creator) {
                                    Ok((cap, mailbox)) => {
                                        let identity = authority
                                            .authorize(domain, cap, Kind::Endpoint, Rights::CONTROL)
                                            .unwrap()
                                            .identity();
                                        *slot = Some(Channel {
                                            identity,
                                            receiver: domain,
                                            mailbox,
                                            tickets: [None; MAX_MESSAGES],
                                        });
                                        frame.registers[9] = cap.0;
                                        0
                                    }
                                    Err(_) => {
                                        control_denied += 1;
                                        1
                                    }
                                }
                            } else {
                                2
                            }
                        }
                        Ok(Call::Delegate {
                            process,
                            source,
                            selector,
                        }) => {
                            match registry.delegate(
                                &mut authority,
                                domain,
                                process,
                                source,
                                selector,
                            ) {
                                Ok(_) => {
                                    delegated += 1;
                                    frame.registers[9] = 0;
                                    0
                                }
                                Err(_) => {
                                    control_denied += 1;
                                    1
                                }
                            }
                        }
                        Ok(Call::BindReceiver { endpoint, process }) => {
                            let setup = (|| -> Result<_, ev_kernel::service::Error> {
                                let meta = registry.metadata(&authority, domain, process)?;
                                let receive = registry.grant(&authority, domain, process, 3)?;
                                let identity = authority
                                    .authorize(domain, endpoint, Kind::Endpoint, Rights::CONTROL)?
                                    .identity();
                                Ok((meta, receive, identity))
                            })();
                            match setup {
                                Ok((meta, receive, identity)) => match channels
                                    .iter_mut()
                                    .flatten()
                                    .find(|c| c.identity == identity)
                                {
                                    Some(channel) => match channel.mailbox.rebind_empty(
                                        &authority,
                                        domain,
                                        endpoint,
                                        meta.domain,
                                        receive,
                                    ) {
                                        Ok(()) => {
                                            channel.receiver = meta.domain;
                                            0
                                        }
                                        Err(_) => 1,
                                    },
                                    None => 1,
                                },
                                Err(_) => 1,
                            }
                        }
                        Ok(Call::Start(process)) => {
                            if let Ok(record) = registry.startup(&authority, domain, process, epoch)
                            {
                                assert!(child.is_none());
                                let meta = registry.metadata(&authority, domain, process).unwrap();
                                let plan = registry.plan(&authority, domain, process).unwrap();
                                let rpc_route = if rpc_mode {
                                    let setup = (|| -> Result<_, ev_kernel::service::Error> {
                                        let receive =
                                            registry.grant(&authority, domain, process, 3)?;
                                        let send =
                                            registry.grant(&authority, domain, process, 4)?;
                                        let request = authority
                                            .authorize(
                                                meta.domain,
                                                receive,
                                                Kind::Endpoint,
                                                Rights::RECEIVE | Rights::CONTROL,
                                            )?
                                            .identity();
                                        let response = authority
                                            .authorize(
                                                meta.domain,
                                                send,
                                                Kind::Endpoint,
                                                Rights::SEND,
                                            )?
                                            .identity();
                                        if request == response
                                            || !channels.iter().flatten().any(|c| {
                                                c.identity == request
                                                    && c.receiver == meta.domain
                                                    && c.mailbox.pending() == 0
                                            })
                                            || !channels.iter().flatten().any(|c| {
                                                c.identity == response
                                                    && c.receiver == root_domain
                                                    && c.mailbox.pending() == 0
                                            })
                                        {
                                            return Err(ev_kernel::service::Error::Descriptor);
                                        }
                                        Ok((request, response, receive))
                                    })();
                                    match setup {
                                        Ok(route) => Some(route),
                                        Err(_) => {
                                            control_denied += 1;
                                            frame.registers[14] = 1;
                                            contexts[index] = frame;
                                            scheduler.yield_cpu(0).unwrap();
                                            continue;
                                        }
                                    }
                                } else {
                                    None
                                };
                                // SAFETY: held service, immutable plan/record, exclusive
                                // allocator and retained inactive controller root.
                                let loaded = unsafe {
                                    LoadedImage::load_startup(
                                        offset,
                                        bits,
                                        original & ADDRESS_MASK,
                                        &plan,
                                        Some(&record),
                                        frames,
                                    )
                                }
                                .unwrap();
                                assert_ne!(loaded.root.root(), root.image().loaded.root.root());
                                let slot = insertion
                                    .take()
                                    .expect("service image slot already initialized");
                                *slot = Some(loaded);
                                let owner = ProcessImage {
                                    loaded: slot.as_mut().unwrap(),
                                    process: meta.process,
                                    frames: meta.frames,
                                };
                                let running = registry
                                    .start(
                                        &authority,
                                        &mut scheduler,
                                        domain,
                                        process,
                                        epoch,
                                        owner,
                                    )
                                    .unwrap_or_else(|r| panic!("service admission: {:?}", r.error));
                                if let Some((request, response, receive)) = rpc_route {
                                    // Registration follows actual admission; held-service preflight
                                    // established exact route ownership and fixed slot capacity.
                                    rpc.register_thread(
                                        &authority,
                                        &scheduler,
                                        meta.thread,
                                        meta.job,
                                        meta.domain,
                                        Some(token),
                                    )
                                    .unwrap();
                                    rpc.bind_endpoint(
                                        &authority,
                                        meta.domain,
                                        receive,
                                        meta.thread,
                                        Policy::new(8, 0).unwrap(),
                                    )
                                    .unwrap();
                                    rpc_request = Some(request);
                                    rpc_response = Some(response);
                                }
                                contexts[1] = running.initial_context().unwrap();
                                child_metadata = Some(meta);
                                child_frames = meta.frames;
                                child = Some(running);
                                0
                            } else {
                                control_denied += 1;
                                1
                            }
                        }
                        Ok(Call::Observe(process)) => {
                            match registry.observe(&authority, &scheduler, domain, process) {
                                Ok(done) => {
                                    frame.registers[9] = u64::from(done);
                                    0
                                }
                                Err(_) => 1,
                            }
                        }
                        Ok(Call::Exit(code)) if index == 1 => {
                            exit_code = Some(code);
                            retire_current = true;
                            0
                        }
                        Ok(Call::Exit(code)) => {
                            panic!("supervisor graph exited unexpectedly {code}")
                        }
                        Ok(Call::Monotonic) => {
                            frame.registers[9] = crate::timer::now();
                            0
                        }
                        Ok(Call::RpcDeadline) if rpc_mode => {
                            match rpc
                                .serving(dispatch.thread)
                                .and_then(|id| rpc.context(id).ok())
                            {
                                Some(context) => {
                                    frame.registers[9] = context.deadline.tick();
                                    0
                                }
                                None => 1,
                            }
                        }
                        Ok(Call::Rpc {
                            endpoint,
                            value,
                            deadline: absolute,
                        }) if rpc_mode => {
                            let now = crate::timer::now();
                            let resolved = authority
                                .authorize(domain, endpoint, Kind::Endpoint, Rights::SEND)
                                .map(|a| a.identity());
                            if index != 0 || resolved.is_err() || resolved.ok() != rpc_request {
                                proof.denied += 1;
                                1
                            } else if absolute <= now {
                                proof.expired += 1;
                                4
                            } else if absolute > deadline.tick() {
                                3
                            } else if let Some(channel) = channels
                                .iter_mut()
                                .flatten()
                                .find(|c| Some(c.identity) == rpc_request)
                            {
                                let call_deadline = Deadline::after(0, absolute).unwrap();
                                if channel.mailbox.pending() != 0 {
                                    proof.busy += 1;
                                    2
                                } else if scheduler.check_block(0, call_deadline).is_err() {
                                    1
                                } else {
                                    match rpc.begin(
                                        &authority,
                                        dispatch.thread,
                                        endpoint,
                                        call_deadline,
                                        MessageShape {
                                            bytes: 8,
                                            capabilities: 0,
                                        },
                                        now,
                                    ) {
                                        Err(RpcError::WouldBlock | RpcError::AlreadyWaiting) => {
                                            proof.busy += 1;
                                            2
                                        }
                                        Err(RpcError::DeadlineExceeded) => {
                                            proof.expired += 1;
                                            4
                                        }
                                        Err(RpcError::PeerDied) => 5,
                                        Err(RpcError::Cancelled) => 6,
                                        Err(_) => {
                                            proof.denied += 1;
                                            1
                                        }
                                        Ok(id) => match channel.send_ticket(
                                            &mut authority,
                                            domain,
                                            endpoint,
                                            value,
                                            call_deadline,
                                            now,
                                        ) {
                                            Err(_) => {
                                                // Nothing was accepted by transport or scheduler. A
                                                // cancelled, undispatched reservation is acknowledged
                                                // under this same controller before returning failure.
                                                rpc.cancel(dispatch.thread, id, now).unwrap();
                                                rpc.complete(
                                                    child.as_ref().unwrap().metadata().thread,
                                                    id,
                                                    now,
                                                )
                                                .unwrap();
                                                2
                                            }
                                            Ok(request) => {
                                                // check_block covered every fallible scheduler condition;
                                                // no scheduler mutation intervened under serialized IF=0.
                                                let wait =
                                                    scheduler.block(0, call_deadline).unwrap();
                                                if let Some((old, old_wait)) = last_call {
                                                    assert_eq!(
                                                        rpc.complete(
                                                            child
                                                                .as_ref()
                                                                .unwrap()
                                                                .metadata()
                                                                .thread,
                                                            old,
                                                            now
                                                        ),
                                                        Err(RpcError::StaleCall)
                                                    );
                                                    assert!(!scheduler.wake(old_wait));
                                                    assert!(scheduler.waiting(wait));
                                                    proof.stale += 1;
                                                }
                                                pending = Some(PendingCall {
                                                    id,
                                                    caller: dispatch.thread,
                                                    callee: child
                                                        .as_ref()
                                                        .unwrap()
                                                        .metadata()
                                                        .thread,
                                                    wait,
                                                    waiting: true,
                                                    request,
                                                    delivered: false,
                                                });
                                                requests += 1;
                                                proof.blocks += 1;
                                                blocked_current = true;
                                                0
                                            }
                                        },
                                    }
                                }
                            } else {
                                proof.denied += 1;
                                1
                            }
                        }
                        _ => 3,
                    };
                }
                _ if index == 1 && frame.ordinary_user_fault() => {
                    let meta = child.as_ref().unwrap().metadata();
                    let record = FaultRecord {
                        process: meta.process.diagnostic_id(),
                        thread: meta.thread.diagnostic_id(),
                        vector: frame.vector,
                        error: frame.error,
                        address,
                        instruction: frame.rip,
                    };
                    assert_eq!(FaultRecord::decode(&record.encode()), Some(record));
                    fault_record = Some(record);
                    retire_current = true;
                }
                _ => panic!(
                    "service graph fault process={index} vector={} error={} address={address:#x} ip={:#x}",
                    frame.vector, frame.error, frame.rip
                ),
            }
            if retire_current {
                let mut owner = child.take().unwrap();
                let meta = owner.metadata();
                owner.stop(&mut authority, &mut scheduler).unwrap();
                scheduler.exit(0).unwrap();
                scheduler.terminate_process(meta.process).unwrap();
                if rpc_mode {
                    for event in rpc
                        .peer_died(&scheduler, meta.thread, crate::timer::now())
                        .unwrap()
                        .iter()
                        .copied()
                    {
                        notify(
                            event,
                            &mut scheduler,
                            &mut pending,
                            &mut contexts[0],
                            &mut proof,
                            false,
                        );
                    }
                    pending = None;
                }
                for channel in channels
                    .iter_mut()
                    .flatten()
                    .filter(|c| c.receiver == meta.domain)
                {
                    cancelled += channel.close(&mut authority, crate::timer::now()).unwrap();
                }
                retired = Some(
                    owner
                        .finish(&scheduler)
                        .unwrap_or_else(|_| panic!("faulted service remained active")),
                );
                continue;
            }
            if stopped {
                assert_eq!(index, 0);
                break;
            }
            contexts[index] = frame;
            if !blocked_current {
                scheduler.yield_cpu(0).unwrap();
            }
        }
        // SAFETY: capture restored controller CR3 at IF=0; no user executes.
        unsafe {
            crate::timer::stop_runtime();
        }
        assert!(stopped, "service graph trap bound");
        if rpc_mode {
            assert_eq!(
                (
                    ready,
                    completed,
                    proof.successes,
                    proof.denied,
                    proof.expired
                ),
                (
                    1,
                    1,
                    if scenario == Scenario::RpcTimeout {
                        4
                    } else {
                        3
                    },
                    1,
                    1
                )
            );
            let accepted = if scenario == Scenario::RpcTimeout {
                5
            } else {
                3
            };
            assert_eq!(
                (requests, responses, proof.blocks, proof.wakes),
                (accepted, accepted, accepted, accepted)
            );
            assert_eq!(
                (proof.timeouts, proof.late),
                if scenario == Scenario::RpcTimeout {
                    (1, 1)
                } else {
                    (0, 0)
                }
            );
            assert!(proof.stale >= 2);
            if scenario == Scenario::RpcTimeout {
                assert!(proof.busy > 0);
            }
            assert!(pending.is_none());
            assert_eq!(rpc.outstanding(), 0);
        } else {
            let exchanges = if inject_fault { 1 } else { 3 };
            assert_eq!(
                (ready, completed, requests, responses),
                (1, 1, if inject_fault { 2 } else { 3 }, exchanges)
            );
        }
        assert_eq!((jobs, processes, delegated), (1, 1, 2));
        assert_eq!((control_denied, service_denied), (4, 4));
        assert_eq!(event_denied, 3);
        assert_eq!(cancelled, usize::from(inject_fault));
        assert_eq!(exit_code, None);
        assert_eq!(fault_record.is_some(), inject_fault);
        if let Some(record) = fault_record {
            assert_eq!((record.vector, record.error, record.address), (14, 6, 0));
        }
        let meta = child_metadata.unwrap();
        let _lease = if let Some(mut running) = child.take() {
            running.stop(&mut authority, &mut scheduler).unwrap();
            scheduler.terminate_process(meta.process).unwrap();
            running
                .finish(&scheduler)
                .unwrap_or_else(|_| panic!("service remained active"))
        } else {
            retired.take().unwrap()
        };
        for channel in channels.iter_mut().flatten() {
            assert_eq!(channel.mailbox.pending(), 0);
            assert_eq!(channel.close(&mut authority, crate::timer::now()), Ok(0));
            channel.mailbox.retire_empty(&mut authority).unwrap();
        }
        (meta, child_frames)
    };
    // SAFETY: child stopped/retired, no selected user CR3, AP parked, channels
    // drained and image owner returned. Its backing has no remaining aliases.
    unsafe {
        assert_eq!(
            child_storage.take().unwrap().root.retire(frames) as u64,
            child_frames
        );
    }
    scheduler.release_frames(meta.job, child_frames).unwrap();
    registry
        .retire_stopped(&mut authority, &scheduler, meta.process)
        .unwrap();
    root.revoke(&mut authority, &mut scheduler, token).unwrap();
    assert_eq!(scheduler.exit(0), Ok(root_thread));
    scheduler.terminate_process(root_process).unwrap();
    let (binding, _lease) = root
        .finish(&scheduler, token)
        .unwrap_or_else(|_| panic!("Root graph remained active"));
    assert_eq!(binding.phase(), Phase::Revoked);
    assert_eq!(scheduler.dispatch(0), Ok(None));
    event_mailbox.receiver_died(custody).unwrap();
    event_mailbox.retire_empty(&mut authority).unwrap();
    // SAFETY: stopped processes, original CR3 current, AP parked, IPC empty/closed,
    // owners returned. No DMA authority was granted. Root lease is no longer used.
    unsafe {
        assert_eq!(
            root_loaded.root.retire(frames) as u64,
            image.required_frames()
        );
    }
    scheduler
        .release_frames(root_job, image.required_frames())
        .unwrap();
    for job in [meta.job, root_job] {
        for resource in [Resource::Frames, Resource::Processes, Resource::Threads] {
            assert_eq!(scheduler.usage(job, resource), Ok(0));
        }
    }
    for entry in catalog {
        assert!(
            authority
                .authorize(
                    custody,
                    entry.root,
                    entry.kind,
                    if entry.kind == Kind::Endpoint {
                        Rights::SEND
                    } else if entry.kind == Kind::Job {
                        Rights::CONTROL
                    } else {
                        Rights::READ
                    }
                )
                .is_ok()
        );
    }
    assert_eq!(frames.remaining_frames(), before);
    proof.frames_balanced = true;
    proof
}
