//! Sustained userspace-selected service replacement with one unrelated live peer.
//! BSP development proof only; no Root/BAC reconstitution is claimed.
use crate::{
    executable_runtime::{LoadedImage, ProcessImage},
    service_runtime::{Channel, PendingCall, RpcProof, expire, notify},
    supervisor_runtime::bundle,
};
use core::{arch::asm, num::NonZeroU64};
use ev_kernel::{
    bootstrap_binding::CatalogEntry,
    bootstrap_manifest,
    capability::{Authority, Handle, Kind, Rights},
    fault::Record,
    incarnation::{Bindings, Target},
    ipc::{Error as IpcError, MAX_MESSAGES, Mailbox, Outgoing},
    mapping::ADDRESS_MASK,
    memory::BootstrapFrames,
    rpc::{CallId, Error as RpcError, MessageShape, Policy, Rpc},
    scheduler::{Resource, Scheduler, WaitTicket},
    service::{Metadata, RESTART_SERVICE_LIMITS, Registry, Role, Running, ServiceImage},
    time::Deadline,
    user_context::{Call, FxState, UserContext, decode},
};
use ev_userspace_contract::{ABI, Event};

#[derive(Default)]
pub struct Proof {
    pub restarts: u64,
    pub faults: u64,
    pub peer_replies: u64,
    pub victim_replies: u64,
    pub starts: u64,
    pub stale: u64,
    pub frames_balanced: bool,
    pub metadata_balanced: bool,
    pub root_preserved: bool,
}
#[derive(Clone, Copy)]
struct LastCall {
    id: CallId,
    wait: WaitTicket,
    request: ev_kernel::ipc::Ticket,
}
#[derive(Clone, Copy)]
struct History {
    metadata: Metadata,
    control: Handle,
    receive: Handle,
    object: usize,
}
struct Child<'a> {
    vacant: Option<&'a mut LoadedImage>,
    running: Option<Running<ProcessImage<'a>>>,
    retired: Option<ProcessImage<'a>>,
    metadata: Option<Metadata>,
    control: Option<Handle>,
    object: Option<usize>,
    receive: Option<Handle>,
    request: Option<usize>,
    response: Option<usize>,
    reaped: bool,
    history: Option<History>,
    last: Option<LastCall>,
}
impl<'a> Child<'a> {
    fn new(storage: &'a mut LoadedImage) -> Self {
        Self {
            vacant: Some(storage),
            running: None,
            retired: None,
            metadata: None,
            control: None,
            object: None,
            receive: None,
            request: None,
            response: None,
            reaped: false,
            history: None,
            last: None,
        }
    }
}
struct Link {
    channel: Channel,
    closed: bool,
}

/// # Safety
/// Retained BSP/controller CR3, initialized ordinary user/FX/IRQ boundary, IF=0,
/// parked AP and exclusive frames. Every image stays owned through stopped CR3,
/// IPC and reference quiescence before any backing or descriptor can be reused.
pub unsafe fn prove(offset: u64, frames: &mut BootstrapFrames) -> Proof {
    let mut proof = Proof::default();
    let manifest = bootstrap_manifest::verify(
        bundle::GRAPH_RESTART_MANIFEST,
        bundle::GRAPH_RESTART_MEASUREMENT,
        bundle::GRAPH_RESTART_IMAGE,
        ABI,
    )
    .unwrap();
    assert!(!bundle::ECHO_SELECTIVE_IMAGE.is_empty());
    let epoch = NonZeroU64::new(103).unwrap(); // Explicit isolated development epoch.
    let mut authority = Authority::new();
    let custody = authority.create_space().unwrap();
    let branches = authority.create_space().unwrap();
    let root_domain = authority.create_space().unwrap();
    let common = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE;
    let roots = [
        authority
            .create_root(custody, Kind::Memory, common | Rights::READ)
            .unwrap(),
        authority
            .create_root(
                custody,
                Kind::Endpoint,
                common | Rights::SEND | Rights::RECEIVE | Rights::CONTROL,
            )
            .unwrap(),
        authority
            .create_root(custody, Kind::Job, common | Rights::CONTROL)
            .unwrap(),
        authority
            .create_root(custody, Kind::Memory, common | Rights::READ)
            .unwrap(),
    ];
    let kinds = [Kind::Memory, Kind::Endpoint, Kind::Job, Kind::Memory];
    let catalog: [_; 4] = core::array::from_fn(|i| CatalogEntry {
        selector: i as u64 + 1,
        root: roots[i],
        kind: kinds[i],
    });
    let mut events = Mailbox::new(&mut authority, custody, roots[1]).unwrap();
    let mut scheduler = Scheduler::new();
    let root_job = scheduler.create_job_with_limits(manifest.limits()).unwrap();
    let root_process = scheduler.create_held_process(root_job).unwrap();
    let root_thread = scheduler.create_thread(root_process).unwrap();
    let mut registry = Registry::with_service_limits(epoch, RESTART_SERVICE_LIMITS).unwrap();
    registry
        .register_job(&authority, custody, roots[2], root_job)
        .unwrap();
    registry
        .register_image(
            &authority,
            custody,
            roots[3],
            ServiceImage::verify(
                bundle::ECHO_SELECTIVE_IMAGE,
                bundle::ECHO_SELECTIVE_SHA,
                RESTART_SERVICE_LIMITS,
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
    // SAFETY: privileged read of retained controller root, no user entry active.
    unsafe {
        asm!("mov {}, cr3",out(reg)original,options(nomem,nostack,preserves_flags));
    }
    let bits = (core::arch::x86_64::__cpuid(0x80000008).eax & 255) as u8;
    let before = frames.remaining_frames();
    // SAFETY: held process, exact immutable plan/startup and exclusive allocator.
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
    let root_owner = ProcessImage {
        loaded: &mut root_loaded,
        process: root_process,
        frames: image.required_frames(),
    };
    let mut root = binding
        .activate(&authority, &mut scheduler, token, root_thread, root_owner)
        .unwrap_or_else(|r| panic!("restart Root activation: {:?}", r.error));
    let mut rpc = Rpc::new(epoch);
    rpc.register_thread(
        &authority,
        &scheduler,
        root_thread,
        root_job,
        root_domain,
        Some(token),
    )
    .unwrap();
    let mut storage = [LoadedImage::empty(), LoadedImage::empty()];
    {
        let mut children = storage.each_mut().map(Child::new);
        let mut contexts = [
            root.initial_context().unwrap(),
            UserContext::ZERO,
            UserContext::ZERO,
        ];
        let mut fx = [FxState::CLEAN; 3];
        let mut links: [Option<Link>; 4] = [const { None }; 4];
        let mut pending: Option<PendingCall> = None;
        let mut transport = RpcProof::default();
        let mut ready = false;
        let mut completed = false;
        let mut stopped = false;
        let mut budget = None;
        let mut unexpected_exit = None;
        let mut baseline = None;
        let mut previous_cpu = [0u64; 3];
        let global = Deadline::after(crate::timer::now(), 2048).unwrap();
        // SAFETY: exclusive initialized PIC, IRET enables the ordinary user timer.
        unsafe {
            crate::timer::start_runtime();
        }
        for _ in 0..131072 {
            let now = crate::timer::now();
            expire(
                &mut rpc,
                &mut scheduler,
                &mut pending,
                &mut contexts[0],
                &mut transport,
                now,
            );
            assert!(!global.reached(now), "sustained service restart deadline");
            let dispatch = scheduler
                .dispatch(0)
                .unwrap()
                .expect("restart graph lost every runnable thread");
            let (index, domain) = if dispatch.process == root_process {
                root.image().loaded.root.activate();
                (0, root_domain)
            } else {
                let slot = children
                    .iter()
                    .position(|c| c.metadata.is_some_and(|m| m.process == dispatch.process))
                    .expect("unknown dispatched service");
                let owner = children[slot]
                    .running
                    .as_ref()
                    .expect("unadmitted service dispatch");
                assert_eq!(owner.metadata().thread, dispatch.thread);
                owner.image().loaded.root.activate();
                (slot + 1, owner.metadata().domain)
            };
            // SAFETY: actual selected owned root/FX/context; shared trap entry
            // restores controller CR3 and IF=0 before any lifecycle mutation.
            let (mut frame, address) = unsafe {
                crate::user_runtime::resume_context(&contexts[index], &mut fx[index], original)
            };
            expire(
                &mut rpc,
                &mut scheduler,
                &mut pending,
                &mut contexts[0],
                &mut transport,
                crate::timer::now(),
            );
            let mut blocked = false;
            let mut retire = false;
            match frame.vector {
                32 => {
                    if scheduler.charge_cpu(0, 1).is_err() {
                        budget = Some(index);
                        if index == 0 {
                            stopped = true;
                        } else {
                            retire = true;
                        }
                    }
                }
                128 => {
                    frame.registers[14] = match decode(&frame) {
                        Ok(Call::Yield) => {
                            if index == 0 && completed {
                                stopped = true;
                            }
                            0
                        }
                        Ok(Call::Monotonic) => {
                            frame.registers[9] = crate::timer::now();
                            0
                        }
                        Ok(Call::Inspect { capability, rights }) => u64::from(
                            authority
                                .authorize(domain, capability, Kind::Memory, rights)
                                .is_err(),
                        ),
                        Ok(Call::CreateJob { creator, template }) => match registry.create_job(
                            &mut authority,
                            &mut scheduler,
                            domain,
                            creator,
                            template,
                        ) {
                            Ok(cap) => {
                                frame.registers[9] = cap.0;
                                0
                            }
                            Err(_) => 1,
                        },
                        Ok(Call::CreateEndpoint(creator)) => {
                            if let Some(slot) = links.iter_mut().find(|c| c.is_none()) {
                                match registry.create_channel(&mut authority, domain, creator) {
                                    Ok((cap, mailbox)) => {
                                        let identity = authority
                                            .authorize(domain, cap, Kind::Endpoint, Rights::CONTROL)
                                            .unwrap()
                                            .identity();
                                        *slot = Some(Link {
                                            channel: Channel {
                                                identity,
                                                receiver: domain,
                                                mailbox,
                                                tickets: [None; MAX_MESSAGES],
                                            },
                                            closed: false,
                                        });
                                        frame.registers[9] = cap.0;
                                        0
                                    }
                                    Err(_) => 1,
                                }
                            } else {
                                2
                            }
                        }
                        Ok(Call::CreateProcess { job, image }) => {
                            if index != 0 {
                                1
                            } else if let Some(slot) = children
                                .iter_mut()
                                .find(|c| c.metadata.is_none() && c.vacant.is_some())
                            {
                                match registry.create_process(
                                    &mut authority,
                                    &mut scheduler,
                                    domain,
                                    job,
                                    image,
                                ) {
                                    Ok(cap) => {
                                        slot.metadata = Some(
                                            registry.metadata(&authority, domain, cap).unwrap(),
                                        );
                                        slot.control = Some(cap);
                                        slot.object = Some(
                                            authority
                                                .authorize(
                                                    domain,
                                                    cap,
                                                    Kind::Process,
                                                    Rights::CONTROL,
                                                )
                                                .unwrap()
                                                .identity(),
                                        );
                                        slot.reaped = false;
                                        frame.registers[9] = cap.0;
                                        0
                                    }
                                    Err(_) => 1,
                                }
                            } else {
                                2
                            }
                        }
                        Ok(Call::Delegate {
                            process,
                            source,
                            selector,
                        }) => match registry.delegate(
                            &mut authority,
                            domain,
                            process,
                            source,
                            selector,
                        ) {
                            Ok(_) => 0,
                            Err(_) => 1,
                        },
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
                                Ok((meta, receive, identity)) => match links
                                    .iter_mut()
                                    .flatten()
                                    .find(|c| c.channel.identity == identity)
                                {
                                    Some(link) => {
                                        let result = if link.closed {
                                            link.channel.mailbox.reopen_empty(
                                                &authority,
                                                domain,
                                                endpoint,
                                                meta.domain,
                                                receive,
                                            )
                                        } else {
                                            link.channel.mailbox.rebind_empty(
                                                &authority,
                                                domain,
                                                endpoint,
                                                meta.domain,
                                                receive,
                                            )
                                        };
                                        if result.is_ok() {
                                            link.channel.receiver = meta.domain;
                                            link.closed = false;
                                            0
                                        } else {
                                            1
                                        }
                                    }
                                    None => 1,
                                },
                                Err(_) => 1,
                            }
                        }
                        Ok(Call::Start(cap)) => {
                            let setup = (|| -> Result<_, ev_kernel::service::Error> {
                                let meta = registry.metadata(&authority, domain, cap)?;
                                let record = registry.startup(&authority, domain, cap, epoch)?;
                                let plan = registry.plan(&authority, domain, cap)?;
                                let receive = registry.grant(&authority, domain, cap, 3)?;
                                let send = registry.grant(&authority, domain, cap, 4)?;
                                let request = authority
                                    .authorize(
                                        meta.domain,
                                        receive,
                                        Kind::Endpoint,
                                        Rights::RECEIVE | Rights::CONTROL,
                                    )?
                                    .identity();
                                let response = authority
                                    .authorize(meta.domain, send, Kind::Endpoint, Rights::SEND)?
                                    .identity();
                                if request == response
                                    || !links.iter().flatten().any(|l| {
                                        l.channel.identity == request
                                            && l.channel.receiver == meta.domain
                                            && !l.closed
                                            && l.channel.mailbox.pending() == 0
                                    })
                                    || !links.iter().flatten().any(|l| {
                                        l.channel.identity == response
                                            && l.channel.receiver == root_domain
                                            && !l.closed
                                            && l.channel.mailbox.pending() == 0
                                    })
                                {
                                    return Err(ev_kernel::service::Error::Descriptor);
                                }
                                Ok((meta, record, plan, receive, request, response))
                            })();
                            if index != 0 {
                                1
                            } else if let Ok((meta, record, plan, receive, request, response)) =
                                setup
                            {
                                if let Some(which) = children.iter().position(|c| {
                                    c.metadata == Some(meta)
                                        && c.running.is_none()
                                        && c.vacant.is_some()
                                }) {
                                    let slot = &mut children[which];
                                    let backing = slot.vacant.take().unwrap();
                                    // SAFETY: held, fully configured measured process; inactive
                                    // controller-owned vacant slot and exclusive physical allocator.
                                    *backing = unsafe {
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
                                    let owner = ProcessImage {
                                        loaded: backing,
                                        process: meta.process,
                                        frames: meta.frames,
                                    };
                                    let running = registry
                                        .start(
                                            &authority,
                                            &mut scheduler,
                                            domain,
                                            cap,
                                            epoch,
                                            owner,
                                        )
                                        .unwrap_or_else(|r| {
                                            panic!("restart service admission: {:?}", r.error)
                                        });
                                    contexts[which + 1] = running.initial_context().unwrap();
                                    fx[which + 1] = FxState::CLEAN;
                                    slot.running = Some(running);
                                    slot.receive = Some(receive);
                                    slot.request = Some(request);
                                    slot.response = Some(response);
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
                                    proof.starts += 1;
                                    if let Some(old) = slot.history {
                                        assert_ne!(old.metadata.process, meta.process);
                                        assert_ne!(old.metadata.thread, meta.thread);
                                        assert_ne!(old.metadata.domain, meta.domain);
                                        assert_eq!(
                                            scheduler.process_job(old.metadata.process),
                                            Err(ev_kernel::scheduler::Error::InvalidId)
                                        );
                                        assert_eq!(
                                            scheduler.state(old.metadata.thread),
                                            Err(ev_kernel::scheduler::Error::InvalidId)
                                        );
                                        assert!(
                                            registry
                                                .metadata(&authority, root_domain, old.control)
                                                .is_err()
                                        );
                                        assert!(
                                            authority
                                                .authorize(
                                                    old.metadata.domain,
                                                    receive,
                                                    Kind::Endpoint,
                                                    Rights::RECEIVE
                                                )
                                                .is_err()
                                        );
                                        assert!(
                                            authority
                                                .authorize(
                                                    meta.domain,
                                                    old.receive,
                                                    Kind::Endpoint,
                                                    Rights::RECEIVE
                                                )
                                                .is_err()
                                        );
                                        assert_ne!(
                                            authority
                                                .authorize(
                                                    domain,
                                                    cap,
                                                    Kind::Process,
                                                    Rights::CONTROL
                                                )
                                                .unwrap()
                                                .identity(),
                                            old.object
                                        );
                                        proof.stale += 7;
                                        proof.restarts += 1;
                                    }
                                    authority.collect_lineage().unwrap();
                                    if children.iter().all(|c| c.running.is_some()) {
                                        let snapshot = (
                                            authority.metadata_usage(),
                                            scheduler.metadata_usage(),
                                            registry.metadata_usage(),
                                            rpc.metadata_usage(),
                                            frames.remaining_frames(),
                                        );
                                        if let Some(expected) = baseline {
                                            assert_eq!(
                                                snapshot, expected,
                                                "restart metadata/frame baseline drift"
                                            );
                                        } else {
                                            baseline = Some(snapshot);
                                        }
                                        for (i, c) in children.iter().enumerate() {
                                            let m = c.metadata.unwrap();
                                            assert_eq!(
                                                scheduler.usage(m.job, Resource::Frames),
                                                Ok(m.frames)
                                            );
                                            assert_eq!(
                                                scheduler.usage(m.job, Resource::Processes),
                                                Ok(1)
                                            );
                                            assert_eq!(
                                                scheduler.usage(m.job, Resource::Threads),
                                                Ok(1)
                                            );
                                            let cpu =
                                                scheduler.usage(m.job, Resource::CpuTicks).unwrap();
                                            assert!(cpu >= previous_cpu[i + 1]);
                                            previous_cpu[i + 1] = cpu;
                                        }
                                        let cpu =
                                            scheduler.usage(root_job, Resource::CpuTicks).unwrap();
                                        assert!(cpu >= previous_cpu[0]);
                                        previous_cpu[0] = cpu;
                                        assert_eq!(root.token(), token);
                                        assert_eq!(root.token().process(), root_process);
                                        assert_eq!(rpc.outstanding(), 0);
                                    }
                                    0
                                } else {
                                    1
                                }
                            } else {
                                1
                            }
                        }
                        Ok(Call::Observe(cap)) => {
                            match registry.observe(&authority, &scheduler, domain, cap) {
                                Ok(done) => {
                                    frame.registers[9] = u64::from(done);
                                    0
                                }
                                Err(_) => 1,
                            }
                        }
                        Ok(Call::Reap(cap)) => {
                            if index != 0 {
                                1
                            } else if let Ok(meta) = registry.metadata(&authority, domain, cap) {
                                if let Some(which) = children.iter().position(|c| {
                                    c.metadata == Some(meta) && c.retired.is_some() && !c.reaped
                                }) {
                                    let slot = &mut children[which];
                                    let owner = slot.retired.take().unwrap();
                                    assert_eq!(rpc.serving(meta.thread), None);
                                    assert_eq!(rpc.waiting(meta.thread), None);
                                    assert!(
                                        links
                                            .iter()
                                            .flatten()
                                            .filter(|l| l.channel.receiver == meta.domain)
                                            .all(|l| l.closed && l.channel.mailbox.pending() == 0)
                                    );
                                    let ProcessImage { loaded, .. } = owner;
                                    // SAFETY: actual fault/stop restored controller CR3, process
                                    // retired, AP parked, IPC drained, Running returned sole lease.
                                    let reclaimed = unsafe { loaded.root.retire_in_place(frames) };
                                    assert_eq!(reclaimed as u64, meta.frames);
                                    scheduler.release_frames(meta.job, meta.frames).unwrap();
                                    registry
                                        .retire_stopped(&mut authority, &scheduler, meta.process)
                                        .unwrap();
                                    slot.vacant = Some(loaded);
                                    slot.reaped = true;
                                    contexts[which + 1] = UserContext::ZERO;
                                    fx[which + 1] = FxState::CLEAN;
                                    0
                                } else {
                                    1
                                }
                            } else {
                                1
                            }
                        }
                        Ok(Call::Close(cap)) => {
                            if authority.close(domain, cap).is_err() {
                                1
                            } else {
                                if index == 0
                                    && let Some(slot) = children
                                        .iter_mut()
                                        .find(|c| c.control == Some(cap) && c.reaped)
                                {
                                    let meta = slot.metadata.unwrap();
                                    let object = slot.history.unwrap().object;
                                    registry
                                        .forget_retired(&mut authority, &scheduler, meta.process)
                                        .unwrap();
                                    rpc.forget_thread(&scheduler, meta.thread).unwrap();
                                    scheduler.reclaim_process(meta.process).unwrap();
                                    assert!(
                                        registry.metadata(&authority, root_domain, cap).is_err()
                                    );
                                    assert!(object > 0);
                                    slot.metadata = None;
                                    slot.control = None;
                                    slot.object = None;
                                }
                                0
                            }
                        }
                        Ok(Call::Rpc {
                            endpoint,
                            value,
                            deadline: absolute,
                        }) => {
                            let now = crate::timer::now();
                            let route = authority
                                .authorize(domain, endpoint, Kind::Endpoint, Rights::SEND)
                                .ok()
                                .and_then(|a| {
                                    children
                                        .iter()
                                        .position(|c| c.request == Some(a.identity()))
                                });
                            match route {
                                _ if index != 0 => 1,
                                None => 1,
                                Some(which) if children[which].running.is_none() => 5,
                                Some(_) if absolute <= now => 4,
                                Some(_) if absolute > global.tick() => 3,
                                Some(which) => {
                                    let meta = children[which].metadata.unwrap();
                                    let identity = children[which].request.unwrap();
                                    let link = links
                                        .iter_mut()
                                        .flatten()
                                        .find(|l| l.channel.identity == identity)
                                        .unwrap();
                                    let deadline = Deadline::after(0, absolute).unwrap();
                                    if link.closed || link.channel.mailbox.pending() != 0 {
                                        2
                                    } else if scheduler.check_block(0, deadline).is_err() {
                                        1
                                    } else {
                                        match rpc.begin(
                                            &authority,
                                            dispatch.thread,
                                            endpoint,
                                            deadline,
                                            MessageShape {
                                                bytes: 8,
                                                capabilities: 0,
                                            },
                                            now,
                                        ) {
                                            Err(
                                                RpcError::WouldBlock | RpcError::AlreadyWaiting,
                                            ) => 2,
                                            Err(RpcError::DeadlineExceeded) => 4,
                                            Err(RpcError::PeerDied) => 5,
                                            Err(_) => 1,
                                            Ok(id) => match link.channel.send_ticket(
                                                &mut authority,
                                                domain,
                                                endpoint,
                                                value,
                                                deadline,
                                                now,
                                            ) {
                                                Err(_) => {
                                                    rpc.cancel(dispatch.thread, id, now).unwrap();
                                                    rpc.complete(meta.thread, id, now).unwrap();
                                                    2
                                                }
                                                Ok(request) => {
                                                    let wait =
                                                        scheduler.block(0, deadline).unwrap();
                                                    if let Some(old) = children[which].last {
                                                        assert_eq!(
                                                            rpc.complete(meta.thread, old.id, now),
                                                            Err(RpcError::StaleCall)
                                                        );
                                                        assert!(!scheduler.wake(old.wait));
                                                        assert!(scheduler.waiting(wait));
                                                        assert_eq!(
                                                            link.channel.reclaim(
                                                                &mut authority,
                                                                root_domain,
                                                                old.request,
                                                                now
                                                            ),
                                                            Err(IpcError::InvalidTicket)
                                                        );
                                                        proof.stale += 3;
                                                    }
                                                    pending = Some(PendingCall {
                                                        id,
                                                        caller: dispatch.thread,
                                                        callee: meta.thread,
                                                        wait,
                                                        waiting: true,
                                                        request,
                                                        delivered: false,
                                                    });
                                                    transport.blocks += 1;
                                                    blocked = true;
                                                    0
                                                }
                                            },
                                        }
                                    }
                                }
                            }
                        }
                        Ok(Call::Receive(endpoint)) => {
                            let identity = authority
                                .authorize(domain, endpoint, Kind::Endpoint, Rights::RECEIVE)
                                .map(|a| a.identity());
                            match identity {
                                Err(_) => 1,
                                Ok(identity) => {
                                    if index == 0 {
                                        3
                                    } else if let Some(link) = links
                                        .iter_mut()
                                        .flatten()
                                        .find(|l| l.channel.identity == identity)
                                    {
                                        match link.channel.receive(
                                            &mut authority,
                                            domain,
                                            endpoint,
                                            crate::timer::now(),
                                        ) {
                                            Ok(delivery) => {
                                                if let Some(wait) = pending.as_mut().filter(|p| {
                                                    p.callee == dispatch.thread
                                                        && !p.delivered
                                                        && rpc.serving(dispatch.thread)
                                                            == Some(p.id)
                                                }) {
                                                    wait.delivered = true;
                                                    frame.registers[9] = u64::from_le_bytes(
                                                        delivery.bytes[..8].try_into().unwrap(),
                                                    );
                                                    frame.registers[11] = 0;
                                                    0
                                                } else {
                                                    3
                                                }
                                            }
                                            Err(IpcError::Empty) => 2,
                                            Err(IpcError::Expired) => {
                                                if let Some(wait) = pending.as_ref().filter(|p| {
                                                    p.callee == dispatch.thread
                                                        && !p.delivered
                                                        && !p.waiting
                                                }) {
                                                    let id = wait.id;
                                                    let ticket = wait.request;
                                                    link.channel
                                                        .reclaim(
                                                            &mut authority,
                                                            root_domain,
                                                            ticket,
                                                            crate::timer::now(),
                                                        )
                                                        .unwrap();
                                                    let event = rpc
                                                        .complete(
                                                            dispatch.thread,
                                                            id,
                                                            crate::timer::now(),
                                                        )
                                                        .unwrap();
                                                    assert!(!event.deliver_reply);
                                                    pending = None;
                                                }
                                                2
                                            }
                                            Err(_) => 1,
                                        }
                                    } else {
                                        1
                                    }
                                }
                            }
                        }
                        Ok(Call::Send {
                            endpoint,
                            value,
                            capability: None,
                        }) => {
                            let identity = authority
                                .authorize(domain, endpoint, Kind::Endpoint, Rights::SEND)
                                .map(|a| a.identity());
                            match identity {
                                Err(_) => 1,
                                Ok(identity) => {
                                    let event_identity = authority
                                        .authorize(
                                            custody,
                                            roots[1],
                                            Kind::Endpoint,
                                            Rights::RECEIVE,
                                        )
                                        .unwrap()
                                        .identity();
                                    if identity == event_identity {
                                        let event = Event::decode(&value.to_le_bytes());
                                        let allowed = index == 0
                                            && match event {
                                                Some(Event::Ready) => !ready && !completed,
                                                Some(Event::ServiceResponded) => {
                                                    ready
                                                        && !completed
                                                        && proof.restarts == 64
                                                        && proof.faults == 64
                                                        && proof.peer_replies == 128
                                                        && rpc.outstanding() == 0
                                                        && pending.is_none()
                                                }
                                                _ => false,
                                            };
                                        if !allowed {
                                            3
                                        } else {
                                            let bytes = value.to_le_bytes();
                                            events
                                                .send(
                                                    &mut authority,
                                                    domain,
                                                    endpoint,
                                                    Outgoing {
                                                        bytes: &bytes,
                                                        capability: None,
                                                        deadline: global,
                                                    },
                                                    crate::timer::now(),
                                                )
                                                .unwrap();
                                            let delivered = events
                                                .receive(
                                                    &mut authority,
                                                    custody,
                                                    roots[1],
                                                    crate::timer::now(),
                                                )
                                                .unwrap();
                                            assert_eq!(
                                                Event::decode(&delivered.bytes[..delivered.length]),
                                                event
                                            );
                                            if event == Some(Event::Ready) {
                                                ready = true;
                                            } else {
                                                completed = true;
                                            }
                                            0
                                        }
                                    } else if index != 0
                                        && children[index - 1].response == Some(identity)
                                    {
                                        if let Some(wait) = pending.as_ref().filter(|p| {
                                            p.callee == dispatch.thread
                                                && p.delivered
                                                && rpc.serving(dispatch.thread) == Some(p.id)
                                        }) {
                                            let event = rpc
                                                .complete(
                                                    dispatch.thread,
                                                    wait.id,
                                                    crate::timer::now(),
                                                )
                                                .unwrap();
                                            let wait = pending.take().unwrap();
                                            if event.deliver_reply {
                                                contexts[0].registers[14] = 0;
                                                contexts[0].registers[9] = value;
                                                contexts[0].registers[11] = 0;
                                                assert!(scheduler.wake(wait.wait));
                                                transport.successes += 1;
                                                transport.wakes += 1;
                                                if index == 1 {
                                                    proof.victim_replies += 1;
                                                } else {
                                                    proof.peer_replies += 1;
                                                }
                                            }
                                            children[index - 1].last = Some(LastCall {
                                                id: wait.id,
                                                wait: wait.wait,
                                                request: wait.request,
                                            });
                                            0
                                        } else {
                                            3
                                        }
                                    } else {
                                        3
                                    }
                                }
                            }
                        }
                        Ok(Call::Exit(code)) => {
                            unexpected_exit = Some((index, code));
                            if index == 0 {
                                stopped = true;
                            } else {
                                retire = true;
                            }
                            0
                        }
                        _ => 3,
                    };
                }
                _ if index != 0 && frame.ordinary_user_fault() => {
                    let meta = children[index - 1].metadata.unwrap();
                    let record = Record {
                        process: meta.process.diagnostic_id(),
                        thread: meta.thread.diagnostic_id(),
                        vector: frame.vector,
                        error: frame.error,
                        address,
                        instruction: frame.rip,
                    };
                    assert_eq!(Record::decode(&record.encode()), Some(record));
                    assert_eq!(
                        (index, record.vector, record.error, record.address),
                        (1, 14, 6, 0)
                    );
                    proof.faults += 1;
                    retire = true;
                }
                _ => panic!(
                    "restart Root fault vector={} ip={:#x}",
                    frame.vector, frame.rip
                ),
            }
            if retire {
                let which = index - 1;
                let slot = &mut children[which];
                let mut owner = slot.running.take().unwrap();
                let meta = owner.metadata();
                let receive = slot.receive.unwrap();
                let control = slot.control.unwrap();
                let object = slot.object.unwrap();
                owner.stop(&mut authority, &mut scheduler).unwrap();
                scheduler.exit(0).unwrap();
                scheduler.terminate_process(meta.process).unwrap();
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
                        &mut transport,
                        false,
                    );
                }
                pending = None;
                for link in links
                    .iter_mut()
                    .flatten()
                    .filter(|l| l.channel.receiver == meta.domain)
                {
                    link.channel
                        .close(&mut authority, crate::timer::now())
                        .unwrap();
                    link.closed = true;
                }
                slot.retired = Some(
                    owner
                        .finish(&scheduler)
                        .unwrap_or_else(|_| panic!("stopped restart victim retained")),
                );
                slot.history = Some(History {
                    metadata: meta,
                    control,
                    receive,
                    object,
                });
                continue;
            }
            if stopped {
                break;
            }
            contexts[index] = frame;
            if !blocked {
                scheduler.yield_cpu(0).unwrap();
            }
        }
        // SAFETY: captured controller root current at IF=0, no user executing.
        unsafe {
            crate::timer::stop_runtime();
        }
        assert!(
            stopped && completed && budget.is_none() && unexpected_exit.is_none(),
            "restart failure: budget={budget:?} exit={unexpected_exit:?} restarts={} faults={} starts={} peer={} victim={} cpu={previous_cpu:?} root_cpu={:?}",
            proof.restarts,
            proof.faults,
            proof.starts,
            proof.peer_replies,
            proof.victim_replies,
            scheduler.usage(root_job, Resource::CpuTicks)
        );
        assert_eq!(
            (
                proof.restarts,
                proof.faults,
                proof.peer_replies,
                proof.victim_replies,
                proof.starts
            ),
            (64, 64, 128, 64, 66)
        );
        assert_eq!(rpc.outstanding(), 0);
        assert!(pending.is_none());
        assert_eq!(root.token(), token);
        proof.metadata_balanced = baseline.is_some();
        proof.root_preserved = true;
        for slot in &mut children {
            let mut owner = slot.running.take().unwrap();
            let meta = owner.metadata();
            owner.stop(&mut authority, &mut scheduler).unwrap();
            scheduler.terminate_process(meta.process).unwrap();
            rpc.peer_died(&scheduler, meta.thread, crate::timer::now())
                .unwrap();
            for link in links
                .iter_mut()
                .flatten()
                .filter(|l| l.channel.receiver == meta.domain)
            {
                link.channel
                    .close(&mut authority, crate::timer::now())
                    .unwrap();
                link.closed = true;
            }
            let owner = owner
                .finish(&scheduler)
                .unwrap_or_else(|_| panic!("final service stop retained image"));
            let ProcessImage { loaded, .. } = owner;
            // SAFETY: actual stopped process, controller CR3, parked AP, closed
            // empty channels and returned sole owner; no device/DMA grants exist.
            unsafe {
                assert_eq!(loaded.root.retire_in_place(frames) as u64, meta.frames);
            }
            scheduler.release_frames(meta.job, meta.frames).unwrap();
            registry
                .retire_stopped(&mut authority, &scheduler, meta.process)
                .unwrap();
            registry
                .forget_retired(&mut authority, &scheduler, meta.process)
                .unwrap();
            rpc.forget_thread(&scheduler, meta.thread).unwrap();
            scheduler.reclaim_process(meta.process).unwrap();
            slot.vacant = Some(loaded);
            for resource in [Resource::Frames, Resource::Processes, Resource::Threads] {
                assert_eq!(scheduler.usage(meta.job, resource), Ok(0));
            }
        }
        for link in links.iter_mut().flatten() {
            if !link.closed {
                link.channel
                    .close(&mut authority, crate::timer::now())
                    .unwrap();
            }
            link.channel.mailbox.retire_empty(&mut authority).unwrap();
        }
    }
    root.revoke(&mut authority, &mut scheduler, token).unwrap();
    scheduler.exit(0).unwrap();
    scheduler.terminate_process(root_process).unwrap();
    let (_, lease) = root
        .finish(&scheduler, token)
        .unwrap_or_else(|_| panic!("final Root stop retained image"));
    events.receiver_died(custody).unwrap();
    events.retire_empty(&mut authority).unwrap();
    let ProcessImage { loaded, .. } = lease;
    // SAFETY: all services and Root retired, original CR3 current, AP parked,
    // every channel drained/closed and all executable leases have returned.
    unsafe {
        assert_eq!(
            loaded.root.retire_in_place(frames) as u64,
            image.required_frames()
        );
    }
    scheduler
        .release_frames(root_job, image.required_frames())
        .unwrap();
    for resource in [Resource::Frames, Resource::Processes, Resource::Threads] {
        assert_eq!(scheduler.usage(root_job, resource), Ok(0));
    }
    assert_eq!(frames.remaining_frames(), before);
    proof.frames_balanced = true;
    proof
}
