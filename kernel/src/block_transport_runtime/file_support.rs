//! Three isolated actors and two distinct shared frames. File/object policy is
//! measured userspace code; this owner only binds capabilities and IPC routes.
use super::*;
use ev_userspace_contract::file_test::{
    self, Completion as FileCompletion, Control as FileControl,
};

pub struct FileProof {
    pub control: FileControl,
    pub report: FileCompletion,
    pub calls: u64,
    pub blocks: u64,
    pub wakes: u64,
    pub replies: u64,
    pub outer_calls: u64,
    pub backend_calls: u64,
    pub nested_calls: u64,
    pub startup_calls: u64,
    pub pre_delivery_calls: u64,
    pub delivered_nested_calls: u64,
    pub max_pending: u64,
    pub mutations: u64,
    pub snapshots: u64,
    pub authority_denied: u64,
    pub block_denied: u64,
    pub unbound_denied: u64,
    pub bindings: u64,
    pub mapped: u64,
    pub elapsed_ticks: u64,
    pub cpu_driver: u64,
    pub cpu_server: u64,
    pub cpu_client: u64,
    pub cpu_parent: u64,
    pub transitions: u64,
    pub frames: bool,
    pub metadata: bool,
    pub guards: bool,
}

/// # Safety
/// Exclusive initialized BSP/PIC/direct-map/allocator owner with AP parked and
/// IF0; dedicated non-DMA ATA fixture. No admitted timeout/cancellation exists.
#[inline(never)]
pub unsafe fn prove_file(offset: u64, frames: &mut BootstrapFrames) -> FileProof {
    let before = frames.remaining_frames();
    let original: u64;
    // SAFETY: retained privileged controller identity, before user dispatch.
    unsafe { asm!("mov {}, cr3",out(reg)original,options(nomem,nostack,preserves_flags)) };
    let hw = Hardware {
        offset,
        original,
        bits: (core::arch::x86_64::__cpuid(0x80000008).eax & 255) as u8,
    };
    let profile = Profile::File;
    let limits = profile.limits();
    let epoch = NonZeroU64::new(271).unwrap();
    let mut a = Authority::new();
    let custody = a.create_space().unwrap();
    let common = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE;
    let jobs: [Handle; 3] = core::array::from_fn(|_| {
        a.create_root(custody, Kind::Job, common | Rights::READ | Rights::CONTROL)
            .unwrap()
    });
    let images: [Handle; 3] =
        core::array::from_fn(|_| a.create_root(custody, Kind::Memory, Rights::READ).unwrap());
    let port = a
        .create_root(
            custody,
            Kind::IoPorts,
            common | Rights::READ | Rights::WRITE | Rights::CONTROL,
        )
        .unwrap();
    let ata_object = a
        .authorize(custody, port, Kind::IoPorts, Rights::CONTROL)
        .unwrap()
        .identity();
    let mut ports = Ports::new();
    ports.register(&a, custody, port, &ATA).unwrap();
    let mut s = Scheduler::new();
    let parent = s
        .create_job_with_limits(Limits::new(profile.parent_cpu(), 65, 3, 3))
        .unwrap();
    let actual_jobs =
        core::array::from_fn::<_, 3, _>(|_| s.create_child_job(parent, limits).unwrap());
    let mut registry = Registry::with_service_limits(epoch, limits).unwrap();
    for index in 0..3 {
        registry
            .register_job(&a, custody, jobs[index], actual_jobs[index])
            .unwrap();
    }
    let (mut io, io_cap, io_alias) = backing(&mut a, &mut s, custody, parent, &hw, frames);
    let (mut application, app_cap, app_alias) =
        backing(&mut a, &mut s, custody, parent, &hw, frames);
    let (block_cap, mut block_box) = registry.create_channel(&mut a, custody, jobs[0]).unwrap();
    let (read_cap, mut read_box) = registry.create_channel(&mut a, custody, jobs[1]).unwrap();
    let (replace_cap, mut replace_box) = registry.create_channel(&mut a, custody, jobs[1]).unwrap();
    let endpoint_caps = [block_cap, read_cap, replace_cap];
    let objects = endpoint_caps.map(|cap| {
        a.authorize(custody, cap, Kind::Endpoint, Rights::CONTROL)
            .unwrap()
            .identity()
    });
    assert!(objects[0] != objects[1] && objects[0] != objects[2] && objects[1] != objects[2]);
    let driver_roles = [
        role(1, Kind::IoPorts, 3),
        role(2, Kind::Memory, 7),
        role(3, Kind::Endpoint, 272),
    ];
    let server_roles = [
        role(1, Kind::Memory, 7),
        role(2, Kind::Endpoint, 8),
        role(3, Kind::Memory, 7),
        role(4, Kind::Endpoint, 272),
        role(5, Kind::Endpoint, 272),
    ];
    let app_roles = [
        role(1, Kind::Memory, 7),
        role(2, Kind::Endpoint, 8),
        role(3, Kind::Endpoint, 8),
    ];
    for (index, bytes, sha, roles) in [
        (
            0,
            bundle::M3_BLOCK_DRIVER_IMAGE,
            bundle::M3_BLOCK_DRIVER_SHA,
            driver_roles.as_slice(),
        ),
        (
            1,
            bundle::M3_FILE_SERVER_IMAGE,
            bundle::M3_FILE_SERVER_SHA,
            server_roles.as_slice(),
        ),
        (
            2,
            bundle::M3_FILE_APP_IMAGE,
            bundle::M3_FILE_APP_SHA,
            app_roles.as_slice(),
        ),
    ] {
        registry
            .register_image(
                &a,
                custody,
                images[index],
                ServiceImage::verify(bytes, sha, limits, roles).unwrap(),
            )
            .unwrap();
    }
    let controls = core::array::from_fn::<_, 3, _>(|index| {
        registry
            .create_process(&mut a, &mut s, custody, jobs[index], images[index])
            .unwrap()
    });
    for (index, grants) in [
        (0, &[(port, 1), (io_cap, 2), (block_cap, 3)][..]),
        (
            1,
            &[
                (io_cap, 1),
                (block_cap, 2),
                (app_cap, 3),
                (read_cap, 4),
                (replace_cap, 5),
            ][..],
        ),
        (2, &[(app_cap, 1), (read_cap, 2), (replace_cap, 3)][..]),
    ] {
        for &(source, selector) in grants {
            registry
                .delegate(&mut a, custody, controls[index], source, selector)
                .unwrap();
        }
    }
    let meta = controls.map(|cap| registry.metadata(&a, custody, cap).unwrap());
    let receive = [
        registry.grant(&a, custody, controls[0], 3).unwrap(),
        registry.grant(&a, custody, controls[1], 4).unwrap(),
        registry.grant(&a, custody, controls[1], 5).unwrap(),
    ];
    for (mailbox, cap, domain, grant) in [
        (&mut block_box, block_cap, meta[0].domain, receive[0]),
        (&mut read_box, read_cap, meta[1].domain, receive[1]),
        (&mut replace_box, replace_cap, meta[1].domain, receive[2]),
    ] {
        mailbox
            .rebind_empty(&a, custody, cap, domain, grant)
            .unwrap();
    }
    assert_eq!(a.metadata_usage(), (10, 37, 37, 15));
    assert!(meta.iter().map(|m| m.frames).sum::<u64>() + 2 <= 65);
    for &control in &controls {
        let plan = registry.plan(&a, custody, control).unwrap();
        for relative in [507 * FRAME_SIZE, 508 * FRAME_SIZE] {
            assert!(
                !plan
                    .pages()
                    .any(|page| page.address == plan.base() + relative)
            );
        }
    }
    verify_store_stack(&registry.plan(&a, custody, controls[1]).unwrap());
    verify_store_stack(&registry.plan(&a, custody, controls[2]).unwrap());
    let mut driver_slot = LoadedImage::empty();
    let mut server_slot = LoadedImage::empty();
    let mut app_slot = LoadedImage::empty();
    let mapping_grants = [
        registry.grant(&a, custody, controls[0], 2).unwrap(),
        registry.grant(&a, custody, controls[1], 1).unwrap(),
        registry.grant(&a, custody, controls[1], 3).unwrap(),
        registry.grant(&a, custody, controls[2], 1).unwrap(),
    ];
    // SAFETY: three held targets, separate initialized buffers and unique roots.
    let driver = unsafe {
        load_actor(
            &mut registry,
            &a,
            &mut s,
            custody,
            controls[0],
            epoch,
            &mut driver_slot,
            &mut io,
            mapping_grants[0],
            None,
            &hw,
            frames,
        )
    };
    // SAFETY: same serialized owner; this target alone maps both distinct pages.
    let server = unsafe {
        load(
            &mut registry,
            &a,
            &mut s,
            custody,
            controls[1],
            epoch,
            &mut server_slot,
            Some((&mut io, mapping_grants[1])),
            &mut application,
            mapping_grants[2],
            &hw,
            frames,
        )
    };
    // SAFETY: app receives only its separate507 buffer;508 remains absent.
    let app = unsafe {
        load(
            &mut registry,
            &a,
            &mut s,
            custody,
            controls[2],
            epoch,
            &mut app_slot,
            None,
            &mut application,
            mapping_grants[3],
            &hw,
            frames,
        )
    };
    let mut actors = [driver, server, app];
    let mapped: usize = actors
        .iter()
        .map(|actor| {
            [507 * FRAME_SIZE, 508 * FRAME_SIZE]
                .into_iter()
                .filter(|&relative| {
                    actor
                        .running
                        .as_ref()
                        .unwrap()
                        .image()
                        .loaded
                        .root
                        .shared_mapping(relative)
                        .is_some()
                })
                .count()
        })
        .sum();
    assert_eq!(mapped, 4);
    let stop = Deadline::after(crate::timer::now(), profile.ticks()).unwrap();
    for actor in &mut actors[1..] {
        actor.context.registers[11] = stop.tick();
    }
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
    // Only the driver's transport is exposed initially. The actual server
    // publishes each File receiver through its authorized self-bind21 after
    // initialization; an early caller cannot attach a reservation beforehand.
    rpc.bind_endpoint(
        &a,
        meta[0].domain,
        receive[0],
        meta[0].thread,
        Policy::new(8, 0).unwrap(),
    )
    .unwrap();
    let mut spare = LoadedImage::empty();
    let mut lifecycle = lifecycle::Lifecycle::new(&mut spare);
    let (mut proof, store, file, progress, cpu, elapsed) = {
        let mut routes = [
            Route {
                object: objects[0],
                receiver: meta[0],
                protocol: Protocol::Block,
                mailbox: &mut block_box,
            },
            Route {
                object: objects[1],
                receiver: meta[1],
                protocol: Protocol::Opaque,
                mailbox: &mut read_box,
            },
            Route {
                object: objects[2],
                receiver: meta[1],
                protocol: Protocol::Opaque,
                mailbox: &mut replace_box,
            },
        ];
        let mut runtime = Runtime {
            a: &mut a,
            s: &mut s,
            rpc: &mut rpc,
            ports: &ports,
            ata_object,
            uart_object: None,
            object: &io,
            actors: &mut actors,
            routes: &mut routes,
            alias: io_alias,
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
            events: None,
            catalogue: None,
            generation: GenerationState::default(),
            progress: Progress::default(),
            application: Some((&application, app_alias)),
            file: FileState::default(),
        };
        // SAFETY: exclusive retained hardware ownership through actual stop.
        unsafe { runtime.run(&hw, frames) };
        let cpu = actual_jobs.map(|job| runtime.s.usage(job, Resource::CpuTicks).unwrap());
        let parent_cpu = runtime.s.usage(parent, Resource::CpuTicks).unwrap();
        let elapsed = crate::timer::now()
            .checked_sub(runtime.progress.started)
            .unwrap();
        assert_eq!(cpu.iter().sum::<u64>(), parent_cpu);
        assert_eq!(elapsed, parent_cpu);
        assert!(elapsed < profile.ticks());
        let Runtime {
            proof,
            store,
            file,
            progress,
            ..
        } = runtime;
        (proof, store, file, progress, cpu, elapsed)
    };
    let control = FileControl::decode(&file.control.unwrap()).unwrap();
    let bytes = file.report.unwrap();
    assert!(bytes[256..].iter().all(|b| *b == 0));
    let report = FileCompletion::decode(&bytes[..256]).unwrap();
    assert_eq!(control.mode, report.mode);
    assert_eq!(file.outer, report.requests);
    assert_eq!(file.snapshots, report.private_snapshot);
    assert_eq!(proof.authority_denied, report.port_denied);
    assert_eq!(file.block_denied, report.block_denied);
    assert_eq!(
        report.payload,
        <[u8; 32]>::from(Sha256::digest(file_test::DATA_B))
    );
    assert_eq!(
        store.mutations,
        if control.mode == file_test::Mode::Write {
            11
        } else {
            0
        }
    );
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
    for (mailbox, receiver) in [
        (&mut block_box, meta[0].domain),
        (&mut read_box, meta[1].domain),
        (&mut replace_box, meta[1].domain),
    ] {
        mailbox.receiver_died(receiver).unwrap();
        assert_eq!(mailbox.pending(), 0);
    }
    for (index, actor) in actors.iter_mut().enumerate() {
        let ProcessImage { loaded, .. } = actor
            .running
            .take()
            .unwrap()
            .finish(&s)
            .unwrap_or_else(|_| panic!("retained File image owner"));
        if index != 0 {
            // SAFETY: actual returned inactive root; wrong-object refusal must
            // retain the app leaf/lease instead of retiring another buffer.
            let wrong = unsafe { loaded.root.unmap_application_inactive(&mut io) };
            assert!(matches!(
                wrong,
                Err(SharedMapError::Authority(
                    ev_kernel::memory_object::Error::WrongObject
                ))
            ));
            // Running::stop revoked the actual grant. Retained physical lease
            // ownership permits cleanup; it must never authorize redispatch.
            assert!(matches!(
                loaded.root.validate_application(&a, &application),
                Err(SharedMapError::Authority(
                    ev_kernel::memory_object::Error::Authority(
                        ev_kernel::capability::Error::Revoked
                    )
                ))
            ));
            // SAFETY: every actor is stopped, actual controller CR3 restored.
            // Successful exact-owner unmap also proves the refused wrong-object
            // attempt retained the original leaf and its live lease token.
            unsafe { loaded.root.unmap_application_inactive(&mut application) }.unwrap();
        }
        if index != 2 {
            // SAFETY: actual stopped image returned its sole backend lease.
            unsafe { loaded.root.unmap_shared_inactive(&mut io) }.unwrap();
        } else {
            // SAFETY: app never owned a508 leaf; no backend lease may be invented.
            let absent = unsafe { loaded.root.unmap_shared_inactive(&mut io) };
            assert!(matches!(absent, Err(SharedMapError::Missing)));
        }
        // SAFETY: all users stopped and every shared lease returned first.
        let retired = unsafe { loaded.root.retire_in_place(frames) } as u64;
        assert_eq!(retired, actor.meta.frames);
        s.release_frames(actor.meta.job, actor.meta.frames).unwrap();
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
    for (object, cap, alias) in [
        (&mut io, io_cap, io_alias),
        (&mut application, app_cap, app_alias),
    ] {
        let frame = object.destroy(&mut a, custody, cap).unwrap();
        for i in 0..FRAME_SIZE as usize {
            // SAFETY: no mapping or executable owner remains; scrub full frame.
            unsafe { alias.add(i).write_volatile(0) };
        }
        for i in 0..FRAME_SIZE as usize {
            // SAFETY: same sole retained backing before allocator ownership.
            assert_eq!(unsafe { alias.add(i).read_volatile() }, 0);
        }
        frames.reclaim(frame).unwrap();
        s.release_frames(parent, 1).unwrap();
        a.close(custody, cap).unwrap();
    }
    for cap in endpoint_caps {
        a.close(custody, cap).unwrap();
    }
    for mailbox in [block_box, read_box, replace_box] {
        let _receipt = mailbox
            .retire_managed(&mut a)
            .unwrap_or_else(|r| panic!("File endpoint retirement: {:?}", r.error));
    }
    ports.retire(&mut a, custody, port).unwrap();
    for job in actual_jobs {
        registry.forget_job(&mut a, &mut s, &rpc, job).unwrap();
    }
    s.reclaim_job(parent).unwrap();
    a.collect_lineage().unwrap();
    a.collect_dead_objects().unwrap();
    assert_eq!(a.metadata_usage(), (1, 6, 6, 6));
    assert_eq!(registry.metadata_usage(), (0, 3, 0, 6));
    assert_eq!(rpc.metadata_usage(), (0, 0, 0));
    assert_eq!(s.metadata_usage(), (0, 0, 0));
    assert_eq!(ports.registered(), 0);
    assert_eq!(frames.remaining_frames(), before);
    proof.frames = true;
    proof.metadata = true;
    proof.mapped = mapped as u64;
    FileProof {
        control,
        report,
        calls: proof.calls,
        blocks: proof.blocks,
        wakes: proof.wakes,
        replies: proof.replies,
        outer_calls: file.outer,
        backend_calls: file.backend,
        nested_calls: file.nested,
        startup_calls: file.startup,
        pre_delivery_calls: file.before_delivery,
        delivered_nested_calls: file.delivered_nested,
        max_pending: progress.max_pending,
        mutations: store.mutations,
        snapshots: file.snapshots,
        authority_denied: proof.authority_denied,
        block_denied: file.block_denied,
        unbound_denied: file.unbound_denied,
        bindings: file.bindings,
        mapped: proof.mapped,
        elapsed_ticks: elapsed,
        cpu_driver: cpu[0],
        cpu_server: cpu[1],
        cpu_client: cpu[2],
        cpu_parent: cpu.iter().sum(),
        transitions: progress.transitions,
        frames: proof.frames,
        metadata: proof.metadata,
        guards: proof.guards,
    }
}
fn role(selector: u64, kind: Kind, rights: u16) -> Role {
    Role {
        selector,
        kind,
        rights: Rights::from_bits(rights).unwrap(),
    }
}
fn backing(
    a: &mut Authority,
    s: &mut Scheduler,
    owner: SpaceId,
    parent: ev_kernel::scheduler::JobId,
    hw: &Hardware,
    frames: &mut BootstrapFrames,
) -> (MemoryObject, Handle, *mut u8) {
    s.charge_frames(parent, 1).unwrap();
    let frame = frames.allocate().unwrap();
    let alias = direct_address(hw.offset, frame.start(), hw.bits).unwrap() as *mut u8;
    for i in 0..FRAME_SIZE as usize {
        // SAFETY: exclusive unpublished initialized frame, bounded to4096B.
        unsafe { alias.add(i).write_volatile(0) };
    }
    let (object, cap) = MemoryObject::new(a, owner, frame).unwrap();
    (object, cap, alias)
}
#[allow(clippy::too_many_arguments)]
unsafe fn load<'a>(
    r: &mut Registry<'static>,
    a: &Authority,
    s: &mut Scheduler,
    custody: SpaceId,
    control: Handle,
    epoch: NonZeroU64,
    slot: &'a mut LoadedImage,
    mut io: Option<(&mut MemoryObject, Handle)>,
    application: &mut MemoryObject,
    app_cap: Handle,
    hw: &Hardware,
    frames: &mut BootstrapFrames,
) -> Actor<'a> {
    let meta = r.metadata(a, custody, control).unwrap();
    let plan = r.plan(a, custody, control).unwrap();
    let startup = r.startup(a, custody, control, epoch).unwrap();
    for relative in [507 * FRAME_SIZE, 508 * FRAME_SIZE] {
        assert!(!plan.pages().any(|p| p.address == plan.base() + relative));
    }
    // SAFETY: held measured target, sole inactive image slot and frame owner.
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
    if let Some((object, cap)) = io.as_mut() {
        let lease = object.map(a, meta.domain, *cap, true).unwrap();
        // SAFETY: target is held, exact live backend lease and initialized frame.
        unsafe { slot.root.map_shared_inactive(a, object, lease) }
            .unwrap_or_else(|r| shared_failure(r.error));
        let duplicate = object.map(a, meta.domain, *cap, true).unwrap();
        // SAFETY: same backend object must never alias the separate app page.
        let rejected = unsafe { slot.root.map_application_inactive(a, object, duplicate) }
            .expect_err("app/backend object alias must reject");
        assert!(matches!(rejected.error, SharedMapError::Unavailable));
        object.unmap(rejected.lease).unwrap();
    }
    let readonly = application.map(a, meta.domain, app_cap, false).unwrap();
    // SAFETY: fixed app page requires a writable role; retain refused lease.
    let rejected = unsafe { slot.root.map_application_inactive(a, application, readonly) }
        .expect_err("readonly lease is not an app buffer");
    assert!(matches!(rejected.error, SharedMapError::Unavailable));
    application.unmap(rejected.lease).unwrap();
    let lease = application.map(a, meta.domain, app_cap, true).unwrap();
    let mut empty = LoadedImage::empty();
    // SAFETY: empty root must reject without consuming the exact live claim.
    let rejected = unsafe { empty.root.map_application_inactive(a, application, lease) }
        .expect_err("empty root");
    assert!(matches!(rejected.error, SharedMapError::Empty));
    slot.root.activate();
    // SAFETY: held root inherits controller mappings; active-root refusal is
    // inspected only after restoring the retained actual controller CR3.
    let result = unsafe {
        slot.root
            .map_application_inactive(a, application, rejected.lease)
    };
    // SAFETY: exclusive CR3/controller boundary before examining the refusal.
    unsafe { asm!("mov cr3, {}",in(reg)hw.original,options(nostack,preserves_flags)) };
    let rejected = result.expect_err("active root");
    assert!(matches!(rejected.error, SharedMapError::Active));
    // SAFETY: restored inactive root; exact writable initialized separate page.
    unsafe {
        slot.root
            .map_application_inactive(a, application, rejected.lease)
    }
    .unwrap_or_else(|r| shared_failure(r.error));
    let duplicate = application.map(a, meta.domain, app_cap, true).unwrap();
    // SAFETY: occupied507 must retain its original leaf and refused extra claim.
    let rejected = unsafe {
        slot.root
            .map_application_inactive(a, application, duplicate)
    }
    .expect_err("occupied app page");
    assert!(matches!(rejected.error, SharedMapError::Unavailable));
    application.unmap(rejected.lease).unwrap();
    slot.root.validate_application(a, application).unwrap();
    if io.is_none() {
        assert!(slot.root.shared_mapping(508 * FRAME_SIZE).is_none());
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
        .unwrap_or_else(|r| panic!("File admission: {:?}", r.error));
    let context = running.initial_context().unwrap();
    Actor {
        running: Some(running),
        meta,
        control,
        context,
        fx: FxState::CLEAN,
    }
}
