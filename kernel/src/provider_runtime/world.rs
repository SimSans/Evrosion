//! One ordinary Root-created provider graph with exact owned shutdown.
use super::*;
/// # Safety
/// Sole BSP/CR3/IF0/direct-map/bootstrap allocator owner, parked APs, initialized
/// ordinary user trap/FX/PIC boundary. Assets remain immutable through teardown.
#[inline(never)]
#[cfg(feature = "test-m5-provider")]
pub unsafe fn prove(
    offset: u64,
    frames: &mut BootstrapFrames,
    assets: &Assets,
    observe: impl FnMut(Observation),
) -> Proof {
    let source = SourceAssets {
        root_image: assets.root_image,
        root_manifest: assets.root_manifest,
        root_measurement: assets.root_measurement,
        images: &assets.images,
    };
    // SAFETY: same sole controller and retained actual source/allocator contract.
    unsafe { prove_mode(offset, frames, &source, Mode::ProviderSwitch, observe) }
}
/// # Safety
/// Same protected capture/allocator ownership contract as prove(); two retained
/// immutable actor images and an independently admitted ordinary5-role Root.
#[inline(never)]
#[cfg(feature = "test-m5-ipc-bench")]
pub unsafe fn prove_benchmark(
    offset: u64,
    frames: &mut BootstrapFrames,
    assets: &BenchmarkAssets,
    observe: impl FnMut(Observation),
) -> Proof {
    let source = SourceAssets {
        root_image: assets.root_image,
        root_manifest: assets.root_manifest,
        root_measurement: assets.root_measurement,
        images: &assets.images,
    };
    // SAFETY: same actual mechanism ownership, with explicit measurement adapter.
    unsafe { prove_mode(offset, frames, &source, Mode::Measurement, observe) }
}
unsafe fn prove_mode(
    offset: u64,
    frames: &mut BootstrapFrames,
    assets: &SourceAssets<'_>,
    mode: Mode,
    mut observe: impl FnMut(Observation),
) -> Proof {
    let manifest = bootstrap_manifest::verify(
        assets.root_manifest,
        assets.root_measurement,
        assets.root_image,
        ev_userspace_contract::ABI,
    )
    .unwrap();
    assert_eq!(
        manifest.grants().count(),
        if mode == Mode::ProviderSwitch { 6 } else { 5 }
    );
    assert_eq!(
        assets.images.len(),
        if mode == Mode::ProviderSwitch { 3 } else { 2 }
    );
    let mut a = Authority::new();
    let custody = a.create_space().unwrap();
    let branches = a.create_space().unwrap();
    let domain = a.create_space().unwrap();
    let common = Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE | Rights::CONTROL;
    let kinds = [
        Kind::Memory,
        Kind::Endpoint,
        Kind::Job,
        Kind::Memory,
        Kind::Memory,
        Kind::Memory,
    ];
    let rights = [
        Rights::READ,
        Rights::SEND | Rights::RECEIVE,
        Rights::CONTROL,
        Rights::READ,
        Rights::READ,
        Rights::READ,
    ];
    let sources = core::array::from_fn(|i| {
        a.create_root(custody, kinds[i], common | rights[i])
            .unwrap()
    });
    let catalogue: [CatalogEntry; 6] = core::array::from_fn(|i| CatalogEntry {
        selector: i as u64 + 1,
        root: sources[i],
        kind: kinds[i],
    });
    let outer = Mailbox::new(&mut a, custody, sources[1]).unwrap();
    let mut s = Scheduler::new();
    let job = s.create_job_with_limits(manifest.limits()).unwrap();
    let process = s.create_held_process(job).unwrap();
    let thread = s.create_thread(process).unwrap();
    let mut registry = Registry::with_service_limits(EPOCH, CHILD_LIMITS).unwrap();
    registry.register_job(&a, custody, sources[2], job).unwrap();
    for (index, asset) in assets.images.iter().enumerate() {
        let image =
            ServiceImage::verify(asset.bytes, asset.sha, CHILD_LIMITS, asset.roles).unwrap();
        assert_eq!(image.digest(), asset.descriptor);
        registry
            .register_image(&a, custody, sources[3 + index], image)
            .unwrap();
    }
    let images = core::array::from_fn(|i| {
        a.authorize(custody, sources[3 + i], Kind::Memory, Rights::READ)
            .unwrap()
            .identity()
    });
    let mut binding = Bindings::new(EPOCH, &manifest, custody, &catalogue);
    let target = Target {
        process,
        job,
        branches,
        destination: domain,
    };
    let token = binding.prepare(&mut a, &s, target).unwrap();
    let plan = binding.executable(token).unwrap();
    let startup = binding.bootstrap_record(token).unwrap().unwrap();
    s.charge_frames(job, plan.required_frames()).unwrap();
    let original: u64;
    // SAFETY: privileged retained controller CR3 read, before any user entry.
    unsafe {
        asm!("mov {}, cr3",out(reg)original,options(nomem,nostack,preserves_flags));
    }
    let bits = (core::arch::x86_64::__cpuid(0x80000008).eax & 255) as u8;
    let before = frames.remaining_frames();
    // SAFETY: held Root, exact measured ordinary startup/ELF and exclusive allocator.
    let mut root_image = unsafe {
        LoadedImage::load_startup(
            offset,
            bits,
            original & ADDRESS_MASK,
            &plan,
            Some(&startup),
            frames,
        )
    }
    .unwrap();
    let meta = Metadata {
        process,
        thread,
        job,
        domain,
        frames: plan.required_frames(),
    };
    let owner = ProcessImage {
        loaded: &mut root_image,
        process,
        frames: meta.frames,
    };
    let active = binding
        .activate(&a, &mut s, token, thread, owner)
        .unwrap_or_else(|r| panic!("provider Root admission: {:?}", r.error));
    let mut rpc = Rpc::new(EPOCH);
    rpc.register_thread(&a, &s, thread, job, domain, Some(token))
        .unwrap();
    let stop = Deadline::after(crate::timer::now(), WORLD_TICKS).unwrap();
    let mut context = active.initial_context().unwrap();
    context.registers[11] = stop.tick();
    let outer_object = a
        .authorize(custody, sources[1], Kind::Endpoint, Rights::CONTROL)
        .unwrap()
        .identity();
    let mut images_storage = [LoadedImage::empty(), LoadedImage::empty()];
    let mut proof = {
        let mut runtime = Runtime {
            a: &mut a,
            s: &mut s,
            registry: &mut registry,
            rpc: &mut rpc,
            root: Root {
                active: Some(active),
                meta,
                context,
                fx: FxState::CLEAN,
                image: Sha256::digest(assets.root_image).into(),
            },
            token,
            actors: core::array::from_fn(|_| None),
            slots: images_storage.each_mut().map(Some),
            wires: [
                None,
                None,
                None,
                Some(Wire::new(outer_object, custody, outer)),
            ],
            pending: None,
            jobs: [None; 2],
            sources,
            images,
            assets,
            mode,
            measurement: measurement::Recorder::new(),
            stop,
            offset,
            bits,
            original,
            facts: Proof {
                actors: 1,
                starts: 1,
                ..Proof::default()
            },
            root_exited: false,
            observations: &mut observe,
            custody,
        };
        runtime.observe_life(0, LifeKind::Start, None);
        // SAFETY: exact sole captured controller; borrowed tables/owners cannot escape.
        unsafe { runtime.run(frames) };
        assert!(runtime.root_exited && runtime.pending.is_none());
        assert_eq!(runtime.rpc.outstanding(), 0);
        assert!(runtime.actors.iter().all(Option::is_none));
        assert_eq!(runtime.facts.root_exit, Some(0));
        assert_eq!(runtime.facts.consumer_exit, Some(0));
        if mode == Mode::Measurement {
            assert!(runtime.measurement.finished());
            assert_eq!(runtime.facts.batch_finished, 1);
        }
        let active = runtime.root.active.as_mut().unwrap();
        active.revoke(runtime.a, runtime.s, token).unwrap();
        runtime.s.terminate_process(process).unwrap();
        assert!(
            runtime
                .rpc
                .peer_died(runtime.s, thread, crate::timer::now())
                .unwrap()
                .is_empty()
        );
        runtime.a.close_space(domain).unwrap();
        runtime.a.close_space(branches).unwrap();
        for (index, wire) in runtime.wires.iter_mut().enumerate() {
            let Some(mut wire) = wire.take() else {
                continue;
            };
            wire.close(runtime.a, crate::timer::now()).unwrap();
            assert_eq!(wire.pending(), 0);
            let mut mailbox = wire.mailbox.take().unwrap();
            if index == 3 {
                mailbox.retire_empty(runtime.a).unwrap();
            } else {
                let _receipt = mailbox.retire_managed(runtime.a).unwrap_or_else(|r| {
                    panic!("provider managed channel retirement: {:?}", r.error)
                });
            }
        }
        runtime.collect();
        assert!(runtime.jobs.iter().all(Option::is_none));
        runtime.rpc.forget_thread(runtime.s, thread).unwrap();
        let active = runtime.root.active.take().unwrap();
        let (_binding, owner) = active
            .finish(runtime.s, token)
            .unwrap_or_else(|_| panic!("provider Root owned finish"));
        // SAFETY: actual Root Exit, restored CR3, all routes/callers/callees stopped;
        // ordinary Root has no external shared/device mapping claims.
        let returned = unsafe { owner.loaded.root.retire_in_place(frames) };
        assert_eq!(returned as u64, meta.frames);
        runtime.s.release_frames(job, meta.frames).unwrap();
        runtime.facts.reaps += 1;
        runtime.observe_life(0, LifeKind::Reap, None);
        runtime.s.reclaim_process(process).unwrap();
        // SAFETY: all protected worlds stopped and private physical owners returned.
        unsafe { crate::timer::stop_runtime() };
        runtime.facts
    };
    for source in sources {
        a.destroy(custody, source).unwrap();
        a.close(custody, source).unwrap();
    }
    registry.forget_job(&mut a, &mut s, &rpc, job).unwrap();
    a.close_space(custody).unwrap();
    a.collect_lineage().unwrap();
    a.collect_dead_objects().unwrap();
    assert_eq!(a.metadata_usage(), (0, 0, 0, 0));
    assert_eq!(s.metadata_usage(), (0, 0, 0));
    assert_eq!(rpc.metadata_usage(), (0, 0, 0));
    assert_eq!(registry.metadata_usage().0, 0);
    assert_eq!(registry.metadata_usage().2, 0);
    assert_eq!(frames.remaining_frames(), before);
    proof.frames = true;
    proof.metadata = true;
    proof.mappings = true;
    proof.authority = true;
    proof
}
