//! One retained checked graph owner with explicit Desktop/Native boot selection.
use super::*;
use backing::{Assets, Profile as AssetProfile};
struct Outcome {
    graph: Proof,
    #[cfg(feature = "test-m5-native")]
    native: Option<crate::native_runtime::Proof>,
}
enum Selected {
    #[cfg(not(feature = "test-m5-native"))]
    Desktop(ev_kernel::root_manifest_v2::CurrentRoot<'static>),
    #[cfg(feature = "test-m5-native")]
    Native(ev_kernel::root_manifest_v2::NativeRoot<'static>),
}
impl Selected {
    fn manifest(&self) -> &ev_kernel::root_manifest_v2::Manifest<'static> {
        match self {
            #[cfg(not(feature = "test-m5-native"))]
            Self::Desktop(root) => root.manifest(),
            #[cfg(feature = "test-m5-native")]
            Self::Native(root) => root.manifest(),
        }
    }
}
/// # Safety
/// Same sole captured controller and immutable assets as the original Desktop world.
#[cfg(not(feature = "test-m5-native"))]
pub unsafe fn prove(
    offset: u64,
    frames: &mut BootstrapFrames,
    fb: Framebuffer,
    observe: impl FnMut(Observation),
) -> Proof {
    // SAFETY: exact original Desktop assets and unchanged checked engine.
    unsafe { run(offset, frames, fb, &Assets::desktop(), observe) }.graph
}
/// # Safety
/// Actual retained native source assets; same exclusive hardware/allocator owner.
#[cfg(feature = "test-m5-native")]
pub(crate) unsafe fn prove_native(
    offset: u64,
    frames: &mut BootstrapFrames,
    fb: Framebuffer,
    assets: &crate::native_runtime::Assets,
    observe: impl FnMut(Observation),
) -> crate::native_runtime::Proof {
    assert!(matches!(assets.common.profile, AssetProfile::Native));
    // SAFETY: explicit Native selection goes through the same actual owners/gates.
    let outcome = unsafe { run(offset, frames, fb, &assets.common, Some(assets), observe) };
    let mut proof = outcome.native.expect("actual native graph proof");
    proof.graph = outcome.graph;
    proof
}
/// # Safety
/// Serialized BSP/direct map/allocator/device owner, IF0/AP exclusion. No admitted
/// timeout/cancellation/spawn or concurrent shared-buffer writer in this fixture.
#[inline(never)]
unsafe fn run(
    offset: u64,
    frames: &mut BootstrapFrames,
    fb: Framebuffer,
    assets: &Assets<'static>,
    #[cfg(feature = "test-m5-native")] native_assets: Option<&crate::native_runtime::Assets>,
    mut observe: impl FnMut(Observation),
) -> Outcome {
    let original: u64;
    // SAFETY: privileged serialized controller before any user root is active.
    unsafe {
        asm!("mov {}, cr3",out(reg)original,options(nomem,nostack,preserves_flags));
    }
    let before_frames = frames.remaining_frames();
    #[cfg(feature = "test-m5-native")]
    if native_assets.is_some() {
        observe(Observation::NativeMemory(NativeMemory {
            phase: NativeMemoryPhase::Before,
            total_frames: frames.total_frames(),
            remaining_frames: before_frames,
        }));
    }
    let hw = Hardware {
        offset,
        bits: (core::arch::x86_64::__cpuid(0x80000008).eax & 255) as u8,
        original,
    };
    let measured = ev_kernel::root_manifest_v2::verify(
        assets.root_manifest,
        assets.root_measurement,
        assets.root_image,
    )
    .unwrap();
    let profile = match assets.profile {
        #[cfg(not(feature = "test-m5-native"))]
        AssetProfile::Desktop => Selected::Desktop(measured.current_profile().unwrap()),
        #[cfg(feature = "test-m5-native")]
        AssetProfile::Native => Selected::Native(measured.native_profile().unwrap()),
    };
    let mut a = Authority::new();
    let mut s = Scheduler::new();
    let domains = ev_kernel::root_factory_v2::RootDomains::allocate(&mut a).unwrap();
    let boot = s
        .create_job_with_limits(Limits::new(262_144, 1024, 8, 8))
        .unwrap();
    let root_job = s
        .create_child_job(boot, profile.manifest().limits())
        .unwrap();
    // SAFETY: all18 immutable roots created once before any managed graph.
    let mut backing = unsafe {
        #[cfg(feature = "test-m5-native")]
        let result = Backing::new_with_assets(
            domains.custody(),
            &mut a,
            &mut s,
            boot,
            root_job,
            offset,
            hw.bits,
            frames,
            fb,
            assets,
        );
        #[cfg(not(feature = "test-m5-native"))]
        let result = Backing::new_in(
            domains.custody(),
            &mut a,
            &mut s,
            boot,
            root_job,
            offset,
            hw.bits,
            frames,
            fb,
        );
        result
    };
    let custody = backing.custody;
    assert_eq!(backing.source(root_v2::Role::Events), backing.sources[7]);
    #[cfg(feature = "test-m5-native")]
    let mut native_backing = if let Some(extra) = native_assets {
        let catalogue = root_v2::native::catalogue::Catalogue::decode(assets.catalogue).unwrap();
        // SAFETY: common18 finished first; actual validated immutable extra sources.
        Some(
            unsafe {
                crate::native_runtime::backing::NativeBacking::append(
                    &mut a,
                    &mut s,
                    boot,
                    custody,
                    frames,
                    offset,
                    hw.bits,
                    &catalogue,
                    extra.app_b.0,
                    extra.app_b.1,
                    extra.bad_shell.0,
                    extra.bad_shell.1,
                    extra.packages,
                )
            }
            .unwrap_or_else(|r| panic!("native source ownership: {r:?}")),
        )
    } else {
        None
    };
    let mut catalog = [CatalogEntry {
        selector: 0,
        root: Handle(0),
        kind: Kind::Memory,
    }; root_v2::MAX_GRANTS];
    for (i, spec) in root_v2::ROLES.into_iter().enumerate() {
        catalog[i] = CatalogEntry {
            selector: spec.role.selector(),
            root: backing.sources[i],
            kind: kind(spec.kind),
        };
    }
    #[cfg(not(feature = "test-m5-native"))]
    let catalog_count = 18;
    #[cfg(feature = "test-m5-native")]
    let mut catalog_count = 18;
    #[cfg(feature = "test-m5-native")]
    if let Some(extra) = &native_backing {
        for (i, root) in extra.sources().into_iter().enumerate() {
            catalog[18 + i] = CatalogEntry {
                selector: 19 + i as u64,
                root,
                kind: Kind::Memory,
            };
        }
        catalog_count = root_v2::native::CURRENT_GRANTS;
    }
    let catalog = &catalog[..catalog_count];
    let mut registry =
        Registry::with_service_limits(NonZeroU64::new(1).unwrap(), CHILD_LIMITS).unwrap();
    registry
        .register_job(&a, backing.custody, backing.sources[6], boot)
        .unwrap();
    let images = assets.images;
    let base_catalogue =
        root_v2::catalogue::Catalogue::decode(&assets.catalogue[..root_v2::catalogue::SIZE])
            .unwrap();
    for child in CHILDREN {
        let grants = root_v2::graph::grants(child);
        let mut roles = [Role {
            selector: 0,
            kind: Kind::Memory,
            rights: Rights::READ,
        }; 8];
        for (i, g) in grants.iter().enumerate() {
            roles[i] = Role {
                selector: (i + 1) as u64,
                kind: kind(g.kind),
                rights: Rights::from_bits(g.rights).unwrap(),
            };
        }
        let (bytes, sha) = images[child.index()];
        let layout = if child == Child::Display {
            ev_kernel::executable::LayoutReservation::DisplayApertureV1
        } else {
            ev_kernel::executable::LayoutReservation::Legacy
        };
        let image =
            ServiceImage::verify_layout(bytes, sha, CHILD_LIMITS, &roles[..grants.len()], layout)
                .unwrap();
        let declared = base_catalogue.images().nth(child.index()).unwrap();
        assert_eq!(declared.descriptor, image.digest());
        assert_eq!(declared.roles, roles_measurement(child));
        assert_eq!(declared.grants as usize, grants.len());
        assert_eq!(declared.abi, ev_userspace_contract::ABI);
        registry
            .register_image(&a, backing.custody, backing.sources[child.index()], image)
            .unwrap();
    }
    #[cfg(feature = "test-m5-native")]
    if let (Some(extra), Some(physical)) = (native_assets, native_backing.as_ref()) {
        let catalogue = root_v2::native::catalogue::Catalogue::decode(assets.catalogue).unwrap();
        let spec = catalogue.app_b();
        let grants = root_v2::graph::grants(Child::App);
        let roles: [Role; 6] = core::array::from_fn(|i| Role {
            selector: i as u64 + 1,
            kind: kind(grants[i].kind),
            rights: Rights::from_bits(grants[i].rights).unwrap(),
        });
        let image =
            ServiceImage::verify(extra.app_b.0, extra.app_b.1, CHILD_LIMITS, &roles).unwrap();
        assert_eq!(spec.descriptor, image.digest());
        assert_eq!(spec.roles, roles_measurement(Child::App));
        assert_eq!(spec.abi, ev_userspace_contract::ABI);
        assert_eq!(spec.limits, [16_384, 32, 1, 1]);
        registry
            .register_image(&a, custody, physical.app_b, image)
            .unwrap();
    }
    #[cfg(feature = "test-m5-native")]
    if let (Some(extra), Some(physical)) = (native_assets, native_backing.as_ref()) {
        let catalogue = root_v2::native::catalogue::Catalogue::decode(assets.catalogue).unwrap();
        let spec = catalogue.bad_shell();
        let grants = root_v2::graph::grants(Child::Shell);
        let roles: [Role; 8] = core::array::from_fn(|i| Role {
            selector: i as u64 + 1,
            kind: kind(grants[i].kind),
            rights: Rights::from_bits(grants[i].rights).unwrap(),
        });
        let image =
            ServiceImage::verify(extra.bad_shell.0, extra.bad_shell.1, CHILD_LIMITS, &roles)
                .unwrap();
        assert_eq!(spec.descriptor, image.digest());
        assert_eq!(spec.roles, roles_measurement(Child::Shell));
        assert_eq!(spec.abi, ev_userspace_contract::ABI);
        assert_eq!(spec.limits, [16_384, 32, 1, 1]);
        registry
            .register_image(&a, custody, physical.bad_shell.unwrap(), image)
            .unwrap();
    }
    let mut rpc = Rpc::new(EPOCH);
    let process = s.create_held_process(root_job).unwrap();
    let thread = s.create_thread(process).unwrap();
    let (_, target) = domains.into_target(process, root_job);
    let mut custodian = match &profile {
        #[cfg(not(feature = "test-m5-native"))]
        Selected::Desktop(root) => Custodian::new_root_v2(EPOCH, root, backing.custody, catalog),
        #[cfg(feature = "test-m5-native")]
        Selected::Native(root) => Custodian::new_native_root(EPOCH, root, backing.custody, catalog),
    };
    let attempt = custodian.begin(crate::timer::now()).unwrap();
    let (mut binding, token) = custodian.prepare(attempt, &mut a, &s, target).unwrap();
    let root_grants = binding.grants(token).unwrap();
    let mut handles = [Handle(0); root_v2::MAX_GRANTS];
    handles[..root_grants.len()].copy_from_slice(root_grants);
    let root_grants = &handles[..root_grants.len()];
    let startup = match &profile {
        #[cfg(not(feature = "test-m5-native"))]
        Selected::Desktop(_) => binding.bootstrap_record_v2(token).unwrap(),
        #[cfg(feature = "test-m5-native")]
        Selected::Native(_) => binding.bootstrap_record_native(token).unwrap(),
    };
    let plan = binding.executable(token).unwrap();
    s.charge_frames(root_job, plan.required_frames()).unwrap();
    let meta = Metadata {
        process,
        thread,
        job: root_job,
        domain: target.destination,
        frames: plan.required_frames(),
    };
    #[cfg(not(feature = "test-m5-native"))]
    let mut root_slot: LoadedImage;
    #[cfg(feature = "test-m5-native")]
    let mut native_slot = crate::native_runtime::image::NativeRootImage::empty();
    #[cfg(feature = "test-m5-native")]
    let mut bank_maps = 0;
    let owner = match &profile {
        #[cfg(not(feature = "test-m5-native"))]
        Selected::Desktop(_) => {
            // SAFETY: original profile1 loader and exact actual held target.
            root_slot = unsafe {
                LoadedImage::load_root_v2(
                    offset,
                    hw.bits,
                    original & ADDRESS_MASK,
                    &plan,
                    &startup,
                    frames,
                )
            }
            .unwrap();
            // SAFETY: same held root and retained initialized scalar owners.
            unsafe {
                map_root_scalars(
                    &mut root_slot,
                    &mut backing,
                    &a,
                    target.destination,
                    root_grants,
                )
            };
            RootImage::Desktop(ProcessImage {
                loaded: &mut root_slot,
                process,
                frames: meta.frames,
            })
        }
        #[cfg(feature = "test-m5-native")]
        Selected::Native(_) => {
            // SAFETY: named profile2 loader plus measured guarded bank reservations.
            unsafe {
                native_slot.load_private(
                    &plan,
                    meta,
                    &startup,
                    offset,
                    hw.bits,
                    original & ADDRESS_MASK,
                    frames,
                )
            }
            .unwrap();
            let physical = native_backing.as_mut().unwrap();
            for index in 0..2 {
                let lease = physical
                    .bank_mut(index)
                    .map_readonly(&a, meta.domain, root_grants[19 + index])
                    .unwrap();
                native_slot
                    .retain_bank(index, lease)
                    .unwrap_or_else(|(error, _lease)| panic!("native bank retain: {error:?}"));
                // SAFETY: same actual held Root and exact initialized bank owner.
                unsafe { native_slot.install_bank(index, &a, &s, physical.bank(index)) }.unwrap();
                bank_maps += 1;
            }
            // SAFETY: outer owner permits mutation only while actual admission held.
            unsafe {
                map_root_scalars(
                    native_slot.loaded_inactive(&s).unwrap(),
                    &mut backing,
                    &a,
                    target.destination,
                    root_grants,
                )
            };
            RootImage::Native(native_slot.lease().unwrap())
        }
    };
    let active = binding
        .activate(&a, &mut s, token, thread, owner)
        .unwrap_or_else(|r| panic!("desktopRoot activation: {:?}", r.error));
    custodian.confirm_active(&active).unwrap();
    rpc.register_thread(&a, &s, thread, root_job, meta.domain, Some(token))
        .unwrap();
    let event = Mailbox::new(&mut a, meta.domain, root_grants[7]).unwrap();
    let event_object = a
        .authorize(meta.domain, root_grants[7], Kind::Endpoint, RECEIVE)
        .unwrap()
        .identity();
    let mut slots: [GraphicsImage; 6] = core::array::from_fn(|_| GraphicsImage::empty());
    let mut context = active.initial_context().unwrap();
    let start = crate::timer::now();
    #[cfg(not(feature = "test-m5-native"))]
    let world_ticks = WORLD_TICKS;
    #[cfg(feature = "test-m5-native")]
    let world_ticks = root_v2::native::world_ticks(
        root_v2::native::catalogue::Catalogue::decode(assets.catalogue)
            .unwrap()
            .boot_mode(),
    );
    let stop = Deadline::after(start, world_ticks).unwrap();
    context.registers[11] = stop.tick();
    let mut wires: [Option<Wire>; 16] = core::array::from_fn(|_| None);
    wires[15] = Some(Wire::new(event_object, meta.domain, event));
    #[cfg(feature = "test-m5-native")]
    let mut native_proof = None;
    #[cfg(feature = "test-m5-native")]
    let native_images = native_backing.as_ref().map(|physical| {
        [
            a.authorize(custody, backing.sources[4], Kind::Memory, Rights::READ)
                .unwrap()
                .identity(),
            a.authorize(custody, physical.app_b, Kind::Memory, Rights::READ)
                .unwrap()
                .identity(),
        ]
    });
    #[cfg(feature = "test-m5-native")]
    let native_bad_object = native_backing.as_ref().map(|physical| {
        a.authorize(
            custody,
            physical.bad_shell.unwrap(),
            Kind::Memory,
            Rights::READ,
        )
        .unwrap()
        .identity()
    });
    let mut proof = {
        let mut runtime = Runtime {
            a: &mut a,
            s: &mut s,
            registry: &mut registry,
            rpc: &mut rpc,
            root: Root {
                active: Some(active),
                context,
                fx: FxState::CLEAN,
                meta,
            },
            token,
            backing: &mut backing,
            hw,
            actors: core::array::from_fn(|_| None),
            slots: slots.each_mut().map(Some),
            wires,
            pending: [None; 8],
            stop,
            dimensions: (fb.width as u32, fb.height as u32),
            facts: Facts {
                starts: 1,
                mapped: {
                    #[cfg(feature = "test-m5-native")]
                    {
                        2 + bank_maps
                    }
                    #[cfg(not(feature = "test-m5-native"))]
                    {
                        2
                    }
                },
                ..Facts::default()
            },
            observations: &mut observe,
            last_present: [None; 2],
            picker: None,
            old: [None; 6],
            barrier: None,
            request: 0,
            open: None,
            awaiting_open: None,
            selection: None,
            snapshots: [observation::Snapshot::default(); 2],
            grants: grant::Grants::new(),
            jobs: [None; 16],
            receipts: [None],
            root_branches: target.branches,
            boot,
            restored: None,
            #[cfg(not(feature = "test-m5-native"))]
            settled: None,
            display_original: None,
            #[cfg(feature = "test-m5-native")]
            image_shas: images.map(|(_, sha)| sha),
            #[cfg(feature = "test-m5-native")]
            native: native_backing
                .as_mut()
                .map(|physical| crate::native_runtime::State {
                    image_objects: native_images.unwrap(),
                    started_mappings: 0,
                    common_prefix: false,
                    root_image_sha256: Sha256::digest(assets.root_image).into(),
                    root_manifest_sha256: Sha256::digest(assets.root_manifest).into(),
                    self_identity_queries: 0,
                    bad_shell_object: native_bad_object.unwrap(),
                    bad_shell_sha: native_assets.unwrap().bad_shell.1,
                    boot_mode: root_v2::native::catalogue::Catalogue::decode(assets.catalogue)
                        .unwrap()
                        .boot_mode(),
                    image_shas: [images[4].1, native_assets.unwrap().app_b.1],
                    backing: physical,
                    app_starts: [0; 2],
                    app_stops: [0; 2],
                    app_reaps: [0; 2],
                    last_process: [0; 2],
                    last_thread: [0; 2],
                    finish_requested: false,
                    root_exited: false,
                    bank_maps,
                    bank_detaches: 0,
                    readonly_rejections: 0,
                    shell_starts: 0,
                    readonly_denial: None,
                    report: root_v2::native::report::Decoder::new(),
                    report_origin: None,
                    report_error: false,
                    diagnostics: ev_diagnostics::framing::Decoder::new(),
                    diagnostic_origin: None,
                    diagnostic_error: false,
                    diagnostic_queries: 0,
                    last_syscall: [None; 7],
                    profile: crate::native_runtime::profile::Profile::new(crate::timer::now()),
                }),
        };
        // SAFETY: sole serialized controller and all retained physical owners.
        unsafe { runtime.run(frames) };
        let display_survived =
            runtime
                .metadata(Child::Display.index() + 1)
                .is_some_and(|display| {
                    runtime.display_original == Some(display.process)
                        && runtime.s.state(display.thread) != Ok(State::Exited)
                });
        runtime.check_scalar_guards();
        let proof = Proof {
            processes: runtime.facts.starts,
            starts: runtime.facts.starts,
            faults: runtime.facts.faults,
            restarts: runtime.facts.restarts,
            calls: runtime.facts.calls,
            replies: runtime.facts.replies,
            grants: runtime.facts.grants,
            frames: false,
            metadata: false,
            guards: {
                #[cfg(feature = "test-m5-native")]
                if let Some(native) = &runtime.native {
                    assert_eq!(
                        runtime.facts.mapped,
                        2 + native.bank_maps + native.started_mappings
                    );
                }
                #[cfg(feature = "test-m5-native")]
                {
                    runtime.native.is_some() || runtime.facts.mapped == 15
                }
                #[cfg(not(feature = "test-m5-native"))]
                {
                    runtime.facts.mapped == 15
                }
            },
            display_survived,
        };
        assert_eq!(runtime.rpc.outstanding(), 0);
        #[cfg(feature = "test-m5-native")]
        if let Some(native) = &runtime.native {
            assert!(native.root_exited);
            (runtime.observations)(Observation::NativeMemory(NativeMemory {
                phase: NativeMemoryPhase::Held,
                total_frames: frames.total_frames(),
                remaining_frames: frames.remaining_frames(),
            }));
        }
        custodian.begin_revocation(token).unwrap();
        // SAFETY: observed scenario complete, every accepted operation replied;
        // shutdown returns every actual image/map/table owner before physical free.
        unsafe { runtime.shutdown(frames) };
        #[cfg(feature = "test-m5-native")]
        if let Some(native) = &runtime.native {
            native_proof = Some(crate::native_runtime::Proof {
                graph: Proof::default(),
                common_prefix: native.common_prefix,
                app_starts: native.app_starts,
                app_stops: native.app_stops,
                app_reaps: native.app_reaps,
                last_process: native.last_process,
                last_thread: native.last_thread,
                package_pages: native.backing.pages(),
                bank_maps: native.bank_maps,
                bank_detaches: native.bank_detaches,
                bank_reclaimed: 0,
                root_exit: native.root_exited,
                readonly_rejections: native.readonly_rejections,
            });
        }
        // SAFETY: IF0, all user contexts stopped; retained PIC/PIT owner ends here.
        unsafe { crate::timer::stop_runtime() };
        proof
    };
    assert_eq!(s.metadata_usage(), (1, 0, 0));
    #[cfg(feature = "test-m5-native")]
    if let Some(physical) = native_backing.take() {
        let pages = physical.pages().iter().sum::<u64>();
        // SAFETY: actual stopped Root returned both exact PTE/lease owners.
        unsafe { physical.retire(&mut a, &mut s, frames) }
            .unwrap_or_else(|r| panic!("native source retirement: {r:?}"));
        native_proof.as_mut().unwrap().bank_reclaimed = pages;
    }
    // SAFETY: all CPU/mapping/device users have stopped, every scalar/surface
    // lease returned and actual PIO actors disabled DMA throughout this scope.
    unsafe { backing.teardown(&mut a, &mut s, frames) };
    registry.forget_job(&mut a, &mut s, &rpc, boot).unwrap();
    a.close_space(custody).unwrap();
    a.collect_lineage().unwrap();
    a.collect_dead_objects().unwrap();
    assert_eq!(a.metadata_usage(), (0, 0, 0, 0));
    assert_eq!(s.metadata_usage(), (0, 0, 0));
    assert_eq!(rpc.metadata_usage(), (0, 0, 0));
    assert_eq!(registry.metadata_usage().0, 0);
    assert_eq!(registry.metadata_usage().2, 0);
    proof.frames = frames.remaining_frames() == before_frames;
    assert!(proof.frames);
    #[cfg(feature = "test-m5-native")]
    if native_proof.is_some() {
        observe(Observation::NativeMemory(NativeMemory {
            phase: NativeMemoryPhase::After,
            total_frames: frames.total_frames(),
            remaining_frames: frames.remaining_frames(),
        }));
    }
    proof.metadata = true;
    assert!(proof.guards);
    Outcome {
        graph: proof,
        #[cfg(feature = "test-m5-native")]
        native: native_proof,
    }
}
/// # Safety
/// Exact held/stopped Root and retained initialized shared/catalogue objects.
unsafe fn map_root_scalars<const N: usize>(
    loaded: &mut crate::executable_runtime::PrivateLoadedImage<N>,
    backing: &mut Backing,
    a: &Authority,
    domain: SpaceId,
    grants: &[Handle],
) {
    for (which, selector, aux) in [
        (Scalar::System, 9usize, false),
        (Scalar::Catalogue, 12, true),
    ] {
        let object = backing.scalar_mut(which);
        let lease = object.map(a, domain, grants[selector], !aux).unwrap();
        // SAFETY: same held/root exclusive ownership, fixed checked page only.
        let result = unsafe {
            if aux {
                loaded.root.map_catalogue_inactive(a, object, lease)
            } else {
                loaded.root.map_shared_inactive(a, object, lease)
            }
        };
        result.unwrap_or_else(|r| panic!("Root scalar map: {:?}", r.error));
    }
}
fn roles_measurement(child: Child) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"evrosion.desktop.roles.v1\0");
    hash.update([child.index() as u8]);
    for (i, grant) in root_v2::graph::grants(child).iter().enumerate() {
        hash.update((i as u64 + 1).to_le_bytes());
        hash.update([grant.kind]);
        hash.update(grant.rights.to_le_bytes());
        match grant.source {
            root_v2::graph::Source::Root(role) => {
                hash.update([1]);
                hash.update(role.selector().to_le_bytes());
            }
            root_v2::graph::Source::Endpoint(channel) => {
                hash.update([2]);
                hash.update((channel.index() as u64 + 1).to_le_bytes());
            }
        }
    }
    hash.finalize().into()
}
