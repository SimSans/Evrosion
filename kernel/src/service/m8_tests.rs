extern crate std;
use super::*;
use crate::executable::m8::tests::elf;
use crate::loaded_image::Information;
use ev_userspace_contract::root_v5::{self as v5, graph::ImageSlot};
fn epoch() -> NonZeroU64 {
    NonZeroU64::new(7).unwrap()
}
fn parent(a: &mut Authority, s: &mut Scheduler, r: &mut Registry<'_>) -> (SpaceId, Handle) {
    let owner = a.create_workspace_control_space().unwrap();
    let cap = a.create_root(owner, Kind::Job, PROCESS_RIGHTS).unwrap();
    let job = s
        .create_job_with_limits(Limits::new(1_000_000, 4096, 16, 16))
        .unwrap();
    r.register_job(a, owner, cap, job).unwrap();
    (owner, cap)
}
#[test]
fn selected_closed_job_ids_cannot_expand_legacy_or_supply_user_quotas() {
    let mut a = Authority::for_workspace_profile();
    let mut s = Scheduler::new();
    let mut selected = Registry::for_m8_services(epoch());
    let (owner, p) = parent(&mut a, &mut s, &mut selected);
    for (template, values) in v5::resources::JOB_TEMPLATE_LIMITS.into_iter().enumerate() {
        let cap = selected
            .create_job(&mut a, &mut s, owner, p, template as u64)
            .unwrap();
        let job = selected.job_id(&a, owner, cap).unwrap();
        let actual = s.job_limits(job).unwrap();
        assert_eq!(RESOURCES.map(|r| actual.limit(r)), values);
    }
    let usage = (
        a.metadata_usage(),
        s.metadata_usage(),
        selected.metadata_usage(),
    );
    for template in [4, u64::MAX, 512, 16384] {
        assert_eq!(
            selected.create_job(&mut a, &mut s, owner, p, template),
            Err(Error::UnsupportedTemplate)
        );
        assert_eq!(
            (
                a.metadata_usage(),
                s.metadata_usage(),
                selected.metadata_usage()
            ),
            usage
        );
    }
    let mut legacy = Registry::with_service_templates(
        epoch(),
        Limits::new(16384, 32, 1, 1),
        Limits::new(16384, 64, 1, 1),
    )
    .unwrap();
    let job = selected.job(&a, owner, p).unwrap();
    legacy.register_job(&a, owner, p, job).unwrap();
    let usage = (
        a.metadata_usage(),
        s.metadata_usage(),
        legacy.metadata_usage(),
    );
    for template in [2, 3] {
        assert_eq!(
            legacy.create_job(&mut a, &mut s, owner, p, template),
            Err(Error::UnsupportedTemplate)
        );
        assert_eq!(
            (
                a.metadata_usage(),
                s.metadata_usage(),
                legacy.metadata_usage()
            ),
            usage
        );
    }
}
#[test]
fn measured_cpu_revision_is_finite_hierarchical_and_never_resets_parent_usage() {
    assert_eq!(v5::ROOT_LIMITS, [4_000_000, 4096, 13, 13]);
    assert_eq!(v5::resources::BOOT_LIMITS, [8_000_000, 8192, 14, 14]);
    assert_eq!(SERVICE_LIMITS.limit(Resource::CpuTicks), 128);
    assert_eq!(
        (
            v5::resources::PERIOD_TICKS,
            v5::resources::CHILD_QUOTA_TICKS,
            v5::resources::ROOT_QUOTA_TICKS
        ),
        (256, 64, 256)
    );
    let mut a = Authority::for_workspace_profile();
    let mut s = Scheduler::new();
    let mut r = Registry::for_m8_services(epoch());
    let owner = a.create_workspace_control_space().unwrap();
    let creator = a.create_root(owner, Kind::Job, PROCESS_RIGHTS).unwrap();
    let l = v5::ROOT_LIMITS;
    let parent = s
        .create_job_with_limits(Limits::new(l[0], l[1], l[2], l[3]))
        .unwrap();
    r.register_job(&a, owner, creator, parent).unwrap();
    for cycle in 0..2 {
        let cap = r.create_job(&mut a, &mut s, owner, creator, 0).unwrap();
        let job = r.job_id(&a, owner, cap).unwrap();
        assert_eq!(
            s.job_limits(job).unwrap().limit(Resource::CpuTicks),
            1_000_000
        );
        let process = s.create_process(job).unwrap();
        let thread = s.create_thread(process).unwrap();
        assert_eq!(s.dispatch(0).unwrap().unwrap().thread, thread);
        s.charge_cpu(0, 65_537).unwrap();
        assert_eq!(s.usage(job, Resource::CpuTicks), Ok(65_537));
        s.charge_cpu(0, 1_000_000 - 65_537).unwrap();
        let before = s.usage(parent, Resource::CpuTicks).unwrap();
        assert!(s.charge_cpu(0, 1).is_err());
        assert_eq!(s.usage(parent, Resource::CpuTicks), Ok(before));
        assert_eq!(before, (cycle + 1) * 1_000_000);
        s.exit(0).unwrap();
        s.terminate_process(process).unwrap();
    }
    // Ordinary factory still issues its exact old finite template in the same
    // selected physical Authority; compile-time headroom grants no policy.
    let mut old = Registry::new();
    old.register_job(&a, owner, creator, parent).unwrap();
    let cap = old.create_job(&mut a, &mut s, owner, creator, 0).unwrap();
    let job = old.job_id(&a, owner, cap).unwrap();
    assert_eq!(s.job_limits(job).unwrap().limit(Resource::CpuTicks), 128);
}
#[test]
fn measured_slot_descriptor_admission_is_separate_and_core_digest_is_exact_v1() {
    let b = include_bytes!("../../fixtures/bootstrap-static-v1.elf");
    let selected = ServiceImage::verify_m8(b, Sha256::digest(b).into(), ImageSlot::Block).unwrap();
    let roles: std::vec::Vec<_> = selected.roles().collect();
    let old = ServiceImage::verify(b, Sha256::digest(b).into(), selected.limits(), &roles).unwrap();
    assert_eq!(selected.digest(), old.digest());
    assert_eq!(selected.plan().unwrap().pages().count(), 4);
    let mut a = Authority::for_workspace_profile();
    let owner = a.create_workspace_control_space().unwrap();
    let image = a.create_root(owner, Kind::Memory, Rights::READ).unwrap();
    let mut legacy = Registry::new();
    let mut m8 = Registry::for_m8_services(epoch());
    assert_eq!(
        legacy.register_image(&a, owner, image, selected),
        Err(Error::Descriptor)
    );
    assert_eq!(
        m8.register_image(&a, owner, image, old),
        Err(Error::Descriptor)
    );
    assert_eq!(legacy.metadata_usage(), (0, 0, 0, 0));
    assert_eq!(m8.metadata_usage(), (0, 0, 0, 0));
    let b = elf(&[(2, 1), (480, 8)]);
    let workspace =
        ServiceImage::verify_m8(&b, Sha256::digest(&b).into(), ImageSlot::Workspace).unwrap();
    let roles: std::vec::Vec<_> = workspace.roles().collect();
    assert_eq!(roles.len(), 16);
    assert_eq!(
        ServiceImage::verify(&b, Sha256::digest(&b).into(), workspace.limits(), &roles).err(),
        Some(Error::Descriptor)
    );
    assert_ne!(
        workspace.digest(),
        ServiceImage::verify_m8(&b, Sha256::digest(&b).into(), ImageSlot::Shell)
            .unwrap()
            .digest()
    );
    assert_eq!(
        ServiceImage::verify_m8(&b, [0; 32], ImageSlot::Workspace).err(),
        Some(Error::Measurement)
    );
}
struct Model {
    information: Information,
    layout: LayoutReservation,
}
// SAFETY: portable test model only. No root is dereferenced or executed; these
// receipts exercise admission metadata and do not qualify a physical loader.
#[allow(unsafe_code)]
unsafe impl LoadedExecutable for Model {
    fn information(&self) -> Information {
        self.information
    }
    fn layout(&self) -> LayoutReservation {
        self.layout
    }
}
#[test]
fn hybrid_startup_retains_sixteen_real_grants_and_rejects_wrong_record_before_admission() {
    for slot in [
        ImageSlot::Workspace,
        ImageSlot::Display,
        ImageSlot::Editor,
        ImageSlot::Shell,
    ] {
        let b = elf(&[(2, 1), (480, 8)]);
        let descriptor = ServiceImage::verify_m8(&b, Sha256::digest(&b).into(), slot).unwrap();
        let roles: std::vec::Vec<_> = descriptor.roles().collect();
        let digest = descriptor.digest();
        let mut a = Authority::for_workspace_profile();
        let mut s = Scheduler::new();
        let mut r = Registry::for_m8_services(epoch());
        let (owner, p) = parent(&mut a, &mut s, &mut r);
        let image = a.create_root(owner, Kind::Memory, Rights::READ).unwrap();
        r.register_image(&a, owner, image, descriptor).unwrap();
        let job = r
            .create_job(
                &mut a,
                &mut s,
                owner,
                p,
                slot.representative().job_template(),
            )
            .unwrap();
        let process = r.create_process(&mut a, &mut s, owner, job, image).unwrap();
        let mut grants = std::vec::Vec::new();
        for role in &roles {
            let source = a
                .create_root(owner, role.kind, role.rights | BRANCH)
                .unwrap();
            grants.push(
                r.delegate(&mut a, owner, process, source, role.selector)
                    .unwrap(),
            );
        }
        let startup = r.startup_m8(&a, owner, process, epoch()).unwrap();
        let record = startup.record().unwrap();
        let plan = r.plan(&a, owner, process).unwrap();
        record.check_layout(plan.startup_layout()).unwrap();
        assert_eq!(
            record.bytes().len(),
            v5::child::startup_size(slot.representative())
        );
        if v5::child::extended(slot.representative()) {
            assert_eq!(
                r.startup(&a, owner, process, epoch()).err(),
                Some(Error::Descriptor)
            );
            let parsed = v5::child::Profile::parse(slot.representative(), record.bytes()).unwrap();
            assert_eq!(parsed.context().manifest, digest);
            assert_eq!(parsed.context().limits, slot.representative().limits());
            assert_eq!(
                parsed
                    .grants()
                    .map(|g| Handle(g.handle))
                    .collect::<std::vec::Vec<_>>(),
                grants
            );
            assert!(ev_userspace_contract::Bootstrap::parse(record.bytes()).is_err());
            assert!(
                record
                    .check_layout(executable::StartupLayout::ServiceV1)
                    .is_err()
            );
        } else {
            assert_eq!(
                r.startup(&a, owner, process, epoch()).unwrap().as_slice(),
                record.bytes()
            );
            assert!(
                record
                    .check_layout(executable::StartupLayout::ServiceV5)
                    .is_err()
            );
        }
        let metadata = r.metadata(&a, owner, process).unwrap();
        let info = Information {
            process: metadata.process,
            manifest: digest,
            entry: plan.entry(),
            stack: plan.stack_top(),
            root: 4096,
            frames: plan.required_frames(),
            startup: Some(Startup {
                address: plan.bootstrap_page().unwrap(),
                bytes: record.bytes().len(),
                digest: Sha256::digest(record.bytes()).into(),
            }),
        };
        let usage = (a.metadata_usage(), s.metadata_usage(), r.metadata_usage());
        let mut wrong = info;
        wrong.startup.as_mut().unwrap().bytes = if record.bytes().len() == 336 {
            528
        } else {
            336
        };
        let rejected = r
            .start(
                &a,
                &mut s,
                owner,
                process,
                epoch(),
                Model {
                    information: wrong,
                    layout: plan.layout(),
                },
            )
            .err()
            .unwrap();
        assert_eq!(rejected.error, Error::ImageMismatch);
        assert_eq!(
            (a.metadata_usage(), s.metadata_usage(), r.metadata_usage()),
            usage
        );
        assert_eq!(s.held_process_job(metadata.process).unwrap(), metadata.job);
        let running = r
            .start(
                &a,
                &mut s,
                owner,
                process,
                epoch(),
                Model {
                    information: info,
                    layout: plan.layout(),
                },
            )
            .unwrap_or_else(|e| panic!("{:?}", e.error));
        assert_eq!(running.metadata(), metadata);
        assert_eq!(
            running.initial_context().unwrap().registers[9],
            record.bytes().len() as u64
        );
    }
}
