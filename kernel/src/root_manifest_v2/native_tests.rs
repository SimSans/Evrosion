use super::*;
use crate::{
    bootstrap_binding::CatalogEntry,
    capability::{Authority, Handle, SpaceId},
    custodian::{self, Custodian, QuiescentIncarnation},
    incarnation::{self, Target, Token},
    loaded_image::{Information, LoadedExecutable, Startup},
    scheduler::{Resource, Scheduler},
};
use core::num::NonZeroU64;
use ev_userspace_contract::root_v2::{self, native};

const IMAGE: &[u8] = include_bytes!("../../fixtures/bootstrap-static-v1.elf");
const LIMITS: [u64; 4] = [4096, 256, 8, 8];
const EPOCH: NonZeroU64 = NonZeroU64::new(71).unwrap();
type NativeBytes = [u8; native::MANIFEST_CURRENT_BYTES];
type Catalog = [CatalogEntry; native::CURRENT_GRANTS];

fn inputs(authority: [u8; 32]) -> root_v2::ManifestInputs {
    root_v2::ManifestInputs {
        root_image: Sha256::digest(IMAGE).into(),
        catalogue: [0x57; 32],
        authority,
        limits: LIMITS,
        restart_attempts: 3,
        restart_window: 60,
    }
}
fn parse(bytes: &[u8]) -> Result<Manifest<'_>, Error> {
    verify(bytes, Sha256::digest(bytes).into(), IMAGE)
}
fn context() -> ev_userspace_contract::Context {
    ev_userspace_contract::Context {
        epoch: EPOCH.get(),
        incarnation: 1,
        process: 1,
        limits: LIMITS,
        manifest: [3; 32],
        authority: [4; 32],
    }
}
fn sources(control: bool) -> (Authority, SpaceId, SpaceId, SpaceId, Catalog, NativeBytes) {
    let mut a = Authority::new();
    let c = a.create_control_space().unwrap();
    let (b, d) = if control {
        (
            a.create_control_space().unwrap(),
            a.create_control_space().unwrap(),
        )
    } else {
        (a.create_space().unwrap(), a.create_space().unwrap())
    };
    let catalog = core::array::from_fn(|i| {
        let role = native::ROLES[i];
        let kind = kind(role.kind).unwrap();
        CatalogEntry {
            selector: role.selector,
            kind,
            root: a
                .create_root(
                    c,
                    kind,
                    Rights::from_bits(role.rights).unwrap()
                        | Rights::DERIVE
                        | Rights::TRANSFER
                        | Rights::REVOKE,
                )
                .unwrap(),
        }
    });
    // Independent producer-side transcript over actual retained factory roots.
    // This only computes expected bytes; the binder resolves those roots again.
    let mut hash = Sha256::new();
    hash.update(b"evrosion.bootstrap.authority.root.v2\0");
    hash.update(native::ABI);
    hash.update((native::SIZE as u64).to_le_bytes());
    hash.update(native::PROFILE.to_le_bytes());
    hash.update((native::CURRENT_GRANTS as u64).to_le_bytes());
    for (entry, role) in catalog.iter().zip(native::ROLES) {
        let access = a
            .authorize(c, entry.root, entry.kind, Rights::DERIVE)
            .unwrap();
        hash.update(entry.selector.to_le_bytes());
        hash.update([role.kind]);
        hash.update((access.identity() as u64).to_le_bytes());
        hash.update((access.lineage_root() as u64).to_le_bytes());
        hash.update(role.rights.to_le_bytes());
        hash.update([0]);
        hash.update(0u64.to_le_bytes());
        hash.update(0u64.to_le_bytes());
    }
    let bytes = native::manifest_profile(inputs(hash.finalize().into())).unwrap();
    (a, c, b, d, catalog, bytes)
}

#[test]
fn native_and_desktop_profiles_are_explicit_disjoint_and_keep_legacy_bytes() {
    let native = native::manifest_profile(inputs([9; 32])).unwrap();
    let desktop = root_v2::manifest_profile(inputs([9; 32])).unwrap();
    assert_eq!((native.len(), desktop.len()), (912, 784));
    assert_ne!(native::ABI, root_v2::ABI);
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(native::ABI_DESCRIPTION)),
        native::ABI
    );
    assert!(parse(&native).unwrap().current_profile().is_err());
    assert!(parse(&desktop).unwrap().native_profile().is_err());
    let native = parse(&native).unwrap().native_profile().unwrap();
    let desktop = parse(&desktop).unwrap().current_profile().unwrap();
    let same_bytes_other_owner = parse(native.manifest().bytes())
        .unwrap()
        .native_profile()
        .unwrap();
    assert!(
        crate::root_selection::Selection::Native(&native)
            .same(crate::root_selection::Selection::Native(&native))
    );
    assert!(!crate::root_selection::Selection::Native(&native).same(
        crate::root_selection::Selection::Native(&same_bytes_other_owner)
    ));
    assert!(
        !crate::root_selection::Selection::Native(&native)
            .same(crate::root_selection::Selection::V2(&desktop))
    );
    assert_eq!(native.manifest().grants().count(), 22);
    assert_eq!(desktop.manifest().grants().count(), 18);
    let plan = crate::executable::Image::from_native_root(&native).unwrap();
    assert_eq!(
        plan.startup_layout(),
        crate::executable::StartupLayout::RootV2
    );
    assert_eq!(plan.bootstrap_page(), Some(plan.base() + 509 * 4096));
    assert_eq!(plan.required_frames(), plan.pages().count() as u64 + 6);
    let a = native::encode_full_graph(context(), core::array::from_fn(|i| 256 + i as u64)).unwrap();
    let b =
        root_v2::encode_full_graph(context(), core::array::from_fn(|i| 256 + i as u64)).unwrap();
    assert_eq!((a.len(), b.len()), (720, 720));
    assert!(root_v2::FullGraph::parse(&a).is_err());
    assert!(native::FullGraph::parse(&b).is_err());
    assert!(crate::startup_record::Record::root_v2(&a).is_err());
    assert!(crate::startup_record::Record::native_root(&b).is_err());
    assert_eq!(
        crate::startup_record::Record::native_root(&a)
            .unwrap()
            .bytes(),
        a
    );
    assert!(
        crate::bootstrap_manifest::verify(
            native.manifest().bytes(),
            native.manifest().digest(),
            IMAGE,
            native::ABI,
        )
        .is_err()
    );
}

#[test]
fn native_measurement_profile_roles_and_spare_capacity_fail_closed() {
    let good = native::manifest_profile(inputs([9; 32])).unwrap();
    let expected = Sha256::digest(good).into();
    for offset in 0..good.len() {
        for bit in 0..8 {
            let mut bad = good;
            bad[offset] ^= 1 << bit;
            assert!(matches!(
                verify(&bad, expected, IMAGE),
                Err(Error::Measurement)
            ));
        }
    }
    for (offset, value) in [(48, good[48] ^ 1), (168, 2), (170, 0), (172, 1), (172, 99)] {
        let mut bad = good;
        bad[offset] = value;
        assert!(parse(&bad).is_err());
    }
    for (index, rights) in [(18, 5u16), (19, 231), (20, 1)] {
        let mut bad = good;
        let offset = HEADER + index * GRANT_BYTES + 10;
        bad[offset..offset + 2].copy_from_slice(&rights.to_le_bytes());
        assert!(matches!(
            parse(&bad).unwrap().native_profile(),
            Err(Error::Roles)
        ));
    }
    let mut extra = [0; MAX_BYTES];
    extra[..good.len()].copy_from_slice(&good);
    extra[160] = 24;
    for i in native::CURRENT_GRANTS..24 {
        let offset = HEADER + i * GRANT_BYTES;
        extra[offset..offset + 8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
        extra[offset + 8] = 1;
        extra[offset + 10] = 1;
    }
    assert!(matches!(
        parse(&extra).unwrap().native_profile(),
        Err(Error::Roles)
    ));
    for length in [0, HEADER, good.len() - 1] {
        assert!(parse(&good[..length]).is_err());
    }
}

#[test]
fn native_live_source_substitution_alias_revocation_and_capacity_never_partially_bind() {
    for case in 0..6 {
        // Ordinary16-slot destinations must honestly reject a22-source profile.
        let (mut a, c, b, d, mut catalog, bytes) = sources(case != 5);
        let root = parse(&bytes).unwrap().native_profile().unwrap();
        match case {
            0 => {
                catalog[20].root = a
                    .create_root(c, Kind::Memory, Rights::from_bits(229).unwrap())
                    .unwrap()
            }
            1 => catalog[20].root = catalog[19].root,
            2 => catalog[20].root = Handle(u64::MAX),
            3 => a.revoke(c, catalog[20].root).unwrap(),
            4 => catalog.swap(19, 20),
            _ => (),
        }
        let before = a.metadata_usage();
        let mut s = Scheduler::new();
        let job = s.create_job_with_limits(root.manifest().limits()).unwrap();
        let process = s.create_held_process(job).unwrap();
        s.create_thread(process).unwrap();
        let mut owner = Custodian::new_native_root(EPOCH, &root, c, &catalog);
        let attempt = owner.begin(0).unwrap();
        assert!(
            owner
                .prepare(
                    attempt,
                    &mut a,
                    &s,
                    Target {
                        process,
                        job,
                        branches: b,
                        destination: d
                    }
                )
                .is_err()
        );
        assert_eq!(a.metadata_usage(), before);
        a.require_empty_space(b).unwrap();
        a.require_empty_space(d).unwrap();
        assert_eq!(s.dispatch(0), Ok(None));
        assert_eq!(owner.phase(), custodian::Phase::RecoveryRequired);
        assert_eq!(owner.last_attempt(), 1);
        assert!(owner.begin(1).is_err());
    }
}

struct Model(Information, bool);
// SAFETY: host-only policy model, with no CR3/backing/permission or physical
// quiescence claim. Only the portable admission transaction is exercised here.
#[allow(unsafe_code)]
unsafe impl LoadedExecutable for Model {
    fn information(&self) -> Information {
        self.0
    }
    fn layout(&self) -> crate::executable::LayoutReservation {
        if self.1 {
            crate::executable::LayoutReservation::DisplayApertureV1
        } else {
            crate::executable::LayoutReservation::Legacy
        }
    }
}
struct ModelReceipt(Token);
// SAFETY: test-only metadata witness; no real physical teardown is claimed.
#[allow(unsafe_code)]
unsafe impl QuiescentIncarnation for ModelReceipt {
    fn token(&self) -> Token {
        self.0
    }
}

#[test]
fn native_same_owner_preserves_activation_revocation_history_tokens_and_budget() {
    let (mut a, c, mut branches, mut destination, catalog, bytes) = sources(true);
    let root = parse(&bytes).unwrap().native_profile().unwrap();
    let mut s = Scheduler::new();
    let job = s.create_job_with_limits(root.manifest().limits()).unwrap();
    let mut owner = Custodian::new_native_root(EPOCH, &root, c, &catalog);
    let mut old = None;
    for number in 1..=4 {
        let process = s.create_held_process(job).unwrap();
        let thread = s.create_thread(process).unwrap();
        let attempt = owner.begin(number - 1).unwrap();
        let (mut binding, token) = owner
            .prepare(
                attempt,
                &mut a,
                &s,
                Target {
                    process,
                    job,
                    branches,
                    destination,
                },
            )
            .unwrap();
        assert_eq!(token.number(), number);
        if let Some(old) = old {
            assert_eq!(
                owner.begin_revocation(old),
                Err(custodian::Error::StaleToken)
            );
        }
        assert!(binding.bootstrap_record_v2(token).is_err());
        assert_eq!(binding.bootstrap_record(token).unwrap(), None);
        let startup = binding.bootstrap_record_native(token).unwrap();
        let record = native::FullGraph::parse(&startup).unwrap();
        assert_eq!(record.context().process, process.diagnostic_id());
        assert_eq!(record.context().incarnation, number);
        for (grant, spec) in record.grants().zip(native::ROLES) {
            assert_eq!(
                (grant.selector, grant.kind, grant.rights),
                (spec.selector, spec.kind, spec.rights)
            );
            a.authorize(
                destination,
                Handle(grant.handle),
                kind(spec.kind).unwrap(),
                Rights::from_bits(spec.rights).unwrap(),
            )
            .unwrap();
        }
        let plan = binding.executable(token).unwrap();
        s.charge_frames(job, plan.required_frames()).unwrap();
        let frames = plan.required_frames();
        let information = Information {
            process,
            manifest: root.manifest().digest(),
            entry: plan.entry(),
            stack: plan.stack_top(),
            root: 4096,
            frames,
            startup: Some(Startup {
                address: plan.bootstrap_page().unwrap(),
                bytes: 720,
                digest: Sha256::digest(startup).into(),
            }),
        };
        let mut active = binding
            .activate(&a, &mut s, token, thread, Model(information, false))
            .unwrap_or_else(|r| panic!("native model refused: {:?}", r.error));
        owner.confirm_active(&active).unwrap();
        assert!(owner.begin(number).is_err());
        assert_eq!(s.dispatch(0).unwrap().unwrap().process, process);
        s.charge_cpu(0, 2).unwrap();
        s.exit(0).unwrap();
        owner.begin_revocation(token).unwrap();
        active.revoke(&mut a, &mut s, token).unwrap();
        s.terminate_process(process).unwrap();
        let (binding, _model) = active
            .finish(&s, token)
            .unwrap_or_else(|_| panic!("native model finish"));
        s.release_frames(job, frames).unwrap();
        a.close_space(destination).unwrap();
        a.close_space(branches).unwrap();
        a.collect_lineage().unwrap();
        owner
            .accept_quiescence(&s, binding, ModelReceipt(token))
            .unwrap_or_else(|_| panic!("native metadata receipt refused"));
        s.reclaim_process(process).unwrap();
        assert_eq!(s.usage(job, Resource::CpuTicks), Ok(number * 2));
        assert_eq!(s.usage(job, Resource::Frames), Ok(0));
        destination = a.recycle_space(destination).unwrap();
        branches = a.recycle_space(branches).unwrap();
        old = Some(token);
    }
    assert!(owner.begin(4).is_err());
    assert_eq!(owner.phase(), custodian::Phase::RecoveryRequired);
    assert_eq!(s.usage(job, Resource::CpuTicks), Ok(8));
}

#[test]
fn native_activation_rechecks_exact_startup_identity_before_releasing_hold() {
    for corrupt in 0..6 {
        let (mut a, c, branches, destination, catalog, bytes) = sources(true);
        let root = parse(&bytes).unwrap().native_profile().unwrap();
        let mut s = Scheduler::new();
        let job = s.create_job_with_limits(root.manifest().limits()).unwrap();
        let process = s.create_held_process(job).unwrap();
        let thread = s.create_thread(process).unwrap();
        let mut owner = Custodian::new_native_root(EPOCH, &root, c, &catalog);
        let attempt = owner.begin(0).unwrap();
        let (mut binding, token) = owner
            .prepare(
                attempt,
                &mut a,
                &s,
                Target {
                    process,
                    job,
                    branches,
                    destination,
                },
            )
            .unwrap();
        let startup = binding.bootstrap_record_native(token).unwrap();
        let plan = binding.executable(token).unwrap();
        s.charge_frames(job, plan.required_frames()).unwrap();
        let mut info = Information {
            process,
            manifest: root.manifest().digest(),
            entry: plan.entry(),
            stack: plan.stack_top(),
            root: 4096,
            frames: plan.required_frames(),
            startup: Some(Startup {
                address: plan.bootstrap_page().unwrap(),
                bytes: 720,
                digest: Sha256::digest(startup).into(),
            }),
        };
        match corrupt {
            0 => info.startup.as_mut().unwrap().bytes = 336,
            1 => info.startup.as_mut().unwrap().digest[0] ^= 1,
            2 => info.startup.as_mut().unwrap().address += 4096,
            3 => info.startup = None,
            4 => {
                let desktop =
                    root_v2::encode_full_graph(context(), core::array::from_fn(|i| 256 + i as u64))
                        .unwrap();
                info.startup.as_mut().unwrap().digest = Sha256::digest(desktop).into();
            }
            _ => (),
        }
        let before = a.metadata_usage();
        let rejected = match binding.activate(&a, &mut s, token, thread, Model(info, corrupt == 5))
        {
            Ok(_) => panic!("corrupt native startup admitted"),
            Err(x) => x,
        };
        assert_eq!(rejected.error, incarnation::Error::ImageMismatch);
        assert_eq!(a.metadata_usage(), before);
        assert_eq!(rejected.image.0.process, process);
        assert_eq!(s.dispatch(0), Ok(None));
        owner.report_failure(&rejected.binding).unwrap();
        assert!(owner.begin(1).is_err());
    }
}

#[test]
fn larger_root_load_plan_requires_native_profile_and_unchanged_actual_frame_quota() {
    use crate::executable::{
        Error as ElfError, Image, MAX_IMAGE_PAGES, NATIVE_ROOT_MAX_IMAGE_PAGES,
    };
    assert_eq!((MAX_IMAGE_PAGES, NATIVE_ROOT_MAX_IMAGE_PAGES), (64, 96));
    assert_eq!(crate::executable::NATIVE_ROOT_MAX_PRIVATE_PAGES, 100);
    assert_eq!(crate::executable::NATIVE_ROOT_MAX_PRIVATE_FRAMES, 102);
    for pages in [64u64, 65, 79, 96, 97] {
        let mut image = IMAGE.to_vec();
        image[160..168].copy_from_slice(&((pages - 1) * 4096).to_le_bytes());
        let make_inputs = |frames| {
            let mut input = inputs([9; 32]);
            input.root_image = Sha256::digest(&image).into();
            input.limits[1] = frames;
            input
        };
        let native_bytes = native::manifest_profile(make_inputs(512)).unwrap();
        let root = verify(&native_bytes, Sha256::digest(native_bytes).into(), &image)
            .unwrap()
            .native_profile()
            .unwrap();
        let result = Image::from_native_root(&root);
        if pages <= 96 {
            let plan = result.unwrap();
            assert_eq!(plan.pages().count() as u64, pages);
            assert_eq!(plan.required_frames(), pages + 6);
        } else {
            assert!(matches!(result, Err(ElfError::Capacity)));
        }
        let service = Image::from_descriptor(
            &image,
            [7; 32],
            ev_userspace_contract::ABI,
            crate::scheduler::Limits::new(4096, 512, 8, 8),
        );
        if pages <= 64 {
            assert_eq!(service.unwrap().pages().count() as u64, pages);
        } else {
            assert!(matches!(service, Err(ElfError::Capacity)));
        }
        let desktop_bytes = root_v2::manifest_profile(make_inputs(512)).unwrap();
        let root = verify(&desktop_bytes, Sha256::digest(desktop_bytes).into(), &image)
            .unwrap()
            .current_profile()
            .unwrap();
        let result = Image::from_root_manifest_v2(&root);
        if pages <= 64 {
            assert_eq!(result.unwrap().pages().count() as u64, pages);
        } else {
            assert!(matches!(result, Err(ElfError::Capacity)));
        }
        if pages == 79 {
            let bytes = native::manifest_profile(make_inputs(84)).unwrap();
            let root = verify(&bytes, Sha256::digest(bytes).into(), &image)
                .unwrap()
                .native_profile()
                .unwrap();
            assert!(matches!(
                Image::from_native_root(&root),
                Err(ElfError::FrameBudget)
            ));
        }
    }
}
