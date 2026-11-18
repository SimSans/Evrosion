extern crate std;
use super::*;
use crate::native_acquisition::tests::Disk;
use ev_content_store::Area;
use ev_store::SectorIo;

fn run(update: &mut Update<Disk>) -> Outcome {
    let mut buffers = acq::Buffers::empty();
    for _ in 0..2048 {
        update.step(&mut buffers, 1);
        update.observe_after(1);
        if let Some(outcome) = update.outcome() {
            return outcome;
        }
    }
    panic!("finite actual continuation did not complete")
}
fn initialize() -> (Disk, Summary) {
    let mut update = Update::new();
    assert!(update.begin(Disk::blank(), Command::Initialize, 1).is_ok());
    let Outcome::Complete(summary) = run(&mut update) else {
        panic!("initial provision")
    };
    assert_eq!(update.scanned(), 7950);
    (update.take_completed().unwrap(), summary)
}
fn cold_downloads(c: bool) -> Update<Disk> {
    let mut initialized = Update::new();
    assert!(
        initialized
            .begin(Disk::blank(), Command::Initialize, 1)
            .is_ok()
    );
    assert!(matches!(run(&mut initialized), Outcome::Complete(_)));
    let retained = acq::tests::retained_store(initialized.store(), c);
    let mut cold = Update::new();
    assert!(
        cold.begin(
            retained.into_arena().into_backend().cold(),
            Command::Inspect,
            1
        )
        .is_ok()
    );
    assert!(matches!(run(&mut cold), Outcome::Complete(_)));
    cold
}

// This model observes real Loader/Images continuations and exact retained
// object reads. Kernel mapping/retirement and cryptographic admission require
// the separate authenticated persisted-media runtime tests.
#[derive(Default)]
struct ImageTrace {
    operations: std::vec::Vec<(ev_userspace_contract::root_v4::dynamic::Operation, u64)>,
    fail_readonly: bool,
}
struct TracedImages {
    model: crate::native_sources::tests::Model,
    trace: std::rc::Rc<std::cell::RefCell<ImageTrace>>,
}
impl crate::native_image::Io for TracedImages {
    fn control(
        &mut self,
        op: ev_userspace_contract::root_v4::dynamic::Operation,
        operand: u64,
        extra: u64,
    ) -> ev_userspace_runtime::CapReply {
        self.trace.borrow_mut().operations.push((op, operand));
        self.model.control(op, operand, extra)
    }
    fn write_header(&mut self, b: &[u8; 256]) -> Result<(), crate::native_image::IoError> {
        self.model.write_header(b)
    }
    fn write_staging(&mut self, at: usize, b: &[u8]) -> Result<(), crate::native_image::IoError> {
        self.model.write_staging(at, b)
    }
    fn readonly(&self, s: usize, n: usize) -> Result<&[u8], crate::native_image::IoError> {
        if self.trace.borrow().fail_readonly {
            return Err(crate::native_image::IoError);
        }
        self.model.readonly(s, n)
    }
}
fn mutant_candidate(kind: &str) -> std::vec::Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut b = include_bytes!("../../../fixtures/acquisition/phase-c/hello.zion").to_vec();
    let manifest = u32::from_le_bytes(b[20..24].try_into().unwrap()) as usize;
    let count = u16::from_le_bytes(b[24..26].try_into().unwrap()) as usize;
    let table = 96 + manifest;
    let elf = u32::from_le_bytes(b[table + 4..table + 8].try_into().unwrap()) as usize;
    let len = u32::from_le_bytes(b[table + 8..table + 12].try_into().unwrap()) as usize;
    match kind {
        "prefix" => b[0] ^= 1,
        "elf" => b[elf] ^= 1,
        "abi" | "contract" | "source" | "version" | "source-abi" | "source-contract"
        | "version-abi" | "version-contract" => {
            let mut at = 96;
            let mut changed = false;
            while at < table {
                let tag = u16::from_le_bytes(b[at..at + 2].try_into().unwrap());
                let n = u32::from_le_bytes(b[at + 4..at + 8].try_into().unwrap()) as usize;
                let body = at + 8;
                if kind.contains("abi") && tag == 9 {
                    b[body] ^= 0x80;
                    changed = true;
                }
                if kind.contains("contract") && tag == 12 {
                    b[body + 10..body + 12].copy_from_slice(&65534u16.to_le_bytes());
                    changed = true;
                }
                if kind.contains("source") && tag == 3 {
                    b[body] ^= 1; // Parse-valid text with a known source-binding mismatch.
                    changed = true;
                }
                if kind.contains("version") && tag == 5 {
                    b[body + 8] ^= 1; // Parse-valid version inconsistent with Content3.
                    changed = true;
                }
                at = body + n;
            }
            assert!(changed);
        }
        "valid" => (),
        _ => panic!("unknown model vector"),
    }
    let digest: [u8; 32] = Sha256::digest(&b[elf..elf + len]).into();
    b[table + 16..table + 48].copy_from_slice(&digest);
    let digest: [u8; 32] = Sha256::digest(&b[96..table]).into();
    b[32..64].copy_from_slice(&digest);
    let digest: [u8; 32] = Sha256::digest(&b[table..table + count * 128]).into();
    b[64..96].copy_from_slice(&digest);
    b
}
fn modeled_candidate(kind: &str, required: bool, wrong_descriptor: bool) -> Update<Disk> {
    let mut update = cold_downloads(true);
    let store = acq::tests::image_loader_candidate(
        update.store(),
        &mutant_candidate(kind),
        required,
        false,
        wrong_descriptor,
    );
    update.io = Some(Io::Store(store));
    update
}
fn traced_images() -> (
    crate::native_image::Images<TracedImages>,
    std::rc::Rc<std::cell::RefCell<ImageTrace>>,
) {
    let trace = std::rc::Rc::new(std::cell::RefCell::new(ImageTrace::default()));
    let mut images = crate::native_image::Images::new(
        TracedImages {
            model: crate::native_sources::tests::empty_model(),
            trace: trace.clone(),
        },
        0x8000000000,
    )
    .unwrap();
    images.initialize(1).unwrap();
    (images, trace)
}
fn load_modeled(
    update: &mut Update<Disk>,
    images: &mut crate::native_image::Images<TracedImages>,
) -> Result<crate::native_cold::Loader, crate::native_cold::Error> {
    let mut loader = crate::native_cold::Loader::new();
    let mut buffers = acq::Buffers::empty();
    for _ in 0..2048 {
        if loader.step(update, images, &mut buffers, 1)? {
            return Ok(loader);
        }
    }
    panic!("bounded image loading did not terminate")
}
#[test]
fn optional_candidate_clean_rejection_preserves_independent_active_known_good_and_owner() {
    use crate::native_sources::{DownloadedSlot, Resolver, Source, Sources};
    use ev_userspace_contract::root_v4::dynamic::Operation;
    for kind in ["prefix", "elf", "abi", "contract"] {
        let mut update = modeled_candidate(kind, false, false);
        let snapshot = update.retained_snapshot().unwrap();
        let before = (
            snapshot.candidate(),
            snapshot.active(),
            snapshot.known_good(),
        );
        let cut = update.original_cut();
        let (mut images, trace) = traced_images();
        let loader = load_modeled(&mut update, &mut images)
            .unwrap_or_else(|e| panic!("optional {kind} poisoned valid B: {e:?}"));
        let bindings = loader.bindings().unwrap();
        assert_eq!(
            bindings[1], None,
            "rejected C never becomes a resolver member"
        );
        let (slot, b) = bindings[0].unwrap();
        assert_eq!(Some(b), before.1);
        assert_eq!(Some(b), before.2);
        assert_eq!(slot, usize::from(kind != "prefix"));
        assert!(images.registered_capability(slot).is_some());
        if kind != "prefix" {
            assert!(images.bytes(0).is_ok(), "permanent Root RO reader retained");
            assert!(images.registered_capability(0).is_none());
        }
        let registrations: std::vec::Vec<_> = trace
            .borrow()
            .operations
            .iter()
            .filter(|(op, _)| *op == Operation::Register)
            .copied()
            .collect();
        assert_eq!(registrations, [(Operation::Register, slot as u64 + 1)]);
        let after = update.retained_snapshot().unwrap();
        assert_eq!(after.candidate(), before.0, "no metadata reset");
        assert_eq!(after.active(), before.1);
        assert_eq!(after.known_good(), before.2);
        assert_eq!(update.original_cut(), cut);
        let (catalogue, context, bank_a, bank_b) = crate::native_sources::tests::fixture();
        let banks =
            crate::native_plan::Packages::verify_network(&catalogue, context, &bank_a, &bank_b)
                .unwrap();
        let sources = Resolver::new(&banks, &images, Some(after), bindings).unwrap();
        assert_eq!(
            sources.source(b.package),
            Some(Source::Downloaded(DownloadedSlot::B))
        );
        assert_eq!(
            sources.source(before.0.unwrap().package),
            None,
            "System selection of rejected C cannot resolve to a different cohort"
        );
        assert!(
            update.take_completed().is_some(),
            "reader drained and exact owner restored"
        );
    }
}
#[test]
fn required_candidate_and_uncertain_image_failure_remain_fenced() {
    use ev_userspace_contract::root_v4::dynamic::Operation;
    for (kind, required, wrong_descriptor, fail_readonly) in [
        ("prefix", true, false, false),
        ("elf", true, false, false),
        ("abi", true, false, false),
        ("contract", true, false, false),
        ("valid", false, true, false),
        ("elf", false, true, false),
        ("elf", false, false, true),
    ] {
        let mut update = modeled_candidate(kind, required, wrong_descriptor);
        let (mut images, trace) = traced_images();
        trace.borrow_mut().fail_readonly = fail_readonly;
        assert!(load_modeled(&mut update, &mut images).is_err());
        assert!(
            !trace
                .borrow()
                .operations
                .iter()
                .any(|(op, _)| *op == Operation::Register)
        );
    }
    for kind in ["prefix", "elf", "abi", "contract"] {
        let mut update = cold_downloads(true);
        let store = acq::tests::image_loader_candidate(
            update.store(),
            &mutant_candidate(kind),
            false,
            true,
            false,
        );
        update.io = Some(Io::Store(store));
        let (mut images, trace) = traced_images();
        assert!(load_modeled(&mut update, &mut images).is_err());
        assert!(
            !trace
                .borrow()
                .operations
                .iter()
                .any(|(op, _)| *op == Operation::Register)
        );
    }
}
#[test]
fn known_source_and_version_bindings_precede_optional_compatibility_rejection() {
    use crate::native_sources::{Downloaded, Error};
    use ev_userspace_contract::root_v4::dynamic::Operation;
    for (kind, expected) in [
        ("source", Error::Source),
        ("source-abi", Error::Source),
        ("source-contract", Error::Source),
        ("version", Error::Identity),
        ("version-abi", Error::Identity),
        ("version-contract", Error::Identity),
    ] {
        assert!(ev_zion::Package::parse(&mutant_candidate(kind)).is_ok());
        let mut update = modeled_candidate(kind, false, false);
        let (mut images, trace) = traced_images();
        assert!(load_modeled(&mut update, &mut images).is_err(), "{kind}");
        let snapshot = update.retained_snapshot().unwrap();
        let error = Downloaded::from_images(&images, 0, snapshot, snapshot.candidate().unwrap())
            .err()
            .expect("known association must refuse");
        assert_eq!(error, expected, "{kind}");
        assert!(
            !trace
                .borrow()
                .operations
                .iter()
                .any(|(op, _)| *op == Operation::Register)
        );
        assert!(images.bytes(0).is_ok(), "sealed reader remains owned");
    }
}
#[test]
fn optional_prefix_refusal_still_requires_whole_hash_io_and_original_cut() {
    use ev_userspace_contract::root_v4::dynamic::Operation;
    for lost_io in [false, true] {
        let mut update = modeled_candidate("prefix", false, false);
        let store = acq::tests::damage_image_loader_candidate(update.store(), lost_io);
        update.io = Some(Io::Store(store));
        let (mut images, trace) = traced_images();
        assert!(load_modeled(&mut update, &mut images).is_err());
        assert!(update.take_completed().is_none());
        assert!(
            !trace
                .borrow()
                .operations
                .iter()
                .any(|(op, _)| *op == Operation::Register)
        );
    }
    let mut update = modeled_candidate("prefix", false, false);
    let cut = update.original_cut().unwrap();
    let (mut images, trace) = traced_images();
    let mut loader = crate::native_cold::Loader::new();
    let mut buffers = acq::Buffers::empty();
    // Select, open reader, first read, syntax refusal; draining has not completed.
    for _ in 0..4 {
        assert_eq!(
            loader.step(&mut update, &mut images, &mut buffers, 1),
            Ok(false)
        );
    }
    assert!(
        loader
            .step(&mut update, &mut images, &mut buffers, cut)
            .is_err()
    );
    assert!(loader.failed());
    assert!(loader.bindings().is_none());
    assert!(update.take_completed().is_none());
    assert_eq!(update.original_cut(), Some(cut));
    assert!(
        !trace
            .borrow()
            .operations
            .iter()
            .any(|(op, _)| *op == Operation::Register)
    );
}
#[test]
fn authenticated_cold_objects_stream_once_to_distinct_registered_images_before_owner_return() {
    use crate::{
        native_cold::Loader,
        native_sources::{DownloadedSlot, Resolver, Source, Sources},
    };
    let mut update = cold_downloads(true);
    let mut images = crate::native_sources::tests::empty_images();
    let mut loader = Loader::new();
    let mut buffers = acq::Buffers::empty();
    for _ in 0..1024 {
        if loader
            .step(&mut update, &mut images, &mut buffers, 1)
            .unwrap()
        {
            break;
        }
        update.observe_after(1);
    }
    let bindings = loader.bindings().expect("finite real streaming completes");
    assert_eq!(bindings[0].unwrap().0, 1); // CandidateC loaded first, then activeB.
    assert_eq!(bindings[1].unwrap().0, 0);
    let b = include_bytes!("../../../fixtures/acquisition/phase-b/hello.zion");
    let c = include_bytes!("../../../fixtures/acquisition/phase-c/hello.zion");
    assert_eq!(images.bytes(1).unwrap(), b);
    assert_eq!(images.bytes(0).unwrap(), c);
    assert!(images.registered_capability(0).is_some());
    assert!(images.registered_capability(1).is_some());
    let mut snapshot = None;
    assert!(update.snapshot_into(&mut snapshot));
    let snapshot = snapshot.unwrap();
    let (catalogue, context, bank_a, bank_b) = crate::native_sources::tests::fixture();
    let banks = crate::native_plan::Packages::verify_network(&catalogue, context, &bank_a, &bank_b)
        .unwrap();
    let sources = Resolver::new(&banks, &images, Some(&snapshot), bindings).unwrap();
    assert_eq!(
        sources.source(bindings[0].unwrap().1.package),
        Some(Source::Downloaded(DownloadedSlot::B))
    );
    assert_eq!(
        sources.source(bindings[1].unwrap().1.package),
        Some(Source::Downloaded(DownloadedSlot::C))
    );
    assert_eq!(snapshot.active(), snapshot.known_good()); // Prior TEST lifecycle carrier is preserved.
    assert_eq!(snapshot.active(), Some(bindings[0].unwrap().1));
    assert_eq!(snapshot.candidate(), Some(bindings[1].unwrap().1));
    assert!(update.take_completed().is_some());
    assert!(!update.busy());
}
#[test]
fn local_streaming_rejects_foreign_membership_and_expiry_without_backend_or_binding_release() {
    let mut update = cold_downloads(false);
    let good = update.retained_snapshot().unwrap().candidate().unwrap();
    let mut foreign = good;
    foreign.source[0] ^= 1;
    assert_eq!(
        update.begin_retained_read(foreign, 1),
        Err(Failure::Authentication)
    );
    assert_eq!(update.retained_snapshot().unwrap().candidate(), Some(good));
    let mut images = crate::native_sources::tests::empty_images();
    let mut loader = crate::native_cold::Loader::new();
    let mut buffers = acq::Buffers::empty();
    for _ in 0..3 {
        assert_eq!(
            loader.step(&mut update, &mut images, &mut buffers, 1),
            Ok(false)
        );
    }
    let cut = update.original_cut().unwrap();
    assert!(
        loader
            .step(&mut update, &mut images, &mut buffers, cut)
            .is_err()
    );
    update.observe_after(cut);
    assert!(loader.failed());
    assert!(loader.bindings().is_none());
    assert!(update.take_completed().is_none());
    assert!(images.registered_capability(0).is_none());
    assert_eq!(update.outcome(), Some(Outcome::Failed(Failure::Clock)));
    assert_eq!(update.original_cut(), Some(cut));
}
#[test]
fn actual_provision_rom_checkpoint_and_full_cold_inspection_restore_same_backend() {
    let (backend, summary) = initialize();
    assert_eq!(
        summary,
        Summary {
            revision: 1,
            ..Summary::default()
        }
    );
    let mut inspect = Update::new();
    assert!(inspect.begin(backend.cold(), Command::Inspect, 1).is_ok());
    assert_eq!(run(&mut inspect), Outcome::Complete(summary));
    assert!(inspect.take_completed().is_some());
    assert!(!inspect.busy());
}
#[test]
fn unformatted_inspection_never_formats_and_a_separate_explicit_init_is_required() {
    let mut inspect = Update::new();
    assert!(inspect.begin(Disk::blank(), Command::Inspect, 1).is_ok());
    assert_eq!(run(&mut inspect), Outcome::Unformatted);
    let mut backend = inspect.take_completed().unwrap();
    for sector in 0..ev_store::REQUIRED_SECTORS {
        let mut bytes = [1; 512];
        backend
            .device(Area::Checkpoint)
            .read(sector, &mut bytes, 2)
            .unwrap();
        assert_eq!(bytes, [0; 512]);
    }
    assert!(inspect.begin(backend, Command::Initialize, 1).is_ok());
    assert!(matches!(run(&mut inspect), Outcome::Complete(_)));
}
#[test]
fn foreign_nonblank_content_refuses_without_format_or_owner_release() {
    let mut backend = Disk::blank();
    backend
        .device(Area::Objects)
        .write(17, &[0x63; 512], 2)
        .unwrap();
    backend.device(Area::Objects).flush(2).unwrap();
    let mut update = Update::new();
    assert!(update.begin(backend, Command::Initialize, 1).is_ok());
    assert_eq!(run(&mut update), Outcome::Failed(Failure::NotBlank));
    assert!(update.take_completed().is_none());
    assert!(!update.cancel());
    let Some(Io::Scan(p)) = update.io else {
        panic!("real failed owner not retained")
    };
    let mut backend = p.into_backend();
    let mut bytes = [0; 512];
    backend
        .device(Area::Objects)
        .read(17, &mut bytes, 2)
        .unwrap();
    assert_eq!(bytes, [0x63; 512]);
    for sector in 0..ev_store::REQUIRED_SECTORS {
        backend
            .device(Area::Checkpoint)
            .read(sector, &mut bytes, 2)
            .unwrap();
        assert_eq!(bytes, [0; 512]);
    }
}
#[test]
fn original_cut_and_post_io_expiry_never_release_owner_or_renew() {
    for post_io in [false, true] {
        let mut update = Update::new();
        assert!(update.begin(Disk::blank(), Command::Initialize, 1).is_ok());
        let cut = update.original_cut().unwrap();
        let mut buffers = acq::Buffers::empty();
        if post_io {
            update.step(&mut buffers, 1);
            update.observe_after(cut);
        } else {
            update.step(&mut buffers, cut);
        }
        assert_eq!(update.original_cut(), Some(cut));
        assert_eq!(update.outcome(), Some(Outcome::Failed(Failure::Clock)));
        assert!(update.take_completed().is_none());
        assert!(!update.cancel());
        update.step(&mut buffers, cut + 1);
        assert_eq!(update.original_cut(), Some(cut));
    }
}
#[test]
fn cancellation_at_quiescent_step_preserves_actual_append_highwater_and_never_publishes() {
    let mut update = Update::new();
    assert!(update.begin(Disk::blank(), Command::Initialize, 1).is_ok());
    let mut buffers = acq::Buffers::empty();
    for _ in 0..1100 {
        update.step(&mut buffers, 1);
        update.observe_after(1);
        if matches!(update.phase, Phase::Put) {
            break;
        }
    }
    assert!(matches!(update.phase, Phase::Put));
    assert!(update.cancel());
    assert_eq!(update.outcome(), Some(Outcome::Cancelled));
    let backend = update.take_completed().unwrap();
    let t = TransferCut::new(1, 8193).unwrap();
    let arena = Arena::open(backend.cold(), creation_manifest(), t.metadata(1).unwrap())
        .unwrap_or_else(|_| panic!("actual retained format"));
    assert_eq!(
        arena.reserved_sectors(),
        acq::ROM_ROOT.len().div_ceil(512) as u64 + 1
    );
    assert_eq!(arena.published_metadata(), None);
}
#[test]
fn creation_identity_is_independent_of_executable_and_refuses_foreign_namespace() {
    let creation = creation_manifest();
    assert!(creation.valid());
    assert_eq!(creation.abi, ev_content_store::FORMAT_ABI);
    let (backend, _) = initialize();
    let mut foreign = creation;
    foreign.cohort[0] ^= 1;
    let t = TransferCut::new(1, 8193).unwrap();
    assert!(Arena::open(backend.cold(), foreign, t.metadata(1).unwrap()).is_err());
    assert!(PROVISION_TICKS >= VOLUME_SECTORS.div_ceil(8) * 1024 + 8192);
}

#[test]
fn cancellation_cannot_label_an_already_published_checkpoint_unpublished() {
    let mut update = Update::new();
    assert!(update.begin(Disk::blank(), Command::Initialize, 1).is_ok());
    let mut buffers = acq::Buffers::empty();
    for _ in 0..2048 {
        update.step(&mut buffers, 1);
        update.observe_after(1);
        if update.phase == Phase::Published {
            break;
        }
    }
    assert!(update.phase == Phase::Published);
    assert!(!update.cancel());
    update.step(&mut buffers, 1);
    update.observe_after(1);
    assert!(matches!(
        update.outcome(),
        Some(Outcome::Complete(Summary { revision: 1, .. }))
    ));
    let backend = update.take_completed().unwrap();
    let mut reopened = Update::new();
    assert!(reopened.begin(backend.cold(), Command::Inspect, 1).is_ok());
    assert!(matches!(
        run(&mut reopened),
        Outcome::Complete(Summary { revision: 1, .. })
    ));
}

#[test]
fn refused_overflow_observation_cannot_hide_a_later_clock_rollback() {
    let mut update = Update::new();
    let rejected = update
        .begin(Disk::blank(), Command::Initialize, u64::MAX - 1)
        .err()
        .unwrap();
    assert!(
        update
            .begin(rejected.backend, Command::Initialize, 1)
            .is_err()
    );
    assert!(!update.busy());
}

#[test]
fn authenticated_snapshot_is_extracted_once_before_the_exact_backend_returns() {
    let mut update = Update::new();
    assert!(update.begin(Disk::blank(), Command::Initialize, 1).is_ok());
    assert!(matches!(run(&mut update), Outcome::Complete(_)));
    let mut snapshot = None;
    assert!(update.snapshot_into(&mut snapshot));
    assert_eq!(snapshot.as_ref().unwrap().revision(), 1);
    assert_eq!(snapshot.as_ref().unwrap().replay().utc_floor(), 0);
    assert!(!update.snapshot_into(&mut snapshot));
    let backend = update.take_completed().unwrap();
    let mut inspect = Update::new();
    assert!(inspect.begin(backend.cold(), Command::Inspect, 1).is_ok());
    assert!(matches!(run(&mut inspect), Outcome::Complete(_)));
    assert_eq!(snapshot.as_ref().unwrap().revision(), 1);
}

fn prepared_fetch() -> Update<Disk> {
    let mut update = cold_downloads(false);
    let backend = update.take_completed().unwrap();
    assert!(update.begin(backend, Command::Fetch, 1).is_ok());
    assert!(matches!(run(&mut update), Outcome::Complete(_)));
    let (store, workspace) = update.authorization_parts().unwrap();
    let snapshot = store.snapshot().unwrap();
    let material = |i, bytes| acq::Material {
        object: snapshot.metadata_object(i).unwrap(),
        bytes,
    };
    let remote = acq::Remote {
        current_root: acq::ROM_ROOT,
        root_updates: &[],
        metadata: [
            material(
                0,
                include_bytes!("../../../fixtures/acquisition/phase-b/targets.bin"),
            ),
            material(
                1,
                include_bytes!("../../../fixtures/acquisition/phase-b/snapshot.bin"),
            ),
            material(
                2,
                include_bytes!("../../../fixtures/acquisition/phase-b/timestamp.bin"),
            ),
        ],
        candidate: acq::Material {
            object: snapshot.candidate().unwrap().object,
            bytes: include_bytes!("../../../fixtures/acquisition/phase-b/hello.zion"),
        },
    };
    store
        .authorize_into(remote, &mut acq::tests::TestClock::new(0), workspace)
        .unwrap();
    update
}
#[test]
fn prepared_without_commit_io_cancels_once_and_retains_prior_checkpoint_on_cold_reopen() {
    let mut update = prepared_fetch();
    assert!(update.commit.has_authorized());
    let prior = update.retained_snapshot().unwrap().revision();
    let cut = update.original_cut();
    assert!(update.cancel());
    assert_eq!(update.outcome(), Some(Outcome::Cancelled));
    assert!(update.commit.is_empty());
    assert_eq!(update.original_cut(), cut);
    let backend = update.take_completed().unwrap();
    assert!(!update.busy());
    assert!(!update.cancel());
    assert!(update.begin(backend.cold(), Command::Inspect, 1).is_ok());
    assert!(matches!(run(&mut update), Outcome::Complete(Summary{revision,..}) if revision==prior));
}
#[test]
fn prepared_consumption_expiry_cannot_cancel_release_or_hide_original_owner_fence() {
    let mut update = prepared_fetch();
    let cut = update.original_cut().unwrap();
    assert_eq!(update.begin_prepared_fetch(cut), Err(Failure::Clock));
    assert_eq!(update.outcome(), Some(Outcome::Failed(Failure::Clock)));
    assert!(!update.cancel());
    update.refuse_fetch(cut);
    assert!(update.commit.is_empty()); // Only no-IO prepared metadata was discarded.
    assert!(update.take_completed().is_none());
    assert!(update.release_settled_refusal().is_none());
    assert!(update.busy());
    assert_eq!(update.original_cut(), Some(cut));
    update.observe_after(2);
    assert!(update.release_settled_refusal().is_none());
}
#[test]
fn backend_only_cold_and_commit_cancellation_preserve_real_media_and_append_highwater() {
    for cold in [false, true] {
        let mut update = Update::new();
        assert!(update.begin(Disk::blank(), Command::Initialize, 1).is_ok());
        if cold {
            assert!(matches!(run(&mut update), Outcome::Complete(_)));
            let backend = update.take_completed().unwrap();
            assert!(update.begin(backend, Command::Inspect, 1).is_ok());
        }
        let mut buffers = acq::Buffers::empty();
        for _ in 0..2048 {
            update.step(&mut buffers, 1);
            update.observe_after(1);
            if if cold {
                !update.cold.is_empty()
            } else {
                !update.commit.is_empty()
            } {
                break;
            }
        }
        assert!(if cold {
            !update.cold.is_empty()
        } else {
            !update.commit.is_empty()
        });
        assert!(update.cancel());
        let backend = update.take_completed().unwrap();
        let arena = Arena::open(
            backend.cold(),
            creation_manifest(),
            TransferCut::new(1, 8193).unwrap().metadata(1).unwrap(),
        )
        .unwrap_or_else(|_| panic!("exact retained media"));
        assert_eq!(arena.published_metadata().is_some(), cold);
        assert!(arena.reserved_sectors() > acq::ROM_ROOT.len().div_ceil(512) as u64);
        if cold {
            assert!(
                update
                    .begin(arena.into_backend(), Command::Inspect, 1)
                    .is_ok()
            );
            assert!(matches!(
                run(&mut update),
                Outcome::Complete(Summary { revision: 1, .. })
            ));
        }
    }
}

// Regression for the live Main Fetch semantic-refusal preservation. This drives
// the actual cold verifier and real affine Arena/Cold owners; no error flag or
// trusted Snapshot is fabricated by the test.
#[derive(Default)]
struct RefusalAudit {
    reads: u64,
    writes: u64,
    flushes: u64,
    lose_read: Option<u64>,
    unresolved: bool,
}
struct AuditedDisk {
    disk: Disk,
    audit: std::rc::Rc<std::cell::RefCell<RefusalAudit>>,
}
struct AuditedDevice<'a> {
    disk: &'a mut AuditedDisk,
    area: Area,
    sectors: u64,
}
impl SectorIo for AuditedDevice<'_> {
    type Error = crate::native_acquisition::tests::Io;
    fn sectors(&self) -> u64 {
        self.sectors
    }
    fn read(&mut self, sector: u64, out: &mut [u8; 512], cut: u64) -> Result<(), Self::Error> {
        {
            let mut audit = self.disk.audit.borrow_mut();
            assert!(
                !audit.unresolved,
                "no IO retry after unknown read completion"
            );
            audit.reads += 1;
        }
        self.disk.disk.device(self.area).read(sector, out, cut)?;
        let mut audit = self.disk.audit.borrow_mut();
        if audit.lose_read == Some(audit.reads) {
            audit.unresolved = true;
            return Err(crate::native_acquisition::tests::Io::Power);
        }
        Ok(())
    }
    fn write(&mut self, sector: u64, bytes: &[u8; 512], cut: u64) -> Result<(), Self::Error> {
        self.disk.audit.borrow_mut().writes += 1;
        self.disk.disk.device(self.area).write(sector, bytes, cut)
    }
    fn flush(&mut self, cut: u64) -> Result<(), Self::Error> {
        self.disk.audit.borrow_mut().flushes += 1;
        self.disk.disk.device(self.area).flush(cut)
    }
}
impl Backend for AuditedDisk {
    type Error = crate::native_acquisition::tests::Io;
    type Device<'a> = AuditedDevice<'a>;
    fn has_unresolved_io(&self) -> bool {
        self.audit.borrow().unresolved || self.disk.has_unresolved_io()
    }
    fn device(&mut self, area: Area) -> Self::Device<'_> {
        let sectors = self.disk.device(area).sectors();
        AuditedDevice {
            disk: self,
            area,
            sectors,
        }
    }
}
fn hash_corrupted_root_disk() -> Disk {
    let mut update = Update::new();
    assert!(update.begin(Disk::blank(), Command::Initialize, 1).is_ok());
    assert!(matches!(run(&mut update), Outcome::Complete(_)));
    let root = update
        .retained_snapshot()
        .unwrap()
        .current_root_object()
        .unwrap();
    let mut disk = update.take_completed().unwrap();
    let mut sector = [0; 512];
    let mut device = disk.device(Area::Objects);
    device.read(root.start() + 1, &mut sector, 2).unwrap();
    sector[19] ^= 1;
    device.write(root.start() + 1, &sector, 2).unwrap();
    device.flush(2).unwrap();
    disk.cold()
}
fn semantic_checkpoint_refusal_disk() -> Disk {
    let mut update = Update::new();
    assert!(update.begin(Disk::blank(), Command::Initialize, 1).is_ok());
    assert!(matches!(run(&mut update), Outcome::Complete(_)));
    let arena = update.store().into_arena();
    // Untrusted media input: the generic content store fully writes, rereads,
    // hashes and publishes an object; that never attests the acquisition codec.
    let bad = [0x5a; acq::CHECKPOINT_BYTES];
    let transfer = TransferCut::new(1, 100_000).unwrap();
    let head = arena.head_digest();
    let mut stage = arena
        .begin_owned(
            head,
            bad.len() as u64,
            Sha256::digest(bad).into(),
            transfer,
            transfer.metadata(1).unwrap(),
        )
        .unwrap_or_else(|_| panic!("untrusted checkpoint object reservation"));
    stage
        .write_chunk(&bad, transfer.child(1, 1024).unwrap())
        .unwrap();
    let mut reader = stage
        .seal(transfer.child(1, 1024).unwrap())
        .unwrap_or_else(|_| panic!("untrusted object seal"));
    let mut readback = [0; acq::CHECKPOINT_BYTES];
    while reader.remaining() != 0 {
        reader
            .read_chunk(&mut readback, transfer.child(1, 1024).unwrap())
            .unwrap();
    }
    assert_eq!(readback, bad);
    let verified = reader
        .finish()
        .unwrap_or_else(|_| panic!("untrusted object full hash"));
    let head = verified.current_head();
    let (arena, _) = verified
        .publish(head, transfer.metadata(1).unwrap())
        .unwrap_or_else(|_| panic!("canonical untrusted metadata publication"));
    arena.into_backend().cold()
}
fn content_media(disk: &Disk) -> std::vec::Vec<[u8; 512]> {
    let mut clone = disk.clone().cold();
    let mut bytes = std::vec::Vec::new();
    for area in [Area::Checkpoint, Area::Objects] {
        let mut device = clone.device(area);
        for at in 0..device.sectors() {
            let mut sector = [0; 512];
            device.read(at, &mut sector, 2).unwrap();
            bytes.push(sector);
        }
    }
    bytes
}
fn run_audited(update: &mut Update<AuditedDisk>) -> Outcome {
    let now = update.last;
    let mut buffers = acq::Buffers::empty();
    for _ in 0..2048 {
        update.step(&mut buffers, now);
        update.observe_after(now);
        if let Some(outcome) = update.outcome() {
            return outcome;
        }
    }
    panic!("bounded actual audited cold operation did not settle")
}
#[test]
fn settled_cold_fetch_authentication_refusal_returns_exact_owner_without_write() {
    for command in [Command::Inspect, Command::Fetch] {
        let disk = semantic_checkpoint_refusal_disk();
        let before = content_media(&disk);
        let audit = std::rc::Rc::new(std::cell::RefCell::new(RefusalAudit::default()));
        let mut update = Update::new();
        assert!(
            update
                .begin(
                    AuditedDisk {
                        disk,
                        audit: audit.clone()
                    },
                    command,
                    1
                )
                .is_ok()
        );
        let cut = update.original_cut();
        assert_eq!(
            run_audited(&mut update),
            Outcome::Failed(Failure::Authentication)
        );
        assert!(update.take_completed().is_none());
        assert!(update.retained_snapshot().is_none());
        let reads = audit.borrow().reads;
        assert!(reads > 0);
        let backend = update.release_settled_refusal().unwrap_or_else(|| {
            panic!(
                "settled {command:?} did not return owner; flag={} cold_empty={} clock_fenced={}",
                update.settled_auth_refusal,
                update.cold.is_empty(),
                update.clock_fenced
            )
        });
        assert!(!update.busy());
        assert!(update.release_settled_refusal().is_none());
        assert!(!backend.has_unresolved_io());
        assert_eq!(update.original_cut(), cut);
        assert_eq!(content_media(&backend.disk), before);
        assert_eq!(
            (
                audit.borrow().reads,
                audit.borrow().writes,
                audit.borrow().flushes
            ),
            (reads, 0, 0)
        );
        // A new explicit request has to authenticate the same corrupt media
        // again. Returning the Backend is neither trust nor auto-provisioning.
        assert!(update.begin(backend, Command::Inspect, 2).is_ok());
        assert_eq!(
            run_audited(&mut update),
            Outcome::Failed(Failure::Authentication)
        );
        let backend = update.release_settled_refusal().unwrap();
        assert_eq!(content_media(&backend.disk), before);
        assert_eq!((audit.borrow().writes, audit.borrow().flushes), (0, 0));
    }
}
#[test]
fn unresolved_cold_fetch_read_keeps_exact_owner_and_never_retries_or_returns() {
    let audit = std::rc::Rc::new(std::cell::RefCell::new(RefusalAudit::default()));
    let mut update = Update::new();
    assert!(
        update
            .begin(
                AuditedDisk {
                    disk: semantic_checkpoint_refusal_disk(),
                    audit: audit.clone()
                },
                Command::Fetch,
                1
            )
            .is_ok()
    );
    let cut = update.original_cut();
    let mut buffers = acq::Buffers::empty();
    update.step(&mut buffers, 1); // Actual Arena open, retaining the real Cold.
    assert!(update.phase == Phase::Cold);
    let lose_read = audit.borrow().reads + 1;
    audit.borrow_mut().lose_read = Some(lose_read);
    assert_eq!(
        run_audited(&mut update),
        Outcome::Failed(Failure::Authentication)
    );
    assert!(audit.borrow().unresolved);
    let reads = audit.borrow().reads;
    assert!(update.take_completed().is_none());
    assert!(update.release_settled_refusal().is_none());
    assert!(!update.cancel());
    update.refuse_fetch(1);
    update.step(&mut buffers, 1);
    update.observe_after(1);
    assert!(update.busy());
    assert!(update.release_settled_refusal().is_none());
    assert_eq!(update.original_cut(), cut);
    assert_eq!(
        (
            audit.borrow().reads,
            audit.borrow().writes,
            audit.borrow().flushes
        ),
        (reads, 0, 0)
    );
}
#[test]
fn local_cold_refusal_and_expired_fetch_do_not_gain_semantic_return_authority() {
    for (command, expire) in [(Command::Local, false), (Command::Fetch, true)] {
        let audit = std::rc::Rc::new(std::cell::RefCell::new(RefusalAudit::default()));
        let mut update = Update::new();
        assert!(
            update
                .begin(
                    AuditedDisk {
                        disk: semantic_checkpoint_refusal_disk(),
                        audit: audit.clone()
                    },
                    command,
                    1
                )
                .is_ok()
        );
        let cut = update.original_cut().unwrap();
        assert_eq!(
            run_audited(&mut update),
            Outcome::Failed(Failure::Authentication)
        );
        if expire {
            update.observe_after(cut);
        }
        let reads = audit.borrow().reads;
        assert!(update.take_completed().is_none());
        assert!(update.release_settled_refusal().is_none());
        assert!(!update.cancel());
        assert!(update.busy());
        assert_eq!(update.original_cut(), Some(cut));
        assert_eq!(
            (
                audit.borrow().reads,
                audit.borrow().writes,
                audit.borrow().flushes
            ),
            (reads, 0, 0)
        );
    }
}
#[test]
fn hash_poisoned_fetch_and_inspect_read_owners_are_not_washed_by_semantic_return() {
    for command in [Command::Inspect, Command::Fetch] {
        let audit = std::rc::Rc::new(std::cell::RefCell::new(RefusalAudit::default()));
        let mut update = Update::new();
        assert!(
            update
                .begin(
                    AuditedDisk {
                        disk: hash_corrupted_root_disk(),
                        audit: audit.clone()
                    },
                    command,
                    1
                )
                .is_ok()
        );
        assert_eq!(
            run_audited(&mut update),
            Outcome::Failed(Failure::Authentication)
        );
        let reads = audit.borrow().reads;
        assert!(update.release_settled_refusal().is_none());
        update.refuse_fetch(1);
        assert!(update.release_settled_refusal().is_none());
        assert!(update.take_completed().is_none());
        assert!(update.busy());
        assert!(!update.cancel());
        assert_eq!(
            (
                audit.borrow().reads,
                audit.borrow().writes,
                audit.borrow().flushes
            ),
            (reads, 0, 0)
        );
    }
}
