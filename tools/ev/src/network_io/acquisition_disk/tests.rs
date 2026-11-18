use super::*;
use ev_app_registry::Change;
use ev_store::{BootPolicy, Request};
#[path = "fixture.rs"]
pub(super) mod fixture;
const TARGETS: &[u8] = include_bytes!(
    "../../../../../services/root-supervisor/fixtures/acquisition/phase-b/targets.bin"
);
const SNAPSHOT: &[u8] = include_bytes!(
    "../../../../../services/root-supervisor/fixtures/acquisition/phase-b/snapshot.bin"
);
const TIMESTAMP: &[u8] = include_bytes!(
    "../../../../../services/root-supervisor/fixtures/acquisition/phase-b/timestamp.bin"
);
const ARTIFACT: &[u8] = include_bytes!(
    "../../../../../services/root-supervisor/fixtures/acquisition/phase-b/hello.zion"
);
fn release() -> Release<'static> {
    Release {
        root: acq::ROM_ROOT,
        targets: TARGETS,
        snapshot: SNAPSHOT,
        timestamp: TIMESTAMP,
        artifact: ARTIFACT,
    }
}
fn saved() -> Saved<'static> {
    Saved {
        note: "M6 keep42",
        note_counter: 1,
        value: 1001,
        data_counter: 0,
    }
}
fn expected(banks: &Packages<'_>) -> Expected<'static> {
    Expected {
        registry_revision: 4,
        registry_active: hash(ARTIFACT),
        registry_previous: Some(banks.digest(Slot::A)),
        registry_staged: None,
        trust_active: None,
        known_good: None,
        saved: saved(),
    }
}
struct Memory(Vec<u8>);
struct MemDevice<'a> {
    bytes: &'a mut [u8],
    first: u64,
    count: u64,
}
impl Memory {
    fn region(&mut self, r: Region) -> MemDevice<'_> {
        MemDevice {
            bytes: &mut self.0,
            first: r.physical_start() as u64,
            count: 14,
        }
    }
}
impl Backend for Memory {
    type Error = &'static str;
    type Device<'a> = MemDevice<'a>;
    fn device(&mut self, a: Area) -> Self::Device<'_> {
        let (first, count) = match a {
            Area::Checkpoint => (128, 14),
            Area::Objects => (256, ev_content_store::OBJECT_SECTORS),
        };
        MemDevice {
            bytes: &mut self.0,
            first,
            count,
        }
    }
    fn has_unresolved_io(&self) -> bool {
        false
    }
}
impl SectorIo for MemDevice<'_> {
    type Error = &'static str;
    fn sectors(&self) -> u64 {
        self.count
    }
    fn read(&mut self, lba: u64, out: &mut Sector, _: u64) -> std::result::Result<(), Self::Error> {
        if lba >= self.count {
            return Err("bounds");
        }
        let start = ((self.first + lba) * 512) as usize;
        out.copy_from_slice(&self.bytes[start..start + 512]);
        Ok(())
    }
    fn write(&mut self, lba: u64, b: &Sector, _: u64) -> std::result::Result<(), Self::Error> {
        if lba >= self.count {
            return Err("bounds");
        }
        let start = ((self.first + lba) * 512) as usize;
        self.bytes[start..start + 512].copy_from_slice(b);
        Ok(())
    }
    fn flush(&mut self, _: u64) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
}
fn baseline(banks: &Packages<'_>) -> (Vec<u8>, Vec<u8>) {
    let mut seed = vec![0; BYTES];
    seed[..512].fill(0xa9); // unrelated sector must stay exact
    let mut disk = Memory(seed.clone());
    let policy = Policy {
        app: banks.app(),
        abi: ev_userspace_contract::ABI,
        platform: 1,
    };
    {
        let mut r = Registry::format_new(
            disk.region(Region::AppRegistry),
            policy,
            banks.format_manifest(Region::AppRegistry),
            1,
        )
        .unwrap_or_else(|_| panic!("format registry"));
        for change in [
            Change::Install {
                package: banks.digest(Slot::A),
                data_epoch: 1,
            },
            Change::Activate,
        ] {
            let p = r
                .prepare(r.expected().unwrap(), change, banks, &Contracts)
                .unwrap();
            r.publish(p, banks, &Contracts, 1).unwrap();
        }
    }
    let data = AppDataEnvelope::initial(banks.app(), 1, 1001).unwrap();
    Store::format_new(
        disk.region(Region::AppData),
        banks.format_manifest(Region::AppData),
        &data.encode(),
        BootPolicy::new(1).unwrap(),
        1,
    )
    .unwrap_or_else(|_| panic!("format data"));
    let note = NoteDataEnvelope::initial(banks.app(), "").unwrap();
    let mut store = Store::format_new(
        disk.region(Region::SessionNote),
        banks.note_format_manifest(),
        &note.encode(),
        BootPolicy::new(1).unwrap(),
        1,
    )
    .unwrap_or_else(|_| panic!("format note"));
    let note = note.checked_replace(banks.app(), 0, saved().note).unwrap();
    store
        .execute(
            store.next_operation().unwrap(),
            Request::WriteMutable {
                object: ObjectId::user_data(),
                bytes: &note.encode(),
            },
            1,
        )
        .unwrap();
    (seed, disk.0)
}
fn put(store: acq::Store<Memory>, b: &[u8]) -> acq::Stored<Memory> {
    let transfer = TransferCut::new(1, CUT).unwrap();
    let mut p = store
        .begin_put(b.len() as u64, hash(b), transfer, 1)
        .unwrap_or_else(|_| panic!("put"));
    for c in b.chunks(4096) {
        p.write_chunk(c, 1).unwrap_or_else(|_| panic!("chunk"))
    }
    let mut r = p.seal(1).unwrap_or_else(|_| panic!("seal"));
    let mut chunk = [0; 4096];
    while r.remaining() != 0 {
        r.read_chunk(&mut chunk, 1)
            .unwrap_or_else(|_| panic!("read"));
    }
    r.finish().unwrap_or_else(|_| panic!("readback"))
}
fn persist(mut c: acq::Commit<Memory>) -> acq::Store<Memory> {
    let mut b = acq::Buffers::empty();
    for _ in 0..1024 {
        if c.step(&mut b, 1).unwrap_or_else(|_| panic!("commit")) {
            return c
                .publication()
                .unwrap_or_else(|_| panic!("publication"))
                .publish(1, &mut b.checkpoint)
                .unwrap_or_else(|_| panic!("publish"));
        }
    }
    panic!("bounded commit")
}
// TEST-only provider: exercising real signatures and storage does not qualify a
// runtime clock. Signed author times are not a production time source.
struct TestClock {
    calls: u64,
    author: u64,
}
impl acq::QualifiedClock for TestClock {
    type Error = ();
    fn fresh(
        &mut self,
    ) -> std::result::Result<
        (
            ev_time_contract::freshness::QualifiedWindow,
            ev_time_contract::Instant,
        ),
        (),
    > {
        use ev_time_contract::{
            Domain,
            freshness::{QualifiedWindow, UtcInterval},
        };
        self.calls += 1;
        let d = Domain::new(77).unwrap();
        Ok((
            QualifiedWindow::new(
                d.at(1),
                d.at(3),
                UtcInterval::new(self.author + 1, self.author + 2).unwrap(),
            )
            .unwrap(),
            d.at(self.calls),
        ))
    }
}
fn accepted(baseline: &[u8], banks: &Packages<'_>) -> Vec<u8> {
    accepted_profile(baseline, banks, true)
}
fn accepted_profile(baseline: &[u8], banks: &Packages<'_>, activate: bool) -> Vec<u8> {
    let transfer = TransferCut::new(1, CUT).unwrap();
    let mut p = ev_content_store::Provisioner::new(
        Memory(baseline.to_vec()),
        ev_root_supervisor::native_update::creation_manifest(),
        transfer,
    )
    .unwrap_or_else(|_| panic!("provision"));
    while p.remaining() != 0 {
        p.scan(transfer.child(1, 1024).unwrap()).unwrap();
    }
    let arena = p
        .finish(transfer.metadata(1).unwrap())
        .unwrap_or_else(|_| panic!("format"));
    let root = put(acq::Store::from_arena(arena), acq::ROM_ROOT);
    let mut store = persist(
        root.store
            .provision(root.object, transfer, 1)
            .unwrap_or_else(|_| panic!("ROM")),
    );
    let mut refs = [None; 3];
    for (i, b) in [TARGETS, SNAPSHOT, TIMESTAMP].into_iter().enumerate() {
        let p = put(store, b);
        refs[i] = Some(p.object);
        store = p.store;
    }
    let artifact = put(store, ARTIFACT);
    let envelope = ev_release_trust::signature::Envelope::parse(TARGETS).unwrap();
    let author = ev_release_trust::metadata::Targets::parse(&envelope)
        .unwrap()
        .common()
        .not_before;
    let decision = artifact
        .store
        .authorize(
            acq::Remote {
                current_root: acq::ROM_ROOT,
                root_updates: &[],
                metadata: core::array::from_fn(|i| acq::Material {
                    object: refs[i].unwrap(),
                    bytes: [TARGETS, SNAPSHOT, TIMESTAMP][i],
                }),
                candidate: acq::Material {
                    object: artifact.object,
                    bytes: ARTIFACT,
                },
            },
            &mut TestClock { calls: 0, author },
        )
        .unwrap();
    let store = persist(
        decision
            .begin(artifact.store, transfer, 1)
            .unwrap_or_else(|_| panic!("decision")),
    );
    let mut disk = store.into_arena().into_backend();
    let policy = Policy {
        app: banks.app(),
        abi: ev_userspace_contract::ABI,
        platform: 1,
    };
    let lookup = Lookup {
        banks,
        artifact: Some(ARTIFACT),
    };
    let mut r = Registry::open(
        disk.region(Region::AppRegistry),
        policy,
        &lookup,
        &Contracts,
        1,
    )
    .unwrap_or_else(|_| panic!("open registry"));
    let mut changes = vec![Change::Stage {
        package: hash(ARTIFACT),
    }];
    if activate {
        changes.push(Change::Activate);
    }
    for change in changes {
        let p = r
            .prepare(r.expected().unwrap(), change, &lookup, &Contracts)
            .unwrap();
        r.publish(p, &lookup, &Contracts, 1).unwrap();
    }
    disk.0
}
fn packages<'a>(
    fixture: &'a ([u8; 4096], ev_userspace_contract::Context, Vec<u8>, Vec<u8>),
) -> Packages<'a> {
    Packages::verify_network(&fixture.0, fixture.1, &fixture.2, &fixture.3).unwrap()
}
#[test]
fn actual_signed_candidate_and_registry_selection_survive_readonly_cold_with_saved_note() {
    let f = fixture::fixture();
    let banks = packages(&f);
    let (seed, baseline) = baseline(&banks);
    let setup = setup(&seed, &baseline, &banks, saved()).unwrap();
    assert_eq!(setup["state"]["note"], "M6 keep42");
    let after = accepted(&baseline, &banks);
    let online = online(&baseline, &after, &banks, release(), expected(&banks)).unwrap();
    assert_eq!(online.proof["authenticated"]["candidate_version"], 2);
    assert_eq!(online.proof["authenticated"]["observer_mutations"], 0);
    assert!(online.proof["authenticated"]["utc_floor"].as_u64().unwrap() > 0);
    assert!(cold(&after, &after, &banks, release(), expected(&banks), &online).is_ok());
    let mut wrong = expected(&banks);
    wrong.trust_active = Some(2);
    assert!(authenticated(&after, &banks, release(), wrong).is_err());
    wrong = expected(&banks);
    wrong.known_good = Some(2);
    assert!(authenticated(&after, &banks, release(), wrong).is_err());
    wrong = expected(&banks);
    wrong.registry_active = banks.digest(Slot::B);
    assert!(authenticated(&after, &banks, release(), wrong).is_err());
}
#[test]
fn captured_artifact_metadata_root_and_unrelated_bytes_cannot_be_substituted_or_repaired() {
    let f = fixture::fixture();
    let banks = packages(&f);
    let (seed, baseline) = baseline(&banks);
    let after = accepted(&baseline, &banks);
    let proof = online(&baseline, &after, &banks, release(), expected(&banks)).unwrap();
    let objects = proof.proof["authenticated"]["objects"].as_array().unwrap();
    for object in objects {
        let sector = 256 + object["start"].as_u64().unwrap() + 1;
        let mut changed = after.clone();
        changed[sector as usize * 512] ^= 1;
        assert!(online(&baseline, &changed, &banks, release(), expected(&banks)).is_err());
    }
    for sector in [0, 16, 32, 48, 80, 96, 112, 142, 255] {
        let mut changed = after.clone();
        changed[sector * 512] ^= 1;
        assert!(online(&baseline, &changed, &banks, release(), expected(&banks)).is_err());
        assert!(
            cold(
                &after,
                &changed,
                &banks,
                release(),
                expected(&banks),
                &proof
            )
            .is_err()
        );
    }
    let mut changed = baseline.clone();
    changed[0] ^= 1;
    assert!(setup(&seed, &changed, &banks, saved()).is_err());
    let mut artifact = ARTIFACT.to_vec();
    artifact[100] ^= 1;
    let mut wrong = release();
    wrong.artifact = &artifact;
    assert!(authenticated(&after, &banks, wrong, expected(&banks)).is_err());
    let mut targets = TARGETS.to_vec();
    targets[100] ^= 1;
    wrong = release();
    wrong.targets = &targets;
    assert!(authenticated(&after, &banks, wrong, expected(&banks)).is_err());
}
#[test]
fn audit_backend_rejects_all_writes_flushes_and_out_of_bounds_reads() {
    let bytes = vec![0; BYTES];
    let mut media = Media {
        bytes: &bytes,
        reads: 0,
        writes: 0,
    };
    let mut d = media.device(Area::Objects);
    let mut out = [0; 512];
    assert!(d.read(d.sectors(), &mut out, 1).is_err());
    assert!(d.read(0, &mut out, 0).is_err());
    assert!(d.write(0, &out, 1).is_err());
    assert!(d.flush(1).is_err());
    assert_eq!(media.writes, 2);
    assert!(bytes.iter().all(|b| *b == 0));
}

#[test]
fn foreign_creation_nonblank_seed_and_wrong_saved_identity_are_refused() {
    let f = fixture::fixture();
    let banks = packages(&f);
    let (seed, baseline) = baseline(&banks);
    let foreign = fixture::alternate();
    let foreign = packages(&foreign);
    let error = setup(&seed, &baseline, &foreign, saved()).unwrap_err();
    assert!(error.contains("original creation/open"), "{error}");
    let mut wrong = saved();
    wrong.note = "different saved text";
    assert!(setup(&seed, &baseline, &banks, wrong).is_err());
    wrong = saved();
    wrong.data_counter = 1;
    assert!(setup(&seed, &baseline, &banks, wrong).is_err());
    let mut nonblank = seed.clone();
    nonblank[64 * 512] = 1;
    assert!(
        setup(&nonblank, &baseline, &banks, saved())
            .unwrap_err()
            .contains("entirely blank")
    );
    assert!(setup(&seed, &seed, &banks, saved()).is_err());
}

#[test]
fn owner_selector_preserves_blank_corrupt_legacy_and_foreign_content_without_repair() {
    use system_health::selector::{self, Selection};
    let fixture = fixture::fixture();
    let banks = packages(&fixture);
    let blank = vec![0; BYTES];
    assert_eq!(
        selector::observe(&blank, &banks).unwrap(),
        Selection::Unformatted
    );
    assert_eq!(selector::author_version(&blank).unwrap(), Some(1));
    for (offset, mark) in [
        (128 * 512, b"EVACQ001".as_slice()),
        (
            Region::System.physical_start() as usize * 512,
            b"foreign System".as_slice(),
        ),
        (256 * 512, b"foreign object".as_slice()),
    ] {
        let mut bytes = blank.clone();
        bytes[offset..offset + mark.len()].copy_from_slice(mark);
        let before = bytes.clone();
        assert!(selector::observe(&bytes, &banks).is_err());
        assert_eq!(bytes, before);
    }
    let envelope = ev_release_trust::signature::Envelope::parse(TARGETS).unwrap();
    let targets = ev_release_trust::metadata::Targets::parse(&envelope).unwrap();
    let compatible =
        fixture::compatible_source(targets.iter().next().unwrap().spec().source_revision);
    let compatible = packages(&compatible);
    let (_, baseline) = baseline(&compatible);
    let bytes = accepted(&baseline, &compatible);
    let before = bytes.clone();
    assert_eq!(
        selector::observe(&bytes, &compatible).unwrap(),
        Selection::Unformatted
    );
    assert!(selector::observe(&bytes, &banks).is_err());
    assert_eq!(selector::author_version(&bytes).unwrap(), Some(2));
    assert_eq!(bytes, before);
}

// Shared real Store/signed-content fixtures for the additive first-use verifier.
// These are model bytes only, never actual guest or owner-consent evidence.
type FirstUseBanks = ([u8; 4096], ev_userspace_contract::Context, Vec<u8>, Vec<u8>);
pub(super) fn first_use_fixture() -> (FirstUseBanks, Vec<u8>, Vec<u8>) {
    let envelope = ev_release_trust::signature::Envelope::parse(TARGETS).unwrap();
    let targets = ev_release_trust::metadata::Targets::parse(&envelope).unwrap();
    let f = fixture::compatible_source(targets.iter().next().unwrap().spec().source_revision);
    let banks = packages(&f);
    let mut seed = vec![0; BYTES];
    seed[..512].fill(0xa9);
    let mut disk = Memory(seed.clone());
    let policy = Policy {
        app: banks.app(),
        abi: ev_userspace_contract::ABI,
        platform: 1,
    };
    {
        let mut registry = Registry::format_new(
            disk.region(Region::AppRegistry),
            policy,
            banks.format_manifest(Region::AppRegistry),
            1,
        )
        .unwrap_or_else(|_| panic!("new first-use registry"));
        let intent = registry
            .prepare(
                registry.expected().unwrap(),
                Change::Install {
                    package: banks.digest(Slot::A),
                    data_epoch: 1,
                },
                &banks,
                &Contracts,
            )
            .unwrap();
        registry.publish(intent, &banks, &Contracts, 1).unwrap();
    }
    let data = AppDataEnvelope::initial(banks.app(), 1, 1001).unwrap();
    Store::format_new(
        disk.region(Region::AppData),
        banks.format_manifest(Region::AppData),
        &data.encode(),
        BootPolicy::new(1).unwrap(),
        1,
    )
    .unwrap_or_else(|_| panic!("new first-use data"));
    let fetched = accepted_profile(&disk.0, &banks, false);
    (f, seed, fetched)
}
pub(super) fn first_use_created(
    bytes: &[u8],
    banks: &Packages<'_>,
    manifest: ev_store::GenerationManifest,
) -> Vec<u8> {
    let mut disk = Memory(bytes.to_vec());
    let note = NoteDataEnvelope::initial(banks.app(), "").unwrap();
    Store::format_new(
        disk.region(Region::SessionNote),
        banks.note_format_manifest(),
        &note.encode(),
        BootPolicy::new(1).unwrap(),
        1,
    )
    .unwrap_or_else(|_| panic!("first-use Note"));
    Store::format_new_downloaded_v2(
        disk.region(Region::System),
        manifest,
        ev_root_supervisor::native_plan::system::INITIAL_PAYLOAD,
        BootPolicy::new(3).unwrap(),
        1,
    )
    .unwrap_or_else(|_| panic!("first-use System"));
    disk.0
}

#[test]
fn original_namespace_context_survives_current_managed_and_recovery_without_repair() {
    use ev_userspace_contract::root_v4::catalogue::BootMode;
    let f = fixture::fixture();
    let original = packages(&f);
    let (_, bytes) = baseline(&original);
    let unchanged = bytes.clone();
    for mode in [BootMode::SystemManaged, BootMode::Recovery] {
        let f = fixture::for_mode(mode);
        let current = packages(&f);
        assert_ne!(
            original.format_manifest(Region::AppRegistry),
            current.format_manifest(Region::AppRegistry)
        );
        let mut media = Media {
            bytes: &bytes,
            reads: 0,
            writes: 0,
        };
        for region in [Region::AppRegistry, Region::AppData] {
            let error = match open_region(&mut media, &current, region) {
                Err(error) => error,
                Ok(_) => panic!("the historical wrong-current-creation checker must fail"),
            };
            assert!(error.contains("Conflict"), "{error}");
        }
        let creation = NamespaceCreation::checked(&original, &current).unwrap();
        creation.check_current(&current).unwrap();
        for region in [Region::AppRegistry, Region::AppData, Region::SessionNote] {
            let mut store = open_original_region(&mut media, &creation, region).unwrap();
            body(&mut store).unwrap();
        }
        assert_eq!(media.writes, 0);
        assert!(saved_state_with_creation(&bytes, &current, &creation, saved()).is_ok());
        assert!(open_original_region(&mut media, &creation, Region::System).is_err());
        assert_eq!(media.writes, 0);
    }
    assert_eq!(bytes, unchanged);
}

#[test]
fn wrong_original_context_keeps_exact_creation_conflict_and_cannot_replace_current_mode() {
    use ev_userspace_contract::root_v4::catalogue::BootMode;
    let f = fixture::fixture();
    let original = packages(&f);
    let (_, bytes) = baseline(&original);
    let foreign = fixture::alternate();
    let foreign = packages(&foreign);
    let wrong = NamespaceCreation::checked(&foreign, &foreign).unwrap();
    let mut media = Media {
        bytes: &bytes,
        reads: 0,
        writes: 0,
    };
    for region in [Region::AppRegistry, Region::AppData] {
        let error = match open_original_region(&mut media, &wrong, region) {
            Err(error) => error,
            Ok(_) => panic!("a foreign original must not become the disk expectation"),
        };
        assert!(error.contains("Conflict"), "{error}");
    }
    assert_eq!(media.writes, 0);
    assert!(NamespaceCreation::checked(&foreign, &original).is_err());
    let changed_source = fixture::compatible_source([9; 32]);
    assert!(NamespaceCreation::checked(&packages(&changed_source), &original).is_err());
    let managed_fixture = fixture::for_mode(BootMode::SystemManaged);
    let managed = packages(&managed_fixture);
    assert!(NamespaceCreation::checked(&managed, &managed).is_err());
    let checked = NamespaceCreation::checked(&original, &managed).unwrap();
    assert!(checked.check_current(&original).is_err());
    let recovery_fixture = fixture::for_mode(BootMode::Recovery);
    assert!(checked.check_current(&packages(&recovery_fixture)).is_err());
    assert!(saved_state_with_creation(&bytes, &original, &checked, saved()).is_err());
}

#[test]
fn original_namespace_context_requires_verified_catalogue_and_exact_payload_hashes() {
    use ev_userspace_contract::root_v4::catalogue::BootMode;
    let f = fixture::fixture();
    let original = packages(&f);
    let mut forged = fixture::for_mode(BootMode::Standalone);
    forged.1.manifest[0] ^= 1;
    assert!(Packages::verify_network(&forged.0, forged.1, &forged.2, &forged.3).is_err());
    let mut forged = fixture::for_mode(BootMode::Standalone);
    forged.2[100] ^= 1;
    assert!(Packages::verify_network(&forged.0, forged.1, &forged.2, &forged.3).is_err());
    let mut wrong_abi = fixture::for_mode(BootMode::SystemManaged);
    // Exact RootABI field of the independently typed V4 catalogue extension.
    wrong_abi.0[ev_userspace_contract::root_v4::catalogue::BASE_SIZE + 16] ^= 1;
    assert!(
        Packages::verify_network(&wrong_abi.0, wrong_abi.1, &wrong_abi.2, &wrong_abi.3).is_err()
    );
    let (_, bytes) = baseline(&original);
    let managed_fixture = fixture::for_mode(BootMode::SystemManaged);
    let current = packages(&managed_fixture);
    let creation = NamespaceCreation::checked(&original, &current).unwrap();
    for region in [Region::AppRegistry, Region::AppData, Region::SessionNote] {
        let mut changed = bytes.clone();
        changed[(region.physical_start() as usize + 10) * 512 + 64 + 24] ^= 1;
        let mut media = Media {
            bytes: &changed,
            reads: 0,
            writes: 0,
        };
        assert!(open_original_region(&mut media, &creation, region).is_err());
        assert_eq!(media.writes, 0);
    }
}
