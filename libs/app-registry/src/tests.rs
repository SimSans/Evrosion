extern crate std;
use super::*;
use ev_store::{GenerationId, SECTOR_BYTES, Sector};
use ev_zion::{
    ContractSupport, DataSchema, Platform, Version,
    producer::{Resource, Spec},
};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    vec,
    vec::Vec,
};
const DEADLINE: u64 = 100_000;
const DISK_SECTORS: usize = 96;
const START: usize = 64;
const END: usize = 78;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Power,
    Offline,
    Bounds,
    Deadline,
}
#[derive(Clone, Copy, Debug)]
enum Cut {
    Before,
    After,
    Torn,
}
#[derive(Default)]
struct Probe {
    trace: RefCell<Vec<(char, u64)>>,
    nth: Cell<usize>,
    cut: Cell<Option<(usize, Cut)>>,
}
struct Disk {
    start: usize,
    guards: Vec<Sector>,
    durable: Vec<Sector>,
    cache: Vec<Sector>,
    offline: bool,
    probe: Rc<Probe>,
}
impl Disk {
    fn blank() -> Self {
        let mut bytes = vec![[0x9b; SECTOR_BYTES]; DISK_SECTORS];
        bytes[START..END].fill([0; SECTOR_BYTES]);
        Self::snapshot(bytes)
    }
    fn snapshot(bytes: Vec<Sector>) -> Self {
        Self::snapshot_at(bytes, START)
    }
    fn snapshot_at(bytes: Vec<Sector>, start: usize) -> Self {
        assert!(start + ev_store::REQUIRED_SECTORS as usize <= bytes.len());
        Self {
            start,
            guards: bytes.clone(),
            cache: bytes.clone(),
            durable: bytes,
            offline: false,
            probe: Rc::new(Probe::default()),
        }
    }
    fn cold(mut self) -> Self {
        self.cache = self.durable.clone();
        self.offline = false;
        self.probe.nth.set(0);
        self.probe.cut.set(None);
        self
    }
    fn enter(&mut self, op: char, local: u64, deadline: u64) -> Result<Option<Cut>, Fault> {
        if self.offline {
            return Err(Fault::Offline);
        }
        if deadline == 0 || deadline == u64::MAX {
            return Err(Fault::Deadline);
        }
        if local >= ev_store::REQUIRED_SECTORS {
            return Err(Fault::Bounds);
        }
        let nth = self.probe.nth.get() + 1;
        self.probe.nth.set(nth);
        self.probe
            .trace
            .borrow_mut()
            .push((op, self.start as u64 + local));
        Ok(self
            .probe
            .cut
            .get()
            .filter(|(n, _)| *n == nth)
            .map(|(_, c)| c))
    }
    fn lost(&mut self) -> Result<(), Fault> {
        self.offline = true;
        Err(Fault::Power)
    }
    fn assert_guards(&self) {
        for (i, sector) in self.durable.iter().enumerate() {
            if !(self.start..self.start + ev_store::REQUIRED_SECTORS as usize).contains(&i) {
                assert_eq!(*sector, self.guards[i], "other region{i}");
            }
        }
    }
}
impl SectorIo for Disk {
    type Error = Fault;
    fn sectors(&self) -> u64 {
        ev_store::REQUIRED_SECTORS
    }
    fn read(&mut self, lba: u64, out: &mut Sector, deadline: u64) -> Result<(), Fault> {
        let cut = self.enter('r', lba, deadline)?;
        if cut.is_some() {
            self.lost()?;
        }
        *out = self.cache[self.start + lba as usize];
        Ok(())
    }
    fn write(&mut self, lba: u64, bytes: &Sector, deadline: u64) -> Result<(), Fault> {
        let cut = self.enter('w', lba, deadline)?;
        if matches!(cut, Some(Cut::Before)) {
            return self.lost();
        }
        let at = self.start + lba as usize;
        self.cache[at] = *bytes;
        if let Some(cut) = cut {
            match cut {
                Cut::After => self.durable[at] = *bytes,
                Cut::Torn => self.durable[at][..257].copy_from_slice(&bytes[..257]),
                Cut::Before => unreachable!(),
            };
            return self.lost();
        }
        Ok(())
    }
    fn flush(&mut self, deadline: u64) -> Result<(), Fault> {
        let cut = self.enter('f', 0, deadline)?;
        if matches!(cut, Some(Cut::Before)) {
            return self.lost();
        }
        if matches!(cut, Some(Cut::Torn)) {
            for i in (self.start..self.start + ev_store::REQUIRED_SECTORS as usize).step_by(2) {
                self.durable[i] = self.cache[i];
            }
            return self.lost();
        }
        self.durable = self.cache.clone();
        if cut.is_some() {
            return self.lost();
        }
        Ok(())
    }
}
struct Support;
impl Contracts for Support {
    fn supported(&self, _: &str, _: u16) -> Option<ContractSupport> {
        None
    }
}
struct Catalog<'a> {
    bytes: &'a [Vec<u8>],
    packages: Vec<Package<'a>>,
    wrong: Option<usize>,
}
impl Packages for Catalog<'_> {
    fn resolve(&self, digest: Digest) -> Option<&[u8]> {
        let index = self
            .wrong
            .or_else(|| self.packages.iter().position(|p| p.id().bytes() == digest))?;
        self.bytes.get(index).map(Vec::as_slice)
    }
}

fn policy() -> Policy {
    Policy {
        app: AppId::new([7; 16]).unwrap(),
        abi: [8; 32],
        platform: 1,
    }
}
fn package(label: u8, current: u32, oldest: u32, app: u8, abi: u8) -> Vec<u8> {
    let spec = Spec {
        app: AppId::new([app; 16]).unwrap(),
        name: "Draft app",
        source: "Model fixture only",
        publisher: None,
        version: Version {
            major: 0,
            minor: 1,
            patch: label as u32,
        },
        build_id: [label; 32],
        platform: Platform {
            minimum: 1,
            target: 1,
        },
        abi: [abi; 32],
        data_schema: DataSchema {
            current,
            oldest_readable: oldest,
        },
        entrypoint: "bin/main.elf",
        contracts: &[],
        capabilities: &[],
    };
    ev_zion::producer::build(
        &spec,
        include_bytes!("../../../kernel/fixtures/bootstrap-static-v1.elf"),
        &[Resource {
            path: "res/model.txt",
            bytes: b"model, not execution",
        }],
    )
    .unwrap()
}
fn catalog(bytes: &[Vec<u8>]) -> Catalog<'_> {
    Catalog {
        bytes,
        packages: bytes.iter().map(|b| Package::parse(b).unwrap()).collect(),
        wrong: None,
    }
}

struct CachedResolver<'a> {
    resolved: Option<&'a [u8]>,
    cached: &'a Package<'a>,
    resolves: Cell<usize>,
}
impl Packages for CachedResolver<'_> {
    fn resolve(&self, _: Digest) -> Option<&[u8]> {
        self.resolves.set(self.resolves.get() + 1);
        self.resolved
    }
    fn parsed(&self, _: Digest) -> Option<&Package<'_>> {
        Some(self.cached)
    }
}
#[test]
fn cached_view_reuses_only_the_exact_resolved_immutable_container() {
    let bytes = package(1, 1, 1, 7, 8);
    let parsed = Package::parse(&bytes).unwrap();
    let id = parsed.id().bytes();
    let resolver = CachedResolver {
        resolved: Some(&bytes),
        cached: &parsed,
        resolves: Cell::new(0),
    };
    for _ in 0..2 {
        with_package::<_, ()>(id, policy(), &resolver, &Support, |actual| {
            assert!(core::ptr::eq(actual.package(), &parsed));
            assert!(core::ptr::eq(actual.package().bytes(), bytes.as_slice()));
            Ok(())
        })
        .unwrap();
    }
    assert_eq!(resolver.resolves.get(), 2);

    // Even equal contents in another allocation require a fresh full parse.
    let copy = bytes.clone();
    let resolver = CachedResolver {
        resolved: Some(&copy),
        ..resolver
    };
    with_package::<_, ()>(id, policy(), &resolver, &Support, |actual| {
        assert!(!core::ptr::eq(actual.package(), &parsed));
        assert!(core::ptr::eq(actual.package().bytes(), copy.as_slice()));
        Ok(())
    })
    .unwrap();
}
#[test]
fn detached_cache_cannot_override_missing_corrupt_or_wrong_resolved_bytes() {
    let bytes = package(1, 1, 1, 7, 8);
    let parsed = Package::parse(&bytes).unwrap();
    let id = parsed.id().bytes();
    let other = package(2, 1, 1, 7, 8);
    let mut corrupt = bytes.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    for (resolved, expected) in [
        (None, Error::MissingPackage),
        (Some(other.as_slice()), Error::WrongPackage),
        (
            Some(corrupt.as_slice()),
            Error::Package(ev_zion::Error::ContentDigest),
        ),
        // Same base pointer with a different length is not the validated view.
        (
            Some(&bytes[..bytes.len() - 1]),
            Error::Package(ev_zion::Error::Length),
        ),
    ] {
        let resolver = CachedResolver {
            resolved,
            cached: &parsed,
            resolves: Cell::new(0),
        };
        assert_eq!(
            with_package::<(), ()>(id, policy(), &resolver, &Support, |_| {
                panic!("invalid resolver must never reach inspection")
            }),
            Err(expected)
        );
        assert_eq!(resolver.resolves.get(), 1);
    }
}
#[test]
fn cached_content_still_requires_current_package_identity_and_host_policy() {
    let bytes = package(1, 1, 1, 7, 8);
    let parsed = Package::parse(&bytes).unwrap();
    let resolver = CachedResolver {
        resolved: Some(&bytes),
        cached: &parsed,
        resolves: Cell::new(0),
    };
    let id = parsed.id().bytes();
    for (requested, policy, expected) in [
        ([99; 32], policy(), Error::WrongPackage),
        (
            id,
            Policy {
                app: AppId::new([9; 16]).unwrap(),
                ..policy()
            },
            Error::Identity,
        ),
        (
            id,
            Policy {
                abi: [9; 32],
                ..policy()
            },
            Error::Package(ev_zion::Error::Abi),
        ),
        (
            id,
            Policy {
                platform: 0,
                ..policy()
            },
            Error::Package(ev_zion::Error::Platform),
        ),
    ] {
        assert_eq!(
            with_package::<(), ()>(requested, policy, &resolver, &Support, |_| {
                panic!("cached content cannot waive current policy")
            }),
            Err(expected)
        );
    }
}
fn format_manifest() -> GenerationManifest {
    GenerationManifest {
        generation: GenerationId::new(1).unwrap(),
        cohort: [11; 32],
        supervisor_image: [12; 32],
        abi: [13; 32],
        health_contract: [14; 32],
        health_version: 1,
        required_checks: 3,
    }
}
fn fresh() -> Registry<Disk> {
    Registry::format_new(Disk::blank(), policy(), format_manifest(), DEADLINE)
        .unwrap_or_else(|r| panic!("format: {:?}", r.error))
}
fn apply(r: &mut Registry<Disk>, c: Change, p: &impl Packages) -> Published {
    let intent = r.prepare(r.expected().unwrap(), c, p, &Support).unwrap();
    r.publish(intent, p, &Support, DEADLINE).unwrap()
}
fn reopen(r: Registry<Disk>, p: &impl Packages) -> Registry<Disk> {
    let (d, policy, pending) = r.into_parts();
    assert!(pending.is_none());
    Registry::open(d.cold(), policy, p, &Support, DEADLINE)
        .unwrap_or_else(|r| panic!("open: {:?}", r.error))
}
#[test]
fn durable_install_stage_replace_rollback_tombstone_reinstall_preserve_data() {
    let bytes = [package(1, 1, 1, 7, 8), package(2, 2, 1, 7, 8)];
    let c = catalog(&bytes);
    let a = c.packages[0].id().bytes();
    let b = c.packages[1].id().bytes();
    let mut r = fresh();
    assert_eq!(r.expected().unwrap().revision, 0);
    assert!(r.store.known_good().is_none());
    apply(
        &mut r,
        Change::Install {
            package: a,
            data_epoch: 1,
        },
        &c,
    );
    assert!(r.record().unwrap().unwrap().active().is_none());
    apply(&mut r, Change::Activate, &c);
    let before = r.record().unwrap().unwrap().active();
    apply(&mut r, Change::Stage { package: b }, &c);
    assert_eq!(r.record().unwrap().unwrap().active(), before);
    r = reopen(r, &c);
    apply(&mut r, Change::Activate, &c);
    assert_eq!(r.record().unwrap().unwrap().active().unwrap().digest(), b);
    apply(&mut r, Change::Rollback, &c);
    assert_eq!(r.record().unwrap().unwrap().active().unwrap().digest(), a);
    apply(&mut r, Change::Replace { package: b }, &c);
    let epoch = r.record().unwrap().unwrap().data_epoch();
    apply(&mut r, Change::Remove, &c);
    r = reopen(r, &c);
    let t = r.record().unwrap().unwrap();
    assert!(!t.installed());
    assert_eq!(t.app(), policy().app);
    assert_eq!(t.data_epoch(), epoch);
    assert!(matches!(
        r.prepare(
            r.expected().unwrap(),
            Change::Install {
                package: a,
                data_epoch: 1
            },
            &c,
            &Support
        ),
        Err(Error::Metadata(lifecycle::Error::State))
    ));
    apply(&mut r, Change::Reinstall { package: a }, &c);
    assert_eq!(r.record().unwrap().unwrap().data_epoch(), epoch);
    let (d, _, _) = r.into_parts();
    d.assert_guards();
}
#[test]
fn compare_revision_and_full_head_fail_without_mutation() {
    let bytes = [package(1, 1, 1, 7, 8)];
    let c = catalog(&bytes);
    let initial = fresh();
    let (d, p, _) = initial.into_parts();
    let ctl = d.probe.clone();
    let mut r = Registry::open(d, p, &c, &Support, DEADLINE)
        .unwrap_or_else(|r| panic!("open: {:?}", r.error));
    let base = r.expected().unwrap();
    let old = r
        .prepare(
            base,
            Change::Install {
                package: c.packages[0].id().bytes(),
                data_epoch: 1,
            },
            &c,
            &Support,
        )
        .unwrap();
    apply(
        &mut r,
        Change::Install {
            package: c.packages[0].id().bytes(),
            data_epoch: 1,
        },
        &c,
    );
    let count = ctl.trace.borrow().len();
    assert_eq!(r.publish(old, &c, &Support, DEADLINE), Err(Error::Stale));
    assert_eq!(ctl.trace.borrow().len(), count);
    let mut forged = r.expected().unwrap();
    forged.base_head[0] ^= 1;
    assert!(matches!(
        r.prepare(forged, Change::Activate, &c, &Support),
        Err(Error::Stale)
    ));
    forged = r.expected().unwrap();
    forged.revision += 1;
    assert!(matches!(
        r.prepare(forged, Change::Activate, &c, &Support),
        Err(Error::Stale)
    ));
}
#[test]
fn full_package_id_app_identity_hostabi_and_retained_schema_are_rechecked() {
    let bytes = [
        package(1, 1, 1, 7, 8),
        package(2, 2, 1, 7, 8),
        package(3, 1, 1, 9, 8),
        package(4, 1, 1, 7, 9),
    ];
    let mut c = catalog(&bytes);
    let mut r = fresh();
    let a = c.packages[0].id().bytes();
    apply(
        &mut r,
        Change::Install {
            package: a,
            data_epoch: 1,
        },
        &c,
    );
    apply(&mut r, Change::Activate, &c);
    let expected = r.expected().unwrap();
    assert!(matches!(
        r.prepare(expected, Change::Stage { package: [99; 32] }, &c, &Support),
        Err(Error::MissingPackage)
    ));
    assert!(matches!(
        r.prepare(
            expected,
            Change::Stage {
                package: c.packages[2].id().bytes()
            },
            &c,
            &Support
        ),
        Err(Error::Identity)
    ));
    assert!(matches!(
        r.prepare(
            expected,
            Change::Stage {
                package: c.packages[3].id().bytes()
            },
            &c,
            &Support
        ),
        Err(Error::Package(ev_zion::Error::Abi))
    ));
    c.wrong = Some(1);
    assert!(matches!(
        r.prepare(expected, Change::Remove, &c, &Support),
        Err(Error::WrongPackage)
    ));
    let (d, p, pending) = r.into_parts();
    assert!(pending.is_none());
    let before = d.durable.clone();
    let rejected = Registry::open(d.cold(), p, &c, &Support, DEADLINE)
        .err()
        .unwrap();
    assert_eq!(rejected.error, Error::WrongPackage);
    assert_eq!(rejected.device.durable, before);
    rejected.device.assert_guards();
}
#[test]
fn incompatible_rollback_after_recorded_data_epoch_advance_refuses() {
    let bytes = [package(1, 1, 1, 7, 8), package(2, 2, 1, 7, 8)];
    let c = catalog(&bytes);
    let mut r = fresh();
    apply(
        &mut r,
        Change::Install {
            package: c.packages[0].id().bytes(),
            data_epoch: 1,
        },
        &c,
    );
    apply(&mut r, Change::Activate, &c);
    apply(
        &mut r,
        Change::Replace {
            package: c.packages[1].id().bytes(),
        },
        &c,
    );
    apply(&mut r, Change::DataMigrated { epoch: 2 }, &c);
    r = reopen(r, &c);
    let before = r.expected().unwrap();
    assert!(matches!(
        r.prepare(before, Change::Rollback, &c, &Support),
        Err(Error::Metadata(lifecycle::Error::Data))
    ));
    assert_eq!(r.expected().unwrap(), before);
    apply(&mut r, Change::Remove, &c);
    assert!(matches!(
        r.prepare(
            r.expected().unwrap(),
            Change::Reinstall {
                package: c.packages[0].id().bytes()
            },
            &c,
            &Support
        ),
        Err(Error::Metadata(lifecycle::Error::Data))
    ));
}
#[test]
fn format_is_explicit_blank_only_and_never_overwrites_existing_region() {
    let r = fresh();
    let (d, p, _) = r.into_parts();
    let bytes = d.durable.clone();
    let rejected = Registry::format_new(d.cold(), p, format_manifest(), DEADLINE)
        .err()
        .unwrap();
    assert_eq!(rejected.error, Error::Store(ev_store::Error::NotBlank));
    assert_eq!(rejected.device.durable, bytes);
    rejected.device.assert_guards();
}
#[test]
fn each_io_failure_cut_cold_recovery_resolves_exact_intent_or_explicit_retry() {
    let bytes = [package(1, 1, 1, 7, 8)];
    let c = catalog(&bytes);
    let change = Change::Install {
        package: c.packages[0].id().bytes(),
        data_epoch: 1,
    };
    let base = fresh();
    let (d, p, _) = base.into_parts();
    let snapshot = d.durable;
    let d = Disk::snapshot(snapshot.clone());
    let control = d.probe.clone();
    let mut normal = Registry::open(d, p, &c, &Support, DEADLINE)
        .unwrap_or_else(|r| panic!("open {:?}", r.error));
    let n = normal
        .prepare(normal.expected().unwrap(), change, &c, &Support)
        .unwrap();
    control.nth.set(0);
    control.trace.borrow_mut().clear();
    normal.publish(n, &c, &Support, DEADLINE).unwrap();
    let boundaries = control.nth.get();
    assert!(boundaries >= 10);
    let mut committed = 0;
    let mut absent = 0;
    for step in 1..=boundaries {
        for cut in [Cut::Before, Cut::After, Cut::Torn] {
            let d = Disk::snapshot(snapshot.clone());
            let ctl = d.probe.clone();
            let mut r = Registry::open(d, p, &c, &Support, DEADLINE)
                .unwrap_or_else(|r| panic!("open {:?}", r.error));
            let intent = r
                .prepare(r.expected().unwrap(), change, &c, &Support)
                .unwrap();
            let op = intent.operation();
            let exact = intent.after().encode();
            ctl.nth.set(0);
            ctl.cut.set(Some((step, cut)));
            assert!(
                r.publish(intent, &c, &Support, DEADLINE).is_err(),
                "missingcut{step} {cut:?}"
            );
            assert_eq!(r.expected(), Err(Error::NeedsRecovery));
            assert!(matches!(r.record(), Err(Error::NeedsRecovery)));
            let (d, p, pending) = r.into_parts();
            assert!(pending.is_some());
            d.assert_guards();
            let (mut r, resolution) =
                Registry::resume(d.cold(), p, pending, &c, &Support, DEADLINE)
                    .unwrap_or_else(|r| panic!("recover{step} {cut:?}: {:?}", r.error));
            match resolution {
                Resolution::Committed(receipt) => {
                    committed += 1;
                    assert_eq!(receipt.operation, op);
                    assert!(receipt.recovered);
                }
                Resolution::Unpublished(retry) => {
                    absent += 1;
                    assert_eq!(retry.operation(), op);
                    assert_eq!(retry.after().encode(), exact);
                    r.publish(retry, &c, &Support, DEADLINE).unwrap();
                }
                Resolution::NoPending => panic!("lostintent"),
            }
            assert_eq!(r.record().unwrap().unwrap().encode(), exact);
            assert_eq!(r.store.next_operation().unwrap().get(), op.get() + 1);
            let (d, _, _) = r.into_parts();
            d.assert_guards();
        }
    }
    assert!(
        committed > 0 && absent > 0,
        "must cover both durable outcomes"
    );
    std::eprintln!(
        "fault matrix: {} IO boundaries x3 cuts; {} committed, {} unpublished",
        boundaries,
        committed,
        absent
    );
}

#[test]
fn unpublished_recovery_revalidates_candidate_and_returns_intent_on_refusal() {
    let bytes = [package(1, 1, 1, 7, 8)];
    let c = catalog(&bytes);
    let original = fresh();
    let (d, p, _) = original.into_parts();
    let ctl = d.probe.clone();
    let mut r = Registry::open(d, p, &c, &Support, DEADLINE)
        .unwrap_or_else(|r| panic!("open: {:?}", r.error));
    let change = Change::Install {
        package: c.packages[0].id().bytes(),
        data_epoch: 1,
    };
    let intent = r
        .prepare(r.expected().unwrap(), change, &c, &Support)
        .unwrap();
    let operation = intent.operation();
    ctl.nth.set(0);
    ctl.cut.set(Some((1, Cut::Before)));
    assert!(r.publish(intent, &c, &Support, DEADLINE).is_err());
    let (d, p, pending) = r.into_parts();
    let missing = Catalog {
        bytes: &[],
        packages: vec![],
        wrong: None,
    };
    let rejected = Registry::resume(d.cold(), p, pending, &missing, &Support, DEADLINE)
        .err()
        .unwrap();
    assert_eq!(rejected.error, Error::MissingPackage);
    assert_eq!(rejected.pending.as_ref().unwrap().operation(), operation);
    let (mut r, resolution) =
        Registry::resume(rejected.device, p, rejected.pending, &c, &Support, DEADLINE)
            .unwrap_or_else(|r| panic!("resume: {:?}", r.error));
    let Resolution::Unpublished(retry) = resolution else {
        panic!("must remain unpublished")
    };
    assert_eq!(retry.operation(), operation);
    assert_eq!(
        r.publish(retry, &missing, &Support, DEADLINE),
        Err(Error::MissingPackage)
    );
    assert!(
        r.expected().is_ok(),
        "preflight package refusal cannot poison or publish"
    );
    apply(&mut r, change, &c);
    let (d, _, _) = r.into_parts();
    d.assert_guards();
}

#[test]
fn checksummed_metadata_cannot_change_actual_package_schema_or_registry_app() {
    let bytes = [package(1, 1, 1, 7, 8)];
    let c = catalog(&bytes);
    for wrong_app in [false, true] {
        let mut r = fresh();
        apply(
            &mut r,
            Change::Install {
                package: c.packages[0].id().bytes(),
                data_epoch: 1,
            },
            &c,
        );
        apply(&mut r, Change::Activate, &c);
        let mut encoded = r.record().unwrap().unwrap().encode();
        if wrong_app {
            encoded[16..32].fill(9);
        } else {
            encoded[80..84].copy_from_slice(&2u32.to_le_bytes());
        }
        let mut hash = Sha256::new();
        hash.update(b"evrosion.app-registry.v1\0");
        hash.update(&encoded[..224]);
        encoded[224..].copy_from_slice(&hash.finalize());
        // Corruption model uses the actual Store codec to reseal outer data/root
        // too; parser checksums alone must not stand in for package admission.
        let (d, p, _) = r.into_parts();
        let mut store = Store::open(d, DEADLINE).unwrap_or_else(|r| panic!("open: {:?}", r.error));
        store
            .execute(
                store.next_operation().unwrap(),
                Request::WriteMutable {
                    object: ObjectId::user_data(),
                    bytes: &encoded,
                },
                DEADLINE,
            )
            .unwrap();
        let d = store.into_device();
        let before = d.durable.clone();
        let rejected = Registry::open(d.cold(), p, &c, &Support, DEADLINE)
            .err()
            .unwrap();
        assert_eq!(
            rejected.error,
            if wrong_app {
                Error::Identity
            } else {
                Error::WrongPackage
            }
        );
        assert_eq!(rejected.device.durable, before);
        rejected.device.assert_guards();
    }
}

#[test]
fn old_prepared_head_cannot_publish_after_journal_ring_reuse() {
    let bytes = [package(1, 1, 1, 7, 8), package(2, 2, 1, 7, 8)];
    let c = catalog(&bytes);
    let a = c.packages[0].id().bytes();
    let b = c.packages[1].id().bytes();
    let mut r = fresh();
    apply(
        &mut r,
        Change::Install {
            package: a,
            data_epoch: 1,
        },
        &c,
    );
    apply(&mut r, Change::Activate, &c);
    let stale = r
        .prepare(
            r.expected().unwrap(),
            Change::Replace { package: b },
            &c,
            &Support,
        )
        .unwrap();
    for _ in 0..20 {
        apply(&mut r, Change::Stage { package: a }, &c);
    }
    r = reopen(r, &c);
    let before = r.expected().unwrap();
    assert_eq!(r.publish(stale, &c, &Support, DEADLINE), Err(Error::Stale));
    assert_eq!(r.expected().unwrap(), before);
    assert_eq!(r.store.next_operation().unwrap().get(), 23);
    assert!(r.store.known_good().is_none());
    let (d, _, _) = r.into_parts();
    d.assert_guards();
}

#[test]
fn future_native_system_mapping_writes_only_registry_and_rejects_holes() {
    use crate::region::{self, Region, Slice};
    struct Window {
        bytes: Vec<Sector>,
        writes: Vec<u64>,
    }
    impl SectorIo for Window {
        type Error = Fault;
        fn sectors(&self) -> u64 {
            30
        }
        fn read(&mut self, lba: u64, out: &mut Sector, _: u64) -> Result<(), Fault> {
            let p = region::physical_sector(lba).ok_or(Fault::Bounds)?;
            *out = self.bytes[p as usize];
            Ok(())
        }
        fn write(&mut self, lba: u64, bytes: &Sector, _: u64) -> Result<(), Fault> {
            let p = region::physical_sector(lba).ok_or(Fault::Bounds)?;
            self.bytes[p as usize] = *bytes;
            self.writes.push(p);
            Ok(())
        }
        fn flush(&mut self, _: u64) -> Result<(), Fault> {
            Ok(())
        }
    }
    let mut device = Window {
        bytes: vec![[0x9b; SECTOR_BYTES]; 96],
        writes: vec![],
    };
    device.bytes[64..78].fill([0; SECTOR_BYTES]);
    let before = device.bytes.clone();
    {
        let slice = Slice::new(&mut device, Region::AppRegistry);
        let r = Registry::format_new(slice, policy(), format_manifest(), DEADLINE)
            .unwrap_or_else(|r| panic!("format: {:?}", r.error));
        let (_returned_backend, _, _) = r.into_parts();
    }
    assert!(device.writes.iter().all(|p| (64..78).contains(p)));
    for (i, (actual, old)) in device.bytes.iter().zip(&before).enumerate() {
        if !(64..78).contains(&i) {
            assert_eq!(actual, old);
        }
    }
    let mut slice = Slice::new(&mut device, Region::AppRegistry);
    let mut sector = [0; SECTOR_BYTES];
    for invalid in [14, 15, 30, u64::MAX] {
        assert_eq!(
            slice.read(invalid, &mut sector, DEADLINE),
            Err(region::Error::Bounds)
        );
        assert_eq!(
            slice.write(invalid, &sector, DEADLINE),
            Err(region::Error::Bounds)
        );
    }
    for logical in [14, 15, 30, 31, 32, 48, 64, u64::MAX] {
        assert_eq!(region::physical_sector(logical), None);
    }
    assert_eq!(Region::System.wire_sector(13), Some(13));
    assert_eq!(Region::AppRegistry.wire_sector(13), Some(29));
}

#[test]
fn detached_descriptor_edits_cannot_change_the_resolved_immutable_container() {
    let bytes = [package(1, 1, 1, 7, 8), package(2, 2, 1, 9, 8)];
    let mut c = catalog(&bytes);
    let a = c.packages[0].id().bytes();
    let other = c.packages[1].id();
    // app() returns a SHARED view. A detached plain descriptor can be edited,
    // but cannot replace the parsed package or change a compatibility receipt.
    let mut detached = *c.packages[0].app();
    detached.claimed_app = AppId::new([9; 16]).unwrap();
    detached.data_schema = DataSchema {
        current: 99,
        oldest_readable: 99,
    };
    assert_ne!(detached.claimed_app, c.packages[0].app().claimed_app);
    assert_eq!(c.packages[0].app().data_schema.current, 1);
    let mut r = fresh();
    apply(
        &mut r,
        Change::Install {
            package: a,
            data_epoch: 1,
        },
        &c,
    );
    assert_eq!(r.record().unwrap().unwrap().app(), policy().app);
    assert_eq!(
        r.record()
            .unwrap()
            .unwrap()
            .staged()
            .unwrap()
            .schema()
            .current,
        1
    );
    // A cached routing tag naming another package still cannot override the
    // digest freshly recomputed from the complete returned container bytes.
    c.wrong = Some(0);
    assert!(matches!(
        r.prepare(
            r.expected().unwrap(),
            Change::Stage {
                package: other.bytes()
            },
            &c,
            &Support
        ),
        Err(Error::WrongPackage)
    ));
}

#[test]
fn partial_format_is_never_silently_reformatted_or_credited_as_install() {
    let bytes = [package(1, 1, 1, 7, 8)];
    let c = catalog(&bytes);
    let disk = Disk::blank();
    let ctl = disk.probe.clone();
    // Fourteen blank reads, then the first format write persists but reports an
    // ambiguous failure. There is no committed registry root or installed app.
    ctl.cut.set(Some((15, Cut::After)));
    let rejected = Registry::format_new(disk, policy(), format_manifest(), DEADLINE)
        .err()
        .unwrap();
    assert_eq!(
        rejected.error,
        Error::Store(ev_store::Error::Io(Fault::Power))
    );
    assert!(rejected.pending.is_none());
    let reopened = Registry::open(rejected.device.cold(), policy(), &c, &Support, DEADLINE)
        .err()
        .unwrap();
    assert_eq!(reopened.error, Error::Store(ev_store::Error::Unformatted));
    let before = reopened.device.durable.clone();
    let reformat = Registry::format_new(reopened.device, policy(), format_manifest(), DEADLINE)
        .err()
        .unwrap();
    assert_eq!(reformat.error, Error::Store(ev_store::Error::NotBlank));
    assert_eq!(reformat.device.durable, before);
    reformat.device.assert_guards();
}

#[test]
fn app_data_envelope_cold_readback_uses_separate_region_and_keeps_registry_bytes() {
    use crate::app_data::AppDataEnvelope;
    // Start from a genuinely formatted Registry model region, then allocate a
    // distinct blank AppData region. Every other byte is retained as a guard.
    let registry = fresh();
    let (d, _, pending) = registry.into_parts();
    assert!(pending.is_none());
    let mut snapshot = d.durable;
    snapshot[80..94].fill([0; SECTOR_BYTES]);
    let data = Disk::snapshot_at(snapshot, 80);
    let initial = AppDataEnvelope::initial(policy().app, 1, 0x0a).unwrap();
    let mut store = Store::format_new(
        data,
        format_manifest(),
        &initial.encode(),
        BootPolicy::new(1).unwrap(),
        DEADLINE,
    )
    .unwrap_or_else(|r| panic!("data format: {:?}", r.error));
    let mut bytes = [0; ev_store::PAYLOAD_BYTES];
    assert_eq!(
        store
            .read_mutable(ObjectId::user_data(), &mut bytes, DEADLINE)
            .unwrap(),
        256
    );
    let actual = AppDataEnvelope::decode(&bytes).unwrap();
    assert_eq!(actual, initial);
    let next = actual.checked_replace(policy().app, 1, 0, 0x0b).unwrap();
    let receipt = store
        .execute(
            store.next_operation().unwrap(),
            Request::WriteMutable {
                object: ObjectId::user_data(),
                bytes: &next.encode(),
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(receipt.operation.get(), 1);
    let data = store.into_device();
    data.assert_guards();
    let mut reopened =
        Store::open(data.cold(), DEADLINE).unwrap_or_else(|r| panic!("data reopen: {:?}", r.error));
    assert_eq!(
        reopened
            .read_mutable(ObjectId::user_data(), &mut bytes, DEADLINE)
            .unwrap(),
        256
    );
    let actual = AppDataEnvelope::decode(&bytes).unwrap();
    assert_eq!(
        (
            actual.app(),
            actual.schema_epoch(),
            actual.counter(),
            actual.value()
        ),
        (policy().app, 1, 1, 0x0b)
    );
    assert!(reopened.known_good().is_none());
    reopened.into_device().assert_guards();
}

#[test]
fn scoped_open_returns_owned_preparation_without_mutating_or_losing_backend() {
    let bytes = [package(1, 1, 1, 7, 8)];
    let catalog = catalog(&bytes);
    let (device, policy, pending) = fresh().into_parts();
    assert!(pending.is_none());
    let before = device.durable.clone();
    let (device, intent) = Registry::with_open(
        device.cold(),
        policy,
        &catalog,
        &Support,
        DEADLINE,
        |registry| {
            registry.prepare(
                registry.expected()?,
                Change::Install {
                    package: catalog.packages[0].id().bytes(),
                    data_epoch: 1,
                },
                &catalog,
                &Support,
            )
        },
    )
    .unwrap_or_else(|r| panic!("scoped open: {:?}", r.error));
    assert_eq!(device.durable, before);
    device.assert_guards();
    assert_eq!(intent.operation().get(), 1);
    assert_eq!(intent.after().app(), policy.app);
    assert!(intent.after().installed());
}
#[test]
fn refused_scoped_open_keeps_actual_device_and_does_not_invoke_operation() {
    let bytes = [package(1, 1, 1, 7, 8)];
    let catalog = catalog(&bytes);
    let called = Cell::new(false);
    let device = Disk::blank();
    let before = device.durable.clone();
    let rejected = Registry::with_open(device, policy(), &catalog, &Support, DEADLINE, |_| {
        called.set(true);
        Ok(())
    })
    .err()
    .unwrap();
    assert!(!called.get());
    assert_eq!(rejected.error, Error::Store(ev_store::Error::Unformatted));
    assert!(rejected.pending.is_none());
    assert_eq!(rejected.policy, policy());
    assert_eq!(rejected.device.durable, before);
    rejected.device.assert_guards();
}
#[test]
fn scoped_publication_failure_preserves_exact_intent_even_if_callback_claims_success() {
    for claim_success in [false, true] {
        let bytes = [package(1, 1, 1, 7, 8)];
        let catalog = catalog(&bytes);
        let (device, policy, _) = fresh().into_parts();
        let probe = device.probe.clone();
        let rejected =
            Registry::with_open(device, policy, &catalog, &Support, DEADLINE, |registry| {
                let intent = registry.prepare(
                    registry.expected()?,
                    Change::Install {
                        package: catalog.packages[0].id().bytes(),
                        data_epoch: 1,
                    },
                    &catalog,
                    &Support,
                )?;
                probe.nth.set(0);
                probe.cut.set(Some((1, Cut::After)));
                let published = registry.publish(intent, &catalog, &Support, DEADLINE);
                assert!(published.is_err());
                if claim_success {
                    Ok(())
                } else {
                    published.map(|_| ())
                }
            })
            .err()
            .unwrap();
        if claim_success {
            assert_eq!(rejected.error, Error::NeedsRecovery);
        }
        let intent = rejected
            .pending
            .expect("actual unresolved intent must remain owned");
        assert_eq!(intent.operation().get(), 1);
        let expected = intent.after().encode();
        let (_registry, outcome) = Registry::resume(
            rejected.device.cold(),
            policy,
            Some(intent),
            &catalog,
            &Support,
            DEADLINE,
        )
        .unwrap_or_else(|r| panic!("exact recovery: {:?}", r.error));
        let Resolution::Unpublished(intent) = outcome else {
            panic!("first journal write was not committed")
        };
        assert_eq!(intent.operation().get(), 1);
        assert_eq!(intent.after().encode(), expected);
    }
}
