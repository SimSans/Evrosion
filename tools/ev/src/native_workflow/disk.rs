//! Independent cold inspection of immutable Native snapshots. The observer
//! cannot format, repair, flush or publish data; every SectorIo mutation refuses.
//! Source diagnostics never supply these expected durable facts.
use crate::{build::Result, storage};
use ev_app_registry::{Policy, Registry, app_data::AppDataEnvelope};
use ev_file::{
    Envelope,
    desktop::{Object, SEED_NOTES, SEED_PRIVATE},
};
use ev_root_supervisor::native_plan::{Contracts, Slot};
use ev_store::{
    GenerationId, GenerationManifest, ObjectId, Sector, SectorIo, Store, native::Region,
};
use ev_userspace_contract::root_v2::native::{self, catalogue::Catalogue};
use ev_zion::{
    Capability, Package,
    lifecycle::{Record, VersionRef},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const DEADLINE: u64 = 1;
#[derive(Clone, Copy)]
pub(super) struct Expected<'a> {
    pub catalogue: &'a [u8],
    pub revision: u64,
    pub installed: bool,
    pub active: Option<Slot>,
    pub previous: Option<Slot>,
    pub staged: Option<Slot>,
    pub data_epoch: u32,
    pub registry_operation: u64,
    pub data_operation: u64,
    pub data_counter: u64,
    pub value: u32,
}
#[derive(Debug, PartialEq, Eq)]
enum SnapshotError {
    Bounds,
    Deadline,
    ReadOnly,
}
struct Snapshot<'a> {
    bytes: &'a [u8],
    start: u32,
    reads: u64,
    mutations: u64,
}
impl<'a> Snapshot<'a> {
    fn new(bytes: &'a [u8], start: u32) -> Result<Self> {
        if bytes.len() != storage::DISK_BYTES
            || start as usize + ev_store::REQUIRED_SECTORS as usize > storage::SECTORS
        {
            return Err("Native snapshot is not the exact bounded4MiB disk".into());
        }
        Ok(Self {
            bytes,
            start,
            reads: 0,
            mutations: 0,
        })
    }
    fn digest(&self) -> String {
        let start = self.start as usize * storage::SECTOR_BYTES;
        let end = start + ev_store::REQUIRED_SECTORS as usize * storage::SECTOR_BYTES;
        format!("{:x}", Sha256::digest(&self.bytes[start..end]))
    }
}
impl SectorIo for Snapshot<'_> {
    type Error = SnapshotError;
    fn sectors(&self) -> u64 {
        ev_store::REQUIRED_SECTORS
    }
    fn read(
        &mut self,
        lba: u64,
        out: &mut Sector,
        deadline: u64,
    ) -> core::result::Result<(), Self::Error> {
        if deadline != DEADLINE {
            return Err(SnapshotError::Deadline);
        }
        if lba >= self.sectors() {
            return Err(SnapshotError::Bounds);
        }
        let start = (u64::from(self.start) + lba) as usize * storage::SECTOR_BYTES;
        out.copy_from_slice(
            self.bytes
                .get(start..start + storage::SECTOR_BYTES)
                .ok_or(SnapshotError::Bounds)?,
        );
        self.reads += 1;
        Ok(())
    }
    fn write(&mut self, _: u64, _: &Sector, _: u64) -> core::result::Result<(), Self::Error> {
        self.mutations += 1;
        Err(SnapshotError::ReadOnly)
    }
    fn flush(&mut self, _: u64) -> core::result::Result<(), Self::Error> {
        self.mutations += 1;
        Err(SnapshotError::ReadOnly)
    }
}
struct Banks<'a> {
    catalogue: Catalogue<'a>,
    packages: [Package<'a>; 2],
    bytes: [&'a [u8]; 2],
}
impl<'a> Banks<'a> {
    fn verify(catalogue: &'a [u8], bytes: [&'a [u8]; 2]) -> Result<Self> {
        let catalogue = Catalogue::decode(catalogue)
            .map_err(|e| format!("Native snapshot catalogue: {e:?}"))?;
        if catalogue.base().app_id() != crate::native_package::HELLO_APP_ID
            || ev_root_supervisor::native_plan::layout_measurement(&catalogue)
                != catalogue.layout_measurement()
        {
            return Err("Native snapshot catalogue identity/layout differs".into());
        }
        let packages = [
            Package::parse(bytes[0]).map_err(|e| format!("Native A container: {e:?}"))?,
            Package::parse(bytes[1]).map_err(|e| format!("Native B container: {e:?}"))?,
        ];
        for (i, package) in packages.iter().enumerate() {
            let (digest, image, build, length) = if i == 0 {
                (
                    catalogue.package_a(),
                    catalogue.base().images().nth(4).unwrap().image,
                    catalogue.base().app_build(),
                    catalogue.package_a_bytes(),
                )
            } else {
                (
                    catalogue.package_b(),
                    catalogue.app_b().image,
                    catalogue.package_b_build(),
                    catalogue.package_b_bytes(),
                )
            };
            if bytes[i].len() as u64 != length
                || package.id().bytes() != digest
                || package.executable().digest != image
                || package.app().build_id != build
                || package.app().claimed_app.bytes() != catalogue.base().app_id()
                || package.app().data_schema.current != 1
                || package.app().data_schema.oldest_readable != 1
            {
                return Err(
                    "Native actual package bytes/identity/build/schema differ from catalogue"
                        .into(),
                );
            }
            package
                .check_requirements(1, ev_userspace_contract::ABI, &Contracts)
                .map_err(|e| format!("Native actual package requirements: {e:?}"))?;
            if !package
                .app()
                .capability_requests()
                .any(|r| r.capability == Capability::AppPrivateData && r.required)
                || !package.app().contracts().any(|r| {
                    r.name == "ev.app.private-data"
                        && r.major == 1
                        && r.minimum_minor == 0
                        && r.features == 0
                })
            {
                return Err("Native package lacks required private-data declaration".into());
            }
        }
        Ok(Self {
            catalogue,
            packages,
            bytes,
        })
    }
    fn package(&self, slot: Slot) -> &Package<'a> {
        &self.packages[usize::from(slot == Slot::B)]
    }
    fn reference(&self, slot: Slot) -> Result<VersionRef> {
        let compatible = self
            .package(slot)
            .compatible(1, ev_userspace_contract::ABI, &Contracts)
            .map_err(|e| format!("Native referenced package incompatible: {e:?}"))?;
        Ok(VersionRef::from_package(&compatible))
    }
    fn format(&self, region: Region) -> GenerationManifest {
        let mut h = Sha256::new();
        h.update(b"evrosion.native.store-format.v1\0");
        h.update(self.catalogue.bytes());
        h.update(region.physical_start().to_le_bytes());
        GenerationManifest {
            generation: GenerationId::new(1).unwrap(),
            cohort: h.finalize().into(),
            supervisor_image: self.catalogue.base().root_image(),
            abi: native::ABI,
            health_contract: Sha256::digest(b"format-context-only; no admitted health").into(),
            health_version: 1,
            required_checks: ev_store::HEALTH_STORAGE | ev_store::HEALTH_SUPERVISOR,
        }
    }
}
impl ev_app_registry::Packages for Banks<'_> {
    fn resolve(&self, digest: [u8; 32]) -> Option<&[u8]> {
        self.packages
            .iter()
            .position(|p| p.id().bytes() == digest)
            .map(|i| self.bytes[i])
    }
}
fn open_region<'a>(
    bytes: &'a [u8],
    start: u32,
    expected: GenerationManifest,
    last_operation: u64,
) -> Result<Store<Snapshot<'a>>> {
    let mut store = Store::open(Snapshot::new(bytes, start)?, DEADLINE).map_err(|r| {
        format!(
            "Native cold region{start} cannot open without repair: {:?}",
            r.error
        )
    })?;
    if store
        .selected_manifest(DEADLINE)
        .map_err(|e| format!("Native format context: {e:?}"))?
        != expected
        || store.known_good().is_some()
        || store
            .committed_boot_serial()
            .map_err(|e| format!("Native boot serial: {e:?}"))?
            != 0
        || store
            .highest_generation()
            .map_err(|e| format!("Native highest generation: {e:?}"))?
            != 1
        || store
            .last_failure()
            .map_err(|e| format!("Native failure metadata: {e:?}"))?
            .is_some()
        || store
            .next_operation()
            .map_err(|e| format!("Native operation metadata: {e:?}"))?
            .get()
            != last_operation
                .checked_add(1)
                .filter(|n| *n != u64::MAX)
                .ok_or("Native expected operation overflow")?
        || !matches!(store.boot_plan(DEADLINE), Err(ev_store::Error::Phase))
    {
        return Err(format!(
            "Native region{start} context/operation/health metadata differs"
        ));
    }
    Ok(store)
}
fn read_body<D: SectorIo>(store: &mut Store<D>) -> Result<[u8; 256]>
where
    D::Error: core::fmt::Debug,
{
    let mut bytes = [0; 256];
    if store
        .read_mutable(ObjectId::user_data(), &mut bytes, DEADLINE)
        .map_err(|e| format!("Native actual mutable object: {e:?}"))?
        != 256
    {
        return Err("Native mutable object has wrong exact256-byte length".into());
    }
    Ok(bytes)
}
fn checked_device(device: Snapshot<'_>) -> Result<Value> {
    if device.mutations != 0 {
        return Err("Native cold observer attempted mutation/repair".into());
    }
    Ok(
        json!({"region_start":device.start,"sectors":ev_store::REQUIRED_SECTORS,"raw_sha256":device.digest(),"reads":device.reads,"mutation_attempts":device.mutations}),
    )
}
fn file_manifest(object: Object) -> GenerationManifest {
    GenerationManifest {
        generation: GenerationId::new(1).unwrap(),
        cohort: [object.stable_id() as u8; 32],
        supervisor_image: [0x22; 32],
        abi: ev_userspace_contract::ABI,
        health_contract: [0x33; 32],
        health_version: 1,
        required_checks: 3,
    }
}
fn file(bytes: &[u8], object: Object) -> Result<Value> {
    let (start, wanted) = match object {
        Object::Notes => (32, SEED_NOTES),
        Object::Private => (48, SEED_PRIVATE),
    };
    let mut store = open_region(bytes, start, file_manifest(object), 0)?;
    let mut body = [0; 256];
    let length = store
        .read_mutable(ObjectId::user_data(), &mut body, DEADLINE)
        .map_err(|e| format!("Native File cold read: {e:?}"))?;
    let envelope =
        Envelope::decode(&body[..length]).map_err(|e| format!("Native File envelope: {e:?}"))?;
    if envelope.counter() != 0 || envelope.global_operation() != 0 || envelope.payload() != wanted {
        return Err("Native File seed/counter/receipt changed".into());
    }
    let mut value = checked_device(store.into_device())?;
    value["payload_sha256"] = json!(format!("{:x}", Sha256::digest(envelope.payload())));
    value["client_counter"] = json!(0);
    value["global_operation"] = json!(0);
    Ok(value)
}
/// Read-only actual raw-byte observer; only explicit expected phase facts are
/// accepted, never successful guest markers or caller-supplied package tags.
pub(super) fn inspect(
    before: &[u8],
    after: &[u8],
    packages: [&[u8]; 2],
    expected: Expected<'_>,
) -> Result<Value> {
    if before.len() != storage::DISK_BYTES || after.len() != storage::DISK_BYTES {
        return Err("Native before/after disk size differs".into());
    }
    for (index, (a, b)) in before.iter().zip(after).enumerate() {
        let sector = index / storage::SECTOR_BYTES;
        if !((64..78).contains(&sector) || (80..94).contains(&sector)) && a != b {
            return Err(format!(
                "Native changed unrelated region/guard at sector{sector} byte{index}"
            ));
        }
    }
    let banks = Banks::verify(expected.catalogue, packages)?;
    let app = ev_zion::AppId::new(banks.catalogue.base().app_id())
        .ok_or("Native expected AppId invalid")?;
    let mut store = open_region(
        after,
        64,
        banks.format(Region::AppRegistry),
        expected.registry_operation,
    )?;
    let encoded = read_body(&mut store)?;
    let record =
        Record::decode(&encoded).map_err(|e| format!("Native durable registry record: {e:?}"))?;
    let reference = |slot: Option<Slot>| slot.map(|s| banks.reference(s)).transpose();
    if record.app() != app
        || record.revision() != expected.revision
        || record.installed() != expected.installed
        || record.data_epoch() != expected.data_epoch
        || record.active() != reference(expected.active)?
        || record.previous() != reference(expected.previous)?
        || record.staged() != reference(expected.staged)?
    {
        return Err(
            "Native durable registry differs from exact expected phase/identity/packages/schema"
                .into(),
        );
    }
    let mut registry_region = checked_device(store.into_device())?;
    let policy = Policy {
        app,
        abi: ev_userspace_contract::ABI,
        platform: 1,
    };
    let registry = Registry::open(
        Snapshot::new(after, 64)?,
        policy,
        &banks,
        &Contracts,
        DEADLINE,
    )
    .map_err(|r| format!("Native registry resolver/cold head: {:?}", r.error))?;
    let actual = registry
        .expected()
        .map_err(|e| format!("Native registry expected head: {e:?}"))?;
    let mut h = Sha256::new();
    h.update(b"evrosion.app-registry.head.v1\0");
    h.update(app.bytes());
    h.update(ev_userspace_contract::ABI);
    h.update(1u32.to_le_bytes());
    h.update(expected.revision.to_le_bytes());
    h.update((expected.registry_operation + 1).to_le_bytes());
    h.update(encoded);
    let head: [u8; 32] = h.finalize().into();
    if actual.revision != expected.revision || actual.base_head != head {
        return Err("Native durable registry head differs from canonical bytes/op".into());
    }
    let (device, _, pending) = registry.into_parts();
    if pending.is_some() {
        return Err("Native readonly registry observer acquired an unresolved publication".into());
    }
    let resolution = checked_device(device)?;
    registry_region["resolver_reads"] = resolution["reads"].clone();
    registry_region["revision"] = json!(record.revision());
    registry_region["installed"] = json!(record.installed());
    registry_region["active"] = json!(expected.active.map(|s| format!("{s:?}")));
    registry_region["previous"] = json!(expected.previous.map(|s| format!("{s:?}")));
    registry_region["staged"] = json!(expected.staged.map(|s| format!("{s:?}")));
    registry_region["last_operation"] = json!(expected.registry_operation);
    registry_region["head_sha256"] = json!(head);
    let mut store = open_region(
        after,
        80,
        banks.format(Region::AppData),
        expected.data_operation,
    )?;
    let data = AppDataEnvelope::decode(&read_body(&mut store)?)
        .map_err(|e| format!("Native App-data envelope: {e:?}"))?;
    if data.app() != app
        || data.schema_epoch() != expected.data_epoch
        || data.counter() != expected.data_counter
        || data.value() != expected.value
    {
        return Err("Native durable App data identity/schema/counter/value differs".into());
    }
    let mut app_data = checked_device(store.into_device())?;
    app_data["schema_epoch"] = json!(data.schema_epoch());
    app_data["counter"] = json!(data.counter());
    app_data["value"] = json!(data.value());
    app_data["last_operation"] = json!(expected.data_operation);
    let files = json!({"before":{"notes":file(before,Object::Notes)?,"private":file(before,Object::Private)?},
        "after":{"notes":file(after,Object::Notes)?,"private":file(after,Object::Private)?}});
    Ok(
        json!({"schema":1,"registry":registry_region,"app_data":app_data,"files":files,
        "outside_native_regions_unchanged":true,"system_region_unchanged":true,"file_regions_unchanged":true,
        "observer":"read-only actual cold Store-v2 snapshots; no format/repair/mutation; complete immutable package resolution",
        "system_health":"unused/unproven by this Native lifecycle observer; no KnownGood inferred"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ev_app_registry::Change;
    use ev_store::{BootPolicy, Request};
    use ev_userspace_contract::root_v2;
    use std::{cell::RefCell, rc::Rc};
    const ELF: &[u8] = include_bytes!("../../../../kernel/fixtures/bootstrap-static-v1.elf");
    struct Fixture {
        catalogue: [u8; native::catalogue::SIZE],
        packages: [Vec<u8>; 2],
        bytes: Rc<RefCell<Vec<u8>>>,
        before: Vec<u8>,
    }
    struct Writable {
        bytes: Rc<RefCell<Vec<u8>>>,
        start: u32,
    }
    impl SectorIo for Writable {
        type Error = ();
        fn sectors(&self) -> u64 {
            ev_store::REQUIRED_SECTORS
        }
        fn read(&mut self, lba: u64, out: &mut Sector, _: u64) -> core::result::Result<(), ()> {
            if lba >= self.sectors() {
                return Err(());
            }
            let at = (self.start as usize + lba as usize) * 512;
            out.copy_from_slice(&self.bytes.borrow()[at..at + 512]);
            Ok(())
        }
        fn write(&mut self, lba: u64, bytes: &Sector, _: u64) -> core::result::Result<(), ()> {
            if lba >= self.sectors() {
                return Err(());
            }
            let at = (self.start as usize + lba as usize) * 512;
            self.bytes.borrow_mut()[at..at + 512].copy_from_slice(bytes);
            Ok(())
        }
        fn flush(&mut self, _: u64) -> core::result::Result<(), ()> {
            Ok(())
        }
    }
    impl Fixture {
        fn new() -> Self {
            use native::catalogue as cat;
            use root_v2::catalogue as base;
            let a = crate::native_package::native_hello(ELF, [1; 32]).unwrap();
            let mut b_elf = ELF.to_vec();
            b_elf.push(0x42); // distinct actual ELF content, not a global source label
            let b = crate::native_package::native_hello(&b_elf, [2; 32]).unwrap();
            let images = core::array::from_fn(|i| base::Image {
                role: root_v2::graph::CHILDREN[i].image(),
                image: if i == 4 {
                    a.executable
                } else {
                    [i as u8 + 10; 32]
                },
                descriptor: if i == 4 {
                    a.descriptor
                } else {
                    [i as u8 + 20; 32]
                },
                abi: ev_userspace_contract::ABI,
                limits: base::CHILD_LIMITS,
                display_layout: i == 5,
                grants: base::CHILD_ROLE_COUNTS[i],
                roles: ev_root_supervisor::desktop_plan::roles_measurement(
                    root_v2::graph::CHILDREN[i],
                ),
            });
            let make = |graph| base::Description {
                root_image: [1; 32],
                kernel_input: [2; 32],
                graph,
                app_id: a.app,
                package: a.package,
                app_build: a.build,
                provenance: base::Provenance::Zion,
                restart_attempts: 3,
                restart_window: 60000,
                images,
            };
            let first = base::encode(make([0; 32])).unwrap();
            let graph = ev_root_supervisor::desktop_plan::graph_measurement(
                &base::Catalogue::decode(&first).unwrap(),
            );
            let base = base::encode(make(graph)).unwrap();
            let description = |layout_measurement| cat::Description {
                base: &base,
                app_b: cat::AppImage {
                    image: b.executable,
                    descriptor: b.descriptor,
                    abi: ev_userspace_contract::ABI,
                    limits: base::CHILD_LIMITS,
                    roles: ev_root_supervisor::desktop_plan::roles_measurement(
                        root_v2::graph::Child::App,
                    ),
                },
                bad_shell: cat::AppImage {
                    image: [0x91; 32],
                    descriptor: [0x92; 32],
                    abi: ev_userspace_contract::ABI,
                    limits: base::CHILD_LIMITS,
                    roles: ev_root_supervisor::desktop_plan::roles_measurement(
                        root_v2::graph::Child::Shell,
                    ),
                },
                boot_mode: cat::BootMode::Standalone,
                package_b: b.package,
                package_b_build: b.build,
                package_a_bytes: a.bytes.len() as u64,
                package_b_bytes: b.bytes.len() as u64,
                layout_measurement,
            };
            let first = cat::encode(description([1; 32])).unwrap();
            let layout = ev_root_supervisor::native_plan::layout_measurement(
                &cat::Catalogue::decode(&first).unwrap(),
            );
            let catalogue = cat::encode(description(layout)).unwrap();
            let bytes = Rc::new(RefCell::new(vec![0x9b; storage::DISK_BYTES]));
            for start in [32usize, 48, 64, 80] {
                bytes.borrow_mut()[start * 512..(start + 14) * 512].fill(0);
            }
            for (object, start, payload) in [
                (Object::Notes, 32, SEED_NOTES),
                (Object::Private, 48, SEED_PRIVATE),
            ] {
                let mut envelope = [0; 256];
                let n = Envelope::initial(payload).unwrap().encode(&mut envelope);
                Store::format_new(
                    Writable {
                        bytes: bytes.clone(),
                        start,
                    },
                    file_manifest(object),
                    &envelope[..n],
                    BootPolicy::new(3).unwrap(),
                    1,
                )
                .unwrap_or_else(|r| panic!("File model format: {:?}", r.error));
            }
            let before = bytes.borrow().clone();
            Self {
                catalogue,
                packages: [a.bytes, b.bytes],
                bytes,
                before,
            }
        }
        fn banks(&self) -> Banks<'_> {
            Banks::verify(&self.catalogue, [&self.packages[0], &self.packages[1]]).unwrap()
        }
        fn device(&self, start: u32) -> Writable {
            Writable {
                bytes: self.bytes.clone(),
                start,
            }
        }
        fn initialize(&self) {
            let banks = self.banks();
            let app = banks.package(Slot::A).app().claimed_app;
            let data = AppDataEnvelope::initial(app, 1, 1001).unwrap();
            Store::format_new(
                self.device(80),
                banks.format(Region::AppData),
                &data.encode(),
                BootPolicy::new(1).unwrap(),
                1,
            )
            .unwrap_or_else(|r| panic!("App model format: {:?}", r.error));
            let mut registry = Registry::format_new(
                self.device(64),
                Policy {
                    app,
                    abi: ev_userspace_contract::ABI,
                    platform: 1,
                },
                banks.format(Region::AppRegistry),
                1,
            )
            .unwrap_or_else(|r| panic!("Registry model format: {:?}", r.error));
            let prepared = registry
                .prepare(
                    registry.expected().unwrap(),
                    Change::Install {
                        package: banks.package(Slot::A).id().bytes(),
                        data_epoch: 1,
                    },
                    &banks,
                    &Contracts,
                )
                .unwrap();
            registry.publish(prepared, &banks, &Contracts, 1).unwrap();
        }
        fn change(&self, change: Change) {
            let banks = self.banks();
            let app = banks.package(Slot::A).app().claimed_app;
            let mut registry = Registry::open(
                self.device(64),
                Policy {
                    app,
                    abi: ev_userspace_contract::ABI,
                    platform: 1,
                },
                &banks,
                &Contracts,
                1,
            )
            .unwrap_or_else(|r| panic!("Registry model reopen: {:?}", r.error));
            let prepared = registry
                .prepare(registry.expected().unwrap(), change, &banks, &Contracts)
                .unwrap();
            registry.publish(prepared, &banks, &Contracts, 1).unwrap();
        }
        fn replace_data(&self, value: u32) {
            let mut store = Store::open(self.device(80), 1)
                .unwrap_or_else(|r| panic!("Data model open: {:?}", r.error));
            let data = AppDataEnvelope::decode(&read_body(&mut store).unwrap()).unwrap();
            let replacement = data
                .checked_replace(data.app(), data.schema_epoch(), data.counter(), value)
                .unwrap();
            store
                .execute(
                    store.next_operation().unwrap(),
                    Request::WriteMutable {
                        object: ObjectId::user_data(),
                        bytes: &replacement.encode(),
                    },
                    1,
                )
                .unwrap();
        }
        fn expected(
            &self,
            revision: u64,
            installed: bool,
            active: Option<Slot>,
            previous: Option<Slot>,
            staged: Option<Slot>,
            updated: bool,
        ) -> Expected<'_> {
            Expected {
                catalogue: &self.catalogue,
                revision,
                installed,
                active,
                previous,
                staged,
                data_epoch: 1,
                registry_operation: revision,
                data_operation: u64::from(updated),
                data_counter: u64::from(updated),
                value: if updated { 2026 } else { 1001 },
            }
        }
        fn inspect(&self, expected: Expected<'_>) -> Result<Value> {
            inspect(
                &self.before,
                &self.bytes.borrow(),
                [&self.packages[0], &self.packages[1]],
                expected,
            )
        }
    }
    #[test]
    fn cold_chain_checks_every_phase_and_preserves_files_and_private_data_after_removal() {
        let f = Fixture::new();
        f.initialize();
        f.inspect(f.expected(1, true, None, None, Some(Slot::A), false))
            .unwrap();
        f.change(Change::Activate);
        f.inspect(f.expected(2, true, Some(Slot::A), None, None, false))
            .unwrap();
        f.change(Change::Stage {
            package: f.banks().package(Slot::B).id().bytes(),
        });
        f.inspect(f.expected(3, true, Some(Slot::A), None, Some(Slot::B), false))
            .unwrap();
        f.change(Change::Activate);
        f.replace_data(2026);
        f.inspect(f.expected(4, true, Some(Slot::B), Some(Slot::A), None, true))
            .unwrap();
        f.change(Change::Rollback);
        f.inspect(f.expected(5, true, Some(Slot::A), Some(Slot::B), None, true))
            .unwrap();
        f.change(Change::Remove);
        f.inspect(f.expected(6, false, None, Some(Slot::A), None, true))
            .unwrap();
        f.change(Change::Reinstall {
            package: f.banks().package(Slot::A).id().bytes(),
        });
        f.inspect(f.expected(7, true, None, Some(Slot::A), Some(Slot::A), true))
            .unwrap();
        f.change(Change::Activate);
        let after = f.bytes.borrow().clone();
        let report = f
            .inspect(f.expected(8, true, Some(Slot::A), Some(Slot::A), None, true))
            .unwrap();
        assert_eq!(report["registry"]["mutation_attempts"], 0);
        assert_eq!(report["app_data"]["mutation_attempts"], 0);
        assert_eq!(report["app_data"]["value"], 2026);
        assert_eq!(report["app_data"]["counter"], 1);
        assert_eq!(
            *f.bytes.borrow(),
            after,
            "cold observer must not alter even one input byte"
        );
    }
    #[test]
    fn expected_state_cannot_accept_a_different_revision_package_data_or_operation() {
        let f = Fixture::new();
        f.initialize();
        f.change(Change::Activate);
        let expected = f.expected(2, true, Some(Slot::A), None, None, false);
        for bad in [
            Expected {
                revision: 3,
                ..expected
            },
            Expected {
                active: Some(Slot::B),
                ..expected
            },
            Expected {
                registry_operation: 1,
                ..expected
            },
            Expected {
                data_operation: 1,
                ..expected
            },
            Expected {
                data_counter: 1,
                ..expected
            },
            Expected {
                value: 2026,
                ..expected
            },
            Expected {
                data_epoch: 2,
                ..expected
            },
            Expected {
                installed: false,
                ..expected
            },
        ] {
            assert!(f.inspect(bad).is_err());
        }
        let original = f.bytes.borrow().clone();
        let mut corrupt = f.packages[0].clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(inspect(&f.before, &original, [&corrupt, &f.packages[1]], expected).is_err());
        assert!(
            inspect(
                &f.before,
                &original,
                [&f.packages[1], &f.packages[0]],
                expected
            )
            .is_err()
        );
    }
    #[test]
    fn committed_intent_requiring_replay_is_refused_without_any_observer_repair() {
        let f = Fixture::new();
        f.initialize();
        let baseline = f.bytes.borrow().clone();
        f.change(Change::Activate);
        let published = f.bytes.borrow().clone();
        // A genuine, checksummed op2 intent from the successful publisher is
        // durable while the old root/data still name op1. Cold Store recovery
        // would replay it. An observer must refuse the required first write.
        let mut pending = baseline;
        let journal = (64 + 2 + 2) * 512;
        pending[journal..journal + 512].copy_from_slice(&published[journal..journal + 512]);
        let rejected = Store::open(Snapshot::new(&pending, 64).unwrap(), 1)
            .err()
            .expect("readonly observer must not complete pending publication");
        assert_eq!(rejected.error, ev_store::Error::Io(SnapshotError::ReadOnly));
        assert_eq!(rejected.device.mutations, 1);
        assert!(
            inspect(
                &f.before,
                &pending,
                [&f.packages[0], &f.packages[1]],
                f.expected(1, true, None, None, Some(Slot::A), false)
            )
            .is_err()
        );
    }
    #[test]
    fn valid_envelope_in_the_wrong_format_context_and_unchanged_broken_files_refuse() {
        let f = Fixture::new();
        f.initialize();
        let mut bad = f.bytes.borrow().clone();
        let mut broken_before = f.before.clone();
        // Both snapshots carry the same corrupt committed Notes root. Byte
        // equality alone cannot establish a preserved readable File object.
        broken_before[33 * 512] ^= 1;
        bad[33 * 512] ^= 1;
        assert!(
            inspect(
                &broken_before,
                &bad,
                [&f.packages[0], &f.packages[1]],
                f.expected(1, true, None, None, Some(Slot::A), false)
            )
            .is_err()
        );
        let banks = f.banks();
        let mut context = banks.format(Region::AppData);
        context.cohort[0] ^= 1;
        f.bytes.borrow_mut()[80 * 512..94 * 512].fill(0);
        let initial =
            AppDataEnvelope::initial(banks.package(Slot::A).app().claimed_app, 1, 1001).unwrap();
        Store::format_new(
            f.device(80),
            context,
            &initial.encode(),
            BootPolicy::new(1).unwrap(),
            1,
        )
        .unwrap_or_else(|r| panic!("mismatched context fixture: {:?}", r.error));
        assert!(
            f.inspect(f.expected(1, true, None, None, Some(Slot::A), false))
                .is_err()
        );
    }
    #[test]
    fn guards_file_tampering_partial_or_cross_volume_data_cannot_be_repaired_or_pass() {
        let f = Fixture::new();
        f.initialize();
        f.change(Change::Activate);
        let expected = f.expected(2, true, Some(Slot::A), None, None, false);
        let after = f.bytes.borrow().clone();
        for sector in [0, 1, 16, 29, 32, 45, 48, 61, 62, 63, 78, 79, 94, 8191] {
            let mut bad = after.clone();
            bad[sector * 512] ^= 1;
            assert!(
                inspect(&f.before, &bad, [&f.packages[0], &f.packages[1]], expected).is_err(),
                "sector{sector}"
            );
        }
        let mut bad = after.clone();
        let registry = bad[64 * 512..78 * 512].to_vec();
        bad[80 * 512..94 * 512].copy_from_slice(&registry);
        assert!(inspect(&f.before, &bad, [&f.packages[0], &f.packages[1]], expected).is_err());
        let mut bad = after.clone();
        bad[80 * 512..94 * 512].fill(0);
        assert!(inspect(&f.before, &bad, [&f.packages[0], &f.packages[1]], expected).is_err());
        assert!(
            inspect(
                &f.before,
                &after[..after.len() - 1],
                [&f.packages[0], &f.packages[1]],
                expected
            )
            .is_err()
        );
        let mut snapshot = Snapshot::new(&after, 64).unwrap();
        assert_eq!(
            snapshot.read(14, &mut [0; 512], 1),
            Err(SnapshotError::Bounds)
        );
        assert_eq!(
            snapshot.read(0, &mut [0; 512], 2),
            Err(SnapshotError::Deadline)
        );
        assert_eq!(
            snapshot.write(0, &[1; 512], 1),
            Err(SnapshotError::ReadOnly)
        );
        assert_eq!(snapshot.flush(1), Err(SnapshotError::ReadOnly));
        assert_eq!(snapshot.mutations, 2);
    }
}
