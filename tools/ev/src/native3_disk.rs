//! Independent Native3 cold disk observer. Its devices reject every write and
//! flush, including Store open-time recovery. Creation provenance is separate
//! from the current mode-bound catalogue and actual running admission.
use crate::{build::Result, storage};
use ev_app_registry::{Policy, Registry, app_data::AppDataEnvelope};
use ev_file::{
    Envelope,
    desktop::{Object, SEED_NOTES, SEED_PRIVATE},
};
use ev_root_supervisor::native_plan::{Contracts, Slot, system};
use ev_store::{
    AdmissionReport, GenerationId, GenerationManifest, LastFailure, ObjectId, Sector, SectorIo,
    Store, native::Region,
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
pub(crate) struct AppExpected {
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
/// A caller specifies expected facts before observing guest output.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Generation {
    pub slot: system::Slot,
    pub id: u64,
}
#[derive(Clone, Copy, Debug)]
pub(crate) enum ProbeExpected {
    /// Initial System namespace only; exact source initial payload, no probe claimed.
    #[cfg_attr(not(test), allow(dead_code))]
    // Initial allocation is independently tested; production stops only after admitted probe.
    Absent,
    Exact(AdmissionReport),
}
#[derive(Clone, Copy, Debug)]
#[allow(clippy::large_enum_variant)] // Bounded copy of exact metadata/probe; no heap indirection needed.
pub(crate) enum SystemExpected {
    Unformatted,
    Committed {
        selected: Generation,
        known_good: Option<u64>,
        highest_generation: u64,
        boot_serial: u64,
        operation: u64,
        failure: Option<LastFailure>,
        probe: ProbeExpected,
    },
}
#[derive(Clone, Copy, Debug)]
pub(crate) enum GrantExpected {
    Absent,
    Empty {
        owner: [u8; 16],
    },
    Record {
        owner: [u8; 16],
        serial: u64,
        revision: u64,
        revoked: bool,
        package: Slot,
        object: Object,
        action: [u8; 32],
    },
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Mutations {
    pub system: bool,
    pub registry: bool,
    pub app_data: bool,
    pub grant_policy: bool,
}
pub(crate) struct Expected<'a> {
    pub catalogue: &'a [u8],
    pub creation_catalogue: &'a [u8],
    pub app: AppExpected,
    pub system: SystemExpected,
    pub grant: GrantExpected,
    pub mutations: Mutations,
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
            || ev_root_supervisor::desktop_plan::graph_measurement(catalogue.base())
                != catalogue.base().graph_measurement()
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
/// Independent read-only document observer. The expected content/revision is
/// supplied before inspection, never inferred from an App success marker.
pub(crate) fn document(bytes: &[u8], counter: u64, text: &[u8]) -> Result<Value> {
    let mut store = open_region(bytes, 32, file_manifest(Object::Notes), counter)?;
    let mut body = [0; 256];
    let length = store
        .read_mutable(ObjectId::user_data(), &mut body, DEADLINE)
        .map_err(|e| format!("document cold read: {e:?}"))?;
    let envelope =
        Envelope::decode(&body[..length]).map_err(|e| format!("document envelope: {e:?}"))?;
    if envelope.counter() != counter
        || envelope.global_operation() != counter
        || envelope.payload() != text
    {
        return Err("document cold bytes/revision differ".into());
    }
    let mut proof = checked_device(store.into_device())?;
    proof["counter"] = json!(counter);
    proof["payload_sha256"] = json!(format!("{:x}", Sha256::digest(text)));
    proof["private_file"] = file(bytes, Object::Private)?;
    Ok(proof)
}
/// Read-only actual raw-byte observer; only explicit expected phase facts are
/// accepted, never successful guest markers or caller-supplied package tags.
fn inspect_app(
    before: &[u8],
    after: &[u8],
    packages: [&[u8]; 2],
    catalogue: &[u8],
    creation_catalogue: &[u8],
    expected: AppExpected,
) -> Result<Value> {
    if before.len() != storage::DISK_BYTES || after.len() != storage::DISK_BYTES {
        return Err("Native before/after disk size differs".into());
    }
    let banks = Banks::verify(catalogue, packages)?;
    let creation = Banks::verify(creation_catalogue, packages)?;
    let app = ev_zion::AppId::new(banks.catalogue.base().app_id())
        .ok_or("Native expected AppId invalid")?;
    let mut store = open_region(
        after,
        64,
        creation.format(Region::AppRegistry),
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
        creation.format(Region::AppData),
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
        "file_regions_unchanged":true,
        "observer":"read-only actual cold Store-v2 snapshots; no format/repair/mutation; complete immutable package resolution",
        "scope":"App registry/data only; System and grant namespace independently opened by parent observer"}),
    )
}

fn system_manifest(banks: &Banks<'_>, selected: Generation) -> Result<GenerationManifest> {
    let generation = GenerationId::new(selected.id).ok_or("Native3 invalid generation")?;
    let cat = &banks.catalogue;
    let image = match selected.slot {
        system::Slot::Good => {
            let i = cat.base().images().next().ok_or("Native3 Shell missing")?;
            native::catalogue::AppImage {
                image: i.image,
                descriptor: i.descriptor,
                abi: i.abi,
                limits: i.limits,
                roles: i.roles,
            }
        }
        system::Slot::Bad => cat.bad_shell(),
    };
    let (a, b, c) = cat.cohort_parts();
    let mut recipe = Sha256::new();
    recipe.update(b"evrosion.native.mode-independent-catalogue.v1\0");
    recipe.update(a);
    recipe.update([0; 32]);
    recipe.update(b);
    recipe.update([0; 2]);
    recipe.update(c);
    let recipe: [u8; 32] = recipe.finalize().into();
    let mut h = Sha256::new();
    h.update(b"evrosion.native.system.cohort.v1\0");
    h.update(native::PROFILE.to_le_bytes());
    h.update(generation.get().to_le_bytes());
    let health = system::health_contract();
    for d in [
        cat.base().root_image(),
        cat.base().kernel_input(),
        recipe,
        native::ABI,
        Sha256::digest(native::layout_description()).into(),
        Sha256::digest(ev_userspace_contract::root_v2::graph::description()).into(),
        cat.package_a(),
        cat.package_b(),
        image.image,
        image.descriptor,
        image.abi,
        image.roles,
        health,
    ] {
        h.update(d);
    }
    for limit in image.limits {
        h.update(limit.to_le_bytes());
    }
    h.update(8u64.to_le_bytes());
    Ok(GenerationManifest {
        generation,
        cohort: h.finalize().into(),
        supervisor_image: cat.base().root_image(),
        abi: native::ABI,
        health_contract: health,
        health_version: 1,
        required_checks: ev_store::HEALTH_STORAGE | ev_store::HEALTH_SUPERVISOR,
    })
}
fn region_bytes(bytes: &[u8], region: Region) -> &[u8] {
    let start = region.physical_start() as usize * storage::SECTOR_BYTES;
    &bytes[start..start + ev_store::REQUIRED_SECTORS as usize * storage::SECTOR_BYTES]
}
fn blank(bytes: &[u8], region: Region) -> Result<Value> {
    let mut device = Snapshot::new(bytes, region.physical_start())?;
    ev_store::desktop::require_blank(&mut device, DEADLINE)
        .map_err(|e| format!("Native3 expected blank {region:?}: {e:?}"))?;
    checked_device(device)
}
fn inspect_system(bytes: &[u8], banks: &Banks<'_>, expected: SystemExpected) -> Result<Value> {
    let SystemExpected::Committed {
        selected,
        known_good,
        highest_generation,
        boot_serial,
        operation,
        failure,
        probe,
    } = expected
    else {
        let mut record = blank(bytes, Region::System)?;
        record["state"] = json!("unformatted");
        return Ok(record);
    };
    let wanted = system_manifest(banks, selected)?;
    let mut store = Store::open(
        Snapshot::new(bytes, Region::System.physical_start())?,
        DEADLINE,
    )
    .map_err(|r| {
        format!(
            "Native3 System cold open refused/needs repair: {:?}",
            r.error
        )
    })?;
    if store
        .selected_manifest(DEADLINE)
        .map_err(|e| format!("Native3 System selected: {e:?}"))?
        != wanted
        || store.known_good().map(|v| v.get()) != known_good
        || store
            .highest_generation()
            .map_err(|e| format!("Native3 highest generation: {e:?}"))?
            != highest_generation
        || store
            .committed_boot_serial()
            .map_err(|e| format!("Native3 boot serial: {e:?}"))?
            != boot_serial
        || store
            .next_operation()
            .map_err(|e| format!("Native3 System next op: {e:?}"))?
            .get()
            != operation
                .checked_add(1)
                .ok_or("Native3 System op overflow")?
        || store
            .last_failure()
            .map_err(|e| format!("Native3 System failure: {e:?}"))?
            != failure
        || !matches!(store.boot_plan(DEADLINE), Err(ev_store::Error::Phase))
    {
        return Err("Native3 System durable selection/KnownGood/failure/operation differs".into());
    }
    if let Some(f) = failure
        && (f.supervisor_image != banks.catalogue.base().root_image()
            || f.sequence != f.operation.get() + 1
            || f.boot_serial > boot_serial
            || f.generation.get() > highest_generation)
    {
        return Err(
            "Native3 LastFailure inconsistent with actual cohort/committed operation".into(),
        );
    }
    let staged = store
        .staged_manifest(DEADLINE)
        .map_err(|e| format!("Native3 staged System manifest: {e:?}"))?;
    let wanted_staged =
        if selected.slot == system::Slot::Bad || matches!(probe, ProbeExpected::Absent) {
            Some(wanted)
        } else {
            None
        };
    if staged != wanted_staged {
        return Err("Native3 staged durable System cohort differs".into());
    }
    let mut head = Sha256::new();
    head.update(b"evrosion.native.system.owner-head.v1\0");
    for m in [Some(wanted), staged] {
        head.update(m.map_or([0; 32], |m| system::manifest_digest(&m)));
    }
    for n in [
        known_good.unwrap_or(0),
        boot_serial,
        highest_generation,
        operation + 1,
    ] {
        head.update(n.to_le_bytes());
    }
    if let Some(f) = failure {
        for n in [
            f.generation.get(),
            f.boot_serial,
            f.operation.get(),
            f.sequence,
        ] {
            head.update(n.to_le_bytes());
        }
    }
    let owner_head: [u8; 32] = head.finalize().into();
    let mut payload = [0; 256];
    let n = store
        .read_mutable(ObjectId::user_data(), &mut payload, DEADLINE)
        .map_err(|e| format!("Native3 System probe read: {e:?}"))?;
    match probe {
        ProbeExpected::Absent if &payload[..n] == b"System pending; no admitted health" => {}
        ProbeExpected::Exact(admitted) if n == 256 && payload == system::probe(admitted) => {
            let recipe = system_manifest(
                banks,
                Generation {
                    slot: system::Slot::Good,
                    id: admitted.generation.get(),
                },
            )?;
            if admitted.cohort != recipe.cohort
                || admitted.supervisor_image != recipe.supervisor_image
                || admitted.abi != recipe.abi
                || admitted.health_contract != recipe.health_contract
                || admitted.health_version != recipe.health_version
                || admitted.boot_serial > boot_serial
                || admitted.process_stamp == [0; 32]
            {
                return Err(
                    "Native3 durable probe does not bind exact executed Good cohort".into(),
                );
            }
        }
        _ => return Err("Native3 System durable probe differs or was invented".into()),
    }
    let mut result = checked_device(store.into_device())?;
    result["owner_head_digest"] = json!(owner_head);
    result["selected_generation"] = json!(selected.id);
    result["selected_slot"] = json!(format!("{:?}", selected.slot));
    result["selected_manifest"] = json!(system::manifest_digest(&wanted));
    result["known_good"] = json!(known_good);
    result["boot_serial"] = json!(boot_serial);
    result["last_operation"] = json!(operation);
    result["highest_generation"] = json!(highest_generation);
    result["last_failure"]=json!(failure.map(|f|json!({"generation":f.generation.get(),"boot_serial":f.boot_serial,"attempts":f.attempts,"reason":format!("{:?}",f.reason),"process_stamp":f.process_stamp,"operation":f.operation.get(),"sequence":f.sequence})));
    result["probe_sha256"] = json!(format!("{:x}", Sha256::digest(&payload[..n])));
    Ok(result)
}
fn grant_format(creation: &Banks<'_>, owner: [u8; 16]) -> GenerationManifest {
    let mut h = Sha256::new();
    h.update(b"evrosion.native.owner-grant-namespace.v1\0");
    h.update(owner);
    h.update(creation.catalogue.base().app_id());
    h.update(1u64.to_le_bytes());
    h.update(Region::GrantPolicy.physical_start().to_le_bytes());
    GenerationManifest {
        generation: GenerationId::new(1).unwrap(),
        cohort: h.finalize().into(),
        supervisor_image: creation.catalogue.base().root_image(),
        abi: native::ABI,
        health_contract: Sha256::digest(b"format-context-only; no System admission or health")
            .into(),
        health_version: 1,
        required_checks: 3,
    }
}
fn inspect_grant(
    bytes: &[u8],
    banks: &Banks<'_>,
    creation: &Banks<'_>,
    expected: GrantExpected,
) -> Result<Value> {
    let (owner, revision) = match expected {
        GrantExpected::Absent => {
            let mut r = blank(bytes, Region::GrantPolicy)?;
            r["state"] = json!("absent");
            return Ok(r);
        }
        GrantExpected::Empty { owner } => (owner, 0),
        GrantExpected::Record {
            owner, revision, ..
        } => (owner, revision),
    };
    let mut store = open_region(
        bytes,
        Region::GrantPolicy.physical_start(),
        grant_format(creation, owner),
        revision,
    )?;
    let encoded = read_body(&mut store)?;
    let mut record = checked_device(store.into_device())?;
    let user = ev_picker::UserId::new(owner).ok_or("Native3 grant owner is zero")?;
    let app = ev_picker::AppId::new(banks.catalogue.base().app_id())
        .ok_or("Native3 grant App invalid")?;
    let scope = ev_grant_policy::Scope { user, app };
    let policy = ev_grant_policy::PolicyOwner::open(
        Snapshot::new(bytes, Region::GrantPolicy.physical_start())?,
        scope,
        DEADLINE,
    )
    .map_err(|r| format!("Native3 grant latest policy rejected: {:?}", r.error))?;
    let head = policy
        .expected()
        .map_err(|e| format!("Native3 grant canonical head: {e:?}"))?;
    let actual = policy
        .record()
        .map_err(|e| format!("Native3 grant current record: {e:?}"))?;
    if head.revision != revision
        || head.operation.get() != revision.checked_add(1).ok_or("Native3 grant op overflow")?
        || head.digest != <[u8; 32]>::from(Sha256::digest(encoded))
    {
        return Err("Native3 grant latest head/op/revision differs".into());
    }
    match (expected, actual) {
        (GrantExpected::Empty { .. }, None) => {}
        (
            GrantExpected::Record {
                serial,
                revision,
                revoked,
                package,
                object,
                action,
                ..
            },
            Some(actual),
        ) => {
            let payload = match object {
                Object::Notes => SEED_NOTES,
                Object::Private => SEED_PRIVATE,
            };
            if actual.user() != user
                || actual.app().app != app
                || actual.app().package.bytes() != banks.package(package).id().bytes()
                || actual.grant_serial() != serial
                || actual.policy_revision() != revision
                || actual.revoked() != revoked
                || actual.object().volume().bytes() != *b"EVRO-USERS-VOL01"
                || actual.object().local() != object.stable_id()
                || actual.revision().counter() != 0
                || actual.revision().content().bytes() != <[u8; 32]>::from(Sha256::digest(payload))
                || actual.approver() != user
                || actual.origin() != ev_picker::Origin::ExplicitOwnerAction
                || actual.action_digest() != action
                || serial == 0
                || serial > revision
                || action == [0; 32]
            {
                return Err(
                    "Native3 grant durable subject/resource/consent/tombstone differs".into(),
                );
            }
            record["grant_serial"] = json!(serial);
            record["revoked"] = json!(revoked);
            record["package"] = json!(banks.package(package).id().bytes());
            record["action_digest"] = json!(action);
        }
        _ => return Err("Native3 grant record/empty mismatch".into()),
    }
    let (device, _, pending) = policy.into_parts();
    if pending.is_some() {
        return Err("Native3 readonly grant observer acquired pending publication".into());
    }
    record["resolver"] = checked_device(device)?;
    record["policy_revision"] = json!(revision);
    record["last_operation"] = json!(revision);
    record["head_sha256"] = json!(head.digest);
    record["owner"] = json!(owner);
    Ok(record)
}
/// Verify the actual cold image and every guard/other namespace independently.
/// No repair, formatting or publication is available to this observer.
pub(crate) fn inspect(
    before: &[u8],
    after: &[u8],
    packages: [&[u8]; 2],
    expected: Expected<'_>,
) -> Result<Value> {
    if before.len() != storage::DISK_BYTES || after.len() != storage::DISK_BYTES {
        return Err("Native3 expected exact4MiB snapshots".into());
    }
    let permitted = [
        (Region::System, expected.mutations.system),
        (Region::AppRegistry, expected.mutations.registry),
        (Region::AppData, expected.mutations.app_data),
        (Region::GrantPolicy, expected.mutations.grant_policy),
    ];
    for (i, (a, b)) in before.iter().zip(after).enumerate() {
        let sector = i / storage::SECTOR_BYTES;
        if a != b
            && !permitted.iter().any(|(r, allowed)| {
                *allowed
                    && (r.physical_start() as usize
                        ..r.physical_start() as usize + ev_store::REQUIRED_SECTORS as usize)
                        .contains(&sector)
            })
        {
            return Err(format!(
                "Native3 unauthorized snapshot mutation at sector{sector} byte{i}"
            ));
        }
    }
    let banks = Banks::verify(expected.catalogue, packages)?;
    let creation = Banks::verify(expected.creation_catalogue, packages)?;
    // Each catalogue independently resolves the same actual App banks. Original
    // creation Root/recipe remains historical namespace provenance, not a rule
    // that current compatible OS code must have the same content identity.
    let app = inspect_app(
        before,
        after,
        packages,
        expected.catalogue,
        expected.creation_catalogue,
        expected.app,
    )?;
    let system = inspect_system(after, &banks, expected.system)?;
    let grant = inspect_grant(after, &banks, &creation, expected.grant)?;
    Ok(
        json!({"schema":1,"profile":3,"app":app,"system":system,"grant_policy":grant,"creation_catalogue_sha256":format!("{:x}",Sha256::digest(expected.creation_catalogue)),"current_catalogue_sha256":format!("{:x}",Sha256::digest(expected.catalogue)),"outside_explicit_mutable_regions_unchanged":true,"file_regions_unchanged":true,"system_region_changed":region_bytes(before,Region::System)!=region_bytes(after,Region::System),"grant_region_changed":region_bytes(before,Region::GrantPolicy)!=region_bytes(after,Region::GrantPolicy),"observer":"independent read-only cold Store opens; no repair or authority inferred from receipts"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ev_app_registry::Change;
    use ev_store::{BootPolicy, Request};
    use ev_userspace_contract::root_v2;
    use std::{cell::RefCell, rc::Rc};
    const ELF: &[u8] = include_bytes!("../../../kernel/fixtures/bootstrap-static-v1.elf");
    struct Fixture {
        catalogue: [u8; native::catalogue::SIZE],
        packages: [Vec<u8>; 2],
        bytes: Rc<RefCell<Vec<u8>>>,
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
            for start in [16usize, 32, 48, 64, 80, 96] {
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
            Self {
                catalogue,
                packages: [a.bytes, b.bytes],
                bytes,
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
        fn activate(&self) {
            self.initialize();
            self.change(Change::Activate);
        }
        fn expected(&self) -> Expected<'_> {
            Expected {
                catalogue: &self.catalogue,
                creation_catalogue: &self.catalogue,
                app: AppExpected {
                    revision: 2,
                    installed: true,
                    active: Some(Slot::A),
                    previous: None,
                    staged: None,
                    data_epoch: 1,
                    registry_operation: 2,
                    data_operation: 0,
                    data_counter: 0,
                    value: 1001,
                },
                system: SystemExpected::Unformatted,
                grant: GrantExpected::Absent,
                mutations: Mutations::default(),
            }
        }
        fn inspect(&self, before: &[u8], expected: Expected<'_>) -> Result<Value> {
            inspect(
                before,
                &self.bytes.borrow(),
                [&self.packages[0], &self.packages[1]],
                expected,
            )
        }
    }
    #[test]
    fn unformatted_namespaces_and_original_files_are_checked_without_mutation() {
        let f = Fixture::new();
        f.activate();
        let before = f.bytes.borrow().clone();
        let result = f.inspect(&before, f.expected()).unwrap();
        assert_eq!(result["system"]["state"], "unformatted");
        assert_eq!(*f.bytes.borrow(), before);
        for sector in [
            0, 15, 16, 29, 30, 32, 48, 63, 64, 77, 78, 80, 93, 94, 96, 109, 110, 8191,
        ] {
            f.bytes.borrow_mut()[sector * 512] ^= 1;
            assert!(
                f.inspect(&before, f.expected()).is_err(),
                "unauthorized sector{sector}"
            );
            f.bytes.borrow_mut()[sector * 512] ^= 1;
        }
        f.replace_data(2026);
        assert!(f.inspect(&before, f.expected()).is_err());
    }
    fn execute(store: &mut Store<Writable>, request: Request<'_>) {
        let op = store.next_operation().unwrap();
        store.execute(op, request, 1).unwrap();
    }
    fn begin(store: &mut Store<Writable>) -> AdmissionReport {
        let m = store.selected_manifest(1).unwrap();
        execute(store, Request::BeginBoot(m.generation));
        let plan = store.boot_plan(1).unwrap();
        let a = AdmissionReport {
            generation: m.generation,
            boot_serial: plan.serial,
            process_stamp: Sha256::digest(plan.serial.to_le_bytes()).into(),
            cohort: m.cohort,
            supervisor_image: m.supervisor_image,
            abi: m.abi,
            health_contract: m.health_contract,
            health_version: m.health_version,
        };
        execute(store, Request::Admission(a));
        a
    }
    fn good(store: &mut Store<Writable>, a: AdmissionReport) {
        let body = system::probe(a);
        execute(
            store,
            Request::WriteMutable {
                object: ObjectId::user_data(),
                bytes: &body,
            },
        );
        execute(
            store,
            Request::Health(ev_store::HealthReport {
                admitted: a,
                outcome: ev_store::HealthOutcome::CriticalPassed,
                observed_checks: 3,
                storage_probe: Sha256::digest(body).into(),
            }),
        );
    }
    fn expected_system(
        selected: Generation,
        kg: Option<u64>,
        highest: u64,
        serial: u64,
        op: u64,
        failure: Option<LastFailure>,
        probe: ProbeExpected,
    ) -> SystemExpected {
        SystemExpected::Committed {
            selected,
            known_good: kg,
            highest_generation: highest,
            boot_serial: serial,
            operation: op,
            failure,
            probe,
        }
    }
    #[test]
    fn durable_system_chain_keeps_running_admission_distinct_from_next_selection() {
        let f = Fixture::new();
        f.activate();
        let before = f.bytes.borrow().clone();
        let banks = f.banks();
        let one = Generation {
            slot: system::Slot::Good,
            id: 1,
        };
        let two = Generation {
            slot: system::Slot::Bad,
            id: 2,
        };
        let mut s = Store::format_new(
            f.device(16),
            system_manifest(&banks, one).unwrap(),
            b"System pending; no admitted health",
            BootPolicy::new(1).unwrap(),
            1,
        )
        .unwrap_or_else(|r| panic!("{:?}", r.error));
        let mut e = f.expected();
        e.mutations.system = true;
        e.system = expected_system(one, None, 1, 0, 0, None, ProbeExpected::Absent);
        f.inspect(&before, e).unwrap();
        let a = begin(&mut s);
        good(&mut s, a);
        let mut e = f.expected();
        e.mutations.system = true;
        e.system = expected_system(one, Some(1), 1, 1, 4, None, ProbeExpected::Exact(a));
        f.inspect(&before, e).unwrap();
        execute(
            &mut s,
            Request::Stage(&system_manifest(&banks, two).unwrap()),
        );
        execute(&mut s, Request::Activate(GenerationId::new(2).unwrap()));
        let mut e = f.expected();
        e.mutations.system = true;
        e.system = expected_system(two, Some(1), 2, 1, 6, None, ProbeExpected::Exact(a));
        f.inspect(&before, e).unwrap();
        let bad = begin(&mut s);
        execute(
            &mut s,
            Request::Health(ev_store::HealthReport {
                admitted: bad,
                outcome: ev_store::HealthOutcome::MissingProgress,
                observed_checks: 0,
                storage_probe: [0; 32],
            }),
        );
        let failure = s.last_failure().unwrap().unwrap();
        assert_eq!(failure.reason, ev_store::LastFailureReason::MissingProgress);
        assert_eq!(failure.operation.get(), 9);
        let mut e = f.expected();
        e.mutations.system = true;
        e.system = expected_system(
            one,
            Some(1),
            2,
            2,
            9,
            Some(failure),
            ProbeExpected::Exact(a),
        );
        f.inspect(&before, e).unwrap();
        let fresh = begin(&mut s);
        good(&mut s, fresh);
        let mut e = f.expected();
        e.mutations.system = true;
        e.system = expected_system(
            one,
            Some(1),
            2,
            3,
            13,
            Some(failure),
            ProbeExpected::Exact(fresh),
        );
        f.inspect(&before, e).unwrap();
        let after = f.bytes.borrow().clone();
        assert_eq!(&after[32 * 512..62 * 512], &before[32 * 512..62 * 512]);
        let mut bad_expected = f.expected();
        bad_expected.mutations.system = true;
        bad_expected.system =
            expected_system(two, Some(2), 2, 3, 13, None, ProbeExpected::Exact(bad));
        assert!(f.inspect(&before, bad_expected).is_err());
        assert_eq!(
            *f.bytes.borrow(),
            after,
            "observer cannot repair or publish"
        );
    }
    #[test]
    fn original_format_context_survives_mode_change_and_current_context_relabel_is_refused() {
        let f = Fixture::new();
        f.activate();
        let before = f.bytes.borrow().clone();
        let mut changed = f.catalogue;
        let at = native::catalogue::BOOT_MODE_OFFSET;
        changed[at..at + 2].copy_from_slice(&1u16.to_le_bytes());
        let measurement = ev_root_supervisor::native_plan::layout_measurement(
            &Catalogue::decode(&changed).unwrap(),
        );
        let at = native::catalogue::MEASUREMENT_OFFSET;
        changed[at..at + 32].copy_from_slice(&measurement);
        let mut e = f.expected();
        e.catalogue = &changed;
        f.inspect(&before, e).unwrap();
        let mut wrong = f.expected();
        wrong.catalogue = &changed;
        wrong.creation_catalogue = &changed;
        assert!(f.inspect(&before, wrong).is_err());
    }
    #[test]
    fn empty_latest_policy_checks_creation_scope_and_never_accepts_a_grant() {
        let f = Fixture::new();
        f.activate();
        let before = f.bytes.borrow().clone();
        let banks = f.banks();
        let owner = *b"EVROSION-OWNER01";
        let scope = ev_grant_policy::Scope {
            user: ev_picker::UserId::new(owner).unwrap(),
            app: banks.package(Slot::A).app().claimed_app,
        };
        let p = ev_grant_policy::PolicyOwner::format_empty(
            f.device(96),
            scope,
            grant_format(&banks, owner),
            1,
        )
        .unwrap_or_else(|r| panic!("{:?}", r.error));
        drop(p);
        let mut e = f.expected();
        e.mutations.grant_policy = true;
        e.grant = GrantExpected::Empty { owner };
        let report = f.inspect(&before, e).unwrap();
        assert_eq!(report["grant_policy"]["policy_revision"], 0);
        let mut e = f.expected();
        e.mutations.grant_policy = true;
        e.grant = GrantExpected::Empty { owner: [3; 16] };
        assert!(f.inspect(&before, e).is_err());
        let mut e = f.expected();
        e.mutations.grant_policy = true;
        e.grant = GrantExpected::Record {
            owner,
            serial: 1,
            revision: 1,
            revoked: false,
            package: Slot::A,
            object: Object::Notes,
            action: [7; 32],
        };
        assert!(f.inspect(&before, e).is_err());
    }
    #[test]
    fn compatible_os_source_replacement_does_not_relabel_existing_app_namespace() {
        let f = Fixture::new();
        f.activate();
        let before = f.bytes.borrow().clone();
        let mut current = f.catalogue;
        // Structural observer model only; no replacement Root ELF is executed.
        current[16..48].copy_from_slice(&[0x81; 32]);
        current[112..144].copy_from_slice(&[0x82; 32]);
        let base = ev_userspace_contract::root_v2::catalogue::Catalogue::decode(
            &current[..native::catalogue::BASE_SIZE],
        )
        .unwrap();
        let graph = ev_root_supervisor::desktop_plan::graph_measurement(&base);
        current[144..176].copy_from_slice(&graph);
        let layout = ev_root_supervisor::native_plan::layout_measurement(
            &Catalogue::decode(&current).unwrap(),
        );
        let at = native::catalogue::MEASUREMENT_OFFSET;
        current[at..at + 32].copy_from_slice(&layout);
        let mut e = f.expected();
        e.catalogue = &current;
        f.inspect(&before, e).unwrap();
        let mut wrong = f.expected();
        wrong.catalogue = &current;
        wrong.creation_catalogue = &current;
        assert!(
            f.inspect(&before, wrong).is_err(),
            "current Root cannot impersonate original format provenance"
        );
        assert_eq!(*f.bytes.borrow(), before);
    }
    struct Proposal<'a> {
        owner: &'a ev_grant_policy::PolicyOwner<Writable>,
        prepared: Option<ev_grant_policy::Prepared>,
    }
    impl ev_picker::Handoff for Proposal<'_> {
        type Delivered = ();
        type Error = ();
        fn revalidate_and_deliver_read(
            &mut self,
            read: ev_picker::ReadDelivery<'_>,
        ) -> ev_picker::Delivery<(), ()> {
            self.prepared = Some(
                self.owner
                    .prepare_remember(self.owner.expected().unwrap(), &read)
                    .unwrap(),
            );
            ev_picker::Delivery::Delivered(())
        }
    }
    fn remember(owner: &mut ev_grant_policy::PolicyOwner<Writable>, banks: &Banks<'_>) -> [u8; 32] {
        use ev_picker::*;
        let user = UserId::new(*b"EVROSION-OWNER01").unwrap();
        let requester = Requester {
            user,
            session: SessionId::new([1; 16]).unwrap(),
            app: AppRef {
                app: banks.package(Slot::A).app().claimed_app,
                package: ContentDigest::new(banks.package(Slot::A).id().bytes()).unwrap(),
            },
            incarnation: Incarnation::new(BootEpoch::new([2; 16]).unwrap(), 25).unwrap(),
            policy_revision: owner.requester_policy_revision().unwrap(),
            alive: true,
        };
        let object = ObjectView {
            object: ev_picker::ObjectId::new(VolumeId::new(*b"EVRO-USERS-VOL01").unwrap(), 1)
                .unwrap(),
            revision: Revision::new(
                0,
                ContentDigest::new(Sha256::digest(SEED_NOTES).into()).unwrap(),
            )
            .unwrap(),
            permission_revision: 1,
            readable: true,
        };
        let mut picker = Picker::new(PickerEpoch::new([3; 16]).unwrap(), 100).unwrap();
        let approval = picker
            .prepare(requester, object, Persistence::RememberPerUser, 10, 30)
            .unwrap();
        let action = approval.selection().action_digest();
        let consent = Consent {
            displayed_action: action,
            approver: user,
            origin: Origin::ExplicitOwnerAction,
        };
        let mut handoff = Proposal {
            owner,
            prepared: None,
        };
        assert!(matches!(
            picker
                .commit(approval, consent, requester, object, 11, &mut handoff)
                .unwrap(),
            Delivery::Delivered(())
        ));
        let prepared = handoff.prepared.take().unwrap();
        owner.publish(prepared, 1).unwrap();
        action
    }
    #[test]
    fn actual_policy_head_tombstone_and_replayed_active_record_are_distinguished() {
        let f = Fixture::new();
        f.activate();
        let before = f.bytes.borrow().clone();
        let banks = f.banks();
        let owner = *b"EVROSION-OWNER01";
        let scope = ev_grant_policy::Scope {
            user: ev_picker::UserId::new(owner).unwrap(),
            app: banks.package(Slot::A).app().claimed_app,
        };
        let mut p = ev_grant_policy::PolicyOwner::format_empty(
            f.device(96),
            scope,
            grant_format(&banks, owner),
            1,
        )
        .unwrap_or_else(|r| panic!("{:?}", r.error));
        let action = remember(&mut p, &banks);
        let active = p.record().unwrap().unwrap().encode();
        let mut e = f.expected();
        e.mutations.grant_policy = true;
        e.grant = GrantExpected::Record {
            owner,
            serial: 1,
            revision: 1,
            revoked: false,
            package: Slot::A,
            object: Object::Notes,
            action,
        };
        f.inspect(&before, e).unwrap();
        {
            let object = Object::Private;
            let mut e = f.expected();
            e.mutations.grant_policy = true;
            e.grant = GrantExpected::Record {
                owner,
                serial: 1,
                revision: 1,
                revoked: false,
                package: Slot::A,
                object,
                action,
            };
            assert!(f.inspect(&before, e).is_err());
        }
        let prepared = p.prepare_revoke(p.expected().unwrap()).unwrap();
        p.publish(prepared, 1).unwrap();
        drop(p);
        let mut e = f.expected();
        e.mutations.grant_policy = true;
        e.grant = GrantExpected::Record {
            owner,
            serial: 1,
            revision: 2,
            revoked: true,
            package: Slot::A,
            object: Object::Notes,
            action,
        };
        f.inspect(&before, e).unwrap();
        let mut store = Store::open(f.device(96), 1).unwrap_or_else(|r| panic!("{:?}", r.error));
        execute(
            &mut store,
            Request::WriteMutable {
                object: ObjectId::user_data(),
                bytes: &active,
            },
        );
        let after = f.bytes.borrow().clone();
        let mut e = f.expected();
        e.mutations.grant_policy = true;
        e.grant = GrantExpected::Record {
            owner,
            serial: 1,
            revision: 1,
            revoked: false,
            package: Slot::A,
            object: Object::Notes,
            action,
        };
        assert!(f.inspect(&before, e).is_err());
        assert_eq!(*f.bytes.borrow(), after);
    }
}
