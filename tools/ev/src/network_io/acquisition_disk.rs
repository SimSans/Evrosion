//! Read-only captured-disk verifier. Local authenticated bytes are not fresh
//! remote authorization, image execution, selection ACK, health or KnownGood.
use crate::build::Result;
use ev_app_registry::{Policy, Registry, app_data::AppDataEnvelope, note_data::NoteDataEnvelope};
use ev_content_store::{Area, Arena, Backend, Object, TransferCut};
use ev_root_supervisor::{
    native_acquisition as acq,
    native_package_profile::KnownContracts as Contracts,
    native_plan::{Packages, Slot},
};
use ev_store::{ObjectId, Sector, SectorIo, Store, native::Region};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const BYTES: usize = 4 * 1024 * 1024;
const CUT: u64 = 1 << 20;

#[derive(Clone, Copy)]
pub(crate) struct Saved<'a> {
    pub note: &'a str,
    pub note_counter: u64,
    pub value: u32,
    pub data_counter: u64,
}
#[derive(Clone, Copy)]
pub(crate) struct Release<'a> {
    pub root: &'a [u8],
    pub targets: &'a [u8],
    pub snapshot: &'a [u8],
    pub timestamp: &'a [u8],
    pub artifact: &'a [u8],
}
#[derive(Clone, Copy)]
pub(crate) struct Expected<'a> {
    pub registry_revision: u64,
    pub registry_active: [u8; 32],
    pub registry_staged: Option<[u8; 32]>,
    pub registry_previous: Option<[u8; 32]>,
    pub trust_active: Option<u64>,
    pub known_good: Option<u64>,
    pub saved: Saved<'a>,
}
#[derive(PartialEq, Eq)]
struct Binding {
    store: acq::AuthorizationBinding,
    replay: [u8; 1024],
    revision: u64,
    candidate: acq::Content,
    active: Option<acq::Content>,
    known_good: Option<acq::Content>,
}
pub(crate) struct Online {
    pub proof: Value,
    binding: Binding,
}
impl Online {
    pub(crate) fn replay(&self) -> [u8; 1024] {
        self.binding.replay
    }
}
struct Media<'a> {
    bytes: &'a [u8],
    reads: u64,
    writes: u64,
}
struct Device<'a, 'b> {
    owner: &'a mut Media<'b>,
    first: u64,
    count: u64,
}
impl<'b> Media<'b> {
    fn region<'a>(&'a mut self, region: Region) -> Device<'a, 'b> {
        Device {
            owner: self,
            first: region.physical_start() as u64,
            count: ev_store::REQUIRED_SECTORS,
        }
    }
}
impl<'b> Backend for Media<'b> {
    type Error = &'static str;
    type Device<'a>
        = Device<'a, 'b>
    where
        Self: 'a;
    fn device(&mut self, area: Area) -> Self::Device<'_> {
        let (first, count) = match area {
            Area::Checkpoint => (
                ev_content_store::CHECKPOINT_PHYSICAL_START,
                ev_store::REQUIRED_SECTORS,
            ),
            Area::Objects => (
                ev_content_store::OBJECT_PHYSICAL_START,
                ev_content_store::OBJECT_SECTORS,
            ),
        };
        Device {
            owner: self,
            first,
            count,
        }
    }
    fn has_unresolved_io(&self) -> bool {
        false
    }
}
impl SectorIo for Device<'_, '_> {
    type Error = &'static str;
    fn sectors(&self) -> u64 {
        self.count
    }
    fn read(
        &mut self,
        lba: u64,
        out: &mut Sector,
        cut: u64,
    ) -> core::result::Result<(), Self::Error> {
        if lba >= self.count || cut == 0 || cut == u64::MAX {
            return Err("readonly acquisition bounds/cut");
        }
        let start = usize::try_from((self.first + lba) * 512).map_err(|_| "readonly offset")?;
        out.copy_from_slice(
            self.owner
                .bytes
                .get(start..start + 512)
                .ok_or("readonly disk extent")?,
        );
        self.owner.reads += 1;
        Ok(())
    }
    fn write(&mut self, _: u64, _: &Sector, _: u64) -> core::result::Result<(), Self::Error> {
        self.owner.writes += 1;
        Err("readonly acquisition rejects write/repair")
    }
    fn flush(&mut self, _: u64) -> core::result::Result<(), Self::Error> {
        self.owner.writes += 1;
        Err("readonly acquisition rejects flush/repair")
    }
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn shape(bytes: &[u8]) -> Result<()> {
    if bytes.len() != BYTES {
        return Err("acquisition audit requires exact4MiB disk".into());
    }
    Ok(())
}
fn content_sector(sector: usize) -> bool {
    (128..142).contains(&sector) || (256..8192).contains(&sector)
}
fn region_sector(sector: usize, region: Region) -> bool {
    let first = region.physical_start() as usize;
    (first..first + ev_store::REQUIRED_SECTORS as usize).contains(&sector)
}
fn changes(before: &[u8], after: &[u8], allowed: impl Fn(usize) -> bool) -> Result<Vec<usize>> {
    shape(before)?;
    shape(after)?;
    let mut changed = Vec::new();
    for (sector, (a, b)) in before
        .as_chunks::<512>()
        .0
        .iter()
        .zip(after.as_chunks::<512>().0.iter())
        .enumerate()
    {
        if a != b {
            if !allowed(sector) {
                return Err(format!("acquisition changed unrelated sector {sector}"));
            }
            changed.push(sector);
        }
    }
    Ok(changed)
}
fn open_region<'a, 'b>(
    media: &'a mut Media<'b>,
    banks: &Packages<'_>,
    region: Region,
) -> Result<Store<Device<'a, 'b>>> {
    let creation = if region == Region::SessionNote {
        banks.note_format_manifest()
    } else {
        banks.format_manifest(region)
    };
    let store =
        Store::open_mutable_namespace(media.region(region), &creation, CUT).map_err(|r| {
            format!(
                "readonly acquisition {region:?} original creation/open: {:?}",
                r.error
            )
        })?;
    Ok(store)
}
/// Exact original immutable namespaces, separately bound to one current mode.
/// This cannot supply a System admission or substitute current package sources.
pub(crate) struct NamespaceCreation {
    original_catalogue: [u8; 32],
    current_catalogue: [u8; 32],
    manifests: [ev_store::GenerationManifest; 3],
}
impl NamespaceCreation {
    pub(crate) fn checked(original: &Packages<'_>, current: &Packages<'_>) -> Result<Self> {
        use ev_userspace_contract::root_v4::catalogue::{
            BOOT_MODE_OFFSET, BootMode, MEASUREMENT_OFFSET,
        };
        if !original.is_network()
            || !current.is_network()
            || original
                .catalogue()
                .network()
                .is_none_or(|c| c.boot_mode() != BootMode::Standalone)
        {
            return Err("namespace creation requires actual original V4 Standalone context".into());
        }
        let a = original.catalogue().bytes();
        let b = current.catalogue().bytes();
        // Both Packages were independently verified. Only these measured mode
        // fields may differ; use the original bytes without normalizing them.
        if a.len() != b.len()
            || a.iter().zip(b).enumerate().any(|(i, (a, b))| {
                !(MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + 32).contains(&i)
                    && !(BOOT_MODE_OFFSET..BOOT_MODE_OFFSET + 2).contains(&i)
                    && a != b
            })
        {
            return Err("original/current namespace source, App, ABI or cohort differs".into());
        }
        Ok(Self {
            original_catalogue: hash(a),
            current_catalogue: hash(b),
            manifests: [
                original.format_manifest(Region::AppRegistry),
                original.format_manifest(Region::AppData),
                original.note_format_manifest(),
            ],
        })
    }
    fn check_current(&self, current: &Packages<'_>) -> Result<()> {
        if hash(current.catalogue().bytes()) != self.current_catalogue {
            return Err("namespace creation bound to another actual current mode".into());
        }
        Ok(())
    }
    fn proof(&self) -> Value {
        json!({"original_catalogue_sha256":hex(&self.original_catalogue),
            "current_catalogue_sha256":hex(&self.current_catalogue),
            "exact_original_creation_checked":true,"current_System_authority_claim":false})
    }
}
fn open_original_region<'a, 'b>(
    media: &'a mut Media<'b>,
    creation: &NamespaceCreation,
    region: Region,
) -> Result<Store<Device<'a, 'b>>> {
    let index = match region {
        Region::AppRegistry => 0,
        Region::AppData => 1,
        Region::SessionNote => 2,
        _ => return Err("namespace creation cannot supply System or Grant policy".into()),
    };
    Store::open_mutable_namespace(media.region(region), &creation.manifests[index], CUT).map_err(
        |r| {
            format!(
                "readonly acquisition {region:?} original creation/open: {:?}",
                r.error
            )
        },
    )
}
fn body<D: SectorIo>(store: &mut Store<D>) -> Result<[u8; 256]>
where
    D::Error: core::fmt::Debug,
{
    let mut bytes = [0; 256];
    if store
        .read_mutable(ObjectId::user_data(), &mut bytes, CUT)
        .map_err(|e| format!("readonly mutable read: {e:?}"))?
        != 256
    {
        return Err("acquisition mutable payload extent differs".into());
    }
    Ok(bytes)
}
struct Lookup<'a, 'b> {
    banks: &'a Packages<'b>,
    artifact: Option<&'a [u8]>,
}
impl ev_app_registry::Packages for Lookup<'_, '_> {
    fn resolve(&self, digest: [u8; 32]) -> Option<&[u8]> {
        self.banks
            .slot(digest)
            .map(|s| self.banks.bytes(s))
            .or_else(|| self.artifact.filter(|b| hash(b) == digest))
    }
}
fn selected_state(
    bytes: &[u8],
    banks: &Packages<'_>,
    artifact: Option<&[u8]>,
    expected: Expected<'_>,
) -> Result<Value> {
    if !banks.is_network()
        || expected.registry_revision == 0
        || expected.registry_revision == u64::MAX
        || expected.saved.note.is_empty()
        || expected.saved.note_counter == 0
    {
        return Err("acquisition expected selected/saved context invalid".into());
    }
    let mut media = Media {
        bytes,
        reads: 0,
        writes: 0,
    };
    let mut registry_store = open_region(&mut media, banks, Region::AppRegistry)?;
    let registry_bytes = body(&mut registry_store)?;
    let record = ev_zion::lifecycle::Record::decode(&registry_bytes)
        .map_err(|e| format!("actual acquisition registry: {e:?}"))?;
    if !record.installed()
        || record.app() != banks.app()
        || record.revision() != expected.registry_revision
        || record.data_epoch() != 1
        || record.active().map(|r| r.digest()) != Some(expected.registry_active)
        || record.staged().map(|r| r.digest()) != expected.registry_staged
        || record.previous().map(|r| r.digest()) != expected.registry_previous
        || registry_store
            .next_operation()
            .map_err(|e| format!("registry operation: {e:?}"))?
            .get()
            != expected.registry_revision + 1
    {
        return Err(
            "actual Registry selection/revision differs from explicit expected phase".into(),
        );
    }
    let device = registry_store.into_device();
    let lookup = Lookup { banks, artifact };
    let registry = Registry::open(
        device,
        Policy {
            app: banks.app(),
            abi: ev_userspace_contract::ABI,
            platform: 1,
        },
        &lookup,
        &Contracts,
        CUT,
    )
    .map_err(|r| {
        format!(
            "actual immutable package Registry resolution: {:?}",
            r.error
        )
    })?;
    let (device, _, pending) = registry.into_parts();
    if pending.is_some() {
        return Err("readonly Registry retained pending publication".into());
    }
    let _ = device;
    let mut data_store = open_region(&mut media, banks, Region::AppData)?;
    let data_bytes = body(&mut data_store)?;
    let data = AppDataEnvelope::decode(&data_bytes)
        .map_err(|e| format!("actual scalar envelope: {e:?}"))?;
    if data.app() != banks.app()
        || data.schema_epoch() != 1
        || data.value() != expected.saved.value
        || data.counter() != expected.saved.data_counter
        || data_store
            .next_operation()
            .map_err(|e| format!("scalar operation: {e:?}"))?
            .get()
            != expected
                .saved
                .data_counter
                .checked_add(1)
                .ok_or("scalar counter overflow")?
    {
        return Err("acquisition changed saved scalar identity/value/counter".into());
    }
    let _ = data_store;
    let mut note_store = open_region(&mut media, banks, Region::SessionNote)?;
    let note_bytes = body(&mut note_store)?;
    let note = NoteDataEnvelope::decode(&note_bytes)
        .map_err(|e| format!("actual note envelope: {e:?}"))?;
    if note.app() != banks.app()
        || note.note() != expected.saved.note
        || note.counter() != expected.saved.note_counter
        || note_store
            .next_operation()
            .map_err(|e| format!("note operation: {e:?}"))?
            .get()
            != expected
                .saved
                .note_counter
                .checked_add(1)
                .ok_or("note counter overflow")?
    {
        return Err("acquisition changed saved Note identity/text/counter".into());
    }
    let _ = note_store;
    if media.writes != 0 {
        return Err("acquisition observer attempted repair/write".into());
    }
    Ok(
        json!({"registry_revision":record.revision(),"active":hex(&expected.registry_active),"staged":expected.registry_staged.map(|v|hex(&v)),"previous":expected.registry_previous.map(|v|hex(&v)),"data_value":data.value(),"data_counter":data.counter(),"note":note.note(),"note_counter":note.counter(),"reads":media.reads,"observer_mutations":media.writes}),
    )
}
pub(crate) fn setup(
    seed: &[u8],
    baseline: &[u8],
    banks: &Packages<'_>,
    saved: Saved<'_>,
) -> Result<Value> {
    let changed = changes(seed, baseline, |s| {
        [Region::AppRegistry, Region::AppData, Region::SessionNote]
            .into_iter()
            .any(|r| region_sector(s, r))
    })?;
    for region in [Region::AppRegistry, Region::AppData, Region::SessionNote] {
        let start = region.physical_start() as usize * 512;
        if seed[start..start + 14 * 512].iter().any(|b| *b != 0) {
            return Err("setup namespace was not entirely blank in actual seed".into());
        }
    }
    let state = selected_state(
        baseline,
        banks,
        None,
        Expected {
            registry_revision: 2,
            registry_active: banks.digest(Slot::A),
            registry_staged: None,
            registry_previous: None,
            trust_active: None,
            known_good: None,
            saved,
        },
    )?;
    Ok(
        json!({"schema":1,"kind":"readonly-acquisition-setup","state":state,"changed_sectors":changed,"all_other_bytes_unchanged":true,"seed_sha256":hex(&hash(seed)),"baseline_sha256":hex(&hash(baseline))}),
    )
}
fn object_json(object: Object) -> Value {
    json!({"start":object.start(),"sectors":object.sectors(),"length":object.length(),"sha256":hex(&object.sha256())})
}
fn package_identity(bytes: &[u8], content: acq::Content) -> Result<Value> {
    let package = ev_zion::Package::parse(bytes)
        .map_err(|e| format!("actual downloaded Zion container: {e:?}"))?;
    package
        .check_requirements(1, ev_userspace_contract::ABI, &Contracts)
        .map_err(|e| format!("actual downloaded requirements: {e:?}"))?;
    let app = package.app();
    let mut descriptor = Sha256::new();
    ev_userspace_contract::root_v4::dynamic::app_descriptor_transcript(
        &package.executable().digest,
        |b| descriptor.update(b),
    );
    let descriptor: [u8; 32] = descriptor.finalize().into();
    if package.id().bytes() != content.package
        || app.claimed_app.bytes() != content.app
        || app.build_id != content.build
        || app.abi != ev_userspace_contract::ABI
        || app.data_schema.current != 1
        || app.data_schema.oldest_readable != 1
        || !ev_root_supervisor::native_package_profile::downloaded(app)
        || app.version.patch != 1
        || app.developer_source != format!("Evrosion DEV B {}", hex(&content.source))
        || descriptor != content.descriptor
    {
        return Err(
            "actual downloaded source/build/ABI/App7/schema/contracts differ from signed content"
                .into(),
        );
    }
    Ok(
        json!({"app_id":hex(&content.app),"package_id":hex(&content.package),
        "build_id":hex(&content.build),"source_sha256":hex(&content.source),
        "descriptor_sha256":hex(&content.descriptor),"elf_sha256":hex(&package.executable().digest),
        "global_abi":hex(&app.abi),"data_schema":1,"note_schema":2,"roles":7}),
    )
}
fn read_exact<'a>(
    store: acq::Store<Media<'a>>,
    object: Object,
    wanted: &[u8],
    transfer: TransferCut,
) -> Result<(acq::Store<Media<'a>>, Value)> {
    if wanted.is_empty()
        || wanted.len() as u64 != object.length()
        || hash(wanted) != object.sha256()
    {
        return Err("public release body differs from actual stored reference".into());
    }
    let mut read = store
        .begin_read(object, transfer, 1)
        .map_err(|_| "readonly content read refused")?;
    let mut chunk = [0; 4096];
    let mut at = 0;
    while read.remaining() != 0 {
        let n = read
            .read_chunk(&mut chunk, 1)
            .map_err(|_| "readonly object full read/hash failed")?;
        if n == 0 || wanted.get(at..at + n) != Some(&chunk[..n]) {
            return Err("stored release bytes differ from actual public fixture".into());
        }
        at += n;
    }
    let stored = read
        .finish()
        .map_err(|_| "readonly object final hash/padding failed")?;
    if at != wanted.len() || stored.object != object {
        return Err("stored release object identity/read length differs".into());
    }
    Ok((stored.store, object_json(object)))
}
fn authenticated(
    bytes: &[u8],
    banks: &Packages<'_>,
    release: Release<'_>,
    expected: Expected<'_>,
) -> Result<(Binding, Value)> {
    shape(bytes)?;
    if !banks.is_network()
        || release.root.len() > acq::ROOT_BUFFER
        || release.targets.len() > acq::TARGET_BUFFER
        || release.snapshot.len() > acq::LINK_BUFFER
        || release.timestamp.len() > acq::LINK_BUFFER
        || release.artifact.len() > ev_content_store::MAX_OBJECT_BYTES as usize
    {
        return Err("public release/profile exceeds exact bounded shapes".into());
    }
    let transfer = TransferCut::new(1, CUT).map_err(|_| "audit transfer")?;
    let arena = Arena::open(
        Media {
            bytes,
            reads: 0,
            writes: 0,
        },
        ev_root_supervisor::native_update::creation_manifest(),
        transfer.metadata(1).unwrap(),
    )
    .map_err(|_| "actual content namespace cannot open read-only")?;
    let mut cold = acq::Store::from_arena(arena)
        .begin_cold(transfer, 1)
        .map_err(|_| "actual content checkpoint cannot cold open")?;
    let mut buffers = acq::Buffers::empty();
    let mut done = false;
    // Synthetic IO cuts only: a captured-disk audit has no runtime clock or
    // qualified UTC. Keep one nonregressing observation across all readbacks.
    for _ in 0..16384 {
        if cold
            .step(&mut buffers, 1)
            .map_err(|_| "actual checkpoint/root/metadata/artifact cold verification failed")?
        {
            done = true;
            break;
        }
    }
    if !done {
        return Err("actual cold authentication exceeded bounded steps".into());
    }
    let mut store = cold
        .finish()
        .map_err(|_| "actual cold owner finish failed")?;
    let state = store.snapshot().ok_or("authenticated snapshot absent")?;
    let candidate = state.candidate().ok_or("actual fetched candidate absent")?;
    let mut replay = [0; 1024];
    ev_release_trust::checkpoint::encode(state.replay(), &mut replay);
    let binding = Binding {
        store: store
            .authorization_binding()
            .ok_or("actual authenticated Store binding absent")?,
        replay,
        revision: state.revision(),
        candidate,
        active: state.active(),
        known_good: state.known_good(),
    };
    if candidate.version != 2
        || candidate.app != banks.app().bytes()
        || candidate.package != hash(release.artifact)
        || candidate.object.sha256() != candidate.package
        || banks.slot(candidate.package).is_some()
        || binding.active.map(|c| c.version) != expected.trust_active
        || binding.known_good.map(|c| c.version) != expected.known_good
        || binding.active.is_some_and(|c| c != candidate)
        || binding.known_good.is_some_and(|c| c != candidate)
        || state.replay().utc_floor() == 0
    {
        return Err(
            "actual candidate/selection/floor differs from explicit acquisition phase".into(),
        );
    }
    let root = state
        .current_root_object()
        .ok_or("current continuity Root absent")?;
    let metadata = core::array::from_fn::<_, 3, _>(|i| state.metadata_object(i));
    let floor = state.replay().utc_floor();
    let package = package_identity(release.artifact, candidate)?;
    let mut objects = Vec::new();
    for (object, wanted) in [
        (Some(root), release.root),
        (metadata[0], release.targets),
        (metadata[1], release.snapshot),
        (metadata[2], release.timestamp),
        (Some(candidate.object), release.artifact),
    ] {
        let (next, report) = read_exact(
            store,
            object.ok_or("actual metadata reference absent")?,
            wanted,
            transfer,
        )?;
        store = next;
        objects.push(report);
    }
    if store.authorization_binding() != Some(binding.store) {
        return Err("readonly audit changed authenticated head".into());
    }
    let arena = store.into_arena();
    let checkpoint = object_json(
        arena
            .published_metadata()
            .ok_or("published checkpoint absent")?,
    );
    let head = hex(&arena.head_digest());
    let media = arena.into_backend();
    if media.writes != 0 {
        return Err("cold acquisition audit attempted write/flush".into());
    }
    let selected = selected_state(bytes, banks, Some(release.artifact), expected)?;
    let revision = binding.revision;
    Ok((
        binding,
        json!({"revision":revision,"utc_floor":floor,"candidate_version":2,"active_version":expected.trust_active,"known_good_version":expected.known_good,"replay_checkpoint_hex":hex(&replay),"replay_checkpoint_sha256":hex(&hash(&replay)),"checkpoint":checkpoint,"checkpoint_head_sha256":head,"objects":objects,"package":package,"state":selected,"content_reads":media.reads,"observer_mutations":media.writes}),
    ))
}
pub(crate) fn online(
    baseline: &[u8],
    after: &[u8],
    banks: &Packages<'_>,
    release: Release<'_>,
    expected: Expected<'_>,
) -> Result<Online> {
    let changed = changes(baseline, after, |s| {
        content_sector(s) || region_sector(s, Region::AppRegistry)
    })?;
    if changed.is_empty() || !changed.iter().any(|s| content_sector(*s)) {
        return Err("online acquisition did not publish actual content bytes".into());
    }
    let (binding, state) = authenticated(after, banks, release, expected)?;
    Ok(Online {
        proof: json!({"schema":1,"kind":"readonly-online-acquisition","authenticated":state,"changed_sectors":changed,"all_unrelated_bytes_unchanged":true,"baseline_sha256":hex(&hash(baseline)),"disk_sha256":hex(&hash(after)),"fresh_remote_or_UTC_authority_claim":false,"App_execution_or_health_claim":false}),
        binding,
    })
}
pub(crate) fn cold(
    online_disk: &[u8],
    cold_disk: &[u8],
    banks: &Packages<'_>,
    release: Release<'_>,
    expected: Expected<'_>,
    online: &Online,
) -> Result<Value> {
    shape(online_disk)?;
    shape(cold_disk)?;
    if online_disk != cold_disk {
        return Err("offline cold boot changed captured whole disk".into());
    }
    let (binding, state) = authenticated(cold_disk, banks, release, expected)?;
    if binding != online.binding {
        return Err("cold replay/head/content/selection differs from retained online state".into());
    }
    Ok(
        json!({"schema":1,"kind":"readonly-offline-cold-acquisition","authenticated":state,"entire_disk_unchanged":true,"all_replay_floors_and_references_preserved":true,"disk_sha256":hex(&hash(cold_disk)),"fresh_remote_or_UTC_authority_claim":false,"App_execution_or_health_claim":false}),
    )
}

pub(crate) mod system_health;

#[cfg(test)]
mod tests;

/// Read-only saved data check shared by the explicit UI qualification driver.
pub(crate) fn saved_state(
    bytes: &[u8],
    banks: &Packages<'_>,
    expected: Saved<'_>,
) -> Result<Value> {
    shape(bytes)?;
    let mut media = Media {
        bytes,
        reads: 0,
        writes: 0,
    };
    let data = AppDataEnvelope::decode(&body(&mut open_region(
        &mut media,
        banks,
        Region::AppData,
    )?)?)
    .map_err(|_| "owner UI scalar decode")?;
    let note = NoteDataEnvelope::decode(&body(&mut open_region(
        &mut media,
        banks,
        Region::SessionNote,
    )?)?)
    .map_err(|_| "owner UI note decode")?;
    if data.app() != banks.app()
        || data.value() != expected.value
        || data.counter() != expected.data_counter
        || note.app() != banks.app()
        || note.note() != expected.note
        || note.counter() != expected.note_counter
        || media.writes != 0
    {
        return Err("owner UI saved data/counter association differs".into());
    }
    Ok(
        json!({"note":note.note(),"note_counter":note.counter(),"value":data.value(),"data_counter":data.counter(),"observer_mutations":media.writes}),
    )
}

/// Namespace-only cross-mode saved data audit; current identity remains explicit.
pub(crate) fn saved_state_with_creation(
    bytes: &[u8],
    banks: &Packages<'_>,
    creation: &NamespaceCreation,
    expected: Saved<'_>,
) -> Result<Value> {
    shape(bytes)?;
    creation.check_current(banks)?;
    let mut media = Media {
        bytes,
        reads: 0,
        writes: 0,
    };
    let data = AppDataEnvelope::decode(&body(&mut open_original_region(
        &mut media,
        creation,
        Region::AppData,
    )?)?)
    .map_err(|_| "owner UI scalar decode")?;
    let note = NoteDataEnvelope::decode(&body(&mut open_original_region(
        &mut media,
        creation,
        Region::SessionNote,
    )?)?)
    .map_err(|_| "owner UI note decode")?;
    if data.app() != banks.app()
        || data.value() != expected.value
        || data.counter() != expected.data_counter
        || note.app() != banks.app()
        || note.note() != expected.note
        || note.counter() != expected.note_counter
        || media.writes != 0
    {
        return Err("owner UI saved data/counter association differs".into());
    }
    Ok(
        json!({"note":note.note(),"note_counter":note.counter(),"value":data.value(),
        "data_counter":data.counter(),"observer_mutations":media.writes,"namespace_creation":creation.proof()}),
    )
}
