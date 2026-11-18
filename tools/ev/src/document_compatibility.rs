//! Read-only provenance for the actual accepted saved0.2 volume. The only
//! writable object this module creates is a NEW runner-owned byte-for-byte
//! clone. Existing Store namespaces and immutable package checks stay intact.
use crate::{
    build::{self, Manifest, Result},
    network_io::components::Context,
    network_mode::Mode,
    storage,
};
use ev_app_registry::{app_data::AppDataEnvelope, note_data::NoteDataEnvelope};
use ev_store::{GenerationManifest, ObjectId, Sector, SectorIo, Store, native::Region};
use ev_zion::lifecycle::Record;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub(crate) const LEGACY_SOURCE: &str =
    "6ea4596434c178a379b74fc402f718c44e37559592b14714161ad83e3f5c8437";
pub(crate) const LEGACY_VOLUME: &str =
    "3607de397ba89439af03a8775a0ac3c67636cf6cbb4b747aa712fa1fdf0d3eb2";
pub(crate) const LEGACY_PACKAGE: &str =
    "a295bc75b9ee0b7f186a4d716a668a8c9d3e2de16151aadecbe839dbd218fc71";
const SNAPSHOT: &str =
    "build/m6/evidence/network-session-3235206-1794738805954806850/data-after.raw";
const MANIFEST: &str = "build/m6/network-session/boot-set/m6-network-owner/manifest.json";
const DEADLINE: u64 = 1;

/// Exact complete historical backing for the new V4 catalogue's retained bankA.
/// Return ELF, then Zion bytes. The caller still binds/admit these measurements
/// through the ordinary catalogue and actual executable owner.
pub(crate) fn load_legacy_a(root: &Path) -> Result<(Vec<u8>, Vec<u8>)> {
    let image = regular(
        root,
        Path::new("tools/m7/fixtures/legacy-02-app-a.elf"),
        2 * 1024 * 1024,
    )?;
    let container = regular(
        root,
        Path::new("tools/m7/fixtures/legacy-02-Hello-A.zion"),
        2 * 1024 * 1024,
    )?;
    if hash(&image) != "b518bd4eb7d5cfd057f55d86d06a82f3d62d7d6a9a58b9d475e2bcc35ff34f3e"
        || hash(&container) != LEGACY_PACKAGE
    {
        return Err("retained qualified0.2 immutable bankA bytes changed".into());
    }
    let parsed = ev_zion::Package::parse(&container)
        .map_err(|e| format!("retained qualified0.2 bankA: {e:?}"))?;
    parsed
        .check_requirements(
            1,
            ev_userspace_contract::ABI,
            &crate::native_package::NativePlatformContracts,
        )
        .map_err(|e| format!("retained qualified0.2 bankA compatibility: {e:?}"))?;
    if parsed.executable().bytes != image
        || parsed.app().claimed_app.bytes() != crate::native_package::HELLO_APP_ID
        || crate::native_package::network_hello(&image, [1; 32])?.bytes != container
    {
        return Err("retained qualified0.2 bankA full package/executable/roles differ".into());
    }
    Ok((image, container))
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn regular(root: &Path, relative: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut path = root.to_owned();
    for part in relative.components() {
        if !matches!(part, std::path::Component::Normal(_)) {
            return Err("saved0.2 input path must be canonical and relative".into());
        }
        path.push(part);
        if fs::symlink_metadata(&path)
            .map_err(|e| e.to_string())?
            .file_type()
            .is_symlink()
        {
            return Err("saved0.2 input refuses symlink ancestry".into());
        }
    }
    let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > limit {
        return Err("saved0.2 input type or bounded extent differs".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() != 1 {
            return Err("saved0.2 input refuses external hard links".into());
        }
    }
    let bytes = fs::read(&path).map_err(|e| e.to_string())?;
    if bytes.is_empty() || bytes.len() as u64 > limit {
        return Err("saved0.2 input changed extent during read".into());
    }
    Ok(bytes)
}

/// Original immutable creator/catalogue context, not a current System cohort.
pub(crate) struct Origin {
    root: PathBuf,
    bytes: Vec<u8>,
    context: Context,
    manifest_hash: String,
    persistent_hash: String,
}
impl Origin {
    /// The caller supplies the retained exact accepted manual-host workspace,
    /// never a personal/physical disk. All origin paths below are fixed outputs.
    pub(crate) fn retain(legacy_root: &Path, evidence: &Path) -> Result<Self> {
        let root = legacy_root.canonicalize().map_err(|e| e.to_string())?;
        let raw_manifest = regular(&root, Path::new(MANIFEST), 2 * 1024 * 1024)?;
        let manifest: Manifest =
            serde_json::from_slice(&raw_manifest).map_err(|e| e.to_string())?;
        manifest.validate_policy_rows()?;
        if manifest.source_sha256 != LEGACY_SOURCE
            || manifest.fixture.as_deref() != Some(Mode::Standalone.owner_fixture())
        {
            return Err("saved0.2 original source/owner fixture differs from accepted pin".into());
        }
        let (source, inputs) = build::source_inputs(&root)?;
        if source != LEGACY_SOURCE || inputs != manifest.source_inputs {
            return Err("saved0.2 original compilation inputs changed".into());
        }
        for artifact in [
            &manifest.kernel,
            &manifest.image,
            &manifest.loader,
            &manifest.image_builder,
        ]
        .into_iter()
        .chain(manifest.supervisor.iter())
        {
            build::verify_artifact(&root.join("build/m0"), artifact)?;
        }
        let bytes = regular(&root, Path::new(SNAPSHOT), storage::DISK_BYTES as u64)?;
        if bytes.len() != storage::DISK_BYTES || hash(&bytes) != LEGACY_VOLUME {
            return Err(
                "saved0.2 original cold snapshot differs from actual accepted s02 bytes".into(),
            );
        }
        let retained = storage::directory_beneath(evidence, Path::new("legacy-origin"))?;
        storage::immutable_new(&retained.join("manifest.json"), &raw_manifest)?;
        storage::immutable_new(&retained.join("saved02-before.raw"), &bytes)?;
        let context = Context::retain_mode(&root, &manifest, &retained, Mode::Standalone, true)?;
        let persistent_hash = hash(&regular(
            &root,
            Path::new("build/m6/network-session/data.raw"),
            storage::DISK_BYTES as u64,
        )?);
        let result = Self {
            root,
            bytes,
            context,
            manifest_hash: hash(&raw_manifest),
            persistent_hash,
        };
        let packages = result.context.packages()?;
        if hash(packages.bytes(ev_root_supervisor::native_plan::Slot::A)) != LEGACY_PACKAGE {
            return Err("saved0.2 original exact complete bankA differs".into());
        }
        let (record, registry_proof) = result.registry(&result.bytes)?;
        if record.revision() != 2
            || !record.installed()
            || record.data_epoch() != 1
            || record.active().map(|v| hex(v.digest())).as_deref() != Some(LEGACY_PACKAGE)
            || record.previous().is_some()
            || record.staged().is_some()
        {
            return Err(
                "saved0.2 original registry differs from actual accepted graphical launch".into(),
            );
        }
        // This open resolves all original references using full original packages.
        let registry = ev_app_registry::Registry::open(
            ReadOnly::new(&result.bytes, Region::AppRegistry)?,
            ev_app_registry::Policy {
                app: packages.app(),
                abi: ev_userspace_contract::ABI,
                platform: 1,
            },
            &packages,
            &ev_root_supervisor::native_plan::Contracts,
            DEADLINE,
        )
        .map_err(|r| format!("saved0.2 exact original package resolution: {:?}", r.error))?;
        let (device, _, pending) = registry.into_parts();
        if pending.is_some() {
            return Err("saved0.2 readonly registry unexpectedly has pending publication".into());
        }
        let resolution = device.proof()?;
        let private = result.saved_data(&result.bytes)?;
        let files = crate::native3_disk::document(&result.bytes, 0, ev_file::desktop::SEED_NOTES)?;
        storage::json_new(
            &retained.join("origin.json"),
            &json!({
                "schema":1, "source_sha256":LEGACY_SOURCE, "volume_sha256":LEGACY_VOLUME,
                "origin_root":result.root, "origin_manifest_sha256":result.manifest_hash,
                "origin_snapshot":SNAPSHOT, "complete_legacy_package":LEGACY_PACKAGE,
            "original_persistent_volume_sha256":result.persistent_hash,
                "registry":registry_proof, "original_package_resolution":resolution,
                "private_data":private, "files":files,
                "observer":"read-only actual Store opens; every write/flush rejects; exact original immutable namespace manifests and full packages",
                "scope":"Original accepted0.2 saved data/provenance only. No new runtime compatibility claimed by preflight."
            }),
        )?;
        Ok(result)
    }
    /// Ordinary supported snapshot import into one NEW owned file. This never
    /// opens the historical disk writable or changes a raw namespace.
    pub(crate) fn clone_disk(&self, root: &Path, evidence: &Path) -> Result<storage::Disk> {
        let mut disk = storage::Disk::create(root, evidence)?;
        disk.restore_snapshot(&self.bytes)?;
        if disk.bytes()? != self.bytes {
            return Err("saved0.2 clone changed bytes".into());
        }
        storage::json_new(
            &evidence.join("clone-provenance.json"),
            &json!({
                "schema":1, "original_sha256":LEGACY_VOLUME, "clone_initial_sha256":LEGACY_VOLUME,
                "original_snapshot":self.root.join(SNAPSHOT), "copy_only":true,
                "format_reset_migration_or_raw_namespace_surgery":false,
                "method":"Complete original saved0.2 snapshot restored once into a NEW runner-owned disk before its first VM; original remains untouched"
            }),
        )?;
        Ok(disk)
    }
    pub(crate) fn baseline(&self) -> &[u8] {
        &self.bytes
    }
    /// Independently open the exact historical creator namespaces after actual
    /// newer runtime use. The App/scalar/note identity and counters stay exact.
    pub(crate) fn saved_data(&self, bytes: &[u8]) -> Result<Value> {
        let packages = self.context.packages()?;
        let (body, scalar) = payload(
            bytes,
            Region::AppData,
            packages.format_manifest(Region::AppData),
            0,
        )?;
        let data = AppDataEnvelope::decode(&body)
            .map_err(|e| format!("saved0.2 scalar envelope: {e:?}"))?;
        if data.app() != packages.app()
            || data.schema_epoch() != 1
            || data.counter() != 0
            || data.value() != 1001
        {
            return Err("saved0.2 scalar identity/schema/counter/value changed".into());
        }
        let (body, note_proof) = payload(
            bytes,
            Region::SessionNote,
            packages.note_format_manifest(),
            1,
        )?;
        let note = NoteDataEnvelope::decode(&body)
            .map_err(|e| format!("saved0.2 private Note envelope: {e:?}"))?;
        if note.app() != packages.app()
            || note.schema_epoch() != 2
            || note.counter() != 1
            || note.note() != "s02"
        {
            return Err("saved0.2 private Note identity/schema/revision/content changed".into());
        }
        Ok(
            json!({"scalar":scalar,"scalar_schema":1,"scalar_counter":0,"scalar_value":1001,
            "note":note_proof,"note_schema":2,"note_counter":1,"note_payload_sha256":hash(b"s02"),"exact_saved02_private_data":true}),
        )
    }
    /// Registry mutation is observed separately from independent saved bytes.
    /// Exact current full-package resolution remains the runtime's responsibility.
    pub(crate) fn registry(&self, bytes: &[u8]) -> Result<(Record, Value)> {
        let packages = self.context.packages()?;
        let mut store = Store::open_mutable_namespace(
            ReadOnly::new(bytes, Region::AppRegistry)?,
            &packages.format_manifest(Region::AppRegistry),
            DEADLINE,
        )
        .map_err(|r| format!("saved0.2 registry original creator: {:?}", r.error))?;
        let mut body = [0; 256];
        if store
            .read_mutable(ObjectId::user_data(), &mut body, DEADLINE)
            .map_err(|e| format!("saved0.2 registry read: {e:?}"))?
            != 256
        {
            return Err("saved0.2 registry body extent".into());
        }
        let record =
            Record::decode(&body).map_err(|e| format!("saved0.2 registry envelope: {e:?}"))?;
        if record.app() != packages.app() || record.data_epoch() != 1 {
            return Err("saved0.2 registry identity/data epoch changed".into());
        }
        let operation = store
            .next_operation()
            .map_err(|e| format!("saved0.2 registry counter: {e:?}"))?
            .get()
            - 1;
        let mut proof = store.into_device().proof()?;
        proof["revision"] = json!(record.revision());
        proof["operation"] = json!(operation);
        proof["installed"] = json!(record.installed());
        proof["data_epoch"] = json!(record.data_epoch());
        proof["active"] = json!(record.active().map(|v| hex(v.digest())));
        proof["previous"] = json!(record.previous().map(|v| hex(v.digest())));
        proof["staged"] = json!(record.staged().map(|v| hex(v.digest())));
        Ok((record, proof))
    }
    pub(crate) fn check_original_untouched(&self) -> Result<()> {
        let bytes = regular(&self.root, Path::new(SNAPSHOT), storage::DISK_BYTES as u64)?;
        let manifest = regular(&self.root, Path::new(MANIFEST), 2 * 1024 * 1024)?;
        let persistent = regular(
            &self.root,
            Path::new("build/m6/network-session/data.raw"),
            storage::DISK_BYTES as u64,
        )?;
        if bytes != self.bytes
            || hash(&manifest) != self.manifest_hash
            || hash(&persistent) != self.persistent_hash
            || build::source_inputs(&self.root)?.0 != LEGACY_SOURCE
        {
            return Err(
                "historical saved0.2 snapshot/manifest changed during compatibility proof".into(),
            );
        }
        Ok(())
    }
}
fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug)]
enum Error {
    Bounds,
    Deadline,
    ReadOnly,
}
struct ReadOnly<'a> {
    bytes: &'a [u8],
    start: u32,
    reads: u64,
    mutations: u64,
}
impl<'a> ReadOnly<'a> {
    fn new(bytes: &'a [u8], region: Region) -> Result<Self> {
        if bytes.len() != storage::DISK_BYTES {
            return Err("saved0.2 readonly device requires exact4MiB snapshot".into());
        }
        Ok(Self {
            bytes,
            start: region.physical_start(),
            reads: 0,
            mutations: 0,
        })
    }
    fn proof(self) -> Result<Value> {
        if self.mutations != 0 {
            return Err("saved0.2 observer attempted write/flush/recovery".into());
        }
        let start = self.start as usize * storage::SECTOR_BYTES;
        let end = start + ev_store::REQUIRED_SECTORS as usize * storage::SECTOR_BYTES;
        Ok(
            json!({"physical_start":self.start,"sectors":ev_store::REQUIRED_SECTORS,"raw_sha256":hash(&self.bytes[start..end]),"reads":self.reads,"mutation_attempts":self.mutations}),
        )
    }
}
impl SectorIo for ReadOnly<'_> {
    type Error = Error;
    fn sectors(&self) -> u64 {
        ev_store::REQUIRED_SECTORS
    }
    fn read(
        &mut self,
        lba: u64,
        out: &mut Sector,
        deadline: u64,
    ) -> std::result::Result<(), Error> {
        if deadline != DEADLINE {
            return Err(Error::Deadline);
        }
        if lba >= self.sectors() {
            return Err(Error::Bounds);
        }
        let start = (u64::from(self.start) + lba) as usize * storage::SECTOR_BYTES;
        out.copy_from_slice(
            self.bytes
                .get(start..start + storage::SECTOR_BYTES)
                .ok_or(Error::Bounds)?,
        );
        self.reads += 1;
        Ok(())
    }
    fn write(&mut self, _: u64, _: &Sector, _: u64) -> std::result::Result<(), Error> {
        self.mutations += 1;
        Err(Error::ReadOnly)
    }
    fn flush(&mut self, _: u64) -> std::result::Result<(), Error> {
        self.mutations += 1;
        Err(Error::ReadOnly)
    }
}
fn payload(
    bytes: &[u8],
    region: Region,
    creation: GenerationManifest,
    operation: u64,
) -> Result<([u8; 256], Value)> {
    let mut store =
        Store::open_mutable_namespace(ReadOnly::new(bytes, region)?, &creation, DEADLINE)
            .map_err(|r| format!("saved0.2 {region:?} exact original creator: {:?}", r.error))?;
    if store
        .next_operation()
        .map_err(|e| format!("saved0.2 operation: {e:?}"))?
        .get()
        != operation + 1
    {
        return Err("saved0.2 private namespace operation changed".into());
    }
    let mut body = [0; 256];
    if store
        .read_mutable(ObjectId::user_data(), &mut body, DEADLINE)
        .map_err(|e| format!("saved0.2 payload: {e:?}"))?
        != 256
    {
        return Err("saved0.2 private body extent differs".into());
    }
    Ok((body, store.into_device().proof()?))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Exercise,
    Cold,
}

/// Explicit finite compatibility workload. Original pixels and protected
/// Note/Present observations join with the independently opened retained data.
#[allow(clippy::too_many_arguments)]
pub(crate) fn supervise(
    command: &mut std::process::Command,
    serial: &Path,
    errors: &Path,
    timeout: std::time::Duration,
    build: &str,
    directory: &Path,
    clock: &mut crate::vm_clock::Prepared,
    phase: Phase,
    disk: &storage::Disk,
) -> Result<std::process::ExitStatus> {
    use crate::{
        desktop_protocol::{self, Producer, StepKind},
        qmp::{Key, Qmp},
        session_reference::Reference,
    };
    use ev_graphics::{
        native::Build,
        session::{Focus as LegacyFocus, SaveState, View},
        shell::{FileChoice, Screen},
    };
    use ev_userspace_contract::document::{Access, Choice, Focus, State};
    use std::{
        io::Write,
        process::Stdio,
        time::{Duration, Instant},
    };
    let fixture = crate::network_fixture::Fixture::hello()?;
    let start = Instant::now();
    let deadline = start + timeout;
    let mut qmp: Option<Qmp> = None;
    let mut stage = 0u32;
    let mut typed = 0usize;
    let mut seen_nonce = 0;
    let mut seen_app_frame = 0;
    let mut capture = 0;
    let mut captures = Vec::new();
    let mut inputs = Vec::new();
    let mut legacy_app = None;
    let mut document_app = None;
    let mut initial = None;
    let mut read_proof = None;
    let mut saved_proof = None;
    let mut finishing = false;
    let mut finished = false;
    let mut last_finish = 0;
    let mut finish_attempts = 0;
    let result = (|| {
        let mut child = crate::boot::ChildGuard(
            command
                .stdin(Stdio::piped())
                .spawn()
                .map_err(|e| e.to_string())?,
        );
        clock.verify_and_start(&mut child.0, directory)?;
        let mut uart = child
            .0
            .stdin
            .take()
            .ok_or("compatibility owner UART absent")?;
        loop {
            if Instant::now() >= deadline {
                return Err(format!(
                    "saved0.2 compatibility deadline stage={stage} typed={typed}"
                ));
            }
            let bytes = bounded_log(serial)?;
            bounded_log(errors)?;
            if let Some(status) = child.0.try_wait().map_err(|e| e.to_string())? {
                if !finished || status.code() != Some(ev_test_protocol::QEMU_PASS_STATUS) {
                    return Err(format!(
                        "saved0.2 compatibility VM exited {status} atstage{stage}"
                    ));
                }
                let clean = crate::document_io::without_observations(&bytes, build)?;
                let record = crate::native_protocol::record_network(&clean, build)?;
                let counts = &record.counts;
                let exercise = phase == Phase::Exercise;
                if counts["faults"] != 0
                    || counts["app_a_starts"] != u64::from(exercise)
                    || counts["app_b_starts"] != 1
                    || counts["readonly_rejections"] != u64::from(exercise)
                {
                    return Err(
                        "compatibility actual App starts/faults/READ denial counts differ".into(),
                    );
                }
                crate::session_io::ProbeUi::parse(&bytes, build)?.finish()?;
                if crate::session_protocol::retention(&bytes, build)?.omitted != 0 {
                    return Err("compatibility emitted history was omitted".into());
                }
                if !crate::network_io::acquisition_hello(&fixture.snapshot()?)? {
                    return Err("compatibility local owned Hello fixture did not complete".into());
                }
                return Ok(status);
            }
            let states = crate::native_protocol::states(&bytes, build)?;
            if finishing {
                for state in states {
                    let report = state.number("report")?;
                    if state.fields["op"] == "finish" && report > last_finish {
                        last_finish = report;
                        match state.fields["result"].as_str() {
                            "ok" => finished = true,
                            "busy" if finish_attempts < 8 => {
                                uart.write_all(b"finish\n")
                                    .and_then(|()| uart.flush())
                                    .map_err(|e| e.to_string())?;
                                finish_attempts += 1;
                            }
                            _ => return Err("compatibility checked finish refused".into()),
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(4));
                continue;
            }
            if stage == 20 {
                if hello_complete(&bytes, build, &fixture.snapshot()?)? {
                    uart.write_all(b"finish\n")
                        .and_then(|()| uart.flush())
                        .map_err(|e| e.to_string())?;
                    finish_attempts = 1;
                    finishing = true;
                }
                std::thread::sleep(Duration::from_millis(4));
                continue;
            }
            if stage == 6 {
                if let Some(state) = states.iter().rev().find(|s| s.fields["op"] == "stage") {
                    if state.fields["result"] != "ok" || state.number("revision")? != 3 {
                        return Err("compatibility real stageB refused or changed revision".into());
                    }
                    uart.write_all(b"activate\n")
                        .and_then(|()| uart.flush())
                        .map_err(|e| e.to_string())?;
                    inputs.push(
                        json!({"stage":stage,"device":"owned QEMU UART","bytes":"activate\n"}),
                    );
                    stage = 7;
                }
                std::thread::sleep(Duration::from_millis(4));
                continue;
            }
            let text = std::str::from_utf8(&bytes).map_err(|_| "compatibility logUTF8")?;
            let steps = text
                .split_inclusive('\n')
                .filter(|l| l.ends_with('\n') && l.starts_with("EVROSION_M4_DESKTOP_STEP "))
                .map(|l| desktop_protocol::step_line(l.trim_end_matches(['\r', '\n']), build))
                .collect::<Result<Vec<_>>>()?;
            let ui = crate::session_io::ProbeUi::parse(&bytes, build)?;
            let observed = crate::document_io::records(&bytes, build)?;
            let latest = observed.last();
            let legacy = matches!(stage, 1 | 2 | 3 | 5);
            let picker = matches!(stage, 4 | 8 | 18);
            let screen = if stage == 0 {
                Screen::Home
            } else if picker {
                Screen::Picker {
                    selected: FileChoice::Notes,
                }
            } else {
                Screen::AppRunning
            };
            let reference = if legacy {
                Reference::new(
                    screen,
                    Some(View {
                        build: Build::A,
                        focus: match stage {
                            2 => LegacyFocus::Save,
                            3 | 5 => LegacyFocus::OpenFile,
                            _ => LegacyFocus::Note,
                        },
                        note: b"s02",
                        state: SaveState::Saved,
                        file: (stage == 5).then_some(ev_file::desktop::SEED_NOTES),
                    }),
                    ui.cursor(),
                )?
            } else {
                Reference::document(
                    screen,
                    if screen == Screen::AppRunning {
                        latest.map(|o| o.view)
                    } else {
                        None
                    },
                    if stage == 4 {
                        Access::Read
                    } else {
                        Access::Edit
                    },
                    ui.cursor(),
                )?
            };
            let current = steps.iter().rev().find(|s| {
                s.producer
                    == if screen == Screen::AppRunning {
                        Producer::App
                    } else {
                        Producer::Shell
                    }
                    && s.kind
                        == if picker {
                            StepKind::PickerReady
                        } else {
                            StepKind::Frame
                        }
            });
            let shell = steps
                .iter()
                .rev()
                .find(|s| s.producer == Producer::Shell && s.kind == StepKind::Frame);
            let ready = current.is_some_and(|s| {
                if screen != Screen::AppRunning {
                    return ui.cursor().is_some()
                        && ui.ready(s.shell_process, s.frame, 0)
                        && reference
                            .surface_hash(Producer::Shell, s.frame)
                            .is_ok_and(|h| h == s.surface_sha256);
                }
                if legacy {
                    s.frame > seen_app_frame
                        && shell.is_some_and(|shell| ui.ready(s.shell_process, shell.frame, 0))
                        && reference.app_composition_ready(s, shell).unwrap_or(false)
                } else {
                    latest.is_some_and(|o| {
                        o.frame == s.frame && o.process == s.app_process && o.nonce > seen_nonce
                    }) && shell.is_some_and(|shell| ui.ready(s.shell_process, shell.frame, 0))
                        && reference.app_composition_ready(s, shell).unwrap_or(false)
                }
            });
            let acceptable = match stage {
                0 | 2 | 3 | 4 | 5 | 8 | 18 => true,
                1 => current.is_some_and(|s| ui.note_complete(s.app_process, 1, 1).is_some()),
                7 | 17 => latest.is_some_and(|o| o.view.state == State::Closed),
                9 => latest.is_some_and(|o| {
                    o.view.state == State::Saved
                        && o.view.choice == Choice::Notes
                        && o.view.access == Access::Edit
                        && o.view.revision == u64::from(phase == Phase::Cold)
                        && o.view.text.as_bytes()
                            == if phase == Phase::Cold {
                                crate::document_io::SAVED
                            } else {
                                ev_file::desktop::SEED_NOTES
                            }
                }),
                10 | 13 => latest.is_some_and(|o| o.view.focus == Focus::SelectAll),
                11 => latest.is_some_and(|o| o.view.focus == Focus::Text && o.view.anchor == 0),
                12 => latest.is_some_and(|o| {
                    o.view.state == State::Dirty
                        && o.view.text.as_bytes() == &crate::document_io::SAVED[..typed]
                }),
                14 => latest.is_some_and(|o| o.view.focus == Focus::Save),
                15 | 19 => latest.is_some_and(|o| {
                    o.view.state == State::Saved
                        && o.view.revision == 1
                        && o.view.text.as_bytes() == crate::document_io::SAVED
                }),
                16 => latest.is_some_and(|o| o.view.focus == Focus::Close),
                _ => false,
            };
            if ready && acceptable {
                if qmp.is_none() {
                    crate::boot::check_desktop_prefix(&bytes, build)?;
                    qmp = Some(Qmp::connect_at(directory, deadline, start)?);
                }
                let q = qmp.as_mut().unwrap();
                capture += 1;
                if capture > 64 {
                    return Err("compatibility capture bound exceeded".into());
                }
                q.set_running(false)?;
                let (path, pixels) = q.capture(capture)?;
                if let Ok(proof) = reference.validate(&pixels) {
                    let actual = current.unwrap();
                    captures.push(json!({"stage":stage,"typed":typed,"path":path,"pixels":proof,"actual_present":actual,"nonce":latest.map(|o|o.nonce)}));
                    if legacy {
                        seen_app_frame = actual.frame;
                    } else if screen == Screen::AppRunning {
                        seen_nonce = latest.unwrap().nonce;
                    }
                    if stage == 0 {
                        let raw = disk.bytes()?;
                        storage::immutable_new(
                            &directory.join("compatibility-baseline.raw"),
                            &raw,
                        )?;
                        initial = Some(raw);
                    }
                    if stage == 1 {
                        legacy_app = Some(actual.app_process);
                    }
                    if stage == 5 {
                        if actual.grants != 1 {
                            return Err(
                                "legacy READ selection lacks one actual selected grant".into()
                            );
                        }
                        let raw = disk.bytes()?;
                        if Some(&raw) != initial.as_ref() {
                            return Err(
                                "legacy actual READ and refused Replace changed disk bytes".into(),
                            );
                        }
                        storage::immutable_new(&directory.join("legacy-read-after.raw"), &raw)?;
                        read_proof = Some(
                            json!({"actual_legacy_process":actual.app_process,"selected_grants":actual.grants,"whole_disk_unchanged":true,"exact_legacy_executable_proves_read_only":true}),
                        );
                    }
                    if stage == 7 {
                        document_app = Some(actual.app_process);
                        if phase == Phase::Exercise && document_app == legacy_app {
                            return Err("document activation reused old incarnation".into());
                        }
                    }
                    if stage == 15 || stage == 19 || (stage == 9 && phase == Phase::Cold) {
                        let raw = disk.bytes()?;
                        saved_proof = Some(crate::native3_disk::document(
                            &raw,
                            1,
                            crate::document_io::SAVED,
                        )?);
                        storage::immutable_new(
                            &directory.join(format!("document-stage-{stage}.raw")),
                            &raw,
                        )?;
                    }
                    q.set_running(true)?;
                    let key = match stage {
                        0 => {
                            stage = if phase == Phase::Exercise { 1 } else { 7 };
                            Some(Key::Enter)
                        }
                        1 => {
                            stage = 2;
                            Some(Key::Tab)
                        }
                        2 => {
                            stage = 3;
                            Some(Key::Tab)
                        }
                        3 => {
                            stage = 4;
                            Some(Key::Enter)
                        }
                        4 => {
                            stage = 5;
                            Some(Key::Enter)
                        }
                        5 => {
                            uart.write_all(b"stage b\n")
                                .and_then(|()| uart.flush())
                                .map_err(|e| e.to_string())?;
                            inputs.push(json!({"stage":stage,"device":"owned QEMU UART","bytes":"stage b\n"}));
                            stage = 6;
                            None
                        }
                        7 => {
                            stage = 8;
                            Some(Key::Enter)
                        }
                        8 => {
                            stage = 9;
                            Some(Key::Enter)
                        }
                        9 if phase == Phase::Cold => {
                            stage = 20;
                            None
                        }
                        9 => {
                            stage = 10;
                            Some(Key::Tab)
                        }
                        10 => {
                            stage = 11;
                            Some(Key::Enter)
                        }
                        11 => {
                            q.ascii(crate::document_io::SAVED[0])?;
                            typed = 1;
                            stage = 12;
                            None
                        }
                        12 if typed < crate::document_io::SAVED.len() => {
                            q.ascii(crate::document_io::SAVED[typed])?;
                            typed += 1;
                            None
                        }
                        12 => {
                            stage = 13;
                            Some(Key::Tab)
                        }
                        13 => {
                            stage = 14;
                            Some(Key::Tab)
                        }
                        14 => {
                            stage = 15;
                            Some(Key::Enter)
                        }
                        15 => {
                            stage = 16;
                            Some(Key::Tab)
                        }
                        16 => {
                            stage = 17;
                            Some(Key::Enter)
                        }
                        17 => {
                            stage = 18;
                            Some(Key::Enter)
                        }
                        18 => {
                            stage = 19;
                            Some(Key::Enter)
                        }
                        19 => {
                            stage = 20;
                            None
                        }
                        _ => None,
                    };
                    if let Some(key) = key {
                        q.key_state(key, true)?;
                        q.key_state(key, false)?;
                        inputs.push(json!({"stage_after":stage,"device":"owned QEMU keyboard","key":format!("{key:?}")}));
                    }
                    if finishing {
                        uart.write_all(b"finish\n")
                            .and_then(|()| uart.flush())
                            .map_err(|e| e.to_string())?;
                        finish_attempts = 1;
                    }
                } else {
                    q.set_running(true)?;
                }
            }
            std::thread::sleep(Duration::from_millis(4));
        }
    })();
    storage::json_new(
        &directory.join("compatibility-observer.json"),
        &json!({"schema":1,"phase":format!("{phase:?}"),"passed":result.is_ok(),"stage":stage,"typed":typed,"error":result.as_ref().err(),"scripted_input":true,"human_acceptance":false,"captures":captures,"inputs":inputs,"legacy_app":legacy_app,"document_app":document_app,"legacy_read":read_proof,"saved_document":saved_proof,"owned_loopback_fixture":fixture.snapshot()?}),
    )?;
    storage::json_new(
        &directory.join("qmp-transcript.json"),
        &json!({"schema":1,"exchanges":qmp.as_ref().map(|q|q.transcript()).unwrap_or(&[])}),
    )?;
    result
}
fn hello_complete(
    serial: &[u8],
    build: &str,
    fixture: &crate::network_fixture::Snapshot,
) -> Result<bool> {
    // A live file read may stop inside the next protected UART row.
    // Readiness uses complete rows; final post-exit raw retention stays strict.
    let network = crate::network_protocol::records(crate::acquisition_io::complete(serial), build)?;
    if network.iter().any(|p| p.stage == 8 || p.result != 0) {
        return Err("compatibility actual local Hello failed before checked finish".into());
    }
    Ok(crate::network_io::acquisition_hello(fixture)?
        && network.iter().any(|p| p.stage == 6 && p.result == 0))
}
fn bounded_log(path: &Path) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 1024 * 1024 {
        return Err("compatibility log type/bound".into());
    }
    fs::read(path).map_err(|e| e.to_string())
}

struct CurrentPackages {
    bytes: [Vec<u8>; 2],
}
impl ev_app_registry::Packages for CurrentPackages {
    fn resolve(&self, digest: [u8; 32]) -> Option<&[u8]> {
        self.bytes
            .iter()
            .find(|b| <[u8; 32]>::from(Sha256::digest(b)) == digest)
            .map(Vec::as_slice)
    }
}
struct MetadataContracts;
impl ev_zion::Contracts for MetadataContracts {
    fn supported(&self, name: &str, major: u16) -> Option<ev_zion::ContractSupport> {
        (major == 1
            && matches!(
                name,
                "ev.app.document"
                    | "ev.ui.document"
                    | "ev.test.document"
                    | "ev.app.private-data"
                    | "ev.app.session-note"
                    | "ev.internal.file"
                    | "ev.internal.focused-input"
                    | "ev.internal.surface-present"
            ))
        .then_some(ev_zion::ContractSupport {
            minor: u16::from(name == "ev.internal.focused-input"),
            features: 0,
        })
    }
}
fn artifact_bytes(root: &Path, manifest: &Manifest, name: &str) -> Result<Vec<u8>> {
    let mut matching = manifest
        .supervisor
        .iter()
        .filter(|a| Path::new(&a.path).file_name().is_some_and(|n| n == name));
    let row = matching
        .next()
        .ok_or_else(|| format!("compatibility current artifact absent: {name}"))?;
    if matching.next().is_some()
        || Path::new(&row.path).parent() != Path::new(&manifest.kernel.path).parent()
    {
        return Err("compatibility current artifact cohort ambiguous".into());
    }
    let path = build::verify_artifact(&root.join("build/m0"), row)?;
    let bytes = regular(
        root,
        path.strip_prefix(root)
            .map_err(|_| "compatibility artifact escaped root")?,
        2 * 1024 * 1024,
    )?;
    if hash(&bytes) != row.sha256 {
        return Err("compatibility current artifact changed".into());
    }
    Ok(bytes)
}
fn current_packages(root: &Path, manifest: &Manifest) -> Result<CurrentPackages> {
    let catalogue_bytes = artifact_bytes(root, manifest, "m5-native-catalogue.bin")?;
    let catalogue = ev_userspace_contract::root_v4::catalogue::Catalogue::decode(&catalogue_bytes)
        .map_err(|e| format!("compatibility current V4 catalogue: {e:?}"))?;
    if catalogue.boot_mode() != ev_userspace_contract::root_v4::catalogue::BootMode::Standalone
        || catalogue.base().app_id() != crate::native_package::HELLO_APP_ID
    {
        return Err("compatibility current Standalone/App identity differs".into());
    }
    let bytes = [
        artifact_bytes(root, manifest, "m5-native-Hello-A.zion")?,
        artifact_bytes(root, manifest, "m5-native-Hello-B.zion")?,
    ];
    if hash(&bytes[0]) != LEGACY_PACKAGE {
        return Err(
            "compatibility current bankA does not retain exact accepted legacy executable package"
                .into(),
        );
    }
    for (i, container) in bytes.iter().enumerate() {
        let p = ev_zion::Package::parse(container)
            .map_err(|e| format!("compatibility current complete package: {e:?}"))?;
        let elf = artifact_bytes(
            root,
            manifest,
            if i == 0 {
                "m5-native-app-a.elf"
            } else {
                "m5-native-app-b.elf"
            },
        )?;
        let (digest, image, build, length) = if i == 0 {
            (
                catalogue.package_a(),
                catalogue
                    .base()
                    .images()
                    .nth(4)
                    .ok_or("compatibility catalogue AppA absent")?
                    .image,
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
        if p.id().bytes() != digest
            || p.executable().digest != image
            || p.executable().bytes != elf
            || p.app().build_id != build
            || container.len() as u64 != length
            || p.app().claimed_app.bytes() != crate::native_package::HELLO_APP_ID
            || p.app().data_schema.current != 1
            || p.app().data_schema.oldest_readable != 1
        {
            return Err("compatibility current full package/catalogue/executable/schema association differs".into());
        }
        p.check_requirements(1, ev_userspace_contract::ABI, &MetadataContracts)
            .map_err(|e| format!("compatibility metadata requirements: {e:?}"))?;
    }
    let doc = ev_zion::Package::parse(&bytes[1])
        .map_err(|e| format!("compatibility Doc package: {e:?}"))?;
    if doc.app().version.minor != 3
        || !doc
            .app()
            .capability_requests()
            .any(|r| r.capability == ev_zion::Capability::SelectedFileEdit && !r.required)
        || !doc
            .app()
            .contracts()
            .any(|r| r.name == "ev.app.document" && r.major == 1)
        || !doc
            .app()
            .contracts()
            .any(|r| r.name == "ev.ui.document" && r.major == 1)
    {
        return Err("compatibility bankB is not the explicit native document package".into());
    }
    Ok(CurrentPackages { bytes })
}
fn current_registry(bytes: &[u8], packages: &CurrentPackages) -> Result<Value> {
    let registry = ev_app_registry::Registry::open(
        ReadOnly::new(bytes, Region::AppRegistry)?,
        ev_app_registry::Policy {
            app: ev_zion::AppId::new(crate::native_package::HELLO_APP_ID).unwrap(),
            abi: ev_userspace_contract::ABI,
            platform: 1,
        },
        packages,
        &MetadataContracts,
        DEADLINE,
    )
    .map_err(|r| {
        format!(
            "compatibility current full immutable registry resolution: {:?}",
            r.error
        )
    })?;
    let record = registry
        .record()
        .map_err(|e| format!("compatibility current registry record: {e:?}"))?
        .ok_or("compatibility current registry unexpectedly empty")?;
    let a = ev_zion::Package::parse(&packages.bytes[0])
        .map_err(|e| format!("compatibility current A: {e:?}"))?;
    let b = ev_zion::Package::parse(&packages.bytes[1])
        .map_err(|e| format!("compatibility current B: {e:?}"))?;
    if record.revision() != 4
        || !record.installed()
        || record.data_epoch() != 1
        || record.active().map(|v| v.digest()) != Some(b.id().bytes())
        || record.previous().map(|v| v.digest()) != Some(a.id().bytes())
        || record.staged().is_some()
    {
        return Err(
            "compatibility current registry did not perform exact retainedA->DocB stage/activate"
                .into(),
        );
    }
    let head = registry
        .expected()
        .map_err(|e| format!("compatibility registry head: {e:?}"))?;
    let (device, _, pending) = registry.into_parts();
    if pending.is_some() {
        return Err(
            "compatibility readonly current registry retained an uncertain publication".into(),
        );
    }
    Ok(
        json!({"revision":4,"data_epoch":1,"active":hex(b.id().bytes()),"previous":hex(a.id().bytes()),"staged":null,"base_head":hex(head.base_head),"device":device.proof()?,"complete_immutable_resolution":true}),
    )
}
fn unchanged_regions(before: &[u8], after: &[u8]) -> Result<()> {
    if before.len() != storage::DISK_BYTES || after.len() != storage::DISK_BYTES {
        return Err("compatibility full disk comparison extent differs".into());
    }
    for (offset, (a, b)) in before.iter().zip(after).enumerate() {
        let sector = offset / storage::SECTOR_BYTES;
        if a != b && !(32..46).contains(&sector) && !(64..78).contains(&sector) {
            return Err(format!(
                "compatibility changed unrelated bytes atsector{sector}"
            ));
        }
    }
    Ok(())
}

pub(crate) fn run() -> Result<()> {
    use crate::{
        boot::{self, CompatibilityBoot},
        cli::BootOptions,
    };
    let root =
        crate::doctor::workspace(&std::env::current_dir().map_err(|e| e.to_string())?, None)?
            .canonicalize()
            .map_err(|e| e.to_string())?;
    let legacy_root=PathBuf::from(std::env::var_os("EV_M7_LEGACY_ROOT").ok_or("set EV_M7_LEGACY_ROOT to the exact retained manual-host-fix workspace; no original disk will be written")?);
    let manifest_path = std::env::var_os("EV_M7_DOCUMENT_COMPAT_MANIFEST")
        .map_or_else(|| root.join("build/m0/manifest.json"), PathBuf::from);
    let relative = manifest_path.strip_prefix(&root).map_err(
        |_| "compatibility manifest must be an owned retained input beneath this workspace",
    )?;
    let manifest_bytes = regular(&root, relative, 2 * 1024 * 1024)?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes).map_err(|e| e.to_string())?;
    manifest.validate_policy_rows()?;
    if manifest.fixture.as_deref() != Some("m7-document-network") || manifest.profile != "release" {
        return Err("compatibility requires exact optimized m7-document-network build".into());
    }
    if build::source_inputs(&root)?
        != (
            manifest.source_sha256.clone(),
            manifest.source_inputs.clone(),
        )
    {
        return Err("compatibility current source differs from guest build".into());
    }
    let parent = storage::directory_beneath(&root, Path::new("build/m7/evidence"))?;
    let evidence = build::unique_directory(&parent, "saved02-compatibility")?;
    println!("Evidence: {}", evidence.display());
    let retained_manifest = evidence.join("manifest.json");
    storage::immutable_new(&retained_manifest, &manifest_bytes)?;
    let origin = Origin::retain(&legacy_root, &evidence)?;
    let current_context = Context::retain_document_mode(
        &root,
        &manifest,
        &storage::directory_beneath(&evidence, Path::new("current-preflight"))?,
        Mode::Standalone,
    )?;
    let packages = current_packages(&root, &manifest)?;
    let current_banks = current_context.packages()?;
    if current_banks.bytes(ev_root_supervisor::native_plan::Slot::A) != packages.bytes[0]
        || current_banks.bytes(ev_root_supervisor::native_plan::Slot::B) != packages.bytes[1]
    {
        return Err("compatibility independent current package views differ".into());
    }
    let disk = origin.clone_disk(&root, &evidence)?;
    let options = BootOptions {
        root: Some(root.clone()),
        timeout_seconds: 240,
        ..BootOptions::default()
    };
    let mut phases = Vec::new();
    let operation: Result<Value> = (|| {
        boot::boot_compatibility(
            &options,
            CompatibilityBoot {
                manifest: &retained_manifest,
                evidence: &evidence,
                disk: &disk,
                phase: Phase::Exercise,
            },
        )?;
        let saved = disk.bytes()?;
        unchanged_regions(origin.baseline(), &saved)?;
        let private = origin.saved_data(&saved)?;
        let (record, registry) = origin.registry(&saved)?;
        if record.revision() != 4 || registry["operation"] != 4 {
            return Err("compatibility actual registry revision/operation differs".into());
        }
        let resolution = current_registry(&saved, &packages)?;
        let file = crate::native3_disk::document(&saved, 1, crate::document_io::SAVED)?;
        storage::immutable_new(&evidence.join("saved02-document-after.raw"), &saved)?;
        phases.push(json!({"phase":"actual-legacy-read-and-document-save-reopen","private_data":private,"registry":registry,"full_registry_resolution":resolution,"file":file,"unchanged_outside_notes_and_registry":true}));
        let cold = storage::directory_beneath(&evidence, Path::new("cold"))?;
        boot::boot_compatibility(
            &options,
            CompatibilityBoot {
                manifest: &retained_manifest,
                evidence: &cold,
                disk: &disk,
                phase: Phase::Cold,
            },
        )?;
        let after = disk.bytes()?;
        if after != saved {
            return Err("compatibility cold reopened same disk changed any byte".into());
        }
        origin.saved_data(&after)?;
        current_registry(&after, &packages)?;
        crate::native3_disk::document(&after, 1, crate::document_io::SAVED)?;
        phases.push(json!({"phase":"actual-cold-same-saved02-compatible-disk","entire_disk_unchanged":true,"sha256":hash(&after)}));
        Ok(
            json!({"private_saved02_preserved":true,"selected_file_revision":1,"cold_disk_unchanged":true,"whole_disk_sha256":hash(&after)}),
        )
    })();
    let after = disk.capture(&evidence, "data-final.raw");
    let seal = disk.seal();
    let original = origin.check_original_untouched();
    let source = build::source_inputs(&root).map(|s| {
        s == (
            manifest.source_sha256.clone(),
            manifest.source_inputs.clone(),
        )
    });
    let passed = operation.is_ok()
        && after.is_ok()
        && seal.is_ok()
        && original.is_ok()
        && source.as_ref() == Ok(&true);
    storage::json_new(
        &evidence.join("compatibility-workflow.json"),
        &json!({"schema":1,"passed":passed,"source_sha256":manifest.source_sha256,"build":manifest.build_id,"original_source_sha256":LEGACY_SOURCE,"original_volume_sha256":LEGACY_VOLUME,"same_compatible_owned02_data":true,"phases":phases,"result":operation.as_ref().ok(),"error":operation.as_ref().err(),"after":after.as_ref().ok(),"capture_error":after.as_ref().err(),"seal_error":seal.as_ref().err(),"original_untouched":original.is_ok(),"original_error":original.as_ref().err(),"source_unchanged":source.as_ref().ok(),"source_error":source.as_ref().err(),"scripted_input":true,"human_acceptance":false,"format_reset_migration_or_raw_namespace_surgery":false,"scope":"Actual accepted saved0.2 volume clone; exact retained legacy App reads s02 and attempts denied selected-file Replace, explicit current native Doc activation edits/reopens Notes, same disk cold reopens. Original namespaces and private data remain unchanged. Not failed-update recovery or full M7 acceptance."}),
    )?;
    operation?;
    after?;
    seal?;
    original?;
    if !source? {
        return Err("compatibility current source changed during proof".into());
    }
    println!(
        "PASS actual saved0.2 private data and native document compatibility: {}",
        evidence.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn trace(stage: u64, result: u64, argument: u64) -> (String, String) {
        let build = "a".repeat(64);
        let text = format!(
            "EVROSION_M5_NATIVE_COMMON_PREFIX protocol=1 build={build} mode=0 root_process=20 root_thread=120 root_image_sha256={} root_epoch=4 root_incarnation=2 root_manifest_sha256={} block_process=24 block_thread=124 block_image_sha256={} system_endpoint=77 root_frames=40 block_frames=20\nEVROSION_M6_NETWORK_PROGRESS protocol=1 build={build} root_process=20 root_thread=120 endpoint=77 ticket=1 tick=10 stage={stage} result={result} argument={argument}\n",
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64)
        );
        (build, text)
    }
    fn exchange() -> crate::network_fixture::Snapshot {
        let body = crate::network_fixture::HELLO;
        crate::network_fixture::Snapshot{observed:1,completed:1,omitted:0,exchanges:vec![crate::network_fixture::Exchange{
            request:b"GET /hello HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n".to_vec(),
            response:[format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes(),body].concat(),error:None,mutation:None}]}
    }
    #[test]
    fn cold_finish_waits_for_both_exact_socket_exchange_and_actual_root_completion() {
        // Synthetic parser/ledger tests only; never new guest or network proof.
        let (build, connecting) = trace(3, 0, 1);
        assert!(
            !hello_complete(
                connecting.as_bytes(),
                &build,
                &crate::network_fixture::Snapshot::default()
            )
            .unwrap()
        );
        assert!(!hello_complete(connecting.as_bytes(), &build, &exchange()).unwrap());
        let (_, completed) = trace(6, 0, crate::network_fixture::HELLO.len() as u64);
        assert!(
            !hello_complete(
                completed.as_bytes(),
                &build,
                &crate::network_fixture::Snapshot::default()
            )
            .unwrap()
        );
        assert!(hello_complete(completed.as_bytes(), &build, &exchange()).unwrap());
    }
    #[test]
    fn live_cold_finish_waits_through_every_split_and_still_refuses_complete_bad_rows() {
        // Prefix/ledger regression only; no synthetic guest or socket proof.
        let (build, connecting) = trace(3, 0, 1);
        let (_, complete) = trace(6, 0, crate::network_fixture::HELLO.len() as u64);
        let completed_row = complete
            .lines()
            .last()
            .unwrap()
            .replace("ticket=1", "ticket=2")
            .replace("tick=10", "tick=20")
            + "\n";
        for end in 0..completed_row.len() {
            let prefix = format!("{connecting}{}", &completed_row[..end]);
            assert!(
                !hello_complete(prefix.as_bytes(), &build, &exchange()).unwrap(),
                "an incomplete protected completion row allowed finish at byte{end}"
            );
        }
        let partial = format!("{connecting}{}", completed_row.trim_end_matches('\n'));
        assert!(crate::network_protocol::records(partial.as_bytes(), &build).is_err());
        let completed = format!("{connecting}{completed_row}");
        assert!(hello_complete(completed.as_bytes(), &build, &exchange()).unwrap());
        assert!(
            !hello_complete(
                completed.as_bytes(),
                &build,
                &crate::network_fixture::Snapshot::default()
            )
            .unwrap()
        );
        let wrong_body = completed.replace(
            "stage=6 result=0 argument=28",
            "stage=6 result=0 argument=27",
        );
        assert_ne!(wrong_body, completed);
        assert!(hello_complete(wrong_body.as_bytes(), &build, &exchange()).is_err());
        let failed = format!(
            "{connecting}{}",
            completed_row.replace("stage=6 result=0", "stage=8 result=1")
        );
        assert!(hello_complete(failed.as_bytes(), &build, &exchange()).is_err());
    }
    #[test]
    fn failed_root_exchange_and_wrong_or_extra_served_bytes_never_allow_finish() {
        let (build, failed) = trace(8, 1, 4);
        assert!(
            hello_complete(
                failed.as_bytes(),
                &build,
                &crate::network_fixture::Snapshot::default()
            )
            .is_err()
        );
        let (_, completed) = trace(6, 0, crate::network_fixture::HELLO.len() as u64);
        let mut wrong = exchange();
        wrong.exchanges[0].response.push(b'x');
        assert!(hello_complete(completed.as_bytes(), &build, &wrong).is_err());
        let mut extra = exchange();
        extra.observed = 2;
        extra.completed = 2;
        assert!(hello_complete(completed.as_bytes(), &build, &extra).is_err());
    }
}
