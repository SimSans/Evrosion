//! Explicit, destructive-to-its-own-fixture-only M3 PIO experiment.
//! No caller-supplied data path is accepted. M0--M2 boot configurations are unchanged.
use crate::{
    boot::{self, StorageBoot},
    build::{self, Manifest, Result},
    cli::{BootOptions, BuildOptions},
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};

pub const SECTOR_BYTES: usize = 512;
pub const SECTORS: usize = 8192;
pub const DISK_BYTES: usize = SECTOR_BYTES * SECTORS;
const LIMIT_SECONDS: u64 = 120;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Write,
    Verify,
}
impl Phase {
    pub fn name(self) -> &'static str {
        match self {
            Self::Write => "write",
            Self::Verify => "verify",
        }
    }
    pub fn fixture(self) -> &'static str {
        match self {
            Self::Write => "m3-pio-write",
            Self::Verify => "m3-pio-verify",
        }
    }
    pub fn flushes(self) -> u64 {
        u64::from(self == Self::Write)
    }
}

fn seed_sector() -> [u8; SECTOR_BYTES] {
    std::array::from_fn(|index| (index as u8).wrapping_mul(17).wrapping_add(0x53))
}
fn committed_sector() -> [u8; SECTOR_BYTES] {
    std::array::from_fn(|index| (index as u8).wrapping_mul(29).wrapping_add(0xa7))
}
fn fixture(committed: bool) -> Vec<u8> {
    let mut bytes = vec![0; DISK_BYTES];
    bytes[..SECTOR_BYTES].copy_from_slice(&seed_sector());
    if committed {
        bytes[SECTOR_BYTES..2 * SECTOR_BYTES].copy_from_slice(&committed_sector());
    }
    bytes
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Inspect each component before following it. This is an owner-run development
/// tool, not protection against a hostile host account racing directory renames.
pub(crate) fn directory_beneath(root: &Path, relative: &Path) -> Result<PathBuf> {
    if relative.as_os_str().is_empty()
        || !relative
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err("fixture directory must be a nonempty relative path without traversal".into());
    }
    let root = root.canonicalize().map_err(|error| error.to_string())?;
    let mut path = root.clone();
    for part in relative.components() {
        path.push(part.as_os_str());
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = fs::DirBuilder::new();
                #[cfg(unix)]
                builder.mode(0o700);
                match builder.create(&path) {
                    Ok(()) => {}
                    // Concurrent runner/test creation is harmless only after
                    // the same no-symlink directory check below.
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.to_string()),
                }
            }
            Err(error) => return Err(error.to_string()),
        }
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(format!(
                "fixture path is not a real directory: {}",
                path.display()
            ));
        }
        if !path
            .canonicalize()
            .map_err(|error| error.to_string())?
            .starts_with(&root)
        {
            return Err("fixture directory escaped the repository".into());
        }
    }
    Ok(path)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())
}
pub(crate) fn immutable_new(path: &Path, bytes: &[u8]) -> Result<()> {
    write_new(path, bytes)?;
    let mut permissions = fs::metadata(path)
        .map_err(|error| error.to_string())?
        .permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions).map_err(|error| error.to_string())
}
pub(crate) fn json_new(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    immutable_new(path, &bytes)
}

/// Sole runner-created attachment. A user path cannot construct this type.
/// This is backend configuration, not a capability or a device-quiescence receipt.
pub(crate) struct Disk {
    root: PathBuf,
    path: PathBuf,
    #[cfg(unix)]
    identity: (u64, u64),
}
/// Persistent developer-session disk, confined to the runner's fixed directory.
/// The open lock remains owned until QEMU has stopped and its bytes are captured.
pub(crate) struct SessionDisk {
    pub disk: Disk,
    _lock: SessionLock,
    pub created: bool,
}
// Unlock the shared open-file description explicitly. A concurrently spawned
// child can temporarily inherit it before exec closes CLOEXEC descriptors; just
// closing our descriptor would leave that inherited reference holding the lock.
struct SessionLock(File);
impl Drop for SessionLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}
impl SessionDisk {
    #[cfg(unix)]
    pub fn open(root: &Path, seed: &[u8]) -> Result<Self> {
        Self::open_profile(root, seed, Path::new("build/m6/session"))
    }
    #[cfg(unix)]
    pub(crate) fn open_network(root: &Path, seed: &[u8]) -> Result<Self> {
        Self::open_profile(root, seed, Path::new("build/m6/network-session"))
    }
    #[cfg(unix)]
    pub(crate) fn open_document(root: &Path, seed: &[u8]) -> Result<Self> {
        let directory = root.join("build/m7/document-session");
        if fs::symlink_metadata(directory.join("boot-set")).is_ok()
            && !(directory.join("data.raw").try_exists().unwrap_or(false)
                && directory.join("owner.json").try_exists().unwrap_or(false))
        {
            return Err("retained document boot set has incomplete owned disk state; preserved without formatting".into());
        }
        Self::open_profile(root, seed, Path::new("build/m7/document-session"))
    }
    #[cfg(unix)]
    fn open_profile(root: &Path, seed: &[u8], relative: &Path) -> Result<Self> {
        if seed.len() != DISK_BYTES {
            return Err("session seed must be exactly 4 MiB".into());
        }
        let root = root.canonicalize().map_err(|e| e.to_string())?;
        let directory = directory_beneath(&root, relative)?;
        let lock_path = directory.join("session.lock");
        if let Ok(meta) = fs::symlink_metadata(&lock_path)
            && (!meta.is_file() || meta.file_type().is_symlink() || meta.nlink() != 1)
        {
            return Err("session lock is not an owned regular file".into());
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|e| e.to_string())?;
        let locked = lock.metadata().map_err(|e| e.to_string())?;
        let named = fs::symlink_metadata(&lock_path).map_err(|e| e.to_string())?;
        if !locked.is_file()
            || locked.nlink() != 1
            || named.file_type().is_symlink()
            || (locked.dev(), locked.ino()) != (named.dev(), named.ino())
        {
            return Err("session lock identity changed".into());
        }
        lock.try_lock()
            .map_err(|_| "another session owns this developer disk")?;
        let lock = SessionLock(lock);
        let receipt = directory.join("owner.json");
        let data = directory.join("data.raw");
        let (disk, created) = match (receipt.try_exists(), data.try_exists()) {
            (Ok(false), Ok(false)) => {
                let mut disk = Disk::create(&root, &directory)?;
                disk.restore_snapshot(seed)?;
                json_new(
                    &receipt,
                    &json!({"schema":1,"workspace":root,"device":disk.identity.0,"inode":disk.identity.1}),
                )?;
                (disk, true)
            }
            (Ok(true), Ok(true)) => {
                let metadata = fs::symlink_metadata(&receipt).map_err(|e| e.to_string())?;
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.nlink() != 1
                    || metadata.len() > 4096
                {
                    return Err("session ownership record must be a small regular file".into());
                }
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Owner {
                    schema: u32,
                    workspace: PathBuf,
                    device: u64,
                    inode: u64,
                }
                let owner: Owner =
                    serde_json::from_slice(&fs::read(&receipt).map_err(|e| e.to_string())?)
                        .map_err(|e| format!("invalid session ownership record: {e}"))?;
                if owner.schema != 1 || owner.workspace != root {
                    return Err("session disk belongs to another workspace".into());
                }
                let disk = Disk {
                    root: root.clone(),
                    path: data,
                    identity: (owner.device, owner.inode),
                };
                disk.validate(&root)?;
                (disk, false)
            }
            _ => {
                return Err(
                    "incomplete or inaccessible session state; retained without formatting".into(),
                );
            }
        };
        Ok(Self {
            disk,
            _lock: lock,
            created,
        })
    }
    #[cfg(not(unix))]
    pub fn open(_: &Path, _: &[u8]) -> Result<Self> {
        Err("persistent developer sessions currently require a supported Linux host".into())
    }
    #[cfg(not(unix))]
    pub(crate) fn open_network(_: &Path, _: &[u8]) -> Result<Self> {
        Err("network developer sessions currently require a supported Linux host".into())
    }
    #[cfg(not(unix))]
    pub(crate) fn open_document(_: &Path, _: &[u8]) -> Result<Self> {
        Err("document developer sessions currently require a supported Linux host".into())
    }
}
impl Disk {
    pub(crate) fn create(root: &Path, evidence: &Path) -> Result<Self> {
        let root = root.canonicalize().map_err(|error| error.to_string())?;
        let relative = evidence
            .strip_prefix(&root)
            .map_err(|_| "disk evidence must be in the repository")?;
        let evidence = directory_beneath(&root, relative)?;
        let path = evidence.join("data.raw");
        write_new(&path, &fixture(false))?;
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        Ok(Self {
            root,
            path,
            #[cfg(unix)]
            identity: (metadata.dev(), metadata.ino()),
        })
    }
    fn validate(&self, root: &Path) -> Result<()> {
        if root.canonicalize().map_err(|error| error.to_string())? != self.root {
            return Err("data disk belongs to another repository".into());
        }
        let parent = self.path.parent().ok_or("disk parent missing")?;
        directory_beneath(
            &self.root,
            parent
                .strip_prefix(&self.root)
                .map_err(|_| "disk escaped repository")?,
        )?;
        let metadata = fs::symlink_metadata(&self.path).map_err(|error| error.to_string())?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() != DISK_BYTES as u64
        {
            return Err("data disk must be the runner's exact regular 4 MiB raw file".into());
        }
        #[cfg(unix)]
        if (metadata.dev(), metadata.ino()) != self.identity || metadata.nlink() != 1 {
            return Err("data disk identity changed or has external hard links".into());
        }
        Ok(())
    }
    pub(crate) fn arguments(&self, root: &Path) -> Result<Vec<String>> {
        self.validate(root)?;
        let path = self
            .path
            .to_str()
            .ok_or("data disk path must be UTF-8")?
            .replace(',', ",,");
        Ok(vec![
            "-device".into(),
            "isa-ide,id=evpio,iobase=0x1e8,iobase2=0x3ee,irq=10".into(),
            "-drive".into(),
            format!("if=none,id=evdata,format=raw,cache=writeback,snapshot=off,rerror=report,werror=report,file={path}"),
            "-device".into(),
            "ide-hd,drive=evdata,bus=evpio.0,unit=0,serial=EVROSION-M3-PIO,logical_block_size=512,physical_block_size=512".into(),
        ])
    }
    pub(crate) fn bytes(&self) -> Result<Vec<u8>> {
        self.validate(&self.root)?;
        let mut bytes = Vec::with_capacity(DISK_BYTES);
        File::open(&self.path)
            .map_err(|error| error.to_string())?
            .take(DISK_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() != DISK_BYTES {
            return Err("data disk size changed during read".into());
        }
        Ok(bytes)
    }
    pub(crate) fn capture(&self, evidence: &Path, name: &str) -> Result<Value> {
        let bytes = self.bytes()?;
        immutable_new(&evidence.join(name), &bytes)?;
        Ok(
            json!({"path":name,"bytes":bytes.len(),"sha256":digest(&bytes),
            "seed_sha256":digest(&bytes[..SECTOR_BYTES]),
            "record_sha256":digest(&bytes[SECTOR_BYTES..2*SECTOR_BYTES])}),
        )
    }
    fn check_committed(&self) -> Result<()> {
        let bytes = self.bytes()?;
        let expected = fixture(true);
        if let Some(index) = bytes
            .iter()
            .zip(&expected)
            .position(|(actual, expected)| actual != expected)
        {
            return Err(format!(
                "data disk differs at byte {index} (sector {}); only the exact sector1 record is permitted",
                index / SECTOR_BYTES
            ));
        }
        Ok(())
    }
    pub(crate) fn seal(&self) -> Result<()> {
        self.validate(&self.root)?;
        let mut permissions = fs::metadata(&self.path)
            .map_err(|error| error.to_string())?
            .permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&self.path, permissions).map_err(|error| error.to_string())
    }

    /// Only a runner-created disk can be initialized from an immutable test
    /// snapshot. The synchronous boot API has returned/reaped its child before
    /// this exclusive borrow permits another host write. No external path exists.
    pub(crate) fn restore_snapshot(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() != DISK_BYTES {
            return Err("journal baseline has the wrong size".into());
        }
        self.validate(&self.root)?;
        let mut file = OpenOptions::new()
            .write(true)
            .open(&self.path)
            .map_err(|error| error.to_string())?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| error.to_string())?;
        self.validate(&self.root)
    }

    /// Closed journal-fixture selector, not guest authority or a host disk path.
    pub(crate) fn journal_control(
        &mut self,
        control: ev_userspace_contract::store_test::Control,
    ) -> Result<()> {
        self.validate(&self.root)?;
        let mut file = OpenOptions::new()
            .write(true)
            .open(&self.path)
            .map_err(|error| error.to_string())?;
        file.seek(SeekFrom::Start((2 * SECTOR_BYTES) as u64))
            .and_then(|_| file.write_all(&control.encode()))
            .and_then(|()| file.sync_all())
            .map_err(|error| error.to_string())?;
        self.validate(&self.root)
    }

    pub(crate) fn generation_control(
        &mut self,
        control: ev_userspace_contract::generation::Control,
    ) -> Result<()> {
        self.validate(&self.root)?;
        let mut file = OpenOptions::new()
            .write(true)
            .open(&self.path)
            .map_err(|e| e.to_string())?;
        file.seek(SeekFrom::Start((2 * SECTOR_BYTES) as u64))
            .and_then(|_| file.write_all(&control.encode()))
            .and_then(|()| file.sync_all())
            .map_err(|e| e.to_string())?;
        self.validate(&self.root)
    }

    pub(crate) fn file_control(
        &mut self,
        control: ev_userspace_contract::file_test::Control,
    ) -> Result<()> {
        self.validate(&self.root)?;
        let mut file = OpenOptions::new()
            .write(true)
            .open(&self.path)
            .map_err(|e| e.to_string())?;
        file.seek(SeekFrom::Start((2 * SECTOR_BYTES) as u64))
            .and_then(|_| file.write_all(&control.encode()))
            .and_then(|()| file.sync_all())
            .map_err(|e| e.to_string())?;
        self.validate(&self.root)
    }
}

fn retained_manifest(root: &Path, directory: &Path, phase: Phase) -> Result<Manifest> {
    let bytes = fs::read(root.join("build/m0/manifest.json")).map_err(|error| error.to_string())?;
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    manifest.validate_policy_rows()?;
    if manifest.fixture.as_deref() != Some(phase.fixture()) {
        return Err("selected build does not match the storage phase".into());
    }
    immutable_new(&directory.join("manifest.json"), &bytes)?;
    Ok(manifest)
}

fn prepare_recorded(root: &Path, evidence: &Path) -> Result<Disk> {
    let preparation = (|| {
        #[cfg(unix)]
        fs::set_permissions(evidence, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
        Disk::create(root, evidence)
    })();
    match preparation {
        Ok(disk) => Ok(disk),
        Err(error) => {
            json_new(
                &evidence.join("results.json"),
                &json!({"schema":1,"kind":"storage-pio","passed":false,
                    "stage":"prepare","error":error,"phase_summaries":[]}),
            )
            .map_err(|record| {
                format!("{error}; failure evidence could not be written: {record}")
            })?;
            Err(error)
        }
    }
}

fn phase_summary(
    evidence: &Path,
    phase: Phase,
    stage: &str,
    operation: &Result<Value>,
    captured: &Result<Value>,
    validation: &Result<()>,
) -> Result<Value> {
    let summary = json!({"phase":phase,"fixture":phase.fixture(),"last_stage":stage,
        "passed":operation.is_ok() && captured.is_ok() && validation.is_ok(),
        "result":operation.as_ref().ok(),"error":operation.as_ref().err(),
        "disk":captured.as_ref().ok(),"capture_error":captured.as_ref().err(),
        "validation_error":validation.as_ref().err()});
    json_new(
        &evidence.join(phase.name()).join("phase-result.json"),
        &summary,
    )?;
    Ok(summary)
}

fn phase_links(evidence: &Path) -> Result<Vec<Value>> {
    [Phase::Write, Phase::Verify]
        .into_iter()
        .filter_map(|phase| {
            let relative = format!("{}/phase-result.json", phase.name());
            let path = evidence.join(&relative);
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Some(
                    build::hash_file(&path).map(|sha256| json!({"path":relative,"sha256":sha256})),
                ),
                Ok(_) => Some(Err("phase evidence is not a regular file".into())),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => Some(Err(error.to_string())),
            }
        })
        .collect()
}

fn run_case(root: &Path, evidence: &Path, disk: &Disk) -> Result<Value> {
    let initial = disk.capture(evidence, "data-before.raw")?;
    let mut phase_evidence = Vec::new();
    let mut source = None;
    let mut write_build = None;
    for phase in [Phase::Write, Phase::Verify] {
        let directory = evidence.join(phase.name());
        fs::create_dir(&directory).map_err(|error| error.to_string())?;
        let mut stage = "build";
        let operation = (|| {
            build::build(&BuildOptions {
                root: Some(root.to_owned()),
                fixture: Some(phase.fixture().into()),
                ..BuildOptions::default()
            })?;
            stage = "retain_manifest";
            let manifest = retained_manifest(root, &directory, phase)?;
            if let Some(expected) = &source {
                if expected != &manifest.source_sha256 {
                    return Err("source changed between storage phase builds".into());
                }
            } else {
                source = Some(manifest.source_sha256.clone());
                write_build = Some(manifest.build_id.clone());
            }
            if phase == Phase::Verify && write_build.as_ref() == Some(&manifest.build_id) {
                return Err("write and verify builds must have distinct identities".into());
            }
            stage = "boot";
            boot::boot_storage(
                &BootOptions {
                    root: Some(root.to_owned()),
                    timeout_seconds: LIMIT_SECONDS,
                    ..BootOptions::default()
                },
                StorageBoot {
                    manifest: &directory.join("manifest.json"),
                    evidence: &directory,
                    disk,
                    phase,
                    store: None,
                },
            )?;
            stage = "disk_validation";
            Ok(json!({"build_id":manifest.build_id,
                "manifest":format!("{}/manifest.json",phase.name()),
                "boot":format!("{}/boot/results.json",phase.name())}))
        })();
        // boot_storage reaps its QEMU child before returning, including failure.
        // Capture the phase's actual bytes even if build/boot/protocol failed.
        let captured = disk.capture(
            evidence,
            match phase {
                Phase::Write => "data-after-write.raw",
                Phase::Verify => "data-after-verify.raw",
            },
        );
        let validation = if operation.is_ok() {
            disk.check_committed()
        } else {
            Ok(())
        };
        phase_evidence.push(phase_summary(
            evidence,
            phase,
            stage,
            &operation,
            &captured,
            &validation,
        )?);
        operation?;
        captured?;
        validation?;
    }
    if phase_evidence[0]["disk"]["sha256"] != phase_evidence[1]["disk"]["sha256"] {
        return Err("verify phase changed the persistent disk".into());
    }
    Ok(json!({"initial_disk":initial,"phases":phase_evidence,
        "guard_sectors_unchanged":true,"only_sector1_changed":true,"verify_unchanged":true,
        "method":"Two fresh Q35/TCG/OVMF VMs, one separately attached persistent raw ISA PIO disk; not host physical power-loss acceptance."}))
}

/// Builds and boots only the two explicit test profiles. No external disk path,
/// QEMU device option, guest selector, or production storage policy is accepted.
pub fn run() -> Result<()> {
    let current = std::env::current_dir().map_err(|error| error.to_string())?;
    let root = crate::doctor::workspace(&current, None)?
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let parent = directory_beneath(&root, Path::new("build/m3/evidence"))?;
    let evidence = build::unique_directory(&parent, "storage-pio")?;
    // Report the location before any preparation/build/VM failure can occur.
    println!("Evidence: {}", evidence.display());
    let disk = prepare_recorded(&root, &evidence)?;
    let result = run_case(&root, &evidence, &disk);
    // Preserve post-failure bytes too; never reset or silently repair the fixture.
    let final_disk = disk.capture(&evidence, "data-final.raw");
    let seal = disk.seal();
    let phase_summaries = phase_links(&evidence);
    let passed = result.is_ok() && final_disk.is_ok() && seal.is_ok() && phase_summaries.is_ok();
    json_new(
        &evidence.join("results.json"),
        &json!({"schema":1,"kind":"storage-pio",
        "passed":passed,"result":result.as_ref().ok(),"error":result.as_ref().err(),
        "final_disk":final_disk.as_ref().ok(),"capture_error":final_disk.as_ref().err(),
        "phase_summaries":phase_summaries.as_ref().ok(),"phase_summary_error":phase_summaries.as_ref().err(),
        "seal_error":seal.as_ref().err(),"ports":["0x1e8..0x1ef","0x3ee"],"irq":10,
        "sector_bytes":SECTOR_BYTES,"sectors":SECTORS,"seed_lba":0,"record_lba":1}),
    )?;
    println!("Evidence: {}", evidence.display());
    result?;
    final_disk?;
    seal?;
    phase_summaries?;
    println!(
        "PASS storage-pio: actual write/flush and fresh-VM reopen, exact disk bytes verified."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            // All fixture writes remain inside this Evrosion repository.
            let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .canonicalize()
                .unwrap();
            let parent = directory_beneath(&root, Path::new("build/storage-host-tests")).unwrap();
            let path = parent.join(format!(
                "{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[cfg(unix)]
    #[test]
    fn network_and_document_disks_are_independent_and_never_replace_session_edits() {
        let root = Temp::new();
        let seed = fixture(false);
        let session = SessionDisk::open(&root.0, &seed).unwrap();
        let mut edited = seed.clone();
        edited[DISK_BYTES - 1] = 0xa7;
        fs::write(&session.disk.path, &edited).unwrap();
        let network = SessionDisk::open_network(&root.0, &seed).unwrap();
        assert!(network.created);
        assert_ne!(network.disk.path, session.disk.path);
        assert_eq!(network.disk.bytes().unwrap(), seed);
        let document = SessionDisk::open_document(&root.0, &seed).unwrap();
        assert!(document.created);
        assert_ne!(document.disk.path, network.disk.path);
        assert_ne!(document.disk.path, session.disk.path);
        assert_eq!(document.disk.bytes().unwrap(), seed);
        assert!(SessionDisk::open_document(&root.0, &seed).is_err());
        assert_eq!(session.disk.bytes().unwrap(), edited);
        assert!(SessionDisk::open_network(&root.0, &seed).is_err());
        drop(network);
        let reopened = SessionDisk::open_network(&root.0, &seed).unwrap();
        assert!(!reopened.created);
        assert_eq!(session.disk.bytes().unwrap(), edited);
    }
    #[cfg(unix)]
    #[test]
    fn document_boot_set_without_its_owned_disk_is_preserved_without_reinitialization() {
        let root = Temp::new();
        let directory =
            directory_beneath(&root.0, Path::new("build/m7/document-session/boot-set")).unwrap();
        immutable_new(&directory.join("retained.bin"), b"retained guest artifacts").unwrap();
        assert!(SessionDisk::open_document(&root.0, &fixture(false)).is_err());
        assert!(!directory.parent().unwrap().join("data.raw").exists());
        assert!(!directory.parent().unwrap().join("owner.json").exists());
        assert_eq!(
            fs::read(directory.join("retained.bin")).unwrap(),
            b"retained guest artifacts"
        );
    }
    #[cfg(unix)]
    #[test]
    fn session_reopens_only_its_original_disk_and_excludes_concurrent_owners() {
        let root = Temp::new();
        let seed = fixture(false);
        let mut session = SessionDisk::open(&root.0, &seed).unwrap();
        assert!(session.created);
        assert!(SessionDisk::open(&root.0, &seed).is_err());
        let mut edited = seed.clone();
        edited[1024] = 91; // Host ownership unit fixture, not a guest storage proof.
        session.disk.restore_snapshot(&edited).unwrap();
        // Model a forked child's reference to the same open-file description.
        // Dropping the session must release ownership even before that reference
        // is closed by exec; a second live SessionDisk still cannot acquire it.
        let inherited = session._lock.0.try_clone().unwrap();
        drop(session);
        let reopened = SessionDisk::open(&root.0, &seed).unwrap();
        assert!(!reopened.created);
        assert_eq!(reopened.disk.bytes().unwrap(), edited);
        drop(reopened);
        drop(inherited);
        let data = root.0.join("build/m6/session/data.raw");
        fs::rename(&data, data.with_extension("retained")).unwrap();
        fs::write(&data, &seed).unwrap();
        assert!(SessionDisk::open(&root.0, &seed).is_err());
        assert_eq!(fs::read(data.with_extension("retained")).unwrap(), edited);
    }
    #[cfg(unix)]
    #[test]
    fn session_never_formats_unowned_partial_or_foreign_state() {
        let root = Temp::new();
        let dir = directory_beneath(&root.0, Path::new("build/m6/session")).unwrap();
        let seed = fixture(false);
        let prior = vec![0x72; DISK_BYTES];
        fs::write(dir.join("data.raw"), &prior).unwrap();
        assert!(SessionDisk::open(&root.0, &seed).is_err());
        assert_eq!(fs::read(dir.join("data.raw")).unwrap(), prior);
        assert!(!dir.join("owner.json").exists());
        fs::remove_file(dir.join("data.raw")).unwrap();
        let owned = SessionDisk::open(&root.0, &seed).unwrap();
        drop(owned);
        let path = dir.join("owner.json");
        let mut owner: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        owner["workspace"] = json!("/different/workspace");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, serde_json::to_vec(&owner).unwrap()).unwrap();
        assert!(SessionDisk::open(&root.0, &seed).is_err());
        assert_eq!(fs::read(dir.join("data.raw")).unwrap(), seed);
        assert!(SessionDisk::open(&root.0, &[0; 1]).is_err());
    }
    #[test]
    fn exact_fixture_and_guard_sectors_are_enforced() {
        let root = Temp::new();
        let evidence = directory_beneath(&root.0, Path::new("evidence")).unwrap();
        let disk = Disk::create(&root.0, &evidence).unwrap();
        assert_eq!(disk.bytes().unwrap(), fixture(false));
        assert!(disk.check_committed().is_err());
        fs::write(&disk.path, fixture(true)).unwrap();
        disk.check_committed().unwrap();
        let mut damaged = fixture(true);
        damaged[4096] = 1;
        fs::write(&disk.path, damaged).unwrap();
        assert!(disk.check_committed().unwrap_err().contains("sector 8"));
    }
    #[test]
    fn one_runner_owned_persistent_backend_has_fixed_ports_and_no_snapshot() {
        let root = Temp::new();
        let evidence = directory_beneath(&root.0, Path::new("evidence,comma")).unwrap();
        let disk = Disk::create(&root.0, &evidence).unwrap();
        let arguments = disk.arguments(&root.0).unwrap();
        assert_eq!(arguments.len(), 6);
        assert_eq!(
            arguments[1],
            "isa-ide,id=evpio,iobase=0x1e8,iobase2=0x3ee,irq=10"
        );
        assert!(arguments[3].contains("format=raw,cache=writeback,snapshot=off"));
        assert!(arguments[3].contains("evidence,,comma"));
        assert!(arguments[5].contains("bus=evpio.0,unit=0"));
        assert!(Disk::create(&root.0, &evidence).is_err());
    }
    #[test]
    fn traversal_absolute_foreign_and_size_changes_are_denied() {
        let root = Temp::new();
        for path in ["../escape", "/absolute", "a/../b", ""] {
            assert!(directory_beneath(&root.0, Path::new(path)).is_err());
        }
        let evidence = directory_beneath(&root.0, Path::new("evidence")).unwrap();
        let disk = Disk::create(&root.0, &evidence).unwrap();
        assert!(disk.arguments(root.0.parent().unwrap()).is_err());
        fs::write(&disk.path, [0]).unwrap();
        assert!(disk.arguments(&root.0).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn symlink_components_replacement_and_hardlink_aliases_are_denied() {
        use std::os::unix::fs::symlink;
        let root = Temp::new();
        let real = directory_beneath(&root.0, Path::new("real")).unwrap();
        symlink(&real, root.0.join("alias")).unwrap();
        assert!(directory_beneath(&root.0, Path::new("alias/nested")).is_err());
        let disk = Disk::create(&root.0, &real).unwrap();
        fs::hard_link(&disk.path, root.0.join("hardlink.raw")).unwrap();
        assert!(disk.arguments(&root.0).is_err());
        fs::remove_file(root.0.join("hardlink.raw")).unwrap();
        fs::rename(&disk.path, real.join("old.raw")).unwrap();
        fs::write(&disk.path, fixture(false)).unwrap();
        assert!(disk.arguments(&root.0).is_err());
        fs::remove_file(&disk.path).unwrap();
        symlink(real.join("old.raw"), &disk.path).unwrap();
        assert!(disk.arguments(&root.0).is_err());
    }
    #[test]
    fn evidence_cannot_overwrite_a_prior_snapshot() {
        let root = Temp::new();
        let path = root.0.join("record.json");
        json_new(&path, &json!({"passed":false})).unwrap();
        assert!(json_new(&path, &json!({"passed":true})).is_err());
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(path).unwrap()).unwrap(),
            json!({"passed":false})
        );
    }

    #[test]
    fn concurrent_directory_creation_retains_the_same_repository_boundary() {
        let root = Temp::new();
        let barrier = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for _ in 0..8 {
                workers.push(scope.spawn(|| {
                    barrier.wait();
                    directory_beneath(&root.0, Path::new("concurrent/nested"))
                }));
            }
            for worker in workers {
                assert_eq!(
                    worker.join().unwrap().unwrap(),
                    root.0.join("concurrent/nested")
                );
            }
        });
    }

    #[test]
    fn preparation_failure_is_recorded_without_touching_a_preexisting_file() {
        let root = Temp::new();
        let evidence = directory_beneath(&root.0, Path::new("evidence")).unwrap();
        let prior = b"preexisting fixture must remain untouched";
        fs::write(evidence.join("data.raw"), prior).unwrap();
        assert!(prepare_recorded(&root.0, &evidence).is_err());
        assert_eq!(fs::read(evidence.join("data.raw")).unwrap(), prior);
        let bytes = fs::read(evidence.join("results.json")).unwrap();
        let result: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result["passed"], false);
        assert_eq!(result["stage"], "prepare");
        assert!(result["error"].as_str().is_some());
        // A retry cannot overwrite the retained failure, either.
        assert!(prepare_recorded(&root.0, &evidence).is_err());
        assert_eq!(fs::read(evidence.join("results.json")).unwrap(), bytes);
    }

    #[test]
    fn failed_phase_summary_retains_actual_bytes_and_cannot_replace_prior_evidence() {
        let root = Temp::new();
        let evidence = directory_beneath(&root.0, Path::new("evidence")).unwrap();
        let disk = Disk::create(&root.0, &evidence).unwrap();
        fs::create_dir(evidence.join("write")).unwrap();
        // This is host error injection before VM admission, not a guest proof.
        let operation = Err("deliberate host build failure".into());
        let captured = disk.capture(&evidence, "data-after-write.raw");
        let result = phase_summary(
            &evidence,
            Phase::Write,
            "build",
            &operation,
            &captured,
            &Ok(()),
        )
        .unwrap();
        assert_eq!(result["passed"], false);
        assert_eq!(result["error"], "deliberate host build failure");
        assert_eq!(result["disk"]["sha256"], digest(&fixture(false)));
        let links = phase_links(&evidence).unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0]["path"], "write/phase-result.json");
        assert!(
            phase_summary(
                &evidence,
                Phase::Write,
                "boot",
                &Ok(json!({})),
                &captured,
                &Ok(())
            )
            .is_err()
        );
        assert_eq!(phase_links(&evidence).unwrap(), links);
        assert_eq!(disk.bytes().unwrap(), fixture(false));
    }
}
