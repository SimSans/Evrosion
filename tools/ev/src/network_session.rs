//! The manual front door reuses one complete measured owner boot set under the
//! existing persistent-disk lock. Missing or incompatible state is preserved.
use crate::{
    build::{self, Manifest, Result},
    cli::BuildOptions,
    download_fixture,
    network_io::{
        acquisition_disk::system_health::selector::{self, Selection},
        components::Context,
    },
    network_mode::Mode,
    restart_protocol::Intent,
    storage,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

const DIRECTORY: &str = "build/m6/network-session/boot-set";
const LIMIT: u64 = 2 * 1024 * 1024;
// Unreleased owner sets before this policy lack first-use selection guards.
const BOOT_SET_SCHEMA: u32 = 2;
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u32,
    source_sha256: String,
    manifests: [String; 3],
    bundle_directory: String,
    bundle_sha256: String,
}
pub(crate) struct BootSet {
    pub manifests: [Manifest; 3],
    paths: [PathBuf; 3],
    contexts: [Context; 3],
    pub bundle: download_fixture::Bundle,
    root_pin: Vec<u8>,
}
fn regular(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() == 0 || meta.len() > limit {
        return Err("retained boot set requires bounded regular files".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() != 1 {
            return Err("retained boot set refuses external hard links".into());
        }
    }
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    if bytes.is_empty() || bytes.len() as u64 > limit {
        return Err("retained boot set read bound".into());
    }
    Ok(bytes)
}
fn existing_directory(root: &Path, relative: &Path) -> Result<PathBuf> {
    let mut path = root.to_owned();
    for part in relative.components() {
        if !matches!(part, std::path::Component::Normal(_)) {
            return Err("retained boot set path".into());
        }
        path.push(part);
        let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err("retained boot set directory identity".into());
        }
    }
    Ok(path)
}
fn manifest(bytes: &[u8], mode: Mode) -> Result<Manifest> {
    let manifest: Manifest =
        serde_json::from_slice(bytes).map_err(|e| format!("retained boot manifest: {e}"))?;
    manifest.validate_policy_rows()?;
    if manifest.fixture.as_deref() != Some(mode.owner_fixture()) || manifest.profile != "release" {
        return Err("manual owner session requires exact optimized owner mode".into());
    }
    Ok(manifest)
}
fn verify_artifacts(root: &Path, manifest: &Manifest) -> Result<()> {
    let output = existing_directory(root, Path::new("build/m0"))?;
    for item in [
        &manifest.kernel,
        &manifest.image,
        &manifest.loader,
        &manifest.image_builder,
    ]
    .into_iter()
    .chain(manifest.supervisor.iter())
    {
        build::verify_artifact(&output, item)?;
    }
    Ok(())
}
impl BootSet {
    pub(crate) fn prepare(
        root: &Path,
        disk: &storage::SessionDisk,
        evidence: &Path,
    ) -> Result<Self> {
        Self::prepare_at(root, &root.join(DIRECTORY), disk.created, evidence)
    }
    pub(crate) fn fresh(root: &Path, evidence: &Path) -> Result<Self> {
        Self::prepare_at(root, &evidence.join("boot-set"), true, evidence)
    }
    fn prepare_at(root: &Path, directory: &Path, created: bool, evidence: &Path) -> Result<Self> {
        if !directory.try_exists().map_err(|e| e.to_string())? {
            if !created {
                return Err("existing developer disk has no protected owner boot set; retained without migration or formatting".into());
            }
            let source = build::source_inputs(root)?;
            let directory = storage::directory_beneath(
                root,
                directory
                    .strip_prefix(root)
                    .map_err(|_| "owner boot set escaped workspace")?,
            )?;
            let mut hashes = Vec::new();
            for mode in Mode::ALL {
                build::build(&BuildOptions {
                    root: Some(root.to_owned()),
                    release: true,
                    fixture: Some(mode.owner_fixture().into()),
                })?;
                let bytes = regular(&root.join("build/m0/manifest.json"), LIMIT)?;
                let measured = manifest(&bytes, mode)?;
                if (
                    measured.source_sha256.as_str(),
                    measured.source_inputs.as_slice(),
                ) != (source.0.as_str(), source.1.as_slice())
                    || build::source_inputs(root)? != source
                {
                    return Err("source changed while preparing all three owner modes; disk retained without launch".into());
                }
                verify_artifacts(root, &measured)?;
                let mode_dir =
                    storage::directory_beneath(&directory, Path::new(mode.owner_fixture()))?;
                let path = mode_dir.join("manifest.json");
                storage::immutable_new(&path, &bytes)?;
                hashes.push(build::hash_file(&path)?);
            }
            let bundle_directory = format!(
                "network-owner-{}",
                evidence
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or("owner evidence name")?
            );
            let downloads = storage::directory_beneath(root, Path::new("build/m6/downloads"))?;
            let bundle_path = downloads.join(&bundle_directory);
            download_fixture::produce(root, &bundle_path, &source.0)?;
            storage::immutable_new(
                &directory.join("development-root.bin"),
                &regular(&root.join(crate::development_release::ROOT_FILE), 8192)?,
            )?;
            storage::json_new(
                &directory.join("boot-set.json"),
                &Record {
                    schema: BOOT_SET_SCHEMA,
                    source_sha256: source.0,
                    manifests: hashes.try_into().map_err(|_| "owner mode count")?,
                    bundle_directory,
                    bundle_sha256: build::hash_file(&bundle_path.join("download-manifest.json"))?,
                },
            )?;
        }
        Self::load(root, directory, evidence)
    }
    fn load(root: &Path, directory: &Path, evidence: &Path) -> Result<Self> {
        let directory = existing_directory(
            root,
            directory
                .strip_prefix(root)
                .map_err(|_| "owner boot set escaped workspace")?,
        )?;
        let record: Record =
            serde_json::from_slice(&regular(&directory.join("boot-set.json"), 4096)?)
                .map_err(|e| format!("retained owner boot set: {e}"))?;
        if record.schema != BOOT_SET_SCHEMA {
            return Err(format!(
                "owner boot set schema {} is unsupported by setup policy {}; preserved disk {} and boot set {}. Keep the matching artifacts and use explicit recovery guidance in docs/development/OWNER_BOOTSET_POLICY_02.md; no automatic migration or formatting",
                record.schema,
                BOOT_SET_SCHEMA,
                root.join("build/m6/network-session/data.raw").display(),
                directory.display()
            ));
        }
        let mut manifests = Vec::new();
        let mut paths = Vec::new();
        let mut contexts = Vec::new();
        for mode in Mode::ALL {
            let directory = existing_directory(&directory, Path::new(mode.owner_fixture()))?;
            let path = directory.join("manifest.json");
            let bytes = regular(&path, LIMIT)?;
            if build::hash_file(&path)? != record.manifests[mode.index()] {
                return Err("retained owner manifest identity changed".into());
            }
            let measured = manifest(&bytes, mode)?;
            if measured.source_sha256 != record.source_sha256 {
                return Err("retained owner modes have different source identities".into());
            }
            verify_artifacts(root, &measured)?;
            let audit = storage::directory_beneath(evidence, Path::new(mode.owner_fixture()))?;
            let context = Context::retain_mode(root, &measured, &audit, mode, true)?;
            let kernel = build::verify_artifact(&root.join("build/m0"), &measured.kernel)?;
            let status = std::process::Command::new("python3")
                .current_dir(root)
                .arg(root.join("tools/m5/stack_audit.py"))
                .arg(kernel)
                .arg(audit.join("kernel-stack.json"))
                .status()
                .map_err(|e| e.to_string())?;
            if !status.success() {
                return Err("retained owner mode linked-stack preflight failed".into());
            }
            manifests.push(measured);
            paths.push(path);
            contexts.push(context);
        }
        let manifests: [Manifest; 3] = manifests.try_into().map_err(|_| "owner mode count")?;
        let contexts: [Context; 3] = contexts.try_into().map_err(|_| "owner mode count")?;
        for i in 1..3 {
            if manifests[i].source_inputs != manifests[0].source_inputs
                || contexts[i].images != contexts[0].images
                || ev_root_supervisor::native_plan::system::catalogue_recipe(
                    &contexts[i].packages()?,
                ) != ev_root_supervisor::native_plan::system::catalogue_recipe(
                    &contexts[0].packages()?,
                )
            {
                return Err(
                    "three owner modes do not share one exact protected component/source recipe"
                        .into(),
                );
            }
        }
        let relative = Path::new(&record.bundle_directory);
        if relative.components().count() != 1
            || !matches!(
                relative.components().next(),
                Some(std::path::Component::Normal(_))
            )
        {
            return Err("retained owner download directory shape".into());
        }
        let downloads = existing_directory(root, Path::new("build/m6/downloads"))?;
        let bundle_path = existing_directory(&downloads, relative)?;
        let bundle_manifest = regular(&bundle_path.join("download-manifest.json"), LIMIT)?;
        if build::hash_file(&bundle_path.join("download-manifest.json"))? != record.bundle_sha256 {
            return Err("retained download bundle identity changed".into());
        }
        let bundle: download_fixture::Bundle =
            serde_json::from_slice(&bundle_manifest).map_err(|e| e.to_string())?;
        if bundle.source_sha256 != record.source_sha256
            || bundle.downloads[0].package.parent() != Some(bundle_path.as_path())
        {
            return Err("retained download bundle source/owner differs".into());
        }
        download_fixture::validate_bundle(root, &bundle)?;
        crate::acquisition_io::absent_from_banks(&contexts[0], &bundle)?;
        let root_pin = regular(&directory.join("development-root.bin"), 8192)?;
        if manifests[0]
            .source_inputs
            .iter()
            .find(|r| r.path == crate::development_release::ROOT_FILE)
            .map(|r| r.sha256.as_str())
            != Some(crate::acquisition_io::hash(&root_pin).as_str())
        {
            return Err("retained public Root differs from protected source inventory".into());
        }
        Ok(Self {
            manifests,
            paths: paths.try_into().map_err(|_| "owner mode count")?,
            contexts,
            bundle,
            root_pin,
        })
    }
    pub(crate) fn publish_b(
        &self,
        root: &Path,
        bytes: &[u8],
        evidence: &Path,
    ) -> Result<Option<download_fixture::PhaseFixture>> {
        self.publish_b_from(root, root, bytes, evidence)
    }
    pub(crate) fn publish_b_from(
        &self,
        root: &Path,
        signer: &Path,
        bytes: &[u8],
        evidence: &Path,
    ) -> Result<Option<download_fixture::PhaseFixture>> {
        self.selection(bytes)?;
        let Some(version) = selector::author_version(bytes)? else {
            return Ok(None);
        };
        let authority = crate::acquisition_io::authority(root, signer)?;
        if authority.root() != self.root_pin {
            return Err("available DEV signer differs from retained source public Root".into());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();
        let author = download_fixture::Author {
            version,
            not_before: now.saturating_sub(5),
            expires: now.checked_add(595).ok_or("DEV author label overflow")?,
        };
        download_fixture::sign_phase(
            root,
            &self.bundle,
            &authority,
            download_fixture::FixturePhase::B,
            author,
            &evidence.join("public-dev-b"),
        )
        .map(Some)
    }
    pub(crate) fn context(&self, mode: Mode) -> &Context {
        &self.contexts[mode.index()]
    }
    pub(crate) fn path(&self, mode: Mode) -> &Path {
        &self.paths[mode.index()]
    }
    pub(crate) fn selection(&self, bytes: &[u8]) -> Result<Selection> {
        selector::observe(bytes, &self.contexts[Mode::Standalone.index()].packages()?)
    }
    pub(crate) fn initial_mode(&self, bytes: &[u8]) -> Result<Mode> {
        Ok(match self.selection(bytes)? {
            Selection::Unformatted => Mode::Standalone,
            Selection::Committed { .. } => Mode::SystemManaged,
            Selection::Recovery { .. } => Mode::Recovery,
        })
    }
    pub(crate) fn restart_mode(&self, bytes: &[u8], intent: &Intent) -> Result<Mode> {
        match self.selection(bytes)? {
            Selection::Committed { selected, .. } if selected.generation.get() == u64::from(intent.generation) => Ok(Mode::SystemManaged),
            _ => Err("authenticated restart intent does not match actual durable selected manifest; no relaunch".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn existing_owned_disk_without_boot_set_is_preserved_and_never_migrated() {
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let root =
            build::unique_directory(&repo.join("build/test-tmp"), "owner-bootset-preservation")
                .unwrap();
        let seed = vec![0x37; storage::DISK_BYTES];
        let first = storage::SessionDisk::open_network(&root, &seed).unwrap();
        drop(first);
        let retained =
            storage::SessionDisk::open_network(&root, &vec![0; storage::DISK_BYTES]).unwrap();
        let evidence = storage::directory_beneath(&root, Path::new("build/evidence")).unwrap();
        let before = retained.disk.bytes().unwrap();
        assert!(BootSet::prepare(&root, &retained, &evidence).is_err());
        assert_eq!(retained.disk.bytes().unwrap(), before);
        assert!(!root.join(DIRECTORY).exists());
        drop(retained);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn schema1_boot_set_is_preserved_and_refused_before_artifact_or_disk_use() {
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let root = build::unique_directory(&repo.join("build/test-tmp"), "owner-schema1-preserved")
            .unwrap();
        let seed = vec![0x37; storage::DISK_BYTES];
        let disk = storage::SessionDisk::open_network(&root, &seed).unwrap();
        let directory = storage::directory_beneath(&root, Path::new(DIRECTORY)).unwrap();
        let record = Record {
            schema: 1,
            source_sha256: "0".repeat(64),
            manifests: core::array::from_fn(|_| "0".repeat(64)),
            bundle_directory: "old-retained-downloads".into(),
            bundle_sha256: "0".repeat(64),
        };
        let path = directory.join("boot-set.json");
        storage::json_new(&path, &record).unwrap();
        let record_before = fs::read(&path).unwrap();
        let disk_before = disk.disk.bytes().unwrap();
        let evidence = storage::directory_beneath(&root, Path::new("build/evidence")).unwrap();
        let error = BootSet::prepare(&root, &disk, &evidence)
            .err()
            .expect("old schema must refuse");
        assert!(
            error.contains("schema 1")
                && error.contains("preserved disk")
                && error.contains("OWNER_BOOTSET_POLICY_02.md")
        );
        assert_eq!(fs::read(&path).unwrap(), record_before);
        assert_eq!(disk.disk.bytes().unwrap(), disk_before);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        drop(disk);
        fs::remove_dir_all(root).unwrap();
    }
}
