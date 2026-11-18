//! Retained offline document front door. One owned disk and its exact guest
//! cohort remain together; later launches neither rebuild nor rebind its data.
use crate::{
    boot::{self, DocumentBoot, DocumentGuideBoot},
    build::{self, Artifact, Manifest, Result},
    cli::{BootOptions, BuildOptions},
    document_guide::Phase,
    storage,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
};

const DIRECTORY: &str = "build/m7/document-session/boot-set";
pub(crate) const ARTIFACTS: &str = "build/m7/document-session/boot-set/artifacts";
const FIXTURE: &str = "m7-document-session";
const MANIFEST_LIMIT: u64 = 2 * 1024 * 1024;
const ARTIFACT_LIMIT: u64 = 64 * 1024 * 1024;
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u32,
    source_sha256: String,
    build_id: String,
    manifest_sha256: String,
}
struct BootSet {
    manifest: Manifest,
    path: PathBuf,
}
fn relative(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() || !path.components().all(|p| matches!(p, Component::Normal(_)))
    {
        return Err("document boot set path must be relative without traversal".into());
    }
    Ok(())
}
fn existing(root: &Path, path: &Path, file: bool) -> Result<PathBuf> {
    relative(path)?;
    let mut checked = root.to_owned();
    let mut parts = path.components().peekable();
    while let Some(part) = parts.next() {
        checked.push(part);
        let meta = fs::symlink_metadata(&checked).map_err(|e| {
            format!(
                "retained document state {}: {e}; preserved without reset",
                checked.display()
            )
        })?;
        if meta.file_type().is_symlink()
            || if parts.peek().is_none() && file {
                !meta.is_file()
            } else {
                !meta.is_dir()
            }
        {
            return Err("retained document state requires regular files and real directories; preserved without reset".into());
        }
    }
    Ok(checked)
}
fn regular(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > limit {
        return Err("retained document input is nonregular or oversized".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() != 1 {
            return Err("retained document input refuses external hard links".into());
        }
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("retained document input grew beyond bound".into());
    }
    Ok(bytes)
}
fn manifest(bytes: &[u8]) -> Result<Manifest> {
    let manifest: Manifest =
        serde_json::from_slice(bytes).map_err(|e| format!("retained document manifest: {e}"))?;
    manifest.validate_policy_rows()?;
    if manifest.schema != 1
        || manifest.fixture.as_deref() != Some(FIXTURE)
        || manifest.profile != "release"
        || !manifest.qemu_test_exit
        || manifest.supervisor.is_empty()
        || manifest.supervisor.len() > 512
    {
        return Err(
            "manual document session requires the exact optimized private-diagnostics profile"
                .into(),
        );
    }
    Ok(manifest)
}
fn artifacts(manifest: &Manifest) -> impl Iterator<Item = &Artifact> {
    [
        &manifest.kernel,
        &manifest.image,
        &manifest.loader,
        &manifest.image_builder,
    ]
    .into_iter()
    .chain(manifest.supervisor.iter())
}
fn verify_artifacts(output: &Path, manifest: &Manifest) -> Result<()> {
    let mut paths = BTreeSet::new();
    let mut total = 0usize;
    for artifact in artifacts(manifest) {
        if !paths.insert(&artifact.path) {
            return Err("retained document artifact path duplicated".into());
        }
        let path = existing(output, Path::new(&artifact.path), true)?;
        let bytes = regular(&path, ARTIFACT_LIMIT)?;
        total = total
            .checked_add(bytes.len())
            .ok_or("retained document artifact size overflow")?;
        if total > 256 * 1024 * 1024 {
            return Err("retained document artifact set exceeds256MiB".into());
        }
        build::verify_artifact(output, artifact)?;
    }
    Ok(())
}
impl BootSet {
    fn prepare(root: &Path, disk: &storage::SessionDisk, evidence: &Path) -> Result<Self> {
        let directory = root.join(DIRECTORY);
        match fs::symlink_metadata(&directory) {
            Ok(_) => return Self::load(root, evidence),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.to_string()),
        }
        if !disk.created {
            return Err("existing document disk has no complete retained boot set; preserved without migration, rebuilding or formatting".into());
        }
        let source = build::source_inputs(root)?;
        build::build(&BuildOptions {
            root: Some(root.to_owned()),
            release: true,
            fixture: Some(FIXTURE.into()),
        })?;
        let bytes = regular(&root.join("build/m0/manifest.json"), MANIFEST_LIMIT)?;
        let measured = manifest(&bytes)?;
        if (
            measured.source_sha256.as_str(),
            measured.source_inputs.as_slice(),
        ) != (source.0.as_str(), source.1.as_slice())
            || build::source_inputs(root)? != source
        {
            return Err(
                "source changed while preparing document boot set; disk preserved without launch"
                    .into(),
            );
        }
        let output = existing(root, Path::new("build/m0"), false)?;
        verify_artifacts(&output, &measured)?;
        let directory = storage::directory_beneath(root, Path::new(DIRECTORY))?;
        let retained = storage::directory_beneath(root, Path::new(ARTIFACTS))?;
        for artifact in artifacts(&measured) {
            let relative = Path::new(&artifact.path);
            let parent = storage::directory_beneath(
                &retained,
                relative.parent().ok_or("document artifact has no parent")?,
            )?;
            storage::immutable_new(
                &parent.join(relative.file_name().ok_or("document artifact name")?),
                &regular(&existing(&output, relative, true)?, ARTIFACT_LIMIT)?,
            )?;
        }
        let path = directory.join("manifest.json");
        storage::immutable_new(&path, &bytes)?;
        verify_artifacts(&retained, &measured)?;
        storage::json_new(
            &directory.join("boot-set.json"),
            &Record {
                schema: 1,
                source_sha256: measured.source_sha256,
                build_id: measured.build_id,
                manifest_sha256: build::hash_file(&path)?,
            },
        )?;
        Self::load(root, evidence)
    }
    fn load(root: &Path, evidence: &Path) -> Result<Self> {
        let directory = existing(root, Path::new(DIRECTORY), false)?;
        let record: Record = serde_json::from_slice(&regular(
            &existing(&directory, Path::new("boot-set.json"), true)?,
            4096,
        )?)
        .map_err(|e| {
            format!("incomplete retained document boot set: {e}; preserved without reset")
        })?;
        let path = existing(&directory, Path::new("manifest.json"), true)?;
        if record.schema != 1 || build::hash_file(&path)? != record.manifest_sha256 {
            return Err("retained document boot-set schema/manifest identity differs; preserved without reset".into());
        }
        let measured = manifest(&regular(&path, MANIFEST_LIMIT)?)?;
        if measured.source_sha256 != record.source_sha256 || measured.build_id != record.build_id {
            return Err(
                "retained document source/build binding differs; preserved without reset".into(),
            );
        }
        let output = existing(root, Path::new(ARTIFACTS), false)?;
        verify_artifacts(&output, &measured)?;
        let kernel = build::verify_artifact(&output, &measured.kernel)?;
        let status = Command::new("python3")
            .current_dir(root)
            .arg(root.join("tools/m5/stack_audit.py"))
            .arg(kernel)
            .arg(evidence.join("kernel-stack.json"))
            .stdin(Stdio::null())
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err("retained document linked-stack preflight failed".into());
        }
        storage::json_new(
            &evidence.join("boot-set-binding.json"),
            &json!({"schema":1,"record":record,
            "manifest":path,"artifact_root":output,"rebuild_on_reopen":false,"source_rebound":false,
            "scope":"Exact retained guest cohort and original Native3 creation catalogue; current host sources do not replace these guest artifacts."}),
        )?;
        Ok(Self {
            manifest: measured,
            path,
        })
    }
}

pub(crate) fn run(guide: bool) -> Result<()> {
    let root =
        crate::doctor::workspace(&std::env::current_dir().map_err(|e| e.to_string())?, None)?
            .canonicalize()
            .map_err(|e| e.to_string())?;
    let options = BootOptions {
        root: Some(root.clone()),
        timeout_seconds: 240,
        ..BootOptions::default()
    };
    crate::native_workflow::preview_host(&options)?;
    let parent = storage::directory_beneath(&root, Path::new("build/m7/evidence"))?;
    let evidence = build::unique_directory(
        &parent,
        if guide {
            "document-session-guide"
        } else {
            "document-session"
        },
    )?;
    println!("Evidence: {}", evidence.display());
    let (seed, provenance) = crate::native_seed::checkpoint(&root, &evidence)?;
    let retained = storage::SessionDisk::open_document(&root, &seed)?;
    let set = BootSet::prepare(&root, &retained, &evidence)?;
    let owner_before = retained.disk.bytes()?;
    if guide {
        let mut disk = storage::Disk::create(&root, &evidence)?;
        disk.restore_snapshot(&seed)?;
        disk.capture(&evidence, "data-before.raw")?;
        println!(
            "Explicit scripted graphical guide qualification on a NEW test disk. The retained manual disk receives no test input."
        );
        let result: Result<serde_json::Value> = (|| {
            boot::boot_document_guide(
                &options,
                DocumentGuideBoot {
                    manifest: &set.path,
                    evidence: &evidence,
                    disk: &disk,
                    phase: Phase::Exercise,
                },
            )?;
            let saved = disk.bytes()?;
            let proof = crate::native3_disk::document(&saved, 1, crate::document_guide::SAVED)?;
            disk.capture(&evidence, "data-saved.raw")?;
            let cold = storage::directory_beneath(&evidence, Path::new("cold"))?;
            boot::boot_document_guide(
                &options,
                DocumentGuideBoot {
                    manifest: &set.path,
                    evidence: &cold,
                    disk: &disk,
                    phase: Phase::Cold,
                },
            )?;
            if disk.bytes()? != saved {
                return Err("graphical cold reopen changed the saved disk".into());
            }
            if retained.disk.bytes()? != owner_before {
                return Err("guide qualification changed the manual disk".into());
            }
            Ok(proof)
        })();
        let after = disk.capture(&evidence, "data-after.raw");
        storage::json_new(
            &evidence.join("results.json"),
            &json!({"schema":1,"kind":"scripted-graphical-document-guide",
            "passed":result.is_ok()&&after.is_ok(),"scripted_input":true,"human_acceptance":false,
            "fixture":FIXTURE,"source_sha256":set.manifest.source_sha256,"build_id":set.manifest.build_id,
            "seed":provenance,"file":result.as_ref().ok(),"error":result.as_ref().err(),"after":after.as_ref().ok(),
            "retained_manual_disk_unchanged":retained.disk.bytes()?==owner_before,
            "scope":"Actual GTK/no-document-observer profile; real QMP device input, original pixels and independent raw Store proof. Separate from human acceptance."}),
        )?;
        result?;
        after?;
        disk.seal()?;
    } else {
        let before = retained.disk.capture(&evidence, "data-before.raw")?;
        println!(
            "Evrosion offline document session. Press Enter to launch the app, then Open for editing and confirm the exact document in the trusted picker.\nThe document disk and exact guest boot set are retained. This launch sends no input. Type 'finish' in this terminal for checked shutdown; closing the window interrupts the VM.\nGuide: docs/development/DOCUMENT_SESSION.md"
        );
        let result = boot::boot_document(
            &options,
            DocumentBoot {
                manifest: &set.path,
                evidence: &evidence,
                disk: &retained.disk,
                phase: None,
            },
        );
        let after = retained.disk.capture(&evidence, "data-after.raw");
        storage::json_new(
            &evidence.join("results.json"),
            &json!({"schema":1,"kind":"manual-offline-document-session",
            "passed":result.is_ok()&&after.is_ok(),"scripted_input":false,"human_acceptance":false,
            "created_disk":retained.created,"fixture":FIXTURE,"build_id":set.manifest.build_id,"source_sha256":set.manifest.source_sha256,
            "seed":provenance,"before":before,"after":after.as_ref().ok(),"error":result.as_ref().err(),
            "document_text_serial_observer":false,"rebuild_on_reopen":false}),
        )?;
        result?;
        after?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_disk_without_complete_boot_set_is_never_rebuilt_or_reset() {
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let root =
            build::unique_directory(&repo.join("build/test-tmp"), "document-preservation").unwrap();
        let seed = vec![0x37; storage::DISK_BYTES];
        let first = storage::SessionDisk::open_document(&root, &seed).unwrap();
        drop(first);
        let retained =
            storage::SessionDisk::open_document(&root, &vec![0; storage::DISK_BYTES]).unwrap();
        let before = retained.disk.bytes().unwrap();
        let evidence = storage::directory_beneath(&root, Path::new("build/evidence")).unwrap();
        assert!(BootSet::prepare(&root, &retained, &evidence).is_err());
        assert_eq!(retained.disk.bytes().unwrap(), before);
        assert!(!root.join(DIRECTORY).exists());
        let directory = storage::directory_beneath(&root, Path::new(DIRECTORY)).unwrap();
        storage::immutable_new(&directory.join("partial.bin"), b"preserve partial state").unwrap();
        assert!(BootSet::prepare(&root, &retained, &evidence).is_err());
        assert_eq!(retained.disk.bytes().unwrap(), before);
        assert_eq!(
            fs::read(directory.join("partial.bin")).unwrap(),
            b"preserve partial state"
        );
        assert_eq!(fs::read_dir(directory).unwrap().count(), 1);
        drop(retained);
        fs::remove_dir_all(root).unwrap();
    }
}
