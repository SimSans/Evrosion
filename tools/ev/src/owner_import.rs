//! Read-only import of an earlier measured owner Prepare3 receipt. The caller
//! must restore the returned bytes only into a NEW runner-owned private disk.
//! Hashes establish retained development-build consistency, not publisher trust.
use crate::{
    boot_protocol,
    build::{self, Artifact, Manifest},
    generation as g,
    journal::{ReadOnlyRegion, SNAPSHOT_DEADLINE, unchanged_guards},
    owner_protocol, storage,
};
use ev_store::{GenerationId, LastFailure, LastFailureReason, ObjectId, Store};
use ev_userspace_contract::generation::{
    Catalogue, Completion, Control, HEALTH_DESCRIPTION, Mode, OwnerDecision, Slot,
};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::Read,
    path::{Component, Path, PathBuf},
};

type Result<T> = std::result::Result<T, String>;
const JSON_LIMIT: usize = 1024 * 1024;
const ARTIFACT_LIMIT: u64 = 128 * 1024 * 1024;

pub(crate) struct Prepared {
    pub(crate) manifest: Manifest,
    pub(crate) manifest_bytes: Vec<u8>,
    pub(crate) catalogue: Catalogue,
    pub(crate) catalogue_hash: [u8; 32],
    pub(crate) snapshot: Vec<u8>,
    pub(crate) failure: LastFailure,
    /// The actual earlier Prepare3 report, never a manufactured EOF completion.
    pub(crate) report: Completion,
    pub(crate) origin: Value,
}

/// Existing paths only. Inspect every component before following it; never
/// create an input directory or canonicalize away an input symlink/traversal.
fn existing(root: &Path, path: &Path, directory: bool) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        root.join(path)
    };
    let relative = path
        .strip_prefix(root)
        .map_err(|_| "owner import escaped repository")?;
    let components: Vec<_> = relative.components().collect();
    if components.is_empty()
        || !components
            .iter()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err("owner import path must have only normal repository components".into());
    }
    let mut current = root.to_owned();
    for (index, component) in components.iter().enumerate() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|error| error.to_string())?;
        let want_directory = directory || index + 1 != components.len();
        if metadata.file_type().is_symlink()
            || if want_directory {
                !metadata.is_dir()
            } else {
                !metadata.is_file()
            }
        {
            return Err(format!(
                "owner import requires an existing regular path: {}",
                current.display()
            ));
        }
    }
    Ok(current)
}

fn read(root: &Path, path: &Path, limit: usize) -> Result<Vec<u8>> {
    let path = existing(root, path, false)?;
    if fs::metadata(&path)
        .map_err(|error| error.to_string())?
        .len()
        > limit as u64
    {
        return Err(format!(
            "owner import file exceeds its bound: {}",
            path.display()
        ));
    }
    let mut file = File::open(&path).map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > limit {
        return Err("owner import file grew beyond its bound".into());
    }
    // Reinspect after reading. The opened inode and retained named file must
    // still agree; no path may turn into an external symlink during import.
    existing(root, &path, false)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata().map_err(|error| error.to_string())?;
        let named = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if (opened.dev(), opened.ino(), opened.len()) != (named.dev(), named.ino(), named.len()) {
            return Err("owner import file identity changed during read".into());
        }
    }
    Ok(bytes)
}

fn value(bytes: &[u8]) -> Result<Value> {
    serde_json::from_slice(bytes).map_err(|error| format!("owner import JSON: {error}"))
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("owner import missing {key}"))
}
fn digest(text: &str) -> Result<[u8; 32]> {
    let bytes = owner_protocol::hex(text, 32)?;
    bytes
        .try_into()
        .map_err(|_| "owner import digest must be32 bytes".into())
}
fn hash(bytes: &[u8]) -> String {
    g::hex(&g::hash(bytes))
}

fn linked(
    root: &Path,
    base: &Path,
    record: &Value,
    expected: &str,
    limit: usize,
) -> Result<Vec<u8>> {
    if text(record, "path")? != expected {
        return Err(format!("owner import link must name {expected}"));
    }
    let expected_hash = text(record, "sha256")?;
    digest(expected_hash)?;
    let bytes = read(root, &base.join(expected), limit)?;
    if hash(&bytes) != expected_hash {
        return Err(format!("owner import hash mismatch: {expected}"));
    }
    Ok(bytes)
}

fn unique_phase<'a>(results: &'a Value, name: &str) -> Result<(usize, &'a Value)> {
    let phases = results
        .pointer("/suite/phases")
        .and_then(Value::as_array)
        .ok_or("owner import has no phase links")?;
    if phases.len() > 64 {
        return Err("owner import has too many phases".into());
    }
    let expected = format!("{name}/phase-result.json");
    let mut matches = phases
        .iter()
        .enumerate()
        .filter(|(_, link)| link["path"] == expected);
    let found = matches
        .next()
        .ok_or_else(|| format!("owner import missing phase {name}"))?;
    if matches.next().is_some() {
        return Err(format!("owner import duplicate phase {name}"));
    }
    Ok(found)
}

fn artifact<'a>(manifest: &'a Manifest, name: &str) -> Result<&'a Artifact> {
    let mut found = manifest.supervisor.iter().filter(|artifact| {
        Path::new(&artifact.path)
            .file_name()
            .is_some_and(|file| file == name)
    });
    let result = found
        .next()
        .ok_or_else(|| format!("owner import missing artifact {name}"))?;
    if found.next().is_some() {
        return Err(format!("owner import ambiguous artifact {name}"));
    }
    Ok(result)
}
fn artifact_path(root: &Path, artifact: &Artifact) -> Result<PathBuf> {
    digest(&artifact.sha256)?;
    let relative = Path::new(&artifact.path);
    if relative.is_absolute()
        || !relative
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err("owner artifact path escaped build/m0".into());
    }
    let path = existing(root, &root.join("build/m0").join(relative), false)?;
    if fs::metadata(&path)
        .map_err(|error| error.to_string())?
        .len()
        > ARTIFACT_LIMIT
    {
        return Err("owner retained artifact exceeds finite128MiB profile".into());
    }
    let verified = build::verify_artifact(&root.join("build/m0"), artifact)?;
    existing(root, &path, false)?;
    if verified != path {
        return Err("owner artifact path changed during verification".into());
    }
    Ok(verified)
}

fn catalogue(root: &Path, source: &Path, manifest: &Manifest) -> Result<(Catalogue, [u8; 32])> {
    if manifest.supervisor.len() > 256 {
        return Err("owner import artifact count exceeds bound".into());
    }
    for recorded in [
        &manifest.kernel,
        &manifest.image,
        &manifest.loader,
        &manifest.image_builder,
    ]
    .into_iter()
    .chain(manifest.supervisor.iter())
    {
        artifact_path(root, recorded)?;
    }
    let recorded = artifact(manifest, "m3-owner-catalogue.bin")?;
    let actual = read(root, &artifact_path(root, recorded)?, 512)?;
    let retained = read(root, &source.join("catalogue.bin"), 512)?;
    if actual != retained {
        return Err("owner retained catalogue differs from measured build artifact".into());
    }
    let catalogue =
        Catalogue::decode(&actual).map_err(|error| format!("owner catalogue: {error:?}"))?;
    let identity = |name| -> Result<[u8; 32]> { digest(&artifact(manifest, name)?.sha256) };
    if catalogue.kernel_build != digest(&manifest.build_id)?
        || catalogue.controller != identity("m3-owner-client.elf")?
        || catalogue.driver != identity("m3-block-driver.elf")?
        || catalogue.image_a != identity("supervisor-generation-good.elf")?
        || catalogue.image_b != identity("supervisor-generation-bad.elf")?
        || catalogue.abi != ev_userspace_contract::ABI
        || catalogue.health != g::hash(HEALTH_DESCRIPTION)
        || catalogue.health_version != 1
        || catalogue.required_checks != 3
    {
        return Err("owner catalogue components differ from retained exact build".into());
    }
    let binding = value(&read(
        root,
        &source.join("catalogue-binding.json"),
        JSON_LIMIT,
    )?)?;
    let catalogue_hash = g::hash(&actual);
    if binding["schema"] != 1
        || binding["passed"] != true
        || binding["catalogue_sha256"] != g::hex(&catalogue_hash)
        || binding["build_input_id"] != manifest.build_id
        || binding["kernel"] != serde_json::to_value(&manifest.kernel).map_err(|e| e.to_string())?
        || binding["boot_image"]
            != serde_json::to_value(&manifest.image).map_err(|e| e.to_string())?
        || binding["publisher_authenticated"] != false
    {
        return Err("owner catalogue binding record is inconsistent".into());
    }
    Ok((catalogue, catalogue_hash))
}

fn snapshot(root: &Path, phase: &Path, record: &Value, name: &str, mode: Mode) -> Result<Vec<u8>> {
    let bytes = linked(root, phase, record, name, storage::DISK_BYTES)?;
    if bytes.len() != storage::DISK_BYTES
        || record["bytes"] != storage::DISK_BYTES
        || record["seed_sha256"] != hash(&bytes[..512])
        || record["record_sha256"] != hash(&bytes[512..1024])
    {
        return Err("owner snapshot size/sector hashes differ".into());
    }
    let control = Control::decode(&bytes[1024..1536])
        .map_err(|e| format!("owner snapshot control: {e:?}"))?;
    if control != Control::new(mode) {
        return Err("owner snapshot has the wrong phase control".into());
    }
    for (index, byte) in bytes.iter().enumerate() {
        if (1024..1536).contains(&index) || (16 * 512..30 * 512).contains(&index) {
            continue;
        }
        let expected = if index < 512 {
            (index as u8).wrapping_mul(17).wrapping_add(0x53)
        } else {
            0
        };
        if *byte != expected {
            return Err(format!("owner snapshot changed protected byte {index}"));
        }
    }
    Ok(bytes)
}

fn before_state(
    bytes: &[u8],
    catalogue: Catalogue,
    mode: Mode,
    previous: Option<LastFailure>,
) -> Result<()> {
    let mut store = Store::open(ReadOnlyRegion::new(bytes)?, SNAPSHOT_DEADLINE)
        .map_err(|rejected| format!("owner before snapshot needs repair: {:?}", rejected.error))?;
    let (operation, serial, highest, payload) = if mode == Mode::FailB {
        (4, 1, 1, b"owner-data-A".as_slice())
    } else {
        (14, 3, 2, b"owner-data-B".as_slice())
    };
    if store.known_good() != GenerationId::new(1)
        || store
            .selected_manifest(SNAPSHOT_DEADLINE)
            .map_err(|e| format!("owner before selection: {e:?}"))?
            != g::manifest(catalogue, Slot::A, 1)
        || store
            .next_operation()
            .map_err(|e| format!("owner before operation: {e:?}"))?
            .get()
            != operation + 1
        || store
            .committed_boot_serial()
            .map_err(|e| format!("owner before serial: {e:?}"))?
            != serial
        || store
            .highest_generation()
            .map_err(|e| format!("owner before generation: {e:?}"))?
            != highest
        || store
            .last_failure()
            .map_err(|e| format!("owner before failure: {e:?}"))?
            != previous
        || !matches!(
            store.boot_plan(SNAPSHOT_DEADLINE),
            Err(ev_store::Error::Phase)
        )
    {
        return Err("owner before snapshot is not the committed preceding state".into());
    }
    let mut contents = [0; ev_store::PAYLOAD_BYTES];
    let length = store
        .read_mutable(ObjectId::user_data(), &mut contents, SNAPSHOT_DEADLINE)
        .map_err(|e| format!("owner before mutable: {e:?}"))?;
    if &contents[..length] != payload {
        return Err("owner before snapshot lost owner data".into());
    }
    if store.into_device().counts().1 != 0 {
        return Err("owner before observer attempted a mutation".into());
    }
    Ok(())
}

struct Phase {
    report: Completion,
    after: Vec<u8>,
    failure: LastFailure,
    origin: Value,
}
#[allow(clippy::too_many_arguments)]
fn phase(
    root: &Path,
    source: &Path,
    link: &Value,
    name: &str,
    mode: Mode,
    manifest: &Manifest,
    manifest_bytes: &[u8],
    catalogue: Catalogue,
    catalogue_hash: [u8; 32],
    previous: Option<LastFailure>,
) -> Result<Phase> {
    let phase_bytes = linked(
        root,
        source,
        link,
        &format!("{name}/phase-result.json"),
        JSON_LIMIT,
    )?;
    let phase = value(&phase_bytes)?;
    if phase["schema"] != 1
        || phase["kind"] != "owner-recovery-phase"
        || phase["phase"] != name
        || phase["passed"] != true
        || !phase["error"].is_null()
    {
        return Err(format!("owner required phase {name} did not PASS"));
    }
    let directory = source.join(name);
    let before = snapshot(root, &directory, &phase["before"], "data-before.raw", mode)?;
    let after = snapshot(root, &directory, &phase["after"], "data-after.raw", mode)?;
    unchanged_guards(&before, &after)?;
    before_state(&before, catalogue, mode, previous)?;
    let boot_bytes = linked(
        root,
        &directory,
        &phase["boot"],
        "boot/results.json",
        JSON_LIMIT,
    )?;
    let boot = value(&boot_bytes)?;
    if boot["schema"] != 1
        || boot["kind"] != "boot"
        || boot["passed"] != true
        || boot["build_id"] != manifest.build_id
        || boot["requested_runs"] != 1
    {
        return Err("owner phase has no matching successful retained boot".into());
    }
    let runs = boot["runs"].as_array().ok_or("owner boot has no runs")?;
    if runs.len() != 1 {
        return Err("owner phase requires one actual fresh VM".into());
    }
    let run = &runs[0];
    if run["run"] != 1
        || run["passed"] != true
        || run["exit_status"] != 33
        || !run["exit_signal"].is_null()
        || run["interruption_expected"] != false
        || run["owner_eof_no_action"] != false
        || run["directory"] != "run-001"
    {
        return Err("owner phase VM did not complete with actual status33".into());
    }
    let boot_manifest = read(root, &directory.join("boot/manifest.json"), JSON_LIMIT)?;
    if boot_manifest != manifest_bytes {
        return Err("owner phase boot manifest differs from retained build".into());
    }
    let single = value(&read(
        root,
        &directory.join("boot/run-001/result.json"),
        JSON_LIMIT,
    )?)?;
    if single != *run {
        return Err("owner per-run result differs from boot summary".into());
    }
    let serial = read(root, &directory.join("boot/run-001/serial.log"), JSON_LIMIT)?;
    let errors = read(
        root,
        &directory.join("boot/run-001/qemu.stderr.log"),
        JSON_LIMIT,
    )?;
    if run["serial_sha256"] != hash(&serial) || run["qemu_stderr_sha256"] != hash(&errors) {
        return Err("owner actual boot logs changed".into());
    }
    boot_protocol::check(&serial, &manifest.build_id, Some(33))?;
    let actual = owner_protocol::record(&serial)?;
    owner_protocol::budget(&serial)?;
    let report = actual.report;
    if report.mode != mode
        || report.owner_decision != OwnerDecision::None
        || report.failure_reason != 1
    {
        return Err("owner source phase is not the actual PF/Prepare3 profile".into());
    }
    g::report_shape(&report, catalogue, catalogue_hash)?;
    let observed = g::inspect_snapshot(&after, catalogue, &report, previous)?;
    if phase.pointer("/validation/actual") != Some(&g::report_json(&report))
        || phase.pointer("/validation/raw") != Some(&observed.evidence)
        || phase.pointer("/validation/guest_completed") != Some(&Value::Bool(true))
        || phase.pointer("/validation/guards_unchanged") != Some(&Value::Bool(true))
    {
        return Err("owner phase validation differs from actual boot and cold bytes".into());
    }
    let failure = observed
        .failure
        .ok_or("owner source lost B failure capsule")?;
    if failure.reason != LastFailureReason::ProcessFault {
        return Err("owner source failure is not the original actual B process fault".into());
    }
    Ok(Phase {
        report,
        after,
        failure,
        origin: json!({"record":link,"boot":phase["boot"],"before":phase["before"],"after":phase["after"],"serial":{"path":format!("{name}/boot/run-001/serial.log"),"sha256":hash(&serial)}}),
    })
}

pub(crate) fn load(root: &Path, source: &Path) -> Result<Prepared> {
    let root = root.canonicalize().map_err(|error| error.to_string())?;
    let source = existing(&root, source, true)?;
    let results_bytes = read(&root, &source.join("results.json"), JSON_LIMIT)?;
    let results = value(&results_bytes)?;
    if results["schema"] != 1
        || results["kind"] != "owner-recovery"
        || results["passed"].as_bool().is_none()
    {
        return Err("owner import requires an owner-suite directory".into());
    }
    // A later interactive/timeout/build failure cannot invalidate already
    // completed earlier phases. Each required link and PASS is checked below.
    let manifest_bytes = linked(
        &root,
        &source,
        &results["build"]["record"],
        "manifest.json",
        JSON_LIMIT,
    )?;
    let manifest: Manifest =
        serde_json::from_slice(&manifest_bytes).map_err(|error| error.to_string())?;
    manifest.validate_policy_rows()?;
    if manifest.schema != 1
        || manifest.fixture.as_deref() != Some("m3-owner")
        || !manifest.qemu_test_exit
        || manifest.signed
    {
        return Err("owner import requires the exact unsigned Internal owner fixture".into());
    }
    if results["build"]["build_id"] != manifest.build_id
        || results["build"]["source_sha256"] != manifest.source_sha256
    {
        return Err("owner top-level build identity differs from retained manifest".into());
    }
    let (catalogue, catalogue_hash) = catalogue(&root, &source, &manifest)?;
    let (failed_index, failed_link) = unique_phase(&results, "fail-b")?;
    let (prepared_index, prepared_link) = unique_phase(&results, "owner-prepare3")?;
    if failed_index >= prepared_index {
        return Err("owner prepared receipt predates its actual B failure".into());
    }
    let failed = phase(
        &root,
        &source,
        failed_link,
        "fail-b",
        Mode::FailB,
        &manifest,
        &manifest_bytes,
        catalogue,
        catalogue_hash,
        None,
    )?;
    let prepared = phase(
        &root,
        &source,
        prepared_link,
        "owner-prepare3",
        Mode::OwnerPrepare3,
        &manifest,
        &manifest_bytes,
        catalogue,
        catalogue_hash,
        Some(failed.failure),
    )?;
    if prepared.failure != failed.failure {
        return Err("owner prepared snapshot replaced its earlier B failure".into());
    }
    let origin = json!({"schema":1,"kind":"prepared-owner-import","source":source.strip_prefix(&root).map_err(|_|"owner origin escaped repository")?,
        "results":{"path":"results.json","sha256":hash(&results_bytes)},"source_suite_passed":results["passed"],
        "manifest":results["build"]["record"],"build_id":manifest.build_id,"catalogue_sha256":g::hex(&catalogue_hash),
        "failed_phase":failed.origin,"prepared_phase":prepared.origin,"actual_prepared_report":g::report_json(&prepared.report),
        "read_only":true,"publisher_authenticated":false});
    Ok(Prepared {
        manifest,
        manifest_bytes,
        catalogue,
        catalogue_hash,
        snapshot: prepared.after,
        failure: failed.failure,
        report: prepared.report,
        origin,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ev_store::{
        AdmissionReport, BootPolicy, HealthOutcome, HealthReport, Request, Sector, SectorIo,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Fixture {
        root: PathBuf,
        source: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let cwd = std::env::current_dir().unwrap();
            let repository = cwd
                .ancestors()
                .find(|p| p.join("kernel/Cargo.toml").is_file())
                .unwrap();
            let root = repository.join("build/test-tmp").join(format!(
                "owner-import-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let source = root.join("suite");
            fs::create_dir_all(&source).unwrap();
            Self { root, source }
        }
        fn write(&self, name: &str, bytes: &[u8]) {
            let path = self.source.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
        fn record(&self, name: &str) -> Value {
            json!({"path":name,"sha256":hash(&fs::read(self.source.join(name)).unwrap())})
        }
        fn build(&self) -> (Manifest, Catalogue) {
            let output = self.root.join("build/m0/assets");
            fs::create_dir_all(&output).unwrap();
            let mut images = Vec::new();
            for (index, name) in [
                "m3-owner-client.elf",
                "m3-block-driver.elf",
                "supervisor-generation-good.elf",
                "supervisor-generation-bad.elf",
            ]
            .into_iter()
            .enumerate()
            {
                let bytes = [index as u8 + 2; 32];
                fs::write(output.join(name), bytes).unwrap();
                images.push(Artifact {
                    path: format!("assets/{name}"),
                    sha256: hash(&bytes),
                });
            }
            let catalogue = Catalogue {
                kernel_build: [1; 32],
                controller: digest(&images[0].sha256).unwrap(),
                driver: digest(&images[1].sha256).unwrap(),
                image_a: digest(&images[2].sha256).unwrap(),
                image_b: digest(&images[3].sha256).unwrap(),
                abi: ev_userspace_contract::ABI,
                health: g::hash(HEALTH_DESCRIPTION),
                health_version: 1,
                required_checks: 3,
            };
            let bytes = catalogue.encode();
            fs::write(output.join("m3-owner-catalogue.bin"), bytes).unwrap();
            images.push(Artifact {
                path: "assets/m3-owner-catalogue.bin".into(),
                sha256: hash(&bytes),
            });
            fs::write(output.join("kernel"), b"test-only-artifact").unwrap();
            let artifact = json!({"path":"assets/kernel","sha256":hash(b"test-only-artifact")});
            let manifest: Manifest = serde_json::from_value(json!({"schema":1,"build_id":g::hex(&[1;32]),"source_revision":null,"source_dirty":true,"source_sha256":g::hex(&[9;32]),"source_inputs":[],"toolchain":"test","rustc":"test","cargo":"test","cargo_lock_sha256":"test","loader_lock_sha256":"test","profile":"test","declared_environment":{},"target":"x86_64-unknown-none","qemu_test_exit":true,"fixture":"m3-owner","signed":false,"kernel":artifact,"image":artifact,"loader":artifact,"image_builder":artifact,"supervisor":images})).unwrap();
            self.write("manifest.json", &serde_json::to_vec(&manifest).unwrap());
            self.write("catalogue.bin", &bytes);
            self.write("catalogue-binding.json", &serde_json::to_vec(&json!({"schema":1,"passed":true,"catalogue_sha256":hash(&bytes),"build_input_id":manifest.build_id,"kernel":manifest.kernel,"boot_image":manifest.image,"publisher_authenticated":false})).unwrap());
            (manifest, catalogue)
        }
        fn results(&self, manifest: &Manifest, phases: Value) {
            self.write("results.json", &serde_json::to_vec(&json!({"schema":1,"kind":"owner-recovery","passed":false,"build":{"record":self.record("manifest.json"),"build_id":manifest.build_id,"source_sha256":manifest.source_sha256},"suite":{"phases":phases}})).unwrap());
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }

    #[test]
    fn importer_never_creates_missing_input_and_rejects_non_suite_raw_files() {
        let fixture = Fixture::new();
        let absent = fixture.root.join("missing-input");
        assert!(load(&fixture.root, &absent).is_err());
        assert!(!absent.exists());
        fixture.write("raw", b"not a directory");
        assert!(load(&fixture.root, &fixture.source.join("raw")).is_err());
        fixture.write(
            "results.json",
            br#"{"schema":1,"kind":"generation","passed":true}"#,
        );
        assert!(
            load(&fixture.root, &fixture.source)
                .err()
                .unwrap()
                .contains("owner-suite")
        );
    }
    #[cfg(unix)]
    #[test]
    fn every_input_component_rejects_symlinks_and_parent_traversal() {
        use std::os::unix::fs::symlink;
        let fixture = Fixture::new();
        fixture.write("record", b"retained");
        symlink(fixture.source.join("record"), fixture.source.join("alias")).unwrap();
        assert!(read(&fixture.root, &fixture.source.join("alias"), 128).is_err());
        symlink(&fixture.source, fixture.root.join("alias-suite")).unwrap();
        assert!(load(&fixture.root, &fixture.root.join("alias-suite")).is_err());
        assert!(read(&fixture.root, &fixture.root.join("alias-suite/record"), 128).is_err());
        assert!(existing(&fixture.root, Path::new("suite/../suite"), true).is_err());
        assert!(existing(&fixture.root, fixture.root.parent().unwrap(), true).is_err());
    }
    #[test]
    fn retained_link_hash_name_and_size_are_checked_before_use() {
        let fixture = Fixture::new();
        fixture.write("manifest.json", b"original");
        let record = fixture.record("manifest.json");
        assert_eq!(
            linked(
                &fixture.root,
                &fixture.source,
                &record,
                "manifest.json",
                128
            )
            .unwrap(),
            b"original"
        );
        fixture.write("manifest.json", b"changed");
        assert!(
            linked(
                &fixture.root,
                &fixture.source,
                &record,
                "manifest.json",
                128
            )
            .is_err()
        );
        assert!(
            linked(
                &fixture.root,
                &fixture.source,
                &record,
                "../manifest.json",
                128
            )
            .is_err()
        );
        assert!(linked(&fixture.root, &fixture.source, &record, "manifest.json", 4).is_err());
    }
    #[test]
    fn exact_failed_phase_must_pass_even_if_later_suite_failure_is_allowed() {
        let fixture = Fixture::new();
        let (manifest, _) = fixture.build();
        fixture.write(
            "fail-b/phase-result.json",
            br#"{"schema":1,"kind":"owner-recovery-phase","phase":"fail-b","passed":false}"#,
        );
        fixture.write(
            "owner-prepare3/phase-result.json",
            br#"{"schema":1,"kind":"owner-recovery-phase","phase":"owner-prepare3","passed":true}"#,
        );
        let failed = fixture.record("fail-b/phase-result.json");
        let prepared = fixture.record("owner-prepare3/phase-result.json");
        fixture.results(&manifest, json!([failed, prepared]));
        let error = load(&fixture.root, &fixture.source).err().unwrap();
        assert!(error.contains("phase fail-b did not PASS"), "{error}");
        // The top-level false was deliberately accepted; only real phase PASS
        // and receipts can unlock import, never an overall-success boolean.
        fixture.results(&manifest, json!([prepared, failed]));
        assert!(
            load(&fixture.root, &fixture.source)
                .err()
                .unwrap()
                .contains("predates")
        );
        fixture.results(&manifest, json!([failed, failed, prepared]));
        assert!(
            load(&fixture.root, &fixture.source)
                .err()
                .unwrap()
                .contains("duplicate")
        );
    }
    #[test]
    fn measured_catalogue_and_component_bytes_cannot_be_substituted() {
        let fixture = Fixture::new();
        let (manifest, original) = fixture.build();
        assert_eq!(
            catalogue(&fixture.root, &fixture.source, &manifest)
                .unwrap()
                .0,
            original
        );
        let mut wrong = original;
        wrong.image_b = [77; 32];
        fixture.write("catalogue.bin", &wrong.encode());
        assert!(catalogue(&fixture.root, &fixture.source, &manifest).is_err());
        fixture.write("catalogue.bin", &original.encode());
        fs::write(
            fixture
                .root
                .join("build/m0/assets/supervisor-generation-bad.elf"),
            b"substituted",
        )
        .unwrap();
        assert!(catalogue(&fixture.root, &fixture.source, &manifest).is_err());
    }

    struct Model(Vec<u8>);
    impl SectorIo for Model {
        type Error = ();
        fn sectors(&self) -> u64 {
            14
        }
        fn read(
            &mut self,
            lba: u64,
            out: &mut Sector,
            deadline: u64,
        ) -> std::result::Result<(), ()> {
            if lba >= 14 || deadline != 1 {
                return Err(());
            }
            out.copy_from_slice(&self.0[(16 + lba as usize) * 512..(17 + lba as usize) * 512]);
            Ok(())
        }
        fn write(
            &mut self,
            lba: u64,
            bytes: &Sector,
            deadline: u64,
        ) -> std::result::Result<(), ()> {
            if lba >= 14 || deadline != 1 {
                return Err(());
            }
            self.0[(16 + lba as usize) * 512..(17 + lba as usize) * 512].copy_from_slice(bytes);
            Ok(())
        }
        fn flush(&mut self, deadline: u64) -> std::result::Result<(), ()> {
            if deadline == 1 { Ok(()) } else { Err(()) }
        }
    }
    fn execute(store: &mut Store<Model>, request: Request<'_>) {
        let id = store.next_operation().unwrap();
        store.execute(id, request, 1).unwrap();
    }
    fn model_boot(store: &mut Store<Model>, catalogue: Catalogue, slot: Slot, serial: u64) {
        let manifest = g::manifest(catalogue, slot, slot.generation());
        execute(store, Request::BeginBoot(manifest.generation));
        let admitted = AdmissionReport {
            generation: manifest.generation,
            boot_serial: serial,
            process_stamp: [serial as u8; 32],
            cohort: manifest.cohort,
            supervisor_image: manifest.supervisor_image,
            abi: manifest.abi,
            health_contract: manifest.health_contract,
            health_version: 1,
        };
        execute(store, Request::Admission(admitted));
        let payload = if serial == 1 {
            b"owner-data-A".as_slice()
        } else {
            b"owner-data-B"
        };
        if slot == Slot::A {
            execute(
                store,
                Request::WriteMutable {
                    object: ObjectId::user_data(),
                    bytes: payload,
                },
            );
        }
        execute(
            store,
            Request::Health(HealthReport {
                admitted,
                outcome: if slot == Slot::A {
                    HealthOutcome::CriticalPassed
                } else {
                    HealthOutcome::ProcessFault
                },
                observed_checks: if slot == Slot::A { 3 } else { 0 },
                storage_probe: g::hash(payload),
            }),
        );
    }
    /// Portable fixture observations only, never actual execution/health proof.
    fn prepared_model(
        catalogue: Catalogue,
        wrong_cohort: bool,
    ) -> (Vec<u8>, LastFailure, Completion) {
        let mut bytes = vec![0; storage::DISK_BYTES];
        for (i, byte) in bytes[..512].iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(17).wrapping_add(0x53);
        }
        bytes[1024..1536].copy_from_slice(&Control::new(Mode::OwnerPrepare3).encode());
        let mut store = Store::format_new(
            Model(bytes),
            g::manifest(catalogue, Slot::A, 1),
            b"owner-data-A",
            BootPolicy::new(3).unwrap(),
            1,
        )
        .unwrap_or_else(|_| panic!("model format"));
        model_boot(&mut store, catalogue, Slot::A, 1);
        execute(
            &mut store,
            Request::WriteMutable {
                object: ObjectId::user_data(),
                bytes: b"owner-data-B",
            },
        );
        execute(
            &mut store,
            Request::Stage(&g::manifest(catalogue, Slot::B, 2)),
        );
        execute(&mut store, Request::Activate(GenerationId::new(2).unwrap()));
        model_boot(&mut store, catalogue, Slot::B, 2);
        let earlier_failure = store.last_failure().unwrap().unwrap();
        model_boot(&mut store, catalogue, Slot::A, 3);
        let mut selected = g::manifest(catalogue, Slot::B, 3);
        if wrong_cohort {
            selected.cohort[0] ^= 0x80;
        }
        execute(&mut store, Request::Stage(&selected));
        execute(&mut store, Request::Activate(GenerationId::new(3).unwrap()));
        let report = Completion {
            mode: Mode::OwnerPrepare3,
            owner_decision: OwnerDecision::None,
            booted: 0,
            selected: 3,
            known_good: 1,
            boot_serial: 0,
            process: 0,
            thread: 0,
            failure_generation: 2,
            failure_serial: 2,
            failure_reason: 1,
            negatives: 0,
            mutations: 10,
            operation: 16,
            sequence: 17,
            failure_operation: 10,
            failure_sequence: 11,
            catalogue: g::hash(&catalogue.encode()),
            process_stamp: [0; 32],
            storage_probe: g::hash(b"owner-data-B"),
            booted_cohort: [0; 32],
        };
        (store.into_device().0, earlier_failure, report)
    }
    #[test]
    fn readonly_prepared_observer_requires_original_earlier_failure_and_exact_cohort() {
        let fixture = Fixture::new();
        let (_, catalogue) = fixture.build();
        let (bytes, earlier, report) = prepared_model(catalogue, false);
        let original = bytes.clone();
        g::report_shape(&report, catalogue, g::hash(&catalogue.encode())).unwrap();
        assert_eq!(
            g::inspect_snapshot(&bytes, catalogue, &report, Some(earlier))
                .unwrap()
                .failure,
            Some(earlier)
        );
        assert_eq!(bytes, original);
        assert!(g::inspect_snapshot(&bytes, catalogue, &report, None).is_err());
        let mut replaced = earlier;
        replaced.process_stamp = Some([99; 32]);
        assert!(g::inspect_snapshot(&bytes, catalogue, &report, Some(replaced)).is_err());
        let (wrong, earlier, report) = prepared_model(catalogue, true);
        assert!(g::inspect_snapshot(&wrong, catalogue, &report, Some(earlier)).is_err());
    }
    #[test]
    fn even_rehashed_snapshots_must_keep_exact_guards_and_control() {
        let fixture = Fixture::new();
        let (_, catalogue) = fixture.build();
        let (mut bytes, _, _) = prepared_model(catalogue, false);
        let make_record = |bytes: &[u8]| json!({"path":"data-after.raw","sha256":hash(bytes),"bytes":bytes.len(),"seed_sha256":hash(&bytes[..512]),"record_sha256":hash(&bytes[512..1024])});
        fixture.write("data-after.raw", &bytes);
        assert!(
            snapshot(
                &fixture.root,
                &fixture.source,
                &make_record(&bytes),
                "data-after.raw",
                Mode::OwnerPrepare3
            )
            .is_ok()
        );
        bytes[3 * 512] = 1;
        fixture.write("data-after.raw", &bytes);
        assert!(
            snapshot(
                &fixture.root,
                &fixture.source,
                &make_record(&bytes),
                "data-after.raw",
                Mode::OwnerPrepare3
            )
            .is_err()
        );
        bytes[3 * 512] = 0;
        bytes[1024..1536].copy_from_slice(&Control::new(Mode::FailB).encode());
        fixture.write("data-after.raw", &bytes);
        assert!(
            snapshot(
                &fixture.root,
                &fixture.source,
                &make_record(&bytes),
                "data-after.raw",
                Mode::OwnerPrepare3
            )
            .is_err()
        );
    }
}
