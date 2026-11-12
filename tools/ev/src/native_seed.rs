//! Fixed sample disk input for the Native developer preview.
use crate::{build::Result, storage};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};

#[cfg(test)]
const DIRECTORY: &str = "tools/m5/fixtures";
const MANIFEST: &str = "tools/m5/fixtures/native-seed.json";
const FILE: &str = "native-seed.raw";
const INPUT: &str = "tools/m5/fixtures/native-seed.raw";
const RETAINED: &str = "m4-reference.raw";
const SEED_SHA: &str = "d907160f4e5fe0ac7b0ec9d11a8c8b48fb2fd918040a1730048fb05d16bdce46";
const SOURCE_RECORD_SHA: &str = "325adce75f2c6b34be05eb43faaa0e9f183f2bb964ee3117c8f0b1d3cac3cfe8";
const MANIFEST_LIMIT: u64 = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    schema: u32,
    kind: String,
    file: String,
    bytes: u64,
    sector_bytes: u32,
    sha256: String,
    provenance: Provenance,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Provenance {
    source: String,
    source_record_sha256: String,
    scope: String,
}

fn regular(root: &Path, relative: &Path) -> Result<PathBuf> {
    if relative.as_os_str().is_empty()
        || !relative
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err("seed input requires a canonical relative path".into());
    }
    let mut path = root.to_path_buf();
    let mut parts = relative.components().peekable();
    while let Some(part) = parts.next() {
        path.push(part.as_os_str());
        let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if meta.file_type().is_symlink()
            || if parts.peek().is_some() {
                !meta.is_dir()
            } else {
                !meta.is_file()
            }
        {
            return Err("seed input contains a symlink or nonregular component".into());
        }
    }
    Ok(path)
}
fn bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > limit {
        return Err("seed input nonregular/oversized".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("seed input grew beyond bound".into());
    }
    Ok(bytes)
}

/// Validate the fixed checked-in sample bytes, then retain a new immutable copy.
/// The caller imports these bytes into its NEW owned runner disk. This function
/// neither formats a disk nor writes the fixture or any historical data path.
pub(crate) fn checkpoint(root: &Path, evidence: &Path) -> Result<(Vec<u8>, Value)> {
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    let relative = evidence
        .strip_prefix(&root)
        .map_err(|_| "seed evidence escaped repository")?;
    if !relative.starts_with("build") {
        return Err("seed evidence must be an owned build directory".into());
    }
    let evidence = storage::directory_beneath(&root, relative)?;
    let manifest_bytes = bounded(&regular(&root, Path::new(MANIFEST))?, MANIFEST_LIMIT)?;
    let fixture: Fixture = serde_json::from_slice(&manifest_bytes).map_err(|e| e.to_string())?;
    if fixture.schema != 1
        || fixture.kind != "evrosion-native-reference-seed"
        || fixture.file != FILE
        || fixture.bytes != storage::DISK_BYTES as u64
        || fixture.sector_bytes != storage::SECTOR_BYTES as u32
        || fixture.sha256 != SEED_SHA
        || fixture.provenance.source != "M4 reference desktop checkpoint"
        || fixture.provenance.source_record_sha256 != SOURCE_RECORD_SHA
        || fixture.provenance.scope.trim().is_empty()
    {
        return Err("seed manifest differs from the fixed reference fixture".into());
    }
    // A manifest cannot select another path or redefine the accepted bytes.
    let bytes = bounded(
        &regular(&root, Path::new(INPUT))?,
        storage::DISK_BYTES as u64,
    )?;
    let sha = format!("{:x}", Sha256::digest(&bytes));
    if bytes.len() != storage::DISK_BYTES || sha != SEED_SHA {
        return Err("seed extent/digest differs from the fixed reference fixture".into());
    }
    let retained = evidence.join(RETAINED);
    storage::immutable_new(&retained, &bytes)?;
    if bounded(&regular(&root, Path::new(MANIFEST))?, MANIFEST_LIMIT)? != manifest_bytes
        || bounded(
            &regular(&root, Path::new(INPUT))?,
            storage::DISK_BYTES as u64,
        )? != bytes
        || bounded(&retained, storage::DISK_BYTES as u64)? != bytes
    {
        return Err("seed fixture/manifest or retained copy changed during import".into());
    }
    Ok((
        bytes,
        json!({"fixture":INPUT,"manifest":MANIFEST,
        "manifest_sha256":format!("{:x}",Sha256::digest(&manifest_bytes)),
        "sha256":sha,"bytes":storage::DISK_BYTES,"retained_input":RETAINED,
        "source_record_sha256":fixture.provenance.source_record_sha256,
        "method":"exact checked-in sample bytes copied into NEW owned evidence and runner disk; no formatting; fixture and historical data never written"}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    struct Temp {
        root: PathBuf,
    }
    impl Temp {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .canonicalize()
                .unwrap();
            let parent = storage::directory_beneath(&repo, Path::new("build/test-tmp")).unwrap();
            let root = parent.join(format!(
                "native-seed-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            fs::create_dir_all(root.join(DIRECTORY)).unwrap();
            for name in [MANIFEST, INPUT] {
                fs::copy(repo.join(name), root.join(name)).unwrap();
            }
            Self { root }
        }
        fn evidence(&self, name: &str) -> PathBuf {
            let p = self.root.join("build/m5/evidence").join(name);
            fs::create_dir_all(&p).unwrap();
            p
        }
        fn writable(&self, name: &str, bytes: &[u8]) {
            let p = self.root.join(name);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
            }
            #[cfg(not(unix))]
            {
                let mut permissions = fs::metadata(&p).unwrap().permissions();
                permissions.set_readonly(false);
                fs::set_permissions(&p, permissions).unwrap();
            }
            fs::write(p, bytes).unwrap();
        }
        fn manifest(&self, change: impl FnOnce(&mut Value)) {
            let mut v: Value =
                serde_json::from_slice(&fs::read(self.root.join(MANIFEST)).unwrap()).unwrap();
            change(&mut v);
            self.writable(MANIFEST, &serde_json::to_vec(&v).unwrap());
        }
        fn refused_without_copy(&self) {
            let evidence = self.evidence("refused");
            assert!(checkpoint(&self.root, &evidence).is_err());
            assert!(!evidence.join(RETAINED).exists());
            assert!(!evidence.join("data.raw").exists());
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    #[test]
    fn exact_public_fixture_works_without_archive_or_helper_and_is_not_modified() {
        let t = Temp::new();
        let raw_before = fs::read(t.root.join(INPUT)).unwrap();
        let manifest_before = fs::read(t.root.join(MANIFEST)).unwrap();
        let evidence = t.evidence("fresh");
        let (bytes, record) = checkpoint(&t.root, &evidence).unwrap();
        assert_eq!(bytes.len(), storage::DISK_BYTES);
        assert_eq!(record["sha256"], SEED_SHA);
        assert_eq!(fs::read(evidence.join(RETAINED)).unwrap(), raw_before);
        assert_eq!(fs::read(t.root.join(INPUT)).unwrap(), raw_before);
        assert_eq!(fs::read(t.root.join(MANIFEST)).unwrap(), manifest_before);
        assert!(!t.root.join("docs/status/evidence").exists());
        assert!(!t.root.join("tools/m5/reference_checkpoint.py").exists());
        assert!(
            fs::metadata(evidence.join(RETAINED))
                .unwrap()
                .permissions()
                .readonly()
        );
        assert!(!evidence.join("data.raw").exists());
        assert!(checkpoint(&t.root, &evidence).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let input = fs::metadata(t.root.join(INPUT)).unwrap();
            let copy = fs::metadata(evidence.join(RETAINED)).unwrap();
            assert_ne!((input.dev(), input.ino()), (copy.dev(), copy.ino()));
        }
    }
    #[test]
    fn corrupted_truncated_oversized_and_blank_seed_are_refused_before_copy() {
        for variant in 0..4 {
            let t = Temp::new();
            let mut raw = fs::read(t.root.join(INPUT)).unwrap();
            match variant {
                0 => raw[0] ^= 1,
                1 => {
                    raw.pop();
                }
                2 => raw.push(0),
                _ => raw.fill(0),
            }
            t.writable(INPUT, &raw);
            t.refused_without_copy();
            assert_eq!(fs::read(t.root.join(INPUT)).unwrap(), raw);
        }
    }
    #[test]
    fn manifest_cannot_redirect_path_or_override_pinned_extent_digest_and_provenance() {
        for (key, value) in [
            ("file", json!("../native-seed.raw")),
            ("file", json!("/tmp/native-seed.raw")),
            ("file", json!("fixtures\\native-seed.raw")),
            ("bytes", json!(storage::DISK_BYTES + 1)),
            ("bytes", json!(true)),
            ("sha256", json!("0".repeat(64))),
            ("sector_bytes", json!(4096)),
            ("schema", json!(2)),
            ("kind", json!("execution-pass")),
            ("unexpected", json!(true)),
        ] {
            let t = Temp::new();
            t.manifest(|v| v[key] = value);
            t.refused_without_copy();
        }
        let t = Temp::new();
        t.manifest(|v| v["provenance"]["source_record_sha256"] = json!("0".repeat(64)));
        t.refused_without_copy();
    }
    #[test]
    fn missing_nonregular_oversized_and_duplicate_manifest_inputs_are_refused() {
        for path in [MANIFEST, INPUT] {
            let t = Temp::new();
            fs::remove_file(t.root.join(path)).unwrap();
            t.refused_without_copy();
            fs::create_dir(t.root.join(path)).unwrap();
            let other = t.evidence("nonregular");
            assert!(checkpoint(&t.root, &other).is_err());
        }
        let t = Temp::new();
        t.writable(MANIFEST, &vec![b' '; MANIFEST_LIMIT as usize + 1]);
        t.refused_without_copy();
        let t = Temp::new();
        let data = String::from_utf8(fs::read(t.root.join(MANIFEST)).unwrap()).unwrap();
        t.writable(MANIFEST, data.replacen('{', "{\"schema\":1,", 1).as_bytes());
        t.refused_without_copy();
    }
    #[test]
    fn output_cannot_escape_build_or_overwrite_an_existing_file() {
        let t = Temp::new();
        assert!(checkpoint(&t.root, &t.root.join(DIRECTORY)).is_err());
        assert!(checkpoint(&t.root, &t.root.join("build/../outside")).is_err());
        assert!(checkpoint(&t.root, &t.root.parent().unwrap().join("outside")).is_err());
        let evidence = t.evidence("existing");
        fs::write(evidence.join(RETAINED), b"owned existing result").unwrap();
        assert!(checkpoint(&t.root, &evidence).is_err());
        assert_eq!(
            fs::read(evidence.join(RETAINED)).unwrap(),
            b"owned existing result"
        );
    }
    #[cfg(unix)]
    #[test]
    fn fixture_and_parent_symlinks_are_refused_even_for_exact_bytes() {
        use std::os::unix::fs::symlink;
        for name in [MANIFEST, INPUT, DIRECTORY, "tools/m5", "tools"] {
            let t = Temp::new();
            let path = t.root.join(name);
            let actual = t.root.join("same-owned-data");
            fs::rename(&path, &actual).unwrap();
            symlink(&actual, &path).unwrap();
            t.refused_without_copy();
            assert!(actual.exists());
        }
    }
    #[cfg(unix)]
    #[test]
    fn evidence_alias_and_existing_output_symlink_never_write_the_target() {
        use std::os::unix::fs::symlink;
        let t = Temp::new();
        let actual = t.root.join("owned-directory");
        fs::create_dir(&actual).unwrap();
        symlink(&actual, t.root.join("build")).unwrap();
        assert!(checkpoint(&t.root, &t.root.join("build/run")).is_err());
        assert_eq!(fs::read_dir(&actual).unwrap().count(), 0);
        let t = Temp::new();
        let evidence = t.evidence("alias");
        let target = t.root.join("owned-target");
        fs::write(&target, b"preserve this file").unwrap();
        symlink(&target, evidence.join(RETAINED)).unwrap();
        assert!(checkpoint(&t.root, &evidence).is_err());
        assert_eq!(fs::read(target).unwrap(), b"preserve this file");
    }
}
