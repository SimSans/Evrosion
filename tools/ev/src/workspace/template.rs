//! Read-only template input and a fresh VM-owned clone. No format or repair.
use super::bundle;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

const BYTES: u64 = 96 * 1024 * 1024;
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Snapshot {
    bytes: u64,
    sha256: String,
    prefix4_sha256: String,
    prefix8_sha256: String,
    device: u64,
    inode: u64,
    mode: u32,
    mtime_seconds: i64,
    mtime_nanoseconds: i64,
}
impl Snapshot {
    fn capture(path: &Path) -> Result<Self, String> {
        let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != BYTES {
            return Err(
                "owned data template must be an exact regular96MiB file, without a symlink".into(),
            );
        }
        let mut file = File::open(path).map_err(|e| e.to_string())?;
        let before = file.metadata().map_err(|e| e.to_string())?;
        if before.dev() != metadata.dev() || before.ino() != metadata.ino() || before.len() != BYTES
        {
            return Err("template input changed while opening read-only".into());
        }
        let (mut whole, mut prefix4, mut prefix8) = (Sha256::new(), Sha256::new(), Sha256::new());
        let mut buffer = [0u8; 64 * 1024];
        let mut offset = 0;
        while offset < BYTES {
            let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("template truncated during read-only hashing".into());
            }
            whole.update(&buffer[..n]);
            for (limit, hash) in [
                (4 * 1024 * 1024, &mut prefix4),
                (8 * 1024 * 1024, &mut prefix8),
            ] {
                let count = (limit as u64).saturating_sub(offset).min(n as u64) as usize;
                hash.update(&buffer[..count]);
            }
            offset += n as u64;
        }
        let after = file.metadata().map_err(|e| e.to_string())?;
        if before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
        {
            return Err("template changed during read-only hashing".into());
        }
        Ok(Self {
            bytes: BYTES,
            sha256: bundle::hex(&whole.finalize()),
            prefix4_sha256: bundle::hex(&prefix4.finalize()),
            prefix8_sha256: bundle::hex(&prefix8.finalize()),
            device: before.dev(),
            inode: before.ino(),
            mode: before.mode(),
            mtime_seconds: before.mtime(),
            mtime_nanoseconds: before.mtime_nsec(),
        })
    }
}
#[derive(Debug, Serialize)]
pub(super) struct Witness {
    source: PathBuf,
    before: Snapshot,
}
pub(super) fn expected_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn clone_new(
    source: &Path,
    target: &Path,
    expected: &str,
    evidence: &Path,
) -> Result<Witness, String> {
    if !expected_hash(expected) {
        return Err("template expected SHA must be64 lowercase hexadecimal bytes".into());
    }
    let before = Snapshot::capture(source)?;
    if before.sha256 != expected {
        return Err("template whole SHA differs before clone; no output opened".into());
    }
    let input = File::open(source).map_err(|e| e.to_string())?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)
        .map_err(|e| e.to_string())?;
    let copied =
        std::io::copy(&mut input.take(BYTES + 1), &mut output).map_err(|e| e.to_string())?;
    output.sync_all().map_err(|e| e.to_string())?;
    drop(output);
    if copied != BYTES {
        return Err("template clone length changed; partial owned output retained".into());
    }
    let after = Snapshot::capture(source)?;
    let clone = Snapshot::capture(target)?;
    if before != after
        || clone.sha256 != expected
        || clone.prefix4_sha256 != before.prefix4_sha256
        || clone.prefix8_sha256 != before.prefix8_sha256
    {
        return Err("template source/clone verification differs; owned evidence retained".into());
    }
    let witness = Witness {
        source: source.to_path_buf(),
        before,
    };
    bundle::write_json_new(
        evidence,
        &serde_json::json!({"schema":1,"scope":"Exact read-only template cloned to a NEW VM-owned96MiB file; no format, repair, guest provisioning or migration acceptance","source":witness,"source_after_clone":after,"clone":target,"clone_snapshot":clone,"host_format_invoked":false}),
    )?;
    Ok(witness)
}
pub(super) fn verify_source(witness: &Witness, evidence: &Path) -> Result<bool, String> {
    let after = Snapshot::capture(&witness.source);
    let unchanged = after.as_ref().is_ok_and(|value| *value == witness.before);
    bundle::write_json_new(
        evidence,
        &serde_json::json!({"schema":1,"scope":"Read-only source recheck after directly owned VM wait; source whole SHA, prefix hashes, inode and mtime must remain unchanged","source":witness,"after":after,"unchanged":unchanged}),
    )?;
    Ok(unchanged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};
    #[test]
    fn clone_is_exact_new_and_readonly_source_changes_are_detected() {
        let d = std::env::temp_dir().join(format!(
            "ev-m8-template-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&d).unwrap();
        let source = d.join("source.raw");
        let target = d.join("clone.raw");
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&source)
            .unwrap();
        f.set_len(BYTES).unwrap();
        f.write_all(b"legacy03").unwrap();
        f.seek(SeekFrom::End(-1)).unwrap();
        f.write_all(&[37]).unwrap();
        f.sync_all().unwrap();
        drop(f);
        let before = Snapshot::capture(&source).unwrap();
        assert!(clone_new(&source, &target, &"0".repeat(64), &d.join("bad.json")).is_err());
        assert!(!target.exists());
        let link = d.join("source-link.raw");
        std::os::unix::fs::symlink(&source, &link).unwrap();
        assert!(Snapshot::capture(&link).is_err());
        let witness = clone_new(&source, &target, &before.sha256, &d.join("clone.json")).unwrap();
        assert_eq!(Snapshot::capture(&source).unwrap(), before);
        let copied = Snapshot::capture(&target).unwrap();
        assert_eq!(copied.sha256, before.sha256);
        assert_ne!(copied.inode, before.inode);
        assert!(clone_new(&source, &target, &before.sha256, &d.join("overwrite.json")).is_err());
        assert_eq!(Snapshot::capture(&target).unwrap(), copied);
        assert!(verify_source(&witness, &d.join("unchanged.json")).unwrap());
        let mut changed = OpenOptions::new().write(true).open(&source).unwrap();
        changed.write_all(b"X").unwrap();
        changed.sync_all().unwrap();
        drop(changed);
        assert!(!verify_source(&witness, &d.join("changed.json")).unwrap());
        assert_eq!(Snapshot::capture(&target).unwrap(), copied);
        let wrong = d.join("wrong.raw");
        File::create(&wrong).unwrap();
        assert!(Snapshot::capture(&wrong).is_err());
        // All test-owned inputs and exact clone evidence remain retained.
    }
}
