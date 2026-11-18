//! Explicit analysis-sidecar join for an independently admitted executable.
//! Symbol/section metadata is not assumed to be loaded. Equality covers the
//! entry, the entire program-header table, and every literal PT_LOAD byte.
use super::{Input, hash, hash32, hex, read_elf, write_json_new, write_new};
use std::path::{Path, PathBuf};

pub(super) struct RetainedAnalysis {
    pub path: PathBuf,
    pub equivalence: Option<serde_json::Value>,
}

struct Loaded<'a> {
    format: &'a [u8],
    flags_and_header_size: &'a [u8],
    entry: u64,
    program_headers: &'a [u8],
    payloads: Vec<&'a [u8]>,
}
fn range(bytes: &[u8], start: u64, length: u64) -> Result<&[u8], String> {
    let end = start.checked_add(length).ok_or("ELF extent overflow")?;
    let start = usize::try_from(start).map_err(|_| "ELF start exceeds host size")?;
    let end = usize::try_from(end).map_err(|_| "ELF end exceeds host size")?;
    bytes.get(start..end).ok_or("truncated ELF extent".into())
}
fn half(bytes: &[u8], at: u64) -> Result<u16, String> {
    Ok(u16::from_le_bytes(range(bytes, at, 2)?.try_into().unwrap()))
}
fn word(bytes: &[u8], at: u64) -> Result<u32, String> {
    Ok(u32::from_le_bytes(range(bytes, at, 4)?.try_into().unwrap()))
}
fn wide(bytes: &[u8], at: u64) -> Result<u64, String> {
    Ok(u64::from_le_bytes(range(bytes, at, 8)?.try_into().unwrap()))
}
fn loaded(bytes: &[u8]) -> Result<Loaded<'_>, String> {
    if bytes.len() < 64
        || bytes.len() > 2 * 1024 * 1024
        || bytes.get(..9) != Some(b"\x7fELF\x02\x01\x01\0\0".as_slice())
        || half(bytes, 16)? != 2
        || half(bytes, 18)? != 62
        || word(bytes, 20)? != 1
        || word(bytes, 48)? != 0
        || half(bytes, 52)? != 64
        || wide(bytes, 32)? != 64
        || half(bytes, 54)? != 56
    {
        return Err("analysis join requires bounded x86-64 EXEC ELF64".into());
    }
    let count = half(bytes, 56)?;
    if count == 0 || usize::from(count) > ev_kernel::executable::MAX_SEGMENTS {
        return Err("invalid analysis program-header count".into());
    }
    let program_headers = range(bytes, 64, u64::from(count) * 56)?;
    let mut payloads = Vec::new();
    for index in 0..u64::from(count) {
        let at = 64 + index * 56;
        match word(bytes, at)? {
            0 => continue,
            1 => (),
            _ => return Err("unsupported analysis program header".into()),
        }
        let flags = word(bytes, at + 4)?;
        let offset = wide(bytes, at + 8)?;
        let address = wide(bytes, at + 16)?;
        let file_bytes = wide(bytes, at + 32)?;
        let memory_bytes = wide(bytes, at + 40)?;
        if !matches!(flags, 4..=6)
            || memory_bytes == 0
            || file_bytes > memory_bytes
            || wide(bytes, at + 48)? != 4096
            || !offset.is_multiple_of(4096)
            || !address.is_multiple_of(4096)
            || offset < 64 + u64::from(count) * 56
        {
            return Err("invalid analysis LOAD extent, flags or alignment".into());
        }
        payloads.push(range(bytes, offset, file_bytes)?);
    }
    if payloads.is_empty() {
        return Err("analysis ELF has no LOAD segments".into());
    }
    Ok(Loaded {
        format: &bytes[..24],
        flags_and_header_size: &bytes[48..54],
        entry: wide(bytes, 24)?,
        program_headers,
        payloads,
    })
}

/// Exact loaded identity, including PT_NULL metadata. This deliberately does
/// not compare unloaded section/symbol tables or assume they are PT_LOAD data.
fn equivalent(actual: &[u8], analysis: &[u8]) -> Result<usize, String> {
    let a = loaded(actual)?;
    let b = loaded(analysis)?;
    if a.format != b.format
        || a.flags_and_header_size != b.flags_and_header_size
        || a.entry != b.entry
        || a.program_headers != b.program_headers
        || a.payloads != b.payloads
    {
        return Err(
            "analysis differs from exact executable entry/program headers/LOAD bytes".into(),
        );
    }
    Ok(a.payloads.len())
}

pub(super) fn retain_analysis(
    input: &Input,
    base: &Path,
    directory: &Path,
    name: &str,
    image: &[u8],
    actual_path: &Path,
) -> Result<RetainedAnalysis, String> {
    let Some(sidecar) = &input.analysis else {
        return Ok(RetainedAnalysis {
            path: actual_path.to_path_buf(),
            equivalence: None,
        });
    };
    if hash(image) != hash32(&input.sha256)? {
        return Err("analysis join executable SHA differs".into());
    }
    let source = if sidecar.path.is_absolute() {
        sidecar.path.clone()
    } else {
        base.join(&sidecar.path)
    };
    let analysis = read_elf(&source)?;
    if hash(&analysis) != hash32(&sidecar.sha256)? {
        return Err("analysis sidecar SHA differs".into());
    }
    let loads = equivalent(image, &analysis)?;
    let path = directory.join(format!("{name}.analysis.elf"));
    write_new(&path, &analysis)?;
    let equivalence = serde_json::json!({
        "schema":1,
        "scope":"Exact entry, entire program-header table and literal PT_LOAD bytewise equality. Symbol/section metadata is independently retained, not assumed loaded. Descriptor, package and Kernel continue to use actual executable bytes. Stack census remains a fixed-prologue/resolved-reference preflight, not a formal bound or runtime measurement.",
        "actual_elf":{"path":actual_path,"sha256":hex(&hash(image)),"bytes":image.len()},
        "analysis_elf":{"source":source,"path":path,"sha256":hex(&hash(&analysis)),"bytes":analysis.len()},
        "entry_equal":true,
        "entire_program_headers_compared_bytewise_equal":true,
        "all_literal_PT_LOAD_payloads_compared_bytewise_equal":true,
        "PT_LOAD_count":loads,
    });
    write_json_new(
        &directory.join(format!("{name}.analysis-equivalence.json")),
        &equivalence,
    )?;
    Ok(RetainedAnalysis {
        path,
        equivalence: Some(equivalence),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::bundle::{AnalysisInput, StackImage, image_stack};
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    fn fixture() -> Vec<u8> {
        let mut b = vec![0; 4100];
        b[..9].copy_from_slice(b"\x7fELF\x02\x01\x01\0\0");
        b[16..18].copy_from_slice(&2u16.to_le_bytes());
        b[18..20].copy_from_slice(&62u16.to_le_bytes());
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[24..32].copy_from_slice(&((1u64 << 39) + 4096).to_le_bytes());
        b[32..40].copy_from_slice(&64u64.to_le_bytes());
        b[52..54].copy_from_slice(&64u16.to_le_bytes());
        b[54..56].copy_from_slice(&56u16.to_le_bytes());
        b[56..58].copy_from_slice(&2u16.to_le_bytes());
        b[64..68].copy_from_slice(&1u32.to_le_bytes());
        b[68..72].copy_from_slice(&5u32.to_le_bytes());
        for (at, n) in [
            (72, 4096),
            (80, (1u64 << 39) + 4096),
            (96, 4),
            (104, 4),
            (112, 4096),
        ] {
            b[at..at + 8].copy_from_slice(&n.to_le_bytes());
        }
        b[4096..].copy_from_slice(&[0x90, 0x90, 0x90, 0xc3]);
        b
    }
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!(
                "ev-compact-analysis-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn input(b: &[u8]) -> Input {
        Input {
            path: "actual.elf".into(),
            sha256: hex(&hash(b)),
            analysis: Some(AnalysisInput {
                path: "symbols.elf".into(),
                sha256: hex(&hash(b)),
            }),
        }
    }

    #[test]
    fn exact_load_join_allows_only_unloaded_metadata_difference() {
        let a = fixture();
        let mut b = a.clone();
        b.extend_from_slice(b"independently retained symbol metadata");
        b[40..48].copy_from_slice(&4100u64.to_le_bytes());
        assert_eq!(equivalent(&a, &b), Ok(1));
        for at in [24, 68, 80, 96, 104, 112, 120, 128, 4096] {
            let mut changed = b.clone();
            changed[at] ^= 1;
            assert!(
                equivalent(&a, &changed).is_err(),
                "accepted differing byte {at}"
            );
        }
        for length in [0, 63, 100, 4098] {
            assert!(equivalent(&a, &a[..length]).is_err());
        }
        let mut foreign = a.clone();
        foreign[18] = 3;
        assert!(equivalent(&a, &foreign).is_err());
    }

    #[test]
    fn analysis_is_hashed_checked_and_retained_before_use_never_ignored() {
        let t = Temp::new();
        let a = fixture();
        let mut i = input(&a);
        let source = t.0.join("symbols.elf");
        let out = t.0.join("out");
        fs::create_dir(&out).unwrap();
        assert!(retain_analysis(&i, &t.0, &out, "Missing", &a, &t.0.join("actual.elf")).is_err());
        fs::write(&source, vec![0u8; 2 * 1024 * 1024 + 1]).unwrap();
        assert!(retain_analysis(&i, &t.0, &out, "Oversize", &a, &t.0.join("actual.elf")).is_err());
        fs::write(&source, &a).unwrap();
        i.analysis.as_mut().unwrap().sha256 = "f".repeat(64);
        assert!(retain_analysis(&i, &t.0, &out, "App", &a, &t.0.join("actual.elf")).is_err());
        assert_eq!(fs::read_dir(&out).unwrap().count(), 0);
        i.analysis.as_mut().unwrap().sha256 = hex(&hash(&a));
        let got = retain_analysis(&i, &t.0, &out, "App", &a, &t.0.join("actual.elf")).unwrap();
        assert_eq!(fs::read(&got.path).unwrap(), a);
        assert!(got.equivalence.is_some());
        i.analysis = None;
        let actual = t.0.join("actual.elf");
        let got = retain_analysis(&i, &t.0, &out, "Unused", &a, &actual).unwrap();
        assert_eq!(got.path, actual);
        assert!(got.equivalence.is_none());
    }

    #[test]
    fn symbol_less_or_foreign_sidecar_cannot_turn_audit_into_success() {
        let t = Temp::new();
        let a = fixture();
        let i = input(&a);
        fs::write(t.0.join("symbols.elf"), &a).unwrap();
        let actual = t.0.join("actual.elf");
        fs::write(&actual, &a).unwrap();
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        assert!(
            image_stack(
                &root,
                &t.0,
                &t.0,
                "NoSymbols",
                StackImage {
                    input: &i,
                    bytes: &a,
                    path: &actual
                },
                (480, 8)
            )
            .is_err()
        );
        assert!(!t.0.join("NoSymbols.stack.json").exists());
        let mut absent = i.clone();
        absent.analysis = None;
        assert!(
            image_stack(
                &root,
                &t.0,
                &t.0,
                "NoAnalysis",
                StackImage {
                    input: &absent,
                    bytes: &a,
                    path: &actual,
                },
                (480, 8)
            )
            .is_err()
        );
        assert!(!t.0.join("NoAnalysis.stack.json").exists());
        let mut bad = a.clone();
        bad[4096] ^= 1;
        fs::write(t.0.join("symbols.elf"), &bad).unwrap();
        let mut i = i;
        i.analysis.as_mut().unwrap().sha256 = hex(&hash(&bad));
        assert!(retain_analysis(&i, &t.0, &t.0, "Foreign", &a, &actual).is_err());
        assert!(!t.0.join("Foreign.analysis.elf").exists());
    }
}
