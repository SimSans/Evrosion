//! Controlled compiler policy for recorded target builds. Artifact comparisons
//! remain byte-for-byte, including symbols and debug information.
use super::Result;
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

pub(crate) const POLICY: &str = "m6-repro-v2";
pub(crate) const ENVIRONMENT: [(&str, &str); 3] = [
    ("CARGO_INCREMENTAL", "0"),
    ("EVROSION_REPRO_POLICY", POLICY),
    ("EVROSION_KERNEL_CODEGEN_UNITS", "1"),
];
pub(crate) const IMAGE_CACHE: &str = "m0-image-v3";

pub(crate) fn unrecorded_override(name: &OsStr) -> bool {
    name.to_str().is_some_and(|name| {
        name.starts_with("CARGO_PROFILE_")
            || matches!(name, "CARGO_BUILD_RUSTFLAGS" | "CARGO_BUILD_TARGET")
            || (name.starts_with("CARGO_TARGET_")
                && (name.ends_with("_RUSTFLAGS") || name.ends_with("_LINKER")))
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SourceMap {
    pub(crate) from: PathBuf,
    pub(crate) to: &'static str,
}

fn setting(command: &Command, name: &str) -> Option<OsString> {
    command
        .get_envs()
        .find(|(key, _)| *key == name)
        .map_or_else(
            || std::env::var_os(name),
            |(_, value)| value.map(OsStr::to_owned),
        )
}
fn absolute(root: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}
fn source_maps(root: &Path, cargo: &Path, sysroot: &Path) -> Result<Vec<SourceMap>> {
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    let cargo = absolute(&root, cargo.to_path_buf());
    let sysroot = absolute(&root, sysroot.to_path_buf());
    let mut paths = BTreeMap::new();
    for (path, to) in [
        (root, "/evrosion"),
        (cargo.join("registry/src"), "/cargo/registry/src"),
        (sysroot, "/rust"),
    ] {
        // Keep lexical and resolved aliases: Cargo and rustc may retain either.
        for from in std::iter::once(path.clone()).chain(path.canonicalize().ok()) {
            let text = from.to_str().ok_or("compiler source root must be UTF-8")?;
            if text.chars().any(char::is_control) || text.contains('=') {
                return Err("compiler source root contains an unsupported control or '='".into());
            }
            if paths.insert(from, to).is_some_and(|old| old != to) {
                return Err("compiler source roots have conflicting virtual identities".into());
            }
        }
    }
    let mut maps: Vec<_> = paths
        .into_iter()
        .map(|(from, to)| SourceMap { from, to })
        .collect();
    // rustc applies the last matching prefix. Specific external roots must win
    // when a private Cargo/toolchain directory lives inside the source checkout.
    maps.sort_by_key(|map| map.from.components().count());
    Ok(maps)
}

pub(crate) fn discover_maps(
    root: &Path,
    channel: &str,
    command: &Command,
) -> Result<Vec<SourceMap>> {
    let cargo = setting(command, "CARGO_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| setting(command, "HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .ok_or("recorded build needs a Cargo home")?;
    let mut probe = Command::new("rustup");
    probe
        .current_dir(root)
        .args(["run", channel, "rustc", "--print", "sysroot"]);
    for (key, value) in command.get_envs() {
        if let Some(value) = value {
            probe.env(key, value);
        } else {
            probe.env_remove(key);
        }
    }
    let output = probe
        .stdin(Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() || output.stdout.len() > 16 * 1024 {
        return Err("cannot identify the pinned compiler sysroot".into());
    }
    let sysroot = String::from_utf8(output.stdout).map_err(|e| e.to_string())?;
    source_maps(root, &cargo, Path::new(sysroot.trim()))
}

fn remap(map: &SourceMap) -> String {
    format!("--remap-path-prefix={}={}", map.from.display(), map.to)
}
fn apply(command: &mut Command, maps: &[SourceMap], kernel: bool) -> Result<()> {
    let mut flags = command
        .get_envs()
        .find(|(key, _)| *key == "CARGO_ENCODED_RUSTFLAGS")
        .and_then(|(_, value)| value)
        .map_or(Ok(String::new()), |value| {
            value
                .to_str()
                .map(str::to_owned)
                .ok_or("nonUTF8 compiler flags")
        })?;
    if kernel {
        // LLVM's local cross-CGU promotion hashes retained path context into
        // private symbol suffixes. One Kernel CGU preserves genuine symbols and
        // avoids that transformation; do not postprocess symbol tables.
        if !flags.is_empty() {
            flags.push('\x1f');
        }
        flags.push_str("-C\x1fcodegen-units=1");
    }
    for map in maps {
        if !flags.is_empty() {
            flags.push('\x1f');
        }
        flags.push_str(&remap(map));
    }
    // The pinned upstream EFI builder clears generic encoded flags before its
    // nested Cargo install. Its target-specific variable must carry the external
    // source mappings separately. EFI sources live in Cargo/sysroot, not here.
    let mut efi = "-C link-arg=/debug:none".to_owned();
    for map in maps.iter().filter(|map| map.to != "/evrosion") {
        let flag = remap(map);
        if flag.chars().any(char::is_whitespace) {
            return Err("nested EFI Cargo requires whitespace-free Cargo/sysroot paths".into());
        }
        efi.push(' ');
        efi.push_str(&flag);
    }
    command
        .env("CARGO_ENCODED_RUSTFLAGS", flags)
        .env("CARGO_TARGET_X86_64_UNKNOWN_UEFI_RUSTFLAGS", efi)
        .envs(ENVIRONMENT);
    Ok(())
}

/// Only frontend-owned `rustup run <pin> cargo build` commands are configured.
/// Stripping, stack inspection and other logged tools retain their own argv.
pub(crate) fn configure(command: &mut Command) -> Result<()> {
    let args: Vec<_> = command.get_args().map(OsStr::to_owned).collect();
    if Path::new(command.get_program()).file_name() != Some(OsStr::new("rustup"))
        || args.len() < 4
        || args[0] != "run"
        || args[2] != "cargo"
        || args[3] != "build"
    {
        return Ok(());
    }
    // Explicit target directories on the outer build must not leave a hidden
    // inherited override for the EFI builder's nested Cargo invocation.
    command
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("CARGO_BUILD_TARGET_DIR");
    let channel = args[1].to_str().ok_or("compiler channel must be UTF-8")?;
    let root = command
        .get_current_dir()
        .ok_or("recorded Cargo build needs its source root")?;
    let maps = discover_maps(root, channel, command)?;
    let kernel = args
        .windows(2)
        .any(|pair| pair[0] == "-p" && pair[1] == "ev-kernel");
    apply(command, &maps, kernel)
}

pub(crate) fn recorded_environment(command: &Command) -> Result<BTreeMap<String, String>> {
    let mut values: BTreeMap<_, _> = ENVIRONMENT
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
    let efi = command
        .get_envs()
        .find(|(key, _)| *key == "CARGO_TARGET_X86_64_UNKNOWN_UEFI_RUSTFLAGS")
        .and_then(|(_, value)| value)
        .and_then(OsStr::to_str)
        .ok_or("recorded EFI flags absent")?;
    values.insert(
        "CARGO_TARGET_X86_64_UNKNOWN_UEFI_RUSTFLAGS".into(),
        efi.into(),
    );
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compiler_policy_preserves_target_flags_and_normalizes_external_sources() {
        let mut command = Command::new("rustup");
        command.env("CARGO_ENCODED_RUSTFLAGS", "-C\x1fcode-model=kernel");
        apply(
            &mut command,
            &[
                SourceMap {
                    from: PathBuf::from("/work/source with spaces"),
                    to: "/evrosion",
                },
                SourceMap {
                    from: PathBuf::from("/private/cargo/registry/src"),
                    to: "/cargo/registry/src",
                },
                SourceMap {
                    from: PathBuf::from("/private/rust"),
                    to: "/rust",
                },
            ],
            false,
        )
        .unwrap();
        let env: BTreeMap<_, _> = command
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.unwrap().to_string_lossy().into_owned(),
                )
            })
            .collect();
        assert!(env["CARGO_ENCODED_RUSTFLAGS"].starts_with("-C\x1fcode-model=kernel\x1f"));
        assert!(env["CARGO_ENCODED_RUSTFLAGS"].contains("source with spaces=/evrosion"));
        assert!(!env["CARGO_TARGET_X86_64_UNKNOWN_UEFI_RUSTFLAGS"].contains("source with spaces"));
        assert!(env["CARGO_TARGET_X86_64_UNKNOWN_UEFI_RUSTFLAGS"].contains("/private/rust=/rust"));
        assert_eq!(env["CARGO_INCREMENTAL"], "0");
        assert_eq!(
            recorded_environment(&command).unwrap()["EVROSION_REPRO_POLICY"],
            POLICY
        );
    }
    #[test]
    fn kernel_codegen_avoids_path_sensitive_private_symbol_promotion() {
        for kernel in [false, true] {
            let mut command = Command::new("rustup");
            command.env("CARGO_ENCODED_RUSTFLAGS", "-C\x1fcode-model=kernel");
            apply(&mut command, &[], kernel).unwrap();
            let flags = setting(&command, "CARGO_ENCODED_RUSTFLAGS").unwrap();
            assert_eq!(flags.to_str().unwrap().contains("codegen-units=1"), kernel);
            assert!(
                flags
                    .to_str()
                    .unwrap()
                    .starts_with("-C\x1fcode-model=kernel")
            );
        }
    }

    #[test]
    fn non_compiler_commands_are_unchanged() {
        let mut command = Command::new("llvm-objcopy");
        command.arg("--strip-debug");
        configure(&mut command).unwrap();
        assert_eq!(command.get_envs().count(), 0);
        assert_eq!(command.get_args().count(), 1);
    }
    #[test]
    fn nested_efi_argument_transport_refuses_ambiguous_external_paths() {
        let mut command = Command::new("rustup");
        let maps = [SourceMap {
            from: PathBuf::from("/cargo home/registry/src"),
            to: "/cargo/registry/src",
        }];
        assert!(apply(&mut command, &maps, false).is_err());
        assert_eq!(command.get_envs().count(), 0);
    }

    #[test]
    fn profile_and_target_overrides_are_explicit_inputs_not_ambient_changes() {
        for name in [
            "CARGO_PROFILE_DEV_OPT_LEVEL",
            "CARGO_PROFILE_RELEASE_DEBUG",
            "CARGO_TARGET_X86_64_UNKNOWN_NONE_LINKER",
            "CARGO_TARGET_X86_64_UNKNOWN_UEFI_RUSTFLAGS",
            "CARGO_BUILD_TARGET",
        ] {
            assert!(unrecorded_override(OsStr::new(name)));
        }
        for name in [
            "CARGO_HOME",
            "CARGO_INCREMENTAL",
            "CARGO_BUILD_JOBS",
            "CARGO_TARGET_DIR",
        ] {
            assert!(!unrecorded_override(OsStr::new(name)));
        }
    }

    #[test]
    fn nested_registry_and_toolchain_roots_have_specific_virtual_prefixes() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let root = repo.join(format!(
            "build/test-tmp/repro-maps-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let cargo = root.join(".ev/cargo");
        let sysroot = root.join(".ev/rust");
        std::fs::create_dir_all(cargo.join("registry/src")).unwrap();
        std::fs::create_dir_all(&sysroot).unwrap();
        let maps = source_maps(&root, &cargo, &sysroot).unwrap();
        for (path, expected) in [
            (
                cargo.join("registry/src/example/src.rs"),
                "/cargo/registry/src/example/src.rs",
            ),
            (sysroot.join("lib/source.rs"), "/rust/lib/source.rs"),
        ] {
            let actual = maps
                .iter()
                .rev()
                .find_map(|map| {
                    path.strip_prefix(&map.from)
                        .ok()
                        .map(|tail| Path::new(map.to).join(tail))
                })
                .unwrap();
            assert_eq!(actual, Path::new(expected));
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
