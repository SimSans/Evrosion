use crate::{
    cli::BuildOptions,
    doctor,
    process::{Invocation, Runner, SystemRunner},
    toolchain::Toolchain,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

pub type Result<T> = std::result::Result<T, String>;

const BUILD_ENVIRONMENT: [(&str, &str); 3] =
    [("LC_ALL", "C"), ("TZ", "UTC"), ("SOURCE_DATE_EPOCH", "0")];

#[derive(Debug, Serialize, Deserialize)]
pub struct Artifact {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SourceInput {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub schema: u32,
    pub build_id: String,
    pub source_revision: Option<String>,
    pub source_dirty: bool,
    pub source_sha256: String,
    pub source_inputs: Vec<SourceInput>,
    pub toolchain: String,
    pub rustc: String,
    pub cargo: String,
    pub cargo_lock_sha256: String,
    pub loader_lock_sha256: String,
    pub profile: String,
    pub declared_environment: std::collections::BTreeMap<String, String>,
    pub target: String,
    pub qemu_test_exit: bool,
    #[serde(default)]
    pub fixture: Option<String>,
    pub signed: bool,
    pub kernel: Artifact,
    pub image: Artifact,
    pub loader: Artifact,
    pub image_builder: Artifact,
    #[serde(default)]
    pub supervisor: Vec<Artifact>,
}

pub fn hash_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let size = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|error| format!("{}: {error}", path.display()))
}

fn probe(root: &Path, program: &str, arguments: &[&str]) -> Result<String> {
    let captured = SystemRunner
        .run(&Invocation::new(program, arguments, root))
        .map_err(|error| error.to_string())?
        .checked()
        .map_err(|error| error.to_string())?;
    String::from_utf8(captured.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| error.to_string())
}

pub(crate) fn source_inputs(root: &Path) -> Result<(String, Vec<SourceInput>)> {
    let paths = probe(
        root,
        "git",
        &[
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
    )?;
    let mut paths: Vec<_> = paths.split('\0').filter(|path| !path.is_empty()).collect();
    paths.sort_unstable();
    paths.dedup();
    if paths.is_empty() {
        return Err("no source files found; build requires a Git working tree".into());
    }
    let mut inputs = Vec::new();
    let mut hash = Sha256::new();
    for path in paths {
        let absolute = root.join(path);
        if !absolute.exists() {
            continue;
        } // tracked deletion is recorded by source_dirty
        if !fs::symlink_metadata(&absolute)
            .map_err(|error| error.to_string())?
            .is_file()
        {
            return Err(format!("source input must be a regular file: {path}"));
        }
        let sha256 = hash_file(&absolute)?;
        hash.update((path.len() as u64).to_le_bytes());
        hash.update(path.as_bytes());
        hash.update(sha256.as_bytes());
        inputs.push(SourceInput {
            path: path.to_owned(),
            sha256,
        });
    }
    Ok((format!("{:x}", hash.finalize()), inputs))
}

pub fn unique_directory(parent: &Path, prefix: &str) -> Result<PathBuf> {
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let path = parent.join(format!("{prefix}-{}-{nanos}", std::process::id()));
    fs::create_dir(&path).map_err(|error| error.to_string())?;
    Ok(path)
}

pub(crate) fn logged(command: &mut Command, log: &Path) -> Result<()> {
    let file = File::create(log).map_err(|error| error.to_string())?;
    println!("Building; log: {}", log.display());
    let status = command
        .envs(BUILD_ENVIRONMENT)
        .stdin(Stdio::null())
        .stdout(file.try_clone().map_err(|error| error.to_string())?)
        .stderr(file)
        .status()
        .map_err(|error| error.to_string())?;
    if !status.success() {
        return Err(format!("build exited with {status}; see {}", log.display()));
    }
    Ok(())
}

pub fn build(options: &BuildOptions) -> Result<()> {
    let current = std::env::current_dir().map_err(|error| error.to_string())?;
    let root = doctor::workspace(&current, options.root.as_deref())?;
    for variable in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTC",
    ] {
        if std::env::var_os(variable).is_some_and(|value| !value.is_empty()) {
            return Err(format!("unset {variable} for a recorded M0 build"));
        }
    }
    let toolchain = Toolchain::load(&root)?;
    let (source_sha256, inputs) = source_inputs(&root)?;
    let cargo_lock_sha256 = hash_file(&root.join("Cargo.lock"))?;
    let loader_lock_sha256 = hash_file(&root.join("third_party/bootloader-uefi.Cargo.lock"))?;
    let profile = if options.release { "release" } else { "dev" };
    let build_id = format!(
        "{:x}",
        Sha256::digest(format!(
            "m0-v2\0{source_sha256}\0{}\0{profile}\0qemu-test-exit\0{}",
            toolchain.channel,
            options.fixture.as_deref().unwrap_or("normal")
        ))
    );
    let output = root.join("build/m0");
    let directory = unique_directory(&output.join("artifacts"), &build_id[..16])?;
    let rustc = probe(
        &root,
        "rustup",
        &["run", &toolchain.channel, "rustc", "-vV"],
    )?;
    let cargo = probe(
        &root,
        "rustup",
        &["run", &toolchain.channel, "cargo", "-vV"],
    )?;
    let source_revision = probe(&root, "git", &["rev-parse", "--verify", "HEAD"]).ok();
    let source_dirty = !probe(
        &root,
        "git",
        &["status", "--porcelain", "--untracked-files=normal"],
    )?
    .is_empty();
    if source_dirty {
        eprintln!(
            "WARNING: source tree is dirty; exact input hashes are recorded; this is not a release build."
        );
    }
    let features = match options.fixture.as_deref() {
        Some("panic") => "qemu-test-exit,test-panic",
        Some("no-framebuffer") => "qemu-test-exit,test-no-framebuffer",
        Some("exception") => "qemu-test-exit,test-unexpected-fault",
        Some("ap-timeout") => "qemu-test-exit,test-ap-timeout",
        Some("context-corruption") => "qemu-test-exit,test-context-corruption",
        Some("preempt-stall") => "qemu-test-exit,test-preempt-stall",
        Some("runtime-kernel-fault") => "qemu-test-exit,test-runtime-kernel-fault",
        Some("user-wait-stall") => "qemu-test-exit,test-user-wait-stall",
        Some("fx-corruption") => "qemu-test-exit,test-fx-corruption",
        Some("reclaim-active-root") => "qemu-test-exit,test-reclaim-active-root",
        Some("m3-pio-write") => "qemu-test-exit,test-m3-pio-write",
        Some("m3-pio-verify") => "qemu-test-exit,test-m3-pio-verify",
        Some("m3-store") => "qemu-test-exit,test-m3-store",
        Some("m3-generation") => "qemu-test-exit,test-m3-generation",
        Some("m3-owner") => "qemu-test-exit,test-m3-owner",
        Some("m3-progress") => "qemu-test-exit,test-m3-progress",
        Some("m3-file") => "qemu-test-exit,test-m3-file",
        Some("m4-display") => "qemu-test-exit,test-m4-display",
        Some("m4-desktop") => "qemu-test-exit,test-m4-desktop",
        Some("m5-native" | "m5-native-system" | "m5-native-recovery") => {
            "qemu-test-exit,test-m5-native"
        }
        Some("m5-ipc-bench") => "qemu-test-exit,test-m5-ipc-bench",
        Some("m5-provider") => "qemu-test-exit,test-m5-provider",
        None => "qemu-test-exit",
        _ => return Err("unsupported build fixture".into()),
    };
    let target = root.join("target");
    let (mut supervisor, bundle) =
        crate::supervisor::produce(&root, &directory, &toolchain, &build_id)?;
    if options.fixture.as_deref() == Some("m4-desktop") {
        crate::supervisor::extend_desktop_graph(
            &root,
            &directory,
            &toolchain,
            &build_id,
            &mut supervisor,
            &bundle,
        )?;
    }
    if let Some(fixture @ ("m5-native" | "m5-native-system" | "m5-native-recovery")) =
        options.fixture.as_deref()
    {
        use ev_userspace_contract::root_v2::native::catalogue::BootMode;
        let mode = match fixture {
            "m5-native-system" => BootMode::SystemManaged,
            "m5-native-recovery" => BootMode::Recovery,
            _ => BootMode::Standalone,
        };
        crate::supervisor::extend_native_graph(
            &root,
            &directory,
            &toolchain,
            &source_sha256,
            mode,
            &mut supervisor,
            &bundle,
        )?;
    }
    if options.fixture.as_deref() == Some("m5-ipc-bench") {
        crate::supervisor::ipc_bench_graph::extend(
            &root,
            &directory,
            &toolchain,
            &mut supervisor,
            &bundle,
        )?;
    }
    if options.fixture.as_deref() == Some("m5-provider") {
        crate::supervisor::extend_provider_graph(
            &root,
            &directory,
            &toolchain,
            &build_id,
            &mut supervisor,
            &bundle,
        )?;
    }
    let mut kernel = Command::new("rustup");
    kernel
        .current_dir(&root)
        .args([
            "run",
            &toolchain.channel,
            "cargo",
            "build",
            "--locked",
            "-p",
            "ev-kernel",
            "--target",
            "x86_64-unknown-none",
            "--features",
            features,
            "--target-dir",
        ])
        .arg(&target)
        .env("EVROSION_BUILD_ID", &build_id)
        .env("EVROSION_SOURCE_SHA256", &source_sha256)
        .env("EVROSION_SUPERVISOR_BUNDLE", &bundle)
        .env("CARGO_ENCODED_RUSTFLAGS", format!("-C\x1frelocation-model=static\x1f-C\x1fcode-model=kernel\x1f-C\x1fforce-frame-pointers=yes\x1f-C\x1flink-arg=--no-pie\x1f--remap-path-prefix={}=/evrosion", root.display()))
        .env("RUSTUP_AUTO_INSTALL", "0")
        .env("CARGO_TERM_COLOR", "never");
    if options.release {
        kernel.arg("--release");
    }
    logged(&mut kernel, &directory.join("kernel-build.log"))?;
    let kernel_source = target
        .join("x86_64-unknown-none")
        .join(if options.release { "release" } else { "debug" })
        .join("evrosion-kernel");
    fs::copy(kernel_source, directory.join("kernel.elf")).map_err(|error| error.to_string())?;
    let mut builder = Command::new("rustup");
    // Separate cache generation: upstream's nested cargo invocation does not declare
    // target rustflags as a rerun input. v2 must never reuse a pre-policy EFI binary.
    let builder_target = target.join("m0-image-v2");
    builder
        .current_dir(&root)
        .args([
            "run",
            &toolchain.channel,
            "cargo",
            "build",
            "--locked",
            "-p",
            "ev-image-builder",
            "--target-dir",
        ])
        .arg(&builder_target)
        .env(
            "CARGO_TARGET_X86_64_UNKNOWN_UEFI_RUSTFLAGS",
            "-C link-arg=/debug:none",
        )
        .env("RUSTUP_AUTO_INSTALL", "0")
        .env("CARGO_TERM_COLOR", "never");
    logged(&mut builder, &directory.join("image-builder-build.log"))?;
    let builder_binary = directory.join("ev-image-builder");
    fs::copy(
        builder_target.join("debug/ev-image-builder"),
        &builder_binary,
    )
    .map_err(|error| error.to_string())?;
    let mut image = Command::new(&builder_binary);
    image
        .current_dir(&root)
        .arg(directory.join("kernel.elf"))
        .arg(directory.join("evrosion-uefi.img"))
        .arg(directory.join("loader"));
    logged(&mut image, &directory.join("image-build.log"))?;
    // The PXE export exposes the exact embedded EFI bytes for the input manifest.
    // Its duplicate kernel is unnecessary; the retained unstripped ELF is above.
    fs::remove_file(directory.join("loader/kernel-x86_64")).map_err(|error| error.to_string())?;
    if source_inputs(&root)?.0 != source_sha256 {
        return Err("source files changed during build; rerun cargo ev build".into());
    }
    let artifact = |name: &str| -> Result<Artifact> {
        let path = directory.join(name);
        Ok(Artifact {
            path: path
                .strip_prefix(&output)
                .map_err(|error| error.to_string())?
                .to_str()
                .ok_or("non-UTF-8 artifact path")?
                .into(),
            sha256: hash_file(&path)?,
        })
    };
    let manifest = Manifest {
        schema: 1,
        build_id,
        source_revision,
        source_dirty,
        source_sha256,
        source_inputs: inputs,
        toolchain: toolchain.channel,
        rustc,
        cargo,
        cargo_lock_sha256,
        loader_lock_sha256,
        profile: profile.into(),
        declared_environment: BUILD_ENVIRONMENT
            .into_iter()
            .chain([(
                "CARGO_TARGET_X86_64_UNKNOWN_UEFI_RUSTFLAGS",
                "-C link-arg=/debug:none",
            )])
            .map(|(key, value)| (key.into(), value.into()))
            .collect(),
        target: "x86_64-unknown-none".into(),
        qemu_test_exit: true,
        fixture: options.fixture.clone(),
        signed: false,
        kernel: artifact("kernel.elf")?,
        image: artifact("evrosion-uefi.img")?,
        loader: artifact("loader/bootloader")?,
        image_builder: artifact("ev-image-builder")?,
        supervisor,
    };
    write_json(&directory.join("manifest.json"), &manifest)?;
    let temporary = directory.join("publish-manifest.json");
    write_json(&temporary, &manifest)?;
    fs::rename(temporary, output.join("manifest.json")).map_err(|error| error.to_string())?;
    println!(
        "PASS build={}\nKernel: {}\nImage: {}\nManifest: {}",
        manifest.build_id,
        output.join(&manifest.kernel.path).display(),
        output.join(&manifest.image.path).display(),
        output.join("manifest.json").display()
    );
    Ok(())
}

pub fn verify_artifact(output: &Path, artifact: &Artifact) -> Result<PathBuf> {
    let relative = Path::new(&artifact.path);
    if relative.is_absolute()
        || !relative
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_)))
    {
        return Err("artifact path must stay within build/m0".into());
    }
    let path = output
        .join(relative)
        .canonicalize()
        .map_err(|error| error.to_string())?;
    if !path.starts_with(output.canonicalize().map_err(|error| error.to_string())?) {
        return Err("artifact symlink escapes build/m0".into());
    }
    if hash_file(&path)? != artifact.sha256 {
        return Err(format!("artifact digest mismatch: {}", path.display()));
    }
    Ok(path)
}
