//! Explicit, owned M8 build and VM observation. No successful observation is a
//! shutdown, recovery, provisioning-cut or whole-milestone acceptance claim.
use super::{
    Options,
    bundle::{self, Input, Inputs},
};
use crate::{build, toolchain::Toolchain};

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MIN_FREE: u64 = 2 * 1024 * 1024 * 1024;
// The aggregate bundle retains every full linked stack census. The measured
// A1 bundle is 4,477,315 bytes; the small build record has no such payload.
const BUNDLE_EVIDENCE_MAX_BYTES: u64 = 8 * 1024 * 1024;
const BUILD_EVIDENCE_MAX_BYTES: u64 = 4 * 1024 * 1024;
pub(super) fn free(path: &Path, reserve: u64) -> Result<(), String> {
    let out = Command::new("df")
        .args(["-B1", "--output=avail"])
        .arg(path)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err("cannot measure free disk".into());
    }
    let n = String::from_utf8(out.stdout)
        .map_err(|e| e.to_string())?
        .lines()
        .last()
        .ok_or("df omitted free bytes")?
        .trim()
        .parse::<u64>()
        .map_err(|e| e.to_string())?;
    if n < MIN_FREE + reserve {
        return Err(format!(
            "need >=2GiB free plus {reserve} bytes reservation; actual {n}"
        ));
    }
    Ok(())
}
pub(super) fn target(root: &Path) -> Result<PathBuf, String> {
    let p = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target"));
    fs::create_dir_all(&p).map_err(|e| e.to_string())?;
    p.canonicalize().map_err(|e| e.to_string())
}
pub(super) fn cargo(root: &Path, target: &Path) -> Result<Command, String> {
    let mut c = Command::new("rustup");
    c.current_dir(root)
        .args([
            "run",
            &Toolchain::load(root)?.channel,
            "cargo",
            "build",
            "--locked",
            "--offline",
            "-j1",
            "--target-dir",
        ])
        .arg(target)
        .env("CARGO_INCREMENTAL", "0")
        .env("RUSTUP_AUTO_INSTALL", "0");
    Ok(c)
}
pub(super) fn flags(root: &Path, kernel: bool) -> String {
    [
        "-C".into(),
        "relocation-model=static".into(),
        "-C".into(),
        format!("code-model={}", if kernel { "kernel" } else { "large" }),
        "-C".into(),
        "force-frame-pointers=yes".into(),
        "-C".into(),
        "debuginfo=1".into(),
        "-C".into(),
        "link-arg=--no-pie".into(),
        "--cfg".into(),
        "curve25519_dalek_backend=\"serial\"".into(),
        format!("--remap-path-prefix={}=/evrosion", root.display()),
    ]
    .join("\x1f")
}
fn bounded_json(path: &Path, max_bytes: u64) -> Result<serde_json::Value, String> {
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !m.is_file() || m.len() > max_bytes {
        return Err(format!(
            "expected regular JSON evidence within {max_bytes} bytes"
        ));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(
            max_bytes
                .checked_add(1)
                .ok_or("JSON evidence bound overflow")?,
        )
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!("JSON evidence grew beyond {max_bytes} bytes"));
    }
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}
/// Compare entry and every literal loaded byte; debug stripping must not alter
/// executable content or LOAD layout. This is independent of hash equality.
type LoadedIdentity = (u64, Vec<(Vec<u8>, Vec<u8>)>);
fn load_identity(bytes: &[u8]) -> Result<LoadedIdentity, String> {
    fn n(b: &[u8], at: usize, len: usize) -> Result<u64, String> {
        let s = b.get(at..at + len).ok_or("truncated ELF")?;
        let mut a = [0; 8];
        a[..len].copy_from_slice(s);
        Ok(u64::from_le_bytes(a))
    }
    if bytes.get(..7) != Some(b"\x7fELF\x02\x01\x01") {
        return Err("not ELF64 LE".into());
    }
    let ph = n(bytes, 32, 8)? as usize;
    let size = n(bytes, 54, 2)? as usize;
    let count = n(bytes, 56, 2)? as usize;
    if size != 56 || count > 128 {
        return Err("ELF header shape refused".into());
    }
    let mut out = Vec::new();
    for i in 0..count {
        let at = ph
            .checked_add(i.checked_mul(size).ok_or("ELF overflow")?)
            .ok_or("ELF overflow")?;
        let header = bytes.get(at..at + 56).ok_or("truncated ELF phdr")?;
        if n(header, 0, 4)? == 1 {
            let start = usize::try_from(n(header, 8, 8)?).map_err(|_| "ELF offset")?;
            let len = usize::try_from(n(header, 32, 8)?).map_err(|_| "ELF length")?;
            let end = start.checked_add(len).ok_or("ELF extent overflow")?;
            let payload = bytes.get(start..end).ok_or("truncated ELF LOAD")?;
            out.push((header.to_vec(), payload.to_vec()));
        }
    }
    if out.is_empty() {
        return Err("ELF has no LOAD".into());
    }
    Ok((n(bytes, 24, 8)?, out))
}
pub(super) fn strip(
    root: &Path,
    directory: &Path,
    name: &str,
    original: &Path,
) -> Result<PathBuf, String> {
    let out = Command::new("rustup")
        .args([
            "run",
            &Toolchain::load(root)?.channel,
            "rustc",
            "--print",
            "sysroot",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err("cannot resolve pinned objcopy".into());
    }
    let sys = String::from_utf8(out.stdout).map_err(|e| e.to_string())?;
    let tool = Path::new(sys.trim()).join("lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objcopy");
    let path = directory.join(format!("{name}.elf"));
    let mut c = Command::new(&tool);
    c.arg("--strip-debug").arg(original).arg(&path);
    build::logged(&mut c, &directory.join(format!("{name}-strip.log")))?;
    let a = fs::read(original).map_err(|e| e.to_string())?;
    let b = fs::read(&path).map_err(|e| e.to_string())?;
    if load_identity(&a)? != load_identity(&b)? {
        return Err("canonical strip changed entry or literal loaded identity".into());
    }
    bundle::write_json_new(
        &directory.join(format!("{name}-strip.json")),
        &serde_json::json!({"schema":1,"strip":"--strip-debug","original_sha256":bundle::hex(&bundle::hash(&a)),"canonical_sha256":bundle::hex(&bundle::hash(&b)),"canonical_bytes":b.len(),"loaded_bytes_compared_bytewise":true,"objcopy_sha256":build::hash_file(&tool)?}),
    )?;
    Ok(path)
}
fn audit_kernel(root: &Path, directory: &Path) -> Result<(), String> {
    let mut c = Command::new("python3");
    c.current_dir(root)
        .arg(root.join("tools/m5/stack_audit.py"))
        .arg(directory.join("kernel.elf"))
        .arg(directory.join("kernel.stack.json"));
    build::logged(&mut c, &directory.join("kernel-stack.log"))
}
pub fn build_kernel(root: &Path, directory: &Path) -> Result<(), String> {
    free(directory, 256 * 1024 * 1024)?;
    let info = bounded_json(&directory.join("bundle.json"), BUNDLE_EVIDENCE_MAX_BYTES)?;
    let source = info["source_sha256"]
        .as_str()
        .ok_or("bundle lacks source identity")?;
    if build::source_inputs(root)?.0 != source {
        return Err("source changed after bundle preparation; prepare a fresh bundle".into());
    }
    let t = target(root)?;
    let mut c = cargo(root, &t)?;
    c.args([
        "-p",
        "ev-kernel",
        "--bin",
        "evrosion-kernel",
        "--release",
        "--target",
        "x86_64-unknown-none",
        "--features",
        "qemu-test-exit,test-m8-workspace-run",
    ])
    .env(
        "EVROSION_WORKSPACE_BUNDLE",
        directory.join("workspace-bundle.rs"),
    )
    .env("EVROSION_BUILD_ID", format!("m8-{}", &source[..16]))
    .env("EVROSION_SOURCE_SHA256", source)
    .env(
        "CARGO_ENCODED_RUSTFLAGS",
        format!(
            "{}\x1f--cfg\x1fev_m8_kernel_source_{}",
            flags(root, true),
            &source[..16]
        ),
    );
    build::logged(&mut c, &directory.join("kernel-build.log"))?;
    let full = directory.join("kernel.full.elf");
    fs::copy(t.join("x86_64-unknown-none/release/evrosion-kernel"), &full)
        .map_err(|e| e.to_string())?;
    strip(root, directory, "kernel", &full)?;
    audit_kernel(root, directory)?;
    free(directory, 192 * 1024 * 1024)?;
    let mut c = cargo(root, &t)?;
    c.args(["-p", "ev-image-builder"])
        .env(
            "CARGO_ENCODED_RUSTFLAGS",
            format!("--cfg\x1fev_m8_image_source_{}", &source[..16]),
        )
        .env(
            "CARGO_TARGET_X86_64_UNKNOWN_UEFI_RUSTFLAGS",
            "-C link-arg=/debug:none",
        );
    build::logged(&mut c, &directory.join("image-builder-build.log"))?;
    let executable = directory.join("ev-image-builder");
    fs::copy(t.join("debug/ev-image-builder"), &executable).map_err(|e| e.to_string())?;
    let mut c = Command::new(&executable);
    c.current_dir(root)
        .arg(directory.join("kernel.elf"))
        .arg(directory.join("evrosion-uefi.img"))
        .arg(directory.join("loader"));
    build::logged(&mut c, &directory.join("image-build.log"))?;
    if build::source_inputs(root)?.0 != source {
        return Err(
            "source changed during selected build; evidence retained, rebuild required".into(),
        );
    }
    bundle::write_json_new(
        &directory.join("build.json"),
        &serde_json::json!({"schema":1,"scope":"Actual selected V5 Kernel and EFI image; no VM admission or milestone acceptance","kernel_feature":"test-m8-workspace-run","source_sha256":source,"kernel_sha256":build::hash_file(&directory.join("kernel.elf"))?,"image_sha256":build::hash_file(&directory.join("evrosion-uefi.img"))?,"image_builder_sha256":build::hash_file(&executable)?,"loader_retained":true}),
    )
}
pub fn rebuild(options: &Options) -> Result<(), String> {
    let root = options.root.canonicalize().map_err(|e| e.to_string())?;
    let directory = bundle::new_output(options.output.as_ref().unwrap())?;
    let actors = directory.join("actors");
    fs::create_dir(&actors).map_err(|e| e.to_string())?;
    let before = build::source_inputs(&root)?.0;
    let t = target(&root)?;
    let specs = [
        (
            "root",
            "ev-workspace-root",
            "ev-workspace-root",
            "native-actor",
        ),
        (
            "shell",
            "ev-workspace-shell-panel",
            "ev-workspace-shell-panel",
            "executable",
        ),
        ("input", "ev-desktop", "ev-desktop", "workspace-input"),
        (
            "workspace",
            "ev-workspace-service",
            "ev-workspace-service",
            if options.provision_new {
                "provision-new"
            } else {
                "native-actor"
            },
        ),
        (
            "block",
            "ev-block-service",
            "ev-block-service",
            "pio-words256",
        ),
        (
            "display",
            "ev-workspace-display",
            "ev-workspace-display",
            "native-actor",
        ),
        (
            "net_driver",
            "ev-net-driver",
            "ev-net-driver",
            "driver-service,workspace-profile",
        ),
        (
            "net_service",
            "ev-net-driver",
            "ev-net-service",
            "stack-executable,workspace-profile",
        ),
        ("files", "ev-native-files", "ev-native-files", "executable"),
        (
            "editor",
            "ev-native-editor",
            "ev-native-editor",
            "executable",
        ),
        (
            "inspector",
            "ev-native-inspector",
            "ev-native-inspector",
            "executable",
        ),
        (
            "editor_candidate",
            "ev-native-editor",
            "ev-native-editor",
            "executable,update-b",
        ),
    ];
    bundle::write_json_new(
        &directory.join("rebuild-features.json"),
        &serde_json::json!({"schema":1,"scope":"Explicit selected source-build features; not reproduction of older prebuilt actor pins or runtime acceptance","source_before":before,"actors":specs}),
    )?;
    let mut rows = std::collections::BTreeMap::new();
    for (name, package, bin, feature) in specs {
        free(&directory, 128 * 1024 * 1024)?;
        let mut c = cargo(&root, &t)?;
        c.args([
            "-p",
            package,
            "--bin",
            bin,
            "--release",
            "--target",
            "x86_64-unknown-none",
            "--features",
            feature,
        ])
        .env("CARGO_ENCODED_RUSTFLAGS", flags(&root, false));
        build::logged(&mut c, &actors.join(format!("{name}-build.log")))?;
        let full = actors.join(format!("{name}.full.elf"));
        fs::copy(t.join("x86_64-unknown-none/release").join(bin), &full)
            .map_err(|e| e.to_string())?;
        let path = strip(&root, &actors, name, &full)?;
        rows.insert(
            name,
            Input {
                sha256: build::hash_file(&path)?,
                path,
                analysis: None,
            },
        );
    }
    if before != build::source_inputs(&root)?.0 {
        return Err(
            "sources changed during actor rebuild; inputs retained, fresh rebuild required".into(),
        );
    }
    let mut take = |s| rows.remove(s).expect("fixed rebuild actor set");
    let inputs = Inputs {
        schema: 1,
        root: take("root"),
        shell: take("shell"),
        input: take("input"),
        workspace: take("workspace"),
        block: take("block"),
        display: take("display"),
        net_driver: take("net_driver"),
        net_service: take("net_service"),
        files: take("files"),
        editor: take("editor"),
        inspector: take("inspector"),
        editor_candidate: Some(take("editor_candidate")),
        workspace_mode: if options.provision_new {
            "provision-new"
        } else {
            "open"
        }
        .into(),
        semantic_tree: super::SemanticDeclarations {
            editor: true,
            editor_candidate: true,
            ..options.semantic_tree
        },
        file_app_packages: None,
        external_ingress: None,
    };
    let input = directory.join("rebuilt-artifacts.json");
    bundle::write_json_new(&input, &inputs)?;
    bundle::prepare(&root, &directory, &input, &inputs)?;
    build_kernel(&root, &directory)
}

struct Region {
    file: File,
    reads: u64,
    writes: u64,
    flushes: u64,
    origin: Instant,
}
impl ev_workspace_store::SectorIo for Region {
    type Error = String;
    fn sectors(&self) -> u64 {
        ev_workspace_store::REQUIRED_SECTORS
    }
    fn read(
        &mut self,
        lba: u64,
        out: &mut ev_workspace_store::Sector,
        deadline: u64,
    ) -> Result<(), String> {
        self.seek(lba, deadline)?;
        self.file.read_exact(out).map_err(|e| e.to_string())?;
        self.reads += 1;
        Ok(())
    }
    fn write(
        &mut self,
        lba: u64,
        bytes: &ev_workspace_store::Sector,
        deadline: u64,
    ) -> Result<(), String> {
        self.seek(lba, deadline)?;
        self.file.write_all(bytes).map_err(|e| e.to_string())?;
        self.writes += 1;
        Ok(())
    }
    fn flush(&mut self, deadline: u64) -> Result<(), String> {
        if deadline == 0
            || deadline == u64::MAX
            || self.origin.elapsed().as_millis() >= u128::from(deadline)
        {
            return Err("invalid finite deadline".into());
        }
        self.file.sync_all().map_err(|e| e.to_string())?;
        self.flushes += 1;
        Ok(())
    }
}
impl Region {
    fn seek(&mut self, lba: u64, deadline: u64) -> Result<(), String> {
        if lba >= ev_workspace_store::REQUIRED_SECTORS
            || deadline == 0
            || deadline == u64::MAX
            || self.origin.elapsed().as_millis() >= u128::from(deadline)
        {
            return Err("workspace region/deadline refused".into());
        }
        self.file
            .seek(SeekFrom::Start((16384 + lba) * 512))
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}
fn prefix(path: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let mut f = File::open(path).map_err(|e| e.to_string())?;
    let mut h = Sha256::new();
    let mut b = [0; 4096];
    for _ in 0..2048 {
        f.read_exact(&mut b).map_err(|e| e.to_string())?;
        h.update(b);
    }
    Ok(format!("{:x}", h.finalize()))
}
fn provision(path: &Path, evidence: &Path) -> Result<(), String> {
    let before = prefix(path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    let region = Region {
        file,
        reads: 0,
        writes: 0,
        flushes: 0,
        origin: Instant::now(),
    };
    let mut scratch = Box::new(ev_workspace_store::Scratch::empty());
    let start = Instant::now();
    let dataset = ev_workspace_store::Dataset::format_new(
        region,
        &mut scratch,
        ev_workspace_store::DatasetId::new([0x84; 16]).unwrap(),
        60_000,
    )
    .map_err(|e| format!("actual host NEW-only Dataset format:{:?}", e.error))?;
    let namespace = dataset.namespace_revision();
    drop(dataset);
    let after = prefix(path)?;
    if before != after {
        return Err("host workspace provision altered legacy prefix".into());
    }
    bundle::write_json_new(
        evidence,
        &serde_json::json!({"schema":1,"scope":"Explicit host-owned NEW disk provisioning using actual Dataset::format_new; NOT guest provisioning or cut qualification","disk":path,"disk_bytes":96*1024*1024,"physical_first_sector":16384,"workspace_sectors":ev_workspace_store::REQUIRED_SECTORS,"dataset_id":bundle::hex(&[0x84;16]),"namespace_revision":namespace,"empty_dataset":true,"host_deadline_ms":60000,"clock":"host Instant since region owner construction","elapsed_ms":start.elapsed().as_millis(),"legacy_prefix_scope":"new all-zero disk prefix unchanged; no historical Store/File compatibility claim","legacy_prefix_bytes":8*1024*1024,"legacy_prefix_before":before,"legacy_prefix_after":after,"legacy_prefix_unchanged":true,"backend_source_sha256":build::hash_file(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../libs/workspace-store/src/engine.rs"))?}),
    )
}
struct ChildOwner(Child);
impl Drop for ChildOwner {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn firmware(explicit: Option<&Path>, default: &str) -> Result<PathBuf, String> {
    let p = explicit
        .unwrap_or_else(|| Path::new(default))
        .canonicalize()
        .map_err(|e| format!("explicit/default OVMF unavailable:{e}"))?;
    let m = fs::symlink_metadata(&p).map_err(|e| e.to_string())?;
    if !m.is_file() || m.len() == 0 || m.len() > 8 * 1024 * 1024 {
        return Err("firmware input must be bounded regular file".into());
    }
    Ok(p)
}
pub fn preview(options: &Options) -> Result<(), String> {
    let root = options.root.canonicalize().map_err(|e| e.to_string())?;
    let prepared = options
        .prepared
        .as_ref()
        .unwrap()
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let bundle = bounded_json(&prepared.join("bundle.json"), BUNDLE_EVIDENCE_MAX_BYTES)?;
    let build_info = bounded_json(&prepared.join("build.json"), BUILD_EVIDENCE_MAX_BYTES)?;
    let mode = bundle["workspace_mode"]
        .as_str()
        .ok_or("prepared bundle mode missing")?;
    let has_template = options.owned_data_template.is_some();
    if !matches!(mode, "open" | "provision-new")
        || (mode == "open") != (options.host_provision_new || has_template)
        || options.host_provision_new && has_template
    {
        return Err("normal-open preview requires host provisioning or an explicit verified template; guest provision-new forbids both".into());
    }
    let image = prepared.join("evrosion-uefi.img");
    if build_info["image_sha256"].as_str() != Some(build::hash_file(&image)?.as_str()) {
        return Err("prepared boot image hash differs".into());
    }
    free(&prepared, 128 * 1024 * 1024)?;
    let name = format!(
        "preview-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos()
    );
    let directory = bundle::new_output(&prepared.join(name))?;
    let data = directory.join("owned-workspace-96MiB.raw");
    let template_witness = if let Some(source) = options.owned_data_template.as_deref() {
        Some(super::template::clone_new(
            source,
            &data,
            options
                .owned_data_template_sha256
                .as_deref()
                .ok_or("template SHA missing")?,
            &directory.join("template-clone.json"),
        )?)
    } else {
        let f = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&data)
            .map_err(|e| e.to_string())?;
        f.set_len(96 * 1024 * 1024).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        drop(f);
        None
    };
    if options.host_provision_new {
        provision(&data, &directory.join("host-provision.json"))?;
    }
    if options
        .scenario
        .as_deref()
        .is_some_and(|p| matches!(p, "large-io" | "large-io-finite"))
        && !inspect_scenario(
            &data,
            &directory.join("template-initial-data.json"),
            true,
            true,
        )?
    {
        return Err("large-io requires the exact clean dataset84/ns3/slot1/gen1/rev2 one-MiB a-pattern fixture before any guest input".into());
    }
    let code = firmware(
        options.ovmf_code.as_deref(),
        "/usr/share/OVMF/OVMF_CODE_4M.fd",
    )?;
    let vars = firmware(
        options.ovmf_vars.as_deref(),
        "/usr/share/OVMF/OVMF_VARS_4M.fd",
    )?;
    let owned_vars = directory.join("OVMF_VARS.fd");
    bundle::write_new(&owned_vars, &fs::read(&vars).map_err(|e| e.to_string())?)?;
    let serial = directory.join("serial.log");
    let qmpdir = std::env::temp_dir().join(format!(
        "ev-m8-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos()
    ));
    fs::create_dir(&qmpdir).map_err(|e| e.to_string())?;
    let qmp = qmpdir.join("qmp.sock");
    let restart_selected = options.scenario.as_deref() == Some("files-restart");
    let mut args: Vec<String> = vec![
        "-machine",
        "q35,accel=tcg",
        "-cpu",
        "max",
        "-smp",
        "1",
        "-m",
        "256M",
        "-nodefaults",
        "-no-user-config",
        "-no-reboot",
        "-S",
        "-display",
        if options.headless {
            "none"
        } else {
            "gtk,gl=off"
        },
        "-monitor",
        "none",
        "-nic",
        "none",
        "-device",
        "VGA",
        "-device",
        "isa-debug-exit,iobase=0xf4,iosize=0x04",
        "-device",
        "isa-serial,chardev=com1",
        "-boot",
        "order=c",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if restart_selected {
        args.retain(|arg| arg != "-no-reboot");
    }
    for(k,v)in[("-chardev",format!("file,id=com1,path={}",serial.display())),("-drive",format!("if=pflash,format=raw,unit=0,readonly=on,file={}",code.display())),("-drive",format!("if=pflash,format=raw,unit=1,file={}",owned_vars.display())),("-drive",format!("if=ide,format=raw,snapshot=on,file={}",image.display())),("-device","isa-ide,id=evpio,iobase=0x1e8,iobase2=0x3ee,irq=10".into()),("-drive",format!("if=none,id=evdata,format=raw,cache=writeback,snapshot=off,rerror=report,werror=report,file={}",data.display())),("-device","ide-hd,drive=evdata,bus=evpio.0,unit=0,serial=EVROSION-M8-WORK    ,logical_block_size=512,physical_block_size=512".into()),("-device",crate::vm_profile::NIC.into()),("-netdev",crate::vm_profile::NETDEV.into()),("-rtc",crate::vm_profile::RTC.into()),("-qmp",format!("unix:{},server=on,wait=off",qmp.display()))]{args.push(k.into());args.push(v);}
    if restart_selected {
        crate::vm_profile::workspace_restart_arguments(&args)?;
    } else {
        crate::vm_profile::workspace_arguments(&args)?;
    }
    let qemu = Command::new("which")
        .arg("qemu-system-x86_64")
        .output()
        .map_err(|e| e.to_string())?;
    if !qemu.status.success() {
        return Err("QEMU executable missing".into());
    }
    let binary = PathBuf::from(
        String::from_utf8(qemu.stdout)
            .map_err(|e| e.to_string())?
            .trim(),
    );
    for path in [&data, &serial, &code, &owned_vars, &image, &qmp] {
        let value = path.to_str().ok_or("QEMU paths must be UTF8")?;
        if value.chars().any(|c| c == ',' || c.is_control()) {
            return Err("QEMU paths reject option separators and controls".into());
        }
    }
    let qualification = if restart_selected {
        crate::vm_profile::qualify_workspace_restart(&binary, &args)?
    } else {
        crate::vm_profile::qualify_workspace(&binary, &args)?
    };
    bundle::write_json_new(&directory.join("vm-profile.json"), &qualification)?;
    let stderr = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("qemu.stderr.log"))
        .map_err(|e| e.to_string())?;
    bundle::write_json_new(
        &directory.join("launch.json"),
        &serde_json::json!({"schema":1,"scope":"Owned M8 VM graph observation only; host provision/template clone explicitly separate","argv":args,"qemu":binary,"qemu_sha256":build::hash_file(&binary)?,"firmware_code_sha256":build::hash_file(&code)?,"firmware_vars_template_sha256":build::hash_file(&vars)?,"data_disk":data,"boot_image_sha256":build::hash_file(&image)?,"prepared_kernel_source_sha256":build_info["source_sha256"],"observer_executable_sha256":build::hash_file(&std::env::current_exe().map_err(|e|e.to_string())?)?,"workspace_mode":mode,"host_provision_new":options.host_provision_new,"owned_template":template_witness,"timeout_seconds":options.timeout,"qmp_socket":qmp,"root":root}),
    )?;
    let child = Command::new(&binary)
        .current_dir(&qmpdir)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut owner = ChildOwner(child);
    let start = Instant::now();
    let absolute_deadline = start + Duration::from_secs(options.timeout);
    while !qmp.exists() {
        if start.elapsed() > Duration::from_secs(5)
            || owner.0.try_wait().map_err(|e| e.to_string())?.is_some()
        {
            return Err("owned QEMU did not publish private QMP socket; evidence retained".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut monitor = crate::qmp::Qmp::connect_at(&qmpdir, absolute_deadline, start)?;
    monitor.start_verified_prelaunch()?;
    let mut scenario = options.scenario.as_ref().map(|profile| {
        if profile == "inspector-reader" {
            super::scenario::Scenario::reader(&root)
        } else if profile == "files-restart" {
            super::scenario::Scenario::restart(&root)
        } else if profile == "inspector-own" {
            super::scenario::Scenario::own(&root)
        } else if profile == "files-shutdown" {
            super::scenario::Scenario::shutdown(&root)
        } else if profile == "files-a1" {
            super::scenario::Scenario::a1(&root)
        } else if profile == "large-io" {
            super::scenario::Scenario::large(&root)
        } else if profile == "large-io-finite" {
            super::scenario::Scenario::large_finite(&root)
        } else if profile == "legacy-owner" {
            super::scenario::Scenario::legacy(&root)
        } else {
            super::scenario::Scenario::new(&root)
        }
    });
    let mut scenario_error = None;
    let mut screenshot = false;
    let mut timed_out = false;
    let mut disk_floor_reached = false;
    let mut last_disk_check = Instant::now();
    let mut scenario_origin = Duration::ZERO;
    let mut restart_witness = None;
    let mut awaiting_reset_since = None;
    let expected_build = format!(
        "m8-{}",
        build_info["source_sha256"]
            .as_str()
            .and_then(|value| value.get(..16))
            .ok_or("prepared source identity missing")?
    );
    if restart_selected {
        scenario
            .as_mut()
            .unwrap()
            .set_power_pacing(serial.clone(), expected_build.clone());
    }
    let status = loop {
        if let Some(s) = owner.0.try_wait().map_err(|e| e.to_string())? {
            break s;
        }
        if last_disk_check.elapsed() >= Duration::from_secs(1) {
            last_disk_check = Instant::now();
            if free(&prepared, 0).is_err() {
                disk_floor_reached = true;
                owner.0.kill().map_err(|e| e.to_string())?;
                break owner.0.wait().map_err(|e| e.to_string())?;
            }
        }
        if let Some(scenario) = scenario.as_mut()
            && let Err(error) = scenario.tick(
                &mut monitor,
                start.elapsed().saturating_sub(scenario_origin),
            )
        {
            scenario_error = Some(error);
            owner.0.kill().map_err(|e| e.to_string())?;
            break owner.0.wait().map_err(|e| e.to_string())?;
        }
        if restart_selected
            && restart_witness.is_none()
            && scenario.as_ref().is_some_and(|s| s.complete())
        {
            let first = *awaiting_reset_since.get_or_insert(start.elapsed());
            let observation = (|| {
                if start.elapsed().saturating_sub(first) > Duration::from_secs(45) {
                    return Err("checked restart did not produce an actual guest RESET and fresh second boot within the original observation allowance".into());
                }
                monitor.poll_restart_events()?;
                if fs::metadata(&serial).map_err(|e| e.to_string())?.len() > 4 * 1024 * 1024 {
                    return Err("restart serial exceeded its observation bound".into());
                }
                let bytes = fs::read(&serial).map_err(|e| e.to_string())?;
                super::restart::observe(&bytes, monitor.transcript(), &expected_build)
            })();
            match observation {
                Ok(Some(witness)) => {
                    scenario
                        .as_ref()
                        .unwrap()
                        .report(&directory.join("scenario-before-restart.json"), &None)?;
                    bundle::write_json_new(
                        &directory.join("restart-second-boot.json"),
                        &serde_json::json!({
                            "witness":witness,"observed_elapsed_ms":start.elapsed().as_millis(),
                            "scope":"Actual guest RESET and new same-build selected record; native reopen and final checked shutdown remain required"
                        }),
                    )?;
                    restart_witness = Some(witness);
                    scenario = Some(super::scenario::Scenario::reopened(&root));
                    scenario
                        .as_mut()
                        .unwrap()
                        .set_power_pacing(serial.clone(), expected_build.clone());
                    scenario_origin = start.elapsed();
                }
                Ok(None) => (),
                Err(error) => {
                    scenario_error = Some(error);
                    owner.0.kill().map_err(|e| e.to_string())?;
                    break owner.0.wait().map_err(|e| e.to_string())?;
                }
            }
        }
        if !screenshot
            && start.elapsed() >= Duration::from_secs(10)
            && !scenario
                .as_ref()
                .is_some_and(|s| s.power_gesture_delivered())
        {
            let capture = monitor
                .capture(1)
                .map(|(path, ppm)| serde_json::json!({"path":path,"dimensions":ppm.dimensions()}));
            bundle::write_json_new(
                &directory.join("scanout.json"),
                &serde_json::json!({"actual_qmp_capture":capture,"scope":"Actual scanout observation, no application/UI acceptance claim"}),
            )?;
            screenshot = true;
        }
        if start.elapsed() >= Duration::from_secs(options.timeout) {
            timed_out = true;
            owner.0.kill().map_err(|e| e.to_string())?;
            break owner.0.wait().map_err(|e| e.to_string())?;
        }
        if fs::metadata(&serial).is_ok_and(|m| m.len() > 4 * 1024 * 1024) {
            owner.0.kill().map_err(|e| e.to_string())?;
            let _ = owner.0.wait();
            return Err(
                "serial observation exceeded4MiB; owned VM stopped, evidence retained".into(),
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let vm_elapsed_ms = start.elapsed().as_millis();
    bundle::write_json_new(&directory.join("qmp.json"), &monitor.transcript())?;
    let template_unchanged = template_witness
        .as_ref()
        .map(|witness| {
            super::template::verify_source(witness, &directory.join("template-source-after.json"))
        })
        .transpose()?;
    if let Some(scenario) = scenario.as_ref() {
        if restart_selected && restart_witness.is_none() && scenario_error.is_none() {
            scenario_error =
                Some("restart ended without an observed guest RESET and fresh second boot".into());
        }
        if scenario_error.is_none() && !scenario.complete() {
            scenario_error = Some(
                "original owned observation ended before the complete bounded input scenario"
                    .into(),
            );
        }
        scenario.report(&directory.join("scenario.json"), &scenario_error)?;
    }
    let scenario_bytes = if scenario.is_some() {
        Some(if options.scenario.as_deref() == Some("legacy-owner") {
            inspect_legacy_readonly(
                &data,
                &directory.join("scenario-cold-bytes.json"),
                options
                    .owned_data_template_sha256
                    .as_deref()
                    .ok_or("legacy template SHA missing")?,
            )
        } else {
            inspect_scenario_profile(
                &data,
                &directory.join("scenario-cold-bytes.json"),
                options
                    .scenario
                    .as_deref()
                    .is_some_and(|p| matches!(p, "large-io" | "large-io-finite")),
                false,
                options.scenario.as_deref() == Some("inspector-own"),
            )
        })
    } else {
        None
    };
    let output =
        fs::read(&serial).map_err(|e| format!("actual serial evidence unavailable: {e}"))?;
    let fatal_guest_line = String::from_utf8_lossy(&output)
        .lines()
        .find(|line| {
            line.starts_with("EVROSION_EXCEPTION ")
                || line.starts_with("EVROSION_PANIC ")
                || line.starts_with("EVROSION_M0_RESULT status=FAIL")
        })
        .map(str::to_owned);
    let shutdown_selected = options.scenario.as_deref().is_some_and(|p| {
        matches!(
            p,
            "files-shutdown" | "inspector-own" | "inspector-reader" | "files-restart"
        )
    });
    let restart_evidence = restart_selected.then(|| {
        super::restart::observe(&output, monitor.transcript(), &expected_build)?
            .filter(|_| restart_witness.is_some())
            .ok_or_else(|| {
                "actual restart and fresh second boot evidence is incomplete".to_string()
            })
    });
    let shutdown_evidence = shutdown_selected.then(|| {
        ShutdownOutcome {
            exit_code: status.code(),
            timed_out,
            disk_floor_reached,
            fatal: fatal_guest_line.is_some(),
            scenario_complete: scenario.as_ref().is_some_and(|s| s.complete()),
            scenario_error: scenario_error.is_some(),
            cold_exact: matches!(scenario_bytes, Some(Ok(true))),
        }
        .validate(if restart_selected {
            super::restart::second_boot_bytes(&output)?
        } else {
            &output
        })
    });
    let clean_shutdown = shutdown_evidence
        .as_ref()
        .is_some_and(|proof| proof.is_ok());
    bundle::write_json_new(
        &directory.join("observation.json"),
        &serde_json::json!({"schema":1,"scope":if restart_selected{"Actual owned guest reset, fresh same-build second boot, native reopen and final checked shutdown are required. No common Root-loss recovery or full M8 acceptance."}else if shutdown_selected{"Actual owned files-shutdown observation; checked Kernel shutdown and cold bytes are required separately. No restart/recovery or full M8 acceptance."}else{"Actual QEMU observation; no clean quiescence, recovery or milestone acceptance follows"},"exit_code":status.code(),"timeout":timed_out,"disk_floor_reached":disk_floor_reached,"fatal_guest_line":fatal_guest_line,"scenario_error":scenario_error,"scenario_cold_bytes":scenario_bytes,"clean_shutdown":clean_shutdown,"checked_shutdown_evidence":shutdown_evidence,"checked_restart_evidence":restart_evidence,"restart_native_reopen_complete":restart_selected&&restart_witness.is_some()&&scenario.as_ref().is_some_and(|s|s.complete())&&scenario_error.is_none(),"elapsed_ms":vm_elapsed_ms,"host_postcheck_elapsed_ms":start.elapsed().as_millis().saturating_sub(vm_elapsed_ms),"serial_bytes":output.len(),"serial_sha256":bundle::hex(&bundle::hash(&output)),"disk_sha256":build::hash_file(&data)?,"host_provision_new":options.host_provision_new,"template_source_unchanged":template_unchanged,"m8_acceptance":false}),
    )?;
    println!(
        "M8 actual VM evidence: {} (timeout={timed_out}, exit={:?})",
        directory.display(),
        status.code()
    );
    if let Some(line) = fatal_guest_line {
        return Err(format!(
            "actual guest reported failure: {line}; evidence {}",
            directory.display()
        ));
    }
    if disk_floor_reached {
        return Err("owned VM stopped at two-GiB disk floor; evidence retained".into());
    }
    if template_unchanged == Some(false) {
        return Err("read-only template source changed; evidence retained".into());
    }
    if let Some(error) = scenario_error {
        return Err(format!("owned input scenario stopped: {error}"));
    }
    if let Some(result) = scenario_bytes {
        match result {
            Ok(true) => (),
            Ok(false) => {
                return Err(
                    "cold actual bytes do not confirm scenario result; evidence retained".into(),
                );
            }
            Err(e) => return Err(e),
        }
    }
    if let Some(proof) = shutdown_evidence {
        proof?;
    }
    if let Some(proof) = restart_evidence {
        proof?;
    }
    Ok(())
}

#[derive(Debug, serde::Serialize)]
struct CheckedShutdown {
    token: u64,
    tick: u64,
    root_exited: bool,
    starts: u64,
    calls: u64,
    replies: u64,
    clean_shutdown: bool,
}
#[derive(Clone, Copy)]
struct ShutdownOutcome {
    exit_code: Option<i32>,
    timed_out: bool,
    disk_floor_reached: bool,
    fatal: bool,
    scenario_complete: bool,
    scenario_error: bool,
    cold_exact: bool,
}
impl ShutdownOutcome {
    fn validate(self, output: &[u8]) -> Result<CheckedShutdown, String> {
        if self.exit_code != Some(33)
            || self.timed_out
            || self.disk_floor_reached
            || self.fatal
            || !self.scenario_complete
            || self.scenario_error
            || !self.cold_exact
        {
            return Err("files-shutdown requires QEMU33, complete input, exact cold bytes, no timeout/disk-floor/fatal/scenario failure".into());
        }
        let serial =
            core::str::from_utf8(output).map_err(|_| "shutdown serial is not complete UTF8")?;
        let records: Vec<_> = serial.lines().enumerate().collect();
        let power: Vec<_> = records
            .iter()
            .filter(|(_, line)| {
                line.starts_with("EVROSION_M8_SESSION_POWER phase=checked_shutdown")
            })
            .collect();
        let ended: Vec<_> = records
            .iter()
            .filter(|(_, line)| line.starts_with("EVROSION_M8_KERNEL_RUN phase=ended"))
            .collect();
        if power.len() != 1 || ended.len() != 1 || power[0].0 >= ended[0].0 {
            return Err("shutdown requires exactly one ordered checked_shutdown and clean Kernel ended record".into());
        }
        let p: Vec<_> = power[0].1.split(' ').collect();
        let e: Vec<_> = ended[0].1.split(' ').collect();
        if p.len() != 9
            || e.len() != 9
            || p[0] != "EVROSION_M8_SESSION_POWER"
            || p[1] != "phase=checked_shutdown"
            || p[4..]
                != [
                    "rpc=0",
                    "windows=0",
                    "async_debt=0",
                    "physical_proof=trusted_root_flush_stop_scrub",
                    "sources_retained_until_power=true",
                ]
            || e[0] != "EVROSION_M8_KERNEL_RUN"
            || e[1] != "phase=ended"
            || e[6..]
                != [
                    "retained=true",
                    "scope=execution_only",
                    "clean_shutdown=true",
                ]
        {
            return Err(
                "shutdown marker shape/physical ownership or clean completion differs".into(),
            );
        }
        let number = |field: &str, key: &str| -> Result<u64, String> {
            let raw = field
                .strip_prefix(key)
                .ok_or("shutdown field key differs")?;
            let n = raw
                .parse::<u64>()
                .map_err(|_| "shutdown counter is not u64")?;
            if n.to_string() != raw {
                return Err("shutdown counter is not canonical decimal".into());
            }
            Ok(n)
        };
        let token = number(p[2], "token=")?;
        if matches!(token, 0 | u64::MAX) {
            return Err("shutdown token is reserved".into());
        }
        let root_exited = match e[2] {
            "root_exited=true" => true,
            "root_exited=false" => false,
            _ => return Err("shutdown Root state is not canonical".into()),
        };
        Ok(CheckedShutdown {
            token,
            tick: number(p[3], "tick=")?,
            root_exited,
            starts: number(e[3], "starts=")?,
            calls: number(e[4], "calls=")?,
            replies: number(e[5], "replies=")?,
            clean_shutdown: true,
        })
    }
}

/// The legacy-owner plan performs only read/authority operations. Independently
/// hash every cold byte after the directly owned VM has exited; a UI status or
/// an unchanged source template alone cannot establish its clone was preserved.
fn inspect_legacy_readonly(path: &Path, evidence: &Path, expected: &str) -> Result<bool, String> {
    use sha2::{Digest, Sha256};
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file()
        || metadata.len() != 96 * 1024 * 1024
        || !super::template::expected_hash(expected)
    {
        return Err("legacy cold input must be a regular96MiB file and a full expected SHA".into());
    }
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let (mut whole, mut prefix4, mut prefix8) = (Sha256::new(), Sha256::new(), Sha256::new());
    let mut buffer = [0; 64 * 1024];
    let mut offset = 0u64;
    while offset < metadata.len() {
        let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("legacy cold input truncated".into());
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
    if offset != metadata.len() || file.read(&mut buffer[..1]).map_err(|e| e.to_string())? != 0 {
        return Err("legacy cold input length changed".into());
    }
    let actual = bundle::hex(&whole.finalize());
    let confirmed = actual == expected;
    bundle::write_json_new(
        evidence,
        &serde_json::json!({"schema":1,"scope":"OS read-only independent whole96MiB and original4MiB/prefix8MiB hashes after directly owned QEMU wait; exact whole equality establishes all original bytes unchanged, not a decoded legacy identity, retirement or authority proof","bytes":offset,"expected_sha256":expected,"actual_sha256":actual,"original4MiB_sha256":bundle::hex(&prefix4.finalize()),"prefix8MiB_sha256":bundle::hex(&prefix8.finalize()),"host_format_invoked":false,"confirmed":confirmed}),
    )?;
    Ok(confirmed)
}

fn inspect_scenario(
    path: &Path,
    evidence: &Path,
    large: bool,
    initial: bool,
) -> Result<bool, String> {
    inspect_scenario_profile(path, evidence, large, initial, false)
}

fn inspect_scenario_profile(
    path: &Path,
    evidence: &Path,
    large: bool,
    initial: bool,
    own: bool,
) -> Result<bool, String> {
    use ev_workspace_store::{Dataset, Kind, ObjectId, Scratch};
    use sha2::{Digest, Sha256};
    // Actual process wait already proved the sole owned VM exited. Open with
    // OS read-only rights: this observer cannot repair or write the volume.
    let region = Region {
        file: File::open(path).map_err(|e| e.to_string())?,
        reads: 0,
        writes: 0,
        flushes: 0,
        origin: Instant::now(),
    };
    let mut scratch = Box::new(Scratch::empty());
    let mut ds = Dataset::open(region, &mut scratch, 60_000)
        .map_err(|e| format!("cold read-only Dataset open:{:?}", e.error))?;
    let mut cursor = 0;
    let mut rows = Vec::new();
    let mut folder = false;
    let mut note = false;
    let mut own_committed = false;
    let mut large_integrity = false;
    let mut committed_large_edit = false;
    let mut initial_baseline = false;
    for _ in 0..=256 {
        let Some(m) = ds
            .list(ObjectId::ROOT, cursor, true)
            .map_err(|e| format!("cold list:{e:?}"))?
        else {
            break;
        };
        cursor = m.id.slot;
        let name = ds
            .name(m.id)
            .map_err(|e| format!("cold name:{e:?}"))?
            .to_owned();
        let mut actual_hash = None;
        let mut text = None;
        let (mut baseline, mut edited) = (true, true);
        if m.kind == Kind::File {
            let mut h = Sha256::new();
            let mut chunk = [0; 4096];
            let mut offset = 0;
            let mut small = Vec::new();
            while offset < m.length {
                let n = ds
                    .read(m.id, m.revision, offset, &mut chunk, 60_000)
                    .map_err(|e| format!("cold exact revision bytes:{e:?}"))?;
                if n == 0 {
                    return Err("cold file read made no progress".into());
                }
                h.update(&chunk[..n]);
                if large && name == "large1m.txt" {
                    for (index, byte) in chunk[..n].iter().enumerate() {
                        let at = offset + index as u64;
                        let expected = if at % 80 == 79 {
                            b'\n'
                        } else {
                            b'a' + (at % 26) as u8
                        };
                        baseline &= *byte == expected;
                        edited &= *byte == if at == m.length - 1 { b'Z' } else { expected };
                    }
                }
                if m.length <= 4096 {
                    small.extend_from_slice(&chunk[..n]);
                }
                offset += n as u64;
            }
            let hash: [u8; 32] = h.finalize().into();
            actual_hash = Some(bundle::hex(&hash));
            if hash != m.sha256 {
                return Err("independent cold whole-file digest differs".into());
            }
            if name == "note1"
                && !m.directly_trashed
                && small == super::scenario::TEXT.as_bytes()
                && m.revision > 1
            {
                note = true;
                own_committed = m.revision >= 3;
            }
            if large && name == "large1m.txt" && m.length == 1024 * 1024 && !m.directly_trashed {
                large_integrity = baseline || edited;
                initial_baseline =
                    baseline && m.id.slot == 1 && m.id.generation == 1 && m.revision == 2;
                committed_large_edit =
                    edited && m.id.slot == 1 && m.id.generation == 1 && m.revision == 3;
            }
            text = String::from_utf8(small).ok();
        } else if name == "folder1" && !m.directly_trashed {
            folder = true;
        }
        rows.push(serde_json::json!({"name":name,"slot":m.id.slot,"generation":m.id.generation,"kind":format!("{:?}",m.kind),"revision":m.revision,"length":m.length,"trashed":m.directly_trashed,"metadata_sha256":bundle::hex(&m.sha256),"independently_read_sha256":actual_hash,"bounded_utf8":text,"baseline_large_pattern":large&&name=="large1m.txt"&&baseline,"edited_large_pattern":large&&name=="large1m.txt"&&edited}));
    }
    let mut result = if large {
        large_integrity
    } else {
        folder && note
    };
    let stage = ds
        .pending_stage()
        .map_err(|e| format!("cold pending stage:{e:?}"))?;
    let receipt = ds
        .last_receipt()
        .map_err(|e| format!("cold retained receipt:{e:?}"))?;
    if initial {
        result = large
            && initial_baseline
            && ds.dataset_id().bytes() == [0x84; 16]
            && ds.namespace_revision() == 3
            && stage.is_none()
            && !ds.needs_mirror_recovery();
    } else if large {
        // Integrity of the preserved baseline is useful failure evidence, but
        // only the exact committed edited revision can confirm this scenario.
        result = committed_large_edit
            && ds.dataset_id().bytes() == [0x84; 16]
            && stage.is_none()
            && !ds.needs_mirror_recovery();
    }
    if own {
        result = !large
            && !initial
            && result
            && own_committed
            && stage.is_none()
            && !ds.needs_mirror_recovery();
    }
    bundle::write_json_new(
        evidence,
        &serde_json::json!({"schema":1,"scope":"OS read-only actual Dataset; before guest launch when initial=true, otherwise after directly owned QEMU wait. No host repair/writes or native Root quiescence claim. Large baseline/edited integrity is not native Saved; final confirmation requires exact edited revision3 without pending stage or mirror recovery. Stage digest is declared, not verified","initial":initial,"namespace_revision":ds.namespace_revision(),"dataset":bundle::hex(&ds.dataset_id().bytes()),"needs_mirror_recovery":ds.needs_mirror_recovery(),"pending_stage":format!("{stage:?}"),"latest_retained_receipt":format!("{receipt:?}"),"rows":rows,"expected_created_folder_found":folder,"expected_saved_file_exact_bytes_and_revision":note,"own_Inspector_profile":own,"own_Inspector_second_Save_revision_at_least3":own_committed,"large_measurement":large,"large_pattern_integrity":large_integrity,"large_committed_edited_revision3":committed_large_edit,"confirmed":result}),
    )?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn own_inspector_cold_guard_requires_second_commit_and_no_unpublished_stage() {
        use ev_workspace_store::{Dataset, Kind, Name, ObjectId, Scratch};
        use sha2::{Digest, Sha256};
        let directory = std::env::temp_dir().join(format!(
            "ev-m8-own-cold-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("owned.raw");
        let owned = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        owned.set_len(96 * 1024 * 1024).unwrap();
        drop(owned);
        provision(&path, &directory.join("provision.json")).unwrap();
        let region = || Region {
            file: OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap(),
            reads: 0,
            writes: 0,
            flushes: 0,
            origin: Instant::now(),
        };
        let text = super::super::scenario::TEXT.as_bytes();
        let mut scratch = Box::new(Scratch::empty());
        let file;
        {
            let mut ds = Dataset::open(region(), &mut scratch, 60_000)
                .map_err(|e| e.error)
                .unwrap();
            ds.create(
                ds.next_operation().unwrap(),
                ds.namespace_revision(),
                ObjectId::ROOT,
                Name::new("folder1").unwrap(),
                Kind::Directory,
                60_000,
            )
            .unwrap();
            file = ds
                .create(
                    ds.next_operation().unwrap(),
                    ds.namespace_revision(),
                    ObjectId::ROOT,
                    Name::new("note1").unwrap(),
                    Kind::File,
                    60_000,
                )
                .unwrap()
                .object;
        }
        for revision in [1, 2] {
            {
                let mut ds = Dataset::open(region(), &mut scratch, 60_000)
                    .map_err(|e| e.error)
                    .unwrap();
                let stage = ds
                    .begin_write(
                        ds.next_operation().unwrap(),
                        file,
                        revision,
                        text.len() as u64,
                        Sha256::digest(text).into(),
                        60_000,
                    )
                    .unwrap()
                    .stage;
                ds.write_chunk(ds.next_operation().unwrap(), stage, 0, text, 60_000)
                    .unwrap();
                ds.commit(ds.next_operation().unwrap(), stage, 60_000)
                    .unwrap();
            }
            let accepted = inspect_scenario_profile(
                &path,
                &directory.join(format!("revision-{}.json", revision + 1)),
                false,
                false,
                true,
            )
            .unwrap();
            assert_eq!(accepted, revision == 2);
        }
        {
            let mut ds = Dataset::open(region(), &mut scratch, 60_000)
                .map_err(|e| e.error)
                .unwrap();
            ds.begin_write(
                ds.next_operation().unwrap(),
                file,
                3,
                text.len() as u64,
                Sha256::digest(text).into(),
                60_000,
            )
            .unwrap();
        }
        assert!(
            !inspect_scenario_profile(
                &path,
                &directory.join("pending-stage.json"),
                false,
                false,
                true
            )
            .unwrap()
        );
    }
    const CHECKED_POWER: &str = "EVROSION_M8_SESSION_POWER phase=checked_shutdown token=9 tick=41000 rpc=0 windows=0 async_debt=0 physical_proof=trusted_root_flush_stop_scrub sources_retained_until_power=true\nEVROSION_M8_KERNEL_RUN phase=ended root_exited=false starts=11 calls=400 replies=400 retained=true scope=execution_only clean_shutdown=true\n";
    fn shutdown_outcome() -> ShutdownOutcome {
        ShutdownOutcome {
            exit_code: Some(33),
            timed_out: false,
            disk_floor_reached: false,
            fatal: false,
            scenario_complete: true,
            scenario_error: false,
            cold_exact: true,
        }
    }
    #[test]
    fn checked_shutdown_requires_all_independent_execution_and_cold_conditions() {
        let good = shutdown_outcome();
        let proof = good.validate(CHECKED_POWER.as_bytes()).unwrap();
        assert_eq!(
            (
                proof.token,
                proof.tick,
                proof.root_exited,
                proof.clean_shutdown
            ),
            (9, 41000, false, true)
        );
        let failures = [
            ShutdownOutcome {
                exit_code: Some(0),
                ..good
            },
            ShutdownOutcome {
                exit_code: Some(35),
                ..good
            },
            ShutdownOutcome {
                exit_code: None,
                ..good
            },
            ShutdownOutcome {
                timed_out: true,
                ..good
            },
            ShutdownOutcome {
                disk_floor_reached: true,
                ..good
            },
            ShutdownOutcome {
                fatal: true,
                ..good
            },
            ShutdownOutcome {
                scenario_complete: false,
                ..good
            },
            ShutdownOutcome {
                scenario_error: true,
                ..good
            },
            ShutdownOutcome {
                cold_exact: false,
                ..good
            },
        ];
        for failed in failures {
            assert!(failed.validate(CHECKED_POWER.as_bytes()).is_err());
        }
    }
    #[test]
    fn marker_substrings_duplicates_changed_scope_or_unclean_records_never_prove_shutdown() {
        let good = shutdown_outcome();
        for changed in [
            CHECKED_POWER.replace("phase=checked_shutdown", "phase=devices_cpu_frozen"),
            CHECKED_POWER.replace("clean_shutdown=true", "clean_shutdown=false"),
            CHECKED_POWER.replace("rpc=0", "rpc=1"),
            CHECKED_POWER.replace("windows=0", "windows=1"),
            CHECKED_POWER.replace("async_debt=0", "async_debt=1"),
            CHECKED_POWER.replace(
                "physical_proof=trusted_root_flush_stop_scrub",
                "physical_proof=pending_trusted_root",
            ),
            CHECKED_POWER.replace(
                "sources_retained_until_power=true",
                "sources_retained_until_power=false",
            ),
            CHECKED_POWER.replace("token=9", "token=0"),
            CHECKED_POWER.replace("token=9", "token=09"),
            CHECKED_POWER.replace("retained=true", "retained=false"),
            CHECKED_POWER.replace("scope=execution_only", "scope=unrelated"),
            format!("{CHECKED_POWER}{CHECKED_POWER}"),
            CHECKED_POWER.lines().rev().collect::<Vec<_>>().join("\n"),
        ] {
            assert!(good.validate(changed.as_bytes()).is_err(), "{changed}");
        }
        assert!(
            good.validate(b"unrelated checked_shutdown clean_shutdown=true")
                .is_err()
        );
    }
    #[test]
    fn large_cold_integrity_does_not_confirm_baseline_or_unpublished_stage() {
        use ev_workspace_store::{Dataset, Kind, Name, ObjectId, Scratch};
        use sha2::{Digest, Sha256};
        let directory = std::env::temp_dir().join(format!(
            "ev-m8-large-cold-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("owned.raw");
        let owned = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        owned.set_len(96 * 1024 * 1024).unwrap();
        drop(owned);
        provision(&path, &directory.join("provision.json")).unwrap();
        let region = || Region {
            file: OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap(),
            reads: 0,
            writes: 0,
            flushes: 0,
            origin: Instant::now(),
        };
        let mut pattern: Vec<u8> = (0..1024 * 1024)
            .map(|at| {
                if at % 80 == 79 {
                    b'\n'
                } else {
                    b'a' + (at % 26) as u8
                }
            })
            .collect();
        let mut scratch = Box::new(Scratch::empty());
        let file;
        {
            let mut ds = Dataset::open(region(), &mut scratch, 60_000)
                .map_err(|e| e.error)
                .unwrap();
            file = ds
                .create(
                    ds.next_operation().unwrap(),
                    ds.namespace_revision(),
                    ObjectId::ROOT,
                    Name::new("large1m.txt").unwrap(),
                    Kind::File,
                    60_000,
                )
                .unwrap()
                .object;
            let stage = ds
                .begin_write(
                    ds.next_operation().unwrap(),
                    file,
                    1,
                    pattern.len() as u64,
                    Sha256::digest(&pattern).into(),
                    60_000,
                )
                .unwrap()
                .stage;
            for (i, chunk) in pattern.chunks(4096).enumerate() {
                ds.write_chunk(
                    ds.next_operation().unwrap(),
                    stage,
                    (i * 4096) as u64,
                    chunk,
                    60_000,
                )
                .unwrap();
            }
            ds.commit(ds.next_operation().unwrap(), stage, 60_000)
                .unwrap();
        }
        assert!(inspect_scenario(&path, &directory.join("initial.json"), true, true).unwrap());
        assert!(
            !inspect_scenario(
                &path,
                &directory.join("baseline-is-not-success.json"),
                true,
                false
            )
            .unwrap()
        );
        let last = pattern.len() - 1;
        pattern[last] = b'Z';
        let stage;
        {
            let mut ds = Dataset::open(region(), &mut scratch, 60_000)
                .map_err(|e| e.error)
                .unwrap();
            stage = ds
                .begin_write(
                    ds.next_operation().unwrap(),
                    file,
                    2,
                    pattern.len() as u64,
                    Sha256::digest(&pattern).into(),
                    60_000,
                )
                .unwrap()
                .stage;
            for (i, chunk) in pattern.chunks(4096).enumerate() {
                ds.write_chunk(
                    ds.next_operation().unwrap(),
                    stage,
                    (i * 4096) as u64,
                    chunk,
                    60_000,
                )
                .unwrap();
            }
        }
        assert!(
            !inspect_scenario(
                &path,
                &directory.join("complete-stage-is-not-success.json"),
                true,
                false
            )
            .unwrap()
        );
        {
            let mut ds = Dataset::open(region(), &mut scratch, 60_000)
                .map_err(|e| e.error)
                .unwrap();
            ds.commit(ds.next_operation().unwrap(), stage, 60_000)
                .unwrap();
        }
        assert!(
            inspect_scenario(&path, &directory.join("committed-edit.json"), true, false).unwrap()
        );
    }
    #[test]
    fn legacy_cold_check_rejects_changes_to_original_bytes() {
        let directory = std::env::temp_dir().join(format!(
            "ev-m8-legacy-cold-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("owned.raw");
        let mut owned = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        owned.set_len(96 * 1024 * 1024).unwrap();
        owned.write_all(b"original legacy bytes").unwrap();
        owned.sync_all().unwrap();
        let expected = build::hash_file(&path).unwrap();
        assert!(inspect_legacy_readonly(&path, &directory.join("exact.json"), &expected).unwrap());
        owned.seek(SeekFrom::Start(1)).unwrap();
        owned.write_all(b"X").unwrap();
        owned.sync_all().unwrap();
        let changed = build::hash_file(&path).unwrap();
        assert!(
            !inspect_legacy_readonly(&path, &directory.join("changed.json"), &expected).unwrap()
        );
        assert_eq!(build::hash_file(&path).unwrap(), changed);
        let result: serde_json::Value =
            serde_json::from_slice(&fs::read(directory.join("changed.json")).unwrap()).unwrap();
        assert_eq!(result["host_format_invoked"], false);
        assert_ne!(
            result["original4MiB_sha256"],
            serde_json::from_slice::<serde_json::Value>(
                &fs::read(directory.join("exact.json")).unwrap()
            )
            .unwrap()["original4MiB_sha256"]
        );
        // Test-owned evidence is retained; independent cold reading cannot repair.
    }
    #[test]
    fn aggregate_bundle_evidence_has_its_own_finite_regular_json_bound() {
        let d = std::env::temp_dir().join(format!(
            "ev-m8-json-bound-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&d).unwrap();
        let path = d.join("aggregate.json");
        let mut bytes = vec![b' '; BUNDLE_EVIDENCE_MAX_BYTES as usize];
        bytes[..4].copy_from_slice(b"null");
        fs::write(&path, &bytes[..BUILD_EVIDENCE_MAX_BYTES as usize]).unwrap();
        assert_eq!(
            bounded_json(&path, BUILD_EVIDENCE_MAX_BYTES).unwrap(),
            serde_json::Value::Null
        );
        fs::write(&path, &bytes[..BUILD_EVIDENCE_MAX_BYTES as usize + 1]).unwrap();
        assert!(bounded_json(&path, BUILD_EVIDENCE_MAX_BYTES).is_err());
        assert!(bounded_json(&path, BUNDLE_EVIDENCE_MAX_BYTES).is_ok());
        fs::write(&path, &bytes).unwrap();
        assert!(bounded_json(&path, BUNDLE_EVIDENCE_MAX_BYTES).is_ok());
        bytes.push(b' ');
        fs::write(&path, &bytes).unwrap();
        assert!(bounded_json(&path, BUNDLE_EVIDENCE_MAX_BYTES).is_err());
        assert!(bounded_json(&d, BUNDLE_EVIDENCE_MAX_BYTES).is_err());
        fs::write(&path, b"{invalid").unwrap();
        assert!(bounded_json(&path, BUNDLE_EVIDENCE_MAX_BYTES).is_err());
        #[cfg(unix)]
        {
            let link = d.join("link.json");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(bounded_json(&link, BUNDLE_EVIDENCE_MAX_BYTES).is_err());
        }
        // Retain test-owned inputs; no historical evidence is removed.
    }
    #[test]
    fn strip_identity_rejects_nonelf_and_truncated_headers() {
        assert!(load_identity(b"placeholder").is_err());
        let mut b = vec![0; 64];
        b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        assert!(load_identity(&b).is_err());
    }
    #[test]
    fn host_new_format_is_scoped_empty_and_cold_readable() {
        use ev_workspace_store::{Dataset, DatasetId, ObjectId, Scratch};
        let d = std::env::temp_dir().join(format!(
            "ev-m8-host-format-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&d).unwrap();
        let p = d.join("owned.raw");
        let f = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&p)
            .unwrap();
        f.set_len(96 * 1024 * 1024).unwrap();
        drop(f);
        provision(&p, &d.join("host-provision.json")).unwrap();
        let f = OpenOptions::new().read(true).write(true).open(&p).unwrap();
        let mut r = Region {
            file: f,
            reads: 0,
            writes: 0,
            flushes: 0,
            origin: Instant::now(),
        };
        use ev_workspace_store::SectorIo;
        assert!(
            r.write(ev_workspace_store::REQUIRED_SECTORS, &[1; 512], 8192)
                .is_err()
        );
        assert!(r.write(0, &[1; 512], u64::MAX).is_err());
        assert_eq!(r.writes, 0);
        let mut scratch = Box::new(Scratch::empty());
        let ds = Dataset::open(r, &mut scratch, 8192)
            .map_err(|e| e.error)
            .unwrap();
        assert_eq!(ds.dataset_id(), DatasetId::new([0x84; 16]).unwrap());
        assert_eq!(ds.namespace_revision(), 1);
        assert_eq!(ds.list(ObjectId::ROOT, 0, true).unwrap(), None);
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(d.join("host-provision.json")).unwrap()).unwrap();
        assert_eq!(
            report["legacy_prefix_before"],
            report["legacy_prefix_after"]
        );
        assert_eq!(report["empty_dataset"], true);
        // Retain this test-owned file/evidence, as required for isolated M8 work.
    }
}
