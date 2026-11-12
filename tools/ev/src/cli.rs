use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

pub const HELP: &str = "Evrosion development frontend

Usage:
  cargo ev doctor [--root PATH] [--ovmf-code PATH]
  cargo ev build [--root PATH] [--profile dev|release]
  cargo ev build --fixture panic|no-framebuffer|exception|ap-timeout|context-corruption|preempt-stall|runtime-kernel-fault|user-wait-stall|reclaim-active-root|fx-corruption
  cargo ev debug kernel [--batch]
  cargo ev test panic
  cargo ev test m0
  cargo ev test storage-pio
  cargo ev test storage-journal
  cargo ev test storage-generation
  cargo ev test storage-file
  cargo ev test storage-progress
  cargo ev test storage-recovery
  cargo ev test display-surface
  cargo ev test desktop-graph
  cargo ev test native-platform
  cargo ev test native-owner-grants
  cargo ev test native-system
  cargo ev test ipc-bench
  cargo ev test provider-switch
  cargo ev recover --from PATH
  cargo ev test architecture --milestone M0
  cargo ev image --verify-reproducible
  cargo ev bootstrap
  cargo ev run [--root PATH] [--ovmf-code PATH] [--ovmf-vars PATH] [--timeout SECONDS] [--cpus N]
  cargo ev test boot [--root PATH] [--ovmf-code PATH] [--ovmf-vars PATH] [--timeout SECONDS] [--runs N] [--cpus N]
  cargo ev doctor --help
  cargo ev --help
  cargo ev --version

doctor checks the host without installing tools or changing project files.
Exit status: 0 = ready (warnings allowed), 1 = failed checks, 2 = invalid arguments.
build creates a UEFI image, symbols and an unsigned input manifest.
run builds and displays one scripted Native developer demonstration on a new private disk.
The visible preview requires a graphical Linux session and QEMU GTK; default timeout: 240 seconds, exactly one CPU.
test boot checks the current M0 image (default: 3 fresh boots, timeout 60 seconds, CPUs 1..64).
Firmware variables and disk writes are isolated for every run; explicit test-exit devices bound each demonstration.
Storage workflows use runner-owned persistent data disks and preserve evidence for every VM.
Flags and images are Internal development interfaces, not production releases.
";

pub const DOCTOR_HELP: &str = "Usage: cargo ev doctor [--root PATH] [--ovmf-code PATH]

Checks Rust, components and targets, QEMU/Q35/TCG/devices, OVMF, GDB,
output permissions, the Cargo lockfile, and architecture exceptions.
KVM is optional. No virtual machine is started.

  --root PATH       Workspace to inspect (default: search current directory and parents)
  --ovmf-code PATH  Explicit firmware file; overrides EV_OVMF_CODE and discovery

An invalid explicit firmware path is a failure; it never silently falls back.
Relative paths are resolved from the directory where ev was invoked.
";

#[derive(Debug, Default, PartialEq, Eq)]
pub struct DoctorOptions {
    pub root: Option<PathBuf>,
    pub ovmf_code: Option<PathBuf>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct BuildOptions {
    pub root: Option<PathBuf>,
    pub release: bool,
    pub fixture: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct BootOptions {
    pub root: Option<PathBuf>,
    pub ovmf_code: Option<PathBuf>,
    pub ovmf_vars: Option<PathBuf>,
    pub timeout_seconds: u64,
    pub runs: u32,
    pub cpus: u32,
    pub debug: bool,
    pub batch: bool,
    pub expect_panic: bool,
}

impl Default for BootOptions {
    fn default() -> Self {
        Self {
            root: None,
            ovmf_code: None,
            ovmf_vars: None,
            timeout_seconds: 60,
            runs: 1,
            cpus: 1,
            debug: false,
            batch: false,
            expect_panic: false,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Cli {
    Help,
    DoctorHelp,
    Version,
    Doctor(DoctorOptions),
    Build(BuildOptions),
    Boot(BootOptions),
    Preview(BootOptions),
    Workflow(String),
    Recover(PathBuf),
}

pub fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Cli, String> {
    let arguments: Vec<_> = arguments.into_iter().collect();
    match arguments.as_slice() {
        [] => return Ok(Cli::Help),
        [flag] if flag == "--help" || flag == "-h" || flag == "help" => return Ok(Cli::Help),
        [flag] if flag == "--version" || flag == "-V" => return Ok(Cli::Version),
        [command, flag] if command == "doctor" && (flag == "--help" || flag == "-h") => {
            return Ok(Cli::DoctorHelp);
        }
        [command, topic] if command == "help" && topic == "doctor" => return Ok(Cli::DoctorHelp),
        _ => {}
    }
    if arguments[0] == "recover" {
        if arguments.len() != 3 || arguments[1] != "--from" || arguments[2].is_empty() {
            return Err("usage: cargo ev recover --from PREPARED_OWNER_SUITE".into());
        }
        return Ok(Cli::Recover(PathBuf::from(&arguments[2])));
    }
    let words: Vec<_> = arguments.iter().map(|v| v.to_str().unwrap_or("")).collect();
    let workflow = match words.as_slice() {
        ["bootstrap"] => Some("bootstrap"),
        ["image", "--verify-reproducible"] => Some("repro"),
        ["test", "m0"] => Some("acceptance"),
        ["test", "storage-journal"] => Some("storage-journal"),
        ["test", "storage-generation"] => Some("storage-generation"),
        ["test", "storage-file"] => Some("storage-file"),
        ["test", "storage-progress"] => Some("storage-progress"),
        ["test", "storage-recovery"] => Some("storage-recovery"),
        ["test", "storage-pio"] => Some("storage-pio"),
        ["test", "display-surface"] => Some("display-surface"),
        ["test", "desktop-graph"] => Some("desktop-graph"),
        ["test", "native-platform"] => Some("native-platform"),
        ["test", "native-system"] => Some("native-system"),
        ["test", "native-owner-grants"] => Some("native-owner-grants"),
        ["test", "ipc-bench"] => Some("ipc-bench"),
        ["test", "provider-switch"] => Some("provider-switch"),
        ["test", "architecture", "--milestone", "M0"] => Some("architecture"),
        _ => None,
    };
    if let Some(workflow) = workflow {
        return Ok(Cli::Workflow(workflow.into()));
    }
    if arguments[0] != "doctor" {
        return parse_work(&arguments);
    }
    parse_doctor(&arguments[1..])
}

fn parse_doctor(arguments: &[OsString]) -> Result<Cli, String> {
    let mut options = DoctorOptions::default();
    let mut arguments = arguments.iter();
    while let Some(flag) = arguments.next() {
        let destination = match flag.as_os_str() {
            value if value == OsStr::new("--root") => &mut options.root,
            value if value == OsStr::new("--ovmf-code") => &mut options.ovmf_code,
            _ => return Err(format!("unknown doctor option: {flag:?}")),
        };
        if destination.is_some() {
            return Err(format!("duplicate option: {flag:?}"));
        }
        *destination = Some(PathBuf::from(value_after(flag, &mut arguments)?));
    }
    Ok(Cli::Doctor(options))
}

fn value_after<'a>(
    flag: &OsStr,
    arguments: &mut std::slice::Iter<'a, OsString>,
) -> Result<&'a OsStr, String> {
    let value = arguments
        .next()
        .ok_or_else(|| format!("missing value after {flag:?}"))?;
    if value.is_empty() || value.as_encoded_bytes().starts_with(b"--") {
        return Err(format!(
            "expected a value after {flag:?}; prefix paths beginning with -- with ./"
        ));
    }
    Ok(value)
}

fn parse_work(arguments: &[OsString]) -> Result<Cli, String> {
    let build = arguments[0] == "build";
    let preview = arguments[0] == "run";
    let test = arguments[0] == "test" && arguments.get(1).is_some_and(|value| value == "boot");
    let panic = arguments[0] == "test" && arguments.get(1).is_some_and(|v| v == "panic");
    let debug = arguments[0] == "debug" && arguments.get(1).is_some_and(|v| v == "kernel");
    if !build && !test && !panic && !debug && arguments[0] != "run" {
        return Err(format!(
            "unsupported command or option: {:?}; use cargo ev --help",
            arguments[0]
        ));
    }
    let arguments = &arguments[if test || panic || debug { 2 } else { 1 }..];
    if arguments.len() == 1 && (arguments[0] == "--help" || arguments[0] == "-h") {
        return Ok(Cli::Help);
    }
    let mut build_options = BuildOptions::default();
    let mut boot_options = BootOptions {
        runs: if test { 3 } else { 1 },
        timeout_seconds: if preview { 240 } else { 60 },
        expect_panic: panic,
        debug,
        ..BootOptions::default()
    };
    let mut seen = std::collections::HashSet::new();
    let mut arguments = arguments.iter();
    while let Some(flag) = arguments.next() {
        if !seen.insert(flag) {
            return Err(format!("duplicate option: {flag:?}"));
        }
        if debug && flag == "--batch" {
            boot_options.batch = true;
            continue;
        }
        let value = value_after(flag, &mut arguments)?;
        match flag.to_str() {
            Some("--root") => {
                build_options.root = Some(value.into());
                boot_options.root = Some(value.into());
            }
            Some("--profile") if build => {
                build_options.release = match value.to_str() {
                    Some("dev") => false,
                    Some("release") => true,
                    _ => return Err("profile must be dev or release".into()),
                }
            }
            Some("--fixture") if build => {
                let value = value.to_str().ok_or("invalid fixture")?;
                if ![
                    "panic",
                    "no-framebuffer",
                    "exception",
                    "ap-timeout",
                    "context-corruption",
                    "preempt-stall",
                    "runtime-kernel-fault",
                    "user-wait-stall",
                    "reclaim-active-root",
                    "fx-corruption",
                    "m3-pio-write",
                    "m3-pio-verify",
                    "m3-store",
                    "m3-generation",
                    "m3-owner",
                    "m3-progress",
                    "m3-file",
                    "m4-display",
                    "m4-desktop",
                    "m5-native",
                    "m5-native-system",
                    "m5-native-recovery",
                    "m5-provider",
                    "m5-ipc-bench",
                ]
                .contains(&value)
                {
                    return Err(
                        "unknown fixture; use a declared boot failure or dedicated m3 storage / m4 display or desktop workflow".into(),
                    );
                }
                build_options.fixture = Some(value.into());
            }
            Some("--ovmf-code") if !build => boot_options.ovmf_code = Some(value.into()),
            Some("--ovmf-vars") if !build => boot_options.ovmf_vars = Some(value.into()),
            Some("--timeout") if !build => boot_options.timeout_seconds = positive(value, 600)?,
            Some("--cpus") if !build => boot_options.cpus = positive(value, 64)? as u32,
            Some("--runs") if test => boot_options.runs = positive(value, 100)? as u32,
            _ => return Err(format!("unknown option: {flag:?}")),
        }
    }
    if preview && boot_options.cpus != 1 {
        return Err(
            "the Native preview requires exactly one CPU; use test boot for the M0 CPU experiment"
                .into(),
        );
    }
    Ok(if build {
        Cli::Build(build_options)
    } else if preview {
        Cli::Preview(boot_options)
    } else {
        Cli::Boot(boot_options)
    })
}

fn positive(value: &OsStr, maximum: u64) -> Result<u64, String> {
    value
        .to_str()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (1..=maximum).contains(value))
        .ok_or_else(|| format!("expected an integer from 1 through {maximum}"))
}
