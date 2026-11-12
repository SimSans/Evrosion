#![cfg(unix)]

mod support;

use ev::cli::{self, Cli, DoctorOptions};
use ev::doctor::{self, Host, Level, Report};
use ev::process::{Captured, Invocation, ProcessError, Runner};
use ev::toolchain::Toolchain;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use support::TempDirectory;

const PIN: &str = "nightly-2026-07-10";
const RUSTC: &str = "rustc 1.99.0-nightly (fixture)\nhost: x86_64-unknown-linux-gnu";
const CARGO: &str = "cargo 1.99.0-nightly (fixture)";
type ProbeKey = (String, Vec<String>);

#[derive(Default)]
struct PreparedTools {
    overrides: BTreeMap<ProbeKey, (i32, String)>,
    invocations: RefCell<Vec<Invocation>>,
}

impl PreparedTools {
    fn override_probe(&mut self, tool: &str, arguments: &[&str], code: i32, output: &str) {
        self.overrides.insert(
            (
                tool.into(),
                arguments.iter().map(|value| (*value).into()).collect(),
            ),
            (code, output.into()),
        );
    }
}

impl Runner for PreparedTools {
    fn run(&self, invocation: &Invocation) -> Result<Captured, ProcessError> {
        self.invocations.borrow_mut().push(invocation.clone());
        let name = invocation.program.file_name().unwrap().to_str().unwrap();
        let arguments: Vec<_> = invocation
            .arguments
            .iter()
            .map(|argument| argument.to_str().unwrap())
            .collect();
        let key = (
            name.to_owned(),
            arguments.iter().map(|value| (*value).into()).collect(),
        );
        let (code, output) = if let Some(value) = self.overrides.get(&key) {
            value.clone()
        } else {
            let text = match (name, arguments.as_slice()) {
                ("rustup", ["show", "active-toolchain"]) => format!("{PIN}-x86_64-unknown-linux-gnu (fixture)"),
                ("rustup", ["run", PIN, "rustc", "-vV"]) | ("rustc", ["-vV"]) => RUSTC.into(),
                ("rustup", ["run", PIN, "cargo", "-vV"]) | ("cargo", ["-vV"]) => CARGO.into(),
                ("rustup", ["component", "list", "--toolchain", PIN, "--installed"]) =>
                    "rust-src\nrustfmt-x86_64-unknown-linux-gnu\nclippy-x86_64-unknown-linux-gnu\nllvm-tools-x86_64-unknown-linux-gnu".into(),
                ("rustup", ["target", "list", "--toolchain", PIN, "--installed"]) =>
                    "x86_64-unknown-linux-gnu\nx86_64-unknown-none\nx86_64-unknown-uefi".into(),
                ("qemu-system-x86_64", ["--version"]) => "QEMU emulator version 10.2.1 (fixture)".into(),
                ("qemu-system-x86_64", ["-machine", "help"]) => "q35 Q35 machine (fixture)".into(),
                ("qemu-system-x86_64", ["-accel", "help"]) => "Accelerators supported:\ntcg\nkvm".into(),
                ("qemu-system-x86_64", ["-device", "help"]) => "name \"isa-serial\", bus ISA\nname \"isa-debug-exit\", bus ISA".into(),
                ("gdb", ["--version"]) => "GNU gdb (fixture) 17.1".into(),
                ("test", ["-w" | "-x", _]) => String::new(),
                ("git", ["status", "--porcelain=v1", "--untracked-files=normal", "--", "Cargo.lock"]) => String::new(),
                ("cargo", ["metadata", "--format-version", "1", "--locked", "--offline"]) => "{}".into(),
                ("git", ["ls-files", "--error-unmatch", "--", "Cargo.lock"]) => "Cargo.lock".into(),
                ("python3", ["--version"]) => "Python 3.12.0".into(),
                ("python3", [script, "--root", root]) if script.ends_with("tools/check_architecture.py") && *root == invocation.directory.to_str().unwrap() =>
                    "PASS: fixture architecture checks; no expired exceptions".into(),
                _ => panic!("unexpected probe: {name} {arguments:?}"),
            };
            (0, text)
        };
        Ok(Captured {
            status: ExitStatus::from_raw(code << 8),
            stdout: output.into_bytes(),
            stderr: Vec::new(),
        })
    }
}

struct Fixture {
    directory: TempDirectory,
    host: Host,
    tools: PreparedTools,
}

impl Fixture {
    fn new() -> Self {
        let directory = TempDirectory::new();
        let root = &directory.0;
        for (relative, contents) in [
            ("Cargo.toml", "[workspace]\nresolver = '3'\n"),
            (
                "Cargo.lock",
                "version = 4\n[[package]]\nname = 'fixture'\nversion = '0.0.0'\n",
            ),
            (
                "rust-toolchain.toml",
                include_str!("../../rust-toolchain.toml"),
            ),
            ("architecture/INVARIANTS.md", "# Fixture\n"),
            (
                "tools/check_architecture.py",
                "# Executed by PreparedTools only\n",
            ),
            (
                "firmware/OVMF_CODE.fd",
                "fixture checks readability, not real firmware boot\n",
            ),
        ] {
            let path = root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }
        let bin = root.join("bin");
        fs::create_dir(&bin).unwrap();
        for name in [
            "rustup",
            "rustc",
            "cargo",
            "qemu-system-x86_64",
            "gdb",
            "test",
            "python3",
            "git",
        ] {
            let path = bin.join(name);
            fs::write(&path, "fixture: use the injected Runner").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let host = Host {
            os: "linux".into(),
            arch: "x86_64".into(),
            search_path: vec![bin],
            firmware_override: None,
            firmware_candidates: vec![root.join("firmware/OVMF_CODE.fd")],
            kvm: root.join("no-kvm-device"),
        };
        Self {
            directory,
            host,
            tools: PreparedTools::default(),
        }
    }

    fn inspect(&self) -> Report {
        doctor::inspect(
            &DoctorOptions::default(),
            &self.host,
            &self.tools,
            &self.directory.0,
        )
    }
}

fn level(report: &Report, name: &str) -> Level {
    report
        .checks
        .iter()
        .find(|check| check.name == name)
        .unwrap()
        .level
}

#[test]
fn prepared_host_passes_and_optional_kvm_is_a_warning() {
    let fixture = Fixture::new();
    let report = fixture.inspect();
    assert!(report.passed(), "{}", report.render());
    assert_eq!(level(&report, "KVM"), Level::Warn);
    assert_eq!(level(&report, "components"), Level::Pass); // llvm-tools-preview is installed as llvm-tools.
    assert!(!fixture.directory.0.join("build").exists());
    assert!(!fixture.directory.0.join(".ev").exists());
}

#[test]
fn missing_required_executables_are_reported_together() {
    let fixture = Fixture::new();
    for tool in ["rustup", "qemu-system-x86_64", "gdb"] {
        fs::remove_file(fixture.host.search_path[0].join(tool)).unwrap();
    }
    let report = fixture.inspect();
    assert!(!report.passed());
    for name in ["toolchain", "QEMU", "GDB"] {
        assert_eq!(level(&report, name), Level::Fail);
    }
    assert!(report.render().contains("sudo apt install"));
}

#[test]
fn missing_components_and_targets_fail() {
    let mut fixture = Fixture::new();
    fixture.tools.override_probe(
        "rustup",
        &["component", "list", "--toolchain", PIN, "--installed"],
        0,
        "rust-src",
    );
    fixture.tools.override_probe(
        "rustup",
        &["target", "list", "--toolchain", PIN, "--installed"],
        0,
        "x86_64-unknown-linux-gnu",
    );
    let report = fixture.inspect();
    assert_eq!(level(&report, "components"), Level::Fail);
    assert_eq!(level(&report, "targets"), Level::Fail);
    assert!(report.render().contains("x86_64-unknown-uefi"));
}

#[test]
fn mismatched_active_toolchain_and_path_compiler_fail() {
    let mut fixture = Fixture::new();
    fixture.tools.override_probe(
        "rustup",
        &["show", "active-toolchain"],
        0,
        "stable-x86_64-unknown-linux-gnu (fixture)",
    );
    fixture
        .tools
        .override_probe("rustc", &["-vV"], 0, "rustc 1.80.0 (wrong PATH)");
    fixture
        .tools
        .override_probe("cargo", &["-vV"], 0, "cargo 1.80.0 (wrong PATH)");
    let report = fixture.inspect();
    for name in ["toolchain", "rustc", "cargo"] {
        assert_eq!(level(&report, name), Level::Fail);
    }
}

#[test]
fn qemu_must_support_the_actual_m0_configuration() {
    for (arguments, output) in [
        (["-machine", "help"], "pc Standard PC only"),
        (["-accel", "help"], "kvm"),
        (["-device", "help"], "name \"isa-serial\", bus ISA"),
    ] {
        let mut fixture = Fixture::new();
        fixture
            .tools
            .override_probe("qemu-system-x86_64", &arguments, 0, output);
        assert_eq!(level(&fixture.inspect(), "QEMU"), Level::Fail);
    }
}

#[test]
fn invalid_explicit_firmware_does_not_fall_back() {
    let fixture = Fixture::new();
    let options = DoctorOptions {
        root: None,
        ovmf_code: Some("missing.fd".into()),
    };
    let report = doctor::inspect(
        &options,
        &fixture.host,
        &fixture.tools,
        &fixture.directory.0,
    );
    assert_eq!(level(&report, "OVMF"), Level::Fail);
    assert!(!report.passed());
}

#[test]
fn cli_firmware_overrides_environment_and_resolves_from_invocation_directory() {
    let mut fixture = Fixture::new();
    fixture.host.firmware_override = Some("missing-from-env.fd".into());
    let options = DoctorOptions {
        root: Some(".".into()),
        ovmf_code: Some("firmware/OVMF_CODE.fd".into()),
    };
    let report = doctor::inspect(
        &options,
        &fixture.host,
        &fixture.tools,
        &fixture.directory.0,
    );
    assert!(report.passed(), "{}", report.render());
}

#[test]
fn empty_firmware_is_not_accepted() {
    let fixture = Fixture::new();
    fs::write(&fixture.host.firmware_candidates[0], "").unwrap();
    assert_eq!(level(&fixture.inspect(), "OVMF"), Level::Fail);
}

#[test]
fn bad_output_path_and_missing_lockfile_fail() {
    let fixture = Fixture::new();
    fs::write(
        fixture.directory.0.join("build"),
        "a file blocks the output directory",
    )
    .unwrap();
    fs::remove_file(fixture.directory.0.join("Cargo.lock")).unwrap();
    let report = fixture.inspect();
    assert_eq!(level(&report, "output access"), Level::Fail);
    assert_eq!(level(&report, "lockfile"), Level::Fail);
}

#[test]
fn stale_lock_resolution_and_dirty_git_lockfile_fail() {
    let mut fixture = Fixture::new();
    fixture.tools.override_probe(
        "cargo",
        &["metadata", "--format-version", "1", "--locked", "--offline"],
        101,
        "the lock file needs to be updated but --locked was passed",
    );
    fixture.tools.override_probe(
        "git",
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=normal",
            "--",
            "Cargo.lock",
        ],
        0,
        " M Cargo.lock",
    );
    let report = fixture.inspect();
    assert_eq!(level(&report, "lockfile"), Level::Fail);
    assert_eq!(level(&report, "lock revision"), Level::Fail);
}

#[test]
fn initial_untracked_lockfile_is_an_explicit_warning() {
    let mut fixture = Fixture::new();
    fixture.tools.override_probe(
        "git",
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=normal",
            "--",
            "Cargo.lock",
        ],
        0,
        "?? Cargo.lock",
    );
    let report = fixture.inspect();
    assert!(report.passed());
    assert_eq!(level(&report, "lock revision"), Level::Warn);
    assert!(report.render().contains("no committed dependency baseline"));
}

#[test]
fn ignored_lockfile_cannot_be_reported_as_tracked_and_clean() {
    let mut fixture = Fixture::new();
    fixture.tools.override_probe(
        "git",
        &["ls-files", "--error-unmatch", "--", "Cargo.lock"],
        1,
        "Cargo.lock did not match any files known to git",
    );
    let report = fixture.inspect();
    assert_eq!(level(&report, "lock revision"), Level::Fail);
    assert!(report.render().contains("check ignore rules"));
}

#[test]
fn expired_exception_output_is_propagated_as_a_failure() {
    let mut fixture = Fixture::new();
    let script = fixture.directory.0.join("tools/check_architecture.py");
    let root = fixture.directory.0.to_str().unwrap();
    fixture.tools.override_probe(
        "python3",
        &[script.to_str().unwrap(), "--root", root],
        1,
        "FAIL: EXC-0001: expired exception must be resolved",
    );
    let report = fixture.inspect();
    assert_eq!(level(&report, "architecture"), Level::Fail);
    assert!(report.render().contains("EXC-0001: expired"));
}

#[test]
fn unsupported_host_is_rejected_before_running_tools() {
    let mut fixture = Fixture::new();
    fixture.host.arch = "aarch64".into();
    assert_eq!(level(&fixture.inspect(), "host"), Level::Fail);
    assert!(fixture.tools.invocations.borrow().is_empty());
}

#[test]
fn toolchain_pin_uses_toml_syntax_and_rejects_floating_or_malformed_pins() {
    let pin = Toolchain::parse("[toolchain]\nchannel = 'nightly-2026-07-10'\ncomponents = [\n 'rust-src', # comment\n]\ntargets = ['x86_64-unknown-none']\n").unwrap();
    assert_eq!(pin.channel, PIN);
    for bad in [
        "[toolchain]\nchannel = 'nightly'\ncomponents = ['rust-src']\ntargets = ['x86_64-unknown-none']",
        "[toolchain]\nchannel = 'nightly-2026-07-10'\ncomponents = 123\ntargets = []",
        "not valid TOML",
    ] {
        assert!(Toolchain::parse(bad).is_err());
    }
}

#[test]
fn cli_preserves_native_paths_and_rejects_duplicate_flags() {
    let path = OsString::from_vec(b"/tmp/firmware path \xff.fd".to_vec());
    let parsed = cli::parse([
        OsString::from("doctor"),
        OsString::from("--ovmf-code"),
        path.clone(),
    ])
    .unwrap();
    assert_eq!(
        parsed,
        Cli::Doctor(DoctorOptions {
            root: None,
            ovmf_code: Some(path.into())
        })
    );
    assert!(cli::parse(["doctor", "--root", ".", "--root", "."].map(OsString::from)).is_err());
}
