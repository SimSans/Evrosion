use crate::cli::DoctorOptions;
use crate::process::{Invocation, Runner};
use crate::toolchain::Toolchain;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

const LINUX_HOST: &str = "x86_64-unknown-linux-gnu";
const HOST_PACKAGES: &str = "On Debian/Ubuntu: sudo apt install qemu-system-x86 ovmf gdb";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug)]
pub struct Check {
    pub name: &'static str,
    pub level: Level,
    pub detail: String,
    pub remedy: Option<String>,
}

#[derive(Debug, Default)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    pub fn passed(&self) -> bool {
        !self.checks.iter().any(|check| check.level == Level::Fail)
    }

    fn add(
        &mut self,
        name: &'static str,
        level: Level,
        detail: impl Into<String>,
        remedy: Option<String>,
    ) {
        self.checks.push(Check {
            name,
            level,
            detail: detail.into(),
            remedy,
        });
    }

    fn check(
        &mut self,
        name: &'static str,
        result: Result<String, String>,
        remedy: impl Into<String>,
    ) {
        match result {
            Ok(detail) => self.add(name, Level::Pass, detail, None),
            Err(detail) => self.add(name, Level::Fail, detail, Some(remedy.into())),
        }
    }

    pub fn render(&self) -> String {
        let mut output = String::from("Evrosion host doctor — M0 Slice 1\n\n");
        for check in &self.checks {
            let label = match check.level {
                Level::Pass => "PASS",
                Level::Warn => "WARN",
                Level::Fail => "FAIL",
            };
            output.push_str(&format!(
                "{label} {:<14} {}\n",
                check.name,
                check.detail.replace('\n', "\n                    ")
            ));
            if let Some(remedy) = &check.remedy {
                output.push_str(&format!("     Fix: {remedy}\n"));
            }
        }
        let count = |level| {
            self.checks
                .iter()
                .filter(|check| check.level == level)
                .count()
        };
        output.push_str(&format!(
            "\n{} passed, {} warnings, {} failed. {}\n",
            count(Level::Pass),
            count(Level::Warn),
            count(Level::Fail),
            if self.passed() {
                "Host prerequisites are ready; boot is not tested by doctor."
            } else {
                "Resolve failed checks before kernel/image bringup."
            }
        ));
        output
    }
}

/// Snapshot paths instead of mutating global environment variables in tests.
#[derive(Debug)]
pub struct Host {
    pub os: String,
    pub arch: String,
    pub search_path: Vec<PathBuf>,
    pub firmware_override: Option<PathBuf>,
    pub firmware_candidates: Vec<PathBuf>,
    pub kvm: PathBuf,
}

impl Host {
    pub fn detect(invoked_from: &Path) -> Self {
        let search_path = std::env::var_os("PATH")
            .map(|path| {
                std::env::split_paths(&path)
                    .filter(|entry| !entry.as_os_str().is_empty())
                    .map(|entry| absolute(invoked_from, &entry))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            search_path,
            firmware_override: std::env::var_os("EV_OVMF_CODE").map(PathBuf::from),
            firmware_candidates: [
                "/usr/share/OVMF/OVMF_CODE_4M.fd",
                "/usr/share/OVMF/OVMF_CODE.fd",
                "/usr/share/edk2/ovmf/OVMF_CODE.fd",
                "/usr/share/edk2/x64/OVMF_CODE.4m.fd",
                "/usr/share/edk2/x64/OVMF_CODE.fd",
                "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd",
                "/usr/share/qemu/edk2-x86_64-code.fd",
                "/usr/local/share/OVMF/OVMF_CODE.fd",
                "/usr/local/share/edk2/ovmf/OVMF_CODE.fd",
            ]
            .into_iter()
            .map(PathBuf::from)
            .collect(),
            kvm: PathBuf::from("/dev/kvm"),
        }
    }

    pub(crate) fn executable(&self, name: &str) -> Result<PathBuf, String> {
        self.search_path
            .iter()
            .map(|directory| directory.join(name))
            .find(|path| executable_file(path))
            .ok_or_else(|| format!("{name} was not found as an executable on PATH"))
    }
}

fn executable_file(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn absolute(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        base.join(path)
    }
}

pub fn workspace(invoked_from: &Path, explicit: Option<&Path>) -> Result<PathBuf, String> {
    let candidate = if let Some(path) = explicit {
        absolute(invoked_from, path)
    } else {
        invoked_from
            .ancestors()
            .find(|path| {
                path.join("rust-toolchain.toml").is_file()
                    && path.join("architecture/INVARIANTS.md").is_file()
            })
            .ok_or("no Evrosion workspace found; use --root PATH")?
            .to_owned()
    };
    let candidate = candidate
        .canonicalize()
        .map_err(|error| format!("{}: {error}", candidate.display()))?;
    if !candidate.join("Cargo.toml").is_file()
        || !candidate.join("architecture/INVARIANTS.md").is_file()
    {
        return Err(format!(
            "{} is not an Evrosion workspace",
            candidate.display()
        ));
    }
    Ok(candidate)
}

fn probe(
    runner: &impl Runner,
    program: &Path,
    arguments: &[impl AsRef<std::ffi::OsStr>],
    root: &Path,
) -> Result<String, String> {
    runner
        .run(&Invocation::new(program, arguments, root))
        .and_then(|output| output.checked())
        .map(|output| output.text().trim().to_owned())
        .map_err(|error| error.to_string())
}

fn tool_probe(
    runner: &impl Runner,
    host: &Host,
    name: &str,
    arguments: &[&str],
    root: &Path,
) -> Result<String, String> {
    probe(runner, &host.executable(name)?, arguments, root)
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or_default().to_owned()
}

fn check_rust(
    report: &mut Report,
    runner: &impl Runner,
    host: &Host,
    root: &Path,
    pin: &Toolchain,
) {
    let install = pin.install_hint();
    let active =
        tool_probe(runner, host, "rustup", &["show", "active-toolchain"], root).and_then(|text| {
            let active = text.split_whitespace().next().unwrap_or_default();
            if active == pin.channel || active == format!("{}-{LINUX_HOST}", pin.channel) {
                Ok(active.to_owned())
            } else {
                Err(format!(
                    "active toolchain is {active:?}, expected {}",
                    pin.channel
                ))
            }
        });
    report.check(
        "toolchain",
        active,
        format!("{install}; remove conflicting RUSTUP_TOOLCHAIN or rustup overrides"),
    );

    for (name, arguments) in [("rustc", "-vV"), ("cargo", "-vV")] {
        let result = (|| {
            let actual = tool_probe(runner, host, name, &[arguments], root)?;
            let expected = tool_probe(
                runner,
                host,
                "rustup",
                &["run", &pin.channel, name, arguments],
                root,
            )?;
            if actual != expected || !actual.starts_with(name) {
                return Err(format!(
                    "PATH {name} differs from the pinned toolchain: {}",
                    first_line(&actual)
                ));
            }
            Ok(format!(
                "{} ({})",
                first_line(&actual),
                host.executable(name)?.display()
            ))
        })();
        report.check(
            name,
            result,
            format!("{install}; put Rustup's cargo/bin directory before other Rust tools on PATH"),
        );
    }

    let components = tool_probe(
        runner,
        host,
        "rustup",
        &[
            "component",
            "list",
            "--toolchain",
            &pin.channel,
            "--installed",
        ],
        root,
    )
    .and_then(|text| {
        let installed: Vec<_> = text.split_whitespace().collect();
        let missing: Vec<_> = pin
            .components
            .iter()
            .filter(|component| {
                let component = component.strip_suffix("-preview").unwrap_or(component);
                !installed.contains(&component)
                    && !installed.contains(&format!("{component}-{LINUX_HOST}").as_str())
            })
            .cloned()
            .collect();
        if missing.is_empty() {
            Ok(pin.components.join(", "))
        } else {
            Err(format!("missing components: {}", missing.join(", ")))
        }
    });
    report.check("components", components, &install);

    let targets = tool_probe(
        runner,
        host,
        "rustup",
        &["target", "list", "--toolchain", &pin.channel, "--installed"],
        root,
    )
    .and_then(|text| {
        let installed: Vec<_> = text.split_whitespace().collect();
        let missing: Vec<_> = pin
            .targets
            .iter()
            .filter(|target| !installed.contains(&target.as_str()))
            .cloned()
            .collect();
        if missing.is_empty() {
            Ok(pin.targets.join(", "))
        } else {
            Err(format!("missing targets: {}", missing.join(", ")))
        }
    });
    report.check("targets", targets, install);
}

fn qemu(runner: &impl Runner, host: &Host, root: &Path) -> Result<String, String> {
    let program = host.executable("qemu-system-x86_64")?;
    let version = probe(runner, &program, &["--version"], root)?;
    if !version.starts_with("QEMU emulator version") {
        return Err(format!("unrecognized QEMU version: {version}"));
    }
    let machines = probe(runner, &program, &["-machine", "help"], root)?;
    if !machines
        .lines()
        .any(|line| line.split_whitespace().next() == Some("q35"))
    {
        return Err("QEMU lacks the q35 machine".into());
    }
    let accelerators = probe(runner, &program, &["-accel", "help"], root)?;
    if !accelerators.lines().any(|line| line.trim() == "tcg") {
        return Err("QEMU lacks TCG acceleration".into());
    }
    let devices = probe(runner, &program, &["-device", "help"], root)?;
    for required in ["isa-debug-exit", "isa-serial"] {
        if !devices.contains(&format!("name \"{required}\"")) {
            return Err(format!("QEMU lacks {required}"));
        }
    }
    Ok(format!(
        "{}; Q35, TCG, isa-debug-exit and serial available ({})",
        first_line(&version),
        program.display()
    ))
}

fn readable_firmware(path: &Path) -> Result<String, String> {
    let read = || -> std::io::Result<u64> {
        let metadata = fs::metadata(path)?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err(std::io::Error::other(
                "expected a nonempty regular firmware file",
            ));
        }
        let mut file = File::open(path)?;
        file.read_exact(&mut [0; 1])?;
        Ok(metadata.len())
    };
    read()
        .map(|length| {
            format!(
                "{} ({length} bytes; readable, boot not yet verified)",
                path.display()
            )
        })
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn firmware(options: &DoctorOptions, host: &Host, invoked_from: &Path) -> Result<String, String> {
    if let Some(path) = options
        .ovmf_code
        .as_ref()
        .or(host.firmware_override.as_ref())
    {
        return readable_firmware(&absolute(invoked_from, path));
    }
    host.firmware_candidates.iter().find_map(|path| readable_firmware(path).ok())
        .ok_or_else(|| "no readable OVMF code image in known distribution locations; set --ovmf-code PATH or EV_OVMF_CODE".into())
}

fn output_access(runner: &impl Runner, host: &Host, root: &Path) -> Result<String, String> {
    let output = root.join("build/m0");
    let parent = output
        .ancestors()
        .find(|path| path.exists())
        .ok_or("no existing output ancestor")?;
    if !parent.is_dir() {
        return Err(format!("{} is not a directory", parent.display()));
    }
    let test = host.executable("test")?;
    for permission in ["-w", "-x"] {
        probe(
            runner,
            &test,
            &[OsString::from(permission), parent.as_os_str().to_owned()],
            root,
        )
        .map_err(|error| format!("{} is not writable/searchable: {error}", parent.display()))?;
    }
    Ok(format!(
        "{} can host build/m0; checked access without creating files",
        parent.display()
    ))
}

fn check_lock(report: &mut Report, runner: &impl Runner, host: &Host, root: &Path) {
    let result = (|| {
        let content = fs::read_to_string(root.join("Cargo.lock"))
            .map_err(|error| format!("Cargo.lock: {error}"))?;
        let document = content
            .parse::<toml::Table>()
            .map_err(|error| format!("invalid Cargo.lock: {error}"))?;
        if !document.contains_key("package") {
            return Err("Cargo.lock contains no packages".into());
        }
        tool_probe(
            runner,
            host,
            "cargo",
            &["metadata", "--format-version", "1", "--locked", "--offline"],
            root,
        )?;
        Ok("Cargo.lock parses and Cargo accepts the workspace with --locked --offline".into())
    })();
    report.check("lockfile", result, "Run cargo fetch --locked for missing cached crates. If manifests changed, review them, run cargo generate-lockfile, and review the resulting lockfile");
    match tool_probe(runner, host, "git", &["status", "--porcelain=v1", "--untracked-files=normal", "--", "Cargo.lock"], root) {
        Ok(status) if status.is_empty() => report.check("lock revision",
            tool_probe(runner, host, "git", &["ls-files", "--error-unmatch", "--", "Cargo.lock"], root)
                .map(|_| "Cargo.lock is tracked and clean against Git".into()),
            "Ensure Cargo.lock is tracked; check ignore rules and include the reviewed lockfile in version control"),
        Ok(status) if status.trim() == "?? Cargo.lock" => report.add("lock revision", Level::Warn,
            "Cargo.lock is untracked; this new repository has no committed dependency baseline",
            Some("Include the reviewed Cargo.lock in the initial commit before claiming reproducible revision evidence".into())),
        Ok(status) => report.add("lock revision", Level::Fail, format!("Cargo.lock has uncommitted changes: {status}"),
            Some("Review the dependency change and commit the intended lockfile before relying on this revision".into())),
        Err(error) => report.add("lock revision", Level::Fail, error, Some("Install Git and initialize this workspace's repository".into())),
    }
}

fn governance(runner: &impl Runner, host: &Host, root: &Path) -> Result<String, String> {
    let python = host.executable("python3")?;
    let version = probe(runner, &python, &["--version"], root)?;
    let numbers: Vec<_> = version
        .trim()
        .strip_prefix("Python ")
        .unwrap_or_default()
        .split('.')
        .take(2)
        .filter_map(|part| part.parse::<u32>().ok())
        .collect();
    if numbers.len() != 2 || numbers.as_slice() < [3, 11].as_slice() {
        return Err(format!("Python 3.11+ is required; found {version}"));
    }
    let script = root.join("tools/check_architecture.py");
    if !script.is_file() {
        return Err(format!(
            "missing architecture validator: {}",
            script.display()
        ));
    }
    probe(
        runner,
        &python,
        &[
            script.as_os_str().to_owned(),
            OsString::from("--root"),
            root.as_os_str().to_owned(),
        ],
        root,
    )
}

pub fn inspect(
    options: &DoctorOptions,
    host: &Host,
    runner: &impl Runner,
    invoked_from: &Path,
) -> Report {
    let mut report = Report::default();
    if host.os != "linux" || host.arch != "x86_64" {
        report.add(
            "host",
            Level::Fail,
            format!(
                "{} {}; Slice 1 supports x86_64 Linux hosts",
                host.os, host.arch
            ),
            Some("Use an x86_64 Linux development host for this M0 slice".into()),
        );
        return report;
    }
    report.add("host", Level::Pass, "x86_64 Linux", None);
    let root = match workspace(invoked_from, options.root.as_deref()) {
        Ok(root) => root,
        Err(error) => {
            report.add(
                "workspace",
                Level::Fail,
                error,
                Some("Run inside Evrosion or pass --root PATH".into()),
            );
            return report;
        }
    };
    report.add("workspace", Level::Pass, root.display().to_string(), None);
    match Toolchain::load(&root) {
        Ok(pin) => check_rust(&mut report, runner, host, &root, &pin),
        Err(error) => report.add(
            "toolchain pin",
            Level::Fail,
            error,
            Some("Restore a valid pinned rust-toolchain.toml".into()),
        ),
    }
    report.check("QEMU", qemu(runner, host, &root), HOST_PACKAGES);
    report.check(
        "OVMF",
        firmware(options, host, invoked_from),
        format!("{HOST_PACKAGES}; use --ovmf-code PATH for another location"),
    );
    report.check(
        "GDB",
        tool_probe(runner, host, "gdb", &["--version"], &root).and_then(|version| {
            if version.starts_with("GNU gdb") {
                Ok(first_line(&version))
            } else {
                Err(format!("unrecognized GDB version: {version}"))
            }
        }),
        HOST_PACKAGES,
    );
    match OpenOptions::new().read(true).write(true).open(&host.kvm) {
        Ok(_) => report.add(
            "KVM",
            Level::Pass,
            format!(
                "{} opens read/write; acceleration remains opt-in",
                host.kvm.display()
            ),
            None,
        ),
        Err(error) => report.add(
            "KVM",
            Level::Warn,
            format!(
                "{}: {error}; optional, TCG is the default",
                host.kvm.display()
            ),
            None,
        ),
    }
    report.check(
        "output access",
        output_access(runner, host, &root),
        "Choose a writable workspace and check directory permissions, ACLs and mount access",
    );
    check_lock(&mut report, runner, host, &root);
    report.check("architecture", governance(runner, host, &root), "Run python3 tools/check_architecture.py and resolve its failures; Python 3.11+ is required");
    report
}
