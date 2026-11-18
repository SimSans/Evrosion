use crate::{
    boot_protocol,
    build::{self, Manifest, Result},
    cli::BootOptions,
    doctor::Host,
};
use serde_json::json;
use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const OUTPUT_LIMIT: u64 = 1024 * 1024;

/// Only the explicit V4 Recovery workflows use the independent Native3
/// footer with nine retained profile slots. Ordinary network grammar stays strict.
pub(crate) fn network_recovery_fixture(fixture: Option<&str>) -> bool {
    matches!(
        fixture,
        Some("m6-network-recovery" | "m6-network-recovery-owner" | "m7-document-recovery")
    )
}
pub(crate) fn check_network_fixture(
    fixture: Option<&str>,
    serial: &[u8],
    build: &str,
    status: Option<i32>,
) -> Result<()> {
    if network_recovery_fixture(fixture) {
        boot_protocol::check_network_recovery(serial, build, status)
    } else {
        boot_protocol::check_network(serial, build, status)
    }
}
pub(crate) fn record_network_fixture(
    fixture: Option<&str>,
    serial: &[u8],
    build: &str,
) -> Result<crate::native_protocol::Record> {
    if network_recovery_fixture(fixture) {
        crate::native3_protocol::record_network_recovery(serial, build)
    } else {
        crate::native_protocol::record_network(serial, build)
    }
}

pub(crate) struct ChildGuard(pub(crate) Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        // Always reap our direct child, including on timeout and I/O failures.
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

/// No pipe readers can remain blocked: QEMU writes bounded, monitored log files.
pub fn supervised(command: &mut Command, logs: &[&Path], timeout: Duration) -> Result<ExitStatus> {
    supervised_until(command, logs, timeout, None)
}

/// Manual host supervision has no automatic lifetime expiry or input stimuli.
/// Kernel operation deadlines and Job windows remain independently enforced.
fn supervised_session(
    command: &mut Command,
    logs: &[&Path],
    clock: Option<(&mut crate::vm_clock::Prepared, &Path)>,
) -> Result<ExitStatus> {
    let mut child = ChildGuard(
        command
            .stdin(Stdio::inherit())
            .spawn()
            .map_err(|e| e.to_string())?,
    );
    if let Some((clock, run)) = clock {
        clock.verify_and_start(&mut child.0, run)?;
    }
    loop {
        for path in logs {
            if fs::metadata(path).map_err(|e| e.to_string())?.len() > OUTPUT_LIMIT {
                return Err(format!(
                    "session diagnostic retention bound exceeded: {}",
                    path.display()
                ));
            }
        }
        if let Some(status) = child.0.try_wait().map_err(|e| e.to_string())? {
            return Ok(status);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

pub(crate) fn supervised_until(
    command: &mut Command,
    logs: &[&Path],
    timeout: Duration,
    mut stop: Option<&mut dyn FnMut() -> Result<bool>>,
) -> Result<ExitStatus> {
    let mut child = ChildGuard(
        command
            .spawn()
            .map_err(|error| format!("cannot start QEMU: {error}"))?,
    );
    let start = Instant::now();
    loop {
        for path in logs {
            let size = fs::metadata(path).map_err(|error| error.to_string())?.len();
            if size > OUTPUT_LIMIT {
                return Err(format!("output limit exceeded: {}", path.display()));
            }
        }
        if start.elapsed() >= timeout {
            return Err(format!(
                "QEMU timed out after {} seconds",
                timeout.as_secs()
            ));
        }
        if let Some(status) = child.0.try_wait().map_err(|error| error.to_string())? {
            if stop.is_some() {
                return Err(format!(
                    "QEMU exited {status} before the validated interruption"
                ));
            }
            return Ok(status);
        }
        if let Some(check) = stop.as_mut()
            && check()?
        {
            // Only our retained direct child is killed; no PID lookup/signal to
            // another process and no orderly QEMU cache-flushing exit occurs.
            child.0.kill().map_err(|error| error.to_string())?;
            return child.0.wait().map_err(|error| error.to_string());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// Dedicated finite IPC timing watcher; the same guard owns every exit/error.
fn supervised_ipc_bench(
    command: &mut Command,
    serial: &Path,
    errors: &Path,
    timeout: Duration,
    build: &str,
    directory: &Path,
) -> Result<ExitStatus> {
    let timeout = timeout.min(Duration::from_secs(180));
    let origin = Instant::now();
    let mut observer = crate::ipc_bench_timing::Observer::new(origin);
    let deadline = origin
        .checked_add(timeout)
        .ok_or("IPC host deadline overflow")?;
    let result: Result<ExitStatus> = (|| {
        let before = Instant::now();
        let mut child = ChildGuard(
            command
                .spawn()
                .map_err(|e| format!("IPC QEMU spawn: {e}"))?,
        );
        observer.spawned(before, Instant::now())?;
        let read = |observer: &mut crate::ipc_bench_timing::Observer| -> Result<()> {
            let start = observer.elapsed(Instant::now())?;
            let mut bytes = Vec::new();
            File::open(serial)
                .map_err(|e| e.to_string())?
                .take(crate::ipc_bench_timing::OUTPUT_LIMIT + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            let end = observer.elapsed(Instant::now())?;
            observer.observe(&bytes, build, start, end)?;
            if fs::metadata(errors).map_err(|e| e.to_string())?.len() > OUTPUT_LIMIT {
                return Err("IPC QEMU stderr exceeded1MiB".into());
            }
            Ok(())
        };
        loop {
            if Instant::now() >= deadline {
                return Err("IPC QEMU finite host deadline elapsed".into());
            }
            read(&mut observer)?;
            if let Some(status) = child.0.try_wait().map_err(|e| e.to_string())? {
                // Child exit can race the preceding read. Capture its complete
                // flushed output while keeping that final read's real bracket.
                read(&mut observer)?;
                return Ok(status);
            }
            thread::sleep(
                Duration::from_millis(1).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    })();
    crate::storage::json_new(
        &directory.join("ipc-host-timing.json"),
        &observer.record(
            result.as_ref().ok().and_then(|s| s.code()),
            result.as_ref().err().cloned(),
        ),
    )?;
    // An unresolved timing lower bound does not erase the independently checked
    // functional result. The dedicated workflow gates timing AFTER retaining it.
    result
}

fn absolute(current: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        current.join(path)
    }
}

fn firmware(current: &Path, options: &BootOptions, host: &Host) -> Result<(PathBuf, PathBuf)> {
    let code = options
        .ovmf_code
        .as_ref()
        .or(host.firmware_override.as_ref())
        .map(|path| absolute(current, path))
        .or_else(|| {
            host.firmware_candidates
                .iter()
                .find(|path| path.is_file())
                .cloned()
        })
        .ok_or("OVMF firmware was not found; use --ovmf-code PATH")?;
    let vars = options
        .ovmf_vars
        .as_ref()
        .map(|path| absolute(current, path))
        .or_else(|| {
            let name = code.file_name()?.to_str()?;
            let name = if name.contains("CODE") {
                name.replace("CODE", "VARS")
            } else if name.contains("code") {
                name.replace("code", "vars")
            } else {
                return None;
            };
            Some(code.with_file_name(name))
        })
        .ok_or("cannot infer firmware variables template; use --ovmf-vars PATH")?;
    for path in [&code, &vars] {
        let metadata =
            fs::metadata(path).map_err(|error| format!("firmware {}: {error}", path.display()))?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err(format!("invalid firmware file: {}", path.display()));
        }
        File::open(path).map_err(|error| format!("firmware {}: {error}", path.display()))?;
    }
    Ok((
        code.canonicalize().map_err(|error| error.to_string())?,
        vars.canonicalize().map_err(|error| error.to_string())?,
    ))
}

// QEMU's comma-separated option parser doubles literal commas in path values.
fn qemu_path(path: &Path) -> Result<String> {
    path.to_str()
        .map(|path| path.replace(',', ",,"))
        .ok_or_else(|| "QEMU paths must be UTF-8".into())
}

/// Internal selection; only the dedicated storage workflow can create its disk.
pub(crate) struct StorageBoot<'a> {
    pub manifest: &'a Path,
    pub evidence: &'a Path,
    pub disk: &'a crate::storage::Disk,
    pub phase: crate::storage::Phase,
    pub store: Option<ev_userspace_contract::store_test::Control>,
}

pub(crate) struct GenerationBoot<'a> {
    pub manifest: &'a Path,
    pub evidence: &'a Path,
    pub disk: &'a crate::storage::Disk,
    pub control: ev_userspace_contract::generation::Control,
    pub variant: GenerationVariant,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum GenerationVariant {
    Fault,
    MissingProgress,
}
impl GenerationVariant {
    pub(crate) fn fixture(self) -> &'static str {
        match self {
            Self::Fault => "m3-generation",
            Self::MissingProgress => "m3-progress",
        }
    }
}

pub(crate) struct FileBoot<'a> {
    pub manifest: &'a Path,
    pub evidence: &'a Path,
    pub disk: &'a crate::storage::Disk,
    pub control: ev_userspace_contract::file_test::Control,
}

pub(crate) struct DisplayBoot<'a> {
    pub manifest: &'a Path,
    pub evidence: &'a Path,
}

pub(crate) struct DesktopBoot<'a> {
    pub manifest: &'a Path,
    pub evidence: &'a Path,
    pub disk: &'a crate::storage::Disk,
}

pub(crate) struct NativeBoot<'a> {
    pub manifest: &'a Path,
    pub evidence: &'a Path,
    pub disk: &'a crate::storage::Disk,
    pub phase: crate::native_io::Phase,
}
pub(crate) struct DocumentBoot<'a> {
    pub manifest: &'a Path,
    pub evidence: &'a Path,
    pub disk: &'a crate::storage::Disk,
    pub phase: Option<crate::document_io::Phase>,
}
/// Explicit finite failure qualification on the ordinary offline document guest.
/// Only Cut expects SIGKILL; Cold retains the normal completed-session grammar.
pub(crate) struct DocumentInterruptionBoot<'a> {
    pub manifest: &'a Path,
    pub evidence: &'a Path,
    pub disk: &'a crate::storage::Disk,
    pub phase: crate::document_interruption::Phase,
}
/// Explicit finite graphical qualification; the manual launch never selects it.
pub(crate) struct DocumentGuideBoot<'a> {
    pub manifest: &'a Path,
    pub evidence: &'a Path,
    pub disk: &'a crate::storage::Disk,
    pub phase: crate::document_guide::Phase,
}
pub(crate) struct CompatibilityBoot<'a> {
    pub manifest: &'a Path,
    pub evidence: &'a Path,
    pub disk: &'a crate::storage::Disk,
    pub phase: crate::document_compatibility::Phase,
}
pub(crate) struct DocumentAcquisitionBoot<'a> {
    pub manifest: &'a Path,
    pub evidence: &'a Path,
    pub disk: &'a crate::storage::Disk,
    pub phase: crate::acquisition_io::Phase,
}
pub(crate) struct DocumentUpdateBoot<'a> {
    pub manifest: &'a Path,
    pub evidence: &'a Path,
    pub disk: &'a crate::storage::Disk,
    pub phase: crate::system_health_io::Phase,
}
pub(crate) struct SessionBoot<'a> {
    pub manifest: &'a Path,
    pub evidence: &'a Path,
    pub disk: &'a crate::storage::Disk,
    pub phase: Option<crate::session_io::Phase>,
}
pub(crate) struct OwnerNetworkBoot<'a> {
    pub manifest: &'a Path,
    pub evidence: &'a Path,
    pub disk: &'a crate::storage::Disk,
    pub mode: crate::network_mode::Mode,
}
/// Separate finite owner-control qualification; manual launches never select it.
pub(crate) struct OwnerUiProbeBoot<'a> {
    pub manifest: &'a Path,
    pub evidence: &'a Path,
    pub disk: &'a crate::storage::Disk,
    pub mode: crate::network_mode::Mode,
    pub phase: crate::owner_ui_io::Phase,
}

pub(crate) struct NetworkBoot<'a> {
    pub manifest: &'a Path,
    pub evidence: &'a Path,
    pub disk: &'a crate::storage::Disk,
    pub probe: Option<crate::network_io::Goal>,
}
pub(crate) struct NetworkNegativeBoot<'a> {
    pub manifest: &'a Path,
    pub evidence: &'a Path,
    pub disk: &'a crate::storage::Disk,
    pub goal: crate::network_negative_contract::Goal,
}

pub(crate) struct SystemHealthBoot<'a> {
    pub manifest: &'a Path,
    pub evidence: &'a Path,
    pub disk: &'a crate::storage::Disk,
    pub phase: crate::system_health_io::Phase,
}

pub(crate) struct AcquisitionBoot<'a> {
    pub manifest: &'a Path,
    pub evidence: &'a Path,
    pub disk: &'a crate::storage::Disk,
    pub phase: crate::acquisition_io::Phase,
}
pub(crate) struct IpcBenchBoot<'a> {
    pub manifest: &'a Path,
    pub evidence: &'a Path,
    pub images: crate::ipc_bench_protocol::Images,
}

pub(crate) struct ProviderBoot<'a> {
    pub manifest: &'a Path,
    pub evidence: &'a Path,
    pub images: crate::provider_protocol::Images,
}
pub(crate) struct Native3Boot<'a> {
    pub manifest: &'a Path,
    pub evidence: &'a Path,
    pub disk: &'a crate::storage::Disk,
    pub phase: crate::native3_io::Phase,
}

pub(crate) struct OwnerBoot<'a> {
    pub manifest: &'a Path,
    pub evidence: &'a Path,
    pub disk: &'a crate::storage::Disk,
    pub control: ev_userspace_contract::generation::Control,
    pub catalogue: &'a str,
    pub input: Option<crate::owner_io::Input>,
}

struct OwnerAttachment<'a> {
    catalogue: &'a str,
    input: Option<crate::owner_io::Input>,
    eof: &'a std::cell::Cell<bool>,
}

#[derive(Clone, Copy)]
enum Experiment {
    Pio(crate::storage::Phase),
    Store(ev_userspace_contract::store_test::Control),
    Generation(
        ev_userspace_contract::generation::Control,
        GenerationVariant,
    ),
    File(ev_userspace_contract::file_test::Control),
    Owner(ev_userspace_contract::generation::Control),
    Display,
    Desktop,
    Native(crate::native_io::Phase),
    Session(Option<crate::session_io::Phase>),
    Document(Option<crate::document_io::Phase>),
    DocumentInterruption(crate::document_interruption::Phase),
    DocumentGuide(crate::document_guide::Phase),
    Compatibility(crate::document_compatibility::Phase),
    DocumentAcquisition(crate::acquisition_io::Phase),
    DocumentUpdate(crate::system_health_io::Phase),
    Network(Option<crate::network_io::Goal>),
    Negative(crate::network_negative_contract::Goal),
    OwnerNetwork(crate::network_mode::Mode),
    OwnerUiProbe(crate::network_mode::Mode, crate::owner_ui_io::Phase),
    Acquisition(crate::acquisition_io::Phase),
    SystemHealth(crate::system_health_io::Phase),
    Native3(crate::native3_io::Phase),
    Provider(crate::provider_protocol::Images),
    IpcBench(crate::ipc_bench_protocol::Images),
}
// A relative server bind must itself fit sockaddr_un; the FD-relative
// client cannot shorten QEMU's bind argument. Retained owner/document sessions
// and the explicitly selected graphical guide bind in their private run folder.
fn qmp_placement(
    root: &Path,
    directory: &Path,
    experiment: Option<Experiment>,
) -> Result<(PathBuf, String)> {
    let relative = directory
        .strip_prefix(root)
        .map_err(|_| "private QMP socket escaped root")?;
    let (cwd, socket) = if matches!(
        experiment,
        Some(
            Experiment::OwnerNetwork(_)
                | Experiment::Document(None)
                | Experiment::DocumentInterruption(_)
                | Experiment::DocumentGuide(_)
                | Experiment::Compatibility(_)
                | Experiment::DocumentAcquisition(_)
                | Experiment::DocumentUpdate(_)
        )
    ) {
        (directory.to_owned(), PathBuf::from("qmp.sock"))
    } else {
        (root.to_owned(), relative.join("qmp.sock"))
    };
    Ok((
        cwd,
        format!("unix:{},server=on,wait=off", qemu_path(&socket)?),
    ))
}

struct SelectedBoot<'a> {
    manifest: &'a Path,
    evidence: &'a Path,
    disk: Option<&'a crate::storage::Disk>,
    experiment: Experiment,
    owner: Option<OwnerAttachment<'a>>,
}
impl Experiment {
    fn fixture(self) -> &'static str {
        match self {
            Self::Pio(phase) => phase.fixture(),
            Self::Store(_) => "m3-store",
            Self::Generation(_, variant) => variant.fixture(),
            Self::File(_) => "m3-file",
            Self::Owner(_) => "m3-owner",
            Self::Display => "m4-display",
            Self::Desktop => "m4-desktop",
            Self::Native(_) => "m5-native",
            Self::Session(_) => "m6-session",
            Self::Document(Some(_)) => "m7-document",
            Self::DocumentInterruption(_) => "m7-document",
            Self::Document(None) | Self::DocumentGuide(_) => "m7-document-session",
            Self::Compatibility(_) => "m7-document-network",
            Self::DocumentAcquisition(_) => "m7-document-network",
            Self::DocumentUpdate(phase) => phase.mode().document_fixture(),
            Self::Network(_) | Self::Acquisition(_) => "m6-network",
            Self::OwnerNetwork(mode) | Self::OwnerUiProbe(mode, _) => mode.owner_fixture(),
            Self::SystemHealth(phase) => phase.fixture(),
            Self::Negative(goal) => goal.fixture(),
            Self::Native3(phase) => phase.fixture(),
            Self::Provider(_) => "m5-provider",
            Self::IpcBench(_) => "m5-ipc-bench",
        }
    }
}

pub(crate) fn boot_generation(options: &BootOptions, selection: GenerationBoot<'_>) -> Result<()> {
    if options.debug || options.expect_panic || options.runs != 1 || options.cpus != 1 {
        return Err("generation acceptance requires one non-debug single-CPU fresh boot".into());
    }
    boot_selected(
        options,
        Some(SelectedBoot {
            manifest: selection.manifest,
            evidence: selection.evidence,
            disk: Some(selection.disk),
            experiment: Experiment::Generation(selection.control, selection.variant),
            owner: None,
        }),
    )
}

pub(crate) fn boot_file(options: &BootOptions, selection: FileBoot<'_>) -> Result<()> {
    if options.debug || options.expect_panic || options.runs != 1 || options.cpus != 1 {
        return Err("File/Object proof requires one non-debug single-CPU fresh boot".into());
    }
    boot_selected(
        options,
        Some(SelectedBoot {
            manifest: selection.manifest,
            evidence: selection.evidence,
            disk: Some(selection.disk),
            experiment: Experiment::File(selection.control),
            owner: None,
        }),
    )
}

pub(crate) fn boot_owner(options: &BootOptions, selection: OwnerBoot<'_>) -> Result<bool> {
    if options.debug || options.expect_panic || options.runs != 1 || options.cpus != 1 {
        return Err("owner recovery requires one non-debug single-CPU boot".into());
    }
    if (selection.control.mode == ev_userspace_contract::generation::Mode::OwnerRecover)
        != selection.input.is_some()
    {
        return Err("only an owner-recovery phase may attach console input".into());
    }
    let eof = std::cell::Cell::new(false);
    boot_selected(
        options,
        Some(SelectedBoot {
            manifest: selection.manifest,
            evidence: selection.evidence,
            disk: Some(selection.disk),
            experiment: Experiment::Owner(selection.control),
            owner: Some(OwnerAttachment {
                catalogue: selection.catalogue,
                input: selection.input,
                eof: &eof,
            }),
        }),
    )?;
    Ok(eof.get())
}

pub(crate) fn boot_display(options: &BootOptions, selection: DisplayBoot<'_>) -> Result<()> {
    if options.debug || options.expect_panic || options.runs != 1 || options.cpus != 1 {
        return Err("display surface proof requires one non-debug single-CPU fresh boot".into());
    }
    boot_selected(
        options,
        Some(SelectedBoot {
            manifest: selection.manifest,
            evidence: selection.evidence,
            disk: None,
            experiment: Experiment::Display,
            owner: None,
        }),
    )
}

pub(crate) fn boot_desktop(options: &BootOptions, selection: DesktopBoot<'_>) -> Result<()> {
    if options.debug || options.expect_panic || options.runs != 1 || options.cpus != 1 {
        return Err("desktop graph requires one non-debug single-CPU fresh VM".into());
    }
    boot_selected(
        options,
        Some(SelectedBoot {
            manifest: selection.manifest,
            evidence: selection.evidence,
            disk: Some(selection.disk),
            experiment: Experiment::Desktop,
            owner: None,
        }),
    )
}

/// The synthetic final line validates ONLY earlier boot protocol parser input.
/// It is never written to evidence or accepted as guest completion.
pub(crate) fn check_display_present_prefix(
    serial: &[u8],
    build: &str,
) -> Result<Option<crate::graphics_protocol::Present>> {
    let Some(present) = crate::graphics_protocol::present(serial, build)? else {
        return Ok(None);
    };
    let text = std::str::from_utf8(serial).map_err(|_| "display prefix is not UTF-8")?;
    let start = text
        .find("EVROSION_M4_PRESENT ")
        .ok_or("display Present prefix missing")?;
    let tail = &text[start..];
    if !tail.ends_with('\n')
        || tail.lines().count() != 1
        || text.contains("EVROSION_M4_DISPLAY ")
        || text.contains(ev_test_protocol::PASS)
    {
        return Err(
            "display Present must precede completion and be the latest complete record".into(),
        );
    }
    boot_protocol::check(
        format!("{}{}\r\n", &text[..start], ev_test_protocol::PASS).as_bytes(),
        build,
        Some(ev_test_protocol::QEMU_PASS_STATUS),
    )?;
    Ok(Some(present))
}

pub(crate) fn boot_provider(options: &BootOptions, selection: ProviderBoot<'_>) -> Result<()> {
    if options.debug || options.expect_panic || options.runs != 1 || options.cpus != 1 {
        return Err("Provider proof requires one non-debug single-CPU fresh VM".into());
    }
    boot_selected(
        options,
        Some(SelectedBoot {
            manifest: selection.manifest,
            evidence: selection.evidence,
            disk: None,
            experiment: Experiment::Provider(selection.images),
            owner: None,
        }),
    )
}

pub(crate) fn boot_ipc_bench(options: &BootOptions, selection: IpcBenchBoot<'_>) -> Result<()> {
    if options.debug || options.expect_panic || options.runs != 1 || options.cpus != 1 {
        return Err("IPC benchmark sample requires one non-debug single-CPU fresh VM".into());
    }
    boot_selected(
        options,
        Some(SelectedBoot {
            manifest: selection.manifest,
            evidence: selection.evidence,
            disk: None,
            experiment: Experiment::IpcBench(selection.images),
            owner: None,
        }),
    )
}

pub(crate) fn boot_native_presented(
    options: &BootOptions,
    selection: NativeBoot<'_>,
    visible: bool,
) -> Result<()> {
    if options.debug || options.expect_panic || options.runs != 1 || options.cpus != 1 {
        return Err("Native proof requires one non-debug single-CPU fresh VM".into());
    }
    if visible && selection.phase != crate::native_io::Phase::InstallFull {
        return Err(
            "visible Native presentation requires the complete install demonstration".into(),
        );
    }
    boot_selected_presented(
        options,
        Some(SelectedBoot {
            manifest: selection.manifest,
            evidence: selection.evidence,
            disk: Some(selection.disk),
            experiment: Experiment::Native(selection.phase),
            owner: None,
        }),
        visible,
    )
}

pub(crate) fn boot_document(options: &BootOptions, selection: DocumentBoot<'_>) -> Result<()> {
    if options.cpus != 1 || options.runs != 1 || options.debug || options.expect_panic {
        return Err("document workflow requires one non-debug single-CPU VM".into());
    }
    boot_selected_presented(
        options,
        Some(SelectedBoot {
            manifest: selection.manifest,
            evidence: selection.evidence,
            disk: Some(selection.disk),
            experiment: Experiment::Document(selection.phase),
            owner: None,
        }),
        selection.phase.is_none(),
    )
}

pub(crate) fn boot_document_interruption(
    options: &BootOptions,
    selection: DocumentInterruptionBoot<'_>,
) -> Result<()> {
    if options.cpus != 1 || options.runs != 1 || options.debug || options.expect_panic {
        return Err("document interruption requires one non-debug single-CPU VM".into());
    }
    boot_selected(
        options,
        Some(SelectedBoot {
            manifest: selection.manifest,
            evidence: selection.evidence,
            disk: Some(selection.disk),
            experiment: Experiment::DocumentInterruption(selection.phase),
            owner: None,
        }),
    )
}

pub(crate) fn boot_document_guide(
    options: &BootOptions,
    selection: DocumentGuideBoot<'_>,
) -> Result<()> {
    if options.cpus != 1 || options.runs != 1 || options.debug || options.expect_panic {
        return Err("document guide requires one non-debug single-CPU VM".into());
    }
    boot_selected_presented(
        options,
        Some(SelectedBoot {
            manifest: selection.manifest,
            evidence: selection.evidence,
            disk: Some(selection.disk),
            experiment: Experiment::DocumentGuide(selection.phase),
            owner: None,
        }),
        true,
    )
}

pub(crate) fn boot_compatibility(
    options: &BootOptions,
    selection: CompatibilityBoot<'_>,
) -> Result<()> {
    if options.cpus != 1 || options.runs != 1 || options.debug || options.expect_panic {
        return Err("saved0.2 compatibility requires one non-debug single-CPU VM".into());
    }
    boot_selected_presented(
        options,
        Some(SelectedBoot {
            manifest: selection.manifest,
            evidence: selection.evidence,
            disk: Some(selection.disk),
            experiment: Experiment::Compatibility(selection.phase),
            owner: None,
        }),
        false,
    )
}

pub(crate) fn boot_document_acquisition(
    options: &BootOptions,
    selection: DocumentAcquisitionBoot<'_>,
) -> Result<()> {
    if options.cpus != 1
        || options.runs != 1
        || options.debug
        || options.expect_panic
        || options.timeout_seconds != crate::acquisition_io::TIMEOUT_SECONDS
    {
        return Err("document acquisition requires one finite600s non-debug single-CPU VM".into());
    }
    boot_selected(
        options,
        Some(SelectedBoot {
            manifest: selection.manifest,
            evidence: selection.evidence,
            disk: Some(selection.disk),
            experiment: Experiment::DocumentAcquisition(selection.phase),
            owner: None,
        }),
    )
}

pub(crate) fn boot_document_update(
    options: &BootOptions,
    selection: DocumentUpdateBoot<'_>,
) -> Result<()> {
    if options.cpus != 1
        || options.runs != 1
        || options.debug
        || options.expect_panic
        || options.timeout_seconds != crate::acquisition_io::TIMEOUT_SECONDS
    {
        return Err("document update requires one finite600s non-debug single-CPU VM".into());
    }
    boot_selected(
        options,
        Some(SelectedBoot {
            manifest: selection.manifest,
            evidence: selection.evidence,
            disk: Some(selection.disk),
            experiment: Experiment::DocumentUpdate(selection.phase),
            owner: None,
        }),
    )
}

pub(crate) fn boot_session(options: &BootOptions, selection: SessionBoot<'_>) -> Result<()> {
    if options.cpus != 1 || options.runs != 1 || options.debug || options.expect_panic {
        return Err("developer session requires one non-debug single-CPU VM".into());
    }
    boot_selected_presented(
        options,
        Some(SelectedBoot {
            manifest: selection.manifest,
            evidence: selection.evidence,
            disk: Some(selection.disk),
            experiment: Experiment::Session(selection.phase),
            owner: None,
        }),
        selection.phase.is_none(),
    )
}

pub(crate) fn boot_network(options: &BootOptions, selection: NetworkBoot<'_>) -> Result<()> {
    if options.cpus != 1 || options.runs != 1 || options.debug || options.expect_panic {
        return Err("network session requires one non-debug single-CPU VM".into());
    }
    boot_selected_presented(
        options,
        Some(SelectedBoot {
            manifest: selection.manifest,
            evidence: selection.evidence,
            disk: Some(selection.disk),
            experiment: Experiment::Network(selection.probe),
            owner: None,
        }),
        selection.probe.is_none(),
    )
}

pub(crate) fn boot_network_negative(
    options: &BootOptions,
    selection: NetworkNegativeBoot<'_>,
) -> Result<()> {
    if options.cpus != 1 || options.runs != 1 || options.debug || options.expect_panic {
        return Err("network negative probe requires one finite non-debug single-CPU VM".into());
    }
    boot_selected_presented(
        options,
        Some(SelectedBoot {
            manifest: selection.manifest,
            evidence: selection.evidence,
            disk: Some(selection.disk),
            experiment: Experiment::Negative(selection.goal),
            owner: None,
        }),
        false,
    )
}

pub(crate) fn boot_system_health(
    options: &BootOptions,
    selection: SystemHealthBoot<'_>,
) -> Result<()> {
    if options.cpus != 1
        || options.runs != 1
        || options.debug
        || options.expect_panic
        || options.timeout_seconds != crate::acquisition_io::TIMEOUT_SECONDS
    {
        return Err("System health requires one finite600s non-debug single-CPU VM".into());
    }
    boot_selected_presented(
        options,
        Some(SelectedBoot {
            manifest: selection.manifest,
            evidence: selection.evidence,
            disk: Some(selection.disk),
            experiment: Experiment::SystemHealth(selection.phase),
            owner: None,
        }),
        false,
    )
}

/// Only a complete checked normal boot may return an authenticated restart
/// intent. The caller must still match the durable selector and retained set.
pub(crate) fn boot_owner_network(
    options: &BootOptions,
    selection: OwnerNetworkBoot<'_>,
) -> Result<Option<crate::restart_protocol::Intent>> {
    if options.cpus != 1
        || options.runs != 1
        || options.debug
        || options.expect_panic
        || options.batch
    {
        return Err("owner network requires one manual non-debug single-CPU boot".into());
    }
    let bytes = fs::read(selection.manifest).map_err(|e| e.to_string())?;
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    manifest.validate_policy_rows()?;
    if manifest.profile != "release"
        || manifest.fixture.as_deref() != Some(selection.mode.owner_fixture())
    {
        return Err("owner network mode/profile differs from retained fixture".into());
    }
    boot_selected_presented(
        options,
        Some(SelectedBoot {
            manifest: selection.manifest,
            evidence: selection.evidence,
            disk: Some(selection.disk),
            experiment: Experiment::OwnerNetwork(selection.mode),
            owner: None,
        }),
        true,
    )?;
    if fs::read(selection.manifest).map_err(|e| e.to_string())? != bytes {
        return Err("owner network retained manifest changed during boot".into());
    }
    let serial = crate::acquisition_io::bounded(
        &selection.evidence.join("boot/run-001/serial.log"),
        1024 * 1024,
    )?;
    let intents = crate::restart_protocol::records(&serial, &manifest.build_id)?;
    Ok(intents.into_iter().next())
}

pub(crate) fn boot_owner_ui_probe(
    options: &BootOptions,
    selection: OwnerUiProbeBoot<'_>,
) -> Result<Option<crate::restart_protocol::Intent>> {
    if options.cpus != 1
        || options.runs != 1
        || options.debug
        || options.expect_panic
        || options.batch
    {
        return Err("owner UI probe requires one finite non-debug single-CPU VM".into());
    }
    boot_selected_presented(
        options,
        Some(SelectedBoot {
            manifest: selection.manifest,
            evidence: selection.evidence,
            disk: Some(selection.disk),
            experiment: Experiment::OwnerUiProbe(selection.mode, selection.phase),
            owner: None,
        }),
        false,
    )?;
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(selection.manifest).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let serial = crate::acquisition_io::bounded(
        &selection.evidence.join("boot/run-001/serial.log"),
        1024 * 1024,
    )?;
    Ok(
        crate::restart_protocol::records(&serial, &manifest.build_id)?
            .into_iter()
            .next(),
    )
}

pub(crate) fn boot_acquisition(
    options: &BootOptions,
    selection: AcquisitionBoot<'_>,
) -> Result<()> {
    if options.cpus != 1
        || options.runs != 1
        || options.debug
        || options.expect_panic
        || options.timeout_seconds != crate::acquisition_io::TIMEOUT_SECONDS
    {
        return Err("acquisition requires one finite600s non-debug single-CPU VM".into());
    }
    boot_selected_presented(
        options,
        Some(SelectedBoot {
            manifest: selection.manifest,
            evidence: selection.evidence,
            disk: Some(selection.disk),
            experiment: Experiment::Acquisition(selection.phase),
            owner: None,
        }),
        false,
    )
}

pub(crate) fn boot_native3(options: &BootOptions, selection: Native3Boot<'_>) -> Result<()> {
    if options.debug
        || options.expect_panic
        || options.runs != 1
        || options.cpus != 1
        || options.batch
    {
        return Err("Native3 requires one non-debug single-CPU cold VM".into());
    }
    boot_selected(
        options,
        Some(SelectedBoot {
            manifest: selection.manifest,
            evidence: selection.evidence,
            disk: Some(selection.disk),
            experiment: Experiment::Native3(selection.phase),
            owner: None,
        }),
    )
}

/// The terminator below validates only immutable earlier boot-parser input.
/// It is never written to serial/evidence or accepted as guest completion.
pub(crate) fn check_desktop_prefix(serial: &[u8], build: &str) -> Result<()> {
    crate::desktop_protocol::steps(serial, build)?;
    let text = std::str::from_utf8(serial).map_err(|_| "desktop prefix not UTF-8")?;
    let start = text
        .find("EVROSION_M4_DESKTOP_STEP ")
        .ok_or("desktop checkpoint missing")?;
    let start = ["EVROSION_NATIVE_", "EVROSION_M5_NATIVE_"]
        .into_iter()
        .filter_map(|marker| text.find(marker))
        .fold(start, usize::min);
    let before = &text[..start];
    if before.contains(ev_test_protocol::PASS)
        || !before.contains("EVROSION_M2_IPC_DISCIPLINE status=PASS ")
    {
        return Err("desktop checkpoint lacks the required completed boot proof prefix".into());
    }
    boot_protocol::check(
        format!("{before}{}\r\n", ev_test_protocol::PASS).as_bytes(),
        build,
        Some(ev_test_protocol::QEMU_PASS_STATUS),
    )
}

#[cfg(test)]
mod native_prefix_regression {
    use super::*;
    // Actual Run4 trace retained unchanged; parser regression, no new guest
    // execution claim. The synthetic terminator never reaches guest/evidence.
    const TRACE: &[u8] = include_bytes!("../../../tests/fixtures/native3-home-prefix.serial");
    const BUILD: &str = "38b85b3ddf4afbb6b9929931fca6f95fceccdd48f5eec3bea6554e13b9b49918";
    #[test]
    fn native_memory_and_common_prefix_do_not_poison_completed_core_prefix() {
        check_desktop_prefix(TRACE, BUILD).unwrap();
        assert!(check_desktop_prefix(TRACE, &"b".repeat(64)).is_err());
        let text = std::str::from_utf8(TRACE).unwrap();
        assert!(
            check_desktop_prefix(
                text.replace(
                    "EVROSION_M2_IPC_DISCIPLINE status=PASS",
                    "EVROSION_M2_IPC_DISCIPLINE status=FAIL"
                )
                .as_bytes(),
                BUILD
            )
            .is_err()
        );
        // Completing the prefix does not turn an incomplete owned run into PASS.
        assert!(
            boot_protocol::check(TRACE, BUILD, Some(ev_test_protocol::QEMU_PASS_STATUS)).is_err()
        );
    }
}

/// Validate only the completed pre-action prefix. The synthetic terminator is
/// parser input, never a guest PASS or evidence that recovery has executed.
pub(crate) fn check_owner_prompt_prefix(
    serial: &[u8],
    build: &str,
    catalogue: &str,
) -> Result<Option<crate::owner_protocol::Prompt>> {
    let prompt = crate::owner_protocol::prompt(serial, build, catalogue)?;
    if prompt.is_none() {
        return Ok(None);
    }
    let text = crate::owner_protocol::text(serial)?;
    if !text.ends_with('\n')
        || text.contains("EVROSION_M3_OWNER status=")
        || text.contains(ev_test_protocol::PASS)
    {
        return Err("owner prompt arrived after completion or incomplete output".into());
    }
    boot_protocol::check(
        format!("{text}{}\r\n", ev_test_protocol::PASS).as_bytes(),
        build,
        Some(ev_test_protocol::QEMU_PASS_STATUS),
    )?;
    Ok(prompt)
}

pub(crate) fn boot_storage(options: &BootOptions, storage: StorageBoot<'_>) -> Result<()> {
    if options.debug || options.expect_panic || options.runs != 1 || options.cpus != 1 {
        return Err("storage acceptance requires one non-debug single-CPU fresh boot".into());
    }
    boot_selected(
        options,
        Some(SelectedBoot {
            manifest: storage.manifest,
            evidence: storage.evidence,
            disk: Some(storage.disk),
            experiment: storage
                .store
                .map_or(Experiment::Pio(storage.phase), Experiment::Store),
            owner: None,
        }),
    )
}

#[cfg(all(test, unix))]
mod cut_lifecycle_tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    #[test]
    fn validated_stop_kills_only_child_and_validation_error_also_reaps() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let parent = crate::storage::directory_beneath(&root, Path::new("build/test-tmp")).unwrap();
        for reject in [false, true] {
            let directory = build::unique_directory(&parent, "cut-lifecycle").unwrap();
            let pid = directory.join("pid");
            let log = directory.join("serial");
            fs::write(&log, b"").unwrap();
            let mut command = Command::new("python3");
            command.args(["-c", "from pathlib import Path; import os,sys,time; Path(sys.argv[1]).write_text(str(os.getpid())); Path(sys.argv[2]).write_text('ready\\n'); time.sleep(30)"])
                .arg(&pid).arg(&log).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
            let mut stop = || {
                if fs::read(&log).map_err(|e| e.to_string())? != b"ready\n" {
                    return Ok(false);
                }
                if reject {
                    Err("deliberate validation refusal".into())
                } else {
                    Ok(true)
                }
            };
            let result = supervised_until(
                &mut command,
                &[&log],
                Duration::from_secs(3),
                Some(&mut stop),
            );
            if reject {
                assert!(result.unwrap_err().contains("validation refusal"));
            } else {
                assert_eq!(result.unwrap().signal(), Some(9));
            }
            let child_pid = fs::read_to_string(&pid).unwrap();
            assert!(
                !Path::new("/proc").join(child_pid).exists(),
                "test child alive or unreaped"
            );
            fs::remove_dir_all(directory).unwrap();
        }
    }
}

pub fn boot(options: &BootOptions) -> Result<()> {
    boot_selected(options, None)
}

fn boot_selected(options: &BootOptions, storage: Option<SelectedBoot<'_>>) -> Result<()> {
    boot_selected_presented(options, storage, false)
}

fn boot_selected_presented(
    options: &BootOptions,
    storage: Option<SelectedBoot<'_>>,
    visible: bool,
) -> Result<()> {
    if visible
        && !storage.as_ref().is_some_and(|s| {
            matches!(
                s.experiment,
                Experiment::Native(crate::native_io::Phase::InstallFull)
                    | Experiment::Session(None)
                    | Experiment::Document(None)
                    | Experiment::DocumentGuide(_)
                    | Experiment::Network(None)
                    | Experiment::Negative(_)
                    | Experiment::OwnerNetwork(_)
            )
        })
    {
        return Err(
            "visible presentation requires an explicitly selected manual session or Native demo"
                .into(),
        );
    }
    let current = std::env::current_dir().map_err(|error| error.to_string())?;
    let root = crate::doctor::workspace(&current, options.root.as_deref())?;
    let output = root.join(
        if storage.as_ref().is_some_and(|s| {
            matches!(
                s.experiment,
                Experiment::Document(None) | Experiment::DocumentGuide(_)
            )
        }) {
            crate::document_session::ARTIFACTS
        } else {
            "build/m0"
        },
    );
    let manifest_path = storage.as_ref().map_or_else(
        || output.join("manifest.json"),
        |selection| selection.manifest.to_owned(),
    );
    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|error| format!("build manifest: {error}; run cargo ev build first"))?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("build manifest: {error}"))?;
    manifest.validate_policy_rows()?;
    if manifest.schema != 1
        || !manifest.qemu_test_exit
        || manifest.build_id.len() != 64
        || !manifest
            .build_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("unsupported or malformed M0 test image manifest".into());
    }
    if options.expect_panic != (manifest.fixture.as_deref() == Some("panic")) && !options.debug {
        return Err(
            "fixture mismatch: use build --fixture panic then test panic, or build then test boot"
                .into(),
        );
    }
    if let Some(selection) = &storage {
        let fixture = selection.experiment.fixture();
        if manifest.fixture.as_deref() != Some(fixture) {
            return Err("storage phase does not match the retained build manifest".into());
        }
    } else if matches!(
        manifest.fixture.as_deref(),
        Some(
            "m3-pio-write"
                | "m3-pio-verify"
                | "m3-store"
                | "m3-generation"
                | "m3-owner"
                | "m3-progress"
                | "m3-file"
                | "m4-display"
                | "m4-desktop"
                | "m5-native"
                | "m5-native-system"
                | "m5-native-recovery"
                | "m6-session"
                | "m7-document"
                | "m7-document-session"
                | "m7-document-network"
                | "m7-document-system"
                | "m7-document-recovery"
                | "m6-network"
                | "m6-network-negative"
                | "m6-network-system"
                | "m6-network-recovery"
                | "m6-network-owner"
                | "m6-network-system-owner"
                | "m6-network-recovery-owner"
                | "m5-provider"
                | "m5-ipc-bench"
        )
    ) {
        return Err("storage/display fixtures require their explicit dedicated workflow".into());
    }
    let image = build::verify_artifact(&output, &manifest.image)?;
    let kernel = build::verify_artifact(&output, &manifest.kernel)?;
    build::verify_artifact(&output, &manifest.loader)?;
    build::verify_artifact(&output, &manifest.image_builder)?;
    for artifact in &manifest.supervisor {
        build::verify_artifact(&output, artifact)?;
    }
    let host = Host::detect(&current);
    let qemu = host.executable("qemu-system-x86_64")?;
    let qemu_hash = build::hash_file(&qemu)?;
    let (code, vars_template) = firmware(&current, options, &host)?;
    let code_hash = build::hash_file(&code)?;
    let vars_hash = build::hash_file(&vars_template)?;
    let cut = storage
        .as_ref()
        .and_then(|s| match s.experiment {
            Experiment::Store(control) => Some(control),
            _ => None,
        })
        .filter(|control| control.mode == ev_userspace_contract::store_test::Mode::Cut);
    let document_interruption = storage.as_ref().and_then(|s| match s.experiment {
        Experiment::DocumentInterruption(phase) => Some(phase),
        _ => None,
    });
    let document_cut = document_interruption == Some(crate::document_interruption::Phase::Cut);
    let kind = if cut.is_some() {
        "store-cut"
    } else if document_cut {
        "document-interruption-cut"
    } else if document_interruption.is_some() {
        "document-interruption-cold"
    } else if options.debug {
        "debug"
    } else if options.expect_panic {
        "panic"
    } else {
        "boot"
    };
    let evidence = if let Some(selection) = &storage {
        let directory = selection.evidence.join("boot");
        fs::create_dir(&directory).map_err(|error| error.to_string())?;
        directory
    } else {
        build::unique_directory(&output.join("evidence"), kind)?
    };
    fs::write(evidence.join("manifest.json"), &manifest_bytes)
        .map_err(|error| error.to_string())?;
    let mut runs = Vec::new();
    let mut failure = None;
    for index in 1..=options.runs {
        let owner_attachment = storage
            .as_ref()
            .and_then(|selection| selection.owner.as_ref());
        let owner_input = owner_attachment.and_then(|owner| owner.input);
        let directory = evidence.join(format!("run-{index:03}"));
        fs::create_dir(&directory).map_err(|error| error.to_string())?;
        let display = storage
            .as_ref()
            .is_some_and(|s| matches!(s.experiment, Experiment::Display));
        let desktop = storage
            .as_ref()
            .is_some_and(|s| matches!(s.experiment, Experiment::Desktop));
        let network = storage.as_ref().is_some_and(|s| {
            matches!(
                s.experiment,
                Experiment::Network(_)
                    | Experiment::Acquisition(_)
                    | Experiment::Negative(_)
                    | Experiment::OwnerNetwork(_)
                    | Experiment::OwnerUiProbe(_, _)
                    | Experiment::SystemHealth(_)
                    | Experiment::Compatibility(_)
                    | Experiment::DocumentAcquisition(_)
                    | Experiment::DocumentUpdate(_)
            )
        });
        let document_update = storage
            .as_ref()
            .is_some_and(|s| matches!(s.experiment, Experiment::DocumentUpdate(_)));
        let document_acquisition = storage
            .as_ref()
            .is_some_and(|s| matches!(s.experiment, Experiment::DocumentAcquisition(_)));
        let system_health = storage.as_ref().and_then(|s| match s.experiment {
            Experiment::SystemHealth(phase) | Experiment::DocumentUpdate(phase) => Some(phase),
            _ => None,
        });
        let acquisition = storage.as_ref().and_then(|s| match s.experiment {
            Experiment::Acquisition(phase) | Experiment::DocumentAcquisition(phase) => Some(phase),
            _ => None,
        });
        let network_probe = storage.as_ref().and_then(|s| match s.experiment {
            Experiment::Network(goal) => goal,
            _ => None,
        });
        let negative = storage.as_ref().and_then(|s| match s.experiment {
            Experiment::Negative(goal) => Some(goal),
            _ => None,
        });
        let owner_ui_probe = storage.as_ref().and_then(|s| match s.experiment {
            Experiment::OwnerUiProbe(mode, phase) => Some((mode, phase)),
            _ => None,
        });
        let missing_entropy = network_probe == Some(crate::network_io::Goal::MissingEntropy);
        let session = storage.as_ref().is_some_and(|s| {
            matches!(
                s.experiment,
                Experiment::Session(_)
                    | Experiment::Document(_)
                    | Experiment::DocumentInterruption(_)
                    | Experiment::DocumentGuide(_)
                    | Experiment::Compatibility(_)
                    | Experiment::DocumentAcquisition(_)
                    | Experiment::DocumentUpdate(_)
                    | Experiment::Network(_)
                    | Experiment::Acquisition(_)
                    | Experiment::Negative(_)
                    | Experiment::OwnerNetwork(_)
                    | Experiment::OwnerUiProbe(_, _)
                    | Experiment::SystemHealth(_)
            )
        });
        let document_phase = storage.as_ref().and_then(|s| match s.experiment {
            Experiment::Document(phase) => phase,
            _ => None,
        });
        let document_guide = storage.as_ref().and_then(|s| match s.experiment {
            Experiment::DocumentGuide(phase) => Some(phase),
            _ => None,
        });
        let compatibility = storage.as_ref().and_then(|s| match s.experiment {
            Experiment::Compatibility(phase) => Some(phase),
            _ => None,
        });
        let session_phase = storage.as_ref().and_then(|s| match s.experiment {
            Experiment::Session(phase) => phase,
            _ => None,
        });
        let native = storage.as_ref().and_then(|s| match s.experiment {
            Experiment::Native(phase) => Some(phase),
            _ => None,
        });
        let native3 = storage.as_ref().and_then(|s| match s.experiment {
            Experiment::Native3(phase) => Some(phase),
            _ => None,
        });
        if display || desktop || native.is_some() || native3.is_some() || session {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
        }
        let vars = directory.join("OVMF_VARS.fd");
        fs::copy(&vars_template, &vars).map_err(|error| error.to_string())?;
        let serial = directory.join("serial.log");
        File::create(&serial).map_err(|error| error.to_string())?;
        let errors = directory.join("qemu.stderr.log");
        let stderr = File::create(&errors).map_err(|error| error.to_string())?;
        let mut arguments: Vec<String> = vec![
            "-machine".into(),
            "q35,accel=tcg".into(),
            "-cpu".into(),
            if missing_entropy {
                "max,rdrand=off"
            } else {
                "max"
            }
            .into(),
            "-smp".into(),
            options.cpus.to_string(),
            "-m".into(),
            "256M".into(),
            "-nodefaults".into(),
            "-no-user-config".into(),
            "-no-reboot".into(),
            "-display".into(),
            if visible { "gtk,gl=off" } else { "none" }.into(),
            "-monitor".into(),
            "none".into(),
            "-nic".into(),
            "none".into(),
            "-device".into(),
            "VGA".into(),
            "-device".into(),
            "isa-debug-exit,iobase=0xf4,iosize=0x04".into(),
            "-chardev".into(),
            if owner_input.is_some() || desktop || native.is_some() || native3.is_some() || session
            {
                format!("stdio,id=com1,signal=off,logfile={}", qemu_path(&serial)?)
            } else {
                format!("file,id=com1,path={}", qemu_path(&serial)?)
            },
            "-device".into(),
            "isa-serial,chardev=com1".into(),
            "-drive".into(),
            format!(
                "if=pflash,format=raw,unit=0,readonly=on,file={}",
                qemu_path(&code)?
            ),
            "-drive".into(),
            format!("if=pflash,format=raw,unit=1,file={}", qemu_path(&vars)?),
            "-drive".into(),
            format!("if=ide,format=raw,snapshot=on,file={}", qemu_path(&image)?),
            "-boot".into(),
            "order=c,menu=off".into(),
        ];
        if let Some(disk) = storage.as_ref().and_then(|s| s.disk) {
            arguments.extend(disk.arguments(&root)?);
        }
        if network {
            arguments.extend([
                "-S".into(),
                "-device".into(),
                crate::vm_profile::NIC.into(),
                "-netdev".into(),
                crate::vm_profile::NETDEV.into(),
                "-rtc".into(),
                crate::vm_profile::RTC.into(),
            ]);
        }
        let mut qemu_cwd = root.clone();
        if display || desktop || native.is_some() || native3.is_some() || session {
            let (cwd, qmp) = qmp_placement(
                &root,
                &directory,
                storage.as_ref().map(|selected| selected.experiment),
            )?;
            qemu_cwd = cwd;
            arguments.extend(["-qmp".into(), qmp]);
        }
        let debug_port = if options.debug {
            let socket = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
            let port = socket.local_addr().map_err(|e| e.to_string())?.port();
            arguments.extend(["-S".into(), "-gdb".into(), format!("tcp:127.0.0.1:{port}")]);
            Some(port)
        } else {
            None
        };
        build::write_json(
            &directory.join("qemu-command.json"),
            &json!({"program":qemu,"arguments":arguments,"cwd":qemu_cwd}),
        )?;
        if network {
            let qualified = if missing_entropy {
                crate::vm_profile::qualify_missing_entropy(&qemu, &arguments)?
            } else {
                crate::vm_profile::qualify(&qemu, &arguments)?
            };
            crate::storage::json_new(
                &directory.join("vm-source-qualification.json"),
                &serde_json::to_value(qualified).map_err(|e| e.to_string())?,
            )?;
        }
        let mut clock = if network {
            Some(crate::vm_clock::prepare(&root, &directory, &qemu)?)
        } else {
            None
        };
        println!(
            "Boot {index}/{} (TCG, timeout {}s); {}",
            options.runs,
            options.timeout_seconds,
            serial.display()
        );
        let mut command = Command::new(&qemu);
        command
            .args(&arguments)
            .current_dir(&qemu_cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr);
        if network {
            // These process hooks could replace the reviewed crypto/backend
            // despite the executable hash. The local host/loader stays trusted.
            for key in ["LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "QEMU_PLUGIN"] {
                command.env_remove(key);
            }
        }
        if let Some(clock) = &clock {
            clock.apply(&mut command)?;
        }
        let start = Instant::now();
        let mut owner_eof = false;
        let result = if let Some(phase) = compatibility {
            crate::document_compatibility::supervise(
                &mut command,
                &serial,
                &errors,
                Duration::from_secs(options.timeout_seconds),
                &manifest.build_id,
                &directory,
                clock
                    .as_mut()
                    .ok_or("compatibility requires verified clock")?,
                phase,
                storage
                    .as_ref()
                    .and_then(|s| s.disk)
                    .ok_or("compatibility disk absent")?,
            )
        } else if let Some((mode, phase)) = owner_ui_probe {
            let selected = storage.as_ref().ok_or("owner UI probe selection absent")?;
            crate::owner_ui_io::supervise(
                &mut command,
                &serial,
                &errors,
                Duration::from_secs(options.timeout_seconds),
                &manifest.build_id,
                &directory,
                clock.as_mut().ok_or("owner UI requires verified clock")?,
                &root,
                &manifest,
                mode,
                phase,
                selected.disk.ok_or("owner UI disk absent")?,
            )
        } else if let Some(phase) = system_health {
            let selected = storage.as_ref().ok_or("System selection absent")?;
            let supervise = if document_update {
                crate::system_health_io::supervise_document
            } else {
                crate::system_health_io::supervise
            };
            supervise(
                &mut command,
                &serial,
                &errors,
                Duration::from_secs(options.timeout_seconds),
                &manifest.build_id,
                &directory,
                clock.as_mut().ok_or("System requires verified clock")?,
                &root,
                &manifest,
                phase,
                selected.evidence,
                selected.disk.ok_or("System disk absent")?,
            )
        } else if let Some(phase) = acquisition {
            let selected = storage.as_ref().ok_or("acquisition selection absent")?;
            let supervise = if document_acquisition {
                crate::acquisition_io::supervise_document
            } else {
                crate::acquisition_io::supervise
            };
            supervise(
                &mut command,
                &serial,
                &errors,
                Duration::from_secs(options.timeout_seconds),
                &manifest.build_id,
                &directory,
                clock
                    .as_mut()
                    .ok_or("acquisition requires verified clock")?,
                &root,
                &manifest,
                phase,
                selected.evidence,
                selected.disk.ok_or("acquisition disk absent")?,
            )
        } else if let Some(goal) = negative {
            let selected = storage.as_ref().ok_or("negative selection absent")?;
            crate::network_negative::supervise(
                &mut command,
                &serial,
                &errors,
                Duration::from_secs(options.timeout_seconds),
                &manifest.build_id,
                &directory,
                clock.as_mut().ok_or("negative verified clock absent")?,
                &root,
                &manifest,
                goal,
                selected.disk.ok_or("negative disk absent")?,
            )
        } else if let Some(goal) = network_probe {
            crate::network_io::supervise(
                &mut command,
                &serial,
                &errors,
                Duration::from_secs(options.timeout_seconds),
                &manifest.build_id,
                &directory,
                clock
                    .as_mut()
                    .ok_or("network probe requires verified clock")?,
                &root,
                &manifest,
                goal,
            )
        } else if let Some(phase) = document_guide {
            crate::document_guide::supervise(
                &mut command,
                &serial,
                &errors,
                Duration::from_secs(options.timeout_seconds),
                &manifest.build_id,
                &directory,
                phase,
                storage
                    .as_ref()
                    .and_then(|s| s.disk)
                    .ok_or("document guide disk absent")?,
            )
        } else if let Some(phase) = document_interruption {
            crate::document_interruption::supervise(
                &mut command,
                &serial,
                &errors,
                Duration::from_secs(options.timeout_seconds),
                &manifest.build_id,
                &directory,
                phase,
                storage
                    .as_ref()
                    .and_then(|s| s.disk)
                    .ok_or("document interruption disk absent")?,
            )
        } else if let Some(phase) = document_phase {
            crate::document_io::supervise(
                &mut command,
                &serial,
                &errors,
                Duration::from_secs(options.timeout_seconds),
                &manifest.build_id,
                &directory,
                phase,
                storage
                    .as_ref()
                    .and_then(|s| s.disk)
                    .ok_or("document disk absent")?,
            )
        } else if session && session_phase.is_none() {
            supervised_session(
                &mut command,
                &[&serial, &errors],
                clock.as_mut().map(|clock| (clock, directory.as_path())),
            )
        } else if storage
            .as_ref()
            .is_some_and(|s| matches!(s.experiment, Experiment::IpcBench(_)))
        {
            supervised_ipc_bench(
                &mut command,
                &serial,
                &errors,
                Duration::from_secs(options.timeout_seconds),
                &manifest.build_id,
                &directory,
            )
        } else if let Some(phase) = session_phase {
            crate::session_io::supervise(
                &mut command,
                &serial,
                &errors,
                Duration::from_secs(options.timeout_seconds),
                &manifest.build_id,
                &directory,
                phase,
                storage
                    .as_ref()
                    .and_then(|s| s.disk)
                    .ok_or("session requires its owned disk")?,
            )
        } else if let Some(port) = debug_port {
            crate::debug::run(
                &mut command,
                &kernel,
                &root,
                &directory,
                port,
                options.batch,
                manifest.fixture.as_deref() == Some("panic"),
                options.timeout_seconds,
            )
        } else if let Some(phase) = native3 {
            crate::native3_io::supervise(
                &mut command,
                &serial,
                &errors,
                Duration::from_secs(options.timeout_seconds),
                &manifest.build_id,
                &directory,
                phase,
                storage
                    .as_ref()
                    .and_then(|s| s.disk)
                    .ok_or("Native3 requires actual owned disk")?,
            )
        } else if let Some(phase) = native {
            crate::native_io::supervise(
                &mut command,
                &serial,
                &errors,
                Duration::from_secs(options.timeout_seconds),
                &manifest.build_id,
                &directory,
                phase,
            )
        } else if desktop {
            crate::desktop_io::supervise(
                &mut command,
                &serial,
                &errors,
                Duration::from_secs(options.timeout_seconds),
                &manifest.build_id,
                &directory,
            )
        } else if display {
            crate::graphics_io::supervise(
                &mut command,
                &serial,
                &errors,
                Duration::from_secs(options.timeout_seconds),
                &manifest.build_id,
                &directory,
            )
        } else if let Some(input) = owner_input {
            let attachment = owner_attachment.ok_or("missing owner input attachment")?;
            crate::owner_io::supervise(&mut command,&serial,&errors,Duration::from_secs(options.timeout_seconds),
                &manifest.build_id,attachment.catalogue,input).and_then(|outcome|{
                    owner_eof=outcome.eof_no_action;
                    attachment.eof.set(owner_eof);
                    crate::storage::json_new(&directory.join("owner-input.json"),&json!({
                        "schema":1,"source":if matches!(input,crate::owner_io::Input::Owner){"interactive-owner"}else{"explicit-test-input"},
                        "eof_no_action":owner_eof,"written":outcome.written,"validated_prompt":outcome.validated_prompt,
                    }))?;
                    Ok(outcome.status)
                })
        } else if let Some(control) = cut {
            let mut stop = || {
                let mut bytes = Vec::new();
                File::open(&serial)
                    .map_err(|error| error.to_string())?
                    .take(OUTPUT_LIMIT + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|error| error.to_string())?;
                if bytes.len() as u64 > OUTPUT_LIMIT {
                    return Err("interrupted serial exceeded output limit".into());
                }
                if bytes.last() != Some(&b'\n')
                    || !String::from_utf8_lossy(&bytes)
                        .lines()
                        .any(|line| line.starts_with("EVROSION_M3_STORE_CUT "))
                {
                    return Ok(false);
                }
                boot_protocol::check_store_cut_prefix(&bytes, &manifest.build_id, control.cut)?;
                Ok(true)
            };
            supervised_until(
                &mut command,
                &[&serial, &errors],
                Duration::from_secs(options.timeout_seconds),
                Some(&mut stop),
            )
        } else {
            supervised(
                &mut command,
                &[&serial, &errors],
                Duration::from_secs(options.timeout_seconds),
            )
        };
        let clock_postflight = clock
            .as_ref()
            .map(crate::vm_clock::Prepared::postflight)
            .transpose();
        let mut serial_bytes = Vec::new();
        File::open(&serial)
            .map_err(|error| error.to_string())?
            .take(OUTPUT_LIMIT + 1)
            .read_to_end(&mut serial_bytes)
            .map_err(|error| error.to_string())?;
        let status = result.as_ref().ok().and_then(|status| status.code());
        #[cfg(unix)]
        let signal = {
            use std::os::unix::process::ExitStatusExt;
            result.as_ref().ok().and_then(|status| status.signal())
        };
        #[cfg(not(unix))]
        let signal: Option<i32> = None;
        let check = result.and_then(|actual| {
            clock_postflight?;
            if owner_eof {
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    if actual.signal() != Some(9) {
                        return Err("owner EOF did not stop and reap its retained child".into());
                    }
                }
                let owner = owner_attachment.ok_or("missing owner EOF context")?;
                if check_owner_prompt_prefix(&serial_bytes, &manifest.build_id, owner.catalogue)?
                    .is_none()
                {
                    return Err("owner EOF has no validated no-action prompt".into());
                }
                Ok(())
            } else if let Some(control) = cut {
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    if actual.signal() != Some(9) {
                        return Err(
                            "interruption did not kill the retained QEMU child with SIGKILL".into(),
                        );
                    }
                }
                boot_protocol::check_store_cut_prefix(
                    &serial_bytes,
                    &manifest.build_id,
                    control.cut,
                )
            } else if document_cut {
                crate::document_interruption::verify(
                    &serial_bytes,
                    &manifest.build_id,
                    crate::document_interruption::Phase::Cut,
                    actual,
                )
            } else if manifest.fixture.as_deref() == Some("panic") {
                boot_protocol::check_panic(&serial_bytes, &manifest.build_id, status)
            } else {
                if let Some(goal) = negative {
                    crate::network_negative::postflight(
                        &serial_bytes,
                        &manifest.build_id,
                        status,
                        goal,
                    )?;
                } else if matches!(
                    manifest.fixture.as_deref(),
                    Some(
                        "m6-session"
                            | "m7-document"
                            | "m7-document-session"
                            | "m7-document-network"
                            | "m7-document-system"
                            | "m7-document-recovery"
                            | "m6-network"
                            | "m6-network-negative"
                            | "m6-network-system"
                            | "m6-network-recovery"
                            | "m6-network-owner"
                            | "m6-network-system-owner"
                            | "m6-network-recovery-owner"
                    )
                ) {
                    let document_serial;
                    let serial_bytes = if matches!(
                        manifest.fixture.as_deref(),
                        Some(
                            "m7-document"
                                | "m7-document-session"
                                | "m7-document-network"
                                | "m7-document-system"
                                | "m7-document-recovery"
                        )
                    ) {
                        document_serial = crate::document_io::without_observations(
                            &serial_bytes,
                            &manifest.build_id,
                        )?;
                        &document_serial
                    } else {
                        &serial_bytes
                    };
                    let protocol_bytes = if network {
                        crate::session_protocol::without_network_diagnostics(
                            serial_bytes,
                            &manifest.build_id,
                        )?
                    } else {
                        crate::session_protocol::without_diagnostics(
                            serial_bytes,
                            &manifest.build_id,
                        )?
                    };
                    if network {
                        check_network_fixture(
                            manifest.fixture.as_deref(),
                            &protocol_bytes,
                            &manifest.build_id,
                            status,
                        )?;
                    } else if storage.as_ref().is_some_and(|s| {
                        matches!(
                            s.experiment,
                            Experiment::Document(Some(crate::document_io::Phase::Crash))
                        )
                    }) {
                        let proof = crate::document_crash::Proof::complete(
                            &protocol_bytes,
                            &manifest.build_id,
                        )?;
                        boot_protocol::check_document_crash(
                            &protocol_bytes,
                            &manifest.build_id,
                            status,
                            &proof,
                        )?;
                    } else {
                        boot_protocol::check_session(&protocol_bytes, &manifest.build_id, status)?;
                    }
                } else {
                    boot_protocol::check(&serial_bytes, &manifest.build_id, status)?;
                }
                if let Some(selection) = &storage {
                    match selection.experiment {
                        Experiment::Store(control) => {
                            boot_protocol::check_store_record(&serial_bytes, control)?
                        }
                        Experiment::Generation(control, _) => {
                            let record = boot_protocol::generation_record(&serial_bytes)?;
                            if record.mode != control.mode {
                                return Err("generation proof reports wrong phase".into());
                            }
                        }
                        Experiment::File(control) => {
                            let record = crate::file_protocol::record(&serial_bytes)?;
                            if record.report.mode != control.mode {
                                return Err("File/Object proof reports the wrong phase".into());
                            }
                        }
                        Experiment::Owner(control) => {
                            let record = crate::owner_protocol::record(&serial_bytes)?;
                            crate::owner_protocol::budget(&serial_bytes)?;
                            if record.report.mode != control.mode {
                                return Err("owner proof has the wrong phase".into());
                            }
                        }
                        Experiment::Display => {
                            crate::graphics_protocol::record(&serial_bytes)?;
                            crate::graphics_protocol::present(&serial_bytes, &manifest.build_id)?
                                .ok_or("display proof has no Present record")?;
                        }
                        Experiment::Desktop => {
                            crate::desktop_protocol::record(&serial_bytes, &manifest.build_id)?;
                        }
                        Experiment::Native(_) => {
                            crate::native_protocol::record(&serial_bytes, &manifest.build_id)?;
                        }
                        Experiment::Acquisition(_)
                        | Experiment::Network(_)
                        | Experiment::OwnerNetwork(_)
                        | Experiment::OwnerUiProbe(_, _)
                        | Experiment::SystemHealth(_) => {
                            record_network_fixture(
                                manifest.fixture.as_deref(),
                                &serial_bytes,
                                &manifest.build_id,
                            )?;
                        }
                        Experiment::Negative(_) => {}
                        Experiment::Compatibility(_) => {
                            let clean = crate::document_io::without_observations(
                                &serial_bytes,
                                &manifest.build_id,
                            )?;
                            crate::native_protocol::record_network(&clean, &manifest.build_id)?;
                            crate::session_protocol::retention(&serial_bytes, &manifest.build_id)?;
                        }
                        Experiment::DocumentAcquisition(_) | Experiment::DocumentUpdate(_) => {
                            let clean = crate::document_io::without_observations(
                                &serial_bytes,
                                &manifest.build_id,
                            )?;
                            record_network_fixture(
                                manifest.fixture.as_deref(),
                                &clean,
                                &manifest.build_id,
                            )?;
                            if network_recovery_fixture(manifest.fixture.as_deref()) {
                                crate::session_protocol::retention_network_recovery(
                                    &serial_bytes,
                                    &manifest.build_id,
                                )?;
                            } else {
                                crate::session_protocol::retention(
                                    &serial_bytes,
                                    &manifest.build_id,
                                )?;
                            }
                        }
                        Experiment::Document(Some(crate::document_io::Phase::Crash)) => {
                            let clean = crate::document_io::without_observations(
                                &serial_bytes,
                                &manifest.build_id,
                            )?;
                            let proof =
                                crate::document_crash::Proof::complete(&clean, &manifest.build_id)?;
                            crate::native_protocol::record_document_crash(
                                &clean,
                                &manifest.build_id,
                                &proof,
                            )?;
                        }
                        Experiment::Document(_) | Experiment::DocumentGuide(_) => {
                            let clean = crate::document_io::without_observations(
                                &serial_bytes,
                                &manifest.build_id,
                            )?;
                            crate::native_protocol::record_session(&clean, &manifest.build_id)?;
                        }
                        Experiment::DocumentInterruption(phase) => {
                            // Cut already took its dedicated validated SIGKILL
                            // branch. Every Cold run reaches all ordinary checks
                            // above and this exact document/Presents verifier.
                            if phase != crate::document_interruption::Phase::Cold {
                                return Err("document Cut reached ordinary completion path".into());
                            }
                            crate::document_interruption::verify(
                                &serial_bytes,
                                &manifest.build_id,
                                phase,
                                actual,
                            )?;
                            let clean = crate::document_io::without_observations(
                                &serial_bytes,
                                &manifest.build_id,
                            )?;
                            crate::native_protocol::record_session(&clean, &manifest.build_id)?;
                        }
                        Experiment::Session(_) => {
                            crate::native_protocol::record_session(
                                &serial_bytes,
                                &manifest.build_id,
                            )?;
                        }
                        Experiment::Native3(phase) => {
                            crate::native3_protocol::record(
                                &serial_bytes,
                                &manifest.build_id,
                                phase.recovery(),
                            )?;
                        }
                        Experiment::IpcBench(images) => {
                            crate::ipc_bench_protocol::record(
                                &serial_bytes,
                                &manifest.build_id,
                                images,
                            )?;
                        }
                        Experiment::Provider(images) => {
                            crate::provider_protocol::record(
                                &serial_bytes,
                                &manifest.build_id,
                                images,
                            )?;
                        }
                        Experiment::Pio(phase) => {
                            let record = boot_protocol::storage_record(&serial_bytes)?;
                            if record.phase != phase {
                                return Err("storage record reports the wrong phase".into());
                            }
                            let shared = boot_protocol::shared_storage_record(&serial_bytes)?;
                            if shared.phase != phase {
                                return Err("shared storage record reports the wrong phase".into());
                            }
                        }
                    }
                }
                if manifest.fixture.as_deref() == Some("no-framebuffer")
                    && !String::from_utf8_lossy(&serial_bytes).contains(
                        "EVROSION_FRAMEBUFFER present=false width=0 height=0 stride=0 format=none",
                    )
                {
                    return Err("serial-only fixture did not report an absent framebuffer".into());
                }
                Ok(())
            }
        });
        // Preserve firmware chatter in the raw log; show the kernel report in the terminal.
        let serial_text = String::from_utf8_lossy(&serial_bytes);
        if !matches!(owner_input, Some(crate::owner_io::Input::Owner))
            && let Some(offset) = serial_text.find("EVROSION_BOOT ")
        {
            print!("{}", &serial_text[offset..]);
        }
        let reason = check.as_ref().err().cloned();
        runs.push(
            json!({"run":index,"passed":check.is_ok(),"error":reason,"exit_status":status,
            "exit_signal":signal,"interruption_expected":cut.is_some()||owner_eof||document_cut,"expected_cut":cut.map(|c|c.cut),"document_interruption_phase":document_interruption,"owner_eof_no_action":owner_eof,
            "elapsed_ms":start.elapsed().as_millis(),"serial_sha256":build::hash_file(&serial)?,
            "qemu_stderr_sha256":build::hash_file(&errors)?,"directory":format!("run-{index:03}")}),
        );
        build::write_json(
            &directory.join("result.json"),
            runs.last().ok_or("missing run record")?,
        )?;
        if let Err(error) = check {
            failure = Some(error);
            break;
        }
    }
    if build::hash_file(&code)? != code_hash
        || build::hash_file(&vars_template)? != vars_hash
        || build::hash_file(&image)? != manifest.image.sha256
        || build::hash_file(&qemu)? != qemu_hash
    {
        failure = Some("a supposedly read-only boot input changed".into());
    }
    build::write_json(
        &evidence.join("results.json"),
        &json!({"schema":1,"kind":kind,"build_id":manifest.build_id,
        "passed":failure.is_none(),"requested_runs":options.runs,"runs":runs,"error":failure,
        "qemu":qemu,"qemu_sha256":qemu_hash,"ovmf_code":code,"ovmf_code_sha256":code_hash,
        "ovmf_vars_template":vars_template,"ovmf_vars_sha256":vars_hash,"acceleration":"tcg",
        "timeout_seconds":options.timeout_seconds,"cpus":options.cpus}),
    )?;
    println!("Evidence: {}", evidence.display());
    if let Some(error) = failure {
        return Err(error);
    }
    if storage
        .as_ref()
        .and_then(|selection| selection.owner.as_ref())
        .is_some_and(|owner| owner.eof.get())
    {
        println!(
            "PASS owner EOF: validated prompt, no approved action, owned child killed and reaped."
        );
    } else if cut.is_some() {
        println!("PASS store-cut: actual process fault, validated prefix and abrupt VM kill/reap.");
    } else if document_cut {
        println!(
            "PASS document-interruption-cut: actual paused Saving scanout; owned QEMU SIGKILL and reap."
        );
    } else {
        println!(
            "PASS {kind}: {}/{} fresh TCG boots; protocol and QEMU status verified.",
            runs.len(),
            options.runs
        );
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod ipc_host_watcher_tests {
    use super::*;
    // This exercises only host-child ownership with a controlled shell writer.
    // It is not guest execution, functional RPC evidence or a benchmark sample.
    #[test]
    fn malformed_log_and_deadline_kill_reap_owned_writer_and_retain_failure() {
        for malformed in [false, true] {
            let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .canonicalize()
                .unwrap();
            let parent =
                crate::storage::directory_beneath(&root, Path::new("build/test-tmp")).unwrap();
            let directory = build::unique_directory(&parent, "ipc-host-watcher-tests").unwrap();
            let serial = directory.join("serial.log");
            let errors = directory.join("stderr.log");
            let pid = directory.join("pid");
            File::create(&serial).unwrap();
            File::create(&errors).unwrap();
            let script = if malformed {
                "printf '%s' \"$$\" > \"$1\"; printf 'EVROSION_M5_IPC_BATCH malformed\\n' >> \"$2\"; exec sleep 60"
            } else {
                "printf '%s' \"$$\" > \"$1\"; exec sleep 60"
            };
            let mut command = Command::new("sh");
            command
                .args(["-c", script, "owned-ipc-writer"])
                .arg(&pid)
                .arg(&serial)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let result = supervised_ipc_bench(
                &mut command,
                &serial,
                &errors,
                Duration::from_millis(200),
                &"d".repeat(64),
                &directory,
            );
            assert!(result.is_err());
            let actual_pid: u32 = fs::read_to_string(pid).unwrap().parse().unwrap();
            assert!(
                !Path::new("/proc").join(actual_pid.to_string()).exists(),
                "owned writer survived error"
            );
            let record: serde_json::Value =
                serde_json::from_slice(&fs::read(directory.join("ipc-host-timing.json")).unwrap())
                    .unwrap();
            assert_eq!(record["quantitative_accepted"], false);
            assert!(record["execution_error"].is_string());
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod qmp_placement_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn dedicated_document_fixtures_do_not_change_legacy_profile_selection() {
        for phase in [
            crate::acquisition_io::Phase::Online,
            crate::acquisition_io::Phase::Cold,
        ] {
            assert_eq!(Experiment::Acquisition(phase).fixture(), "m6-network");
            assert_eq!(
                Experiment::DocumentAcquisition(phase).fixture(),
                "m7-document-network"
            );
        }
        for (phase, old, document) in [
            (
                crate::system_health_io::Phase::SelectB,
                "m6-network",
                "m7-document-network",
            ),
            (
                crate::system_health_io::Phase::HealthyAndStageC,
                "m6-network-system",
                "m7-document-system",
            ),
            (
                crate::system_health_io::Phase::FaultC,
                "m6-network-system",
                "m7-document-system",
            ),
            (
                crate::system_health_io::Phase::Recovery,
                "m6-network-recovery",
                "m7-document-recovery",
            ),
            (
                crate::system_health_io::Phase::FinalB,
                "m6-network-system",
                "m7-document-system",
            ),
        ] {
            assert_eq!(Experiment::SystemHealth(phase).fixture(), old);
            assert_eq!(Experiment::DocumentUpdate(phase).fixture(), document);
        }
        for phase in [
            crate::document_interruption::Phase::Cut,
            crate::document_interruption::Phase::Cold,
        ] {
            assert_eq!(
                Experiment::DocumentInterruption(phase).fixture(),
                "m7-document"
            );
        }
        assert!(network_recovery_fixture(Some("m7-document-recovery")));
        assert!(network_recovery_fixture(Some("m6-network-recovery")));
        assert!(network_recovery_fixture(Some("m6-network-recovery-owner")));
        for fixture in [
            None,
            Some("m7-document"),
            Some("m7-document-network"),
            Some("m7-document-system"),
            Some("m6-network-system"),
        ] {
            assert!(!network_recovery_fixture(fixture));
        }
    }

    #[test]
    fn only_explicit_retained_owner_document_and_guide_modes_move_the_server_cwd() {
        let root = Path::new("/private/source");
        let run = root.join("build/m6/evidence/phase, with space/boot/run-001");
        for mode in crate::network_mode::Mode::ALL {
            let (cwd, argument) =
                qmp_placement(root, &run, Some(Experiment::OwnerNetwork(mode))).unwrap();
            assert_eq!(cwd, run);
            assert_eq!(argument, "unix:qmp.sock,server=on,wait=off");
        }
        for experiment in [
            Experiment::Document(None),
            Experiment::DocumentInterruption(crate::document_interruption::Phase::Cut),
            Experiment::DocumentInterruption(crate::document_interruption::Phase::Cold),
            Experiment::DocumentGuide(crate::document_guide::Phase::Exercise),
            Experiment::DocumentGuide(crate::document_guide::Phase::Cold),
            Experiment::Compatibility(crate::document_compatibility::Phase::Exercise),
            Experiment::Compatibility(crate::document_compatibility::Phase::Cold),
            Experiment::DocumentAcquisition(crate::acquisition_io::Phase::Online),
            Experiment::DocumentAcquisition(crate::acquisition_io::Phase::Cold),
            Experiment::DocumentUpdate(crate::system_health_io::Phase::SelectB),
            Experiment::DocumentUpdate(crate::system_health_io::Phase::HealthyAndStageC),
            Experiment::DocumentUpdate(crate::system_health_io::Phase::FaultC),
            Experiment::DocumentUpdate(crate::system_health_io::Phase::Recovery),
            Experiment::DocumentUpdate(crate::system_health_io::Phase::FinalB),
        ] {
            let (cwd, argument) = qmp_placement(root, &run, Some(experiment)).unwrap();
            assert_eq!(cwd, run);
            assert_eq!(argument, "unix:qmp.sock,server=on,wait=off");
        }
        for experiment in [
            None,
            Some(Experiment::Display),
            Some(Experiment::Desktop),
            Some(Experiment::Native(crate::native_io::Phase::InstallFull)),
            Some(Experiment::Native3(crate::native3_io::Phase::SystemFull)),
            Some(Experiment::Session(None)),
            Some(Experiment::Document(Some(
                crate::document_io::Phase::Exercise,
            ))),
            Some(Experiment::Network(None)),
            Some(Experiment::Acquisition(
                crate::acquisition_io::Phase::Online,
            )),
            Some(Experiment::SystemHealth(
                crate::system_health_io::Phase::FaultC,
            )),
            Some(Experiment::OwnerUiProbe(
                crate::network_mode::Mode::Standalone,
                crate::owner_ui_io::Phase::Exercise,
            )),
        ] {
            let (cwd, argument) = qmp_placement(root, &run, experiment).unwrap();
            assert_eq!(cwd, root);
            assert_eq!(
                argument,
                "unix:build/m6/evidence/phase,, with space/boot/run-001/qmp.sock,server=on,wait=off"
            );
        }
        for experiment in [
            None,
            Some(Experiment::DocumentInterruption(
                crate::document_interruption::Phase::Cut,
            )),
            Some(Experiment::DocumentAcquisition(
                crate::acquisition_io::Phase::Online,
            )),
            Some(Experiment::DocumentUpdate(
                crate::system_health_io::Phase::Recovery,
            )),
            Some(Experiment::OwnerNetwork(
                crate::network_mode::Mode::Standalone,
            )),
        ] {
            assert!(qmp_placement(root, Path::new("/foreign/run-001"), experiment).is_err());
        }
    }

    #[test]
    fn child_binds_private_socket_beyond_long_pid_and_absolute_path_limits() {
        let original_cwd = std::env::current_dir().unwrap();
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let parent = crate::storage::directory_beneath(&root, Path::new("build/test-tmp")).unwrap();
        let evidence = build::unique_directory(&parent, "qmp-placement-tests").unwrap();
        // Max-width u32 PID and a real-width timestamp make the old relative
        // server path too long even without this component's long root path.
        let run = evidence.join("network-session-4294967295-1794632158011131269/vm-4294967295-1794632158011131269/boot/run-001");
        fs::create_dir_all(&run).unwrap();
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            fs::symlink_metadata(&run).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(
            run.strip_prefix(&root)
                .unwrap()
                .join("qmp.sock")
                .as_os_str()
                .len()
                >= 108
        );
        assert!(run.join("qmp.sock").as_os_str().len() >= 108);
        let (cwd, argument) = qmp_placement(
            &root,
            &run,
            Some(Experiment::OwnerNetwork(
                crate::network_mode::Mode::Standalone,
            )),
        )
        .unwrap();
        let recorded = json!({"cwd":cwd,"qmp":argument});
        let mut command = Command::new("python3");
        command
            .current_dir(&cwd)
            .args([
                "-I",
                "-c",
                r#"
import json,socket
s=socket.socket(socket.AF_UNIX)
s.settimeout(3)
s.bind('qmp.sock')
s.listen(1)
c,_=s.accept()
c.settimeout(2)
c.sendall(b'{"QMP":{}}\n')
r=json.loads(c.makefile('rb').readline(1024))
assert r == {'execute':'qmp_capabilities','arguments':{},'id':1}
c.sendall(b'{"return":{},"id":1}\n')
c.close()
s.close()
"#,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        assert_eq!(
            command.get_current_dir(),
            Some(Path::new(recorded["cwd"].as_str().unwrap()))
        );
        assert_eq!(recorded["qmp"], "unix:qmp.sock,server=on,wait=off");
        let mut child = ChildGuard(command.spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(2);
        while !run.join("qmp.sock").exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "socket child exited before bind"
            );
            assert!(Instant::now() < deadline, "private socket bind deadline");
            thread::sleep(Duration::from_millis(10));
        }
        let qmp = crate::qmp::Qmp::connect(&run, deadline).unwrap();
        drop(qmp);
        assert!(child.0.wait().unwrap().success());
        assert_eq!(std::env::current_dir().unwrap(), original_cwd);
    }
}
