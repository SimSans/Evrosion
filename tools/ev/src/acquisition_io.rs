//! Actual owned acquisition experiment. Host authoring is untrusted transport;
//! candidate trust, selection, execution and retirement require separate joins.
use crate::{
    boot::ChildGuard,
    build::{self, Manifest, Result},
    desktop_protocol::{Producer, Step, StepKind},
    download_fixture::{self, Author, Authority, Bundle, FixturePhase, Server},
    network_io::components::Context,
    qmp::{Key, Qmp},
    session_io::ProbeUi,
    session_reference::Reference,
    storage,
};
use ev_graphics::{
    native::Build,
    session::{Focus, SaveState, View},
    shell::Screen,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(crate) const TIMEOUT_SECONDS: u64 = 600;
pub(crate) const NOTE: &str = "M6 keep42";
const LOG_LIMIT: u64 = 1024 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum Phase {
    Online,
    Cold,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Plan {
    pub schema: u16,
    pub source_sha256: String,
    pub build_id: String,
    pub bundle_directory: PathBuf,
    pub authority_workspace: PathBuf,
    pub public_root_sha256: String,
    pub downloaded_elf_sha256: String,
    pub downloaded_package_sha256: String,
}
pub(crate) fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(crate) fn bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() > limit {
        return Err("acquisition input must be bounded regular bytes".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("acquisition input grew beyond bound".into());
    }
    Ok(bytes)
}
pub(crate) fn authority(root: &Path, signer: &Path) -> Result<Authority> {
    // Independently pinned candidate public Root is compared BEFORE any signing.
    let expected = bounded(&root.join(crate::development_release::ROOT_FILE), 8192)?;
    let authority = Authority::load(signer)?;
    if expected != authority.root() {
        return Err("explicit signer public Root differs from candidate pin".into());
    }
    Ok(authority)
}
pub(crate) fn complete(bytes: &[u8]) -> &[u8] {
    bytes
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(&[], |at| &bytes[..=at])
}
impl Plan {
    pub(crate) fn load(
        root: &Path,
        directory: &Path,
        manifest: &Manifest,
    ) -> Result<(Self, Bundle)> {
        let plan: Self =
            serde_json::from_slice(&bounded(&directory.join("acquisition-plan.json"), 65536)?)
                .map_err(|e| e.to_string())?;
        if plan.schema != 1
            || plan.build_id != manifest.build_id
            || plan.source_sha256 != manifest.source_sha256
        {
            return Err("acquisition plan source/build mismatch".into());
        }
        let base = root.join("build/m6/downloads");
        let relative = plan
            .bundle_directory
            .strip_prefix(&base)
            .map_err(|_| "acquisition bundle outside owned producer area")?;
        if relative.components().count() != 1
            || !matches!(
                relative.components().next(),
                Some(std::path::Component::Normal(_))
            )
            || fs::canonicalize(&plan.bundle_directory).map_err(|e| e.to_string())?
                != plan.bundle_directory
        {
            return Err("acquisition bundle path is not exact owned child".into());
        }
        let bundle = download_fixture::load_bundle(&plan.bundle_directory)?;
        let b = &bundle.downloads[0];
        if bundle.compiled_into_kernel
            || bundle.source_sha256 != manifest.source_sha256
            || hash(&bounded(&b.package, 262144)?) != plan.downloaded_package_sha256
            || hash(&bounded(&b.component.image, 1024 * 1024)?) != plan.downloaded_elf_sha256
            || hex(&b.package_id) != plan.downloaded_package_sha256
            || hex(&b.component.image_sha256) != plan.downloaded_elf_sha256
            || hash(&bounded(
                &root.join(crate::development_release::ROOT_FILE),
                8192,
            )?) != plan.public_root_sha256
        {
            return Err("actual separately produced B differs from acquisition plan".into());
        }
        Ok((plan, bundle))
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(crate) fn absent_from_banks(context: &Context, bundle: &Bundle) -> Result<()> {
    let banks = context.packages()?;
    let b = &bundle.downloads[0];
    for slot in [
        ev_root_supervisor::native_plan::Slot::A,
        ev_root_supervisor::native_plan::Slot::B,
    ] {
        let executable = banks
            .checked(slot)
            .map_err(|e| format!("retained bank package: {e:?}"))?
            .executable()
            .bytes;
        if b.package_id == banks.digest(slot) || hex(&b.component.image_sha256) == hash(executable)
        {
            return Err("downloaded B aliases an actually retained compiled bank".into());
        }
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
enum Stage {
    Ready,
    Installed,
    StartedA,
    Typing(usize),
    FocusSave,
    Saved,
    Initialized,
    Fetched,
    StartedB,
    ColdHome,
    ColdB,
    Finished,
}
struct At {
    step: Step,
    line: usize,
}
fn steps(bytes: &[u8], build: &str) -> Result<Vec<At>> {
    let mut out = Vec::new();
    for (line, raw) in std::str::from_utf8(complete(bytes))
        .map_err(|_| "acquisition serial UTF8")?
        .lines()
        .enumerate()
    {
        if raw.starts_with("EVROSION_M4_DESKTOP_EXIT ") {
            return Err(format!("acquisition actor exited unexpectedly: {raw}"));
        }
        if raw.starts_with("EVROSION_M4_DESKTOP_STEP ") {
            out.push(At {
                step: crate::desktop_protocol::step_line(raw, build)?,
                line,
            });
        }
    }
    if out.len() > 256 {
        return Err("acquisition protected frame bound exceeded".into());
    }
    Ok(out)
}
fn reply<'a>(
    rows: &'a [crate::native_protocol::StateRecord],
    op: &str,
    n: usize,
) -> Result<Option<&'a crate::native_protocol::StateRecord>> {
    let found: Vec<_> = rows
        .iter()
        .filter(|r| r.fields.get("op").is_some_and(|v| v == op))
        .collect();
    if found.len() > n {
        return Err(format!("acquisition command {op} replay"));
    }
    if let Some(row) = found.get(n - 1) {
        if !row.is(op) || row.number("recovery")? != 0 {
            return Err(format!("actual acquisition command {op} refused/recovery"));
        }
        Ok(Some(*row))
    } else {
        Ok(None)
    }
}
fn field(row: &crate::native_protocol::StateRecord, name: &str, value: &str) -> bool {
    row.fields.get(name).is_some_and(|v| v == value)
}
pub(crate) struct State {
    stage: Stage,
    inputs: Vec<Value>,
    pub(crate) captures: Vec<Value>,
    capture: u32,
    first_app: Option<u64>,
    downloaded_app: Option<u64>,
    pub(crate) min_frame: u64,
    finish_sent: bool,
    published: bool,
}
impl State {
    pub(crate) fn new(phase: Phase) -> Self {
        Self {
            stage: if phase == Phase::Online {
                Stage::Ready
            } else {
                Stage::ColdHome
            },
            inputs: Vec::new(),
            captures: Vec::new(),
            capture: 0,
            first_app: None,
            downloaded_app: None,
            min_frame: 0,
            finish_sent: false,
            published: false,
        }
    }
    fn send(
        &mut self,
        input: &mut impl Write,
        bytes: &'static [u8],
        origin: Instant,
    ) -> Result<()> {
        let before = crate::perf_ledger::elapsed_ns(origin, Instant::now())
            .map_err(|e| format!("acquisition host clock: {e:?}"))?;
        input
            .write_all(bytes)
            .and_then(|()| input.flush())
            .map_err(|e| e.to_string())?;
        self.inputs.push(json!({"device":"owned QEMU owner UART","bytes":std::str::from_utf8(bytes).unwrap(),"host_bracket_ns":[before,crate::perf_ledger::elapsed_ns(origin,Instant::now()).map_err(|e|format!("acquisition host clock: {e:?}"))?],"scripted_input":true,"human_consent_claim":false}));
        if bytes == b"finish\n" {
            self.finish_sent = true;
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)] // One actual protected frame/scanout boundary.
    pub(crate) fn view(
        &mut self,
        serial: &[u8],
        build: &str,
        qmp: &mut Qmp,
        _directory: &Path,
        view: Option<View<'_>>,
        expected_app: Option<u64>,
    ) -> Result<Option<(Step, ProbeUi)>> {
        let ui = ProbeUi::parse(serial, build)?;
        let steps = steps(serial, build)?;
        let producer = if view.is_some() {
            Producer::App
        } else {
            Producer::Shell
        };
        let Some(at) = steps
            .iter()
            .rev()
            .find(|at| at.step.producer == producer && at.step.kind == StepKind::Frame)
        else {
            return Ok(None);
        };
        let s = &at.step;
        if s.frame <= self.min_frame
            || s.grants != 0
            || expected_app.is_some_and(|p| p != s.app_process)
        {
            return Ok(None);
        }
        let reference = Reference::new(
            if view.is_some() {
                Screen::AppRunning
            } else {
                Screen::Home
            },
            view,
            ui.cursor(),
        )?;
        if reference.surface_hash(producer, s.frame)? != s.surface_sha256 {
            return Ok(None);
        }
        let shell = steps
            .iter()
            .rev()
            .find(|at| at.step.producer == Producer::Shell && at.step.kind == StepKind::Frame);
        if producer == Producer::App {
            let Some(shell) = shell else {
                return Ok(None);
            };
            if !reference.fresh_app_ready(s, at.line, &shell.step, shell.line, &ui)? {
                return Ok(None);
            }
        } else if !ui.ready(s.shell_process, s.frame, at.line) {
            return Ok(None);
        }
        self.capture += 1;
        if self.capture > 80 {
            return Err("acquisition actual scanout capture bound80 exceeded".into());
        }
        qmp.set_running(false)?;
        let captured = qmp.capture(self.capture);
        qmp.set_running(true)?;
        let (path, ppm) = captured?;
        if ppm.dimensions() != (s.width, s.height) {
            return Err("acquisition scanout/Present geometry differs".into());
        }
        let valid = reference.validate(&ppm);
        self.captures.push(json!({"stage":self.stage,"step":s,"path":path.file_name(),"sha256":build::hash_file(&path)?,"validation":valid.as_ref().ok(),"error":valid.as_ref().err()}));
        valid?; // A genuine fresh-frame pixel mismatch is a failure, never a blind retry.
        Ok(Some((s.clone(), ui)))
    }
}

pub(crate) fn identities(context: &Context, serial: &[u8], build: &str) -> Result<bool> {
    identities_mode(
        context,
        serial,
        build,
        crate::network_mode::Mode::Standalone,
    )
}
/// Exact selected-mode variant for dedicated owner cold qualification. The
/// ordinary acquisition wrapper above remains strictly Standalone.
pub(crate) fn identities_mode(
    context: &Context,
    serial: &[u8],
    build: &str,
    mode: crate::network_mode::Mode,
) -> Result<bool> {
    let mut common = None;
    let mut shell = None;
    for line in std::str::from_utf8(complete(serial))
        .map_err(|_| "acquisition serial UTF8")?
        .lines()
    {
        if line.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX ") {
            let crate::native3_protocol::Event::Common(c) =
                crate::native3_protocol::event_network(line, build)?
            else {
                unreachable!()
            };
            if common.is_some()
                || c.mode != mode.boot_mode() as u64
                || c.root_image != context.images[0]
                || c.root_manifest != context.root_manifest
                || c.block_image != context.images[4]
                || c.root_frames != context.root_frames
                || c.block_frames != context.block_frames
            {
                return Err("acquisition actual Root/Block differs from retained source".into());
            }
            common = Some(c);
        }
        if line.starts_with("EVROSION_M5_NATIVE_CRITICAL_READY ") {
            let crate::native3_protocol::Event::Critical(c) =
                crate::native3_protocol::event_network(line, build)?
            else {
                unreachable!()
            };
            if shell.is_some() || c.image != context.images[1] {
                return Err("acquisition actual Shell image/replay".into());
            }
            shell = Some(c);
        }
    }
    Ok(common.is_some() && shell.is_some())
}
pub(crate) fn tap(qmp: &mut Qmp, key: Key) -> Result<()> {
    qmp.key_state(key, true)?;
    qmp.key_state(key, false)
}
pub(crate) fn view(build: Build, focus: Focus, note: &[u8], state: SaveState) -> View<'_> {
    View {
        build,
        focus,
        note,
        state,
        file: None,
    }
}

#[allow(clippy::too_many_arguments)] // One owned VM and its explicit immutable experiment inputs.
pub(crate) fn supervise(
    command: &mut Command,
    serial: &Path,
    errors: &Path,
    timeout: Duration,
    build: &str,
    directory: &Path,
    clock: &mut crate::vm_clock::Prepared,
    root: &Path,
    manifest: &Manifest,
    phase: Phase,
    experiment: &Path,
    disk: &storage::Disk,
) -> Result<ExitStatus> {
    supervise_profile(
        command, serial, errors, timeout, build, directory, clock, root, manifest, phase,
        experiment, disk, false,
    )
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn supervise_document(
    command: &mut Command,
    serial: &Path,
    errors: &Path,
    timeout: Duration,
    build: &str,
    directory: &Path,
    clock: &mut crate::vm_clock::Prepared,
    root: &Path,
    manifest: &Manifest,
    phase: Phase,
    experiment: &Path,
    disk: &storage::Disk,
) -> Result<ExitStatus> {
    supervise_profile(
        command, serial, errors, timeout, build, directory, clock, root, manifest, phase,
        experiment, disk, true,
    )
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn supervise_profile(
    command: &mut Command,
    serial: &Path,
    errors: &Path,
    timeout: Duration,
    build: &str,
    directory: &Path,
    clock: &mut crate::vm_clock::Prepared,
    root: &Path,
    manifest: &Manifest,
    phase: Phase,
    experiment: &Path,
    disk: &storage::Disk,
    document: bool,
) -> Result<ExitStatus> {
    if timeout != Duration::from_secs(TIMEOUT_SECONDS) {
        return Err("acquisition requires original600s bound".into());
    }
    let (plan, bundle) = Plan::load(root, experiment, manifest)?;
    if bundle.document != document {
        return Err("acquisition explicit package profile differs".into());
    }
    let context = if document {
        Context::retain_document_mode(
            root,
            manifest,
            directory,
            crate::network_mode::Mode::Standalone,
        )?
    } else {
        Context::retain(root, manifest, directory)?
    };
    absent_from_banks(&context, &bundle)?;
    let fixture = if phase == Phase::Online {
        Some(Server::pending()?)
    } else {
        None
    };
    let authority = if phase == Phase::Online {
        Some(authority(root, &plan.authority_workspace)?)
    } else {
        None
    };
    let origin = Instant::now();
    let deadline = origin
        .checked_add(timeout)
        .ok_or("acquisition deadline overflow")?;
    let mut qmp = None;
    let mut state = State::new(phase);
    let mut document_observer = crate::document_update::Observer::new();
    let mut actual = None;
    let mut failure: Option<String> = None;
    let serial_path = serial;
    let result = (|| {
        let mut child = ChildGuard(
            command
                .stdin(Stdio::piped())
                .spawn()
                .map_err(|e| format!("owned acquisition QEMU spawn: {e}"))?,
        );
        if phase == Phase::Cold {
            clock.verify_and_start_acquisition_cold(&mut child.0, directory)?;
        } else {
            clock.verify_and_start(&mut child.0, directory)?;
        }
        qmp = Some(Qmp::connect_at(directory, deadline, origin)?);
        let qmp = qmp.as_mut().unwrap();
        let mut input = child
            .0
            .stdin
            .take()
            .ok_or("acquisition owner UART absent")?;
        loop {
            let bytes = bounded(serial, LOG_LIMIT)?;
            let _ = bounded(errors, LOG_LIMIT)?;
            let serial = complete(&bytes);
            if failure.is_none() {
                let progress = (|| {
                    if !identities(&context, serial, build)? {
                        return Ok(());
                    }
                    let rows = crate::native_protocol::states_network(serial, build)?;
                    let actions = crate::downloaded_protocol::records(serial, build, false)?;
                    if actions.iter().any(|a| {
                        a.slot != 1
                            || a.elf_sha256 != plan.downloaded_elf_sha256
                            || a.content_sha256 != plan.downloaded_package_sha256
                            || a.declared_package_id != plan.downloaded_package_sha256
                    }) {
                        return Err("acquisition actual downloaded identity differs from produced absent-bank B".into());
                    }
                    match state.stage {
                        Stage::Ready => {
                            let network = crate::network_protocol::records(serial, build)?;
                            if network.iter().any(|p| p.stage == 8 || p.result != 0) {
                                return Err("acquisition initial network failed".into());
                            }
                            if network.last().is_some_and(|p| p.stage == 6)
                                && crate::network_io::acquisition_hello(
                                    &fixture.as_ref().unwrap().actual_snapshot()?,
                                )?
                            {
                                state.send(&mut input, b"install a\n", origin)?;
                                state.stage = Stage::Installed;
                            }
                        }
                        Stage::Installed => {
                            if let Some(r) = reply(&rows, "install", 1)? {
                                if !field(r, "staged", "a") || r.number("revision")? != 1 {
                                    return Err("initial real install differs".into());
                                }
                                state.send(&mut input, b"activate\n", origin)?;
                                state.stage = Stage::StartedA;
                            }
                        }
                        Stage::StartedA => {
                            if let Some(r) = reply(&rows, "activate", 1)? {
                                if !field(r, "active", "a")
                                    || r.number("value")? != 1001
                                    || r.number("data_counter")? != 0
                                    || !field(r, "actual_image_sha256", &context.images[5])
                                {
                                    return Err("initial actual A/data differs".into());
                                }
                                let app = r.number("actual_process")?;
                                if let Some((s, ui)) = state.view(
                                    serial,
                                    build,
                                    qmp,
                                    directory,
                                    Some(view(Build::A, Focus::Note, b"", SaveState::Saved)),
                                    Some(app),
                                )? && ui.note_complete(app, 1, 1).is_some()
                                {
                                    state.first_app = Some(app);
                                    state.min_frame = s.frame;
                                    qmp.ascii(NOTE.as_bytes()[0])?;
                                    state.stage = Stage::Typing(1);
                                }
                            }
                        }
                        Stage::Typing(n) => {
                            if let Some((s, _)) = state.view(
                                serial,
                                build,
                                qmp,
                                directory,
                                Some(view(
                                    Build::A,
                                    Focus::Note,
                                    &NOTE.as_bytes()[..n],
                                    SaveState::Unsaved,
                                )),
                                state.first_app,
                            )? {
                                state.min_frame = s.frame;
                                if n < NOTE.len() {
                                    qmp.ascii(NOTE.as_bytes()[n])?;
                                    state.stage = Stage::Typing(n + 1);
                                } else {
                                    tap(qmp, Key::Tab)?;
                                    state.stage = Stage::FocusSave;
                                }
                            }
                        }
                        Stage::FocusSave => {
                            if let Some((s, _)) = state.view(
                                serial,
                                build,
                                qmp,
                                directory,
                                Some(view(
                                    Build::A,
                                    Focus::Save,
                                    NOTE.as_bytes(),
                                    SaveState::Unsaved,
                                )),
                                state.first_app,
                            )? {
                                state.min_frame = s.frame;
                                tap(qmp, Key::Enter)?;
                                state.stage = Stage::Saved;
                            }
                        }
                        Stage::Saved => {
                            if let Some((_, ui)) = state.view(
                                serial,
                                build,
                                qmp,
                                directory,
                                Some(view(
                                    Build::A,
                                    Focus::Save,
                                    NOTE.as_bytes(),
                                    SaveState::Saved,
                                )),
                                state.first_app,
                            )? && ui.note_complete(state.first_app.unwrap(), 2, 2).is_some()
                            {
                                qmp.set_running(false)?;
                                let captured = (|| {
                                    disk.capture(experiment, "setup-baseline.raw")?;
                                    let baseline = disk.bytes()?;
                                    let seed = bounded(
                                        &experiment.join("data-before.raw"),
                                        storage::DISK_BYTES as u64,
                                    )?;
                                    let proof = crate::network_io::acquisition_disk::setup(
                                        &seed,
                                        &baseline,
                                        &context.packages()?,
                                        crate::network_io::acquisition_disk::Saved {
                                            note: NOTE,
                                            note_counter: 1,
                                            value: 1001,
                                            data_counter: 0,
                                        },
                                    )?;
                                    storage::json_new(
                                        &experiment.join("setup-disk-audit.json"),
                                        &proof,
                                    )
                                })();
                                qmp.set_running(true)?;
                                captured?;
                                state.send(&mut input, b"update-init\n", origin)?;
                                state.stage = Stage::Initialized;
                            }
                        }
                        Stage::Initialized => {
                            if reply(&rows, "update-init", 1)?.is_some() {
                                let update = crate::update_protocol::records(serial, build)?;
                                if update.iter().any(|p| p.stage == 5) {
                                    return Err("actual update initialization failed".into());
                                }
                                if update.iter().any(|p| p.stage == 3 && p.progress == 7950) {
                                    let now = SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .map_err(|e| e.to_string())?
                                        .as_secs();
                                    let phase = download_fixture::sign_phase(
                                        root,
                                        &bundle,
                                        authority.as_ref().unwrap(),
                                        FixturePhase::B,
                                        Author {
                                            version: 1,
                                            not_before: now.saturating_sub(5),
                                            expires: now
                                                .checked_add(595)
                                                .ok_or("fixture author time overflow")?,
                                        },
                                        &experiment.join("phase-b"),
                                    )?;
                                    fixture.as_ref().unwrap().replace_phase(phase)?;
                                    state.published = true;
                                    state.send(&mut input, b"update-fetch\n", origin)?;
                                    state.stage = Stage::Fetched;
                                }
                            }
                        }
                        Stage::Fetched => {
                            if let Some(r) = reply(&rows, "update-fetch", 1)? {
                                if !field(r, "staged", "downloaded-b") || r.number("revision")? != 3
                                {
                                    return Err("fetch did not stage actual downloadedB".into());
                                }
                                state.send(&mut input, b"activate\n", origin)?;
                                state.min_frame = 0;
                                state.stage = Stage::StartedB;
                            }
                        }
                        Stage::StartedB | Stage::ColdB => {
                            if state.stage == Stage::StartedB {
                                if let Some(r) = reply(&rows, "activate", 2)? {
                                    if !field(r, "active", "downloaded-b")
                                        || r.number("revision")? != 4
                                    {
                                        return Err("actual B selection differs".into());
                                    }
                                } else {
                                    return Ok(());
                                }
                            }
                            if let Some(action) = actions.iter().find(|a| a.kind == "start") {
                                if state.first_app == Some(action.process) {
                                    return Err("downloadedB reused compiledA identity".into());
                                }
                                let ui = ProbeUi::parse(serial, build)?;
                                let shown = if document {
                                    ui.note_complete(action.process, 1, 1).is_some()
                                        && document_observer.closed(
                                            serial,
                                            build,
                                            qmp,
                                            action.process,
                                        )?
                                } else {
                                    state
                                        .view(
                                            serial,
                                            build,
                                            qmp,
                                            directory,
                                            Some(view(
                                                Build::B,
                                                Focus::Note,
                                                NOTE.as_bytes(),
                                                SaveState::Saved,
                                            )),
                                            Some(action.process),
                                        )?
                                        .is_some()
                                };
                                if shown && ui.note_complete(action.process, 1, 1).is_some() {
                                    state.downloaded_app = Some(action.process);
                                    state.send(&mut input, b"finish\n", origin)?;
                                    state.stage = Stage::Finished;
                                }
                            }
                        }
                        Stage::ColdHome => {
                            if state
                                .view(serial, build, qmp, directory, None, None)?
                                .is_some()
                            {
                                tap(qmp, Key::Enter)?;
                                state.stage = Stage::ColdB;
                                state.min_frame = 0;
                            }
                        }
                        Stage::Finished => (),
                    }
                    Ok(())
                })();
                if let Err(e) = progress {
                    failure = Some(e);
                }
            }
            if let Some(status) = child.0.try_wait().map_err(|e| e.to_string())? {
                if let Some(e) = &failure {
                    return Err(e.clone());
                }
                // The earlier loop snapshot can predate the final finish/exit.
                let bytes = bounded(serial_path, LOG_LIMIT)?;
                let _ = bounded(errors, LOG_LIMIT)?;
                actual = Some(finished(
                    &context,
                    &bytes,
                    build,
                    status,
                    phase,
                    &state,
                    &plan,
                    fixture.as_ref(),
                    experiment,
                    document,
                )?);
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "acquisition original600s deadline; {}",
                    failure
                        .as_deref()
                        .unwrap_or("required actual acquisition/retirement incomplete")
                ));
            }
            thread::sleep(Duration::from_millis(20));
        }
    })();
    storage::json_new(
        &directory.join("acquisition-qmp.json"),
        &json!({"transcript":qmp.as_ref().map(Qmp::transcript),"prelaunch_clock_transcript":"vm-clock/prelaunch-qmp.json","cold_link_down":phase==Phase::Cold}),
    )?;
    storage::json_new(
        &directory.join("acquisition-observer.json"),
        &json!({"schema":1,"phase":phase,"passed":result.is_ok(),"error":result.as_ref().err(),"diagnostic_failure":failure,"stage":state.stage,"inputs":state.inputs,"captures":state.captures,"document_captures":document_observer.captures,"document_profile":document,"fixture":fixture.as_ref().map(Server::snapshot).transpose().as_ref().ok(),"public_serving_provenance":fixture.as_ref().map(Server::provenance).transpose().as_ref().ok(),"actual":actual,"original_timeout_seconds":TIMEOUT_SECONDS,"scripted_input":true,"human_consent_claim":false,"guest_cleanup_verified":result.is_ok(),"whole_M6_acceptance":false}),
    )?;
    result
}

#[allow(clippy::too_many_arguments)] // Exact final source, transport, execution and ownership joins.
fn finished(
    context: &Context,
    serial: &[u8],
    build: &str,
    status: ExitStatus,
    phase: Phase,
    state: &State,
    plan: &Plan,
    fixture: Option<&Server>,
    experiment: &Path,
    document: bool,
) -> Result<Value> {
    if status.code() != Some(ev_test_protocol::QEMU_PASS_STATUS)
        || serial.last() != Some(&b'\n')
        || !state.finish_sent
        || state.stage != Stage::Finished
        || state.downloaded_app.is_none()
    {
        return Err("acquisition lacks actual finish/exit/selected B".into());
    }
    if !identities(context, serial, build)? {
        return Err("acquisition final source identities absent".into());
    }
    let network = crate::network_protocol::records(serial, build)?;
    if network
        .last()
        .is_none_or(|p| p.stage != 7 || p.result != 0 || p.argument != 2)
    {
        return Err("acquisition lacks actual cooperative NIC retirement".into());
    }
    let retention = crate::session_protocol::retention(serial, build)?;
    if retention.omitted != 0 {
        return Err("acquisition history omitted".into());
    }
    let document_serial;
    let serial = if document {
        document_serial = crate::document_io::without_observations(serial, build)?;
        document_serial.as_slice()
    } else {
        serial
    };
    let protocol = crate::session_protocol::without_network_diagnostics(serial, build)?;
    crate::boot_protocol::check_network(&protocol, build, status.code())?;
    let native = crate::native_protocol::record_network(serial, build)?;
    let counts = &native.counts;
    if counts["calls"] == 0
        || counts["calls"] != counts["replies"]
        || counts["faults"] != 0
        || counts["restarts"] != 0
        || counts["grants"] != 0
        || counts["readonly_rejections"] != 0
        || counts["app_b_starts"] != 0
        || counts["app_a_starts"] != if phase == Phase::Online { 1 } else { 0 }
        || counts["starts"] != if phase == Phase::Online { 10 } else { 9 }
        || counts["processes"] != counts["starts"]
        || native.actions.len() != if phase == Phase::Online { 3 } else { 0 }
        || native
            .actions
            .iter()
            .any(|a| a.image_sha256 != context.images[5] || Some(a.process) != state.first_app)
    {
        return Err("acquisition graph/calls/compiled bank accounting differs".into());
    }
    if native.downloaded_actions.len() != 3
        || native
            .downloaded_actions
            .iter()
            .zip(["start", "stop", "reap"])
            .any(|(a, k)| {
                a.kind != k
                    || a.slot != 1
                    || a.process != state.downloaded_app.unwrap()
                    || a.elf_sha256 != plan.downloaded_elf_sha256
                    || a.content_sha256 != plan.downloaded_package_sha256
                    || a.declared_package_id != plan.downloaded_package_sha256
            })
    {
        return Err("actual downloaded B lifecycle not complete/exact".into());
    }
    let profiles = crate::native_profile::finished_network(serial, build, 0, Some(0))?;
    let ui = ProbeUi::parse(serial, build)?.finish()?;
    let time = crate::time_protocol::records(serial, build)?;
    let proofs = crate::time_proof_protocol::records(serial, build)?;
    if !crate::tc_protocol::records(serial, build)?.is_empty() {
        return Err("acquisition observed an unsolicited explicit time-check".into());
    }
    if phase == Phase::Online {
        if !state.published {
            return Err("acquisition never published fresh B transport".into());
        }
        let time_lengths = validate_fixture(
            &fixture
                .ok_or("acquisition server absent")?
                .actual_snapshot()?,
            &experiment.join("phase-b"),
        )?;
        if proofs.len() != 4
            || proofs
                .iter()
                .zip([(1, 1), (2, time_lengths[0] as u64), (3, 11), (1, 2)])
                .any(|(p, (stage, arg))| p.stage != stage || p.result != 0 || p.argument != arg)
            || time
                .first()
                .is_none_or(|p| p.stage != 1 || p.result != 0 || p.elapsed_seconds != 0)
            || !time.iter().any(|p| p.stage == 2 && p.elapsed_seconds > 0)
            || time.iter().any(|p| p.stage == 3 || p.result != 0)
        {
            return Err(
                "acquisition lacks actual private proof phases/healthy elapsed source".into(),
            );
        }
    } else if fixture.is_some() {
        return Err("offline cold unexpectedly served a fixture".into());
    } else if !proofs.is_empty() {
        return Err("isolated cold unexpectedly attempted remote time proof".into());
    }
    Ok(
        json!({"native":native,"profiles":profiles,"network":network,"ui":ui,"time_proof":proofs,"elapsed_source":time,"retention":retention,"source_bound_execution":true,"complete_Kernel_retirement_receipt":true,"utc_trust_claim":"Guest acquisition verifier and durable state checked separately; Host author timestamps grant no trust."}),
    )
}
pub(crate) fn validate_fixture(
    snapshot: &crate::network_fixture::Snapshot,
    phase: &Path,
) -> Result<[usize; 2]> {
    if snapshot.omitted != 0
        || snapshot.observed != 7
        || snapshot.completed != 7
        || snapshot.exchanges.len() != 7
    {
        return Err("acquisition fixture exact seven-exchange ledger incomplete".into());
    }
    crate::network_io::hello_exchange(&snapshot.exchanges[0])?;
    let mut paths = std::collections::BTreeSet::new();
    let mut nonces = std::collections::BTreeSet::new();
    let mut time_lengths = Vec::new();
    for (index, e) in snapshot.exchanges[1..].iter().enumerate() {
        let (path, body) = exchange_body(e)?;
        expected_route(index, path)?;
        if let Some(nonce) = path.strip_prefix("/time/") {
            if nonce.len() != 64
                || !nonce
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || !nonces.insert(nonce.to_owned())
            {
                return Err("acquisition time nonce replay/shape".into());
            }
            let mut challenge = [0; 32];
            for (i, b) in challenge.iter_mut().enumerate() {
                *b = u8::from_str_radix(&nonce[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
            }
            if challenge == [0; 32] {
                return Err("acquisition public challenge is zero".into());
            }
            crate::network_fixture::time_corruption::verify_public_nonce(body, &challenge)?;
            time_lengths.push(body.len());
        } else {
            let file = match path {
                "/release/timestamp.bin" => "timestamp.bin",
                "/release/snapshot.bin" => "snapshot.bin",
                "/release/targets.bin" => "targets.bin",
                "/artifacts/hello.zion" => "hello.zion",
                _ => return Err("acquisition served an unrequested release route".into()),
            };
            if !paths.insert(path.to_owned()) || body != bounded(&phase.join(file), 262144)? {
                return Err("actual served release bytes differ or repeat".into());
            }
        }
    }
    if paths.len() != 4 || nonces.len() != 2 {
        return Err("acquisition lacks exact four objects and two fresh time exchanges".into());
    }
    time_lengths
        .try_into()
        .map_err(|_| "acquisition time response count".into())
}

fn expected_route(index: usize, path: &str) -> Result<()> {
    let valid = match index {
        0 => path == "/release/timestamp.bin",
        1 => path == "/release/snapshot.bin",
        2 => path == "/release/targets.bin",
        3 | 5 => path.starts_with("/time/"),
        4 => path == "/artifacts/hello.zion",
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(
            "acquisition transfer order differs from metadata preflight/artifact/final proof"
                .into(),
        )
    }
}
fn exchange_body(e: &crate::network_fixture::Exchange) -> Result<(&str, &[u8])> {
    if e.error.is_some() || e.mutation.is_some() {
        return Err("acquisition transport failed/mutated".into());
    }
    let suffix = " HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n";
    let path = std::str::from_utf8(&e.request)
        .map_err(|_| "acquisition HTTP request UTF8")?
        .strip_prefix("GET ")
        .and_then(|s| s.strip_suffix(suffix))
        .ok_or("acquisition HTTP request bytes differ")?;
    let end = e
        .response
        .windows(4)
        .position(|b| b == b"\r\n\r\n")
        .ok_or("acquisition response headers absent")?
        + 4;
    let body = &e.response[end..];
    let expected = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    if e.response[..end] != *expected.as_bytes() {
        return Err("acquisition response framing differs".into());
    }
    Ok((path, body))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn exchange(path: &str, body: &[u8]) -> crate::network_fixture::Exchange {
        crate::network_fixture::Exchange{request:format!("GET {path} HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n").into_bytes(),response:[format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes(),body].concat(),error:None,mutation:None}
    }
    #[test]
    fn actual_transport_shape_requires_exact_completed_body_not_count_or_status() {
        let good = exchange("/release/timestamp.bin", b"actual body");
        let (path, body) = exchange_body(&good).unwrap();
        assert_eq!(path, "/release/timestamp.bin");
        assert_eq!(body, b"actual body");
        let mut bad = good.clone();
        bad.response.pop();
        assert!(exchange_body(&bad).is_err());
        let mut bad = good.clone();
        bad.request.push(0);
        assert!(exchange_body(&bad).is_err());
        let mut bad = good.clone();
        bad.response.extend_from_slice(b"x");
        assert!(exchange_body(&bad).is_err());
        let mut bad = good;
        bad.error = Some("partial accepted write".into());
        assert!(exchange_body(&bad).is_err());
    }
    #[test]
    fn release_order_needs_metadata_before_first_proof_and_body_before_final_proof() {
        let route = [
            "/release/timestamp.bin",
            "/release/snapshot.bin",
            "/release/targets.bin",
            "/time/nonce1",
            "/artifacts/hello.zion",
            "/time/nonce2",
        ];
        for (index, path) in route.iter().enumerate() {
            expected_route(index, path).unwrap();
        }
        for (index, path) in [
            (0, "/release/root.bin"),
            (0, "/artifacts/hello.zion"),
            (3, "/artifacts/hello.zion"),
            (4, "/time/nonce"),
            (6, "/time/nonce"),
        ] {
            assert!(expected_route(index, path).is_err());
        }
        let missing = crate::network_fixture::Snapshot {
            observed: 7,
            completed: 7,
            omitted: 0,
            exchanges: vec![],
        };
        assert!(validate_fixture(&missing, Path::new("never read")).is_err());
    }
    #[test]
    fn signer_must_match_independent_candidate_root_before_any_fixture_is_authored() {
        let a = crate::development_release::tests::Scratch::new();
        let aa = a.provision();
        let b = crate::development_release::tests::Scratch::new();
        let _bb = b.provision();
        assert_eq!(authority(&a.0, &a.0).unwrap().root(), aa.root());
        assert!(authority(&a.0, &b.0).is_err());
        let after = fs::read(a.0.join(crate::development_release::ROOT_FILE)).unwrap();
        assert_eq!(after, aa.root());
    }
    #[test]
    fn command_reply_replay_refusal_and_recovery_cannot_advance_script() {
        let row = |result: &str, recovery: &str| crate::native_protocol::StateRecord {
            fields: std::collections::BTreeMap::from([
                ("op".into(), "activate".into()),
                ("result".into(), result.into()),
                ("recovery".into(), recovery.into()),
            ]),
        };
        assert!(reply(&[], "activate", 1).unwrap().is_none());
        assert!(reply(&[row("ok", "0")], "activate", 1).unwrap().is_some());
        assert!(reply(&[row("ok", "0"), row("ok", "0")], "activate", 1).is_err());
        assert!(reply(&[row("refused", "0")], "activate", 1).is_err());
        assert!(reply(&[row("ok", "1")], "activate", 1).is_err());
    }
}
