//! Explicit finite real-device qualification. References inspect original QMP
//! pixels; only actual current RPC receipts establish input/save correlation.
use crate::{
    boot::ChildGuard,
    build::{self, Manifest, Result},
    desktop_protocol::{self, Producer, StepKind},
    network_io::{acquisition_disk as disk_check, components::Context},
    network_mode::Mode,
    qmp::{Key, Qmp},
    session_io::ProbeUi,
    session_reference::Reference,
    storage,
};
use ev_graphics::{
    connection::{Action, Connection, Status, Update, View as OwnerView},
    native::Build,
    session::{Focus, SaveState, View},
    shell::Screen,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    io::Write,
    path::Path,
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

pub(crate) const NOTE: &str = "M6UI42";
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum Phase {
    Exercise,
    Cold,
    FirstUse { package: [u8; 32] },
    FirstUseCold,
}
impl Phase {
    fn cold(self) -> bool {
        matches!(self, Self::Cold | Self::FirstUseCold)
    }
    fn mode(self) -> Mode {
        if self.cold() {
            Mode::SystemManaged
        } else {
            Mode::Standalone
        }
    }
    fn no_app(self) -> bool {
        matches!(self, Self::FirstUse { .. })
    }
    fn saved(self) -> disk_check::Saved<'static> {
        disk_check::Saved {
            note: if matches!(self, Self::FirstUse { .. } | Self::FirstUseCold) {
                ""
            } else {
                NOTE
            },
            note_counter: if matches!(self, Self::FirstUse { .. } | Self::FirstUseCold) {
                0
            } else {
                1
            },
            value: 1001,
            data_counter: 0,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
enum Stage {
    Home,
    Loaded,
    Typed(usize),
    DirtyHome,
    MenuIdle,
    FetchFocus,
    PrimingBack,
    PrimedFetchFocus,
    Preparing,
    BusyHome,
    DirtyApp,
    SaveFocus,
    Busy,
    ReadyHome,
    ReadyMenu,
    SelectFocus,
    Selected,
    RestartFocus,
    CancelDefault,
    CanceledHome,
    ReturnedBusy,
    Saved,
    SavedHome,
    SelectedAgain,
    RestartAgain,
    ConfirmDefault,
    ConfirmFocus,
    Finishing,
    Done,
}
struct FrameAt {
    line: usize,
    step: desktop_protocol::Step,
}
fn observation_bytes(bytes: &[u8], terminal: bool) -> Result<&[u8]> {
    if terminal {
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            return Err("owner UI terminal serial has an incomplete final line".into());
        }
        Ok(bytes)
    } else {
        Ok(crate::acquisition_io::complete(bytes))
    }
}
/// Project only an already validated current Shell/frame barrier. ProbeUi
/// retains the wire verifier; the existing Input codec supplies Enter state.
fn enter_at(
    ui: &ProbeUi,
    bytes: &[u8],
    shell: u64,
    frame: u64,
    line: usize,
) -> Result<Option<ev_input::EnterState>> {
    if !ui.ready(shell, frame, line) {
        return Ok(None);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "owner barrier UTF8")?;
    let caller = format!("caller_process={shell}");
    let frame = format!("frame={frame}");
    let fields = text
        .lines()
        .rev()
        .filter(|row| row.starts_with("EVROSION_M6_BARRIER "))
        .map(|row| row.split(' ').collect::<Vec<_>>())
        .find(|f| f.get(7) == Some(&caller.as_str()) && f.get(11) == Some(&frame.as_str()))
        .ok_or("validated current owner barrier missing")?;
    let reply = fields
        .get(16)
        .and_then(|f| f.strip_prefix("reply="))
        .and_then(|f| u64::from_str_radix(f, 16).ok())
        .ok_or("validated owner barrier reply missing")?;
    Ok(Some(
        ev_input::SessionBarrierReply::decode(reply.to_le_bytes())
            .map_err(|_| "validated owner barrier codec")?
            .enter,
    ))
}
fn released_enter(enter: ev_input::EnterState) -> bool {
    enter.main_released && !enter.main_held && !enter.keypad_held
}
fn check_priming_enter(stage: Stage, enter: ev_input::EnterState) -> Result<()> {
    if stage == Stage::FetchFocus {
        if enter.main_released || enter.main_held || enter.keypad_held {
            return Err("first-use priming requires actual unknown, nonheld main Enter".into());
        }
    } else if !released_enter(enter) {
        return Err("first-use needs actual released, nonheld Enter before Fetch".into());
    }
    Ok(())
}
fn frame_steps(bytes: &[u8], build: &str) -> Result<Vec<FrameAt>> {
    let steps = desktop_protocol::steps(bytes, build)?;
    let lines = std::str::from_utf8(bytes)
        .map_err(|_| "owner UI serial not UTF-8")?
        .split_inclusive('\n')
        .enumerate()
        .filter_map(|(line, raw)| {
            (raw.ends_with('\n') && raw.starts_with("EVROSION_M4_DESKTOP_STEP ")).then_some(line)
        });
    Ok(steps
        .into_iter()
        .zip(lines)
        .map(|(step, line)| FrameAt { line, step })
        .collect())
}
fn app_capture_ready(
    reference: &Reference,
    app: &FrameAt,
    shell: Option<&FrameAt>,
    ui: &ProbeUi,
) -> Result<bool> {
    let Some(shell) = shell else {
        return Ok(false);
    };
    // Showing chrome deliberately does not sample a runnable App's surface.
    // The Shell asks Root for a real repaint after its protected Present and
    // input barrier. An older matching App frame cannot prove that the Home
    // pixels beneath the now-visible viewport have been replaced.
    reference.fresh_app_ready(&app.step, app.line, &shell.step, shell.line, ui)
}
fn no_app_history(bytes: &[u8], build: &str, steps: &[FrameAt]) -> Result<()> {
    if steps.iter().any(|s| s.step.app_process != 0)
        || !crate::downloaded_protocol::records(bytes, build, false)?.is_empty()
        || std::str::from_utf8(bytes)
            .map_err(|_| "first-use UTF8")?
            .lines()
            .any(|line| line.starts_with("EVROSION_M5_NATIVE_ACTION "))
    {
        return Err("first-use standalone started App code".into());
    }
    Ok(())
}
struct Observer {
    phase: Phase,
    stage: Stage,
    app: Option<u64>,
    shell: Option<u64>,
    display: Option<u64>,
    min_frame: u64,
    history: Vec<u8>,
    captures: Vec<Value>,
    stimuli: Vec<Value>,
    snapshots: Vec<Value>,
    initial: Option<Vec<u8>>,
    fetched: Option<Vec<u8>>,
}
impl Observer {
    fn new(phase: Phase, initial: Option<Vec<u8>>) -> Self {
        Self {
            phase,
            stage: if phase.cold() {
                Stage::Loaded
            } else {
                Stage::Home
            },
            app: None,
            shell: None,
            display: None,
            min_frame: 0,
            history: Vec::new(),
            captures: Vec::new(),
            stimuli: Vec::new(),
            snapshots: Vec::new(),
            initial,
            fetched: None,
        }
    }
    fn key(&mut self, q: &mut Qmp, key: Key) -> Result<()> {
        q.key_state(key, true)?;
        q.key_state(key, false)?;
        self.stimuli.push(json!({"stage":self.stage,"device":"owned QEMU PS/2 keyboard","key":format!("{key:?}"),"make_then_break":true}));
        Ok(())
    }
    fn parse_input<'a>(&mut self, bytes: &'a [u8], terminal: bool) -> Result<&'a [u8]> {
        if !bytes.starts_with(&self.history) {
            return Err("owner UI serial was truncated/rewritten".into());
        }
        self.history = bytes.to_vec();
        observation_bytes(bytes, terminal)
    }
    fn owner(&self, update: Update, focus: Action, confirm: bool) -> Screen {
        Screen::Connection(OwnerView {
            status: Status {
                connection: Connection::Online,
                update,
                app_running: !self.phase.no_app(),
                confirm,
                candidate_available: matches!(update, Update::Ready | Update::Selected),
            },
            focus,
        })
    }
    fn expected(&self) -> (Screen, Option<View<'_>>, Producer) {
        let build = if self.phase.cold() {
            Build::B
        } else {
            Build::A
        };
        let app = |focus, note, state| {
            (
                Screen::AppRunning,
                Some(View {
                    build,
                    focus,
                    note,
                    state,
                    file: None,
                }),
                Producer::App,
            )
        };
        match self.stage {
            Stage::Loaded => app(
                Focus::Note,
                if self.phase.cold() {
                    self.phase.saved().note.as_bytes()
                } else {
                    b""
                },
                SaveState::Saved,
            ),
            Stage::Typed(n) => app(Focus::Note, &NOTE.as_bytes()[..n], SaveState::Unsaved),
            Stage::DirtyApp => app(Focus::Note, NOTE.as_bytes(), SaveState::Unsaved),
            Stage::SaveFocus => app(Focus::Save, NOTE.as_bytes(), SaveState::Unsaved),
            Stage::Busy | Stage::ReturnedBusy => app(Focus::Save, NOTE.as_bytes(), SaveState::Busy),
            Stage::Saved => app(Focus::Save, NOTE.as_bytes(), SaveState::Saved),
            Stage::MenuIdle | Stage::PrimingBack => (
                self.owner(
                    if self.phase.no_app() {
                        Update::SetupRequired
                    } else {
                        Update::Idle
                    },
                    Action::Back,
                    false,
                ),
                None,
                Producer::Shell,
            ),
            Stage::FetchFocus | Stage::PrimedFetchFocus => (
                self.owner(
                    if self.phase.no_app() {
                        Update::SetupRequired
                    } else {
                        Update::Idle
                    },
                    Action::Fetch,
                    false,
                ),
                None,
                Producer::Shell,
            ),
            Stage::Preparing => (
                self.owner(Update::Preparing, Action::Back, false),
                None,
                Producer::Shell,
            ),
            Stage::ReadyMenu => (
                self.owner(Update::Ready, Action::Back, false),
                None,
                Producer::Shell,
            ),
            Stage::SelectFocus => (
                self.owner(Update::Ready, Action::SelectNext, false),
                None,
                Producer::Shell,
            ),
            Stage::Selected | Stage::SelectedAgain => (
                self.owner(Update::Selected, Action::Back, false),
                None,
                Producer::Shell,
            ),
            Stage::RestartFocus | Stage::RestartAgain => (
                self.owner(Update::Selected, Action::Restart, false),
                None,
                Producer::Shell,
            ),
            Stage::CancelDefault | Stage::ConfirmDefault => (
                self.owner(Update::Selected, Action::Cancel, true),
                None,
                Producer::Shell,
            ),
            Stage::ConfirmFocus => (
                self.owner(Update::Selected, Action::Confirm, true),
                None,
                Producer::Shell,
            ),
            _ => (Screen::Home, None, Producer::Shell),
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn observe(
        &mut self,
        bytes: &[u8],
        build: &str,
        q: &mut Qmp,
        directory: &Path,
        input: &mut impl Write,
        disk: &storage::Disk,
        context: &Context,
        terminal: bool,
    ) -> Result<()> {
        let bytes = self.parse_input(bytes, terminal)?;
        if !crate::acquisition_io::identities_mode(context, bytes, build, self.phase.mode())? {
            return Ok(());
        }
        let ui = ProbeUi::parse(bytes, build)?;
        let intents = crate::restart_protocol::records(bytes, build)?;
        if !matches!(self.stage, Stage::Finishing | Stage::Done) && !intents.is_empty() {
            return Err("restart intent preceded explicit Confirm input".into());
        }
        if matches!(self.stage, Stage::Finishing | Stage::Done) {
            if !self.phase.cold() && intents.len() == 1 {
                self.stage = Stage::Done;
            }
            if self.phase.cold()
                && crate::native_protocol::states_network(bytes, build)?
                    .iter()
                    .any(|r| r.fields["op"] == "finish" && r.fields["result"] == "ok")
            {
                self.stage = Stage::Done;
            }
            return Ok(());
        }
        let steps = frame_steps(bytes, build)?;
        if self.phase.no_app() {
            no_app_history(bytes, build, &steps)?;
        }
        let (screen, view, producer) = self.expected();
        let reference = Reference::owner(screen, view, ui.cursor())?;
        let Some(step) = steps
            .iter()
            .rev()
            .find(|s| s.step.kind == StepKind::Frame && s.step.producer == producer)
        else {
            return Ok(());
        };
        let at = step;
        let step = &at.step;
        if step.frame <= self.min_frame
            || reference.surface_hash(producer, step.frame)? != step.surface_sha256
        {
            return Ok(());
        }
        let shell = steps
            .iter()
            .rev()
            .find(|s| s.step.kind == StepKind::Frame && s.step.producer == Producer::Shell);
        if producer == Producer::Shell && !ui.ready(step.shell_process, step.frame, at.line) {
            return Ok(());
        }
        let priming_enter = if self.phase.no_app()
            && matches!(
                self.stage,
                Stage::FetchFocus | Stage::PrimingBack | Stage::PrimedFetchFocus
            ) {
            let enter = enter_at(&ui, bytes, step.shell_process, step.frame, at.line)?
                .ok_or("first-use needs its current protected Enter barrier")?;
            check_priming_enter(self.stage, enter)?;
            Some(enter)
        } else {
            None
        };
        if producer == Producer::App && !app_capture_ready(&reference, at, shell, &ui)? {
            return Ok(());
        }
        if self.shell.is_some_and(|p| p != step.shell_process)
            || self.display.is_some_and(|p| p != step.display_process)
        {
            return Err("owner UI critical identity changed during finite controls".into());
        }
        if !self.phase.no_app() && self.stage != Stage::Home && step.app_process == 0 {
            return Err("owner controls lost current live App".into());
        }
        if self.app.is_some_and(|p| p != step.app_process) {
            return Err("owner controls stopped/replaced current App".into());
        }
        match self.stage {
            Stage::Home
                if !self.phase.cold()
                    && crate::network_protocol::records(bytes, build)?
                        .last()
                        .is_none_or(|p| p.stage != 6) =>
            {
                return Ok(());
            }
            Stage::Loaded if ui.note_complete(step.app_process, 1, 1).is_none() => return Ok(()),
            Stage::Busy if ui.note_busy(step.app_process, 2, 2).is_none() => return Ok(()),
            Stage::Saved if ui.note_complete(step.app_process, 3, 2).is_none() => return Ok(()),
            _ => (),
        }
        if (self.stage == Stage::Busy || (self.phase.no_app() && self.stage == Stage::ReadyMenu))
            && !crate::native_protocol::states_network(bytes, build)?
                .iter()
                .any(|r| r.fields["op"] == "update-fetch" && r.fields["result"] == "ok")
        {
            return Ok(());
        }
        if self.phase.cold()
            && self.stage == Stage::Loaded
            && !crate::system_health_io::cold_b_ready(context, bytes, build, disk)?
        {
            return Ok(());
        }
        q.set_running(false)?;
        let capture: Result<Value> = (|| {
            let (path, frame) = q.capture(self.captures.len() as u32 + 1)?;
            let checked = reference.validate(&frame)?;
            if let Phase::FirstUse { package } = self.phase {
                if self.stage == Stage::PrimingBack {
                    let actual = disk.bytes()?;
                    if self.initial.as_deref() != Some(actual.as_slice())
                        || crate::native_protocol::states_network(bytes, build)?
                            .iter()
                            .any(|r| r.fields["op"] == "update-fetch")
                    {
                        return Err("initial unknown Enter changed seed or reported Fetch".into());
                    }
                    storage::immutable_new(
                        &directory.join("first-use-after-priming.raw"),
                        &actual,
                    )?;
                    let enter =
                        priming_enter.ok_or("first-use priming lost actual Enter barrier")?;
                    self.snapshots.push(json!({"stage":self.stage,"whole_seed_unchanged":true,"no_app":true,"update_fetch_reports":0,"current_shell_frame":step.frame,"enter_main_released":enter.main_released,"enter_main_held":enter.main_held,"enter_keypad_held":enter.keypad_held}));
                } else if self.stage == Stage::ReadyMenu {
                    let actual = disk.bytes()?;
                    let proof = disk_check::system_health::first_use::fetched(
                        self.initial.as_deref().ok_or("first-use seed missing")?,
                        &actual,
                        &context.packages()?,
                        package,
                    )?;
                    storage::immutable_new(&directory.join("first-use-after-fetch.raw"), &actual)?;
                    self.fetched = Some(actual);
                    self.snapshots.push(proof);
                } else if self.stage == Stage::Selected {
                    let actual = disk.bytes()?;
                    let proof = disk_check::system_health::first_use::selected(
                        self.fetched
                            .as_deref()
                            .ok_or("first-use Fetch capture missing")?,
                        &actual,
                        &context.packages()?,
                        package,
                    )?;
                    storage::immutable_new(&directory.join("first-use-after-select.raw"), &actual)?;
                    self.snapshots.push(proof);
                }
            }
            Ok(
                json!({"stage":self.stage,"surface":step,"surface_line":at.line,"current_shell_line":shell.map(|s|s.line),"path":path.file_name().ok_or("owner UI screenshot name")?,"sha256":build::hash_file(&path)?,"scanout":checked}),
            )
        })();
        let resumed = q.set_running(true);
        self.captures.push(capture?);
        resumed?;
        self.shell = Some(step.shell_process);
        self.display = Some(step.display_process);
        if step.app_process != 0 {
            self.app = Some(step.app_process);
        }
        self.min_frame = 0;
        let key = match self.stage {
            Stage::Home if self.phase.no_app() => {
                self.stage = Stage::MenuIdle;
                Some(Key::Tab)
            }
            Stage::Home => {
                self.stage = Stage::Loaded;
                Some(Key::Enter)
            }
            Stage::Loaded if self.phase.cold() => {
                self.stage = Stage::Finishing;
                input
                    .write_all(b"finish\n")
                    .and_then(|()| input.flush())
                    .map_err(|e| e.to_string())?;
                self.stimuli.push(
                    json!({"stage":"cold saved B","device":"owned QEMU UART","bytes":"finish\n"}),
                );
                None
            }
            Stage::Loaded => {
                self.stage = Stage::Typed(1);
                q.ascii(NOTE.as_bytes()[0])?;
                self.stimuli
                    .push(json!({"device":"owned QEMU PS/2 keyboard","ascii":NOTE.as_bytes()[0]}));
                None
            }
            Stage::Typed(n) if n < NOTE.len() => {
                self.stage = Stage::Typed(n + 1);
                self.min_frame = step.frame;
                q.ascii(NOTE.as_bytes()[n])?;
                self.stimuli
                    .push(json!({"device":"owned QEMU PS/2 keyboard","ascii":NOTE.as_bytes()[n]}));
                None
            }
            Stage::Typed(_) => {
                self.stage = Stage::DirtyHome;
                Some(Key::Escape)
            }
            Stage::DirtyHome => {
                self.stage = Stage::MenuIdle;
                Some(Key::Tab)
            }
            Stage::MenuIdle => {
                self.stage = Stage::FetchFocus;
                self.min_frame = step.frame;
                Some(Key::Tab)
            }
            Stage::FetchFocus => {
                if self.phase.no_app() {
                    // The first make is intentionally ineligible. Its real
                    // break is witnessed by the NEW Back frame's barrier;
                    // no eligible Fetch is issued until that evidence arrives.
                    self.stage = Stage::PrimingBack;
                    self.min_frame = step.frame;
                    self.key(q, Key::Enter)?;
                    Some(Key::Tab)
                } else {
                    self.stage = Stage::Preparing;
                    self.min_frame = step.frame;
                    Some(Key::Enter)
                }
            }
            Stage::PrimingBack => {
                self.stage = Stage::PrimedFetchFocus;
                self.min_frame = step.frame;
                Some(Key::Tab)
            }
            Stage::PrimedFetchFocus => {
                self.stage = Stage::ReadyMenu;
                self.min_frame = step.frame;
                Some(Key::Enter)
            }
            Stage::Preparing => {
                self.stage = Stage::BusyHome;
                Some(Key::Escape)
            }
            Stage::BusyHome => {
                self.stage = Stage::DirtyApp;
                Some(Key::Enter)
            }
            Stage::DirtyApp => {
                self.stage = Stage::SaveFocus;
                self.min_frame = step.frame;
                Some(Key::Tab)
            }
            Stage::SaveFocus => {
                self.stage = Stage::Busy;
                self.min_frame = step.frame;
                Some(Key::Enter)
            }
            Stage::Busy => {
                self.snapshots.push(disk_check::saved_state(
                    &disk.bytes()?,
                    &context.packages()?,
                    disk_check::Saved {
                        note: "",
                        note_counter: 0,
                        value: 1001,
                        data_counter: 0,
                    },
                )?);
                self.stage = Stage::ReadyHome;
                Some(Key::Escape)
            }
            Stage::ReadyHome => {
                self.stage = Stage::ReadyMenu;
                Some(Key::Tab)
            }
            Stage::ReadyMenu => {
                self.stage = Stage::SelectFocus;
                self.min_frame = step.frame;
                Some(Key::Tab)
            }
            Stage::SelectFocus => {
                self.stage = Stage::Selected;
                self.min_frame = step.frame;
                Some(Key::Enter)
            }
            Stage::Selected => {
                self.stage = Stage::RestartFocus;
                self.min_frame = step.frame;
                Some(Key::Tab)
            }
            Stage::RestartFocus => {
                self.stage = Stage::CancelDefault;
                self.min_frame = step.frame;
                Some(Key::Enter)
            }
            Stage::CancelDefault => {
                self.stage = Stage::CanceledHome;
                Some(Key::Enter)
            }
            Stage::CanceledHome => {
                if !intents.is_empty() {
                    return Err("Cancel emitted authenticated restart intent".into());
                }
                self.snapshots.push(json!({"cancel_restart_intents":0,"current_app":step.app_process,"protected_saved":disk_check::saved_state(&disk.bytes()?,&context.packages()?,disk_check::Saved{note:"",note_counter:0,value:1001,data_counter:0})?}));
                if self.phase.no_app() {
                    self.stage = Stage::SelectedAgain;
                    Some(Key::Tab)
                } else {
                    self.stage = Stage::ReturnedBusy;
                    Some(Key::Enter)
                }
            }
            Stage::ReturnedBusy => {
                self.stage = Stage::Saved;
                self.min_frame = step.frame;
                Some(Key::Enter)
            }
            Stage::Saved => {
                self.snapshots.push(disk_check::saved_state(
                    &disk.bytes()?,
                    &context.packages()?,
                    disk_check::Saved {
                        note: NOTE,
                        note_counter: 1,
                        value: 1001,
                        data_counter: 0,
                    },
                )?);
                self.stage = Stage::SavedHome;
                Some(Key::Escape)
            }
            Stage::SavedHome => {
                self.stage = Stage::SelectedAgain;
                Some(Key::Tab)
            }
            Stage::SelectedAgain => {
                self.stage = Stage::RestartAgain;
                self.min_frame = step.frame;
                Some(Key::Tab)
            }
            Stage::RestartAgain => {
                self.stage = Stage::ConfirmDefault;
                self.min_frame = step.frame;
                Some(Key::Enter)
            }
            Stage::ConfirmDefault => {
                self.stage = Stage::ConfirmFocus;
                self.min_frame = step.frame;
                Some(Key::Tab)
            }
            Stage::ConfirmFocus => {
                self.stage = Stage::Finishing;
                Some(Key::Enter)
            }
            _ => None,
        };
        if let Some(key) = key {
            self.key(q, key)?;
        }
        if self.stimuli.len() > 128 || self.captures.len() > 64 {
            return Err("owner UI finite stimulus/capture bound".into());
        }
        let _ = directory;
        Ok(())
    }
}
#[allow(clippy::too_many_arguments)]
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
    mode: Mode,
    phase: Phase,
    disk: &storage::Disk,
) -> Result<ExitStatus> {
    if mode != phase.mode() {
        return Err("owner UI phase differs from its exact selected mode".into());
    }
    if timeout != Duration::from_secs(600) {
        return Err("owner UI probe requires one explicit600s bound".into());
    }
    let context = Context::retain_mode(root, manifest, directory, mode, true)?;
    let initial = if phase.no_app() {
        Some(disk.bytes()?)
    } else {
        None
    };
    let mut observer = Observer::new(phase, initial);
    let mut qmp = None;
    let origin = Instant::now();
    let deadline = origin.checked_add(timeout).ok_or("owner UI deadline")?;
    let result = (|| {
        let mut child = ChildGuard(
            command
                .stdin(Stdio::piped())
                .spawn()
                .map_err(|e| e.to_string())?,
        );
        clock.verify_and_start(&mut child.0, directory)?;
        qmp = Some(Qmp::connect_at(directory, deadline, origin)?);
        let q = qmp.as_mut().unwrap();
        let mut input = child.0.stdin.take().ok_or("owner UI owned UART absent")?;
        loop {
            if Instant::now() >= deadline {
                return Err(format!("owner UI finite deadline at {:?}", observer.stage));
            }
            let bytes = crate::acquisition_io::bounded(serial, 1024 * 1024)?;
            crate::acquisition_io::bounded(errors, 1024 * 1024)?;
            observer.observe(
                &bytes, build, q, directory, &mut input, disk, &context, false,
            )?;
            if let Some(status) = child.0.try_wait().map_err(|e| e.to_string())? {
                let final_bytes = crate::acquisition_io::bounded(serial, 1024 * 1024)?;
                observer.observe(
                    &final_bytes,
                    build,
                    q,
                    directory,
                    &mut input,
                    disk,
                    &context,
                    true,
                )?;
                if observer.stage != Stage::Done {
                    return Err(format!(
                        "owner UI exited before completed controls at {:?}",
                        observer.stage
                    ));
                }
                let ui = ProbeUi::parse(&final_bytes, build)?;
                let finished_ui = ui.finish()?;
                if phase.no_app() {
                    if finished_ui["notes"]
                        .as_array()
                        .is_none_or(|notes| !notes.is_empty())
                    {
                        return Err("first-use standalone minted an App Note observation".into());
                    }
                    storage::json_new(&directory.join("first-use-finished-ui.json"), &finished_ui)?;
                    no_app_history(&final_bytes, build, &frame_steps(&final_bytes, build)?)?;
                    let record = crate::native_protocol::record_network(&final_bytes, build)?;
                    let profile =
                        crate::native_profile::finished_network(&final_bytes, build, 0, Some(0))?;
                    if !record.actions.is_empty()
                        || !record.downloaded_actions.is_empty()
                        || [
                            "app_a_starts",
                            "app_b_starts",
                            "app_a_stops",
                            "app_b_stops",
                            "app_a_reaps",
                            "app_b_reaps",
                        ]
                        .iter()
                        .any(|key| record.counts[*key] != 0)
                        || profile[5].counts.iter().any(|(key, value)| {
                            !matches!(key.as_str(), "index" | "elapsed_ticks") && *value != 0
                        })
                    {
                        return Err("first-use standalone invented an App incarnation".into());
                    }
                }
                if crate::session_protocol::retention(&final_bytes, build)?.omitted != 0 {
                    return Err("owner UI finite receipt history omitted".into());
                }
                if status.code() != Some(ev_test_protocol::QEMU_PASS_STATUS) {
                    return Err("owner UI lacks actual normal QEMU exit".into());
                }
                return Ok(status);
            }
            thread::sleep(
                Duration::from_millis(4).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    })();
    storage::json_new(
        &directory.join("owner-ui-observer.json"),
        &json!({"schema":1,"phase":phase,"passed":result.is_ok(),"stage":observer.stage,"error":result.as_ref().err(),"captures":observer.captures,"stimuli":observer.stimuli,"snapshots":observer.snapshots,"scripted_input":true,"human_consent_claim":false,"GUI_ready_is_health_claim":false,"scope":if matches!(phase,Phase::FirstUse { .. } | Phase::FirstUseCold) {"Original QMP scanout and real PS/2 first use: no standalone App admission; Fetch leaves Note blank; explicit selection creates exact empty Note0 before System mutation; Cancel emits no intent; Confirm requires RS1/full retirement; offline cold needs actual health/probe/KG/content and initial empty Saved B."} else {"Original QMP scanout and real PS/2 controls; nonce2 Busy preserves unsaved bytes, explicit fresh nonce3 Save, default Cancel emits no intent, explicit Confirm requires authenticated RS1 plus outer full normal retirement."}}),
    )?;
    storage::json_new(
        &directory.join("qmp-transcript.json"),
        &json!({"schema":1,"exchanges":qmp.as_ref().map(Qmp::transcript).unwrap_or(&[])}),
    )?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn reference() -> Reference {
        Reference::owner(
            Screen::AppRunning,
            Some(View {
                build: Build::A,
                focus: Focus::Note,
                note: NOTE.as_bytes(),
                state: SaveState::Unsaved,
                file: None,
            }),
            None,
        )
        .unwrap()
    }
    fn frame(reference: &Reference, producer: Producer, frame: u64, line: usize) -> FrameAt {
        FrameAt {
            line,
            step: desktop_protocol::Step {
                kind: StepKind::Frame,
                frame,
                width: 1280,
                height: 800,
                app_process: 9,
                shell_process: 8,
                display_process: 3,
                grants: 0,
                producer,
                surface_sha256: reference.surface_hash(producer, frame).unwrap(),
                held_ticks: 0,
            },
        }
    }
    fn barrier(frame: u32, line: usize, shell: u64) -> ProbeUi {
        let request = ev_input::SessionBarrierRequest::new(frame)
            .unwrap()
            .encode();
        let reply = ev_input::SessionBarrierReply {
            sequence: 13,
            enter: ev_input::EnterState {
                main_released: true,
                ..Default::default()
            },
            pointer: ev_input::PointerState {
                held: 0,
                released: 0,
            },
        }
        .encode()
        .unwrap();
        let build = "a".repeat(64);
        let serial = format!(
            "{}EVROSION_M6_BARRIER protocol=1 build={} count=1 call_epoch=501 call=2571 endpoint=34 caller_process={} caller_thread={} callee_process=5 callee_thread=5 frame={} sequence=13 flags=1 buttons=0 request={:016x} reply={:016x} tick=15162\n",
            "\n".repeat(line),
            build,
            shell,
            shell,
            frame,
            u64::from_le_bytes(request),
            u64::from_le_bytes(reply)
        );
        ProbeUi::parse(serial.as_bytes(), &build).unwrap()
    }
    #[test]
    fn owner_phases_select_only_their_declared_standalone_or_managed_mode() {
        assert_eq!(Phase::Exercise.mode(), Mode::Standalone);
        assert_eq!(
            Phase::FirstUse { package: [8; 32] }.mode(),
            Mode::Standalone
        );
        assert_eq!(Phase::Cold.mode(), Mode::SystemManaged);
        assert_eq!(Phase::FirstUseCold.mode(), Mode::SystemManaged);
    }
    #[test]
    fn exact_mode_identity_join_refuses_managed_in_the_old_standalone_wrapper() {
        let build = "a".repeat(64);
        let context = Context {
            images: core::array::from_fn(|i| format!("{:064x}", i + 1)),
            root_manifest: "f".repeat(64),
            root_frames: 40,
            block_frames: 8,
            package_pages: [1, 1],
            banks: None,
        };
        let serial = |mode| {
            format!(
                "EVROSION_M5_NATIVE_COMMON_PREFIX protocol=1 build={build} mode={mode} root_process=20 root_thread=120 root_image_sha256={} root_epoch=1 root_incarnation=2 root_manifest_sha256={} block_process=24 block_thread=124 block_image_sha256={} system_endpoint=9 root_frames=40 block_frames=8\nEVROSION_M5_NATIVE_CRITICAL_READY protocol=1 build={build} process=21 thread=121 image_sha256={} tick=1\n",
                context.images[0], context.root_manifest, context.images[4], context.images[1]
            )
        };
        let standalone = serial(0);
        let managed = serial(1);
        assert_eq!(
            crate::acquisition_io::identities(&context, standalone.as_bytes(), &build),
            Ok(true)
        );
        assert!(crate::acquisition_io::identities(&context, managed.as_bytes(), &build).is_err());
        assert_eq!(
            crate::acquisition_io::identities_mode(
                &context,
                managed.as_bytes(),
                &build,
                Mode::SystemManaged
            ),
            Ok(true)
        );
        assert!(
            crate::acquisition_io::identities_mode(
                &context,
                standalone.as_bytes(),
                &build,
                Mode::SystemManaged
            )
            .is_err()
        );
        assert!(
            crate::acquisition_io::identities_mode(
                &context,
                managed
                    .replace(&context.images[4], &"b".repeat(64))
                    .as_bytes(),
                &build,
                Mode::SystemManaged
            )
            .is_err()
        );
    }
    #[test]
    fn first_use_has_no_app_and_cold_requires_the_actual_initial_empty_note() {
        let mut observer = Observer::new(
            Phase::FirstUse { package: [8; 32] },
            Some(vec![0; 4 * 1024 * 1024]),
        );
        observer.stage = Stage::MenuIdle;
        let (Screen::Connection(view), app, producer) = observer.expected() else {
            panic!("owner view")
        };
        assert!(!view.status.app_running);
        assert!(!view.status.candidate_available);
        assert_eq!(view.status.update, Update::SetupRequired);
        assert!(app.is_none());
        assert_eq!(producer, Producer::Shell);
        let cold = Observer::new(Phase::FirstUseCold, None);
        let (_, Some(view), producer) = cold.expected() else {
            panic!("App view")
        };
        assert_eq!(view.build, Build::B);
        assert_eq!(view.note, b"");
        assert_eq!(view.state, SaveState::Saved);
        assert_eq!(producer, Producer::App);
    }
    #[test]
    fn no_app_history_refuses_even_an_older_app_frame_or_action() {
        let reference = reference();
        let mut home = frame(&reference, Producer::Shell, 2, 20);
        home.step.app_process = 0;
        assert!(no_app_history(b"", &"a".repeat(64), &[home]).is_ok());
        let app = frame(&reference, Producer::App, 1, 10);
        let mut home = frame(&reference, Producer::Shell, 2, 20);
        home.step.app_process = 0;
        assert!(no_app_history(b"", &"a".repeat(64), &[app, home]).is_err());
        assert!(
            no_app_history(
                b"EVROSION_M5_NATIVE_ACTION unexpected
",
                &"a".repeat(64),
                &[]
            )
            .is_err()
        );
    }
    #[test]
    fn resumed_dirty_app_requires_real_repaint_after_current_visible_shell_and_barrier() {
        let reference = reference();
        let old_app = frame(&reference, Producer::App, 9, 20);
        let shell = frame(&reference, Producer::Shell, 8, 30);
        let ready = barrier(8, 31, 8);
        // A real old App surface and new matching chrome are insufficient:
        // visible Shell paint deliberately leaves the old Home viewport alone.
        assert!(!app_capture_ready(&reference, &old_app, Some(&shell), &ready).unwrap());
        let repaint = frame(&reference, Producer::App, 10, 32);
        assert!(app_capture_ready(&reference, &repaint, Some(&shell), &ready).unwrap());
        assert!(!app_capture_ready(&reference, &repaint, None, &ready).unwrap());
        for ui in [barrier(7, 31, 8), barrier(8, 29, 8), barrier(8, 31, 88)] {
            assert!(!app_capture_ready(&reference, &repaint, Some(&shell), &ui).unwrap());
        }
        let mut substituted = frame(&reference, Producer::App, 10, 32);
        substituted.step.surface_sha256 = "0".repeat(64);
        assert!(!app_capture_ready(&reference, &substituted, Some(&shell), &ready).unwrap());
    }
    #[test]
    fn priming_stages_keep_setup_required_and_released_nonheld_input() {
        let mut observer = Observer::new(
            Phase::FirstUse { package: [8; 32] },
            Some(vec![0; 4 * 1024 * 1024]),
        );
        for (stage, focus) in [
            (Stage::PrimingBack, Action::Back),
            (Stage::PrimedFetchFocus, Action::Fetch),
        ] {
            observer.stage = stage;
            let (Screen::Connection(view), app, producer) = observer.expected() else {
                panic!("owner view")
            };
            assert_eq!(view.status.update, Update::SetupRequired);
            assert_eq!(view.focus, focus);
            assert!(!view.status.app_running && !view.status.candidate_available);
            assert!(app.is_none());
            assert_eq!(producer, Producer::Shell);
        }
        let released = ev_input::EnterState {
            main_released: true,
            ..Default::default()
        };
        assert!(released_enter(released));
        assert!(!released_enter(ev_input::EnterState::default()));
        assert!(check_priming_enter(Stage::FetchFocus, ev_input::EnterState::default()).is_ok());
        assert!(check_priming_enter(Stage::FetchFocus, released).is_err());
        assert!(
            check_priming_enter(
                Stage::FetchFocus,
                ev_input::EnterState {
                    main_held: true,
                    ..Default::default()
                }
            )
            .is_err()
        );
        assert!(
            check_priming_enter(
                Stage::FetchFocus,
                ev_input::EnterState {
                    keypad_held: true,
                    ..Default::default()
                }
            )
            .is_err()
        );
        assert!(check_priming_enter(Stage::PrimingBack, ev_input::EnterState::default()).is_err());
        assert!(check_priming_enter(Stage::PrimedFetchFocus, released).is_ok());
        assert!(!released_enter(ev_input::EnterState {
            main_held: true,
            ..released
        }));
        assert!(!released_enter(ev_input::EnterState {
            keypad_held: true,
            ..released
        }));
    }
    #[test]
    fn current_enter_projection_cannot_use_an_older_or_foreign_barrier() {
        let request = ev_input::SessionBarrierRequest::new(3).unwrap().encode();
        for held in [false, true] {
            let reply = ev_input::SessionBarrierReply {
                sequence: 4,
                enter: ev_input::EnterState {
                    main_released: true,
                    main_held: held,
                    ..Default::default()
                },
                pointer: ev_input::PointerState::default(),
            }
            .encode()
            .unwrap();
            let build = "a".repeat(64);
            let raw = format!(
                "\nEVROSION_M6_BARRIER protocol=1 build={build} count=1 call_epoch=501 call=724 endpoint=34 caller_process=8 caller_thread=8 callee_process=5 callee_thread=5 frame=3 sequence=4 flags={} buttons=0 request={:016x} reply={:016x} tick=8865\n",
                reply[2],
                u64::from_le_bytes(request),
                u64::from_le_bytes(reply)
            );
            let ui = ProbeUi::parse(raw.as_bytes(), &build).unwrap();
            let enter = enter_at(&ui, raw.as_bytes(), 8, 3, 0).unwrap().unwrap();
            assert_eq!(released_enter(enter), !held);
            assert!(enter_at(&ui, raw.as_bytes(), 88, 3, 0).unwrap().is_none());
            assert!(enter_at(&ui, raw.as_bytes(), 8, 2, 0).unwrap().is_none());
            assert!(enter_at(&ui, raw.as_bytes(), 8, 3, 1).unwrap().is_none());
        }
    }
    #[test]
    fn live_partial_rows_keep_raw_history_but_terminal_tail_stays_strict() {
        // Actual closed diagnostic Common + four network rows, without any
        // synthesized success/EOF. The full actual-log projection is separate.
        let raw = br#"EVROSION_M5_NATIVE_COMMON_PREFIX protocol=1 build=b07e533541d3a7c32a713b193ffb7e12b375bebd9f8e71a2b8946a646997f1df mode=0 root_process=1 root_thread=1 root_image_sha256=b876b9b363a6f1a79dcff4471e2c0deecfe7f474a6127fb778d3d03338095425 root_epoch=501 root_incarnation=1 root_manifest_sha256=d860279ed45d7c41d0b9c56c07dccb2f7b568a373a3dcef422626015f1673eb3 block_process=2 block_thread=2 block_image_sha256=0c208ca572d6acaa8d721d31caa4269044335382e518f11164c3ddaf7bb961dd system_endpoint=38 root_frames=232 block_frames=18
EVROSION_M6_NETWORK_PROGRESS protocol=1 build=b07e533541d3a7c32a713b193ffb7e12b375bebd9f8e71a2b8946a646997f1df root_process=1 root_thread=1 endpoint=7 ticket=9 tick=7141 stage=1 result=0 argument=1
EVROSION_M6_NETWORK_PROGRESS protocol=1 build=b07e533541d3a7c32a713b193ffb7e12b375bebd9f8e71a2b8946a646997f1df root_process=1 root_thread=1 endpoint=7 ticket=110 tick=7749 stage=2 result=0 argument=251789322
EVROSION_M6_NETWORK_PROGRESS protocol=1 build=b07e533541d3a7c32a713b193ffb7e12b375bebd9f8e71a2b8946a646997f1df root_process=1 root_thread=1 endpoint=7 ticket=122 tick=7829 stage=3 result=0 argument=3986506412
EVROSION_M6_NETWORK_PROGRESS protocol=1 build=b07e533541d3a7c32a713b193ffb7e12b375bebd9f8e71a2b8946a646997f1df root_process=1 root_thread=1 endpoint=7 ticket=128 tick=8915 stage=4 result=0 argument=8080
"#;
        let build = "b07e533541d3a7c32a713b193ffb7e12b375bebd9f8e71a2b8946a646997f1df";
        let mut observer = Observer::new(Phase::FirstUse { package: [8; 32] }, None);
        for end in 0..=raw.len() {
            let parsed = observer.parse_input(&raw[..end], false).unwrap();
            crate::network_protocol::records(parsed, build).unwrap();
            assert_eq!(observer.history, raw[..end]);
            if end > 0 && raw[end - 1] != b'\n' {
                assert!(observation_bytes(&raw[..end], true).is_err());
            }
        }
        assert_eq!(observer.parse_input(raw, true).unwrap(), raw);
        assert!(observer.parse_input(&raw[..raw.len() - 1], false).is_err());
        let mut rewritten = raw.to_vec();
        rewritten[0] ^= 1;
        assert!(observer.parse_input(&rewritten, false).is_err());
        let malformed = String::from_utf8(raw.to_vec())
            .unwrap()
            .replace("argument=8080", "argument=8081");
        assert!(
            crate::network_protocol::records(
                observation_bytes(malformed.as_bytes(), false).unwrap(),
                build
            )
            .is_err()
        );
        assert!(
            crate::network_protocol::records(
                observation_bytes(malformed.as_bytes(), true).unwrap(),
                build
            )
            .is_err()
        );
    }
}
