//! Bounded owner of one desktop QEMU and its private QMP/keyboard/UART test
//! stimuli. The guest still receives real device input through userspace Input.
use crate::{
    build::{self, Result},
    desktop_protocol::{self, Producer, Reference, StepKind, Timeline},
    qmp::{Key, Qmp},
    storage,
};
use ev_graphics::{
    HelloControl, HelloView,
    shell::{FileChoice, Screen},
};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::Path,
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};
const OUTPUT_LIMIT: u64 = 1024 * 1024;
const PERFORMANCE_CLOCK: &str =
    "host monotonic nanoseconds; QEMU/TCG end-to-end observation bounds";
const PERFORMANCE_SCOPE: &str = "actual owned spawn/input to semantically expected protected Present; serial polling uncertainty retained; excludes bounded actual QMP paused intervals; not raw guest CPU or physical hardware latency";
const FRAME_METRICS: [&str; 10] = [
    "owned_spawn_to_first_home_present",
    "stimulus_to_hello_present",
    "stimulus_to_notes_present",
    "stimulus_to_cancel_kept_notes_present",
    "stimulus_to_private_present",
    "stimulus_to_crash_focus_present",
    "stimulus_to_app_stopped_present",
    "stimulus_to_relaunched_without_grant_present",
    "stimulus_to_regranted_notes_present",
    "stimulus_to_shell_restored_present",
];

/// Separate acceptance after evidence retention and functional conformance.
/// Invalid metrics remain in the original file so a failed run is reviewable.
pub(crate) fn validate_performance(directory: &Path) -> Result<Value> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Interval {
        earliest_ns: u64,
        latest_ns: u64,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Timing {
        wall_min_ns: u64,
        wall_max_ns: u64,
        active_min_ns: u64,
        active_max_ns: u64,
        excluded_pause_min_ns: u64,
        excluded_pause_max_ns: u64,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Record {
        name: String,
        begin: Interval,
        end: Interval,
        valid: bool,
        timing: Timing,
        error: Value,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Performance {
        schema: u32,
        clock: String,
        scope: String,
        records: Vec<Record>,
    }
    let bytes = bounded(&directory.join("performance.json"))?;
    // Typed decoding rejects missing/duplicate fields, negative/fractional
    // durations, unknown schema fields and a null/incomplete timing payload.
    let proof: Performance =
        serde_json::from_slice(&bytes).map_err(|e| format!("desktop performance record: {e}"))?;
    if proof.schema != 1
        || proof.clock != PERFORMANCE_CLOCK
        || proof.scope != PERFORMANCE_SCOPE
        || proof.records.len() != FRAME_METRICS.len()
    {
        return Err("desktop performance schema/context or ten Frame metrics absent".into());
    }
    let mut previous_end = None;
    for (record, expected) in proof.records.iter().zip(FRAME_METRICS) {
        let b = &record.begin;
        let e = &record.end;
        let t = &record.timing;
        if record.name != expected || !record.valid || !record.error.is_null() {
            return Err(format!(
                "desktop performance invalid/replayed Frame metric: {expected}"
            ));
        }
        if b.earliest_ns > b.latest_ns
            || e.earliest_ns > e.latest_ns
            || b.earliest_ns > e.earliest_ns
            || b.latest_ns > e.latest_ns
            || previous_end.is_some_and(|end| b.earliest_ns < end)
        {
            return Err(format!(
                "desktop performance unordered event brackets: {expected}"
            ));
        }
        let wall_min = e.earliest_ns.saturating_sub(b.latest_ns);
        let wall_max = e.latest_ns - b.earliest_ns;
        if t.wall_min_ns != wall_min
            || t.wall_max_ns != wall_max
            || t.excluded_pause_min_ns > t.excluded_pause_max_ns
            || t.excluded_pause_min_ns > wall_min
            || t.excluded_pause_max_ns > wall_max
            || t.active_min_ns != wall_min.saturating_sub(t.excluded_pause_max_ns)
            || t.active_max_ns != wall_max - t.excluded_pause_min_ns
            || t.active_min_ns > t.active_max_ns
        {
            return Err(format!(
                "desktop performance inconsistent wall/active/pause bounds: {expected}"
            ));
        }
        previous_end = Some(e.latest_ns);
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("desktop performance JSON: {e}"))
}
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn bounded(path: &Path) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > OUTPUT_LIMIT {
        return Err("desktop log is nonregular or exceeds1MiB".into());
    }
    let mut b = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(OUTPUT_LIMIT + 1)
        .read_to_end(&mut b)
        .map_err(|e| e.to_string())?;
    if b.len() as u64 > OUTPUT_LIMIT {
        return Err("desktop log grew beyond1MiB".into());
    }
    Ok(b)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Home,
    Hello,
    NotesHeld,
    Notes,
    CancelPicker,
    CancelNotes,
    PrivateInitialPicker,
    PrivateHeld,
    Private,
    CrashFocus,
    AppStopped,
    Relaunched,
    RegrantHeld,
    RegrantedNotes,
    ShellRestored,
    Done,
}
impl Stage {
    fn name(self) -> &'static str {
        match self {
            Self::Home => "home",
            Self::Hello => "hello",
            Self::NotesHeld => "notes_held_no_grant",
            Self::Notes => "notes",
            Self::CancelPicker => "cancel_picker",
            Self::CancelNotes => "cancel_kept_notes",
            Self::PrivateInitialPicker => "private_initial_picker",
            Self::PrivateHeld => "private_held_no_grant",
            Self::Private => "private",
            Self::CrashFocus => "crash_focus",
            Self::AppStopped => "app_stopped",
            Self::Relaunched => "relaunched_without_grant",
            Self::RegrantHeld => "regrant_held",
            Self::RegrantedNotes => "regranted_notes",
            Self::ShellRestored => "shell_restored",
            Self::Done => "done",
        }
    }
    fn grants(self) -> u64 {
        match self {
            Self::Home | Self::Hello | Self::NotesHeld => 0,
            Self::Notes
            | Self::CancelPicker
            | Self::CancelNotes
            | Self::PrivateInitialPicker
            | Self::PrivateHeld => 1,
            Self::Private
            | Self::CrashFocus
            | Self::AppStopped
            | Self::Relaunched
            | Self::RegrantHeld => 2,
            Self::RegrantedNotes | Self::ShellRestored | Self::Done => 3,
        }
    }
    fn expected(self, native: bool) -> Result<(StepKind, Producer, Reference)> {
        let (kind, producer, screen, content, focus) = match self {
            Self::Home => (
                StepKind::Frame,
                Producer::Shell,
                Screen::Home,
                None,
                HelloControl::OpenFile,
            ),
            Self::Hello | Self::Relaunched => (
                StepKind::Frame,
                Producer::App,
                Screen::AppRunning,
                None,
                HelloControl::OpenFile,
            ),
            Self::NotesHeld | Self::RegrantHeld => (
                StepKind::PickerHeld,
                Producer::Shell,
                Screen::Picker {
                    selected: FileChoice::Notes,
                },
                None,
                HelloControl::OpenFile,
            ),
            Self::CancelPicker | Self::PrivateInitialPicker => (
                StepKind::PickerReady,
                Producer::Shell,
                Screen::Picker {
                    selected: FileChoice::Notes,
                },
                None,
                HelloControl::OpenFile,
            ),
            Self::PrivateHeld => (
                StepKind::PickerHeld,
                Producer::Shell,
                Screen::Picker {
                    selected: FileChoice::Private,
                },
                None,
                HelloControl::OpenFile,
            ),
            Self::Notes | Self::CancelNotes | Self::RegrantedNotes | Self::ShellRestored => (
                StepKind::Frame,
                Producer::App,
                Screen::AppRunning,
                Some(ev_file::desktop::SEED_NOTES),
                HelloControl::OpenFile,
            ),
            Self::Private => (
                StepKind::Frame,
                Producer::App,
                Screen::AppRunning,
                Some(ev_file::desktop::SEED_PRIVATE),
                HelloControl::OpenFile,
            ),
            Self::CrashFocus => (
                StepKind::Frame,
                Producer::App,
                Screen::AppRunning,
                Some(ev_file::desktop::SEED_PRIVATE),
                HelloControl::CrashMe,
            ),
            Self::AppStopped => (
                StepKind::Frame,
                Producer::Shell,
                Screen::AppStopped,
                None,
                HelloControl::OpenFile,
            ),
            Self::Done => return Err("desktop scenario already completed".into()),
        };
        let app = (screen == Screen::AppRunning).then_some(HelloView {
            focus,
            content,
            incarnation: 1,
        });
        let reference = if native {
            Reference::native(
                screen,
                app.map(|hello| ev_graphics::native::View {
                    hello,
                    build: ev_graphics::native::Build::A,
                    saved_value: 1001,
                }),
            )?
        } else {
            Reference::new(screen, app)?
        };
        Ok((kind, producer, reference))
    }
    fn next(self) -> Self {
        match self {
            Self::Home => Self::Hello,
            Self::Hello => Self::NotesHeld,
            Self::NotesHeld => Self::Notes,
            Self::Notes => Self::CancelPicker,
            Self::CancelPicker => Self::CancelNotes,
            Self::CancelNotes => Self::PrivateInitialPicker,
            Self::PrivateInitialPicker => Self::PrivateHeld,
            Self::PrivateHeld => Self::Private,
            Self::Private => Self::CrashFocus,
            Self::CrashFocus => Self::AppStopped,
            Self::AppStopped => Self::Relaunched,
            Self::Relaunched => Self::RegrantHeld,
            Self::RegrantHeld => Self::RegrantedNotes,
            Self::RegrantedNotes => Self::ShellRestored,
            Self::ShellRestored | Self::Done => Self::Done,
        }
    }
}
pub(crate) struct Observer {
    stage: Stage,
    seen: usize,
    timeline: Timeline,
    qmp: Option<Qmp>,
    captures: Vec<Value>,
    inputs: Vec<Value>,
    started: Instant,
    first_app: Option<u64>,
    current_app: Option<u64>,
    first_shell: Option<u64>,
    capture_index: u32,
    native: bool,
    finish_attempts: u8,
    last_finish_report: u64,
    defer_finish: bool,
    spawn: Option<crate::perf_ledger::Bracket>,
    stimulus: Option<crate::perf_ledger::Bracket>,
    last_poll_start: u64,
    metrics: Vec<(
        String,
        crate::perf_ledger::Bracket,
        crate::perf_ledger::Bracket,
    )>,
}
impl Observer {
    fn new(native: bool) -> Self {
        Self {
            stage: Stage::Home,
            seen: 0,
            timeline: Timeline::default(),
            qmp: None,
            captures: Vec::new(),
            inputs: Vec::new(),
            started: Instant::now(),
            first_app: None,
            current_app: None,
            first_shell: None,
            capture_index: 0,
            native,
            finish_attempts: 0,
            last_finish_report: 0,
            defer_finish: false,
            spawn: None,
            stimulus: None,
            last_poll_start: 0,
            metrics: Vec::new(),
        }
    }
    pub(crate) fn composed() -> Self {
        let mut value = Self::new(true);
        value.defer_finish = true;
        value
    }
    pub(crate) fn done(&self) -> bool {
        self.stage == Stage::Done
    }
    fn elapsed(&self, at: Instant) -> Result<u64> {
        crate::perf_ledger::elapsed_ns(self.started, at)
            .map_err(|e| format!("desktop monotonic clock: {e:?}"))
    }
    pub(crate) fn spawned(&mut self, before: Instant, after: Instant) -> Result<()> {
        self.spawn = Some(
            crate::perf_ledger::Bracket::new(self.elapsed(before)?, self.elapsed(after)?)
                .map_err(|e| format!("desktop spawn bracket: {e:?}"))?,
        );
        Ok(())
    }
    fn metric_record(&self) -> Value {
        json!({"schema":1,"clock":PERFORMANCE_CLOCK,"scope":PERFORMANCE_SCOPE,"records":self.metrics.iter().map(|(name,begin,end)|{
            let result=self.qmp.as_ref().ok_or("QMP absent".to_string()).and_then(|q|q.timing(*begin,*end));
            json!({"name":name,"begin":{"earliest_ns":begin.earliest_ns,"latest_ns":begin.latest_ns},"end":{"earliest_ns":end.earliest_ns,"latest_ns":end.latest_ns},"valid":result.is_ok(),"timing":result.as_ref().ok(),"error":result.as_ref().err()})
        }).collect::<Vec<_>>()})
    }
    pub(crate) fn retain(&self, directory: &Path, status: &Result<ExitStatus>) -> Result<()> {
        storage::json_new(&directory.join("performance.json"), &self.metric_record())?;
        storage::json_new(
            &directory.join("qmp-transcript.json"),
            &json!({"schema":1,"exchanges":self.qmp.as_ref().map(|q|q.transcript()).unwrap_or(&[])}),
        )?;
        storage::json_new(
            &directory.join("desktop-observer.json"),
            &json!({"schema":1,"passed":status.as_ref().is_ok_and(|s|s.code()==Some(ev_test_protocol::QEMU_PASS_STATUS)),"last_stage":self.stage.name(),"error":status.as_ref().err(),"checkpoints":self.seen,"captures":self.captures,"inputs":self.inputs,"first_app":self.first_app,"current_app":self.current_app,"initial_shell":self.first_shell,"method":"Actual protected Present/Input receipts and unmodified QMP scanout; real make/break and owned UART test stimuli."}),
        )
    }
    fn key(&mut self, key: Key, down: bool) -> Result<()> {
        self.qmp
            .as_mut()
            .ok_or("desktop QMP not connected")?
            .key_state(key, down)?;
        self.inputs.push(json!({"elapsed_ms":self.started.elapsed().as_millis(),"stage":self.stage.name(),"device":"QEMU keyboard","key":format!("{key:?}"),"down":down}));
        Ok(())
    }
    fn tap(&mut self, key: Key) -> Result<()> {
        self.key(key, true)?;
        self.key(key, false)
    }
    fn approve(&mut self) -> Result<()> {
        self.key(Key::Enter, false)?;
        self.tap(Key::Enter)
    }
    fn uart(&mut self, stdin: &mut ChildStdin, bytes: &[u8], action: &str) -> Result<()> {
        stdin
            .write_all(bytes)
            .and_then(|()| stdin.flush())
            .map_err(|e| format!("owned Native UART input: {e}"))?;
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        self.inputs.push(json!({"elapsed_ms":self.started.elapsed().as_millis(),"stage":self.stage.name(),"device":"owned QEMU UART","bytes_hex":hex,"action":action}));
        Ok(())
    }
    fn action(&mut self, stdin: &mut ChildStdin) -> Result<()> {
        match self.stage {
            Stage::Home if self.native => self.uart(
                stdin,
                b"install a\nactivate\n",
                "explicit native install/activation",
            )?,
            Stage::Home | Stage::AppStopped => self.approve()?,
            Stage::Hello | Stage::Notes | Stage::CancelNotes | Stage::Relaunched => {
                self.key(Key::Enter, true)?
            }
            Stage::NotesHeld | Stage::PrivateHeld | Stage::RegrantHeld => self.approve()?,
            Stage::CancelPicker => {
                self.tap(Key::Escape)?;
                self.key(Key::Enter, false)?;
            }
            Stage::PrivateInitialPicker | Stage::Private => self.tap(Key::Tab)?,
            Stage::CrashFocus => self.tap(Key::Enter)?,
            Stage::RegrantedNotes if self.native => {
                self.uart(stdin, b"crash shell\n", "explicit Shell fault diagnostic")?
            }
            Stage::ShellRestored if self.native => {
                if !self.defer_finish {
                    self.uart(stdin, b"finish\n", "request Native owned retirement")?;
                    self.finish_attempts = 1;
                }
            }
            Stage::RegrantedNotes => {
                stdin
                    .write_all(b"s")
                    .and_then(|()| stdin.flush())
                    .map_err(|e| format!("desktop owned UART input: {e}"))?;
                self.inputs.push(json!({"elapsed_ms":self.started.elapsed().as_millis(),"stage":self.stage.name(),"device":"owned QEMU UART","bytes_hex":"73","action":"request actual Shell fault"}));
            }
            Stage::ShellRestored | Stage::Done => {}
        }
        Ok(())
    }
    pub(crate) fn observe(
        &mut self,
        bytes: &[u8],
        build: &str,
        directory: &Path,
        deadline: Instant,
        stdin: &mut ChildStdin,
        read_before: Instant,
    ) -> Result<()> {
        let poll_end = self.elapsed(Instant::now())?;
        let steps = desktop_protocol::steps(bytes, build)?;
        if steps.len() < self.seen {
            return Err("desktop serial history truncated".into());
        }
        for step in &steps[self.seen..] {
            self.timeline.observe(step)?;
            if self.stage == Stage::Done {
                continue;
            }
            if step.grants > self.stage.grants() {
                return Err(
                    "actual grant advanced before the required fresh approval stimulus".into(),
                );
            }
            let (kind, producer, reference) = self.stage.expected(self.native)?;
            if step.kind != kind || step.producer != producer || step.grants != self.stage.grants()
            {
                continue;
            }
            if self.stage == Stage::Home && step.app_process != 0 {
                continue;
            }
            if self.stage == Stage::Relaunched && Some(step.app_process) == self.first_app {
                continue;
            }
            if self.stage == Stage::ShellRestored
                && (Some(step.shell_process) == self.first_shell
                    || Some(step.app_process) != self.current_app)
            {
                continue;
            }
            if reference.surface_hash(producer, step.frame)? != step.surface_sha256 {
                continue;
            }
            if self.qmp.is_none() {
                crate::boot::check_desktop_prefix(bytes, build)?;
                self.qmp = Some(Qmp::connect_at(directory, deadline, self.started)?);
            }
            self.capture_index = self
                .capture_index
                .checked_add(1)
                .ok_or("desktop capture index exhausted")?;
            if self.capture_index > 64 {
                return Err("desktop capture bound64 exceeded".into());
            }
            // Freeze only the owned VM after a validated actual receipt. The
            // reference never supplies pixels, and paused host work cannot
            // satisfy the guest's independently measured held64tick interval.
            self.qmp.as_mut().unwrap().set_running(false)?;
            let (path, frame) = self.qmp.as_mut().unwrap().capture(self.capture_index)?;
            if frame.dimensions() != (step.width, step.height) {
                return Err("desktop actual QMP geometry differs from actual Present".into());
            }
            let validation = reference.validate(&frame);
            self.captures.push(json!({"stage":self.stage.name(),"step":step,"path":path.file_name().ok_or("desktop scanout has no filename")?,"sha256":build::hash_file(&path)?,"passed":validation.is_ok(),"validation":validation.as_ref().ok(),"transient_mismatch":validation.as_ref().err()}));
            // QEMU requires a running VM for input-send-event. Resume after
            // verification, before emitting the explicitly recorded stimulus.
            self.qmp.as_mut().unwrap().set_running(true)?;
            if validation.is_err() {
                continue;
            }
            if self.first_shell.is_none() {
                self.first_shell = Some(step.shell_process);
            }
            if self.stage == Stage::Hello {
                self.first_app = Some(step.app_process);
                self.current_app = self.first_app;
            }
            if self.stage == Stage::Relaunched {
                self.current_app = Some(step.app_process);
            }
            let begin = if self.stage == Stage::Home {
                self.spawn
            } else {
                self.stimulus
            };
            if let Some(begin) = begin
                && kind == StepKind::Frame
            {
                let end = crate::perf_ledger::Bracket::new(
                    self.last_poll_start.max(begin.earliest_ns),
                    poll_end,
                )
                .map_err(|e| format!("desktop receipt bracket: {e:?}"))?;
                self.metrics.push((
                    if self.stage == Stage::Home {
                        "owned_spawn_to_first_home_present".into()
                    } else {
                        format!("stimulus_to_{}_present", self.stage.name())
                    },
                    begin,
                    end,
                ));
            }
            let input_before = self.elapsed(Instant::now())?;
            self.action(stdin)?;
            self.stimulus = Some(
                crate::perf_ledger::Bracket::new(input_before, self.elapsed(Instant::now())?)
                    .map_err(|e| format!("desktop input bracket: {e:?}"))?,
            );
            self.stage = self.stage.next();
        }
        self.seen = steps.len();
        self.last_poll_start = self.elapsed(read_before)?;
        if self.native && !self.defer_finish && self.stage == Stage::Done {
            for state in crate::native_protocol::states(bytes, build)? {
                let report = state.number("report")?;
                if state.fields["op"] == "finish" && report > self.last_finish_report {
                    self.last_finish_report = report;
                    if state.fields["result"] == "busy" {
                        if self.finish_attempts >= 8 {
                            return Err(
                                "Native finish remains busy after8 explicit refusals".into()
                            );
                        }
                        self.uart(
                            stdin,
                            b"finish\n",
                            "resubmit only after complete Busy refusal",
                        )?;
                        self.finish_attempts += 1;
                    }
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn supervise(
    command: &mut Command,
    serial: &Path,
    errors: &Path,
    timeout: Duration,
    build: &str,
    directory: &Path,
) -> Result<ExitStatus> {
    supervise_mode(command, serial, errors, timeout, build, directory, false)
}
pub(crate) fn supervise_native_full(
    command: &mut Command,
    serial: &Path,
    errors: &Path,
    timeout: Duration,
    build: &str,
    directory: &Path,
) -> Result<ExitStatus> {
    supervise_mode(command, serial, errors, timeout, build, directory, true)
}
#[allow(clippy::too_many_arguments)]
fn supervise_mode(
    command: &mut Command,
    serial: &Path,
    errors: &Path,
    timeout: Duration,
    build: &str,
    directory: &Path,
    native: bool,
) -> Result<ExitStatus> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or("desktop absolute deadline overflow")?;
    let mut observer = Observer::new(native);
    let result = (|| {
        if Instant::now() >= deadline {
            return Err("desktop deadline elapsed before spawn".into());
        }
        let spawn_before = Instant::now();
        let mut child = OwnedChild(
            command
                .stdin(Stdio::piped())
                .spawn()
                .map_err(|e| format!("desktop QEMU spawn: {e}"))?,
        );
        observer.spawned(spawn_before, Instant::now())?;
        let mut stdin = child
            .0
            .stdin
            .take()
            .ok_or("desktop owned UART stdin missing")?;
        loop {
            if Instant::now() >= deadline {
                return Err("desktop absolute deadline elapsed".into());
            }
            let read_before = Instant::now();
            let bytes = bounded(serial)?;
            let _ = bounded(errors)?;
            observer.observe(&bytes, build, directory, deadline, &mut stdin, read_before)?;
            if let Some(status) = child.0.try_wait().map_err(|e| e.to_string())? {
                if observer.stage != Stage::Done {
                    return Err(format!(
                        "owned desktop QEMU exited before stage {}",
                        observer.stage.name()
                    ));
                }
                return Ok(status);
            }
            thread::sleep(
                Duration::from_millis(4).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    })();
    storage::json_new(
        &directory.join("performance.json"),
        &observer.metric_record(),
    )?;
    storage::json_new(
        &directory.join("qmp-transcript.json"),
        &json!({"schema":1,"exchanges":observer.qmp.as_ref().map(|q|q.transcript()).unwrap_or(&[])}),
    )?;
    storage::json_new(
        &directory.join("desktop-observer.json"),
        &json!({"schema":1,"passed":result.as_ref().is_ok_and(|s|s.code()==Some(ev_test_protocol::QEMU_PASS_STATUS)),"qemu_exit_status":result.as_ref().ok().and_then(|s|s.code()),"last_stage":observer.stage.name(),"error":result.as_ref().err(),"checkpoints":observer.seen,"captures":observer.captures,"inputs":observer.inputs,"first_app":observer.first_app,"current_app":observer.current_app,"initial_shell":observer.first_shell,"method":"Actual unmodified QMP scanout. Explicit real-device make/break and owned UART input; guest protected Present/Input receipts and >=64actualguesttick held no-grant checkpoint. Host references verify pixels; metadata never mints authority."}),
    )?;
    result
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    fn directory() -> std::path::PathBuf {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let parent = storage::directory_beneath(&root, Path::new("build/test-tmp")).unwrap();
        build::unique_directory(&parent, "desktop-owned-lifecycle").unwrap()
    }
    fn performance_fixture() -> Value {
        use crate::perf_ledger::{Bracket, Ledger};
        let mut ledger = Ledger::new();
        let records: Vec<_> = FRAME_METRICS
            .into_iter()
            .enumerate()
            .map(|(index, name)| {
                let offset = index as u64 * 1000;
                let begin = Bracket::new(offset + 10, offset + 20).unwrap();
                let end = Bracket::new(offset + 110, offset + 125).unwrap();
                ledger.stop_sent(offset + 40).unwrap();
                ledger.stopped_confirmed(offset + 45).unwrap();
                ledger.resume_sent(offset + 75).unwrap();
                ledger.running_confirmed(offset + 80).unwrap();
                let timing = ledger.measure(begin, end).unwrap();
                json!({"name":name,"begin":{"earliest_ns":begin.earliest_ns,"latest_ns":begin.latest_ns},"end":{"earliest_ns":end.earliest_ns,"latest_ns":end.latest_ns},"valid":true,"timing":timing,"error":null})
            })
            .collect();
        json!({"schema":1,"clock":PERFORMANCE_CLOCK,"scope":PERFORMANCE_SCOPE,"records":records})
    }
    fn validate_value(value: &Value) -> Result<Value> {
        let d = directory();
        let path = d.join("performance.json");
        let bytes = serde_json::to_vec(value).unwrap();
        fs::write(&path, &bytes).unwrap();
        let result = validate_performance(&d);
        assert_eq!(
            fs::read(path).unwrap(),
            bytes,
            "validator changed retained evidence"
        );
        result
    }
    #[test]
    fn performance_accepts_complete_actual_ledger_ranges_for_exact_frame_stages() {
        let value = performance_fixture();
        assert_eq!(validate_value(&value).unwrap(), value);
        let mut zero_lower = value;
        let r = &mut zero_lower["records"][0];
        let begin = crate::perf_ledger::Bracket::new(10, 120).unwrap();
        let end = crate::perf_ledger::Bracket::new(110, 125).unwrap();
        r["begin"]["latest_ns"] = json!(120);
        r["timing"] = serde_json::to_value(
            crate::perf_ledger::Ledger::new()
                .measure(begin, end)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(validate_value(&zero_lower).unwrap(), zero_lower);
    }
    #[test]
    fn performance_rejects_empty_missing_duplicate_reordered_and_invalid_records() {
        let good = performance_fixture();
        let mut cases = Vec::new();
        for schema in [0, 2] {
            let mut v = good.clone();
            v["schema"] = json!(schema);
            cases.push(v);
        }
        let mut v = good.clone();
        v["records"] = json!([]);
        cases.push(v);
        let mut v = good.clone();
        v["records"].as_array_mut().unwrap().remove(4);
        cases.push(v);
        let mut v = good.clone();
        v["records"][4] = good["records"][3].clone();
        cases.push(v);
        let mut v = good.clone();
        v["records"]
            .as_array_mut()
            .unwrap()
            .push(good["records"][0].clone());
        cases.push(v);
        let mut v = good.clone();
        v["records"].as_array_mut().unwrap().swap(1, 2);
        cases.push(v);
        for (key, value) in [
            ("valid", json!(false)),
            ("error", json!("incomplete QMP pause")),
            ("timing", Value::Null),
        ] {
            let mut v = good.clone();
            v["records"][0][key] = value;
            cases.push(v);
        }
        for key in ["name", "begin", "end", "valid", "timing", "error"] {
            let mut v = good.clone();
            v["records"][0].as_object_mut().unwrap().remove(key);
            cases.push(v);
        }
        for key in ["clock", "scope"] {
            let mut v = good.clone();
            v[key] = json!("foreign clock/context");
            cases.push(v);
        }
        let mut v = good.clone();
        v["records"][0]["extra"] = json!(true);
        cases.push(v);
        for value in cases {
            assert!(validate_value(&value).is_err(), "accepted {value}");
        }
    }
    #[test]
    fn performance_rejects_negative_reversed_and_inconsistent_interval_arithmetic() {
        let good = performance_fixture();
        let mut cases = Vec::new();
        for (section, key, value) in [
            ("begin", "earliest_ns", json!(-1)),
            ("begin", "latest_ns", json!(9)),
            ("begin", "earliest_ns", json!(130)),
            ("end", "earliest_ns", json!(126)),
            ("end", "latest_ns", json!(19)),
            ("timing", "wall_min_ns", json!(-1)),
            ("timing", "wall_min_ns", json!(89)),
            ("timing", "wall_max_ns", json!(114)),
            ("timing", "active_min_ns", json!(51)),
            ("timing", "active_max_ns", json!(84)),
            ("timing", "excluded_pause_min_ns", json!(41)),
            ("timing", "excluded_pause_max_ns", json!(116)),
            ("timing", "wall_min_ns", json!(0.5)),
        ] {
            let mut v = good.clone();
            v["records"][0][section][key] = value;
            cases.push(v);
        }
        let mut v = good.clone();
        v["records"][1]["begin"] = good["records"][0]["begin"].clone();
        v["records"][1]["end"] = good["records"][0]["end"].clone();
        v["records"][1]["timing"] = good["records"][0]["timing"].clone();
        cases.push(v);
        let mut v = good.clone();
        v["records"][0]["timing"]["excluded_pause_min_ns"] = json!(91);
        v["records"][0]["timing"]["excluded_pause_max_ns"] = json!(100);
        cases.push(v);
        for value in cases {
            assert!(validate_value(&value).is_err(), "accepted {value}");
        }
    }
    #[test]
    fn performance_refuses_missing_nonregular_oversized_truncated_and_duplicate_field_files() {
        let d = directory();
        let path = d.join("performance.json");
        assert!(validate_performance(&d).is_err());
        fs::create_dir(&path).unwrap();
        assert!(validate_performance(&d).is_err());
        fs::remove_dir(&path).unwrap();
        let good = serde_json::to_vec(&performance_fixture()).unwrap();
        for bytes in [
            Vec::new(),
            good[..good.len() - 1].to_vec(),
            vec![b' '; OUTPUT_LIMIT as usize + 1],
            String::from_utf8(good.clone())
                .unwrap()
                .replacen("\"schema\":1", "\"schema\":1,\"schema\":1", 1)
                .into_bytes(),
        ] {
            fs::write(&path, &bytes).unwrap();
            assert!(validate_performance(&d).is_err());
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
        fs::remove_file(&path).unwrap();
        let target = d.join("actual.json");
        fs::write(&target, good).unwrap();
        std::os::unix::fs::symlink(target, &path).unwrap();
        assert!(validate_performance(&d).is_err());
    }
    #[test]
    fn missing_guest_checkpoints_and_deadline_never_leave_the_owned_child_alive() {
        for wait in [false, true] {
            let d = directory();
            let serial = d.join("serial");
            let errors = d.join("stderr");
            let pid = d.join("pid");
            fs::write(&serial, []).unwrap();
            fs::write(&errors, []).unwrap();
            let mut cmd = Command::new("python3");
            cmd.args(["-c","import pathlib,os,sys,time; pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(float(sys.argv[2]))"]).arg(&pid).arg(if wait{"30"}else{"0"}).stdout(Stdio::null()).stderr(Stdio::null());
            let error = supervise(
                &mut cmd,
                &serial,
                &errors,
                Duration::from_millis(300),
                &"a".repeat(64),
                &d,
            )
            .unwrap_err();
            assert!(error.contains(if wait { "deadline" } else { "before stage" }));
            let id = fs::read_to_string(pid).unwrap();
            assert!(!Path::new("/proc").join(id).exists());
            let record: Value =
                serde_json::from_slice(&fs::read(d.join("desktop-observer.json")).unwrap())
                    .unwrap();
            assert_eq!(record["passed"], false);
            assert_eq!(record["last_stage"], "home");
            assert_eq!(record["captures"].as_array().unwrap().len(), 0);
        }
    }
    #[test]
    fn scenario_requires_cancel_fresh_regrant_and_new_shell_while_reusing_display() {
        let mut stage = Stage::Home;
        let mut names = Vec::new();
        let mut frame_metrics = Vec::new();
        while stage != Stage::Done {
            let (kind, _, _) = stage.expected(false).unwrap();
            if kind == StepKind::Frame {
                frame_metrics.push(if stage == Stage::Home {
                    "owned_spawn_to_first_home_present".into()
                } else {
                    format!("stimulus_to_{}_present", stage.name())
                });
            }
            names.push(stage.name());
            stage = stage.next();
            assert!(names.len() <= 16);
        }
        assert_eq!(names.len(), 15);
        assert_eq!(frame_metrics, FRAME_METRICS);
        for required in [
            "notes_held_no_grant",
            "cancel_kept_notes",
            "private_held_no_grant",
            "relaunched_without_grant",
            "regrant_held",
            "shell_restored",
        ] {
            assert!(names.contains(&required));
        }
        assert_eq!(Stage::NotesHeld.grants(), 0);
        assert_eq!(Stage::PrivateHeld.grants(), 1);
        assert_eq!(Stage::RegrantHeld.grants(), 2);
        assert_eq!(Stage::ShellRestored.grants(), 3);
    }
}
