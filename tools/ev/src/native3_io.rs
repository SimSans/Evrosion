//! Owned Native3 cold-VM inputs. Every action follows a complete source/Kernel
//! receipt; host pixel references only inspect actual guest scanout.
use crate::{
    build::{self, Result},
    desktop_protocol::{self, Producer, Reference, StepKind},
    qmp::{Key, Qmp},
    storage,
};
use ev_diagnostics::{
    owner::{Action, Phase as OwnerPhase},
    system::{Phase as HealthPhase, Snapshot},
};
use ev_graphics::{
    HelloControl, HelloView,
    native::{Build, View},
    shell::{FileChoice, Screen},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    SystemFull,
    SystemBad,
    SystemGoodStage,
    SystemRecovery,
    SystemFinal,
    GrantRemember,
    GrantCold,
    GrantRevoke,
    GrantRefused,
}
impl Phase {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::SystemFull => "system-full",
            Self::SystemBad => "system-bad",
            Self::SystemGoodStage => "system-good-stage",
            Self::SystemRecovery => "system-recovery",
            Self::SystemFinal => "system-final",
            Self::GrantRemember => "grant-remember",
            Self::GrantCold => "grant-cold",
            Self::GrantRevoke => "grant-revoke",
            Self::GrantRefused => "grant-refused",
        }
    }
    pub(crate) fn fixture(self) -> &'static str {
        match self {
            Self::SystemRecovery => "m5-native-recovery",
            Self::SystemFull | Self::SystemBad | Self::SystemGoodStage | Self::SystemFinal => {
                "m5-native-system"
            }
            _ => "m5-native",
        }
    }
    pub(crate) fn recovery(self) -> bool {
        self == Self::SystemRecovery
    }
}
struct Owned(Child);
impl Drop for Owned {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn log(path: &Path) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !m.is_file() || m.file_type().is_symlink() || m.len() > 1024 * 1024 {
        return Err("Native3 log nonregular/oversized".into());
    }
    let mut out = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut out)
        .map_err(|e| e.to_string())?;
    if out.len() > 1024 * 1024 {
        return Err("Native3 log grew beyond bound".into());
    }
    Ok(out)
}
fn systems(serial: &[u8], build: &str) -> Result<Vec<Snapshot>> {
    let text = std::str::from_utf8(serial).map_err(|_| "Native3 serial notUTF8")?;
    let mut out = Vec::new();
    for line in text
        .split_inclusive('\n')
        .filter(|l| l.ends_with('\n'))
        .map(|l| l.trim_end_matches(['\r', '\n']))
        .filter(|l| l.starts_with("EVROSION_NATIVE_SYSTEM "))
    {
        crate::native_diagnostics::line(line, build)?;
        let hex = line
            .split(' ')
            .next_back()
            .and_then(|s| s.strip_prefix("bytes="))
            .ok_or("Native3 System bytes absent")?;
        let mut bytes = [0; 384];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
        }
        out.push(Snapshot::decode(&bytes).map_err(|e| format!("Native3 System snapshot: {e:?}"))?);
    }
    Ok(out)
}
fn app(content: Option<&[u8]>) -> Result<Reference> {
    Reference::native(
        Screen::AppRunning,
        Some(View {
            hello: HelloView {
                focus: HelloControl::OpenFile,
                content,
                incarnation: 1,
            },
            build: Build::A,
            saved_value: 1001,
        }),
    )
}
struct Observer {
    phase: Phase,
    stage: u8,
    seen: usize,
    started: Instant,
    qmp: Option<Qmp>,
    captures: Vec<Value>,
    inputs: Vec<Value>,
    capture: u32,
    full: Option<crate::desktop_io::Observer>,
    finish_report: u64,
    finish_attempts: u8,
    prompt: Option<u64>,
    initial_app: Option<u64>,
    initialize_after_report: u64,
}
impl Observer {
    fn new(phase: Phase) -> Self {
        Self {
            phase,
            stage: 0,
            seen: 0,
            started: Instant::now(),
            qmp: None,
            captures: Vec::new(),
            inputs: Vec::new(),
            capture: 0,
            full: (phase == Phase::SystemFull).then(crate::desktop_io::Observer::composed),
            finish_report: 0,
            finish_attempts: 0,
            prompt: None,
            initial_app: None,
            initialize_after_report: 0,
        }
    }
    fn uart(&mut self, input: &mut impl Write, bytes: &[u8], purpose: &str) -> Result<()> {
        input
            .write_all(bytes)
            .and_then(|()| input.flush())
            .map_err(|e| e.to_string())?;
        self.inputs.push(json!({"elapsed_ms":self.started.elapsed().as_millis(),"stage":self.stage,"device":"owned QEMU UART","bytes_hex":bytes.iter().map(|b|format!("{b:02x}")).collect::<String>(),"purpose":purpose}));
        Ok(())
    }
    fn key(&mut self, key: Key, down: bool) -> Result<()> {
        self.qmp
            .as_mut()
            .ok_or("Native3 QMP absent")?
            .key_state(key, down)?;
        self.inputs.push(json!({"elapsed_ms":self.started.elapsed().as_millis(),"stage":self.stage,"device":"QEMU keyboard","key":format!("{key:?}"),"down":down}));
        Ok(())
    }
    fn tap(&mut self, key: Key) -> Result<()> {
        self.key(key, true)?;
        self.key(key, false)
    }
    fn open_app_file(&mut self) -> Result<()> {
        if self.phase == Phase::GrantRefused {
            // This phase verifies a held Enter cannot approve after revocation.
            // Keep the actual make held across Present/Input barrier +64ticks.
            self.key(Key::Enter, true)
        } else {
            self.tap(Key::Enter)
        }
    }
    fn cancel_refused_picker(&mut self, step: &desktop_protocol::Step) -> Result<()> {
        if self.phase != Phase::GrantRefused
            || self.stage != 2
            || step.kind != StepKind::PickerHeld
            || step.producer != Producer::Shell
            || step.grants != 0
            || step.held_ticks < 64
            || self.initial_app != Some(step.app_process)
        {
            return Err("Native3 refused picker lacks actual held no-grant checkpoint".into());
        }
        self.key(Key::Enter, false)?;
        self.tap(Key::Escape)?;
        self.stage = 3;
        Ok(())
    }
    fn scanout(
        &mut self,
        bytes: &[u8],
        build: &str,
        directory: &Path,
        deadline: Instant,
        step: &desktop_protocol::Step,
        reference: Reference,
    ) -> Result<bool> {
        if reference.surface_hash(step.producer, step.frame)? != step.surface_sha256 {
            return Ok(false);
        }
        if self.qmp.is_none() {
            crate::boot::check_desktop_prefix(bytes, build)?;
            self.qmp = Some(Qmp::connect(directory, deadline)?);
        }
        self.capture += 1;
        if self.capture > 64 {
            return Err("Native3 capture bound exceeded".into());
        }
        let qmp = self.qmp.as_mut().unwrap();
        qmp.set_running(false)?;
        let (path, frame) = qmp.capture(self.capture)?;
        if frame.dimensions() != (step.width, step.height) {
            return Err("Native3 actual Present/scanout geometry differs".into());
        }
        let validation = reference.validate(&frame);
        self.captures.push(json!({"stage":self.stage,"step":step,"path":path.file_name(),"sha256":build::hash_file(&path)?,"passed":validation.is_ok(),"validation":validation.as_ref().ok(),"transient_mismatch":validation.as_ref().err()}));
        qmp.set_running(true)?;
        Ok(validation.is_ok())
    }
    fn finish(&mut self, input: &mut impl Write) -> Result<()> {
        self.uart(input, b"finish\n", "request ordinary Root/graph retirement")?;
        self.finish_attempts += 1;
        self.stage = 250;
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    fn observe(
        &mut self,
        bytes: &[u8],
        build: &str,
        directory: &Path,
        deadline: Instant,
        input: &mut std::process::ChildStdin,
        disk: &storage::Disk,
        read_before: Instant,
    ) -> Result<()> {
        let states = crate::native_protocol::states(bytes, build)?;
        let snapshots = systems(bytes, build)?;
        if self.stage == 0 && states.iter().any(|s| s.fields["op"] == "open") {
            match self.phase {
                Phase::SystemFull => {
                    self.uart(
                        input,
                        b"system init\n",
                        "explicit initialize pending Good System",
                    )?;
                    self.stage = 1;
                }
                Phase::SystemRecovery => {
                    self.uart(
                        input,
                        b"recover good\n",
                        "request independent basic owner recovery",
                    )?;
                    self.stage = 1;
                }
                Phase::SystemBad => self.stage = 1,
                _ => {}
            }
        }
        if self.phase == Phase::SystemFull {
            self.full.as_mut().unwrap().observe(
                bytes,
                build,
                directory,
                deadline,
                input,
                read_before,
            )?;
            if self.stage == 1 && self.full.as_ref().unwrap().done() {
                self.uart(
                    input,
                    b"system stage-bad\nsystem activate\n",
                    "stage and select actual Bad Shell cohort for next cold boot",
                )?;
                self.stage = 2;
            }
        }
        if matches!(self.phase, Phase::SystemFull | Phase::SystemGoodStage) && self.stage == 2 {
            let next = if self.phase == Phase::SystemFull {
                2
            } else {
                3
            };
            if snapshots.iter().any(|s| {
                s.selected.is_some_and(|m| m.generation == next)
                    && s.current
                        .is_some_and(|c| c.generation == 1 && c.phase == HealthPhase::Healthy)
                    && s.known_good == Some(1)
            }) {
                self.finish(input)?;
            }
        }
        if self.phase == Phase::SystemBad
            && self.stage != 250
            && snapshots.iter().any(|s| {
                s.selected.is_some_and(|m| m.generation == 1)
                    && s.current
                        .is_some_and(|c| c.generation == 2 && c.phase == HealthPhase::Failed)
                    && s.last_failure
                        .is_some_and(|f| f.generation == 2 && f.reason == 2)
            })
        {
            self.finish(input)?;
        }
        let owners = crate::native3_diagnostics::owners(bytes, build)?;
        for event in &owners {
            if event.prompt.phase == OwnerPhase::Armed
                && self.prompt != Some(event.prompt.prompt_serial)
            {
                let expected = match self.phase {
                    Phase::SystemRecovery => Action::RecoverGood,
                    Phase::GrantRemember => Action::RememberRead,
                    Phase::GrantRevoke => Action::RevokeRead,
                    _ => return Err("unexpected owner prompt in cold phase".into()),
                };
                if event.prompt.action != expected {
                    return Err("Native3 prompt action differs from intended exact action".into());
                }
                self.prompt = Some(event.prompt.prompt_serial);
                let mut line = b"approve ".to_vec();
                line.extend_from_slice(&event.prompt.token);
                line.push(b'\n');
                self.uart(
                    input,
                    &line,
                    "fresh exact confirmation after complete printed prompt and Armed",
                )?;
            }
            if self.phase == Phase::SystemRecovery
                && self.stage != 250
                && event.prompt.phase == OwnerPhase::Completed
                && self.prompt == Some(event.prompt.prompt_serial)
                && snapshots.iter().any(|s| {
                    s.selected.is_some_and(|m| m.generation == 1)
                        && s.known_good == Some(1)
                        && s.current.is_none()
                })
            {
                self.finish(input)?;
            }
        }
        let steps = desktop_protocol::steps(bytes, build)?;
        if steps.len() < self.seen {
            return Err("Native3 desktop history truncated".into());
        }
        for step in &steps[self.seen..] {
            if self.phase == Phase::SystemFull || self.stage >= 250 {
                continue;
            }
            match (self.phase, self.stage) {
                (Phase::SystemGoodStage | Phase::SystemFinal, 0)
                    if step.producer == Producer::App && step.kind == StepKind::Frame =>
                {
                    if self.scanout(bytes, build, directory, deadline, step, app(None)?)? {
                        self.initial_app = Some(step.app_process);
                        if self.phase == Phase::SystemGoodStage {
                            self.uart(input,b"system stage-bad\nsystem activate\n","stage second actual Bad generation while current Good remains healthy")?;
                            self.stage = 2;
                        } else {
                            self.uart(
                                input,
                                b"inspect\n",
                                "collect live current generation and Job inspector",
                            )?;
                            self.stage = 3;
                        }
                    }
                }
                (Phase::GrantRemember, 0)
                    if step.producer == Producer::Shell
                        && step.kind == StepKind::Frame
                        && step.app_process == 0 =>
                {
                    if self.scanout(
                        bytes,
                        build,
                        directory,
                        deadline,
                        step,
                        Reference::native(Screen::Home, None)?,
                    )? {
                        self.uart(
                            input,
                            b"install a\nactivate\n",
                            "explicit install and actual A admission",
                        )?;
                        self.stage = 1;
                    }
                }
                (Phase::GrantRemember, 1)
                | (Phase::GrantCold | Phase::GrantRevoke | Phase::GrantRefused, 0)
                    if step.producer == Producer::App
                        && step.kind == StepKind::Frame
                        && step.grants == 0 =>
                {
                    if self.scanout(bytes, build, directory, deadline, step, app(None)?)? {
                        self.initial_app = Some(step.app_process);
                        if self.phase == Phase::GrantRemember {
                            self.initialize_after_report = states
                                .last()
                                .map(|s| s.number("report"))
                                .transpose()?
                                .unwrap_or(0);
                            self.uart(
                                input,
                                b"initialize grants\n",
                                "explicit initialize verified blank owner policy region",
                            )?;
                            self.stage = 10;
                        } else {
                            self.open_app_file()?;
                            self.stage = 2;
                        }
                    }
                }
                (Phase::GrantRemember, 2)
                    if step.producer == Producer::Shell
                        && step.kind == StepKind::PickerReady
                        && step.grants == 0 =>
                {
                    if self.scanout(
                        bytes,
                        build,
                        directory,
                        deadline,
                        step,
                        Reference::native(
                            Screen::Picker {
                                selected: FileChoice::Notes,
                            },
                            None,
                        )?,
                    )? {
                        self.uart(
                            input,
                            b"remember notes\n",
                            "request exact READ/UntilRevoked policy for actual pending Open",
                        )?;
                        self.stage = 3;
                    }
                }
                (Phase::GrantRemember, 3) | (Phase::GrantCold | Phase::GrantRevoke, 2)
                    if step.producer == Producer::App
                        && step.kind == StepKind::Frame
                        && step.grants == 1 =>
                {
                    if self.scanout(
                        bytes,
                        build,
                        directory,
                        deadline,
                        step,
                        app(Some(ev_file::desktop::SEED_NOTES))?,
                    )? {
                        if self.phase == Phase::GrantRevoke {
                            self.uart(input,b"revoke grant\n","fence remints and revoke actual live authority before durable acknowledgment")?;
                            self.stage = 3;
                        } else {
                            self.finish(input)?;
                        }
                    }
                }
                (Phase::GrantRefused, 2)
                    if step.kind == StepKind::PickerHeld
                        && step.producer == Producer::Shell
                        && step.grants == 0 =>
                {
                    self.cancel_refused_picker(step)?;
                }
                (Phase::GrantRefused, 3)
                    if step.producer == Producer::App
                        && step.kind == StepKind::Frame
                        && step.grants == 0
                        && self.scanout(bytes, build, directory, deadline, step, app(None)?)? =>
                {
                    self.finish(input)?;
                }
                _ => {}
            }
        }
        self.seen = steps.len();
        if self.phase == Phase::GrantRemember
            && self.stage == 10
            && states.iter().any(|s| {
                s.is("initialize-grants")
                    && s.number("report")
                        .is_ok_and(|n| n > self.initialize_after_report)
            })
        {
            let qmp = self
                .qmp
                .as_mut()
                .ok_or("grant initialization lacks actual GUI checkpoint")?;
            qmp.set_running(false)?;
            let snapshot = disk.capture(directory, "grant-initial-empty.raw")?;
            qmp.set_running(true)?;
            self.inputs.push(json!({"stage":self.stage,"device":"owned QMP stop and read-only disk snapshot","purpose":"independently retain durable empty policy after exact initialize ACK before pending App Open","snapshot":snapshot}));
            self.tap(Key::Enter)?;
            self.stage = 2;
        }
        if self.phase == Phase::SystemFinal
            && self.stage == 3
            && states.last().is_some_and(|s| s.is("inspect"))
        {
            self.finish(input)?;
        }
        if self.phase == Phase::GrantRevoke
            && self.stage == 3
            && owners.iter().any(|e| {
                e.prompt.phase == OwnerPhase::Completed
                    && Some(e.prompt.prompt_serial) == self.prompt
            })
        {
            self.finish(input)?;
        }
        if self.stage == 250 {
            for state in states {
                let report = state.number("report")?;
                if state.fields["op"] == "finish" && report > self.finish_report {
                    self.finish_report = report;
                    if state.fields["result"] == "busy" {
                        if self.finish_attempts >= 8 {
                            return Err(
                                "Native3 finish remained Busy after8 explicit refusals".into()
                            );
                        }
                        self.finish(input)?;
                    }
                }
            }
        }
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
    phase: Phase,
    disk: &storage::Disk,
) -> Result<ExitStatus> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or("Native3 deadline overflow")?;
    let mut observer = Observer::new(phase);
    let result = (|| {
        let spawn_before = Instant::now();
        let mut child = Owned(
            command
                .stdin(Stdio::piped())
                .spawn()
                .map_err(|e| e.to_string())?,
        );
        if let Some(full) = &mut observer.full {
            full.spawned(spawn_before, Instant::now())?;
        }
        let mut input = child
            .0
            .stdin
            .take()
            .ok_or("Native3 actual owner UART absent")?;
        loop {
            if Instant::now() >= deadline {
                return Err(format!(
                    "Native3 {} deadline atstage{}",
                    phase.name(),
                    observer.stage
                ));
            }
            let read_before = Instant::now();
            let bytes = log(serial)?;
            let _ = log(errors)?;
            observer.observe(
                &bytes,
                build,
                directory,
                deadline,
                &mut input,
                disk,
                read_before,
            )?;
            if let Some(status) = child.0.try_wait().map_err(|e| e.to_string())? {
                if observer.stage != 250 {
                    return Err(format!(
                        "Native3 exited before complete action atstage{}",
                        observer.stage
                    ));
                }
                return Ok(status);
            }
            thread::sleep(
                Duration::from_millis(4).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    })();
    if let Some(full) = &observer.full {
        full.retain(directory, &result)?;
    } else {
        storage::json_new(
            &directory.join("qmp-transcript.json"),
            &json!({"schema":1,"exchanges":observer.qmp.as_ref().map(|q|q.transcript()).unwrap_or(&[])}),
        )?;
    }
    storage::json_new(
        &directory.join("native3-observer.json"),
        &json!({"schema":1,"phase":phase.name(),"passed":result.as_ref().is_ok_and(|s|s.code()==Some(ev_test_protocol::QEMU_PASS_STATUS)),"last_stage":observer.stage,"error":result.as_ref().err(),"captures":observer.captures,"inputs":observer.inputs,"initial_app":observer.initial_app,"scripted_input":true,"human_consent_claim":false,"method":"Actual complete Root/Kernel records, fresh owner UART token after Armed, real keyboard make/break and unmodified QMP scanout. No disk repair or host-supplied guest pixel bytes."}),
    )?;
    result
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn actual_picker_ready_keeps_live_app_identity_but_hides_its_surface() {
        let bytes = include_bytes!("../../../tests/fixtures/native3-picker-ready.serial");
        let build = "185c69a9fe31dbc29150dcbff3f9a2a15c80d5b31fe766d699a14001bda284d1";
        let steps = desktop_protocol::steps(bytes, build).unwrap();
        let ready = steps
            .iter()
            .find(|s| s.kind == StepKind::PickerReady)
            .unwrap();
        assert_ne!(ready.app_process, 0);
        let reference = Reference::native(
            Screen::Picker {
                selected: FileChoice::Notes,
            },
            None,
        )
        .unwrap();
        assert_eq!(
            reference.surface_hash(ready.producer, ready.frame).unwrap(),
            ready.surface_sha256
        );
    }
    #[test]
    fn revoked_picker_keeps_enter_held_until_genuine_no_grant_checkpoint() {
        use std::{
            io::{BufRead, BufReader},
            os::{fd::AsRawFd, unix::net::UnixListener},
        };
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let parent = storage::directory_beneath(&root, Path::new("build/test-tmp")).unwrap();
        let directory =
            build::unique_directory(&parent, "native3-revoked-picker-stimulus").unwrap();
        let directory_fd = fs::File::open(&directory).unwrap();
        let listener = UnixListener::bind(format!(
            "/proc/self/fd/{}/qmp.sock",
            directory_fd.as_raw_fd()
        ))
        .unwrap();
        // This is a bounded host transport peer, not a VM or a claim that the
        // modeled Held step below occurred. It records the real QMP commands.
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream.write_all(b"{\"QMP\":{\"version\":{}}}\n").unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut requests = Vec::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                let request: Value = serde_json::from_str(&line).unwrap();
                writeln!(stream, "{}", json!({"return":{},"id":request["id"]})).unwrap();
                requests.push(request);
            }
            requests
        });
        let trace = include_bytes!("../../../tests/fixtures/native3-picker-ready.serial");
        let build = "185c69a9fe31dbc29150dcbff3f9a2a15c80d5b31fe766d699a14001bda284d1";
        let ready = desktop_protocol::steps(trace, build)
            .unwrap()
            .into_iter()
            .find(|s| s.kind == StepKind::PickerReady)
            .unwrap();
        let mut observer = Observer::new(Phase::GrantRefused);
        observer.initial_app = Some(ready.app_process);
        observer.qmp =
            Some(Qmp::connect(&directory, Instant::now() + Duration::from_secs(2)).unwrap());
        observer.open_app_file().unwrap();
        observer.stage = 2;
        // Actual retained Ready alone must never release/cancel the held key.
        assert!(observer.cancel_refused_picker(&ready).is_err());
        assert_eq!(observer.inputs.len(), 1);
        assert_eq!(observer.inputs[0]["down"], true);
        let mut held = ready.clone();
        held.kind = StepKind::PickerHeld;
        held.held_ticks = 63;
        assert!(observer.cancel_refused_picker(&held).is_err());
        held.held_ticks = 64;
        held.grants = 1;
        assert!(observer.cancel_refused_picker(&held).is_err());
        held.grants = 0;
        observer.cancel_refused_picker(&held).unwrap();
        assert_eq!(observer.stage, 3);
        drop(observer);
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 5); // Capabilities + make/break + Escape pair.
        assert_eq!(requests[0]["execute"], "qmp_capabilities");
        for (request, (key, down)) in
            requests[1..]
                .iter()
                .zip([("ret", true), ("ret", false), ("esc", true), ("esc", false)])
        {
            assert_eq!(request["execute"], "input-send-event");
            assert_eq!(
                request["arguments"]["events"][0]["data"]["key"]["data"],
                key
            );
            assert_eq!(request["arguments"]["events"][0]["data"]["down"], down);
        }
    }
    #[test]
    fn missing_receipts_deadlines_and_output_overflow_reap_only_the_owned_child() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let parent = storage::directory_beneath(&root, Path::new("build/test-tmp")).unwrap();
        for mode in ["exit", "wait", "overflow"] {
            let directory = build::unique_directory(&parent, "native3-child-failure").unwrap();
            let serial = directory.join("serial.log");
            let errors = directory.join("stderr.log");
            let pid = directory.join("pid");
            fs::write(&serial, []).unwrap();
            fs::write(&errors, []).unwrap();
            let disk = storage::Disk::create(&root, &directory).unwrap();
            let mut command = Command::new("python3");
            command.args(["-c","import pathlib,os,sys,time; pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); mode=sys.argv[3]; pathlib.Path(sys.argv[2]).write_bytes(b'x'*(1024*1024+1) if mode=='overflow' else b''); time.sleep(0 if mode=='exit' else 30)"]).arg(&pid).arg(&serial).arg(mode).stdout(Stdio::null()).stderr(Stdio::null());
            let result = supervise(
                &mut command,
                &serial,
                &errors,
                Duration::from_millis(300),
                &"a".repeat(64),
                &directory,
                Phase::SystemBad,
                &disk,
            );
            let error = result.unwrap_err();
            assert!(
                error.contains(match mode {
                    "exit" => "before complete action",
                    "wait" => "deadline",
                    _ => "oversized",
                }),
                "{error}"
            );
            let child = fs::read_to_string(pid).unwrap();
            assert!(!Path::new("/proc").join(child).exists());
            let record: Value =
                serde_json::from_slice(&fs::read(directory.join("native3-observer.json")).unwrap())
                    .unwrap();
            assert_eq!(record["passed"], false);
            assert_eq!(record["inputs"].as_array().unwrap().len(), 0);
        }
    }
}
