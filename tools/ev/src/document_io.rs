//! Explicit scripted owned-VM document exercise. Real input, protected Present
//! observations, original QMP scanout and read-only raw Store inspection join.
use crate::{
    boot::ChildGuard,
    build::Result,
    desktop_protocol::{self, Producer, Step, StepKind},
    perf_ledger::{Bracket, Timing},
    qmp::{Key, Qmp},
    session_reference::Reference,
    storage,
};
use ev_graphics::shell::{FileChoice, Screen};
use ev_userspace_contract::document::{Access, Choice, Focus, Snapshot, State};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};
pub(crate) const SAVED: &[u8] = b"Evrosion_03";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Exercise,
    Cold,
    Cancel,
    Crash,
}
pub(crate) struct Observed {
    pub(crate) view: Snapshot,
    pub(crate) frame: u64,
    pub(crate) process: u64,
    pub(crate) nonce: u32,
}
pub(crate) fn records(bytes: &[u8], build: &str) -> Result<Vec<Observed>> {
    let text = std::str::from_utf8(bytes).map_err(|_| "document serial UTF8")?;
    let mut result = Vec::new();
    let mut last = std::collections::BTreeMap::new();
    for line in text
        .split_inclusive('\n')
        .filter(|l| l.ends_with('\n'))
        .map(|l| l.trim_end_matches(['\r', '\n']))
        .filter(|l| l.starts_with("EVROSION_M7_DOCUMENT"))
    {
        let fields: Vec<_> = line.split(' ').collect();
        if fields.len() != 11
            || fields[0] != "EVROSION_M7_DOCUMENT"
            || fields[1] != "protocol=1"
            || fields[2] != format!("build={build}")
        {
            return Err("document record header/extent/build".into());
        }
        let mut numbers = Vec::new();
        for (field, key) in fields[3..10].iter().zip([
            "process", "thread", "endpoint", "ticket", "nonce", "tick", "frame",
        ]) {
            numbers.push(crate::boot_protocol::canonical_number(field, key)?);
        }
        let [process, thread, _endpoint, ticket, nonce, tick, frame]: [u64; 7] =
            numbers.try_into().unwrap();
        if [process, thread, ticket, nonce, frame]
            .iter()
            .any(|n| matches!(*n, 0 | u64::MAX))
            || nonce >= u32::MAX as u64
            || tick == u64::MAX
            || last.insert(process, nonce).is_some_and(|n| nonce <= n)
        {
            return Err("document actual identity/nonce/frame invalid".into());
        }
        let hex = fields[10]
            .strip_prefix("bytes=")
            .filter(|s| s.len() == 512)
            .ok_or("document bytes extent")?;
        let mut body = [0; 256];
        for (at, byte) in body.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[at * 2..at * 2 + 2], 16)
                .map_err(|_| "document bytes hex")?;
        }
        let view =
            Snapshot::decode(&body, 0).map_err(|e| format!("actual semantic snapshot: {e:?}"))?;
        result.push(Observed {
            view,
            frame,
            process,
            nonce: nonce as u32,
        });
        if result.len() > 128 {
            return Err("document observation bound exceeded".into());
        }
    }
    Ok(result)
}
pub(crate) fn without_observations(bytes: &[u8], build: &str) -> Result<Vec<u8>> {
    records(bytes, build)?;
    Ok(std::str::from_utf8(bytes)
        .map_err(|_| "document UTF8")?
        .split_inclusive('\n')
        .filter(|l| !l.starts_with("EVROSION_M7_DOCUMENT"))
        .collect::<String>()
        .into_bytes())
}
fn bounded(path: &Path) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 1024 * 1024 {
        return Err("document log bound/type".into());
    }
    fs::read(path).map_err(|e| e.to_string())
}
fn tap(qmp: &mut Qmp, key: Key) -> Result<()> {
    qmp.key_state(key, true)?;
    qmp.key_state(key, false)
}
fn elapsed(origin: Instant) -> Result<u64> {
    crate::perf_ledger::elapsed_ns(origin, Instant::now())
        .map_err(|e| format!("document host monotonic: {e:?}"))
}
fn bracket(before: u64, after: u64) -> Result<Bracket> {
    Bracket::new(before, after).map_err(|e| format!("document response bracket: {e:?}"))
}
struct Response {
    name: String,
    from_stage: u32,
    target_stage: u32,
    typed: usize,
    begin: Bracket,
    first_join: Option<(Bracket, Value)>,
    validated_capture: Option<Value>,
}
#[derive(Default)]
struct Responses {
    previous_read_start: u64,
    read: Option<Bracket>,
    reads: u64,
    pending: Option<Response>,
    completed: Vec<Response>,
}
impl Responses {
    fn sent(
        &mut self,
        name: &str,
        from: u32,
        target: u32,
        typed: usize,
        begin: Bracket,
    ) -> Result<()> {
        if self.pending.is_some() || self.completed.len() >= 96 {
            return Err("document response overlap/bound".into());
        }
        self.pending = Some(Response {
            name: name.into(),
            from_stage: from,
            target_stage: target,
            typed,
            begin,
            first_join: None,
            validated_capture: None,
        });
        Ok(())
    }
    fn serial_read(&mut self, read: Bracket) -> Result<()> {
        if self
            .read
            .is_some_and(|last| read.earliest_ns < last.latest_ns)
        {
            return Err("document serial-read clock regressed".into());
        }
        self.previous_read_start = self.read.map_or(0, |last| last.earliest_ns);
        self.read = Some(read);
        self.reads = self
            .reads
            .checked_add(1)
            .ok_or("document poll count overflow")?;
        Ok(())
    }
    fn joined(&mut self, stage: u32, step: &Step, semantic: Option<&Observed>) -> Result<()> {
        let Some(pending) = self.pending.as_mut() else {
            return Ok(());
        };
        if pending.target_stage != stage {
            return Err("document response reached wrong control stage".into());
        }
        if pending.first_join.is_none() {
            let read = self
                .read
                .ok_or("document response lacks serial-read bracket")?;
            // An append can race a bounded read. Its START, rather than read
            // completion, is the conservative previous-absence lower bound.
            // Cache the FIRST join even if the later scanout capture is transient;
            // a retry must never narrow an already observed endpoint interval.
            let end = bracket(
                self.previous_read_start.max(pending.begin.earliest_ns),
                read.latest_ns,
            )?;
            pending.first_join = Some((
                end,
                json!({"actual_present":step,
                "semantic":semantic.map(|o|json!({"process":o.process,"frame":o.frame,"nonce":o.nonce,
                    "state":format!("{:?}",o.view.state),"focus":format!("{:?}",o.view.focus),
                    "revision":o.view.revision,"dirty":o.view.dirty,"text_bytes":o.view.text.len()})),
                "poll_index":self.reads,"previous_read_start_ns":self.previous_read_start,
                "current_serial_read_ns":[read.earliest_ns,read.latest_ns]}),
            ));
        }
        Ok(())
    }
    fn captured(&mut self, stage: u32, capture: u32, step: &Step, at: u64) -> Result<()> {
        if let Some(mut pending) = self.pending.take() {
            if pending.target_stage != stage || pending.first_join.is_none() {
                return Err("document response capture lacks matching observed join".into());
            }
            pending.validated_capture = Some(json!({"capture":capture,"actual_present":step,
                "matching_scanout_verified_host_ns":at}));
            self.completed.push(pending);
        }
        Ok(())
    }
    fn report(
        &self,
        phase: Phase,
        functional_ok: bool,
        measure: impl Fn(Bracket, Bracket) -> Result<Timing>,
    ) -> (Value, bool) {
        let mut all_valid = self.pending.is_none() && !self.completed.is_empty();
        let records: Vec<_> = self.completed.iter().map(|record| {
            let measured = record.first_join.as_ref().ok_or("response endpoint missing".to_owned())
                .and_then(|(end,_)|measure(record.begin,*end));
            all_valid &= measured.is_ok() && record.validated_capture.is_some();
            json!({"name":record.name,"from_stage":record.from_stage,"target_stage":record.target_stage,
                "typed_after_input":record.typed,
                "input_or_spawn_ns":[record.begin.earliest_ns,record.begin.latest_ns],
                "first_join_ns":record.first_join.as_ref().map(|(end,_)|[end.earliest_ns,end.latest_ns]),
                "first_join":record.first_join.as_ref().map(|(_,join)|join),
                "validated_capture":record.validated_capture,"valid":measured.is_ok(),
                "timing":measured.as_ref().ok(),"error":measured.as_ref().err()})
        }).collect();
        let save_recorded = self
            .completed
            .iter()
            .any(|record| record.name == "save_to_exact_readback_confirmed_saved");
        let required_controls = phase != Phase::Exercise || save_recorded;
        let passed = functional_ok && all_valid && required_controls;
        (
            json!({"schema":1,"passed":passed,"functional_phase_passed":functional_ok,
            "all_recorded_intervals_valid":all_valid,"save_control_recorded":save_recorded,"required_controls_present":required_controls,
            "clock":"std::time::Instant host monotonic nanoseconds",
            "endpoint":"first complete actual semantic/protected-Present join (Shell Present for Home/picker); actual scanout verified separately",
            "scope":"source-bound owned-QEMU host intervals, conservatively bracketed serial polling and QMP input acknowledgements; completed QMP capture pauses excluded with uncertainty; running host scheduling, parser/poll work and TCG remain included",
            "not_claimed":["pure guest execution time","physical input/display latency","first visible pixel time","performance SLA or human acceptance"],
            "serial_reads":self.reads,"records":records,
            "pending":self.pending.as_ref().map(|p|json!({"name":p.name,"from_stage":p.from_stage,
                "target_stage":p.target_stage,"input_ns":[p.begin.earliest_ns,p.begin.latest_ns],
                "first_join_observed":p.first_join.is_some()})),
            "poll_sleep_ms":4,"bounds":{"controls":96,"captures":96,"serial_bytes":1048576}}),
            passed,
        )
    }
}
fn response_name(stage: u32, phase: Phase, typed: usize) -> Option<&'static str> {
    Some(match stage {
        0 => "launch_application",
        1 | 11 | 25 | 51 => "open_edit_picker",
        2 if phase == Phase::Cancel => "cancel_picker",
        2 | 12 | 26 | 52 => "confirm_edit_open",
        3 if phase == Phase::Cold => return None,
        3 if phase == Phase::Crash => "fault_current_app",
        3 | 14 | 19 | 27 => "focus_select_all",
        4 => "select_all",
        5 => "insert_character",
        6 if typed < SAVED.len() => "insert_character",
        6 => "focus_select_all",
        7 | 15 | 20 | 28 => "focus_save",
        8 => "save_to_exact_readback_confirmed_saved",
        9 | 16 | 21 | 29 => "focus_close",
        10 => "close_saved_document",
        13 => "edit_dirty_document",
        17 | 22 => "dirty_close_confirmation",
        18 => "keep_editing",
        23 => "focus_discard",
        24 => "discard_unsaved_edit",
        30 => "open_readonly_picker",
        31 => "confirm_readonly_open",
        32 => "readonly_edit_refusal",
        50 => "relaunch_after_fault",
        _ => return None,
    })
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
    let start = Instant::now();
    let deadline = start + timeout;
    let mut qmp = None;
    let mut stage = 0;
    let mut typed = 0;
    let mut seen_nonce = 0;
    let mut capture = 0;
    let mut captures = Vec::new();
    let mut baseline = None;
    let mut readonly_baseline = None;
    let mut cancel_baseline = None;
    let mut file_proof = None;
    let mut crashed_process = None;
    let mut crash_baseline = None;
    let mut crash_survivors = None;
    let mut fault_proof = None;
    let mut finishing = false;
    let mut finished = false;
    let mut finish_attempts = 0;
    let mut last_finish = 0;
    let mut responses = Responses::default();
    let mut result = (|| {
        let spawn_before = elapsed(start)?;
        let mut child = ChildGuard(
            command
                .stdin(Stdio::piped())
                .spawn()
                .map_err(|e| e.to_string())?,
        );
        responses.sent(
            "owned_spawn_to_first_home_present",
            0,
            0,
            0,
            bracket(spawn_before, elapsed(start)?)?,
        )?;
        let mut uart = child.0.stdin.take().ok_or("document UART missing")?;
        loop {
            if Instant::now() >= deadline {
                return Err(format!("document deadline stage={stage} typed={typed}"));
            }
            let read_before = elapsed(start)?;
            let bytes = bounded(serial)?;
            responses.serial_read(bracket(read_before, elapsed(start)?)?)?;
            bounded(errors)?;
            if let Some(status) = child.0.try_wait().map_err(|e| e.to_string())? {
                if !finished || status.code() != Some(ev_test_protocol::QEMU_PASS_STATUS) {
                    return Err(format!(
                        "document VM exit {status} before checked finish, stage={stage}"
                    ));
                }
                crate::session_protocol::retention(&bytes, build)?;
                return Ok(status);
            }
            if finishing {
                let clean = without_observations(&bytes, build)?;
                let states = if phase == Phase::Crash {
                    crate::document_crash::prefix_states(&clean, build)?
                } else {
                    crate::native_protocol::states(&clean, build)?
                };
                for state in states {
                    let report = state.number("report")?;
                    if state.fields["op"] == "finish" && report > last_finish {
                        last_finish = report;
                        match state.fields["result"].as_str() {
                            "ok" => finished = true,
                            "busy" if finish_attempts < 8 => {
                                uart.write_all(b"finish\n").map_err(|e| e.to_string())?;
                                uart.flush().map_err(|e| e.to_string())?;
                                finish_attempts += 1;
                            }
                            _ => return Err("document finish refused".into()),
                        }
                    }
                }
            } else {
                let text = std::str::from_utf8(&bytes).map_err(|_| "document UTF8")?;
                let steps: Vec<Step> = text
                    .split_inclusive('\n')
                    .filter(|l| l.ends_with('\n') && l.starts_with("EVROSION_M4_DESKTOP_STEP "))
                    .map(|l| desktop_protocol::step_line(l.trim_end_matches(['\r', '\n']), build))
                    .collect::<Result<_>>()?;
                let ui = crate::session_io::ProbeUi::parse(&bytes, build)?;
                let observed = records(&bytes, build)?;
                let latest = observed.last();
                let picker = matches!(stage, 2 | 12 | 26 | 31 | 52);
                let screen = if stage == 0 {
                    Screen::Home
                } else if stage == 50 {
                    Screen::AppStopped
                } else if picker {
                    Screen::Picker {
                        selected: FileChoice::Notes,
                    }
                } else {
                    Screen::AppRunning
                };
                let app = if screen == Screen::AppRunning {
                    latest.map(|o| o.view)
                } else {
                    None
                };
                let current = steps.iter().rev().find(|s| {
                    s.producer
                        == if screen == Screen::AppRunning {
                            Producer::App
                        } else {
                            Producer::Shell
                        }
                        && s.kind
                            == if picker {
                                StepKind::PickerReady
                            } else {
                                StepKind::Frame
                            }
                });
                let shell = steps
                    .iter()
                    .rev()
                    .find(|s| s.producer == Producer::Shell && s.kind == StepKind::Frame);
                let reference = Reference::document(
                    screen,
                    app,
                    if stage == 31 {
                        Access::Read
                    } else {
                        Access::Edit
                    },
                    ui.cursor(),
                )?;
                let ready = current.is_some_and(|s| {
                    if (stage == 0 || stage == 50 || picker)
                        && (!ui.ready(s.shell_process, s.frame, 0) || ui.cursor().is_none())
                    {
                        return false;
                    }

                    if screen == Screen::AppRunning {
                        latest.is_some_and(|o| {
                            o.frame == s.frame && o.process == s.app_process && o.nonce > seen_nonce
                        }) && reference.app_composition_ready(s, shell).unwrap_or(false)
                    } else {
                        reference
                            .surface_hash(Producer::Shell, s.frame)
                            .is_ok_and(|h| h == s.surface_sha256)
                    }
                });
                if ready {
                    let view = latest.map(|o| o.view);
                    let acceptable = match stage {
                        0 | 2 | 12 | 26 | 31 | 52 => true,
                        50 => text
                            .split_inclusive('\n')
                            .filter(|l| {
                                l.ends_with('\n') && l.starts_with("EVROSION_M4_DESKTOP_LIFECYCLE ")
                            })
                            .map(|l| {
                                desktop_protocol::lifecycle_syntax(
                                    l.trim_end_matches(['\r', '\n']),
                                    build,
                                )
                            })
                            .collect::<Result<Vec<_>>>()?
                            .iter()
                            .any(|e| {
                                e.event == desktop_protocol::Event::Fault
                                    && e.actor == desktop_protocol::Actor::App
                                    && Some(e.process) == crashed_process
                            }),
                        51 => {
                            view.is_some_and(|v| v.state == State::Closed)
                                && latest.is_some_and(|o| Some(o.process) != crashed_process)
                        }
                        53 => {
                            view.is_some_and(|v| {
                                v.state == State::Saved
                                    && v.revision == 1
                                    && v.text.as_bytes() == SAVED
                            }) && latest.is_some_and(|o| Some(o.process) != crashed_process)
                        }
                        1 | 11 | 25 | 40 => view.is_some_and(|v| v.state == State::Closed),
                        3 => view.is_some_and(|v| {
                            v.state == State::Saved
                                && v.choice == Choice::Notes
                                && v.text.as_bytes()
                                    == if matches!(phase, Phase::Cold | Phase::Crash) {
                                        SAVED
                                    } else {
                                        ev_file::desktop::SEED_NOTES
                                    }
                        }),
                        4 | 7 => view.is_some_and(|v| v.focus == Focus::SelectAll),
                        5 => view.is_some_and(|v| v.focus == Focus::Text && v.anchor == 0),
                        6 => view.is_some_and(|v| {
                            v.state == State::Dirty && v.text.as_bytes() == &SAVED[..typed]
                        }),
                        8 => view.is_some_and(|v| v.focus == Focus::Save),
                        9 | 13 => view.is_some_and(|v| {
                            v.state == State::Saved && v.revision == 1 && v.text.as_bytes() == SAVED
                        }),
                        10 | 17 | 22 | 29 => view.is_some_and(|v| v.focus == Focus::Close),
                        14 | 19 => view.is_some_and(|v| {
                            v.state == State::Dirty && v.text.as_str() == "Evrosion_03X"
                        }),
                        15 | 20 | 28 => view.is_some_and(|v| v.focus == Focus::SelectAll),
                        16 | 21 => view.is_some_and(|v| v.focus == Focus::Save),
                        18 | 23 => view.is_some_and(|v| {
                            v.state == State::ConfirmDiscard && v.focus == Focus::KeepEditing
                        }),
                        24 => view.is_some_and(|v| {
                            v.state == State::ConfirmDiscard && v.focus == Focus::Discard
                        }),
                        27 => view.is_some_and(|v| {
                            v.state == State::Saved && v.revision == 1 && v.text.as_bytes() == SAVED
                        }),
                        30 => view.is_some_and(|v| v.focus == Focus::OpenRead),
                        32 | 33 => view.is_some_and(|v| {
                            v.state == State::Saved
                                && v.access == Access::Read
                                && v.revision == 1
                                && v.text.as_bytes() == SAVED
                                && !v.can_save()
                        }),
                        _ => false,
                    };
                    if acceptable {
                        responses.joined(
                            stage,
                            current.ok_or("response Present missing")?,
                            latest,
                        )?;
                        if qmp.is_none() {
                            crate::boot::check_desktop_prefix(&bytes, build)?;
                            qmp = Some(Qmp::connect_at(directory, deadline, start)?);
                        }
                        let q = qmp.as_mut().unwrap();
                        capture += 1;
                        if capture > 96 {
                            return Err("document capture bound".into());
                        }
                        q.set_running(false)?;
                        let (path, pixels) = q.capture(capture)?;
                        let valid = reference.validate(&pixels);
                        if let Ok(proof) = valid {
                            captures.push(json!({"stage":stage,"typed":typed,"path":path,"pixels":proof,"actual_present":current,"nonce":latest.map(|o|o.nonce)}));
                            if screen == Screen::AppRunning {
                                seen_nonce = latest.unwrap().nonce;
                            }
                            if stage == 3 {
                                let raw = disk.bytes()?;
                                storage::immutable_new(
                                    &directory.join("document-baseline.raw"),
                                    &raw,
                                )?;
                                baseline = Some(raw);
                            }
                            if stage == 9 {
                                let raw = disk.bytes()?;
                                storage::immutable_new(
                                    &directory.join("document-saved.raw"),
                                    &raw,
                                )?;
                                let before =
                                    baseline.as_ref().ok_or("document baseline missing")?;
                                if before[..32 * 512] != raw[..32 * 512]
                                    || before[46 * 512..] != raw[46 * 512..]
                                {
                                    return Err(
                                        "document save changed bytes outside Notes Store".into()
                                    );
                                }
                                file_proof = Some(crate::native3_disk::document(&raw, 1, SAVED)?);
                            }
                            if stage == 1 && phase == Phase::Cancel {
                                cancel_baseline = Some(disk.bytes()?);
                            }
                            if stage == 27 {
                                file_proof =
                                    Some(crate::native3_disk::document(&disk.bytes()?, 1, SAVED)?);
                            }
                            if stage == 32 {
                                readonly_baseline = Some(disk.bytes()?);
                            }
                            if stage == 33 && readonly_baseline.as_ref() != Some(&disk.bytes()?) {
                                return Err("read-only input changed retained disk".into());
                            }
                            if stage == 40 && cancel_baseline.as_ref() != Some(&disk.bytes()?) {
                                return Err("cancelled selection changed retained disk".into());
                            }
                            if stage == 3 && phase == Phase::Crash {
                                crashed_process = latest.map(|o| o.process);
                                crash_baseline = Some(disk.bytes()?);
                                let step = current.unwrap();
                                crash_survivors = Some((step.shell_process, step.display_process));
                            }
                            if stage == 50 {
                                let step = current.unwrap();
                                if crash_survivors
                                    != Some((step.shell_process, step.display_process))
                                {
                                    return Err("app fault replaced surviving Shell/Display".into());
                                }
                                fault_proof = text
                                    .split_inclusive('\n')
                                    .filter(|l| {
                                        l.ends_with('\n')
                                            && l.starts_with("EVROSION_M4_DESKTOP_LIFECYCLE ")
                                    })
                                    .map(|l| {
                                        desktop_protocol::lifecycle_syntax(
                                            l.trim_end_matches(['\r', '\n']),
                                            build,
                                        )
                                    })
                                    .collect::<Result<Vec<_>>>()?
                                    .into_iter()
                                    .find(|e| {
                                        e.event == desktop_protocol::Event::Fault
                                            && e.actor == desktop_protocol::Actor::App
                                            && Some(e.process) == crashed_process
                                    });
                                if fault_proof.as_ref().is_none_or(|e| e.grants != 1) {
                                    return Err(
                                        "app fault lacks actual selected-grant count".into()
                                    );
                                }
                            }
                            if stage == 53 {
                                file_proof =
                                    Some(crate::native3_disk::document(&disk.bytes()?, 1, SAVED)?);
                                if crash_baseline.as_ref() != Some(&disk.bytes()?) {
                                    return Err("app crash/relaunch changed retained data".into());
                                }
                            }
                            q.set_running(true)?;
                            responses.captured(
                                stage,
                                capture,
                                current.ok_or("response capture Present missing")?,
                                elapsed(start)?,
                            )?;
                            let action_stage = stage;
                            let action_name = response_name(stage, phase, typed);
                            let input_before = elapsed(start)?;
                            match stage {
                                0 => {
                                    q.key_state(Key::Enter, false)?;
                                    tap(q, Key::Enter)?;
                                    stage = 1;
                                }
                                1 | 11 => {
                                    tap(q, Key::Enter)?;
                                    stage = if stage == 1 { 2 } else { 12 };
                                }
                                2 if phase == Phase::Cancel => {
                                    tap(q, Key::Escape)?;
                                    stage = 40;
                                }
                                2 | 12 => {
                                    tap(q, Key::Enter)?;
                                    stage = if stage == 2 { 3 } else { 13 };
                                }
                                3 if phase == Phase::Crash => {
                                    uart.write_all(b"crash app\n").map_err(|e| e.to_string())?;
                                    uart.flush().map_err(|e| e.to_string())?;
                                    stage = 50;
                                }
                                50 => {
                                    seen_nonce = 0;
                                    tap(q, Key::Enter)?;
                                    stage = 51;
                                }
                                51 | 52 => {
                                    tap(q, Key::Enter)?;
                                    stage += 1;
                                }
                                53 => finishing = true,
                                3 if phase == Phase::Cold => {
                                    file_proof = Some(crate::native3_disk::document(
                                        &disk.bytes()?,
                                        1,
                                        SAVED,
                                    )?);
                                    finishing = true;
                                }
                                3 => {
                                    tap(q, Key::Tab)?;
                                    stage = 4;
                                }
                                4 => {
                                    tap(q, Key::Enter)?;
                                    stage = 5;
                                }
                                5 => {
                                    q.ascii(SAVED[0])?;
                                    typed = 1;
                                    stage = 6;
                                }
                                6 if typed < SAVED.len() => {
                                    q.ascii(SAVED[typed])?;
                                    typed += 1;
                                }
                                6 => {
                                    tap(q, Key::Tab)?;
                                    stage = 7;
                                }
                                7 => {
                                    tap(q, Key::Tab)?;
                                    stage = 8;
                                }
                                8 => {
                                    tap(q, Key::Enter)?;
                                    stage = 9;
                                }
                                9 => {
                                    tap(q, Key::Tab)?;
                                    stage = 10;
                                }
                                10 => {
                                    tap(q, Key::Enter)?;
                                    stage = 11;
                                }
                                13 => {
                                    q.ascii(b'X')?;
                                    stage = 14;
                                }
                                14 | 15 | 16 | 19 | 20 | 21 | 23 | 27 | 28 | 29 => {
                                    tap(q, Key::Tab)?;
                                    stage += 1;
                                }
                                17 | 18 | 22 | 24 | 25 | 26 | 30 | 31 => {
                                    tap(q, Key::Enter)?;
                                    stage += 1;
                                }
                                32 => {
                                    q.ascii(b'Z')?;
                                    stage = 33;
                                }
                                33 | 40 => finishing = true,
                                _ => (),
                            }
                            if let Some(name) = action_name {
                                responses.sent(
                                    name,
                                    action_stage,
                                    stage,
                                    typed,
                                    bracket(input_before, elapsed(start)?)?,
                                )?;
                            }
                            if finishing {
                                uart.write_all(b"finish\n").map_err(|e| e.to_string())?;
                                uart.flush().map_err(|e| e.to_string())?;
                                finish_attempts = 1;
                            }
                        } else {
                            q.set_running(true)?;
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(4));
        }
    })();
    let (mut performance, valid_performance) =
        responses.report(phase, result.is_ok(), |begin, end| {
            qmp.as_ref()
                .ok_or("document response QMP absent".to_owned())?
                .timing(begin, end)
        });
    let manifest_path = directory
        .parent()
        .ok_or("document response run parent absent")?
        .join("manifest.json");
    let retained_manifest: crate::build::Manifest =
        serde_json::from_slice(&fs::read(&manifest_path).map_err(|e| e.to_string())?)
            .map_err(|e| format!("document response retained manifest: {e}"))?;
    if retained_manifest.build_id != build {
        return Err("document response build differs from retained manifest".into());
    }
    performance["build"] = json!(build);
    performance["source_sha256"] = json!(retained_manifest.source_sha256);
    performance["retained_manifest_sha256"] = json!(crate::build::hash_file(&manifest_path)?);
    performance["phase"] = json!(format!("{phase:?}"));
    storage::json_new(&directory.join("performance.json"), &performance)?;
    if result.is_ok() && !valid_performance {
        result = Err("document functional phase passed but bounded response observations are incomplete/invalid".into());
    }
    storage::json_new(
        &directory.join("document-observer.json"),
        &json!({"schema":1,"phase":format!("{phase:?}"),"passed":result.is_ok(),"stage":stage,"typed":typed,"error":result.as_ref().err(),"scripted_input":true,"human_acceptance":false,"captures":captures,"file_proof":file_proof,"fault_proof":fault_proof,"crashed_process":crashed_process}),
    )?;
    storage::json_new(
        &directory.join("qmp-transcript.json"),
        &json!({"schema":1,"exchanges":qmp.as_ref().map(|q|q.transcript()).unwrap_or(&[])}),
    )?;
    result
}

#[cfg(test)]
mod response_tests {
    use super::*;
    use crate::perf_ledger::Ledger;

    fn b(lo: u64, hi: u64) -> Bracket {
        Bracket::new(lo, hi).unwrap()
    }
    fn step(frame: u64) -> Step {
        // Synthetic math/verifier fixture; not actual guest execution evidence.
        Step {
            kind: StepKind::Frame,
            frame,
            width: 1280,
            height: 800,
            app_process: 7,
            shell_process: 6,
            display_process: 3,
            grants: 1,
            producer: Producer::App,
            surface_sha256: "a".repeat(64),
            held_ticks: 0,
        }
    }
    fn measure(begin: Bracket, end: Bracket) -> Result<Timing> {
        Ledger::new()
            .measure(begin, end)
            .map_err(|e| format!("test ledger: {e:?}"))
    }
    #[test]
    fn first_join_uses_previous_read_start_and_is_not_narrowed_by_capture_retry() {
        let mut r = Responses::default();
        r.serial_read(b(10, 15)).unwrap();
        r.sent(
            "save_to_exact_readback_confirmed_saved",
            8,
            9,
            11,
            b(20, 24),
        )
        .unwrap();
        r.serial_read(b(40, 45)).unwrap();
        r.serial_read(b(100, 110)).unwrap();
        r.joined(9, &step(5), None).unwrap();
        r.serial_read(b(120, 130)).unwrap();
        r.joined(9, &step(6), None).unwrap();
        r.captured(9, 1, &step(6), 150).unwrap();
        let (record, passed) = r.report(Phase::Exercise, true, measure);
        assert!(passed);
        assert_eq!(record["records"][0]["first_join_ns"], json!([40, 110]));
        assert_eq!(
            record["records"][0]["first_join"]["actual_present"]["frame"],
            5
        );
        assert_eq!(
            record["records"][0]["validated_capture"]["actual_present"]["frame"],
            6
        );
        assert_eq!(record["records"][0]["timing"]["wall_min_ns"], 16);
        assert_eq!(record["records"][0]["timing"]["wall_max_ns"], 90);
    }
    #[test]
    fn missing_control_unfinished_pause_or_pending_input_never_passes_response_gate() {
        let mut r = Responses::default();
        r.sent("focus_save", 7, 8, 11, b(10, 12)).unwrap();
        let (_, pending) = r.report(Phase::Cold, true, measure);
        assert!(!pending);
        r.serial_read(b(20, 30)).unwrap();
        r.joined(8, &step(3), None).unwrap();
        r.captured(8, 1, &step(3), 40).unwrap();
        assert!(r.report(Phase::Cold, true, measure).1);
        assert!(
            !r.report(Phase::Exercise, true, measure).1,
            "Exercise must measure actual Save completion"
        );
        let mut ledger = Ledger::new();
        ledger.stop_sent(50).unwrap();
        assert!(
            !r.report(Phase::Cold, true, |begin, end| ledger
                .measure(begin, end)
                .map_err(|e| format!("{e:?}")))
                .1
        );
        assert!(
            !r.report(Phase::Cold, false, measure).1,
            "failed functional attempts remain failed"
        );
    }
    #[test]
    fn response_order_overlap_and_storage_bounds_fail_closed() {
        let mut r = Responses::default();
        r.serial_read(b(10, 20)).unwrap();
        assert!(r.serial_read(b(19, 21)).is_err());
        r.sent("control", 1, 2, 0, b(21, 22)).unwrap();
        assert!(r.sent("another", 2, 3, 0, b(22, 23)).is_err());
        assert!(r.joined(3, &step(4), None).is_err());
        assert_eq!(
            response_name(8, Phase::Exercise, 11),
            Some("save_to_exact_readback_confirmed_saved")
        );
        assert_eq!(response_name(3, Phase::Cold, 0), None);
        assert_eq!(response_name(2, Phase::Cancel, 0), Some("cancel_picker"));
    }
}
