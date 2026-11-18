//! Explicit graphical guide exercise against the privacy-preserving manual
//! guest. Expected view models only select checks; actual pixels, protected
//! presentation hashes and read-only disk inspection establish the result.
use crate::{
    boot::ChildGuard,
    build::Result,
    desktop_protocol::{self, Producer, Step, StepKind},
    qmp::{Key, Qmp},
    session_reference::Reference,
    storage,
};
use ev_graphics::shell::{FileChoice, Screen};
use ev_userspace_contract::document::{Access, Choice, Feedback, Focus, Snapshot, State, Text};
use serde_json::json;
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

pub(crate) const SAVED: &[u8] = b"Guide_03";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Exercise,
    Cold,
}
fn bounded(path: &Path) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 1024 * 1024 {
        return Err("document guide log bound/type".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 1024 * 1024 {
        return Err("document guide log grew beyond bound".into());
    }
    Ok(bytes)
}
fn expected(phase: Phase, stage: u32, typed: usize) -> Result<Option<Snapshot>> {
    if matches!(stage, 0 | 2 | 12) {
        return Ok(None);
    }
    let mut view = Snapshot {
        state: State::Closed,
        focus: Focus::Open,
        choice: Choice::None,
        access: Access::None,
        text: Text::empty(),
        cursor: 0,
        anchor: 0,
        revision: 0,
        feedback: Feedback::None,
        dirty: false,
    };
    if matches!(stage, 1 | 11) {
        return Ok(Some(view));
    }
    let saved = stage >= 6 || phase == Phase::Cold;
    let bytes = if stage == 6 {
        &SAVED[..typed]
    } else if saved {
        SAVED
    } else {
        ev_file::desktop::SEED_NOTES
    };
    view.text = Text::new(bytes).map_err(|e| format!("guide expected text: {e:?}"))?;
    view.choice = Choice::Notes;
    view.access = Access::Edit;
    view.state = if (6..=8).contains(&stage) {
        State::Dirty
    } else {
        State::Saved
    };
    view.dirty = view.state == State::Dirty;
    view.cursor = bytes.len() as u16;
    view.anchor = if stage == 5 { 0 } else { view.cursor };
    view.revision = u64::from(stage >= 9 || phase == Phase::Cold);
    view.focus = match stage {
        4 | 7 => Focus::SelectAll,
        8 | 9 => Focus::Save,
        10 => Focus::Close,
        _ => Focus::Text,
    };
    view.valid()
        .map_err(|e| format!("guide expected view: {e:?}"))?;
    Ok(Some(view))
}
fn tap(qmp: &mut Qmp, key: Key) -> Result<()> {
    qmp.key_state(key, true)?;
    qmp.key_state(key, false)
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
    let origin = Instant::now();
    let deadline = origin + timeout;
    let mut qmp: Option<Qmp> = None;
    let mut stage = 0;
    let mut typed = 0;
    let mut last_line = 0;
    let mut capture = 0;
    let mut captures = Vec::new();
    let mut inputs = Vec::new();
    let mut baseline = None;
    let mut file_proof = None;
    let mut finishing = false;
    let mut finished = false;
    let mut finish_attempts = 0;
    let mut last_finish = 0;
    let result = (|| {
        let mut child = ChildGuard(
            command
                .stdin(Stdio::piped())
                .spawn()
                .map_err(|e| e.to_string())?,
        );
        let mut uart = child
            .0
            .stdin
            .take()
            .ok_or("document guide owner UART missing")?;
        loop {
            if Instant::now() >= deadline {
                return Err(format!(
                    "graphical document guide deadline stage={stage} typed={typed}"
                ));
            }
            let bytes = bounded(serial)?;
            bounded(errors)?;
            let text = std::str::from_utf8(&bytes).map_err(|_| "document guide serial UTF8")?;
            if text.lines().any(|l| l.starts_with("EVROSION_M7_DOCUMENT")) {
                return Err(
                    "manual document guest exposed a full semantic-text serial diagnostic".into(),
                );
            }
            if let Some(status) = child.0.try_wait().map_err(|e| e.to_string())? {
                if !finished || status.code() != Some(ev_test_protocol::QEMU_PASS_STATUS) {
                    return Err(format!(
                        "document guide VM exit {status} before checked finish, stage={stage}"
                    ));
                }
                crate::session_protocol::retention(&bytes, build)?;
                return Ok(status);
            }
            if finishing {
                for state in crate::native_protocol::states(&bytes, build)? {
                    let report = state.number("report")?;
                    if state.fields["op"] == "finish" && report > last_finish {
                        last_finish = report;
                        match state.fields["result"].as_str() {
                            "ok" => finished = true,
                            "busy" if finish_attempts < 8 => {
                                uart.write_all(b"finish\n")
                                    .and_then(|()| uart.flush())
                                    .map_err(|e| e.to_string())?;
                                finish_attempts += 1;
                                inputs.push(
                                    json!({"owner_uart":"finish\\n","attempt":finish_attempts}),
                                );
                            }
                            _ => return Err("document guide finish refused".into()),
                        }
                    }
                }
            } else {
                let steps: Vec<(usize, Step)> = text
                    .split_inclusive('\n')
                    .enumerate()
                    .filter(|(_, l)| {
                        l.ends_with('\n') && l.starts_with("EVROSION_M4_DESKTOP_STEP ")
                    })
                    .map(|(n, l)| {
                        desktop_protocol::step_line(l.trim_end_matches(['\r', '\n']), build)
                            .map(|s| (n + 1, s))
                    })
                    .collect::<Result<_>>()?;
                let ui = crate::session_io::ProbeUi::parse(&bytes, build)?;
                let screen = if stage == 0 {
                    Screen::Home
                } else if matches!(stage, 2 | 12) {
                    Screen::Picker {
                        selected: FileChoice::Notes,
                    }
                } else {
                    Screen::AppRunning
                };
                let app = expected(phase, stage, typed)?;
                let reference = Reference::document(screen, app, Access::Edit, ui.cursor())?;
                let shell = steps
                    .iter()
                    .rev()
                    .find(|(_, s)| s.producer == Producer::Shell && s.kind == StepKind::Frame);
                let current = steps.iter().rev().find(|(_, s)| {
                    s.producer
                        == if app.is_some() {
                            Producer::App
                        } else {
                            Producer::Shell
                        }
                        && s.kind
                            == if matches!(stage, 2 | 12) {
                                StepKind::PickerReady
                            } else {
                                StepKind::Frame
                            }
                });
                let ready = if let Some((line, step)) = current {
                    *line > last_line
                        && ui.cursor().is_some()
                        && if app.is_some() {
                            reference.app_composition_ready(step, shell.map(|(_, s)| s))?
                        } else {
                            ui.ready(step.shell_process, step.frame, 0)
                                && reference.surface_hash(Producer::Shell, step.frame)?
                                    == step.surface_sha256
                        }
                } else {
                    false
                };
                if ready {
                    if qmp.is_none() {
                        crate::boot::check_desktop_prefix(&bytes, build)?;
                        qmp = Some(Qmp::connect_at(directory, deadline, origin)?);
                    }
                    let q = qmp.as_mut().ok_or("document guide QMP missing")?;
                    q.set_running(false)?;
                    capture += 1;
                    if capture > 64 {
                        return Err("document guide original capture bound".into());
                    }
                    let (path, pixels) = q.capture(capture)?;
                    let validation = reference.validate(&pixels);
                    captures.push(json!({"stage":stage,"typed":typed,"path":path,"actual_present":current,
                        "all_pixels_match":validation.is_ok(),"validation":validation.as_ref().ok(),"transient_mismatch":validation.as_ref().err(),
                        "expected_view_is_host_model_not_guest_receipt":true}));
                    if validation.is_ok() {
                        last_line = current.ok_or("document guide presentation missing")?.0;
                        if stage == 3 {
                            let raw = disk.bytes()?;
                            storage::immutable_new(&directory.join("document-baseline.raw"), &raw)?;
                            if phase == Phase::Cold {
                                file_proof = Some(crate::native3_disk::document(&raw, 1, SAVED)?);
                            }
                            baseline = Some(raw);
                        }
                        if stage == 9 {
                            let raw = disk.bytes()?;
                            storage::immutable_new(&directory.join("document-saved.raw"), &raw)?;
                            let before =
                                baseline.as_ref().ok_or("document guide baseline missing")?;
                            if before[..32 * 512] != raw[..32 * 512]
                                || before[46 * 512..] != raw[46 * 512..]
                            {
                                return Err(
                                    "document guide save changed bytes outside Notes Store".into(),
                                );
                            }
                            file_proof = Some(crate::native3_disk::document(&raw, 1, SAVED)?);
                        }
                        if stage == 13 {
                            file_proof =
                                Some(crate::native3_disk::document(&disk.bytes()?, 1, SAVED)?);
                        }
                        q.set_running(true)?;
                        let action = match stage {
                            0 | 1 | 2 | 4 | 8 | 10 | 11 | 12 => {
                                tap(q, Key::Enter)?;
                                "Enter"
                            }
                            3 if phase == Phase::Cold => {
                                finishing = true;
                                "finish"
                            }
                            3 | 6 if stage != 6 || typed == SAVED.len() => {
                                tap(q, Key::Tab)?;
                                "Tab"
                            }
                            5 | 6 => {
                                q.ascii(SAVED[typed])?;
                                typed += 1;
                                "character"
                            }
                            7 | 9 => {
                                tap(q, Key::Tab)?;
                                "Tab"
                            }
                            13 => {
                                finishing = true;
                                "finish"
                            }
                            _ => return Err("document guide stage invalid".into()),
                        };
                        inputs.push(json!({"after_stage":stage,"action":action,"typed":typed,"input_transport":"actual QMP PS/2 device; owner UART only for explicit finish"}));
                        if finishing {
                            uart.write_all(b"finish\n")
                                .and_then(|()| uart.flush())
                                .map_err(|e| e.to_string())?;
                            finish_attempts = 1;
                        } else if stage == 5
                            || stage == 6 && typed <= SAVED.len() && action == "character"
                        {
                            stage = 6;
                        } else {
                            stage += 1;
                        }
                    } else {
                        q.set_running(true)?;
                    }
                }
            }
            thread::sleep(Duration::from_millis(4));
        }
    })();
    storage::json_new(
        &directory.join("document-guide.json"),
        &json!({"schema":1,"phase":format!("{phase:?}"),
        "passed":result.is_ok(),"stage":stage,"typed":typed,"error":result.as_ref().err(),"scripted_input":true,"human_acceptance":false,
        "semantic_text_serial_observer":false,"original_captures":captures,"inputs":inputs,"file_proof":file_proof}),
    )?;
    storage::json_new(
        &directory.join("qmp-transcript.json"),
        &json!({"schema":1,"exchanges":qmp.as_ref().map(|q| q.transcript()).unwrap_or(&[])}),
    )?;
    result
}
