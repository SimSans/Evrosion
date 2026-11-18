//! One actual owned-QEMU interruption while Save lacks visible confirmation,
//! followed by actual File/Block cold recovery. A protected Saving Present and
//! matching stopped scanout do not establish File acceptance or a missing ACK.
//! This is not a physical power-loss or every-sector-cut proof.
use crate::{
    boot::{self, ChildGuard},
    build::Result,
    desktop_protocol::{self, Producer, Step, StepKind},
    document_io,
    qmp::{Key, Qmp},
    session_io::ProbeUi,
    session_reference::Reference,
    storage,
};
use ev_graphics::shell::{FileChoice, Screen};
use ev_userspace_contract::document::{Access, Choice, Feedback, Focus, Snapshot, State, Text};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

pub(crate) const CUT: &[u8] = b"Evrosion_03_cut";
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum Phase {
    Cut,
    Cold,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
enum Outcome {
    Old,
    New,
}
impl Outcome {
    fn counter(self) -> u64 {
        match self {
            Self::Old => 1,
            Self::New => 2,
        }
    }
    fn text(self) -> &'static [u8] {
        match self {
            Self::Old => document_io::SAVED,
            Self::New => CUT,
        }
    }
}
fn bounded(path: &Path) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 1024 * 1024 {
        return Err("document interruption log bound/type".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 1024 * 1024 {
        return Err("document interruption log grew beyond bound".into());
    }
    Ok(bytes)
}
fn outside_notes(before: &[u8], after: &[u8]) -> Result<()> {
    if before.len() != storage::DISK_BYTES || after.len() != storage::DISK_BYTES {
        return Err("document interruption requires exact4MiB owner disk".into());
    }
    if before[..32 * 512] != after[..32 * 512] || before[46 * 512..] != after[46 * 512..] {
        return Err("document interruption/recovery changed bytes outside Notes Store".into());
    }
    Ok(())
}
fn allowed_document(bytes: &[u8]) -> Result<(Outcome, Value)> {
    let old = crate::native3_disk::document(bytes, Outcome::Old.counter(), Outcome::Old.text());
    if let Ok(proof) = old {
        return Ok((Outcome::Old, proof));
    }
    let new = crate::native3_disk::document(bytes, Outcome::New.counter(), Outcome::New.text());
    match new {
        Ok(proof) => Ok((Outcome::New, proof)),
        Err(new) => Err(format!(
            "cold document is neither exact old nor exact new: old={}; new={new}",
            old.unwrap_err()
        )),
    }
}
/// Called only AFTER the real cold VM has stopped. No host recovery or reset is
/// performed: native3_disk's write-refusing observer checks the exact allowed
/// envelope, Store operation and original sibling File, while full bytes check
/// also preserves the registry, scalar AppData and legacy private-note region.
pub(crate) fn recovery(before: &[u8], after: &[u8]) -> Result<Value> {
    crate::native3_disk::document(before, 1, document_io::SAVED)?;
    outside_notes(before, after)?;
    let (outcome, proof) = allowed_document(after)?;
    Ok(
        json!({"scope":"one actual owned-VM interruption while Save lacked visible confirmation; actual cold old-or-new recovery",
        "outcome":outcome,"counter":outcome.counter(),"payload_bytes":outcome.text().len(),
        "unchanged_bytes_outside_notes":storage::DISK_BYTES - 14 * 512,"file":proof,
        "file_acceptance_or_missing_ack_inferred":false,"physical_power_loss_claim":false}),
    )
}
fn proposed(state: State, revision: u64, dirty: bool) -> Snapshot {
    Snapshot {
        state,
        focus: Focus::Save,
        choice: Choice::Notes,
        access: Access::Edit,
        text: Text::new(CUT).expect("fixed supported bounded reference text"),
        cursor: CUT.len() as u16,
        anchor: CUT.len() as u16,
        revision,
        feedback: Feedback::None,
        dirty,
    }
}
fn editing_prefix(typed: usize) -> Result<Snapshot> {
    let bytes = CUT
        .get(..typed)
        .ok_or("interruption typing exceeds proposal")?;
    let dirty = bytes != document_io::SAVED;
    Ok(Snapshot {
        state: if dirty { State::Dirty } else { State::Saved },
        focus: Focus::Text,
        text: Text::new(bytes).map_err(|e| format!("interruption prefix: {e:?}"))?,
        cursor: typed as u16,
        anchor: typed as u16,
        dirty,
        ..proposed(State::Dirty, 1, true)
    })
}
fn app_reference(view: Snapshot, ui: &ProbeUi) -> Result<Reference> {
    Reference::document(Screen::AppRunning, Some(view), Access::Edit, ui.cursor())
}
fn shell(steps: &[Step]) -> Option<&Step> {
    steps
        .iter()
        .rev()
        .find(|s| s.producer == Producer::Shell && s.kind == StepKind::Frame)
}
fn app(steps: &[Step]) -> Option<&Step> {
    steps
        .iter()
        .rev()
        .find(|s| s.producer == Producer::App && s.kind == StepKind::Frame)
}
fn complete_unomitted(serial: &[u8]) -> Result<()> {
    if serial.last() != Some(&b'\n') {
        return Err("interruption ends with an incomplete serial record".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "interruption serial UTF8")?;
    if text.lines().any(|line| {
        line.starts_with("EVROSION_M6_LOG_BOUND")
            || line.trim_end_matches('\r') == ev_test_protocol::PASS
    }) {
        return Err("interruption has omitted observations or ordinary completion".into());
    }
    Ok(())
}
/// Strict protected-Present check used both while stopped and after SIGKILL.
/// The latest semantic row is intentionally Dirty: the synchronous Save path
/// paints Saving before Replace and publishes semantic state only afterward.
fn saving(serial: &[u8], build: &str) -> Result<Step> {
    complete_unomitted(serial)?;
    boot::check_desktop_prefix(serial, build)?;
    let steps = desktop_protocol::steps(serial, build)?;
    let observed = document_io::records(serial, build)?;
    let latest = observed
        .last()
        .ok_or("interruption lacks actual semantic document")?;
    let current = app(&steps).ok_or("interruption lacks actual App Present")?;
    let ui = ProbeUi::parse(serial, build)?;
    let dirty = proposed(State::Dirty, 1, true);
    let wanted = proposed(State::Saving, 1, true);
    if latest.view != dirty
        || latest.process != current.app_process
        || current.frame <= latest.frame
        || ui.cursor().is_none()
        || !app_reference(wanted, &ui)?.app_composition_ready(current, shell(&steps))?
    {
        return Err(
            "latest protected App Present is not the exact unconfirmed Saving proposal".into(),
        );
    }
    let saved = app_reference(proposed(State::Saved, 2, false), &ui)?;
    for step in &steps {
        if step.producer == Producer::App
            && step.app_process == current.app_process
            && saved.surface_hash(Producer::App, step.frame)? == step.surface_sha256
        {
            return Err("actual Saved Present preceded interruption".into());
        }
    }
    Ok(current.clone())
}
/// Dedicated boot postflight. Cut accepts only the retained child's SIGKILL
/// plus strict actual Saving prefix. Cold retains the ordinary session grammar.
/// QMP pause/scanout checks happen in supervise and cannot be replaced by this
/// serial verifier or by any guest marker.
pub(crate) fn verify(serial: &[u8], build: &str, phase: Phase, status: ExitStatus) -> Result<()> {
    match phase {
        Phase::Cut => {
            use std::os::unix::process::ExitStatusExt;
            if status.signal() != Some(9) {
                return Err(
                    "document interruption did not SIGKILL/reap retained QEMU child".into(),
                );
            }
            saving(serial, build)?;
            Ok(())
        }
        Phase::Cold => {
            let steps = desktop_protocol::steps(serial, build)?;
            let observed = document_io::records(serial, build)?;
            let latest = observed
                .last()
                .ok_or("cold recovery lacks an actual document row")?;
            let current = app(&steps).ok_or("cold recovery lacks an actual App Present")?;
            let ui = ProbeUi::parse(serial, build)?;
            if outcome(&latest.view).is_none()
                || current.app_process != latest.process
                || current.frame != latest.frame
                || !app_reference(latest.view, &ui)?
                    .app_composition_ready(current, shell(&steps))?
            {
                return Err(
                    "cold recovery lacks exact old/new semantic and protected Saved join".into(),
                );
            }
            crate::session_protocol::retention(serial, build)?;
            let serial = document_io::without_observations(serial, build)?;
            let serial = crate::session_protocol::without_diagnostics(&serial, build)?;
            crate::boot_protocol::check_session(&serial, build, status.code())
        }
    }
}
fn outcome(view: &Snapshot) -> Option<Outcome> {
    [Outcome::Old, Outcome::New].into_iter().find(|value| {
        view.state == State::Saved
            && view.choice == Choice::Notes
            && view.access == Access::Edit
            && view.revision == value.counter()
            && view.text.as_bytes() == value.text()
            && !view.dirty
    })
}
fn tap(qmp: &mut Qmp, key: Key) -> Result<()> {
    qmp.key_state(key, true)?;
    qmp.key_state(key, false)
}
struct Driver<'a> {
    build: &'a str,
    directory: &'a Path,
    disk: &'a storage::Disk,
    phase: Phase,
    origin: Instant,
    deadline: Instant,
    qmp: Option<Qmp>,
    stage: u32,
    typed: usize,
    seen_nonce: u32,
    capture: u32,
    captures: Vec<Value>,
    armed_frame: Option<(u64, u64)>,
    cut_frame: Option<Step>,
    file_proof: Option<Value>,
    done: bool,
}
impl Driver<'_> {
    fn poll(&mut self, serial: &[u8]) -> Result<bool> {
        if self.done {
            return Ok(true);
        }
        let steps = desktop_protocol::steps(serial, self.build)?;
        let observed = document_io::records(serial, self.build)?;
        let latest = observed.last();
        let ui = ProbeUi::parse(serial, self.build)?;
        if self.stage == 9 {
            let (process, after) = self.armed_frame.ok_or("Save was not actually armed")?;
            let Some(current) = app(&steps) else {
                return Ok(false);
            };
            if current.app_process != process {
                return Err("application incarnation changed while waiting for Saving".into());
            }
            if current.frame <= after {
                return Ok(false);
            }
            let saving_reference = app_reference(proposed(State::Saving, 1, true), &ui)?;
            if !saving_reference.app_composition_ready(current, shell(&steps))? {
                let unchanged_dirty = app_reference(proposed(State::Dirty, 1, true), &ui)?;
                if unchanged_dirty.app_composition_ready(current, shell(&steps))? {
                    // Enter paints the still-dirty focused control before poll
                    // prepares the save. This is not the interruption point.
                    return Ok(false);
                }
                return Err(
                    "missed Saving window: later/different actual Present already exists".into(),
                );
            }
            let candidate = current.clone();
            let qmp = self.qmp.as_mut().ok_or("cut QMP absent")?;
            qmp.set_running(false)?;
            // Stop may race the guest. Re-read while confirmed paused; an older
            // Saving observation must never substitute for the latest frame.
            let paused = bounded(&self.directory.join("serial.log"))?;
            let actual = saving(&paused, self.build)?;
            if actual != candidate {
                return Err("Saving changed before QMP confirmed paused".into());
            }
            self.capture += 1;
            let (path, pixels) = qmp.capture(self.capture)?;
            let validation = saving_reference.validate(&pixels);
            self.captures
                .push(json!({"stage":9,"path":path,"actual_present":actual,
                "qmp_running":false,"all_pixels_match":validation.is_ok(),
                "validation":validation.as_ref().ok(),"error":validation.as_ref().err()}));
            validation?;
            self.cut_frame = Some(actual);
            self.done = true;
            // Do not resume, finish, quit or power down. supervised_until will
            // immediately SIGKILL and reap ONLY its own retained direct child.
            return Ok(true);
        }
        let picker = self.stage == 2;
        let screen = match self.stage {
            0 => Screen::Home,
            2 => Screen::Picker {
                selected: FileChoice::Notes,
            },
            _ => Screen::AppRunning,
        };
        let app_view = (screen == Screen::AppRunning)
            .then(|| latest.map(|o| o.view))
            .flatten();
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
        let Some(current) = current else {
            return Ok(false);
        };
        let reference = Reference::document(screen, app_view, Access::Edit, ui.cursor())?;
        let ready = if screen == Screen::AppRunning {
            latest.is_some_and(|o| {
                o.process == current.app_process
                    && o.frame == current.frame
                    && o.nonce > self.seen_nonce
            }) && reference.app_composition_ready(current, shell(&steps))?
        } else {
            ui.cursor().is_some()
                && ui.ready(current.shell_process, current.frame, 0)
                && reference.surface_hash(Producer::Shell, current.frame)? == current.surface_sha256
        };
        let acceptable = match self.stage {
            0 | 2 => true,
            1 => app_view.is_some_and(|v| v.state == State::Closed),
            3 => app_view.is_some_and(|v| {
                outcome(&v).is_some_and(|value| self.phase == Phase::Cold || value == Outcome::Old)
            }),
            4 => app_view.is_some_and(|v| v.focus == Focus::SelectAll),
            5 => app_view.is_some_and(|v| v.focus == Focus::Text && v.anchor == 0),
            6 => app_view == Some(editing_prefix(self.typed)?),
            7 => app_view.is_some_and(|v| v.focus == Focus::SelectAll && v.text.as_bytes() == CUT),
            8 => app_view == Some(proposed(State::Dirty, 1, true)),
            _ => false,
        };
        if !ready || !acceptable {
            return Ok(false);
        }
        if self.qmp.is_none() {
            boot::check_desktop_prefix(serial, self.build)?;
            self.qmp = Some(Qmp::connect_at(self.directory, self.deadline, self.origin)?);
        }
        let qmp = self
            .qmp
            .as_mut()
            .ok_or("document interruption QMP absent")?;
        qmp.set_running(false)?;
        self.capture += 1;
        if self.capture > 80 {
            return Err("document interruption capture bound".into());
        }
        let (path, pixels) = qmp.capture(self.capture)?;
        let validation = reference.validate(&pixels);
        self.captures
            .push(json!({"stage":self.stage,"typed":self.typed,"path":path,
            "actual_present":current,"nonce":latest.map(|o|o.nonce),
            "all_pixels_match":validation.is_ok(),"validation":validation.as_ref().ok(),
            "transient_mismatch":validation.as_ref().err()}));
        if validation.is_err() {
            qmp.set_running(true)?;
            return Ok(false);
        }
        if screen == Screen::AppRunning {
            self.seen_nonce = latest.ok_or("actual App semantic row missing")?.nonce;
        }
        if self.stage == 3 {
            let value = outcome(&app_view.ok_or("actual saved document view missing")?)
                .ok_or("actual saved document is not an allowed outcome")?;
            let raw = self.disk.bytes()?;
            self.file_proof = Some(crate::native3_disk::document(
                &raw,
                value.counter(),
                value.text(),
            )?);
            storage::immutable_new(&self.directory.join("document-opened.raw"), &raw)?;
            if self.phase == Phase::Cold {
                self.done = true;
                qmp.set_running(true)?;
                return Ok(true);
            }
        }
        // input-send-event requires a running VM. Resume after verifying this
        // checkpoint and before the next actual input. The stage9 cut branch
        // above deliberately remains paused after its exact Saving capture.
        qmp.set_running(true)?;
        // All stimuli reach real QEMU input devices. No guest ACK is injected.
        match self.stage {
            0 | 1 | 2 | 4 => {
                tap(qmp, Key::Enter)?;
                self.stage += 1;
            }
            3 => {
                tap(qmp, Key::Tab)?;
                self.stage = 4;
            }
            5 => {
                qmp.ascii(CUT[0])?;
                self.typed = 1;
                self.stage = 6;
            }
            6 if self.typed < CUT.len() => {
                qmp.ascii(CUT[self.typed])?;
                self.typed += 1;
            }
            6 => {
                tap(qmp, Key::Tab)?;
                self.stage = 7;
            }
            7 => {
                tap(qmp, Key::Tab)?;
                self.stage = 8;
            }
            8 => {
                self.armed_frame = Some((current.app_process, current.frame));
                tap(qmp, Key::Enter)?;
                self.stage = 9;
            }
            _ => return Err("document interruption input stage invalid".into()),
        }
        Ok(false)
    }
}

/// Cut uses boot's existing supervised_until owner/kill/reap path. Cold starts
/// one new owned QEMU, permits real Store::open recovery, performs a fresh picker
/// open, then uses the existing finite Root finish protocol. Never runs both at
/// once, writes a host-repaired disk or restores a pre-interruption snapshot.
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
    let deadline = origin
        .checked_add(timeout)
        .ok_or("interruption host deadline overflow")?;
    let initial = disk.bytes()?;
    storage::immutable_new(&directory.join("document-before.raw"), &initial)?;
    let mut driver = Driver {
        build,
        directory,
        disk,
        phase,
        origin,
        deadline,
        qmp: None,
        stage: 0,
        typed: 0,
        seen_nonce: 0,
        capture: 0,
        captures: Vec::new(),
        armed_frame: None,
        cut_frame: None,
        file_proof: None,
        done: false,
    };
    let mut result = (|| {
        if phase == Phase::Cut {
            crate::native3_disk::document(&initial, 1, document_io::SAVED)?;
        }
        let status = match phase {
            Phase::Cut => {
                command.stdin(Stdio::null());
                let mut stop = || driver.poll(&bounded(serial)?);
                boot::supervised_until(command, &[serial, errors], timeout, Some(&mut stop))?
            }
            Phase::Cold => {
                let mut child = ChildGuard(
                    command
                        .stdin(Stdio::piped())
                        .spawn()
                        .map_err(|e| e.to_string())?,
                );
                let mut uart = child.0.stdin.take().ok_or("cold document UART absent")?;
                let mut finishing = false;
                let mut finished = false;
                let mut attempts = 0;
                let mut last_report = 0;
                loop {
                    if Instant::now() >= deadline {
                        return Err(format!(
                            "cold document recovery deadline stage={}",
                            driver.stage
                        ));
                    }
                    let bytes = bounded(serial)?;
                    bounded(errors)?;
                    if let Some(status) = child.0.try_wait().map_err(|e| e.to_string())? {
                        if !finished || status.code() != Some(ev_test_protocol::QEMU_PASS_STATUS) {
                            return Err(format!(
                                "cold document VM exited before checked finish: {status}"
                            ));
                        }
                        break status;
                    }
                    if finishing {
                        let clean = document_io::without_observations(&bytes, build)?;
                        for state in crate::native_protocol::states(&clean, build)? {
                            let report = state.number("report")?;
                            if state.fields["op"] == "finish" && report > last_report {
                                last_report = report;
                                match state.fields["result"].as_str() {
                                    "ok" => finished = true,
                                    "busy" if attempts < 8 => {
                                        uart.write_all(b"finish\n").map_err(|e| e.to_string())?;
                                        uart.flush().map_err(|e| e.to_string())?;
                                        attempts += 1;
                                    }
                                    _ => return Err("cold document finish refused".into()),
                                }
                            }
                        }
                    } else if driver.poll(&bytes)? {
                        uart.write_all(b"finish\n").map_err(|e| e.to_string())?;
                        uart.flush().map_err(|e| e.to_string())?;
                        attempts = 1;
                        finishing = true;
                    }
                    thread::sleep(Duration::from_millis(4));
                }
            }
        };
        verify(&bounded(serial)?, build, phase, status)?;
        let after = disk.bytes()?;
        outside_notes(&initial, &after)?;
        if phase == Phase::Cold {
            let (_, proof) = allowed_document(&after)?;
            if driver.file_proof.as_ref() != Some(&proof) {
                return Err("cold final disk differs from the actually opened document".into());
            }
        }
        Ok(status)
    })();
    // Both supervisor paths reap their old writer before returning, including
    // failures. Keep the actual post-attempt image even when Saving was missed;
    // a failed race must not disappear or be mistaken for a passing cut.
    let retained = disk
        .bytes()
        .and_then(|bytes| storage::immutable_new(&directory.join("document-after.raw"), &bytes));
    if let Err(error) = retained {
        result = Err(format!(
            "{}; post-attempt raw retention failed: {error}",
            result
                .as_ref()
                .err()
                .map(String::as_str)
                .unwrap_or("VM checks passed")
        ));
    }
    #[cfg(unix)]
    let signal = {
        use std::os::unix::process::ExitStatusExt;
        result.as_ref().ok().and_then(ExitStatusExt::signal)
    };
    storage::json_new(
        &directory.join("document-interruption-observer.json"),
        &json!({
            "schema":1,"phase":phase,"passed":result.is_ok(),"error":result.as_ref().err(),
            "scope":"one owned-QEMU interruption while Save lacked protected/visible confirmation; actual cold File/Block recovery",
            "stage":driver.stage,"typed":driver.typed,"proposal_bytes":CUT.len(),
            "scripted_input":true,"human_acceptance":false,"captures":driver.captures,
            "armed_frame":driver.armed_frame,"cut_frame":driver.cut_frame,"file_proof":driver.file_proof,
            "exit_signal":signal,"file_acceptance_or_missing_ack_inferred":false,
            "physical_power_loss_claim":false,"all_io_cut_claim":false,
        }),
    )?;
    storage::json_new(
        &directory.join("qmp-transcript.json"),
        &json!({"schema":1,
        "exchanges":driver.qmp.as_ref().map(Qmp::transcript).unwrap_or(&[])}),
    )?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    // Existing boot-parser fixture plus explicit synthetic observation rows.
    // These are verifier regressions, never claims that the synthetic VM ran.
    const PREFIX: &[u8] = include_bytes!("../../../tests/fixtures/native3-home-prefix.serial");
    const BUILD: &str = "38b85b3ddf4afbb6b9929931fca6f95fceccdd48f5eec3bea6554e13b9b49918";

    fn step(frame: u64, producer: Producer, view: Snapshot) -> String {
        let reference =
            Reference::document(Screen::AppRunning, Some(view), Access::Edit, None).unwrap();
        format!(
            "EVROSION_M4_DESKTOP_STEP protocol=1 build={BUILD} step=frame frame={frame} width=1280 height=800 app_process=7 shell_process=6 display_process=3 grants=1 producer={} surface_sha256={} held_ticks=0\n",
            if producer == Producer::App {
                "app"
            } else {
                "shell"
            },
            reference.surface_hash(producer, frame).unwrap()
        )
    }
    fn trace() -> Vec<u8> {
        let mut bytes = PREFIX.to_vec();
        let cursor = ev_desktop::protocol::CursorControl {
            x: 0,
            y: 0,
            sequence: 1,
        };
        bytes.extend_from_slice(format!(
            "EVROSION_M6_CURSOR protocol=1 build={BUILD} count=1 call_epoch=1 call=3 endpoint=4 caller_process=6 caller_thread=6 callee_process=3 callee_thread=3 x=0 y=0 sequence=1 request={:016x} reply={:016x} tick=11\n",
            u64::from_le_bytes(cursor.request().unwrap()),
            u64::from_le_bytes(cursor.reply().unwrap())
        ).as_bytes());
        let dirty = proposed(State::Dirty, 1, true);
        bytes.extend_from_slice(step(2, Producer::Shell, dirty).as_bytes());
        bytes.extend_from_slice(step(4, Producer::App, dirty).as_bytes());
        let body = dirty.encode().unwrap();
        let hex: String = body.iter().map(|byte| format!("{byte:02x}")).collect();
        bytes.extend_from_slice(format!(
            "EVROSION_M7_DOCUMENT protocol=1 build={BUILD} process=7 thread=7 endpoint=55 ticket=1 nonce=1 tick=20 frame=4 bytes={hex}\n"
        ).as_bytes());
        bytes
            .extend_from_slice(step(5, Producer::App, proposed(State::Saving, 1, true)).as_bytes());
        bytes
    }

    #[test]
    fn saving_verifier_requires_actual_latest_hash_and_sigkill_not_an_exit_marker() {
        assert_eq!(CUT.len(), 15);
        let bytes = trace();
        assert_eq!(saving(&bytes, BUILD).unwrap().frame, 5);
        verify(&bytes, BUILD, Phase::Cut, ExitStatus::from_raw(9)).unwrap();
        for raw in [0, 15, ev_test_protocol::QEMU_PASS_STATUS << 8] {
            assert!(verify(&bytes, BUILD, Phase::Cut, ExitStatus::from_raw(raw)).is_err());
        }
        assert!(saving(&bytes, &"a".repeat(64)).is_err());
        let altered = String::from_utf8(bytes).unwrap().replace(
            "process=7 thread=7 endpoint=55",
            "process=8 thread=8 endpoint=55",
        );
        assert!(saving(altered.as_bytes(), BUILD).is_err());
    }

    #[test]
    fn actual_editor_returns_saved_at_old_content_prefix_then_dirty_for_later_bytes() {
        use ev_native_hello::document::Editor;
        let mut editor = Editor::new();
        editor
            .open(
                Choice::Notes,
                Access::Edit,
                1,
                &ev_file::Payload::new(document_io::SAVED).unwrap(),
            )
            .unwrap();
        editor.select_all().unwrap();
        for typed in 1..=CUT.len() {
            editor
                .insert(core::str::from_utf8(&CUT[typed - 1..typed]).unwrap())
                .unwrap();
            assert_eq!(
                editor.snapshot(),
                editing_prefix(typed).unwrap(),
                "prefix {typed}"
            );
        }
        assert_eq!(
            editing_prefix(document_io::SAVED.len()).unwrap().state,
            State::Saved
        );
        assert_eq!(editing_prefix(CUT.len()).unwrap().state, State::Dirty);
        assert!(editing_prefix(CUT.len() + 1).is_err());
    }

    #[test]
    fn saving_verifier_rejects_later_checking_saved_and_a_cached_earlier_saving() {
        for later in [
            proposed(State::Readback, 1, true),
            proposed(State::Saved, 2, false),
        ] {
            let mut bytes = trace();
            bytes.extend_from_slice(step(6, Producer::App, later).as_bytes());
            assert!(saving(&bytes, BUILD).is_err());
        }
        let mut bytes = trace();
        bytes
            .extend_from_slice(step(6, Producer::App, proposed(State::Saved, 2, false)).as_bytes());
        bytes
            .extend_from_slice(step(7, Producer::App, proposed(State::Saving, 1, true)).as_bytes());
        assert_eq!(
            saving(&bytes, BUILD).unwrap_err(),
            "actual Saved Present preceded interruption"
        );
    }

    #[test]
    fn saving_verifier_refuses_truncated_or_omitted_observations_and_completion() {
        let mut truncated = trace();
        truncated.pop();
        assert!(saving(&truncated, BUILD).is_err());
        for suffix in [
            "EVROSION_M6_LOG_BOUND protocol=1 observation=1 retained=0 detail_bytes=0\n".to_owned(),
            format!("{}\n", ev_test_protocol::PASS),
        ] {
            let mut bytes = trace();
            bytes.extend_from_slice(suffix.as_bytes());
            assert!(saving(&bytes, BUILD).is_err());
        }
    }

    #[test]
    fn cold_outcomes_are_exact_old_or_new_and_all_nonselected_bytes_are_protected() {
        let old = Snapshot {
            text: Text::new(document_io::SAVED).unwrap(),
            cursor: document_io::SAVED.len() as u16,
            anchor: document_io::SAVED.len() as u16,
            ..proposed(State::Saved, 1, false)
        };
        assert_eq!(outcome(&old), Some(Outcome::Old));
        let new = proposed(State::Saved, 2, false);
        assert_eq!(outcome(&new), Some(Outcome::New));
        for bad in [
            Snapshot { revision: 1, ..new },
            Snapshot { revision: 2, ..old },
            Snapshot { dirty: true, ..new },
            Snapshot {
                access: Access::Read,
                ..new
            },
            Snapshot {
                text: Text::new(&CUT[..CUT.len() - 1]).unwrap(),
                ..new
            },
        ] {
            assert_eq!(outcome(&bad), None);
        }
        let before = vec![0; storage::DISK_BYTES];
        let mut after = before.clone();
        after[32 * 512] = 1;
        after[46 * 512 - 1] = 1;
        outside_notes(&before, &after).unwrap();
        for sector in [0, 16, 31, 46, 48, 64, 80, 96, 112, 8191] {
            let mut changed = after.clone();
            changed[sector * 512] = 1;
            assert!(outside_notes(&before, &changed).is_err());
        }
        assert!(outside_notes(&before, &after[..after.len() - 1]).is_err());
    }
}
