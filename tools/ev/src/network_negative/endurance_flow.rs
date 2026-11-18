//! The sustained-use workflow joins actual protected work and Scheduler CPU
//! to surviving Shell pixels, then an ordinary stopped/reaped App replacement.
use super::{cases, endurance_disk, endurance_observer, fixture, note, records};
use crate::{
    build::{self, Result},
    desktop_protocol::{Producer, Step, StepKind},
    native_protocol::{Action, StateRecord},
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
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{io::Write, path::Path};

pub(super) struct Flow {
    stage: u8,
    work: Option<note::Work>,
    old: Option<(u64, u64)>,
    new: Option<(u64, u64)>,
    shell: Option<(u64, u64)>,
    display: Option<u64>,
    baseline: Option<Vec<u8>>,
    history: Vec<u8>,
    escape_prefix: Option<(usize, [u8; 32])>,
    escape_lines: usize,
    min_shell_frame: u64,
    home_line: Option<usize>,
    threshold: Option<endurance_observer::Threshold>,
    reopen_prefix: usize,
    reopened: bool,
    captures: Vec<Value>,
    inputs: Vec<Value>,
    disk_proofs: Vec<Value>,
    finish_report: u64,
    finish_attempts: u8,
    pub(super) finish_sent: bool,
}
impl Flow {
    pub(super) fn new() -> Self {
        Self {
            stage: 0,
            work: None,
            old: None,
            new: None,
            shell: None,
            display: None,
            baseline: None,
            history: Vec::new(),
            escape_prefix: None,
            escape_lines: 0,
            min_shell_frame: 0,
            home_line: None,
            threshold: None,
            reopen_prefix: 0,
            reopened: false,
            captures: Vec::new(),
            inputs: Vec::new(),
            disk_proofs: Vec::new(),
            finish_report: 0,
            finish_attempts: 0,
            finish_sent: false,
        }
    }
    fn send(&mut self, input: &mut impl Write, command: &str) -> Result<()> {
        input
            .write_all(command.as_bytes())
            .and_then(|()| input.flush())
            .map_err(|e| e.to_string())?;
        self.inputs.push(json!({"command":command,"stage":self.stage,"scripted_input":true,"human_consent_claim":false}));
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn advance(
        &mut self,
        serial: &[u8],
        build: &str,
        context: &Context,
        peer: &fixture::Snapshot,
        input: &mut impl Write,
        qmp: &mut Qmp,
        disk: &storage::Disk,
        directory: &Path,
    ) -> Result<()> {
        if !serial.starts_with(&self.history) {
            return Err("endurance actual serial prefix truncated/rewritten".into());
        }
        self.history = serial.to_vec();
        hello(peer, false)?;
        if !actual_context(serial, build, context)? {
            return Ok(());
        }
        if !crate::network_error_protocol::records(serial, build)?.is_empty()
            || crate::network_protocol::records(serial, build)?
                .iter()
                .any(|r| r.stage == 8)
        {
            return Err("endurance actual NIC failure before ordinary Finish".into());
        }
        let states = crate::native_protocol::states_network(serial, build)?;
        let actions = actions(serial, build)?;
        if self.old.is_some() {
            self.action_prefix(&actions, &context.images[5], false)?;
        }
        let evidence = endurance_observer::prefix(serial, build, Some(&context.images))?;
        match self.stage {
            0 => {
                if crate::network_protocol::records(serial, build)?
                    .last()
                    .is_some_and(|r| r.stage == 6)
                    && peer.hello_completed == 1
                {
                    hello(peer, true)?;
                    self.send(input, "install a\n")?;
                    self.stage = 1;
                }
            }
            1 => {
                if let Some(r) = reply(&states, "install", 1)? {
                    if r.fields["staged"] != "a" || r.number("revision")? != 1 {
                        return Err("endurance initial install selection/revision".into());
                    }
                    self.send(input, "activate\n")?;
                    self.stage = 2;
                }
            }
            2 => {
                if let Some(r) = reply(&states, "activate", 1)? {
                    let old = active(r, context, 2)?;
                    self.old = Some(old);
                    self.shell = actual_shell(serial, build)?;
                    self.work = Some(note::Work::new(old.0));
                    self.stage = 3;
                    self.action_prefix(&actions, &context.images[5], false)?;
                }
            }
            3 => {
                if self.work.as_mut().unwrap().advance(serial, build, qmp)? {
                    let observed = records::prefix(serial, build, Some(&context.images))?;
                    if !cases::app_denials(&observed)? {
                        return Ok(());
                    }
                    let frames = frames(serial, build)?;
                    let shell = frames
                        .iter()
                        .rev()
                        .find(|(_, s)| s.producer == Producer::Shell && s.kind == StepKind::Frame)
                        .ok_or("endurance saved Note lacks actual Shell frame")?;
                    if Some(shell.1.shell_process) != self.shell.map(|s| s.0)
                        || shell.1.app_process != self.old.unwrap().0
                    {
                        return Err("endurance initial Note belongs to another Shell/App".into());
                    }
                    self.display = Some(shell.1.display_process);
                    qmp.set_running(false)?;
                    let snapshot: Result<_> = (|| {
                        let bytes = disk.bytes()?;
                        let proof = endurance_disk::saved(&bytes, &context.packages()?, 2)?;
                        disk.capture(directory, "endurance-saved-before-work.raw")?;
                        Ok((bytes, proof))
                    })();
                    qmp.set_running(true)?;
                    let (bytes, proof) = snapshot?;
                    self.baseline = Some(bytes);
                    self.disk_proofs.push(proof);
                    self.send(input, "net-endurance\n")?;
                    self.stage = 4;
                }
            }
            4 => {
                if let Some(e) = &evidence
                    && e.app.is_some()
                    && e.shell.is_some()
                {
                    if e.app.as_ref().map(|w| w.identity) != self.old
                        || e.shell.as_ref().map(|w| w.identity) != self.shell
                    {
                        return Err(
                            "endurance delivered work differs from actual live Note/Shell".into(),
                        );
                    }
                    let fs = frames(serial, build)?;
                    let shell = fs
                        .iter()
                        .rev()
                        .find(|(_, s)| s.producer == Producer::Shell && s.kind == StepKind::Frame)
                        .ok_or("endurance no pre-Escape Shell frame")?;
                    self.min_shell_frame = shell.1.frame;
                    self.escape_prefix = Some((serial.len(), Sha256::digest(serial).into()));
                    self.escape_lines = serial.iter().filter(|b| **b == b'\n').count();
                    note::tap(qmp, Key::Escape)?;
                    self.inputs.push(json!({"device":"owned PS2","key":"Escape","after_actual_both_WORK":true,"stage":4}));
                    self.stage = 5;
                }
            }
            5 => {
                if let Some(line) = self.capture_home(serial, build, qmp)? {
                    self.home_line = Some(line);
                    self.stage = 6;
                }
            }
            6 => {
                if let Some(e) = &evidence
                    && let Some(t) = e.threshold()?
                {
                    if Some(t.app) != self.old || Some(t.shell) != self.shell {
                        return Err("endurance threshold changed workers".into());
                    }
                    if self.home_line.is_none() {
                        return Err("endurance CPU cannot substitute for surviving Shell UI".into());
                    }
                    self.threshold = Some(t);
                    // The actual Root UART parses the first line before the second.
                    // No synthetic ACK or wall-clock delay claims Stop completion.
                    self.send(input, "net-endurance-stop\nremove\n")?;
                    self.stage = 7;
                }
            }
            7 => {
                if let Some(r) = reply(&states, "remove", 1)? {
                    if r.number("revision")? != 3
                        || r.number("installed")? != 0
                        || r.fields["active"] != "none"
                        || r.fields["previous"] != "a"
                        || r.number("actual_process")? != 0
                    {
                        return Err("endurance actual Remove did not retire selected App".into());
                    }
                    exact_actions(&actions, &[self.old.unwrap()], &context.images[5], true)?;
                    self.send(input, "reinstall a\n")?;
                    self.stage = 8;
                }
            }
            8 => {
                if let Some(r) = reply(&states, "reinstall", 1)? {
                    if r.number("revision")? != 4
                        || r.number("installed")? != 1
                        || r.fields["staged"] != "a"
                        || r.fields["active"] != "none"
                        || r.fields["previous"] != "a"
                        || r.number("actual_process")? != 0
                        || r.number("value")? != 1001
                        || r.number("data_counter")? != 0
                    {
                        return Err("endurance Reinstall changed saved scalar/selection".into());
                    }
                    self.reopen_prefix = serial.iter().filter(|b| **b == b'\n').count();
                    self.send(input, "activate\n")?;
                    self.stage = 9;
                }
            }
            9 => {
                if let Some(r) = reply(&states, "activate", 2)? {
                    let new = active(r, context, 5)?;
                    let old = self.old.unwrap();
                    if new.0 == old.0 || new.1 == old.1 {
                        return Err("endurance replacement reused old actual incarnation".into());
                    }
                    self.new = Some(new);
                    self.action_prefix(&actions, &context.images[5], false)?;
                    self.stage = 10;
                }
            }
            10 => {
                if self.capture_reopened(serial, build, qmp)? {
                    qmp.set_running(false)?;
                    let snapshot: Result<_> = (|| {
                        let bytes = disk.bytes()?;
                        let proof = endurance_disk::replacement(
                            self.baseline
                                .as_ref()
                                .ok_or("endurance initial saved snapshot absent")?,
                            &bytes,
                            &context.packages()?,
                        )?;
                        disk.capture(directory, "endurance-reopened-saved.raw")?;
                        Ok(proof)
                    })();
                    qmp.set_running(true)?;
                    self.disk_proofs.push(snapshot?);
                    self.reopened = true;
                    self.send(input, "finish\n")?;
                    self.finish_sent = true;
                    self.finish_attempts = 1;
                    self.stage = 11;
                }
            }
            11 => {
                for r in states.iter().filter(|r| r.fields["op"] == "finish") {
                    let report = r.number("report")?;
                    if report <= self.finish_report {
                        continue;
                    }
                    self.finish_report = report;
                    match r.fields["result"].as_str() {
                        "ok" => self.stage = 12,
                        "busy" if self.finish_attempts < 8 => {
                            self.send(input, "finish\n")?;
                            self.finish_attempts += 1;
                        }
                        _ => return Err("endurance ordinary Finish refused or Busy bound".into()),
                    }
                }
            }
            12 => (),
            _ => return Err("endurance Host stage".into()),
        }
        Ok(())
    }
    fn action_prefix(&self, actual: &[Action], image: &str, final_boundary: bool) -> Result<()> {
        let old = self.old.ok_or("endurance missing old App")?;
        let count = actual.len();
        let range = if final_boundary {
            6..=6
        } else {
            match self.stage {
                0..=2 => 0..=1,
                3..=6 => 1..=1,
                7 => 1..=3,
                8 => 3..=3,
                9 => 3..=4,
                10 => 4..=4,
                11..=12 => 4..=6,
                _ => return Err("endurance action stage".into()),
            }
        };
        if !range.contains(&count) {
            return Err("endurance unexpected early stop/reap/new App".into());
        }
        for (i, a) in actual.iter().enumerate() {
            let kind = ["start", "stop", "reap"][i % 3];
            let id = if i < 3 {
                old
            } else {
                self.new.unwrap_or((a.process, a.thread))
            };
            if a.kind != kind
                || (a.process, a.thread) != id
                || a.image_sha256 != image
                || i >= 3 && (a.process == old.0 || a.thread == old.1)
            {
                return Err("endurance stale/foreign/replayed App lifecycle".into());
            }
        }
        Ok(())
    }
    fn capture_home(&mut self, serial: &[u8], build: &str, qmp: &mut Qmp) -> Result<Option<usize>> {
        let ui = ProbeUi::parse(serial, build)?;
        let fs = frames(serial, build)?;
        let Some((line, shell)) = fs
            .iter()
            .rev()
            .find(|(_, s)| s.producer == Producer::Shell && s.kind == StepKind::Frame)
        else {
            return Ok(None);
        };
        let reference = Reference::new(Screen::Home, None, ui.cursor())?;
        if *line < self.escape_lines
            || shell.frame <= self.min_shell_frame
            || shell.shell_process != self.shell.unwrap().0
            || shell.app_process != self.old.unwrap().0
            || Some(shell.display_process) != self.display
            || shell.grants != 0
            || reference.surface_hash(Producer::Shell, shell.frame)? != shell.surface_sha256
            || !ui.ready(shell.shell_process, shell.frame, *line)
        {
            return Ok(None);
        }
        self.capture(
            qmp,
            &reference,
            shell,
            "same-Shell Home during actual abusive App",
        )?;
        Ok(Some(*line))
    }
    fn capture_reopened(&mut self, serial: &[u8], build: &str, qmp: &mut Qmp) -> Result<bool> {
        let ui = ProbeUi::parse(serial, build)?;
        let new = self.new.unwrap();
        let Some(ack) = ui.note_complete(new.0, 1, 1) else {
            return Ok(false);
        };
        let fs = frames(serial, build)?;
        let Some((line, app)) = fs
            .iter()
            .rev()
            .find(|(_, s)| s.producer == Producer::App && s.kind == StepKind::Frame)
        else {
            return Ok(false);
        };
        let Some((shell_line, shell)) = fs
            .iter()
            .rev()
            .find(|(_, s)| s.producer == Producer::Shell && s.kind == StepKind::Frame)
        else {
            return Ok(false);
        };
        let reference = Reference::new(
            Screen::AppRunning,
            Some(View {
                build: Build::A,
                focus: Focus::Note,
                note: note::FIRST.as_bytes(),
                state: SaveState::Saved,
                file: None,
            }),
            ui.cursor(),
        )?;
        if *line < self.reopen_prefix
            || *line <= ack
            || app.app_process != new.0
            || app.shell_process != self.shell.unwrap().0
            || Some(app.display_process) != self.display
            || app.grants != 0
            || !reference.fresh_app_ready(app, *line, shell, *shell_line, &ui)?
        {
            return Ok(false);
        }
        self.capture(
            qmp,
            &reference,
            app,
            "replacement NoteRead1 and reopened saved pixels",
        )?;
        Ok(true)
    }
    fn capture(
        &mut self,
        qmp: &mut Qmp,
        reference: &Reference,
        step: &Step,
        purpose: &str,
    ) -> Result<()> {
        let index = 128u32
            .checked_add(
                self.captures
                    .len()
                    .try_into()
                    .map_err(|_| "endurance capture count")?,
            )
            .ok_or("endurance capture index")?;
        if index > 135 {
            return Err("endurance additional scanout bound8".into());
        }
        qmp.set_running(false)?;
        let capture = qmp.capture(index);
        qmp.set_running(true)?;
        let (path, frame) = capture?;
        if frame.dimensions() != (step.width, step.height) {
            return Err("endurance actual scanout geometry".into());
        }
        let result = reference.validate(&frame);
        self.captures.push(json!({"purpose":purpose,"step":step,"path":path.file_name(),"sha256":build::hash_file(&path)?,"passed":result.is_ok(),"validation":result.as_ref().ok(),"error":result.as_ref().err()}));
        result.map(|_| ())
    }
    pub(super) fn verify_final(
        &self,
        serial: &[u8],
        build: &str,
        context: &Context,
        peer: &fixture::Snapshot,
    ) -> Result<()> {
        hello(peer, true)?;
        if !self.finish_sent
            || !self.reopened
            || self.home_line.is_none()
            || self.threshold.is_none()
            || self.disk_proofs.len() != 2
        {
            return Err("endurance required GUI/data/CPU/Finish join absent".into());
        }
        if !serial.starts_with(&self.history) {
            return Err("endurance final history rewritten/truncated".into());
        }
        let (length, hash) = self
            .escape_prefix
            .ok_or("endurance actual pre-Escape prefix absent")?;
        if serial
            .get(..length)
            .map(|b| <[u8; 32]>::from(Sha256::digest(b)))
            != Some(hash)
        {
            return Err("endurance final pre-Escape serial binding differs".into());
        }
        let e = endurance_observer::prefix(serial, build, Some(&context.images))?
            .ok_or("endurance final CPU evidence absent")?;
        let threshold = e.complete()?;
        let captured = self.threshold.as_ref().unwrap();
        if Some(threshold.app) != self.old
            || Some(threshold.shell) != self.shell
            || threshold.first_sample != captured.first_sample
            || threshold.last_sample < captured.last_sample
            || threshold
                .delta
                .iter()
                .zip(captured.delta)
                .any(|(last, first)| *last < first)
        {
            return Err("endurance final CPU proof regressed/changed actual workers".into());
        }
        self.action_prefix(&actions(serial, build)?, &context.images[5], true)?;
        let ui = ProbeUi::parse(serial, build)?;
        for (app, nonce, opcode) in [
            (self.old.unwrap().0, 1, 1),
            (self.old.unwrap().0, 2, 2),
            (self.new.unwrap().0, 1, 1),
        ] {
            if ui.note_complete(app, nonce, opcode).is_none() {
                return Err(
                    "endurance initial saved/reopened actual Note transaction absent".into(),
                );
            }
        }
        ui.finish()?;
        Ok(())
    }
    pub(super) fn receipt(&self) -> Value {
        json!({"stage":self.stage,"old_app":self.old,"replacement_app":self.new,"shell":self.shell,"display":self.display,"finish_sent":self.finish_sent,"finish_attempts":self.finish_attempts,"inputs":self.inputs,"initial_note_captures":self.work.as_ref().map(|w|&w.captures),"captures":self.captures,"home_line":self.home_line,"threshold":self.threshold,"reopened":self.reopened,"disk_proofs":self.disk_proofs,"escape_serial_prefix":self.escape_prefix})
    }
}
fn frames(serial: &[u8], build: &str) -> Result<Vec<(usize, Step)>> {
    let mut out = Vec::new();
    for (i, line) in std::str::from_utf8(serial)
        .map_err(|_| "endurance desktop UTF8")?
        .lines()
        .enumerate()
    {
        if line.starts_with("EVROSION_M4_DESKTOP_STEP ") {
            out.push((i, crate::desktop_protocol::step_line(line, build)?));
            if out.len() > 256 {
                return Err("endurance desktop bound256".into());
            }
        }
    }
    Ok(out)
}
fn actions(serial: &[u8], build: &str) -> Result<Vec<Action>> {
    let mut out = Vec::new();
    for line in std::str::from_utf8(serial)
        .map_err(|_| "endurance lifecycle UTF8")?
        .lines()
    {
        if line.starts_with("EVROSION_M5_NATIVE_ACTION ") {
            out.push(crate::native_protocol::action(line, build)?);
            if out.len() > 6 {
                return Err("endurance lifecycle bound6".into());
            }
        }
    }
    Ok(out)
}
fn exact_actions(actual: &[Action], ids: &[(u64, u64)], image: &str, closed: bool) -> Result<()> {
    if actual.len() != ids.len() * 3 - usize::from(!closed) {
        return Err("endurance ordinary stopped/reaped history absent".into());
    }
    for (i, a) in actual.iter().enumerate() {
        if a.kind != ["start", "stop", "reap"][i % 3]
            || (a.process, a.thread) != ids[i / 3]
            || a.image_sha256 != image
        {
            return Err("endurance foreign lifecycle history".into());
        }
    }
    Ok(())
}
fn reply<'a>(states: &'a [StateRecord], op: &str, count: usize) -> Result<Option<&'a StateRecord>> {
    let rows: Vec<_> = states.iter().filter(|r| r.fields["op"] == op).collect();
    if rows.len() > count {
        return Err(format!("endurance repeated command:{op}"));
    }
    for row in &rows {
        if !row.is(op) || row.number("recovery")? != 0 {
            return Err(format!("endurance refused command:{op}"));
        }
    }
    Ok(if rows.len() == count {
        rows.last().copied()
    } else {
        None
    })
}
fn active(r: &StateRecord, context: &Context, revision: u64) -> Result<(u64, u64)> {
    let id = (r.number("actual_process")?, r.number("actual_thread")?);
    if r.fields["active"] != "a"
        || r.fields["staged"] != "none"
        || r.fields["previous"] != if revision == 2 { "none" } else { "a" }
        || r.number("installed")? != 1
        || r.number("revision")? != revision
        || r.number("data_epoch")? != 1
        || r.number("value")? != 1001
        || r.number("data_counter")? != 0
        || r.fields["actual_image_sha256"] != context.images[5]
        || [id.0, id.1].iter().any(|v| matches!(*v, 0 | u64::MAX))
    {
        return Err("endurance actual A/data incarnation differs".into());
    }
    Ok(id)
}
fn actual_shell(serial: &[u8], build: &str) -> Result<Option<(u64, u64)>> {
    let mut result = None;
    for line in std::str::from_utf8(serial)
        .map_err(|_| "endurance Shell UTF8")?
        .lines()
    {
        if line.starts_with("EVROSION_M5_NATIVE_CRITICAL_READY ") {
            let crate::native3_protocol::Event::Critical(c) =
                crate::native3_protocol::event_network(line, build)?
            else {
                unreachable!()
            };
            if result.replace((c.process, c.thread)).is_some() {
                return Err("endurance Shell incarnation changed".into());
            }
        }
    }
    Ok(result)
}
fn actual_context(serial: &[u8], build: &str, context: &Context) -> Result<bool> {
    let mut common = false;
    for line in std::str::from_utf8(serial)
        .map_err(|_| "endurance source UTF8")?
        .lines()
    {
        if line.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX ") {
            let crate::native3_protocol::Event::Common(c) =
                crate::native3_protocol::event_network(line, build)?
            else {
                unreachable!()
            };
            if common
                || c.mode != 0
                || c.root_image != context.images[0]
                || c.root_manifest != context.root_manifest
                || c.block_image != context.images[4]
                || c.root_frames != context.root_frames
                || c.block_frames != context.block_frames
            {
                return Err("endurance selected actual Root/Block differs".into());
            }
            common = true;
        }
        if line.starts_with("EVROSION_M5_NATIVE_CRITICAL_READY ") {
            let crate::native3_protocol::Event::Critical(c) =
                crate::native3_protocol::event_network(line, build)?
            else {
                unreachable!()
            };
            if c.image != context.images[1] {
                return Err("endurance selected actual Shell differs".into());
            }
        }
    }
    Ok(common)
}
fn hello(peer: &fixture::Snapshot, complete: bool) -> Result<()> {
    if peer.error.is_some()
        || peer.accepted > 1
        || peer.hello_completed > 1
        || peer.pending_accepted != 0
        || peer.requests.iter().any(|r| r != fixture::HELLO)
    {
        return Err("endurance owned Hello-only peer differs".into());
    }
    let response_bytes = format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",crate::network_fixture::HELLO.len()).len()+crate::network_fixture::HELLO.len();
    if complete
        && (peer.accepted != 1
            || peer.hello_completed != 1
            || peer.response_bytes != response_bytes as u64
            || peer.requests != [fixture::HELLO.to_vec()])
    {
        return Err("endurance lacks actual completed Hello".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn action(kind: &str, id: (u64, u64)) -> Action {
        let build = "a".repeat(64);
        crate::native_protocol::action(&format!("EVROSION_M5_NATIVE_ACTION protocol=1 build={build} action={kind} process={} thread={} image_sha256={}",id.0,id.1,"b".repeat(64)),&build).unwrap()
    }
    #[test]
    fn live_cpu_and_shell_proof_cannot_hide_early_app_stop_or_reused_incarnation() {
        let mut f = Flow::new();
        f.stage = 6;
        f.old = Some((25, 125));
        let image = "b".repeat(64);
        let start = action("start", (25, 125));
        assert!(
            f.action_prefix(std::slice::from_ref(&start), &image, false)
                .is_ok()
        );
        for bad in [
            vec![start.clone(), action("stop", (25, 125))],
            vec![action("start", (26, 126))],
            vec![action("reap", (25, 125))],
        ] {
            assert!(f.action_prefix(&bad, &image, false).is_err());
        }
        let mut actual = vec![start, action("stop", (25, 125)), action("reap", (25, 125))];
        f.stage = 8;
        assert!(f.action_prefix(&actual, &image, false).is_ok());
        actual.swap(1, 2);
        assert!(f.action_prefix(&actual, &image, false).is_err());
        actual.swap(1, 2);
        f.stage = 11;
        f.new = Some((30, 130));
        actual.extend([
            action("start", (30, 130)),
            action("stop", (30, 130)),
            action("reap", (30, 130)),
        ]);
        assert!(f.action_prefix(&actual, &image, true).is_ok());
        let mut bad = actual.clone();
        bad[3] = action("start", (25, 130));
        assert!(f.action_prefix(&bad, &image, true).is_err());
        let mut bad = actual;
        bad.pop();
        assert!(f.action_prefix(&bad, &image, true).is_err());
    }
    #[test]
    fn completed_hello_needs_exact_owned_request_and_written_response_ledger() {
        let n=format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",crate::network_fixture::HELLO.len()).len()+crate::network_fixture::HELLO.len();
        let peer = fixture::Snapshot {
            accepted: 1,
            hello_completed: 1,
            pending_accepted: 0,
            response_bytes: n as u64,
            requests: vec![fixture::HELLO.to_vec()],
            error: None,
        };
        assert!(hello(&peer, true).is_ok());
        let mut bad = peer.clone();
        bad.response_bytes += 1;
        assert!(hello(&bad, true).is_err());
        let mut bad = peer.clone();
        bad.requests = vec![fixture::PENDING.to_vec()];
        assert!(hello(&bad, true).is_err());
        let mut bad = peer.clone();
        bad.accepted = 2;
        assert!(hello(&bad, false).is_err());
        let mut bad = peer;
        bad.pending_accepted = 1;
        assert!(hello(&bad, false).is_err());
        assert!(hello(&fixture::Snapshot::default(), false).is_ok());
        assert!(hello(&fixture::Snapshot::default(), true).is_err());
    }
}
