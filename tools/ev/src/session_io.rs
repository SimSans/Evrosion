// SPDX-License-Identifier: GPL-3.0-only
//! Explicit owned-VM session conformance, never automatic manual-session input.
//! Every next stimulus follows actual complete observations. Host references
//! inspect retained pixels; they cannot supply guest acknowledgements or consent.
use crate::{
    build::{self, Result},
    desktop_protocol::{self, Producer, Step, StepKind},
    qmp::{Key, Qmp},
    session_reference::Reference,
    storage,
};
use ev_graphics::{
    native::Build,
    session::{Focus, SaveState, View},
    shell::{FileChoice, Screen},
};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};
pub(crate) const TYPED: &[u8] = b"EvRo_42!?x";
pub(crate) const SAVED: &str = "EvRo_42!?";
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum Phase {
    Exercise,
    ColdReopen,
}
#[derive(Clone, Debug, Serialize)]
struct Rpc {
    count: u64,
    call_epoch: u64,
    call: u64,
    endpoint: u64,
    caller_process: u64,
    caller_thread: u64,
    callee_process: u64,
    callee_thread: u64,
}
#[derive(Clone, Debug, Serialize)]
struct Barrier {
    rpc: Rpc,
    frame: u64,
    sequence: u64,
    flags: u64,
    buttons: u64,
    request: u64,
    reply: u64,
    tick: u64,
    line: usize,
}
#[derive(Clone, Debug, Serialize)]
struct Cursor {
    rpc: Rpc,
    x: u16,
    y: u8,
    sequence: u64,
    request: u64,
    reply: u64,
    tick: u64,
    line: usize,
}
#[derive(Clone, Debug, Serialize)]
struct Note {
    phase: String,
    count: u64,
    endpoint: u64,
    ticket: u64,
    sender_process: u64,
    sender_thread: u64,
    receiver_process: u64,
    receiver_thread: u64,
    nonce: u64,
    opcode: u64,
    message: u64,
    tick: u64,
    line: usize,
}
#[derive(Default, Serialize)]
struct Ui {
    barriers: Vec<Barrier>,
    cursors: Vec<Cursor>,
    notes: Vec<Note>,
    counts: Option<([u64; 5], String)>,
}
/// Read-only reuse of the actual KBR2/Note observation joins by the separate
/// acquisition workflow. This wrapper cannot inject an ACK or modify a frame.
pub(crate) struct ProbeUi(Ui);
impl ProbeUi {
    pub(crate) fn parse(serial: &[u8], build: &str) -> Result<Self> {
        Ui::parse(serial, build).map(Self)
    }
    pub(crate) fn cursor(&self) -> Option<(u16, u8)> {
        self.0.cursors.last().map(|c| (c.x, c.y))
    }
    pub(crate) fn ready(&self, shell: u64, frame: u64, line: usize) -> bool {
        self.0
            .barriers
            .iter()
            .rev()
            .find(|b| b.rpc.caller_process == shell)
            .is_some_and(|b| b.frame == frame && b.line > line)
    }
    pub(crate) fn note_complete(&self, app: u64, nonce: u64, opcode: u64) -> Option<usize> {
        self.0.completed(app, nonce, opcode)
    }
    pub(crate) fn note_busy(&self, app: u64, nonce: u64, opcode: u64) -> Option<usize> {
        self.0.completed_response(app, nonce, opcode, 131)
    }
    pub(crate) fn finish(&self) -> Result<Value> {
        self.0.final_check()?;
        serde_json::to_value(&self.0).map_err(|e| e.to_string())
    }
}
fn number(field: &str, key: &str) -> Result<u64> {
    crate::boot_protocol::canonical_number(field, key)
}
fn word(field: &str, key: &str) -> Result<u64> {
    let value = field
        .strip_prefix(&format!("{key}="))
        .ok_or("session scalar field/order")?;
    if value.len() != 16
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("session scalar must be16 lowercase hex".into());
    }
    u64::from_str_radix(value, 16).map_err(|_| "session scalar overflow".into())
}
fn rpc(fields: &[&str]) -> Result<Rpc> {
    let r = Rpc {
        count: number(fields[0], "count")?,
        call_epoch: number(fields[1], "call_epoch")?,
        call: number(fields[2], "call")?,
        endpoint: number(fields[3], "endpoint")?,
        caller_process: number(fields[4], "caller_process")?,
        caller_thread: number(fields[5], "caller_thread")?,
        callee_process: number(fields[6], "callee_process")?,
        callee_thread: number(fields[7], "callee_thread")?,
    };
    if !(1..=32).contains(&r.count)
        || [
            r.call_epoch,
            r.call,
            r.caller_process,
            r.caller_thread,
            r.callee_process,
            r.callee_thread,
        ]
        .iter()
        .any(|n| matches!(*n, 0 | u64::MAX))
        || r.caller_process == r.callee_process
    {
        return Err("session RPC identities/count invalid".into());
    }
    Ok(r)
}
impl Ui {
    fn push(&mut self, line: &str, build: &str, ordinal: usize) -> Result<bool> {
        if ![
            "EVROSION_M6_BARRIER ",
            "EVROSION_M6_CURSOR ",
            "EVROSION_M6_NOTE ",
            "EVROSION_M6_UI_COUNTS ",
        ]
        .iter()
        .any(|p| line.starts_with(p))
        {
            return Ok(false);
        }
        let f: Vec<_> = line.split(' ').collect();
        if line.len() > 1536
            || f.len() < 4
            || f[1] != "protocol=1"
            || f[2] != format!("build={build}")
        {
            return Err("session UI observation header/build differs".into());
        }
        if self.counts.is_some() {
            return Err("session UI observation follows terminal totals".into());
        }
        match f[0] {
            "EVROSION_M6_BARRIER" if f.len() == 18 => {
                let r = rpc(&f[3..11])?;
                let b = Barrier {
                    rpc: r,
                    frame: number(f[11], "frame")?,
                    sequence: number(f[12], "sequence")?,
                    flags: number(f[13], "flags")?,
                    buttons: number(f[14], "buttons")?,
                    request: word(f[15], "request")?,
                    reply: word(f[16], "reply")?,
                    tick: number(f[17], "tick")?,
                    line: ordinal,
                };
                let request = ev_input::SessionBarrierRequest::decode(b.request.to_le_bytes())
                    .map_err(|_| "actual session barrier request codec")?;
                let reply = ev_input::SessionBarrierReply::decode(b.reply.to_le_bytes())
                    .map_err(|_| "actual session barrier reply codec")?;
                if b.rpc.count != self.barriers.len() as u64 + 1
                    || request.nonce() as u64 != b.frame
                    || b.frame == 0
                    || b.sequence != u64::from(reply.sequence)
                    || b.flags != u64::from(b.reply.to_le_bytes()[2])
                    || b.buttons != u64::from(b.reply.to_le_bytes()[3])
                    || b.tick == u64::MAX
                {
                    return Err("session barrier replay/decoded fields differ".into());
                }
                self.barriers.push(b);
            }
            "EVROSION_M6_CURSOR" if f.len() == 17 => {
                let r = rpc(&f[3..11])?;
                let c = Cursor {
                    rpc: r,
                    x: u16::try_from(number(f[11], "x")?)
                        .map_err(|_| "session cursor x overflow")?,
                    y: u8::try_from(number(f[12], "y")?)
                        .map_err(|_| "session cursor y overflow")?,
                    sequence: number(f[13], "sequence")?,
                    request: word(f[14], "request")?,
                    reply: word(f[15], "reply")?,
                    tick: number(f[16], "tick")?,
                    line: ordinal,
                };
                let request =
                    ev_desktop::protocol::CursorControl::parse_request(c.request.to_le_bytes())
                        .map(|p| (p.x, p.y, u64::from(p.sequence)))
                        .map_err(|_| "actual cursor request codec")?;
                if c.rpc.count != self.cursors.len() as u64 + 1
                    || request != (c.x, c.y, c.sequence)
                    || ev_desktop::protocol::CursorControl::parse_reply(c.reply.to_le_bytes())
                        .map(|p| (p.x, p.y, u64::from(p.sequence)))
                        .map_err(|_| "actual cursor reply codec")?
                        != request
                    || c.tick == u64::MAX
                {
                    return Err("session cursor replay/decoded fields differ".into());
                }
                self.cursors.push(c);
            }
            "EVROSION_M6_NOTE" if f.len() == 15 => {
                let phase = f[3]
                    .strip_prefix("phase=")
                    .filter(|p| matches!(*p, "request" | "accepted" | "delivered"))
                    .ok_or("session Note phase")?;
                let n = Note {
                    phase: phase.into(),
                    count: number(f[4], "count")?,
                    endpoint: number(f[5], "endpoint")?,
                    ticket: number(f[6], "ticket")?,
                    sender_process: number(f[7], "sender_process")?,
                    sender_thread: number(f[8], "sender_thread")?,
                    receiver_process: number(f[9], "receiver_process")?,
                    receiver_thread: number(f[10], "receiver_thread")?,
                    nonce: number(f[11], "nonce")?,
                    opcode: number(f[12], "opcode")?,
                    message: word(f[13], "message")?,
                    tick: number(f[14], "tick")?,
                    line: ordinal,
                };
                let bytes = n.message.to_le_bytes();
                let nonce = if phase == "request" {
                    u64::from(
                        ev_userspace_contract::session_note::Request::decode(&bytes, 0)
                            .map_err(|_| "actual Note request codec")?
                            .nonce(),
                    )
                } else {
                    u64::from(
                        ev_userspace_contract::session_note::Response::decode(&bytes, 0)
                            .map_err(|_| "actual Note reply codec")?
                            .nonce(),
                    )
                };
                if n.count != self.notes.iter().filter(|n| n.phase == phase).count() as u64 + 1
                    || n.count > 32
                    || n.nonce != nonce
                    || n.opcode != u64::from(bytes[3])
                    || [
                        n.ticket,
                        n.sender_process,
                        n.sender_thread,
                        n.receiver_process,
                        n.receiver_thread,
                    ]
                    .iter()
                    .any(|n| matches!(*n, 0 | u64::MAX))
                    || n.sender_process == n.receiver_process
                    || n.tick == u64::MAX
                {
                    return Err("session Note sequence/actual message fields differ".into());
                }
                self.notes.push(n);
            }
            "EVROSION_M6_UI_COUNTS" if f.len() == 9 => {
                let phase = f[3]
                    .strip_prefix("phase=")
                    .filter(|p| matches!(*p, "finished" | "bound"))
                    .ok_or("session UI totals phase")?;
                let counts = [
                    number(f[4], "barriers")?,
                    number(f[5], "cursors")?,
                    number(f[6], "note_requests")?,
                    number(f[7], "note_accepted")?,
                    number(f[8], "note_delivered")?,
                ];
                if self.counts.is_some() {
                    return Err("session UI totals replay".into());
                }
                self.counts = Some((counts, phase.into()));
            }
            _ => return Err("session UI observation fields/order differ".into()),
        }
        Ok(true)
    }
    fn parse(serial: &[u8], build: &str) -> Result<Self> {
        let text = std::str::from_utf8(serial).map_err(|_| "session serial notUTF8")?;
        let mut ui = Self::default();
        for (line, raw) in text.split_inclusive('\n').enumerate() {
            if raw.ends_with('\n') {
                ui.push(raw.trim_end_matches(['\r', '\n']), build, line)?;
            }
        }
        ui.validate_notes(false)?;
        Ok(ui)
    }
    fn validate_notes(&self, complete: bool) -> Result<()> {
        let mut requests = std::collections::BTreeMap::new();
        let mut accepted = std::collections::BTreeMap::new();
        let mut delivered = std::collections::BTreeSet::new();
        let mut last_nonce = std::collections::BTreeMap::new();
        for n in &self.notes {
            if n.phase == "request" {
                let key = (n.sender_process, n.sender_thread, n.nonce);
                let last = last_nonce
                    .entry((n.sender_process, n.sender_thread))
                    .or_insert(0);
                if n.nonce <= *last || requests.insert(key, n).is_some() {
                    return Err("session Note request nonce replay".into());
                }
                *last = n.nonce;
            } else {
                let key = (n.receiver_process, n.receiver_thread, n.nonce);
                let request = requests
                    .get(&key)
                    .ok_or("session ACK has no earlier actual Note request")?;
                if (n.sender_process, n.sender_thread)
                    != (request.receiver_process, request.receiver_thread)
                    || n.tick < request.tick
                {
                    return Err("session ACK belongs to another Root/request incarnation".into());
                }
                if n.phase == "accepted" {
                    if accepted.insert(key, n).is_some() {
                        return Err("session Note accepted ACK replay".into());
                    }
                } else {
                    let ack = accepted
                        .get(&key)
                        .ok_or("session delivery has no actual accepted ACK")?;
                    if (n.endpoint, n.ticket, n.message) != (ack.endpoint, ack.ticket, ack.message)
                        || n.tick < ack.tick
                        || !delivered.insert(key)
                    {
                        return Err(
                            "session Note delivery ticket/message replay or mismatch".into()
                        );
                    }
                }
            }
        }
        if complete && (requests.len() != accepted.len() || requests.len() != delivered.len()) {
            return Err("session finished with incomplete actual Note delivery".into());
        }
        Ok(())
    }
    fn completed(&self, app: u64, nonce: u64, opcode: u64) -> Option<usize> {
        self.completed_response(app, nonce, opcode, opcode + 2)
    }
    fn completed_response(
        &self,
        app: u64,
        nonce: u64,
        opcode: u64,
        response: u64,
    ) -> Option<usize> {
        let request = self.notes.iter().find(|n| {
            n.phase == "request"
                && n.sender_process == app
                && n.nonce == nonce
                && n.opcode == opcode
        })?;
        let accepted = self.notes.iter().find(|n| {
            n.phase == "accepted"
                && n.receiver_process == app
                && n.sender_process == request.receiver_process
                && n.sender_thread == request.receiver_thread
                && n.receiver_thread == request.sender_thread
                && n.nonce == nonce
                && n.opcode == response
                && n.line > request.line
        })?;
        let delivered = self.notes.iter().find(|n| {
            n.phase == "delivered"
                && n.ticket == accepted.ticket
                && n.endpoint == accepted.endpoint
                && n.message == accepted.message
                && n.sender_process == accepted.sender_process
                && n.sender_thread == accepted.sender_thread
                && n.receiver_process == app
                && n.receiver_thread == accepted.receiver_thread
                && n.line > accepted.line
                && n.tick >= accepted.tick
        })?;
        Some(delivered.line)
    }
    fn final_check(&self) -> Result<()> {
        let (counts, phase) = self.counts.as_ref().ok_or("session UI totals absent")?;
        let actual = [
            self.barriers.len() as u64,
            self.cursors.len() as u64,
            self.notes.iter().filter(|n| n.phase == "request").count() as u64,
            self.notes.iter().filter(|n| n.phase == "accepted").count() as u64,
            self.notes.iter().filter(|n| n.phase == "delivered").count() as u64,
        ];
        // This finite conformance route deliberately stays below every sample
        // cap. Unsampled operations cannot support a complete-delivery claim.
        if phase != "finished" || counts.iter().zip(actual).any(|(n, a)| *n > 32 || *n != a) {
            return Err("session UI sampled records differ from actual finished totals".into());
        }
        self.validate_notes(true)?;
        Ok(())
    }
}
/// Generic selected-session syntax only; full joins remain in this driver.
pub(crate) fn line(line: &str, build: &str) -> Result<()> {
    let mut ui = Ui::default();
    let f: Vec<_> = line.split(' ').collect();
    let mut normalized = line.to_string();
    if let Some(count) = f.iter().find(|f| f.starts_with("count=")) {
        let n = number(count, "count")?;
        if !(1..=32).contains(&n) {
            return Err("session UI sample count outside bound".into());
        }
        normalized = normalized.replacen(count, "count=1", 1);
    }
    if !ui.push(&normalized, build, 0)? {
        return Err("unknown session UI observation".into());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
enum Stage {
    Home,
    Loading,
    Saved,
    Typing(usize),
    Backspace,
    Saving,
    CancelHeld,
    CancelSaved,
    Picker,
    FileSaved,
    Stopped,
    RelaunchLoading,
    RelaunchSaved,
    HeldBeforeShell,
    ShellRestored,
    HeldMove,
    HeldTab,
    FreshNote,
    Finishing,
    Done,
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
fn bounded(path: &Path) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !m.is_file() || m.file_type().is_symlink() || m.len() > 1024 * 1024 {
        return Err("session log nonregular/oversized".into());
    }
    let mut out = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut out)
        .map_err(|e| e.to_string())?;
    if out.len() > 1024 * 1024 {
        return Err("session log grew beyond1MiB".into());
    }
    Ok(out)
}
struct At {
    step: Step,
    line: usize,
}
fn app_capture_ready(
    reference: &Reference,
    app: &Step,
    steps: &[At],
    barriers: &[Barrier],
) -> Result<bool> {
    // Use the current actual Shell Present, never an older matching chrome
    // hidden underneath the newer picker/Opening surface.
    let shell = steps
        .iter()
        .rev()
        .find(|at| at.step.producer == Producer::Shell && at.step.kind == StepKind::Frame);
    if !reference.app_composition_ready(app, shell.map(|at| &at.step))? {
        return Ok(false);
    }
    let shell = shell.expect("matching actual Shell checked above");
    // The real Shell arms pointer freshness only after this exact Present's
    // actual Input reply. An older sampled barrier cannot arm a new frame.
    Ok(barriers
        .iter()
        .rev()
        .find(|barrier| barrier.rpc.caller_process == app.shell_process)
        .is_some_and(|barrier| barrier.frame == shell.step.frame && barrier.line > shell.line))
}
struct Move {
    x: u16,
    y: u8,
    click: bool,
    awaiting: Option<(u16, u8, u64)>,
}
struct Observer {
    phase: Phase,
    stage: Stage,
    origin: Instant,
    qmp: Option<Qmp>,
    history: Vec<u8>,
    inputs: Vec<Value>,
    captures: Vec<Value>,
    surfaces: Vec<Value>,
    snapshots: Vec<Value>,
    capture: u32,
    first_app: Option<u64>,
    current_app: Option<u64>,
    first_shell: Option<u64>,
    display: Option<u64>,
    min_app_frame: u64,
    last_app_frame: u64,
    movement: Option<Move>,
    last_finish: u64,
    finish_attempts: u8,
}
impl Observer {
    fn new(phase: Phase) -> Self {
        Self {
            phase,
            stage: Stage::Home,
            origin: Instant::now(),
            qmp: None,
            history: Vec::new(),
            inputs: Vec::new(),
            captures: Vec::new(),
            surfaces: Vec::new(),
            snapshots: Vec::new(),
            capture: 0,
            first_app: None,
            current_app: None,
            first_shell: None,
            display: None,
            min_app_frame: 0,
            last_app_frame: 0,
            movement: None,
            last_finish: 0,
            finish_attempts: 0,
        }
    }
    fn verify_lifecycle(&self, serial: &[u8], build: &str) -> Result<()> {
        let text = std::str::from_utf8(serial).map_err(|_| "session lifecycle serial notUTF8")?;
        let mut rows = Vec::new();
        for raw in text
            .lines()
            .filter(|raw| raw.starts_with("EVROSION_M4_DESKTOP_LIFECYCLE "))
        {
            rows.push(desktop_protocol::lifecycle_syntax(raw, build)?);
        }
        if self.phase == Phase::ColdReopen {
            return if rows.is_empty() {
                Ok(())
            } else {
                Err("cold note read unexpectedly faulted/replaced an actor".into())
            };
        }
        if rows.len() != 4 {
            return Err(
                "session requires exactly actual App and Shell fault/replacement pairs".into(),
            );
        }
        let final_shell = Ui::parse(serial, build)?
            .cursors
            .last()
            .map(|c| c.rpc.caller_process)
            .ok_or("session final actual Shell identity absent")?;
        for (i, actor, old, new) in [
            (
                0,
                desktop_protocol::Actor::App,
                self.first_app,
                self.current_app,
            ),
            (
                2,
                desktop_protocol::Actor::Shell,
                self.first_shell,
                Some(final_shell),
            ),
        ] {
            let fault = &rows[i];
            let restart = &rows[i + 1];
            if fault.actor != actor
                || restart.actor != actor
                || fault.event != desktop_protocol::Event::Fault
                || restart.event != desktop_protocol::Event::Restart
                || Some(fault.process) != old
                || restart.process != fault.process
                || restart.thread != fault.thread
                || Some(restart.replacement) != new
                || self.display != Some(fault.display_process)
                || restart.display_process != fault.display_process
                || fault.grants != 1
                || restart.grants != 1
            {
                return Err(
                    "session actual fault/replacement identity/thread/display/grants differ".into(),
                );
            }
        }
        Ok(())
    }
    fn ns(&self) -> Result<u64> {
        crate::perf_ledger::elapsed_ns(self.origin, Instant::now())
            .map_err(|e| format!("session host monotonic: {e:?}"))
    }
    fn action(
        &mut self,
        kind: &str,
        value: Value,
        f: impl FnOnce(&mut Qmp) -> Result<()>,
    ) -> Result<()> {
        if self.inputs.len() >= 128 {
            return Err("session stimulus bound exceeded".into());
        }
        let before = self.ns()?;
        f(self.qmp.as_mut().ok_or("session private QMP absent")?)?;
        self.inputs.push(json!({"stage":self.stage,"device":"owned QEMU PS/2","kind":kind,"value":value,"host_bracket_ns":[before,self.ns()?]}));
        Ok(())
    }
    fn key(&mut self, key: Key, down: bool) -> Result<()> {
        self.action("key", json!({"key":format!("{key:?}"),"down":down}), |q| {
            q.key_state(key, down)
        })
    }
    fn tap(&mut self, key: Key) -> Result<()> {
        self.key(key, true)?;
        self.key(key, false)
    }
    fn button(&mut self, down: bool) -> Result<()> {
        self.action("left_button", json!({"down":down}), |q| q.left_button(down))
    }
    fn uart(&mut self, input: &mut impl Write, bytes: &[u8]) -> Result<()> {
        if self.inputs.len() >= 128 {
            return Err("session stimulus bound exceeded".into());
        }
        let before = self.ns()?;
        input
            .write_all(bytes)
            .and_then(|()| input.flush())
            .map_err(|e| e.to_string())?;
        self.inputs.push(json!({"stage":self.stage,"device":"owned QEMU UART","bytes":std::str::from_utf8(bytes).map_err(|_|"session UART nonASCII")?,"host_bracket_ns":[before,self.ns()?]}));
        Ok(())
    }
    fn click(&mut self, x: u16, y: u8, next: Stage) {
        self.stage = next;
        self.movement = Some(Move {
            x,
            y,
            click: true,
            awaiting: None,
        });
    }
    fn move_held(&mut self, x: u16, y: u8) {
        self.stage = Stage::HeldMove;
        self.movement = Some(Move {
            x,
            y,
            click: false,
            awaiting: None,
        });
    }
    fn move_tick(&mut self, ui: &Ui) -> Result<bool> {
        let Some(mut m) = self.movement.take() else {
            return Ok(false);
        };
        let cursor = ui
            .cursors
            .last()
            .ok_or("session movement has no actual cursor receipt")?;
        if let Some((x, y, count)) = m.awaiting {
            if cursor.rpc.count <= count || (cursor.x, cursor.y) != (x, y) {
                self.movement = Some(m);
                return Ok(true);
            }
            m.awaiting = None;
        }
        if (cursor.x, cursor.y) == (m.x, m.y) {
            if m.click {
                self.button(true)?;
                self.button(false)?;
            }
            return Ok(false);
        }
        let dx = (i32::from(m.x) - i32::from(cursor.x)).clamp(-100, 100) as i16;
        let dy = (i32::from(m.y) - i32::from(cursor.y)).clamp(-100, 100) as i16;
        let target = (
            (i32::from(cursor.x) + i32::from(dx)) as u16,
            (i32::from(cursor.y) + i32::from(dy)) as u8,
        );
        self.action(
            "relative",
            json!({"dx":dx,"dy":dy,"from_actual_cursor":cursor,"expected_actual_position":target}),
            |q| q.relative(dx, dy),
        )?;
        m.awaiting = Some((target.0, target.1, cursor.rpc.count));
        self.movement = Some(m);
        Ok(true)
    }
    fn view(&self) -> (Screen, Option<View<'_>>, Producer, StepKind, u64) {
        let (note, state, focus, file) = match self.stage {
            Stage::Loading | Stage::RelaunchLoading => {
                (b"".as_slice(), SaveState::Loading, Focus::Note, None)
            }
            Stage::Saved => (
                if self.phase == Phase::ColdReopen {
                    SAVED.as_bytes()
                } else {
                    b""
                },
                SaveState::Saved,
                Focus::Note,
                None,
            ),
            Stage::Typing(n) => (TYPED[..n].as_ref(), SaveState::Unsaved, Focus::Note, None),
            Stage::Backspace => (SAVED.as_bytes(), SaveState::Unsaved, Focus::Note, None),
            Stage::Saving => (SAVED.as_bytes(), SaveState::Saved, Focus::Save, None),
            Stage::CancelSaved => (SAVED.as_bytes(), SaveState::Saved, Focus::OpenFile, None),
            Stage::FileSaved => (
                SAVED.as_bytes(),
                SaveState::Saved,
                Focus::OpenFile,
                Some(ev_file::desktop::SEED_NOTES),
            ),
            Stage::HeldTab => (SAVED.as_bytes(), SaveState::Saved, Focus::Save, None),
            _ => (SAVED.as_bytes(), SaveState::Saved, Focus::Note, None),
        };
        let (screen, producer, kind) = match self.stage {
            Stage::Home => (Screen::Home, Producer::Shell, StepKind::Frame),
            Stage::CancelHeld => (
                Screen::Picker {
                    selected: FileChoice::Notes,
                },
                Producer::Shell,
                StepKind::PickerHeld,
            ),
            Stage::Picker => (
                Screen::Picker {
                    selected: FileChoice::Notes,
                },
                Producer::Shell,
                StepKind::PickerReady,
            ),
            Stage::Stopped => (Screen::AppStopped, Producer::Shell, StepKind::Frame),
            _ => (Screen::AppRunning, Producer::App, StepKind::Frame),
        };
        let grants = if matches!(
            self.stage,
            Stage::FileSaved
                | Stage::Stopped
                | Stage::RelaunchLoading
                | Stage::RelaunchSaved
                | Stage::HeldBeforeShell
                | Stage::ShellRestored
                | Stage::HeldMove
                | Stage::HeldTab
                | Stage::FreshNote
                | Stage::Finishing
                | Stage::Done
        ) {
            1
        } else {
            0
        };
        (
            screen,
            (screen == Screen::AppRunning).then_some(View {
                build: Build::A,
                focus,
                note,
                state,
                file,
            }),
            producer,
            kind,
            grants,
        )
    }
    fn observe(
        &mut self,
        bytes: &[u8],
        build: &str,
        directory: &Path,
        deadline: Instant,
        input: &mut impl Write,
        disk: &storage::Disk,
    ) -> Result<()> {
        if !bytes.starts_with(&self.history) {
            return Err("session serial history truncated/rewritten".into());
        }
        self.history = bytes.to_vec();
        let ui = Ui::parse(bytes, build)?;
        if self.movement.is_some() && self.move_tick(&ui)? {
            return Ok(());
        }
        if self.stage == Stage::HeldMove {
            self.min_app_frame = self.last_app_frame;
            self.tap(Key::Tab)?;
            self.stage = Stage::HeldTab;
        }
        if matches!(self.stage, Stage::Finishing | Stage::Done) {
            for state in crate::native_protocol::states(bytes, build)? {
                let report = state.number("report")?;
                if state.fields["op"] == "finish" && report > self.last_finish {
                    self.last_finish = report;
                    match state.fields["result"].as_str() {
                        "ok" => self.stage = Stage::Done,
                        "busy" if self.finish_attempts < 8 => {
                            self.uart(input, b"finish\n")?;
                            self.finish_attempts += 1;
                        }
                        _ => return Err("session finish refused or repeated Busy limit".into()),
                    }
                }
            }
            return Ok(());
        }
        let text = std::str::from_utf8(bytes).map_err(|_| "session serial notUTF8")?;
        let mut steps = Vec::new();
        for (line, raw) in text.split_inclusive('\n').enumerate() {
            if !raw.ends_with('\n') {
                break;
            }
            let raw = raw.trim_end_matches(['\r', '\n']);
            if raw.starts_with("EVROSION_M4_DESKTOP_EXIT ") {
                return Err(format!("session actor exited unexpectedly: {raw}"));
            }
            if raw.starts_with("EVROSION_M4_DESKTOP_STEP ") {
                steps.push(At {
                    step: desktop_protocol::step_line(raw, build)?,
                    line,
                });
            }
        }
        if steps.len() > 256 {
            return Err("session actual frame bound exceeded".into());
        }
        let (screen, app, producer, kind, grants) = self.view();
        let cursor = ui.cursors.last();
        let reference = Reference::new(screen, app, cursor.map(|c| (c.x, c.y)))?;
        let mut candidate = None;
        for at in steps.iter().rev() {
            let s = &at.step;
            if s.producer == producer
                && s.kind == kind
                && s.grants == grants
                && reference.surface_hash(producer, s.frame)? == s.surface_sha256
            {
                candidate = Some(at);
                break;
            }
        }
        let Some(at) = candidate else {
            return Ok(());
        };
        let s = &at.step;
        let loading = matches!(self.stage, Stage::Loading | Stage::RelaunchLoading);
        if !loading
            && steps
                .iter()
                .rev()
                .find(|a| a.step.kind == StepKind::Frame && a.step.producer == producer)
                .is_none_or(|a| {
                    a.step.frame != s.frame
                        || a.step.shell_process != s.shell_process
                        || a.step.app_process != s.app_process
                })
        {
            return Ok(());
        }
        if !loading
            && producer == Producer::App
            && !app_capture_ready(&reference, s, &steps, &ui.barriers)?
        {
            // Let the owned guest finish FileDelivered/control/Present while
            // retaining the original wall-clock and80-capture bounds. Repeated
            // QMP stop/capture/resume of a known unfinished Shell can otherwise
            // prevent that very transition from obtaining execution time.
            return Ok(());
        }
        if self.display.is_some_and(|p| p != s.display_process) {
            return Err("session surviving Display identity changed".into());
        }
        if self.stage == Stage::Home && s.app_process != 0 {
            return Err("session Home already has an unrequested App".into());
        }
        if producer == Producer::App && s.frame <= self.min_app_frame {
            return Ok(());
        }
        if matches!(self.stage, Stage::RelaunchLoading | Stage::RelaunchSaved)
            && self.first_app == Some(s.app_process)
        {
            return Ok(());
        }
        if self.stage == Stage::ShellRestored
            && (self.first_shell == Some(s.shell_process)
                || self.current_app != Some(s.app_process))
        {
            return Ok(());
        }
        let barrier = ui
            .barriers
            .iter()
            .rev()
            .find(|b| b.rpc.caller_process == s.shell_process);
        if matches!(
            self.stage,
            Stage::Home | Stage::CancelHeld | Stage::Picker | Stage::ShellRestored
        ) {
            let Some(b) = barrier else {
                return Ok(());
            };
            if self.stage != Stage::ShellRestored && b.frame != s.frame {
                return Ok(());
            }
            if self.stage == Stage::CancelHeld && (b.flags & 12 == 0 || s.held_ticks < 64) {
                return Err("session held picker lacks actual held Enter64tick barrier".into());
            }
            if self.stage == Stage::ShellRestored && b.buttons & 1 == 0 {
                return Err("Shell replacement forgot an actual held pointer button".into());
            }
        }
        let Some(c) = cursor else {
            return Ok(());
        };
        if !loading
            && (c.rpc.caller_process != s.shell_process
                || c.rpc.callee_process != s.display_process)
        {
            return Ok(());
        }
        let ack = match self.stage {
            Stage::Saved | Stage::RelaunchSaved => ui.completed(s.app_process, 1, 1),
            Stage::Saving => ui.completed(s.app_process, 2, 2),
            _ => None,
        };
        if matches!(
            self.stage,
            Stage::Saved | Stage::RelaunchSaved | Stage::Saving
        ) && ack.is_none_or(|line| at.line <= line)
        {
            return Ok(());
        }
        if self.stage == Stage::Saving {
            let saving = Reference::new(
                Screen::AppRunning,
                Some(View {
                    build: Build::A,
                    focus: Focus::Save,
                    note: SAVED.as_bytes(),
                    state: SaveState::Saving,
                    file: None,
                }),
                None,
            )?;
            if !steps.iter().any(|a| {
                a.step.producer == Producer::App
                    && a.step.app_process == s.app_process
                    && a.line < ack.unwrap()
                    && saving
                        .surface_hash(Producer::App, a.step.frame)
                        .is_ok_and(|hash| hash == a.step.surface_sha256)
            }) {
                return Err(
                    "Saved lacks preceding actual Saving surface and delivered write ACK".into(),
                );
            }
        }
        if self.qmp.is_none() {
            crate::boot::check_desktop_prefix(bytes, build)?;
            self.qmp = Some(Qmp::connect_at(directory, deadline, self.origin)?);
        }
        if loading {
            self.surfaces.push(json!({"stage":self.stage,"actual_step":s,"method":"Actual protected Present surface hash; transient loading scanout is not claimed"}));
        } else {
            self.capture += 1;
            if self.capture > 80 {
                return Err("session actual capture bound80 exceeded".into());
            }
            self.qmp.as_mut().unwrap().set_running(false)?;
            let (path, frame) = self.qmp.as_mut().unwrap().capture(self.capture)?;
            let valid = if frame.dimensions() != (s.width, s.height) {
                Err("session scanout geometry differs from actual Present".into())
            } else {
                reference.validate(&frame)
            };
            self.captures.push(json!({"stage":self.stage,"step":s,"cursor":c,"barrier":barrier,"path":path.file_name(),"sha256":build::hash_file(&path)?,"passed":valid.is_ok(),"validation":valid.as_ref().ok(),"transient_mismatch":valid.as_ref().err()}));
            if valid.is_ok() {
                let snapshot = match self.stage {
                    Stage::Saved => Some("note-baseline.raw"),
                    Stage::Saving => Some("note-saved.raw"),
                    Stage::RelaunchSaved => Some("note-relaunch.raw"),
                    Stage::ShellRestored => Some("note-shell-restored.raw"),
                    _ => None,
                };
                if let Some(name) = snapshot {
                    self.snapshots.push(disk.capture(directory, name)?);
                }
            }
            self.qmp.as_mut().unwrap().set_running(true)?;
            if valid.is_err() {
                return Ok(());
            }
        }
        self.display = Some(s.display_process);
        if self.first_shell.is_none() {
            self.first_shell = Some(s.shell_process);
        }
        if producer == Producer::App {
            self.last_app_frame = s.frame;
        }
        match self.stage {
            Stage::Home => self.click(160, 101, Stage::Loading),
            Stage::Loading => {
                self.first_app = Some(s.app_process);
                self.current_app = self.first_app;
                self.stage = Stage::Saved;
                self.min_app_frame = s.frame;
            }
            Stage::Saved if self.phase == Phase::ColdReopen => {
                self.stage = Stage::Finishing;
                self.uart(input, b"finish\n")?;
                self.finish_attempts = 1;
            }
            Stage::Saved => {
                self.stage = Stage::Typing(1);
                self.action("ascii", json!({"byte":TYPED[0]}), |q| q.ascii(TYPED[0]))?;
            }
            Stage::Typing(n) if n < TYPED.len() => {
                self.stage = Stage::Typing(n + 1);
                self.action("ascii", json!({"byte":TYPED[n]}), |q| q.ascii(TYPED[n]))?;
            }
            Stage::Typing(_) => {
                self.stage = Stage::Backspace;
                self.tap(Key::Backspace)?;
            }
            Stage::Backspace => self.click(48, 152, Stage::Saving),
            Stage::Saving => {
                self.key(Key::Enter, true)?;
                self.click(80, 58, Stage::CancelHeld);
            }
            Stage::CancelHeld => {
                self.key(Key::Enter, false)?;
                self.tap(Key::Escape)?;
                self.stage = Stage::CancelSaved;
            }
            Stage::CancelSaved => {
                self.tap(Key::Enter)?;
                self.stage = Stage::Picker;
            }
            Stage::Picker => self.click(80, 156, Stage::FileSaved),
            Stage::FileSaved => self.click(220, 58, Stage::Stopped),
            Stage::Stopped => {
                self.min_app_frame = 0;
                self.click(160, 100, Stage::RelaunchLoading);
            }
            Stage::RelaunchLoading => {
                self.current_app = Some(s.app_process);
                self.min_app_frame = s.frame;
                self.stage = Stage::RelaunchSaved;
            }
            Stage::RelaunchSaved => {
                self.min_app_frame = s.frame;
                self.button(true)?;
                self.stage = Stage::HeldBeforeShell;
            }
            Stage::HeldBeforeShell => {
                self.min_app_frame = s.frame;
                self.uart(input, b"crash shell\n")?;
                self.stage = Stage::ShellRestored;
            }
            Stage::ShellRestored => {
                self.min_app_frame = s.frame;
                self.move_held(48, 152);
            }
            Stage::HeldTab => {
                self.min_app_frame = s.frame;
                self.button(false)?;
                self.click(160, 100, Stage::FreshNote);
            }
            Stage::FreshNote => {
                self.stage = Stage::Finishing;
                self.uart(input, b"finish\n")?;
                self.finish_attempts = 1;
            }
            _ => return Err("session observer stage has no real stimulus transition".into()),
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
    let mut observer = Observer::new(phase);
    let deadline = observer
        .origin
        .checked_add(timeout)
        .ok_or("session absolute deadline overflow")?;
    let result = (|| {
        let spawn_before = observer.ns()?;
        let mut child = Owned(
            command
                .stdin(Stdio::piped())
                .spawn()
                .map_err(|e| format!("owned session QEMU spawn: {e}"))?,
        );
        observer.inputs.push(json!({"device":"owned child","kind":"spawn","host_bracket_ns":[spawn_before,observer.ns()?]}));
        let mut input = child
            .0
            .stdin
            .take()
            .ok_or("session owned UART stdin absent")?;
        loop {
            if Instant::now() >= deadline {
                return Err(format!(
                    "session finite conformance deadline at {:?}",
                    observer.stage
                ));
            }
            let bytes = bounded(serial)?;
            let _ = bounded(errors)?;
            observer.observe(&bytes, build, directory, deadline, &mut input, disk)?;
            if let Some(status) = child.0.try_wait().map_err(|e| e.to_string())? {
                let final_bytes = bounded(serial)?;
                if observer.stage != Stage::Done {
                    return Err(format!(
                        "session QEMU exited before actual completion at {:?}",
                        observer.stage
                    ));
                }
                let ui = Ui::parse(&final_bytes, build)?;
                ui.final_check()?;
                observer.verify_lifecycle(&final_bytes, build)?;
                let expected_notes = if phase == Phase::Exercise { 3 } else { 1 };
                if ui.notes.iter().filter(|n| n.phase == "request").count() != expected_notes {
                    return Err("session actual Note operation count differs".into());
                }
                if crate::session_protocol::retention(&final_bytes, build)?.omitted != 0 {
                    return Err("finite session conformance lost emitted diagnostic history".into());
                }
                let final_record = crate::native_protocol::record_session(&final_bytes, build)?;
                let counts = &final_record.counts;
                let (faults, restarts, grants, starts, denials) = if phase == Phase::Exercise {
                    (2, 2, 1, 2, 1)
                } else {
                    (0, 0, 0, 1, 0)
                };
                if status.code() != Some(ev_test_protocol::QEMU_PASS_STATUS)
                    || counts["faults"] != faults
                    || counts["restarts"] != restarts
                    || counts["grants"] != grants
                    || counts["app_a_starts"] != starts
                    || counts["app_b_starts"] != 0
                    || counts["readonly_rejections"] != denials
                {
                    return Err(
                        "session actual final fault/grant/App/read-only/exit facts differ".into(),
                    );
                }
                return Ok(status);
            }
            thread::sleep(
                Duration::from_millis(4).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    })();
    storage::json_new(
        &directory.join("qmp-transcript.json"),
        &json!({"schema":1,"exchanges":observer.qmp.as_ref().map(|q|q.transcript()).unwrap_or(&[])}),
    )?;
    storage::json_new(
        &directory.join("session-observer.json"),
        &json!({"schema":1,"phase":phase,"passed":result.as_ref().is_ok_and(|s|s.code()==Some(ev_test_protocol::QEMU_PASS_STATUS)),"last_stage":observer.stage,"error":result.as_ref().err(),"scripted_input":true,"human_consent_claim":false,"captures":observer.captures,"surface_checkpoints":observer.surfaces,"inputs":observer.inputs,"snapshots":observer.snapshots,"first_app":observer.first_app,"current_app":observer.current_app,"initial_shell":observer.first_shell,"scope":"Actual bounded owned-VM device stimuli, complete kernel receipts, original QMP pixels and raw snapshots. No host pixel substitution, human consent, disk repair or M6 completion claim."}),
    )?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn surface_step(reference: &Reference, producer: Producer, frame: u64) -> Step {
        Step {
            kind: StepKind::Frame,
            frame,
            width: 1280,
            height: 800,
            app_process: 7,
            shell_process: 6,
            display_process: 3,
            grants: 1,
            producer,
            surface_sha256: reference.surface_hash(producer, frame).unwrap(),
            held_ticks: 0,
        }
    }
    fn file_saved_reference() -> Reference {
        Reference::new(
            Screen::AppRunning,
            Some(View {
                build: Build::A,
                focus: Focus::OpenFile,
                note: SAVED.as_bytes(),
                state: SaveState::Saved,
                file: Some(ev_file::desktop::SEED_NOTES),
            }),
            None,
        )
        .unwrap()
    }
    fn scanout_barrier(frame: u32, line: usize) -> Barrier {
        let request = ev_input::SessionBarrierRequest::new(frame)
            .unwrap()
            .encode();
        let reply = ev_input::SessionBarrierReply {
            sequence: 24,
            enter: ev_input::EnterState {
                main_released: true,
                ..ev_input::EnterState::default()
            },
            pointer: ev_input::PointerState {
                held: 0,
                released: 7,
            },
        }
        .encode()
        .unwrap();
        Barrier {
            rpc: Rpc {
                count: 5,
                call_epoch: 501,
                call: 339,
                endpoint: 27,
                caller_process: 6,
                caller_thread: 6,
                callee_process: 5,
                callee_thread: 5,
            },
            frame: u64::from(frame),
            sequence: 24,
            flags: 1,
            buttons: 56,
            request: u64::from_le_bytes(request),
            reply: u64::from_le_bytes(reply),
            tick: 22622,
            line,
        }
    }
    #[test]
    fn actual_app_surface_waits_for_current_shell_chrome_before_scanout_capture() {
        let ready = file_saved_reference();
        let app = surface_step(&ready, Producer::App, 20);
        let opening = Reference::new(
            Screen::Opening {
                selected: FileChoice::Notes,
            },
            None,
            None,
        )
        .unwrap();
        let mut steps = vec![
            At {
                step: surface_step(&ready, Producer::Shell, 4),
                line: 1,
            },
            At {
                step: surface_step(&opening, Producer::Shell, 6),
                line: 2,
            },
        ];
        // The correct App surface can arrive before FileDelivered returns the
        // current Shell from Opening. An older matching frame is insufficient.
        assert!(!app_capture_ready(&ready, &app, &steps, &[scanout_barrier(5, 2)]).unwrap());
        steps.push(At {
            step: surface_step(&ready, Producer::Shell, 7),
            line: 3,
        });
        assert!(!app_capture_ready(&ready, &app, &steps, &[]).unwrap());
        assert!(!app_capture_ready(&ready, &app, &steps, &[scanout_barrier(5, 4)]).unwrap());
        assert!(!app_capture_ready(&ready, &app, &steps, &[scanout_barrier(7, 2)]).unwrap());
        let mut wrong_shell = scanout_barrier(7, 4);
        wrong_shell.rpc.caller_process = 262;
        assert!(!app_capture_ready(&ready, &app, &steps, &[wrong_shell]).unwrap());
        assert!(app_capture_ready(&ready, &app, &steps, &[scanout_barrier(7, 4)]).unwrap());
    }
    #[test]
    fn app_capture_readiness_rejects_stale_identity_geometry_and_nonmatching_surfaces() {
        let ready = file_saved_reference();
        let app = surface_step(&ready, Producer::App, 20);
        let shell = surface_step(&ready, Producer::Shell, 7);
        assert!(!app_capture_ready(&ready, &app, &[], &[]).unwrap());
        let mut bad_app = app.clone();
        bad_app.surface_sha256 = "0".repeat(64);
        assert!(!ready.app_composition_ready(&bad_app, Some(&shell)).unwrap());
        for field in 0..8 {
            let mut other = shell.clone();
            match field {
                0 => other.app_process = 8,
                1 => other.shell_process = 262,
                2 => other.display_process = 4,
                3 => other.grants = 0,
                4 => other.width = 800,
                5 => other.kind = StepKind::PickerReady,
                6 => other.producer = Producer::App,
                _ => other.surface_sha256 = "0".repeat(64),
            }
            assert!(!ready.app_composition_ready(&app, Some(&other)).unwrap());
        }
    }
    fn build() -> String {
        "a".repeat(64)
    }
    fn barrier() -> String {
        let request = ev_input::SessionBarrierRequest::new(1).unwrap().encode();
        let reply = ev_input::SessionBarrierReply {
            sequence: 7,
            enter: ev_input::EnterState {
                main_released: true,
                main_held: true,
                ..ev_input::EnterState::default()
            },
            pointer: ev_input::PointerState {
                held: 1,
                released: 7,
            },
        }
        .encode()
        .unwrap();
        format!(
            "EVROSION_M6_BARRIER protocol=1 build={} count=1 call_epoch=1 call=2 endpoint=3 caller_process=6 caller_thread=6 callee_process=5 callee_thread=5 frame=1 sequence=7 flags=5 buttons=57 request={:016x} reply={:016x} tick=10",
            build(),
            u64::from_le_bytes(request),
            u64::from_le_bytes(reply)
        )
    }
    fn cursor() -> String {
        let c = ev_desktop::protocol::CursorControl {
            x: 319,
            y: 199,
            sequence: 1,
        };
        format!(
            "EVROSION_M6_CURSOR protocol=1 build={} count=1 call_epoch=1 call=3 endpoint=4 caller_process=6 caller_thread=6 callee_process=3 callee_thread=3 x=319 y=199 sequence=1 request={:016x} reply={:016x} tick=11",
            build(),
            u64::from_le_bytes(c.request().unwrap()),
            u64::from_le_bytes(c.reply().unwrap())
        )
    }
    fn notes() -> [String; 3] {
        use ev_userspace_contract::session_note::{Operation, Outcome, Request};
        let r = Request::new(Operation::Read, 1).unwrap();
        let ack = r.reply(Outcome::Read);
        [
            format!(
                "EVROSION_M6_NOTE protocol=1 build={} phase=request count=1 endpoint=5 ticket=9 sender_process=7 sender_thread=8 receiver_process=1 receiver_thread=1 nonce=1 opcode=1 message={:016x} tick=12",
                build(),
                u64::from_le_bytes(r.encode())
            ),
            format!(
                "EVROSION_M6_NOTE protocol=1 build={} phase=accepted count=1 endpoint=6 ticket=10 sender_process=1 sender_thread=1 receiver_process=7 receiver_thread=8 nonce=1 opcode=3 message={:016x} tick=13",
                build(),
                u64::from_le_bytes(ack.encode())
            ),
            format!(
                "EVROSION_M6_NOTE protocol=1 build={} phase=delivered count=1 endpoint=6 ticket=10 sender_process=1 sender_thread=1 receiver_process=7 receiver_thread=8 nonce=1 opcode=3 message={:016x} tick=14",
                build(),
                u64::from_le_bytes(ack.encode())
            ),
        ]
    }
    fn totals() -> String {
        format!(
            "EVROSION_M6_UI_COUNTS protocol=1 build={} phase=finished barriers=1 cursors=1 note_requests=1 note_accepted=1 note_delivered=1",
            build()
        )
    }
    #[test]
    fn busy_completion_requires_actual_matching_root_nonce_accepted_and_delivered_records() {
        use ev_userspace_contract::session_note::{Operation, Outcome, Refusal, Request};
        let request = Request::new(Operation::Write, 2).unwrap();
        let response = request.reply(Outcome::Refused(Refusal::Busy));
        let old = notes();
        let old_request = Request::new(Operation::Read, 1).unwrap();
        let mut lines = old.map(|line| line.replace("nonce=1", "nonce=2"));
        lines[0] = lines[0].replace("opcode=1", "opcode=2").replace(
            &format!("message={:016x}", u64::from_le_bytes(old_request.encode())),
            &format!("message={:016x}", u64::from_le_bytes(request.encode())),
        );
        for line in &mut lines[1..] {
            *line = line.replace("opcode=3", "opcode=131").replace(
                &format!(
                    "message={:016x}",
                    u64::from_le_bytes(old_request.reply(Outcome::Read).encode())
                ),
                &format!("message={:016x}", u64::from_le_bytes(response.encode())),
            );
        }
        let serial = lines.join("\n") + "\n";
        let ui = Ui::parse(serial.as_bytes(), &build()).unwrap();
        assert!(ui.completed(7, 2, 2).is_none());
        assert!(ui.completed_response(7, 2, 2, 131).is_some());
        assert!(ui.completed_response(7, 3, 2, 131).is_none());
        let foreign = serial.replace(
            "sender_process=1 sender_thread=1",
            "sender_process=9 sender_thread=9",
        );
        assert!(Ui::parse(foreign.as_bytes(), &build()).is_err());
        let mut wrong = lines.clone();
        wrong[2] = wrong[2].replace("ticket=10", "ticket=11");
        assert!(Ui::parse((wrong.join("\n") + "\n").as_bytes(), &build()).is_err());
    }
    #[test]
    fn actual_codec_joins_are_little_endian_complete_newline_and_crlf_safe() {
        let notes = notes();
        let serial = format!(
            "{}\r\n{}\n{}\r\n{}\n{}\r\n{}\n",
            barrier(),
            cursor(),
            notes[0],
            notes[1],
            notes[2],
            totals()
        );
        let ui = Ui::parse(serial.as_bytes(), &build()).unwrap();
        ui.final_check().unwrap();
        assert_eq!(ui.completed(7, 1, 1), Some(4));
        assert_eq!(ui.completed(7, 1, 2), None);
        for raw in serial.lines() {
            assert!(line(raw, &build()).is_ok());
        }
        let partial = format!("{}\n{}\n{}", notes[0], notes[1], notes[2]);
        assert!(
            Ui::parse(partial.as_bytes(), &build())
                .unwrap()
                .completed(7, 1, 1)
                .is_none()
        );
        assert!(
            Ui::parse(partial.as_bytes(), &build())
                .unwrap()
                .final_check()
                .is_err()
        );
    }
    #[test]
    fn accepted_or_wrong_recipient_ticket_nonce_and_replays_never_become_note_completion() {
        let n = notes();
        let accepted_only = format!("{}\n{}\n", n[0], n[1]);
        let ui = Ui::parse(accepted_only.as_bytes(), &build()).unwrap();
        assert!(ui.completed(7, 1, 1).is_none());
        assert!(ui.validate_notes(true).is_err());
        for bad in [
            n[2].replace("ticket=10", "ticket=11"),
            n[2].replace("endpoint=6", "endpoint=7"),
            n[2].replace("sender_process=1", "sender_process=2"),
            n[2].replace("receiver_thread=8", "receiver_thread=9"),
            n[2].replace("nonce=1", "nonce=2"),
            n[2].replace("tick=14", "tick=12"),
        ] {
            assert!(
                Ui::parse(format!("{}\n{}\n{bad}\n", n[0], n[1]).as_bytes(), &build()).is_err()
            );
        }
        assert!(
            Ui::parse(
                format!("{}\n{}\n{}\n", n[0], n[2], n[1]).as_bytes(),
                &build()
            )
            .is_err()
        );
        for (prefix, replay) in [
            (n[0].clone(), n[0].replace("count=1", "count=2")),
            (accepted_only.clone(), n[1].replace("count=1", "count=2")),
        ] {
            assert!(Ui::parse(format!("{prefix}\n{replay}\n").as_bytes(), &build()).is_err());
        }
    }
    #[test]
    fn syntax_refuses_wrong_build_reserved_barrier_cursor_counter_and_totals() {
        for bad in [
            barrier().replace("sequence=7", "sequence=8"),
            barrier().replace("buttons=57", "buttons=64"),
            barrier().replace("frame=1", "frame=2"),
            cursor().replace("x=319", "x=320"),
            cursor().replace("sequence=1", "sequence=2"),
            cursor().replace("count=1", "count=33"),
            format!("{} extra=1", cursor()),
        ] {
            assert!(line(&bad, &build()).is_err());
        }
        assert!(line(&barrier(), &"b".repeat(64)).is_err());
        assert!(
            Ui::parse(
                format!("{}\n{}\n", cursor(), cursor().replace("count=1", "count=3")).as_bytes(),
                &build()
            )
            .is_err()
        );
        let n = notes();
        let prefix = format!(
            "{}\n{}\n{}\n{}\n{}\n",
            barrier(),
            cursor(),
            n[0],
            n[1],
            n[2]
        );
        assert!(
            Ui::parse(
                format!("{prefix}{}\n", totals().replace("cursors=1", "cursors=2")).as_bytes(),
                &build()
            )
            .unwrap()
            .final_check()
            .is_err()
        );
        assert!(
            Ui::parse(
                format!(
                    "{prefix}{}\n",
                    totals().replace("phase=finished", "phase=bound")
                )
                .as_bytes(),
                &build()
            )
            .unwrap()
            .final_check()
            .is_err()
        );
    }
    fn directory() -> std::path::PathBuf {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let parent = storage::directory_beneath(&root, Path::new("build/test-tmp")).unwrap();
        build::unique_directory(&parent, "session-host-checks").unwrap()
    }
    #[test]
    fn thirty_two_sampled_completions_cannot_hide_an_unsampled_thirty_third_request() {
        use ev_userspace_contract::session_note::{Operation, Outcome, Request};
        let mut serial = String::new();
        for nonce in 1..=32 {
            let r = Request::new(Operation::Read, nonce).unwrap();
            let ack = r.reply(Outcome::Read);
            serial += &format!(
                "EVROSION_M6_NOTE protocol=1 build={} phase=request count={nonce} endpoint=5 ticket={nonce} sender_process=7 sender_thread=8 receiver_process=1 receiver_thread=1 nonce={nonce} opcode=1 message={:016x} tick={}\n",
                build(),
                u64::from_le_bytes(r.encode()),
                nonce * 3
            );
            for (phase, tick) in [("accepted", nonce * 3 + 1), ("delivered", nonce * 3 + 2)] {
                serial += &format!(
                    "EVROSION_M6_NOTE protocol=1 build={} phase={phase} count={nonce} endpoint=6 ticket={} sender_process=1 sender_thread=1 receiver_process=7 receiver_thread=8 nonce={nonce} opcode=3 message={:016x} tick={tick}\n",
                    build(),
                    nonce + 100,
                    u64::from_le_bytes(ack.encode())
                );
            }
        }
        let totals = format!(
            "EVROSION_M6_UI_COUNTS protocol=1 build={} phase=finished barriers=0 cursors=0 note_requests=32 note_accepted=32 note_delivered=32\n",
            build()
        );
        Ui::parse(format!("{serial}{totals}").as_bytes(), &build())
            .unwrap()
            .final_check()
            .unwrap();
        for extra in [
            totals.replace("note_requests=32", "note_requests=33"),
            totals.replace("note_delivered=32", "note_delivered=33"),
            totals
                .replace("note_requests=32", "note_requests=33")
                .replace("note_accepted=32", "note_accepted=33")
                .replace("note_delivered=32", "note_delivered=33"),
        ] {
            assert!(
                Ui::parse(format!("{serial}{extra}").as_bytes(), &build())
                    .unwrap()
                    .final_check()
                    .is_err()
            );
        }
    }
    #[test]
    fn session_faults_join_exact_original_and_replacement_identities_without_relaxing_legacy_grants()
     {
        let mut observer = Observer::new(Phase::Exercise);
        observer.first_app = Some(7);
        observer.current_app = Some(9);
        observer.first_shell = Some(6);
        observer.display = Some(3);
        let row = |event: &str, actor: &str, process: u64, thread: u64, replacement: u64| {
            format!(
                "EVROSION_M4_DESKTOP_LIFECYCLE protocol=1 build={} event={event} actor={actor} process={process} thread={thread} replacement={replacement} display_process=3 grants=1 vector={} error={} address={}\n",
                build(),
                if event == "fault" { 14 } else { 0 },
                if event == "fault" { 4 } else { 0 },
                if event == "fault" {
                    (1u64 << 39) + 4 * 1024 * 1024
                } else {
                    0
                }
            )
        };
        let fault = row("fault", "app", 7, 8, 0);
        assert!(desktop_protocol::lifecycle_line(fault.trim_end(), &build()).is_err());
        let serial = format!(
            "{fault}{}{}{}{}\n",
            row("restart", "app", 7, 8, 9),
            row("fault", "shell", 6, 6, 0),
            row("restart", "shell", 6, 6, 10),
            cursor().replace(
                "caller_process=6 caller_thread=6",
                "caller_process=10 caller_thread=10"
            )
        );
        observer
            .verify_lifecycle(serial.as_bytes(), &build())
            .unwrap();
        for bad in [
            serial.replace("replacement=9", "replacement=11"),
            serial.replace(
                "process=7 thread=8 replacement=9",
                "process=7 thread=12 replacement=9",
            ),
            serial.replace("display_process=3", "display_process=4"),
            serial.replace("grants=1", "grants=2"),
        ] {
            assert!(observer.verify_lifecycle(bad.as_bytes(), &build()).is_err());
        }
        assert!(
            Observer::new(Phase::ColdReopen)
                .verify_lifecycle(serial.as_bytes(), &build())
                .is_err()
        );
    }
    #[test]
    fn missing_guest_progress_retains_failure_and_owned_child_cleanup_without_vm_claim() {
        let directory = directory();
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let disk = storage::Disk::create(&root, &directory).unwrap();
        let serial = directory.join("serial.log");
        let errors = directory.join("stderr.log");
        fs::write(&serial, b"").unwrap();
        fs::write(&errors, b"").unwrap();
        let result = supervise(
            &mut Command::new("/bin/true"),
            &serial,
            &errors,
            Duration::from_secs(2),
            &build(),
            &directory,
            Phase::Exercise,
            &disk,
        );
        assert!(result.is_err());
        let record: Value =
            serde_json::from_slice(&fs::read(directory.join("session-observer.json")).unwrap())
                .unwrap();
        assert_eq!(record["passed"], false);
        assert_eq!(record["human_consent_claim"], false);
        assert!(record["captures"].as_array().unwrap().is_empty());
        let mut child = Owned(Command::new("/bin/sleep").arg("30").spawn().unwrap());
        let pid = child.0.id();
        assert!(child.0.try_wait().unwrap().is_none());
        drop(child);
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }
}
