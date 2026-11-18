//! Real PS/2 edits, protected Present/barrier joins and actual scanout. A
//! screenshot is never substituted for a successful Note transaction.
use crate::{
    build::{self, Result},
    desktop_protocol::{Producer, Step, StepKind},
    qmp::{Key, Qmp},
    session_io::ProbeUi,
    session_reference::Reference,
};
use ev_graphics::{
    native::Build,
    session::{Focus, SaveState, View},
    shell::Screen,
};
use serde_json::{Value, json};

pub(super) const FIRST: &str = "M6 keep42";
pub(super) const FINAL: &str = "M6 keep42 later";
pub(super) fn tap(qmp: &mut Qmp, key: Key) -> Result<()> {
    qmp.key_state(key, true)?;
    qmp.key_state(key, false)
}
pub(super) struct Work {
    phase: u8,
    typed: usize,
    second: bool,
    pub app: u64,
    min_frame: u64,
    capture: u32,
    pub captures: Vec<Value>,
}
impl Work {
    pub(super) fn new(app: u64) -> Self {
        Self {
            phase: 0,
            typed: 0,
            second: false,
            app,
            min_frame: 0,
            capture: 0,
            captures: Vec::new(),
        }
    }
    pub(super) fn append(&mut self, qmp: &mut Qmp) -> Result<()> {
        if self.phase != 4 || self.second {
            return Err("negative Note append out of order".into());
        }
        for _ in 0..3 {
            tap(qmp, Key::Tab)?;
        }
        self.phase = 0;
        self.typed = FIRST.len();
        self.second = true;
        Ok(())
    }
    pub(super) fn done(&self) -> bool {
        self.phase == 4
    }
    pub(super) fn advance(&mut self, serial: &[u8], build: &str, qmp: &mut Qmp) -> Result<bool> {
        if self.done() {
            return Ok(true);
        }
        let target = if self.second {
            FINAL.as_bytes()
        } else {
            FIRST.as_bytes()
        };
        let (focus, state) = match self.phase {
            0 => (Focus::Note, SaveState::Saved),
            1 => (Focus::Note, SaveState::Unsaved),
            2 => (Focus::Save, SaveState::Unsaved),
            3 => (Focus::Save, SaveState::Saved),
            _ => unreachable!(),
        };
        let note = &target[..self.typed];
        let ui = ProbeUi::parse(serial, build)?;
        if self.phase == 0 && !self.second && ui.note_complete(self.app, 1, 1).is_none() {
            return Ok(false);
        }
        if self.phase == 3
            && ui
                .note_complete(self.app, if self.second { 3 } else { 2 }, 2)
                .is_none()
        {
            return Ok(false);
        }
        let mut frames = Vec::new();
        for (line, text) in std::str::from_utf8(serial)
            .map_err(|_| "negative Note UTF8")?
            .lines()
            .enumerate()
        {
            if text.starts_with("EVROSION_M4_DESKTOP_STEP ") {
                let step = crate::desktop_protocol::step_line(text, build)?;
                if step.kind == StepKind::Frame {
                    frames.push((line, step));
                }
            }
        }
        if frames.len() > 256 {
            return Err("negative Note frame ledger exceeded256".into());
        }
        let Some((app_line, app)) = frames
            .iter()
            .rev()
            .find(|(_, s)| s.producer == Producer::App)
        else {
            return Ok(false);
        };
        if app.app_process != self.app || app.grants != 0 || app.frame <= self.min_frame {
            return Ok(false);
        }
        let reference = Reference::new(
            Screen::AppRunning,
            Some(View {
                build: Build::A,
                focus,
                note,
                state,
                file: None,
            }),
            ui.cursor(),
        )?;
        if reference.surface_hash(Producer::App, app.frame)? != app.surface_sha256 {
            return Ok(false);
        }
        let Some((line, shell)) = frames
            .iter()
            .rev()
            .find(|(_, s)| s.producer == Producer::Shell)
        else {
            return Ok(false);
        };
        if !reference.fresh_app_ready(app, *app_line, shell, *line, &ui)? {
            return Ok(false);
        }
        self.capture += 1;
        if self.capture > 48 {
            return Err("negative Note scanout bound48".into());
        }
        qmp.set_running(false)?;
        let capture = qmp.capture(self.capture);
        qmp.set_running(true)?;
        let (path, ppm) = capture?;
        if ppm.dimensions() != (app.width, app.height) {
            return Err("negative Note scanout geometry".into());
        }
        let actual = reference.validate(&ppm);
        self.captures.push(json!({"second":self.second,"phase":self.phase,"typed":self.typed,"frame":app,"scanout":path.file_name(),"sha256":build::hash_file(&path)?,"validation":actual.as_ref().ok(),"error":actual.as_ref().err()}));
        actual?;
        self.min_frame = app.frame;
        match self.phase {
            0 => {
                qmp.ascii(target[self.typed])?;
                self.typed += 1;
                self.phase = 1;
            }
            1 => {
                if self.typed < target.len() {
                    qmp.ascii(target[self.typed])?;
                    self.typed += 1;
                } else {
                    tap(qmp, Key::Tab)?;
                    self.phase = 2;
                }
            }
            2 => {
                tap(qmp, Key::Enter)?;
                self.phase = 3;
            }
            3 => self.phase = 4,
            _ => unreachable!(),
        }
        Ok(self.done())
    }
}

pub(super) fn app_step(serial: &[u8], build: &str, app: u64) -> Result<Option<Step>> {
    let steps = crate::desktop_protocol::steps(serial, build)?;
    if steps
        .iter()
        .any(|s| s.grants != 0 || s.app_process != 0 && s.app_process != app)
    {
        return Err("negative changed App or grant".into());
    }
    Ok(steps
        .into_iter()
        .rev()
        .find(|s| s.producer == Producer::App && s.kind == StepKind::Frame))
}
