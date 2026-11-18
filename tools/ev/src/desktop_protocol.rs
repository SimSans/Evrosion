//! Full desktop diagnostics and a host-only pixel reference. This reference is
//! used to inspect real, unmodified QMP scanout; it is never guest evidence.
use crate::{build::Result, qmp::Ppm};
use ev_graphics::{Color, HEIGHT, Pixels, WIDTH, composition::app_sample, shell::Screen};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Producer {
    App,
    Shell,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StepKind {
    Frame,
    PickerReady,
    PickerHeld,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Step {
    pub(crate) kind: StepKind,
    pub(crate) frame: u64,
    pub(crate) width: usize,
    pub(crate) height: usize,
    pub(crate) app_process: u64,
    pub(crate) shell_process: u64,
    pub(crate) display_process: u64,
    pub(crate) grants: u64,
    pub(crate) producer: Producer,
    pub(crate) surface_sha256: String,
    pub(crate) held_ticks: u64,
}
fn hash(field: &str, name: &str) -> Result<String> {
    let value = field
        .strip_prefix(name)
        .and_then(|s| s.strip_prefix('='))
        .ok_or("missing desktop digest field")?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("desktop digest must be64 lowercase hexadecimal digits".into());
    }
    Ok(value.into())
}
pub(crate) fn step_line(line: &str, build: &str) -> Result<Step> {
    use crate::boot_protocol::canonical_number as number;
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 1024
        || f.len() != 14
        || f[0] != "EVROSION_M4_DESKTOP_STEP"
        || f[1] != "protocol=1"
        || hash(f[2], "build")? != build
    {
        return Err("malformed or wrong-build desktop step".into());
    }
    let kind = match f[3] {
        "step=frame" => StepKind::Frame,
        "step=picker_ready" => StepKind::PickerReady,
        "step=picker_held" => StepKind::PickerHeld,
        _ => return Err("unknown desktop checkpoint".into()),
    };
    let value = Step {
        kind,
        frame: number(f[4], "frame")?,
        width: usize::try_from(number(f[5], "width")?).map_err(|_| "desktop width overflow")?,
        height: usize::try_from(number(f[6], "height")?).map_err(|_| "desktop height overflow")?,
        app_process: number(f[7], "app_process")?,
        shell_process: number(f[8], "shell_process")?,
        display_process: number(f[9], "display_process")?,
        grants: number(f[10], "grants")?,
        producer: match f[11] {
            "producer=app" => Producer::App,
            "producer=shell" => Producer::Shell,
            _ => return Err("invalid desktop producer".into()),
        },
        surface_sha256: hash(f[12], "surface_sha256")?,
        held_ticks: number(f[13], "held_ticks")?,
    };
    if value.frame == 0
        || value.frame >= u64::from(u32::MAX)
        || !(800..=2048).contains(&value.width)
        || !(600..=2048).contains(&value.height)
        || value.shell_process == 0
        || value.display_process == 0
        || value.shell_process == value.display_process
        || value.app_process != 0
            && (value.app_process == value.shell_process
                || value.app_process == value.display_process)
        || value.producer == Producer::App && value.app_process == 0
        || kind != StepKind::Frame && value.producer != Producer::Shell
        || kind != StepKind::PickerHeld && value.held_ticks != 0
        || kind == StepKind::PickerHeld && !(64..=16_384).contains(&value.held_ticks)
    {
        return Err("incoherent desktop frame/identity/held checkpoint".into());
    }
    Ok(value)
}
pub(crate) fn steps(serial: &[u8], build: &str) -> Result<Vec<Step>> {
    if serial.len() > 1024 * 1024 {
        return Err("desktop serial exceeds1MiB".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "desktop serial not UTF-8")?;
    let mut output = Vec::new();
    for line in text.split_inclusive('\n') {
        if !line.ends_with('\n') {
            break;
        }
        if line.starts_with("EVROSION_M4_DESKTOP_EXIT") {
            let exit = exit_line(line.trim_end_matches(['\r', '\n']), build)?;
            return Err(format!(
                "desktop {:?} exited with code={} process={} thread={} instruction={} calls={} replies={}",
                exit.actor,
                exit.code,
                exit.process,
                exit.thread,
                exit.instruction,
                exit.calls,
                exit.replies
            ));
        }
        if line.starts_with("EVROSION_M4_DESKTOP_STEP ") {
            output.push(step_line(line.trim_end_matches(['\r', '\n']), build)?);
            if output.len() > 256 {
                return Err("desktop checkpoint bound exceeded".into());
            }
        }
    }
    Ok(output)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Actor {
    App,
    Shell,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Exit {
    actor: Actor,
    process: u64,
    thread: u64,
    code: u64,
    instruction: u64,
    calls: u64,
    replies: u64,
}
/// Voluntary termination is a distinct actual diagnostic, never a fabricated
/// processor fault. The scripted scenario expects no Exit, including code0.
fn exit_line(line: &str, build: &str) -> Result<Exit> {
    use crate::boot_protocol::canonical_number as number;
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 1024
        || f.len() != 10
        || f[0] != "EVROSION_M4_DESKTOP_EXIT"
        || f[1] != "protocol=1"
        || hash(f[2], "build")? != build
    {
        return Err("malformed/wrong-build desktop exit".into());
    }
    let exit = Exit {
        actor: match f[3] {
            "actor=app" => Actor::App,
            "actor=shell" => Actor::Shell,
            _ => return Err("unknown desktop exit actor".into()),
        },
        process: number(f[4], "process")?,
        thread: number(f[5], "thread")?,
        code: number(f[6], "code")?,
        instruction: number(f[7], "instruction")?,
        calls: number(f[8], "calls")?,
        replies: number(f[9], "replies")?,
    };
    if exit.process == 0 || exit.thread == 0 || exit.instruction == 0 || exit.replies > exit.calls {
        return Err("invalid desktop exit identity or counters".into());
    }
    Ok(exit)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Event {
    Fault,
    Restart,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Lifecycle {
    pub(crate) event: Event,
    pub(crate) actor: Actor,
    pub(crate) process: u64,
    pub(crate) thread: u64,
    pub(crate) replacement: u64,
    pub(crate) display_process: u64,
    pub(crate) grants: u64,
    pub(crate) vector: u64,
    pub(crate) error: u64,
    pub(crate) address: u64,
}
pub(crate) fn lifecycle_syntax(line: &str, build: &str) -> Result<Lifecycle> {
    use crate::boot_protocol::canonical_number as number;
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 1024
        || f.len() != 13
        || f[0] != "EVROSION_M4_DESKTOP_LIFECYCLE"
        || f[1] != "protocol=1"
        || hash(f[2], "build")? != build
    {
        return Err("malformed/wrong-build desktop lifecycle".into());
    }
    let value = Lifecycle {
        event: match f[3] {
            "event=fault" => Event::Fault,
            "event=restart" => Event::Restart,
            _ => return Err("unknown desktop lifecycle event".into()),
        },
        actor: match f[4] {
            "actor=app" => Actor::App,
            "actor=shell" => Actor::Shell,
            _ => return Err("unknown desktop fault actor".into()),
        },
        process: number(f[5], "process")?,
        thread: number(f[6], "thread")?,
        replacement: number(f[7], "replacement")?,
        display_process: number(f[8], "display_process")?,
        grants: number(f[9], "grants")?,
        vector: number(f[10], "vector")?,
        error: number(f[11], "error")?,
        address: number(f[12], "address")?,
    };
    if value.process == 0
        || value.thread == 0
        || value.display_process == 0
        || value.display_process == value.process
    {
        return Err("invalid desktop lifecycle identity".into());
    }
    match value.event {
        Event::Fault
            if value.replacement == 0
                && value.vector == 14
                && value.error == 4
                && value.address == (1u64 << 39) + 4 * 1024 * 1024 => {}
        Event::Restart
            if value.replacement != 0
                && value.replacement != value.process
                && value.replacement != value.display_process
                && value.vector == 0
                && value.error == 0
                && value.address == 0 => {}
        _ => return Err("desktop lifecycle is not exact actual fault or replacement shape".into()),
    };
    Ok(value)
}
pub(crate) fn lifecycle_line(line: &str, build: &str) -> Result<Lifecycle> {
    let value = lifecycle_syntax(line, build)?;
    if value.grants != if value.actor == Actor::App { 2 } else { 3 } {
        return Err("invalid desktop lifecycle grants".into());
    }
    Ok(value)
}
/// Syntax for the one Native Managed initial Shell fault before its first
/// protected frame. The caller must enforce mode, ordering, zero App execution
/// and completion facts; this tuple establishes no admission or health policy.
pub(crate) fn initial_native_shell_fault_line(line: &str, build: &str) -> Result<Lifecycle> {
    let value = lifecycle_syntax(line, build)?;
    if value.actor != Actor::Shell || value.event != Event::Fault || value.grants != 0 {
        return Err("Native initial Shell fault is not the exact zero-grant fault".into());
    }
    Ok(value)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Record {
    pub(crate) processes: u64,
    pub(crate) starts: u64,
    pub(crate) calls: u64,
    pub(crate) replies: u64,
}
pub(crate) fn line(line: &str) -> Result<Record> {
    use crate::boot_protocol::canonical_number as number;
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 1024
        || f.len() != 14
        || f[..3] != ["EVROSION_M4_DESKTOP", "status=PASS", "scope=graph"]
        || f[5..7] != ["faults=2", "restarts=2"]
        || f[9..]
            != [
                "grants=3",
                "frames=true",
                "metadata=true",
                "guards=true",
                "display_survived=true",
            ]
    {
        return Err("malformed desktop graph final proof".into());
    }
    let value = Record {
        processes: number(f[3], "processes")?,
        starts: number(f[4], "starts")?,
        calls: number(f[7], "calls")?,
        replies: number(f[8], "replies")?,
    };
    if !(9..=64).contains(&value.processes)
        || !(3..=64).contains(&value.starts)
        || value.processes != value.starts
        || !(1..=100000).contains(&value.calls)
        || value.replies > value.calls
    {
        return Err("desktop graph counts exceed bounded profile".into());
    }
    Ok(value)
}
pub(crate) fn record(serial: &[u8], build: &str) -> Result<Record> {
    if serial.len() > 1024 * 1024 {
        return Err("desktop serial exceeds1MiB".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "desktop final serial not UTF-8")?;
    let mut final_record = None;
    let mut events = Vec::new();
    let mut display = None;
    for raw in text.split_inclusive('\n') {
        if !raw.ends_with('\n') {
            return Err("desktop final serial truncated".into());
        }
        let l = raw.trim_end_matches(['\r', '\n']);
        if l.starts_with("EVROSION_M4_DESKTOP_STEP ") {
            let s = step_line(l, build)?;
            if display.is_some_and(|d| d != s.display_process) {
                return Err("desktop Display changed".into());
            }
            display = Some(s.display_process);
        } else if l.starts_with("EVROSION_M4_DESKTOP_LIFECYCLE ") {
            let e = lifecycle_line(l, build)?;
            if display != Some(e.display_process) {
                return Err("lifecycle changed surviving Display".into());
            }
            events.push(e);
        } else if l.starts_with("EVROSION_M4_DESKTOP ") {
            if final_record.is_some() {
                return Err("duplicate desktop final proof".into());
            }
            final_record = Some(line(l)?);
        }
    }
    if events.len() != 4 {
        return Err("desktop proof must retain exactly two actual faults and replacements".into());
    }
    for (i, actor) in [Actor::App, Actor::Shell].into_iter().enumerate() {
        let fault = &events[i * 2];
        let restart = &events[i * 2 + 1];
        if fault.actor != actor
            || fault.event != Event::Fault
            || restart.actor != actor
            || restart.event != Event::Restart
            || fault.process != restart.process
            || fault.thread != restart.thread
            || fault.display_process != restart.display_process
        {
            return Err(
                "desktop replacement not bound to exact retained dead process/thread".into(),
            );
        }
    }
    final_record.ok_or("missing desktop final proof".into())
}

/// Diagnostic ordering checks correlate actual receipts. They do not convert
/// frames, sequence numbers or a trusted-looking tuple into guest authority.
#[derive(Default)]
pub(crate) struct Timeline {
    frames: std::collections::BTreeMap<(u64, u8), u64>,
    latest_shell: Option<Step>,
    ready: Option<Step>,
    held: bool,
    display: Option<u64>,
    grants: u64,
}
impl Timeline {
    pub(crate) fn observe(&mut self, step: &Step) -> Result<()> {
        self.observe_profile(step, false)
    }
    pub(crate) fn observe_session(&mut self, step: &Step) -> Result<()> {
        self.observe_profile(step, true)
    }
    fn observe_profile(&mut self, step: &Step, session: bool) -> Result<()> {
        if self.display.is_some_and(|d| d != step.display_process)
            || step.grants < self.grants
            || (!session && step.grants > 3)
        {
            return Err(
                "desktop Display changed or grant history regressed/exceededscenario".into(),
            );
        }
        match step.kind {
            StepKind::Frame => {
                let (id, kind) = match step.producer {
                    Producer::App => (step.app_process, 0),
                    Producer::Shell => (step.shell_process, 1),
                };
                if self
                    .frames
                    .get(&(id, kind))
                    .is_some_and(|f| *f >= step.frame)
                {
                    return Err("replayed/regressed desktop frame".into());
                }
                self.frames.insert((id, kind), step.frame);
                if step.producer == Producer::Shell {
                    self.latest_shell = Some(step.clone());
                    self.ready = None;
                    self.held = false;
                }
            }
            StepKind::PickerReady => {
                if self.ready.is_some()
                    || !self
                        .latest_shell
                        .as_ref()
                        .is_some_and(|f| same_frame(f, step))
                {
                    return Err("picker ready has no exact completed producing frame".into());
                }
                self.ready = Some(step.clone());
            }
            StepKind::PickerHeld => {
                if self.held || !self.ready.as_ref().is_some_and(|f| same_frame(f, step)) {
                    return Err(
                        "held interval has no matching current picker/barrier/grants".into(),
                    );
                }
                self.held = true;
            }
        }
        self.display = Some(step.display_process);
        self.grants = step.grants;
        Ok(())
    }
}
fn same_frame(a: &Step, b: &Step) -> bool {
    a.frame == b.frame
        && a.width == b.width
        && a.height == b.height
        && a.app_process == b.app_process
        && a.shell_process == b.shell_process
        && a.display_process == b.display_process
        && a.grants == b.grants
        && a.producer == b.producer
        && a.surface_sha256 == b.surface_sha256
}

struct Buffer(Vec<Color>);
impl Pixels for Buffer {
    fn dimensions(&self) -> (usize, usize) {
        (WIDTH, HEIGHT)
    }
    fn write(
        &mut self,
        x: usize,
        y: usize,
        color: Color,
    ) -> core::result::Result<(), ev_graphics::Error> {
        if x >= WIDTH || y >= HEIGHT || color.0 & 0xff00_0000 != 0 {
            return Err(ev_graphics::Error::Bounds);
        }
        self.0[y * WIDTH + x] = color;
        Ok(())
    }
}
/// Independent composition of the source-defined Shell chrome and, only when
/// visible, the actual expected App view. Surface digests are checked separately
/// against protected frame snapshots; screen pixels cannot grant File access.
pub(crate) struct Reference {
    pixels: Vec<Color>,
    shell: Vec<Color>,
    app: Option<Vec<Color>>,
}
impl Reference {
    pub(crate) fn new(screen: Screen, app: Option<ev_graphics::HelloView<'_>>) -> Result<Self> {
        if (screen == Screen::AppRunning) != app.is_some() {
            return Err("desktop reference visibility mismatch".into());
        }
        let mut shell = Buffer(vec![Color(0); WIDTH * HEIGHT]);
        ev_graphics::shell::render(&mut shell, screen)
            .map_err(|e| format!("desktop Shell reference: {e:?}"))?;
        let shell_pixels = shell.0.clone();
        let mut app_pixels = None;
        if let Some(view) = app {
            let mut surface = Buffer(vec![Color(0); WIDTH * HEIGHT]);
            ev_graphics::hello_window(&mut surface, view)
                .map_err(|e| format!("desktop App reference: {e:?}"))?;
            app_pixels = Some(surface.0.clone());
            for y in 0..HEIGHT {
                for x in 0..WIDTH {
                    if let Some((sx, sy)) = app_sample(x, y) {
                        shell.0[y * WIDTH + x] = surface.0[sy * WIDTH + sx];
                    }
                }
            }
        }
        Ok(Self {
            pixels: shell.0,
            shell: shell_pixels,
            app: app_pixels,
        })
    }
    pub(crate) fn native(
        screen: Screen,
        app: Option<ev_graphics::native::View<'_>>,
    ) -> Result<Self> {
        if (screen == Screen::AppRunning) != app.is_some() {
            return Err("Native reference visibility mismatch".into());
        }
        let mut shell = Buffer(vec![Color(0); WIDTH * HEIGHT]);
        ev_graphics::shell::render(&mut shell, screen)
            .map_err(|e| format!("Native Shell: {e:?}"))?;
        let shell_pixels = shell.0.clone();
        let app_pixels = if let Some(view) = app {
            let mut surface = Buffer(vec![Color(0); WIDTH * HEIGHT]);
            ev_graphics::native::render(&mut surface, view)
                .map_err(|e| format!("Native App: {e:?}"))?;
            for y in 0..HEIGHT {
                for x in 0..WIDTH {
                    if let Some((sx, sy)) = app_sample(x, y) {
                        shell.0[y * WIDTH + x] = surface.0[sy * WIDTH + sx];
                    }
                }
            }
            Some(surface.0)
        } else {
            None
        };
        Ok(Self {
            pixels: shell.0,
            shell: shell_pixels,
            app: app_pixels,
        })
    }
    pub(crate) fn surface_hash(&self, producer: Producer, sequence: u64) -> Result<String> {
        let pixels = match producer {
            Producer::Shell => &self.shell,
            Producer::App => self
                .app
                .as_ref()
                .ok_or("App reference absent for producing surface")?,
        };
        let mut hash = Sha256::new();
        hash.update(
            ev_graphics::SurfaceHeader { sequence }
                .encode()
                .map_err(|e| format!("desktop reference header: {e:?}"))?,
        );
        for color in pixels {
            hash.update(color.0.to_le_bytes());
        }
        hash.update(vec![
            0;
            ev_graphics::MAPPED_BYTES
                - ev_graphics::HEADER_BYTES
                - ev_graphics::PIXEL_BYTES
        ]);
        Ok(format!("{:x}", hash.finalize()))
    }
    fn pixel(&self, x: usize, y: usize, width: usize, height: usize) -> [u8; 3] {
        let left = (width - WIDTH * 2) / 2;
        let top = (height - HEIGHT * 2) / 2;
        if x >= left && x < left + WIDTH * 2 && y >= top && y < top + HEIGHT * 2 {
            self.pixels[((y - top) / 2) * WIDTH + (x - left) / 2].components()
        } else {
            ev_graphics::BACKGROUND.components()
        }
    }
    pub(crate) fn validate(&self, frame: &Ppm) -> Result<Value> {
        let (width, height) = frame.dimensions();
        if !(800..=2048).contains(&width) || !(600..=2048).contains(&height) {
            return Err("unsupported desktop scanout geometry".into());
        }
        let mut actual = Sha256::new();
        let mut expected = Sha256::new();
        for y in 0..height {
            for x in 0..width {
                let observed = frame.pixel(x, y)?;
                let wanted = self.pixel(x, y, width, height);
                actual.update(observed);
                expected.update(wanted);
                if observed != wanted {
                    return Err(format!(
                        "actual desktop scanout mismatch at({x},{y}): {observed:?} != {wanted:?}"
                    ));
                }
            }
        }
        Ok(
            json!({"width":width,"height":height,"pixels":width*height,"actual_rgb_sha256":format!("{:x}",actual.finalize()),"expected_rgb_sha256":format!("{:x}",expected.finalize()),"all_pixels_match":true}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ev_graphics::{HelloControl, HelloView, shell::FileChoice};
    #[test]
    fn initial_native_shell_fault_does_not_relax_legacy_lifecycle_grants_or_shape() {
        let build = "a".repeat(64);
        let initial = format!(
            "EVROSION_M4_DESKTOP_LIFECYCLE protocol=1 build={build} event=fault actor=shell process=6 thread=6 replacement=0 display_process=3 grants=0 vector=14 error=4 address=549760008192"
        );
        assert!(initial_native_shell_fault_line(&initial, &build).is_ok());
        assert!(lifecycle_line(&initial, &build).is_err());
        let legacy = initial.replace("grants=0", "grants=3");
        assert!(lifecycle_line(&legacy, &build).is_ok());
        assert!(initial_native_shell_fault_line(&legacy, &build).is_err());
        assert!(initial_native_shell_fault_line(&initial, &"b".repeat(64)).is_err());
        for changed in [
            initial.replace("actor=shell", "actor=app"),
            initial.replace("grants=0", "grants=1"),
            initial.replace("event=fault", "event=restart"),
            initial.replace("replacement=0", "replacement=262"),
            initial.replace("vector=14", "vector=13"),
            initial.replace("error=4", "error=6"),
            initial.replace("address=549760008192", "address=549760008193"),
            initial.replace("process=6", "process=3"),
            initial.replace("thread=6", "thread=0"),
            initial.replace("thread=6", "thread=06"),
            format!("{initial} ignored=true"),
        ] {
            assert!(initial_native_shell_fault_line(&changed, &build).is_err());
        }
    }
    fn frame(reference: &Reference) -> Vec<u8> {
        let mut b = b"P6\n800 600\n255\n".to_vec();
        for y in 0..600 {
            for x in 0..800 {
                b.extend(reference.pixel(x, y, 800, 600));
            }
        }
        b
    }
    fn step(kind: &str, frame: u64, held: u64) -> String {
        format!(
            "EVROSION_M4_DESKTOP_STEP protocol=1 build={} step={kind} frame={frame} width=1280 height=800 app_process=7 shell_process=8 display_process=9 grants=0 producer=shell surface_sha256={} held_ticks={held}",
            "a".repeat(64),
            "b".repeat(64)
        )
    }
    #[test]
    fn checkpoint_total_decoder_rejects_wrongbuild_reserved_shape_and_short_held_interval() {
        let build = "a".repeat(64);
        let good = step("picker_held", 2, 64);
        assert!(step_line(&good, &build).is_ok());
        for bad in [
            good.replace("ticks=64", "ticks=63"),
            good.replace("producer=shell", "producer=app"),
            good.replace("width=1280", "width=01280"),
            good.replace("shell_process=8", "shell_process=9"),
            format!("{good} extra=0"),
            good.replace("step=picker_held", "step=unknown"),
        ] {
            assert!(step_line(&bad, &build).is_err());
        }
        assert!(step_line(&good, &"c".repeat(64)).is_err());
        assert!(steps(good.as_bytes(), &build).unwrap().is_empty());
        assert_eq!(
            steps(format!("{good}\n").as_bytes(), &build).unwrap().len(),
            1
        );
    }
    #[test]
    fn actual_exit_fails_the_script_immediately_with_its_own_code_and_identity() {
        let build = "a".repeat(64);
        for code in [0, 833, u64::MAX] {
            let line = format!(
                "EVROSION_M4_DESKTOP_EXIT protocol=1 build={build} actor=app process=7 thread=17 code={code} instruction=268435900 calls=112 replies=112"
            );
            let exit = exit_line(&line, &build).unwrap();
            assert_eq!((exit.code, exit.process, exit.thread), (code, 7, 17));
            // A partial write is not a complete receipt. The next completed
            // line must stop the owned scenario, rather than wait for a frame.
            assert!(steps(line.as_bytes(), &build).unwrap().is_empty());
            let error = steps(format!("{line}\n").as_bytes(), &build).unwrap_err();
            assert!(error.contains(&format!("code={code} process=7 thread=17")));
            assert!(error.contains("instruction=268435900 calls=112 replies=112"));
        }
    }
    #[test]
    fn exit_diagnostic_is_exact_and_cannot_be_relabelled_as_a_fault_or_another_build() {
        let build = "a".repeat(64);
        let line = format!(
            "EVROSION_M4_DESKTOP_EXIT protocol=1 build={build} actor=app process=7 thread=17 code=833 instruction=268435900 calls=112 replies=112"
        );
        assert!(exit_line(&line, &"b".repeat(64)).is_err());
        for changed in [
            line.replace("protocol=1", "protocol=2"),
            line.replace("actor=app", "actor=unknown"),
            line.replace("process=7", "process=0"),
            line.replace("thread=17", "thread=017"),
            line.replace("instruction=268435900", "instruction=0"),
            line.replace("replies=112", "replies=113"),
            line.replace("code=833", "vector=14"),
            format!("{line} fault=true"),
        ] {
            assert!(exit_line(&changed, &build).is_err(), "{changed}");
            assert!(steps(format!("{changed}\n").as_bytes(), &build).is_err());
        }
    }
    #[test]
    fn held_evidence_requires_exact_completed_frame_ready_and_unchanged_grants() {
        let build = "a".repeat(64);
        let frame = step_line(&step("frame", 2, 0), &build).unwrap();
        let ready = step_line(&step("picker_ready", 2, 0), &build).unwrap();
        let held = step_line(&step("picker_held", 2, 64), &build).unwrap();
        let mut history = Timeline::default();
        assert!(history.observe(&held).is_err());
        history.observe(&frame).unwrap();
        assert!(history.observe(&held).is_err());
        history.observe(&ready).unwrap();
        let mut wrong = held.clone();
        wrong.grants = 1;
        assert!(history.observe(&wrong).is_err());
        history.observe(&held).unwrap();
        assert!(history.observe(&held).is_err());
        assert!(history.observe(&frame).is_err());
        let mut next = frame.clone();
        next.frame = 3;
        history.observe(&next).unwrap();
        assert!(history.observe(&held).is_err());
        next.frame = 4;
        next.display_process = 10;
        assert!(history.observe(&next).is_err());
    }
    #[test]
    fn source_composition_checks_every_pixel_and_separates_selected_contents() {
        let notes = Reference::new(
            Screen::AppRunning,
            Some(HelloView {
                focus: HelloControl::OpenFile,
                content: Some(ev_file::desktop::SEED_NOTES),
                incarnation: 1,
            }),
        )
        .unwrap();
        let private = Reference::new(
            Screen::AppRunning,
            Some(HelloView {
                focus: HelloControl::OpenFile,
                content: Some(ev_file::desktop::SEED_PRIVATE),
                incarnation: 1,
            }),
        )
        .unwrap();
        let bytes = frame(&notes);
        let actual = Ppm::parse(bytes.clone()).unwrap();
        assert_eq!(notes.validate(&actual).unwrap()["all_pixels_match"], true);
        assert!(private.validate(&actual).is_err());
        for offset in [0, bytes.len() - 1] {
            let mut changed = bytes.clone();
            let first = changed.len() - 800 * 600 * 3;
            changed[first + offset % (800 * 600 * 3)] ^= 1;
            assert!(notes.validate(&Ppm::parse(changed).unwrap()).is_err());
        }
    }
    #[test]
    fn desktop_viewport_copies_every_compact_app_pixel_without_dropping_font_rows() {
        let reference = Reference::new(
            Screen::AppRunning,
            Some(HelloView {
                focus: HelloControl::OpenFile,
                content: Some(b"Hello"),
                incarnation: 1,
            }),
        )
        .unwrap();
        let app = reference.app.as_ref().unwrap();
        for sy in 0..ev_graphics::composition::APP_VIEW.height {
            for sx in 0..ev_graphics::composition::APP_VIEW.width {
                assert_eq!(
                    reference.pixels[(54 + sy) * WIDTH + 20 + sx],
                    app[sy * WIDTH + sx]
                );
            }
        }
        // Independent H bitmap checks all seven rows in actual composition.
        for (row, bits) in [17u8, 17, 17, 31, 17, 17, 17].into_iter().enumerate() {
            for col in 0..5 {
                let expected = if bits & (1 << (4 - col)) != 0 {
                    ev_graphics::INK
                } else {
                    ev_graphics::PANEL
                };
                assert_eq!(
                    reference.pixels[(54 + 8 + row) * WIDTH + 20 + 8 + col],
                    expected
                );
            }
        }
    }
    #[test]
    fn picker_is_full_trusted_chrome_and_visibility_cannot_reuse_app_pixels() {
        let notes = Reference::new(
            Screen::Picker {
                selected: FileChoice::Notes,
            },
            None,
        )
        .unwrap();
        let private = Reference::new(
            Screen::Picker {
                selected: FileChoice::Private,
            },
            None,
        )
        .unwrap();
        let actual = Ppm::parse(frame(&notes)).unwrap();
        assert!(notes.validate(&actual).is_ok());
        assert!(private.validate(&actual).is_err());
        assert!(Reference::new(Screen::AppRunning, None).is_err());
        assert!(
            Reference::new(
                Screen::Home,
                Some(HelloView {
                    focus: HelloControl::OpenFile,
                    content: None,
                    incarnation: 1
                })
            )
            .is_err()
        );
    }
}
