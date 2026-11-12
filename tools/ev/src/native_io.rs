//! Runner-owned Native VM stimuli. Real keyboard/UART and lossless QMP captures
//! are retained; no host reference paints guest memory or repairs the disk.
use crate::{
    build::{self, Result},
    desktop_protocol::{self, Producer, Reference, StepKind, Timeline},
    native_protocol,
    qmp::Qmp,
    storage,
};
use ev_graphics::{
    HelloControl, HelloView,
    native::{Build, View},
    shell::Screen,
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
    InstallFull,
    ActivateB,
    RollbackA,
    Remove,
    ReinstallA,
    VerifyCancel,
}
impl Phase {
    pub fn name(self) -> &'static str {
        match self {
            Self::InstallFull => "install-full",
            Self::ActivateB => "activate-b",
            Self::RollbackA => "rollback-a",
            Self::Remove => "remove",
            Self::ReinstallA => "reinstall-a",
            Self::VerifyCancel => "verify-cancel",
        }
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
        return Err("Native log nonregular/over1MiB".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 1024 * 1024 {
        return Err("Native log grew over1MiB".into());
    }
    Ok(bytes)
}
fn reference(build: Build, value: u32) -> Result<Reference> {
    Reference::native(
        Screen::AppRunning,
        Some(View {
            hello: HelloView {
                focus: HelloControl::OpenFile,
                content: None,
                incarnation: 1,
            },
            build,
            saved_value: value,
        }),
    )
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
) -> Result<ExitStatus> {
    if phase == Phase::InstallFull {
        return crate::desktop_io::supervise_native_full(
            command, serial, errors, timeout, build, directory,
        );
    }
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or("Native deadline overflow")?;
    let mut qmp = None;
    let mut captures = Vec::<Value>::new();
    let mut inputs = Vec::<Value>::new();
    let mut stage = 0u8;
    let mut seen = 0;
    let mut timeline = Timeline::default();
    let mut first_process = None;
    let mut capture_index = 0u32;
    let mut final_frame = false;
    let mut finish_attempts = 0u8;
    let mut last_finish_report = 0u64;
    let result = (|| {
        if Instant::now() >= deadline {
            return Err("Native deadline before spawn".into());
        }
        let mut child = Owned(
            command
                .stdin(Stdio::piped())
                .spawn()
                .map_err(|e| e.to_string())?,
        );
        let mut stdin = child.0.stdin.take().ok_or("Native owned UART absent")?;
        loop {
            if Instant::now() >= deadline {
                return Err(format!("Native {} deadline at stage{stage}", phase.name()));
            }
            let bytes = log(serial)?;
            let _ = log(errors)?;
            let steps = desktop_protocol::steps(&bytes, build)?;
            let states = native_protocol::states(&bytes, build)?;
            if steps.len() < seen {
                return Err("Native serial history truncated".into());
            }
            let mut send = None;
            for step in &steps[seen..] {
                timeline.observe(step)?;
                let expected = match (phase, stage) {
                    (Phase::ActivateB, 0) => Some(reference(Build::A, 1001)?),
                    (Phase::RollbackA, 0) => Some(reference(Build::B, 2026)?),
                    (Phase::Remove | Phase::VerifyCancel, 0) => Some(reference(Build::A, 2026)?),
                    (Phase::ReinstallA, 0) => Some(Reference::native(Screen::Home, None)?),
                    (Phase::ActivateB, 2) => Some(reference(Build::B, 2026)?),
                    (Phase::RollbackA | Phase::ReinstallA, 1) => Some(reference(Build::A, 2026)?),
                    (Phase::Remove, 1) => Some(Reference::native(Screen::AppStopped, None)?),
                    _ => None,
                };
                let Some(reference) = expected else {
                    continue;
                };
                let producer =
                    if matches!((phase, stage), (Phase::ReinstallA, 0) | (Phase::Remove, 1)) {
                        Producer::Shell
                    } else {
                        Producer::App
                    };
                if step.kind != StepKind::Frame
                    || step.producer != producer
                    || reference.surface_hash(producer, step.frame)? != step.surface_sha256
                {
                    continue;
                }
                if qmp.is_none() {
                    crate::boot::check_desktop_prefix(&bytes, build)?;
                    qmp = Some(Qmp::connect(directory, deadline)?);
                }
                capture_index += 1;
                if capture_index > 32 {
                    return Err("Native capture bound32".into());
                }
                let observer = qmp.as_mut().unwrap();
                observer.set_running(false)?;
                let (path, frame) = observer.capture(capture_index)?;
                let validation = reference.validate(&frame);
                captures.push(json!({"phase":phase.name(),"stage":stage,"step":step,"path":path.file_name(),"sha256":build::hash_file(&path)?,"passed":validation.is_ok(),"validation":validation.as_ref().ok(),"transient_mismatch":validation.as_ref().err()}));
                observer.set_running(true)?;
                if validation.is_err() {
                    continue;
                }
                if stage == 0 {
                    first_process = Some(step.app_process);
                    send = Some(match phase {
                        Phase::ActivateB => b"stage b\n".as_slice(),
                        Phase::RollbackA => b"rollback\n",
                        Phase::Remove => b"remove\n",
                        Phase::ReinstallA => b"reinstall a\nactivate\n",
                        Phase::VerifyCancel => b"inspect\ncancel\n",
                        Phase::InstallFull => unreachable!(),
                    });
                    stage = 1;
                } else {
                    final_frame = true;
                }
            }
            seen = steps.len();
            if phase == Phase::ActivateB
                && stage == 1
                && let Some(state) = states.iter().find(|s| s.is("stage"))
            {
                if Some(state.number("actual_process")?) != first_process
                    || state.fields["active"] != "a"
                    || state.fields["staged"] != "b"
                {
                    return Err("staging changed the actual running A incarnation".into());
                }
                send = Some(b"activate\n");
                stage = 2;
            }
            let complete_op = match phase {
                Phase::ActivateB | Phase::ReinstallA => "activate",
                Phase::RollbackA => "rollback",
                Phase::Remove => "remove",
                Phase::VerifyCancel => "cancel",
                Phase::InstallFull => unreachable!(),
            };
            if stage != 3
                && states.iter().any(|s| s.is(complete_op))
                && (final_frame || phase == Phase::VerifyCancel)
            {
                send = Some(b"finish\n");
                stage = 3;
                finish_attempts = 1;
            }
            if stage == 3 {
                for state in &states {
                    let report = state.number("report")?;
                    if state.fields["op"] == "finish" && report > last_finish_report {
                        last_finish_report = report;
                        if state.fields["result"] == "busy" {
                            if finish_attempts >= 8 {
                                return Err(
                                    "Native finish remains busy after8 explicit refusals".into()
                                );
                            }
                            send = Some(b"finish\n");
                            finish_attempts += 1;
                        }
                    }
                }
            }
            if let Some(input) = send {
                stdin
                    .write_all(input)
                    .and_then(|()| stdin.flush())
                    .map_err(|e| e.to_string())?;
                inputs.push(json!({"phase":phase.name(),"stage":stage,"device":"owned QEMU UART","bytes_hex":input.iter().map(|b|format!("{b:02x}")).collect::<String>()}));
            }
            if let Some(status) = child.0.try_wait().map_err(|e| e.to_string())? {
                if stage != 3 {
                    return Err(format!(
                        "Native exited before requested phase completion at stage{stage}"
                    ));
                }
                native_protocol::record(&log(serial)?, build)?;
                return Ok(status);
            }
            thread::sleep(
                Duration::from_millis(4).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    })();
    storage::json_new(
        &directory.join("qmp-transcript.json"),
        &json!({"schema":1,"exchanges":qmp.as_ref().map(|q|q.transcript()).unwrap_or(&[])}),
    )?;
    storage::json_new(
        &directory.join("native-observer.json"),
        &json!({"schema":1,"phase":phase.name(),"passed":result.as_ref().is_ok_and(|s|s.code()==Some(ev_test_protocol::QEMU_PASS_STATUS)),"error":result.as_ref().err(),"last_stage":stage,"captures":captures,"inputs":inputs,"method":"actual protected frame receipts, complete framed state diagnostics, real owned UART, independent full-pixel QMP captures; durable facts separately cold-read"}),
    )?;
    result
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn native_missing_checkpoint_and_deadline_reap_only_the_owned_child() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        for wait in [false, true] {
            let directory =
                build::unique_directory(&root.join("build/test-tmp"), "native-child-lifecycle")
                    .unwrap();
            let serial = directory.join("serial");
            let errors = directory.join("errors");
            let pid = directory.join("pid");
            fs::write(&serial, []).unwrap();
            fs::write(&errors, []).unwrap();
            let mut command = Command::new("python3");
            command.args(["-c","import pathlib,os,sys,time; pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(float(sys.argv[2]))"]).arg(&pid).arg(if wait{"30"}else{"0"}).stdout(Stdio::null()).stderr(Stdio::null());
            let error = supervise(
                &mut command,
                &serial,
                &errors,
                Duration::from_millis(300),
                &"a".repeat(64),
                &directory,
                Phase::ActivateB,
            )
            .unwrap_err();
            assert!(error.contains(if wait { "deadline" } else { "before requested" }));
            assert!(
                !Path::new("/proc")
                    .join(fs::read_to_string(pid).unwrap())
                    .exists()
            );
            let record: Value =
                serde_json::from_slice(&fs::read(directory.join("native-observer.json")).unwrap())
                    .unwrap();
            assert_eq!(record["passed"], false);
            assert_eq!(record["inputs"].as_array().unwrap().len(), 0);
        }
    }
}
