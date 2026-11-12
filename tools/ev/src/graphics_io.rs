//! Bounded direct-child supervision and actual QMP scanout observation.
//! All observer failures kill/reap only the child created by this invocation.
use crate::{
    build::{self, Result},
    graphics_protocol::{self, Reference},
    qmp::Qmp,
    storage,
};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
    process::{Child, Command, ExitStatus},
    thread,
    time::{Duration, Instant},
};

const OUTPUT_LIMIT: u64 = 1024 * 1024;
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn read_log(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > OUTPUT_LIMIT {
        return Err("display log is nonregular or exceeds1MiB".into());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(OUTPUT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > OUTPUT_LIMIT {
        return Err("display log exceeds1MiB".into());
    }
    Ok(bytes)
}
fn observe_child(
    command: &mut Command,
    serial: &Path,
    errors: &Path,
    deadline: Instant,
    mut observe: impl FnMut(&[u8]) -> Result<()>,
) -> Result<ExitStatus> {
    if Instant::now() >= deadline {
        return Err("display absolute deadline elapsed before spawn".into());
    }
    let mut child = OwnedChild(
        command
            .spawn()
            .map_err(|e| format!("cannot start owned display QEMU: {e}"))?,
    );
    loop {
        if Instant::now() >= deadline {
            return Err("display QEMU absolute deadline elapsed".into());
        }
        let bytes = read_log(serial)?;
        let _ = read_log(errors)?;
        observe(&bytes)?;
        if let Some(status) = child.0.try_wait().map_err(|e| e.to_string())? {
            return Ok(status);
        }
        thread::sleep(
            Duration::from_millis(4).min(deadline.saturating_duration_since(Instant::now())),
        );
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
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or("display deadline overflow")?;
    let mut qmp = None;
    let mut capture: Option<Value> = None;
    let result=observe_child(command,serial,errors,deadline,|bytes|{
        let marker=graphics_protocol::present(bytes,build)?;
        if marker.is_none() || capture.is_some(){return Ok(());}
        let present=crate::boot::check_display_present_prefix(bytes,build)?.ok_or("Present record has no validated boot prefix")?;
        qmp=Some(Qmp::connect(directory,deadline)?);
        let observer=qmp.as_mut().ok_or("missing private QMP observer")?;
        let (path,frame)=observer.capture(1)?;
        let validation=Reference::hello()?.validate(&present,&frame)?;
        capture=Some(json!({"present":present,"scanout":{"path":path.file_name().ok_or("scanout filename missing")?,"sha256":build::hash_file(&path)?},"validation":validation}));
        Ok(())
    }).and_then(|status|if capture.is_none(){Err("owned QEMU exited without a validated actual QMP capture".into())}else{Ok(status)});
    let transcript = directory.join("qmp-transcript.json");
    storage::json_new(
        &transcript,
        &json!({"schema":1,"scope":"owned private QMP observer","exchanges":qmp.as_ref().map(|q|q.transcript()).unwrap_or(&[])}),
    )?;
    storage::json_new(
        &directory.join("graphics-observer.json"),
        &json!({"schema":1,"capture_observed":capture.is_some(),"passed":result.is_ok(),"error":result.as_ref().err(),"capture":capture,
        "qmp_transcript":{"path":"qmp-transcript.json","sha256":build::hash_file(&transcript)?},"method":"actual unmodified QMP scanout; host reference verifies all pixels and the retained surface digest"}),
    )?;
    result
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{path::PathBuf, process::Stdio};
    fn directory() -> PathBuf {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let parent = storage::directory_beneath(&root, Path::new("build/test-tmp")).unwrap();
        build::unique_directory(&parent, "graphics-lifecycle").unwrap()
    }
    #[test]
    fn observer_refusal_and_deadline_reap_the_exact_owned_child() {
        for refuse in [true, false] {
            let d = directory();
            let serial = d.join("serial");
            let errors = d.join("errors");
            let pid = d.join("pid");
            fs::write(&serial, []).unwrap();
            fs::write(&errors, []).unwrap();
            let mut command = Command::new("python3");
            command.args(["-c","from pathlib import Path; import os,sys,time; Path(sys.argv[1]).write_text(str(os.getpid())); Path(sys.argv[2]).write_text('ready\\n'); time.sleep(30)"]).arg(&pid).arg(&serial).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
            let deadline = Instant::now() + Duration::from_millis(300);
            let result = observe_child(&mut command, &serial, &errors, deadline, |bytes| {
                if refuse && bytes == b"ready\n" {
                    Err("deliberate observer refusal".into())
                } else {
                    Ok(())
                }
            });
            let error = result.unwrap_err();
            assert!(error.contains(if refuse {
                "observer refusal"
            } else {
                "deadline"
            }));
            let id = fs::read_to_string(&pid).unwrap();
            assert!(
                !Path::new("/proc").join(id).exists(),
                "owned child must be reaped"
            );
        }
    }
    #[test]
    fn early_process_exit_missing_present_and_oversized_logs_cannot_pass() {
        let d = directory();
        let serial = d.join("serial");
        let errors = d.join("errors");
        fs::write(&serial, []).unwrap();
        fs::write(&errors, []).unwrap();
        let mut command = Command::new("python3");
        command
            .args(["-c", "raise SystemExit(33)"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        assert!(
            supervise(
                &mut command,
                &serial,
                &errors,
                Duration::from_secs(2),
                &"a".repeat(64),
                &d
            )
            .unwrap_err()
            .contains("without a validated")
        );
        let observer: Value =
            serde_json::from_slice(&fs::read(d.join("graphics-observer.json")).unwrap()).unwrap();
        assert_eq!(observer["passed"], false);
        assert_eq!(observer["capture"], Value::Null);
        fs::write(&serial, vec![0; OUTPUT_LIMIT as usize + 1]).unwrap();
        assert!(read_log(&serial).is_err());
    }
}
