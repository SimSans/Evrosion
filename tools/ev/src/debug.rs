use crate::build::Result;
use std::{
    fs::{self, File},
    path::Path,
    process::{Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

struct Vm(std::process::Child);
impl Drop for Vm {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    command: &mut Command,
    kernel: &Path,
    root: &Path,
    directory: &Path,
    port: u16,
    batch: bool,
    panic: bool,
    timeout: u64,
) -> Result<ExitStatus> {
    let mut vm = Vm(command.spawn().map_err(|e| e.to_string())?);
    let transcript = directory.join("gdb-transcript.txt");
    let script = directory.join("session.gdb");
    // Quote paths for GDB's own parser; all commands are generated locally.
    let quote = |p: &Path| {
        format!(
            "\"{}\"",
            p.to_string_lossy()
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
        )
    };
    let mut commands = format!(
        "set pagination off\nset confirm off\nset remotetimeout 10\nset tcp connect-timeout 10\nset tcp auto-retry on\nset substitute-path /evrosion {}\nfile {}\ntarget remote 127.0.0.1:{port}\nhbreak evrosion_kernel_entry\n",
        quote(root),
        quote(kernel)
    );
    if batch {
        commands.push_str("continue\nprintf \"EV_GDB_ENTRY_PC=%p\\n\", $pc\ninfo line *$pc\nbt\ndelete breakpoints\n");
        if panic {
            commands.push_str("hbreak evrosion_deliberate_panic\ncontinue\nprintf \"EV_GDB_PANIC_PC=%p\\n\", $pc\ninfo line *$pc\nlist\nbt\ndelete breakpoints\n");
        }
        commands.push_str("detach\nquit\n");
    }
    fs::write(&script, commands).map_err(|e| e.to_string())?;
    let mut gdb = Command::new("gdb");
    gdb.args(["-q", "-nx"])
        .arg("-x")
        .arg(&script)
        .current_dir(root);
    if batch {
        let log = File::create(&transcript).map_err(|e| e.to_string())?;
        gdb.arg("--batch")
            .stdin(Stdio::null())
            .stdout(log.try_clone().map_err(|e| e.to_string())?)
            .stderr(log);
        let status =
            crate::boot::supervised(&mut gdb, &[&transcript], Duration::from_secs(timeout))?;
        let text = fs::read_to_string(&transcript).map_err(|e| e.to_string())?;
        if !status.success()
            || !text.contains("EV_GDB_ENTRY_PC=")
            || !text.contains("kernel/src/main.rs")
            || !text.contains("#0")
            || !text.contains("#1")
            || (panic && !text.contains("EV_GDB_PANIC_PC="))
        {
            return Err(format!(
                "GDB symbol/source verification failed; see {}",
                transcript.display()
            ));
        }
        println!("PASS GDB symbols and source: {}", transcript.display());
    } else {
        println!(
            "QEMU paused before kernel execution. In GDB: continue, bt; detach, quit to finish."
        );
        if !gdb.status().map_err(|e| e.to_string())?.success() {
            return Err("GDB failed".into());
        }
    }
    let started = Instant::now();
    loop {
        if let Some(status) = vm.0.try_wait().map_err(|e| e.to_string())? {
            return Ok(status);
        }
        if started.elapsed() > Duration::from_secs(timeout) {
            return Err("QEMU timed out after debugger detach".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
