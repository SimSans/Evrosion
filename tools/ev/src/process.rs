//! Argument-array process execution for short host probes. No shell evaluation.
//! VM lifecycle/deadlines are added with the QEMU runner in Slice 3.

use std::ffi::OsString;
use std::fmt;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;

pub const CAPTURE_LIMIT: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Invocation {
    pub program: PathBuf,
    pub arguments: Vec<OsString>,
    pub directory: PathBuf,
}

impl Invocation {
    pub fn new(
        program: impl AsRef<Path>,
        arguments: &[impl AsRef<std::ffi::OsStr>],
        directory: &Path,
    ) -> Self {
        Self {
            program: program.as_ref().to_owned(),
            arguments: arguments
                .iter()
                .map(|argument| argument.as_ref().to_owned())
                .collect(),
            directory: directory.to_owned(),
        }
    }
}

#[derive(Debug)]
pub struct Captured {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Captured {
    pub fn text(&self) -> String {
        format!(
            "{}\n{}",
            String::from_utf8_lossy(&self.stdout),
            String::from_utf8_lossy(&self.stderr)
        )
    }

    pub fn checked(self) -> Result<Self, ProcessError> {
        if self.status.success() {
            Ok(self)
        } else {
            Err(ProcessError::Exit(self))
        }
    }
}

#[derive(Debug)]
pub enum ProcessError {
    Spawn {
        program: PathBuf,
        source: io::Error,
    },
    Wait(io::Error),
    Capture {
        stream: &'static str,
        source: io::Error,
    },
    ReaderPanic(&'static str),
    OutputLimit(&'static str),
    Exit(Captured),
}

impl fmt::Display for ProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn { program, source } => {
                write!(formatter, "cannot launch {}: {source}", program.display())
            }
            Self::Wait(source) => write!(formatter, "cannot wait for process: {source}"),
            Self::Capture { stream, source } => {
                write!(formatter, "cannot capture {stream}: {source}")
            }
            Self::ReaderPanic(stream) => write!(formatter, "{stream} capture thread failed"),
            Self::OutputLimit(stream) => write!(
                formatter,
                "{stream} exceeded the {CAPTURE_LIMIT}-byte probe limit"
            ),
            Self::Exit(output) => write!(
                formatter,
                "{}: {}",
                output.status,
                output.text().trim().chars().take(600).collect::<String>()
            ),
        }
    }
}

impl std::error::Error for ProcessError {}

pub trait Runner {
    fn run(&self, invocation: &Invocation) -> Result<Captured, ProcessError>;
}

pub struct SystemRunner;

fn capture(stream: impl Read, name: &'static str) -> Result<Vec<u8>, ProcessError> {
    let mut bytes = Vec::new();
    stream
        .take((CAPTURE_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| ProcessError::Capture {
            stream: name,
            source,
        })?;
    if bytes.len() > CAPTURE_LIMIT {
        return Err(ProcessError::OutputLimit(name));
    }
    Ok(bytes)
}

impl Runner for SystemRunner {
    fn run(&self, invocation: &Invocation) -> Result<Captured, ProcessError> {
        let mut child = Command::new(&invocation.program)
            .args(&invocation.arguments)
            .current_dir(&invocation.directory)
            .env("RUSTUP_AUTO_INSTALL", "0")
            .env("CARGO_NET_OFFLINE", "true")
            .env("CARGO_TERM_COLOR", "never")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| ProcessError::Spawn {
                program: invocation.program.clone(),
                source,
            })?;
        // Both pipes were requested above; drain concurrently to avoid pipe deadlock.
        let stdout = child
            .stdout
            .take()
            .expect("stdout was configured as a pipe");
        let stderr = child
            .stderr
            .take()
            .expect("stderr was configured as a pipe");
        let stdout = thread::spawn(move || capture(stdout, "stdout"));
        let stderr = thread::spawn(move || capture(stderr, "stderr"));
        let status = child.wait().map_err(ProcessError::Wait);
        if status.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let stdout = stdout
            .join()
            .map_err(|_| ProcessError::ReaderPanic("stdout"));
        let stderr = stderr
            .join()
            .map_err(|_| ProcessError::ReaderPanic("stderr"));
        Ok(Captured {
            status: status?,
            stdout: stdout??,
            stderr: stderr??,
        })
    }
}
