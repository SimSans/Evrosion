//! Supervise one owned owner-console child, preserving finite logs and input.
pub(crate) use crate::owner_serial::Input;
use crate::{
    owner_protocol::Prompt,
    owner_serial::{Console, Poll},
};
use serde_json::Value;
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

const LIMIT: u64 = 1024 * 1024;

pub(crate) struct Outcome {
    pub(crate) status: ExitStatus,
    pub(crate) eof_no_action: bool,
    pub(crate) written: Vec<(u128, u8)>,
    pub(crate) validated_prompt: Option<Value>,
}

struct ChildGuard(Child);
impl ChildGuard {
    fn kill_wait(&mut self) -> Result<ExitStatus, String> {
        if let Some(status) = self.0.try_wait().map_err(|error| error.to_string())? {
            return Ok(status);
        }
        if let Err(error) = self.0.kill() {
            if let Some(status) = self.0.try_wait().map_err(|error| error.to_string())? {
                return Ok(status);
            }
            return Err(format!("cannot stop owned owner console: {error}"));
        }
        self.0.wait().map_err(|error| error.to_string())
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn bounded(path: &Path) -> Result<Vec<u8>, String> {
    if fs::metadata(path).map_err(|error| error.to_string())?.len() > LIMIT {
        return Err(format!("owner output limit exceeded: {}", path.display()));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| error.to_string())?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > LIMIT {
        return Err(format!("owner output limit exceeded: {}", path.display()));
    }
    Ok(bytes)
}

/// Only the five checked explanatory lines are displayed. Kernel/firmware and
/// machine diagnostics remain in the bounded raw logfile for independent audit.
fn explanation(serial: &[u8]) -> Result<String, String> {
    let text = crate::owner_protocol::text(serial)?;
    let mut stage = 0;
    let mut result = String::new();
    for line in text.lines() {
        if stage == 0 && !line.starts_with("Evrosion generation ") {
            continue;
        }
        if stage == 5 {
            break;
        }
        stage = crate::owner_protocol::ui_line(stage, line, false)?;
        result.push_str(line);
        result.push('\n');
    }
    if stage != 5 {
        return Err("owner prompt has no complete validated explanation".into());
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn supervise(
    command: &mut Command,
    serial: &Path,
    errors: &Path,
    timeout: Duration,
    build: &str,
    catalogue: &str,
    input: Input,
) -> Result<Outcome, String> {
    let display = matches!(input, Input::Owner);
    supervise_with(
        command,
        serial,
        errors,
        timeout,
        build,
        catalogue,
        Console::new(input)?,
        display,
        crate::boot::check_owner_prompt_prefix,
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        os::unix::process::ExitStatusExt,
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        time::{SystemTime, UNIX_EPOCH},
    };

    const BUILD: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const CATALOGUE: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn prefix() -> String {
        format!(
            "Evrosion generation 2 could not start: a process fault.\r\nFailed image: {}\r\nCurrent selection: generation 3 (pending validation).\r\nKnown-good generation 1 is available. Returning keeps your files.\r\nType r then Enter to continue with known-good, or q then Enter to cancel.\r\nEVROSION_M3_OWNER_PROMPT protocol=1 build={BUILD} catalogue={CATALOGUE} operation=16 selected=3 known_good=1 failure_generation=2 failure_serial=2 deadline=62000 actions=r,q\n",
            "ab".repeat(32)
        )
    }

    // This test adapter checks the actual UI/prompt grammar, while Root's
    // production callback separately checks the complete ordered boot prefix.
    fn validate(bytes: &[u8], build: &str, catalogue: &str) -> Result<Option<Prompt>, String> {
        let found = crate::owner_protocol::prompt(bytes, build, catalogue)?;
        if found.is_some() {
            explanation(bytes)?;
        }
        Ok(found)
    }

    struct Fixture {
        directory: PathBuf,
        serial: PathBuf,
        errors: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let cwd = std::env::current_dir().unwrap();
            let root = cwd
                .ancestors()
                .find(|path| path.join("kernel/Cargo.toml").is_file())
                .unwrap();
            let directory = root.join("build/test-tmp").join(format!(
                "owner-io-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&directory).unwrap();
            Self {
                serial: directory.join("serial"),
                errors: directory.join("stderr"),
                directory,
            }
        }
        fn command(&self, text: &str, read: usize, mode: &str) -> Command {
            let mut result = Command::new("python3");
            result.args(["-c", "import pathlib,sys,os,time\np=pathlib.Path(sys.argv[1]); p.joinpath('pid').write_text(str(os.getpid()))\ntime.sleep(.04)\np.joinpath('serial').write_text(sys.argv[2])\nif sys.argv[4]=='stderr':\n sys.stderr.write('x'*1048577); sys.stderr.flush()\nif sys.argv[4]=='serial':\n p.joinpath('serial').write_text('x'*1048577)\nif sys.argv[4]!='normal': time.sleep(30)\ndata=sys.stdin.buffer.read(int(sys.argv[3])); p.joinpath('received').write_bytes(data)\ntime.sleep(.03)\n"])
                .arg(&self.directory).arg(text).arg(read.to_string()).arg(mode);
            result
        }
        fn run(
            &self,
            command: &mut Command,
            console: Console,
            timeout: Duration,
        ) -> Result<Outcome, String> {
            supervise_with(
                command,
                &self.serial,
                &self.errors,
                timeout,
                BUILD,
                CATALOGUE,
                console,
                false,
                validate,
            )
        }
        fn reaped(&self) {
            let pid = fs::read_to_string(self.directory.join("pid")).unwrap();
            assert!(
                !Path::new("/proc").join(pid).exists(),
                "owned test child is alive or unreaped"
            );
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.directory).unwrap();
        }
    }

    struct Reader {
        input: mpsc::Receiver<u8>,
        read: Arc<AtomicUsize>,
    }
    impl Read for Reader {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            match self.input.recv() {
                Ok(byte) => {
                    bytes[0] = byte;
                    self.read.fetch_add(1, Ordering::AcqRel);
                    Ok(1)
                }
                Err(_) => Ok(0),
            }
        }
    }
    fn reader() -> (Console, mpsc::Sender<u8>, Arc<AtomicUsize>) {
        let (input, receiver) = mpsc::channel();
        let read = Arc::new(AtomicUsize::new(0));
        let console = Console::with_reader(Reader {
            input: receiver,
            read: Arc::clone(&read),
        })
        .unwrap();
        (console, input, read)
    }
    fn wait(check: impl Fn() -> bool) {
        let start = Instant::now();
        while !check() {
            assert!(start.elapsed() < Duration::from_secs(2));
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn written(outcome: &Outcome) -> Vec<u8> {
        outcome.written.iter().map(|(_, byte)| *byte).collect()
    }

    #[test]
    fn only_a_complete_bound_prompt_can_submit_one_whole_command() {
        for bytes in [b"r\nq\n".as_slice(), b" \tQ\rr\n"] {
            let fixture = Fixture::new();
            let expected = if bytes[0] == b'r' {
                b"r\n".as_slice()
            } else {
                b" \tQ\r"
            };
            let outcome = fixture
                .run(
                    &mut fixture.command(&prefix(), expected.len(), "normal"),
                    Console::new(Input::Script(if bytes[0] == b'r' {
                        b"r\nq\n"
                    } else {
                        b" \tQ\rr\n"
                    }))
                    .unwrap(),
                    Duration::from_secs(2),
                )
                .unwrap();
            assert!(outcome.status.success());
            assert!(!outcome.eof_no_action);
            assert_eq!(written(&outcome), expected);
            assert_eq!(
                fs::read(fixture.directory.join("received")).unwrap(),
                expected
            );
            assert_eq!(outcome.validated_prompt.as_ref().unwrap()["build"], BUILD);
            assert!(
                outcome
                    .written
                    .windows(2)
                    .all(|pair| pair[0].0 <= pair[1].0)
            );
            fixture.reaped();
        }
    }

    #[test]
    fn invalid_partial_and_wrong_build_prompts_never_receive_input() {
        for text in [
            prefix().trim_end().to_owned(),
            prefix().replace(BUILD, CATALOGUE),
            prefix().replace(
                "Current selection: generation 3",
                "Current selection: generation 4",
            ),
        ] {
            let fixture = Fixture::new();
            assert!(
                fixture
                    .run(
                        &mut fixture.command(&text, 0, "wait"),
                        Console::new(Input::Script(b"r\n")).unwrap(),
                        Duration::from_millis(180)
                    )
                    .is_err()
            );
            assert!(!fixture.directory.join("received").exists());
            fixture.reaped();
        }
    }

    #[test]
    fn scripted_eof_kills_and_reaps_only_after_a_validated_prompt() {
        let fixture = Fixture::new();
        let outcome = fixture
            .run(
                &mut fixture.command(&prefix(), 0, "wait"),
                Console::new(Input::Eof).unwrap(),
                Duration::from_secs(2),
            )
            .unwrap();
        assert!(outcome.eof_no_action);
        assert_eq!(outcome.status.signal(), Some(9));
        assert!(outcome.written.is_empty());
        assert!(outcome.validated_prompt.is_some());
        fixture.reaped();
    }

    #[test]
    fn live_reader_discards_stale_complete_and_prompt_spanning_lines() {
        for stale in [b"r\n".as_slice(), b"r"] {
            let fixture = Fixture::new();
            let (console, input, read) = reader();
            for byte in stale {
                input.send(*byte).unwrap();
            }
            wait(|| read.load(Ordering::Acquire) == stale.len());
            let armed = console.armed_for_test();
            let partial = stale.len() == 1;
            let feeder = std::thread::spawn(move || {
                wait(|| armed.load(Ordering::Acquire));
                for byte in if partial { b"\nq\r".as_slice() } else { b"q\r" } {
                    input.send(*byte).unwrap();
                }
                // EOF after the completed command must never abort its action.
            });
            let outcome = fixture
                .run(
                    &mut fixture.command(&prefix(), 2, "normal"),
                    console,
                    Duration::from_secs(2),
                )
                .unwrap();
            feeder.join().unwrap();
            assert!(outcome.status.success());
            assert!(!outcome.eof_no_action);
            assert_eq!(written(&outcome), b"q\r");
            fixture.reaped();
        }
    }

    #[test]
    fn unterminated_or_escape_noise_followed_by_eof_is_never_consent() {
        for bytes in [b"r".as_slice(), b"\x1br\n", b"r \n"] {
            let fixture = Fixture::new();
            let (console, input, _) = reader();
            let armed = console.armed_for_test();
            let bytes = bytes.to_vec();
            let feeder = std::thread::spawn(move || {
                wait(|| armed.load(Ordering::Acquire));
                for byte in bytes {
                    input.send(byte).unwrap();
                }
            });
            let outcome = fixture
                .run(
                    &mut fixture.command(&prefix(), 0, "wait"),
                    console,
                    Duration::from_secs(2),
                )
                .unwrap();
            feeder.join().unwrap();
            assert!(outcome.eof_no_action);
            assert_eq!(outcome.status.signal(), Some(9));
            fixture.reaped();
        }
    }

    #[test]
    fn receive_budget_and_blocked_reader_do_not_block_cleanup() {
        let fixture = Fixture::new();
        let outcome = fixture
            .run(
                &mut fixture.command(&prefix(), 128, "normal"),
                Console::new(Input::Script(&[b'x'; 128])).unwrap(),
                Duration::from_secs(2),
            )
            .unwrap();
        assert!(outcome.status.success());
        assert_eq!(outcome.written.len(), 128);
        fixture.reaped();
        let fixture = Fixture::new();
        let (console, input, _) = reader();
        let started = Instant::now();
        assert!(
            fixture
                .run(
                    &mut fixture.command(&prefix(), 0, "wait"),
                    console,
                    Duration::from_millis(180)
                )
                .is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        fixture.reaped();
        drop(input);
    }

    #[test]
    fn either_log_overflow_kills_and_reaps_the_child() {
        for mode in ["serial", "stderr"] {
            let fixture = Fixture::new();
            let error = fixture
                .run(
                    &mut fixture.command("", 0, mode),
                    Console::new(Input::Silent).unwrap(),
                    Duration::from_secs(2),
                )
                .err()
                .unwrap();
            assert!(error.contains("output limit"));
            fixture.reaped();
        }
    }

    #[test]
    fn human_display_excludes_all_machine_diagnostics() {
        let human = explanation(&format!("firmware chatter\n{}", prefix()).into_bytes()).unwrap();
        assert!(human.starts_with("Evrosion generation 2"));
        assert!(!human.contains("firmware"));
        assert!(!human.contains("EVROSION_M3_OWNER_PROMPT"));
        assert!(human.ends_with(
            "Type r then Enter to continue with known-good, or q then Enter to cancel.\n"
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn supervise_with(
    command: &mut Command,
    serial: &Path,
    errors: &Path,
    timeout: Duration,
    build: &str,
    catalogue: &str,
    mut console: Console,
    display: bool,
    validate: impl Fn(&[u8], &str, &str) -> Result<Option<Prompt>, String>,
) -> Result<Outcome, String> {
    // These are new caller-owned evidence paths. The QEMU stdio chardev writes
    // its TX logfile independently; stdout must not leak unchecked guest text.
    File::create(serial).map_err(|error| error.to_string())?;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(File::create(errors).map_err(|error| error.to_string())?);
    let mut child = ChildGuard(
        command
            .spawn()
            .map_err(|error| format!("cannot start owner VM: {error}"))?,
    );
    let started = Instant::now();
    let mut prompt = None;
    loop {
        let bytes = bounded(serial)?;
        // Reading the bounded stderr too closes the metadata/read race.
        bounded(errors)?;
        if started.elapsed() >= timeout {
            return Err(format!(
                "owner VM timed out after {} seconds",
                timeout.as_secs()
            ));
        }
        if let Some(status) = child.0.try_wait().map_err(|error| error.to_string())? {
            return Ok(Outcome {
                status,
                eof_no_action: false,
                written: std::mem::take(&mut console.written),
                validated_prompt: prompt,
            });
        }
        if prompt.is_none()
            && let Some(found) = validate(&bytes, build, catalogue)?
        {
            // Validation precedes both display and arming the sole input writer.
            let human = explanation(&bytes)?;
            if display {
                let mut output = std::io::stdout().lock();
                output
                    .write_all(human.as_bytes())
                    .and_then(|()| output.flush())
                    .map_err(|error| format!("cannot display owner prompt: {error}"))?;
            }
            prompt = Some(serde_json::to_value(found).map_err(|error| error.to_string())?);
        }
        if console.poll(&mut child.0, prompt.is_some())? == Poll::EofNoAction {
            let status = child.kill_wait()?;
            return Ok(Outcome {
                status,
                eof_no_action: true,
                written: std::mem::take(&mut console.written),
                validated_prompt: prompt,
            });
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
