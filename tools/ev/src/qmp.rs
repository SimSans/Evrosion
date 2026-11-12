//! Private test-only QMP connection. This is host test infrastructure, never a
//! guest input or display authority. Every exchange has an ID and finite bounds.
use crate::build::Result;
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const LINE_LIMIT: usize = 256 * 1024;
const EVENT_LIMIT: usize = 128;
const FRAME_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Key {
    Tab,
    Enter,
    Escape,
    #[cfg(test)]
    Up,
    #[cfg(test)]
    Down,
}
impl Key {
    fn qcode(self) -> &'static str {
        match self {
            Self::Tab => "tab",
            Self::Enter => "ret",
            Self::Escape => "esc",
            #[cfg(test)]
            Self::Up => "up",
            #[cfg(test)]
            Self::Down => "down",
        }
    }
}

pub(crate) struct Qmp {
    reader: BufReader<UnixStream>,
    next: u64,
    transcript: Vec<Value>,
    directory: PathBuf,
    deadline: Instant,
    origin: Instant,
    pauses: crate::perf_ledger::Ledger,
}
impl Qmp {
    /// The caller owns this newly created, private QEMU evidence directory and
    /// the direct child that listens at its socket. No external monitor accepted.
    pub(crate) fn connect(directory: &Path, deadline: Instant) -> Result<Self> {
        Self::connect_at(directory, deadline, Instant::now())
    }
    pub(crate) fn connect_at(directory: &Path, deadline: Instant, origin: Instant) -> Result<Self> {
        let metadata = fs::symlink_metadata(directory).map_err(|e| e.to_string())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("QMP evidence directory must be an owned regular directory".into());
        }
        let directory = directory.canonicalize().map_err(|e| e.to_string())?;
        let socket = directory.join("qmp.sock");
        use std::os::unix::fs::FileTypeExt;
        let metadata = fs::symlink_metadata(&socket).map_err(|e| e.to_string())?;
        if !metadata.file_type().is_socket() || metadata.file_type().is_symlink() {
            return Err("private QMP path is not its actual socket".into());
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("QMP deadline elapsed")?;
        // Evidence paths exceed sockaddr_un's108-byte bound. Resolve only this
        // retained, checked directory through our own live fd; the socket still
        // lives inside the private evidence directory, with no external alias.
        use std::os::fd::AsRawFd;
        let directory_fd = fs::File::open(&directory).map_err(|e| e.to_string())?;
        let short_socket = PathBuf::from(format!(
            "/proc/self/fd/{}/qmp.sock",
            directory_fd.as_raw_fd()
        ));
        let stream = UnixStream::connect(&short_socket).map_err(|e| format!("private QMP: {e}"))?;
        stream
            .set_read_timeout(Some(remaining.min(Duration::from_secs(2))))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(remaining.min(Duration::from_secs(2))))
            .map_err(|e| e.to_string())?;
        let mut qmp = Self {
            reader: BufReader::new(stream),
            next: 1,
            transcript: Vec::new(),
            directory,
            deadline,
            origin,
            pauses: crate::perf_ledger::Ledger::new(),
        };
        let greeting = qmp.read(deadline.min(Instant::now() + Duration::from_secs(2)))?;
        if !greeting.get("QMP").is_some_and(Value::is_object) {
            return Err("QMP greeting missing".into());
        }
        qmp.execute("qmp_capabilities", json!({}))?;
        Ok(qmp)
    }
    fn read(&mut self, deadline: Instant) -> Result<Value> {
        let mut bytes = Vec::new();
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or("QMP absolute deadline elapsed")?;
            self.reader
                .get_mut()
                .set_read_timeout(Some(remaining))
                .map_err(|e| e.to_string())?;
            let available = self
                .reader
                .fill_buf()
                .map_err(|e| format!("QMP read: {e}"))?;
            if available.is_empty() {
                return Err("QMP disconnected".into());
            }
            let take = available
                .iter()
                .position(|b| *b == b'\n')
                .map_or(available.len(), |i| i + 1);
            if bytes.len() + take > LINE_LIMIT {
                return Err("QMP line exceeds bound".into());
            }
            let complete = available[take - 1] == b'\n';
            bytes.extend_from_slice(&available[..take]);
            self.reader.consume(take);
            if complete {
                break;
            }
        }
        let value = serde_json::from_slice(&bytes).map_err(|e| format!("QMP JSON: {e}"))?;
        self.transcript.push(json!({"received":value}));
        Ok(value)
    }
    fn execute(&mut self, name: &str, arguments: Value) -> Result<Value> {
        let deadline = self.deadline.min(Instant::now() + Duration::from_secs(2));
        let id = self.next;
        self.next = self
            .next
            .checked_add(1)
            .ok_or("QMP command counter exhausted")?;
        let value = json!({"execute":name,"arguments":arguments,"id":id});
        let mut bytes = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        self.reader
            .get_mut()
            .set_write_timeout(Some(
                deadline
                    .checked_duration_since(Instant::now())
                    .ok_or("QMP command deadline elapsed")?,
            ))
            .map_err(|e| e.to_string())?;
        self.reader
            .get_mut()
            .write_all(&bytes)
            .map_err(|e| format!("QMP write: {e}"))?;
        self.transcript.push(json!({"sent":value}));
        for _ in 0..EVENT_LIMIT {
            let reply = self.read(deadline)?;
            if reply.get("event").is_some() {
                if reply.get("id").is_some() {
                    return Err("QMP event carries unexpected ID".into());
                }
                continue;
            }
            if reply.get("id").and_then(Value::as_u64) != Some(id) {
                return Err("QMP response ID mismatch".into());
            }
            if let Some(error) = reply.get("error") {
                return Err(format!("QMP command {name} failed: {error}"));
            }
            return reply
                .get("return")
                .cloned()
                .ok_or_else(|| "QMP response has no return".into());
        }
        Err("QMP event bound exhausted".into())
    }
    /// Test infrastructure injects a real PS/2 key via the QEMU input device.
    /// Guest Input still reads its own scoped ports and decides what happened.
    #[cfg(test)]
    pub(crate) fn key(&mut self, key: Key) -> Result<()> {
        self.execute(
            "send-key",
            json!({"keys":[{"type":"qcode","data":key.qcode()}],"hold-time":30}),
        )?;
        Ok(())
    }
    /// Pause/resume only this invocation's retained QEMU. Host pixel checking
    /// while stopped consumes no guest ticks; held-key proof still needs the
    /// guest's separately measured running interval. The command is recorded.
    pub(crate) fn set_running(&mut self, running: bool) -> Result<()> {
        let sent = crate::perf_ledger::elapsed_ns(self.origin, Instant::now())
            .map_err(|e| format!("QMP timing: {e:?}"))?;
        if running {
            self.pauses.resume_sent(sent)
        } else {
            self.pauses.stop_sent(sent)
        }
        .map_err(|e| format!("QMP pause order: {e:?}"))?;
        let value = self.execute(if running { "cont" } else { "stop" }, json!({}))?;
        if value != json!({}) {
            return Err("QMP run-state acknowledgement is noncanonical".into());
        }
        let status = self.execute("query-status", json!({}))?;
        if status.get("running").and_then(Value::as_bool) != Some(running)
            || status.get("status").and_then(Value::as_str)
                != Some(if running { "running" } else { "paused" })
        {
            return Err("QMP actual run-state query disagrees with requested transition".into());
        }
        let observed = crate::perf_ledger::elapsed_ns(self.origin, Instant::now())
            .map_err(|e| format!("QMP timing: {e:?}"))?;
        if running {
            self.pauses.running_confirmed(observed)
        } else {
            self.pauses.stopped_confirmed(observed)
        }
        .map_err(|e| format!("QMP observed pause order: {e:?}"))?;
        self.transcript.push(json!({"host_monotonic_ns":{"origin":"caller monotonic origin; spawn bracket retained separately in performance.json","command_sent":sent,"actual_state_observed":observed,"running":running}}));
        Ok(())
    }
    pub(crate) fn timing(
        &self,
        begin: crate::perf_ledger::Bracket,
        end: crate::perf_ledger::Bracket,
    ) -> Result<crate::perf_ledger::Timing> {
        self.pauses
            .measure(begin, end)
            .map_err(|e| format!("QMP complete pause timing: {e:?}"))
    }
    /// Explicit make/break through the real QEMU input device. Unlike a timed
    /// send-key command, a make remains held until an independently recorded
    /// break. This host transport cannot certify guest input freshness/consent.
    pub(crate) fn key_state(&mut self, key: Key, down: bool) -> Result<()> {
        self.execute(
            "input-send-event",
            json!({"events":[{"type":"key","data":{"down":down,"key":{"type":"qcode","data":key.qcode()}}}]}),
        )?;
        Ok(())
    }
    /// Capture actual scanout. Guest-provided pixel buffers are not substituted
    /// for the framebuffer. The bounded filename cannot escape the owned run.
    pub(crate) fn capture(&mut self, index: u32) -> Result<(PathBuf, Ppm)> {
        let path = self.directory.join(format!("screen-{index:03}.ppm"));
        if fs::symlink_metadata(&path).is_ok() {
            return Err("QMP screenshot already exists".into());
        }
        self.execute("screendump", json!({"filename":path}))?;
        let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > FRAME_LIMIT as u64 {
            return Err("QMP screenshot is missing, nonregular or oversized".into());
        }
        let frame = Ppm::parse(fs::read(&path).map_err(|e| e.to_string())?)?;
        Ok((path, frame))
    }
    pub(crate) fn transcript(&self) -> &[Value] {
        &self.transcript
    }
}

/// Exact P6 decoder for QEMU's scanout evidence; no pixel modification/scaling.
pub(crate) struct Ppm {
    width: usize,
    height: usize,
    offset: usize,
    bytes: Vec<u8>,
}
impl Ppm {
    pub(crate) fn parse(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > FRAME_LIMIT {
            return Err("PPM frame exceeds bound".into());
        }
        let mut cursor = 0;
        fn token<'a>(bytes: &'a [u8], cursor: &mut usize) -> Result<&'a [u8]> {
            loop {
                while bytes.get(*cursor).is_some_and(u8::is_ascii_whitespace) {
                    *cursor += 1;
                }
                if bytes.get(*cursor) != Some(&b'#') {
                    break;
                }
                let length = bytes[*cursor..]
                    .iter()
                    .position(|b| *b == b'\n')
                    .ok_or("unterminated PPM comment")?;
                *cursor += length + 1;
            }
            let start = *cursor;
            while bytes.get(*cursor).is_some_and(|b| !b.is_ascii_whitespace()) {
                *cursor += 1;
            }
            if start == *cursor {
                return Err("missing PPM token".into());
            }
            Ok(&bytes[start..*cursor])
        }
        if token(&bytes, &mut cursor)? != b"P6" {
            return Err("PPM requires P6 encoding".into());
        }
        let number = |text: &[u8]| -> Result<usize> {
            if text.is_empty() || text.iter().any(|b| !b.is_ascii_digit()) {
                return Err("invalid PPM integer".into());
            }
            std::str::from_utf8(text)
                .map_err(|e| e.to_string())?
                .parse()
                .map_err(|_| "PPM integer overflow".into())
        };
        let width = number(token(&bytes, &mut cursor)?)?;
        let height = number(token(&bytes, &mut cursor)?)?;
        if !(1..=2048).contains(&width)
            || !(1..=2048).contains(&height)
            || token(&bytes, &mut cursor)? != b"255"
        {
            return Err("unsupported PPM geometry or sample size".into());
        }
        // Exactly one header separator. Skipping arbitrary whitespace here
        // would silently eat valid leading RGB bytes such as 0x0a or 0x20.
        if !bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            return Err("PPM pixel separator missing".into());
        }
        cursor += 1;
        let length = width
            .checked_mul(height)
            .and_then(|v| v.checked_mul(3))
            .ok_or("PPM geometry overflow")?;
        if bytes.len().checked_sub(cursor) != Some(length) {
            return Err("PPM pixel extent differs".into());
        }
        Ok(Self {
            width,
            height,
            offset: cursor,
            bytes,
        })
    }
    pub(crate) fn dimensions(&self) -> (usize, usize) {
        (self.width, self.height)
    }
    pub(crate) fn pixel(&self, x: usize, y: usize) -> Result<[u8; 3]> {
        if x >= self.width || y >= self.height {
            return Err("PPM pixel outside frame".into());
        }
        let at = self.offset + (y * self.width + x) * 3;
        Ok(self.bytes[at..at + 3].try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pair() -> (Qmp, UnixStream) {
        let (client, server) = UnixStream::pair().unwrap();
        (
            Qmp {
                reader: BufReader::new(client),
                next: 1,
                transcript: Vec::new(),
                directory: PathBuf::new(),
                deadline: Instant::now() + Duration::from_secs(2),
                origin: Instant::now(),
                pauses: crate::perf_ledger::Ledger::new(),
            },
            server,
        )
    }
    #[test]
    fn owned_long_evidence_path_connects_without_an_external_socket_alias() {
        use std::os::{fd::AsRawFd, unix::net::UnixListener};
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let parent = crate::storage::directory_beneath(&root, Path::new("build/test-tmp")).unwrap();
        let directory = crate::build::unique_directory(
            &parent,
            "long-private-qmp-directory-which-exceeds-sockaddr-un",
        )
        .unwrap();
        assert!(directory.join("qmp.sock").as_os_str().len() > 108);
        let fd = fs::File::open(&directory).unwrap();
        let listener =
            UnixListener::bind(format!("/proc/self/fd/{}/qmp.sock", fd.as_raw_fd())).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(b"{\"QMP\":{\"version\":{}}}\n").unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(request["execute"], "qmp_capabilities");
            stream.write_all(b"{\"return\":{},\"id\":1}\n").unwrap();
        });
        let qmp = Qmp::connect(&directory, Instant::now() + Duration::from_secs(2)).unwrap();
        assert_eq!(qmp.transcript.len(), 3);
        server.join().unwrap();
    }
    #[test]
    fn command_uses_real_sequence_and_tolerates_bounded_events() {
        assert_eq!(
            [Key::Escape, Key::Up, Key::Down].map(Key::qcode),
            ["esc", "up", "down"]
        );
        let (mut qmp, mut server) = pair();
        let peer = std::thread::spawn(move || {
            let mut line = String::new();
            BufReader::new(server.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(request["execute"], "send-key");
            assert_eq!(request["arguments"]["keys"][0]["data"], "tab");
            server
                .write_all(b"{\"event\":\"DEVICE_DELETED\"}\n{\"return\":{},\"id\":1}\n")
                .unwrap();
        });
        qmp.key(Key::Tab).unwrap();
        peer.join().unwrap();
        assert_eq!(qmp.next, 2);
        assert_eq!(qmp.transcript.len(), 3);
    }
    #[test]
    fn held_enter_has_independent_make_and_break_with_no_automatic_release() {
        let (mut qmp, mut server) = pair();
        let peer = std::thread::spawn(move || {
            let mut reader = BufReader::new(server.try_clone().unwrap());
            for (index, down) in [true, false].into_iter().enumerate() {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let request: Value = serde_json::from_str(&line).unwrap();
                assert_eq!(request["execute"], "input-send-event");
                assert_eq!(
                    request["arguments"],
                    json!({"events":[{"type":"key","data":{"down":down,"key":{"type":"qcode","data":"ret"}}}]})
                );
                assert!(request["arguments"].get("hold-time").is_none());
                server
                    .write_all(format!("{{\"return\":{{}},\"id\":{}}}\n", index + 1).as_bytes())
                    .unwrap();
            }
        });
        qmp.key_state(Key::Enter, true).unwrap();
        qmp.key_state(Key::Enter, false).unwrap();
        peer.join().unwrap();
        assert_eq!(qmp.next, 3);
    }
    #[test]
    fn pause_and_resume_are_explicit_owned_commands_and_do_not_forge_input() {
        let (mut qmp, mut server) = pair();
        let peer = std::thread::spawn(move || {
            let mut reader = BufReader::new(server.try_clone().unwrap());
            for (index, name) in ["stop", "query-status", "cont", "query-status"]
                .into_iter()
                .enumerate()
            {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let request: Value = serde_json::from_str(&line).unwrap();
                assert_eq!(request["execute"], name);
                assert_eq!(request["arguments"], json!({}));
                let value = if name == "query-status" {
                    json!({"running":index==3,"status":if index==3 {"running"}else{"paused"}})
                } else {
                    json!({})
                };
                server
                    .write_all(format!("{}\n", json!({"return":value,"id":index+1})).as_bytes())
                    .unwrap();
            }
        });
        qmp.set_running(false).unwrap();
        qmp.set_running(true).unwrap();
        peer.join().unwrap();
        assert_eq!(qmp.next, 5);
        assert!(
            qmp.timing(
                crate::perf_ledger::Bracket::new(0, 0).unwrap(),
                crate::perf_ledger::Bracket::new(100, 100).unwrap()
            )
            .is_ok()
        );
    }
    #[test]
    fn command_ack_without_observed_paused_state_cannot_authorize_capture_timing() {
        let (mut qmp, mut server) = pair();
        server.write_all(b"{\"return\":{},\"id\":1}\n{\"return\":{\"running\":true,\"status\":\"running\"},\"id\":2}\n").unwrap();
        assert!(
            qmp.set_running(false)
                .unwrap_err()
                .contains("actual run-state")
        );
        assert!(
            qmp.timing(
                crate::perf_ledger::Bracket::new(0, 0).unwrap(),
                crate::perf_ledger::Bracket::new(100, 100).unwrap()
            )
            .is_err()
        );
    }
    #[test]
    fn wrong_response_id_and_disconnection_cannot_acknowledge_a_key() {
        for wrong in [
            b"{\"return\":{},\"id\":2}\n".as_slice(),
            b"{\"error\":{\"class\":\"BadCommand\"},\"id\":1}\n",
            b"",
        ] {
            let (mut qmp, mut server) = pair();
            server.write_all(wrong).unwrap();
            server.shutdown(std::net::Shutdown::Write).unwrap();
            assert!(qmp.key(Key::Enter).is_err());
        }
    }
    #[test]
    fn exhausted_absolute_deadline_rejects_without_an_extendable_read() {
        let (mut qmp, _server) = pair();
        assert!(qmp.read(Instant::now() - Duration::from_millis(1)).is_err());
    }
    #[test]
    fn ppm_preserves_whitespace_valued_first_pixel_and_rejects_trailing_bytes() {
        let mut bytes = b"P6\n# actual RGB evidence\n1 1\n255\n".to_vec();
        bytes.extend([10, 32, 13]);
        let frame = Ppm::parse(bytes.clone()).unwrap();
        assert_eq!(frame.dimensions(), (1, 1));
        assert_eq!(frame.pixel(0, 0).unwrap(), [10, 32, 13]);
        assert!(frame.pixel(1, 0).is_err());
        bytes.push(0);
        assert!(Ppm::parse(bytes).is_err());
    }
    #[test]
    fn ppm_rejects_overflow_and_non_eight_bit_scanout() {
        for bad in [
            b"P6\n99999999999999999999999999 1\n255\n".as_slice(),
            b"P6\n1 1\n256\nabc",
            b"P6\n0 1\n255\n",
            b"P3\n1 1\n255\nabc",
            b"P6\n1 1\n255\nab",
        ] {
            assert!(Ppm::parse(bad.to_vec()).is_err());
        }
    }
}
