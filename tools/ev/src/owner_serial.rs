//! Bounded input for one owned guest console. No reader owns a guest or disk.
use std::{
    io::{Read, Write},
    process::Child,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, TryRecvError},
    },
    thread::JoinHandle,
    time::Instant,
};

const BYTES: usize = 128;

#[derive(Clone, Copy)]
pub(crate) enum Input {
    /// Explicit test action, submitted only after the validated guest prompt.
    Script(&'static [u8]),
    Silent,
    Eof,
    Owner,
}

enum Event {
    Byte(u8),
    Eof,
    Exhausted,
    Error(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Poll {
    Continue,
    EofNoAction,
}

/// Exactly the guest grammar: leading SP/TAB, one r/q (any case), then CR/LF.
/// Trailing whitespace and control/escape sequences never become consent.
fn decision_line(bytes: &[u8]) -> bool {
    let leading = bytes
        .iter()
        .take_while(|byte| matches!(byte, b' ' | b'\t'))
        .count();
    matches!(&bytes[leading..], b"r" | b"R" | b"q" | b"Q")
}

pub(crate) struct Console {
    input: Input,
    armed: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    decision_submitted: bool,
    exhausted: bool,
    line: Vec<u8>,
    started: Instant,
    receiver: Option<Receiver<Event>>,
    reader: Option<JoinHandle<()>>,
    /// Actual bytes successfully written to this owned child's stdin.
    pub(crate) written: Vec<(u128, u8)>,
}

impl Console {
    pub(crate) fn new(input: Input) -> Result<Self, String> {
        let mut result = Self::empty(input);
        if matches!(input, Input::Owner) {
            // Start before spawning the VM. Consume and discard pre-prompt
            // input instead of forwarding a line buffered before the question.
            result.start_reader(std::io::stdin())?;
        }
        Ok(result)
    }

    fn empty(input: Input) -> Self {
        Self {
            input,
            armed: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(AtomicBool::new(false)),
            decision_submitted: false,
            exhausted: false,
            line: Vec::with_capacity(BYTES),
            started: Instant::now(),
            receiver: None,
            reader: None,
            written: Vec::new(),
        }
    }

    fn start_reader<R: Read + Send + 'static>(&mut self, mut input: R) -> Result<(), String> {
        let armed = Arc::clone(&self.armed);
        let stop = Arc::clone(&self.stop);
        let (sender, receiver) = mpsc::sync_channel(16);
        self.reader = Some(
            std::thread::Builder::new()
                .name("owner-console-input".into())
                .spawn(move || {
                    let mut read = 0;
                    let mut stale_line = false;
                    let mut line = Vec::with_capacity(BYTES);
                    while read < BYTES && !stop.load(Ordering::Acquire) {
                        let mut byte = [0];
                        let event = match input.read(&mut byte) {
                            Ok(0) => Event::Eof,
                            Ok(_) => {
                                read += 1;
                                Event::Byte(byte[0])
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                                continue;
                            }
                            Err(error) => Event::Error(error.to_string()),
                        };
                        let Event::Byte(byte) = event else {
                            let _ = sender.send(event);
                            return;
                        };
                        let ended = matches!(byte, b'\r' | b'\n');
                        if !armed.load(Ordering::Acquire) {
                            // A partial line begun before the prompt remains
                            // stale through its terminator, even if arming races.
                            stale_line = !ended;
                            continue;
                        }
                        if stale_line {
                            stale_line = !ended;
                            continue;
                        }
                        if sender.send(Event::Byte(byte)).is_err() {
                            return;
                        }
                        if ended {
                            if decision_line(&line) {
                                return;
                            }
                            line.clear();
                        } else {
                            line.push(byte);
                        }
                    }
                    // The guest has its own RX/clock limit. Do not preempt its
                    // graceful InputBudget after delivering the 128th byte.
                    let _ = sender.send(Event::Exhausted);
                })
                .map_err(|error| format!("cannot read owner input: {error}"))?,
        );
        self.receiver = Some(receiver);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn with_reader<R: Read + Send + 'static>(input: R) -> Result<Self, String> {
        let mut result = Self::empty(Input::Owner);
        result.start_reader(input)?;
        Ok(result)
    }

    #[cfg(test)]
    pub(crate) fn armed_for_test(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.armed)
    }

    fn write(&mut self, child: &mut Child, byte: u8) -> Result<(), String> {
        if self.written.len() == BYTES {
            return Err("owner input exceeded128 bytes; no further action submitted".into());
        }
        // One writer, at most128 bytes to a fresh child pipe (below pipe
        // capacity), so no unbounded stream or pipe-capacity wait is possible.
        child
            .stdin
            .as_mut()
            .ok_or("owned serial child has no input pipe")?
            .write_all(&[byte])
            .map_err(|error| format!("cannot submit owner input: {error}"))?;
        self.written
            .push((self.started.elapsed().as_millis(), byte));
        if matches!(byte, b'\r' | b'\n') {
            self.decision_submitted = decision_line(&self.line);
            self.line.clear();
        } else {
            self.line.push(byte);
        }
        Ok(())
    }

    pub(crate) fn poll(&mut self, child: &mut Child, prompt: bool) -> Result<Poll, String> {
        if self.decision_submitted || self.exhausted {
            return Ok(Poll::Continue);
        }
        if prompt && !self.armed.swap(true, Ordering::AcqRel) {
            match self.input {
                Input::Script(bytes) => {
                    for byte in bytes {
                        self.write(child, *byte)?;
                        if self.decision_submitted {
                            return Ok(Poll::Continue);
                        }
                    }
                    self.exhausted = bytes.len() == BYTES;
                }
                Input::Eof => return Ok(Poll::EofNoAction),
                Input::Silent | Input::Owner => (),
            }
        }
        for _ in 0..16 {
            let event = match self.receiver.as_ref().map(Receiver::try_recv) {
                None | Some(Err(TryRecvError::Empty)) => return Ok(Poll::Continue),
                Some(Err(TryRecvError::Disconnected)) => return Ok(Poll::EofNoAction),
                Some(Ok(event)) => event,
            };
            match event {
                Event::Byte(byte) => {
                    if !self.armed.load(Ordering::Acquire) {
                        return Err("owner input arrived before the validated prompt".into());
                    }
                    self.write(child, byte)?;
                    if self.decision_submitted {
                        return Ok(Poll::Continue);
                    }
                }
                Event::Eof => return Ok(Poll::EofNoAction),
                Event::Exhausted => {
                    self.exhausted = true;
                    return Ok(Poll::Continue);
                }
                Event::Error(error) => return Err(format!("owner input failed: {error}")),
            }
        }
        Ok(Poll::Continue)
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // Safe std cannot cancel a blocking terminal read. Never join it while
        // blocked: it has no child/disk/output owner, and this interactive
        // frontend is one short-lived process. Process exit ends the reader.
        if self.reader.as_ref().is_some_and(JoinHandle::is_finished) {
            let _ = self.reader.take().unwrap().join();
        }
    }
}
