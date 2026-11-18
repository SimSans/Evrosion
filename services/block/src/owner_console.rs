//! Bounded owner UART. It produces a choice from actual RX bytes only;
//! the caller alone invokes SelectKnownGood after Continue. No storage calls,
//! implicit approval, UART EOF inference or hardware acceptance is claimed here.
use core::fmt::{self, Write};
use ev_store::{GenerationId, LastFailure, LastFailureReason};
use ev_userspace_contract::generation::OwnerDecision;
use ev_userspace_runtime::{self as rt, syscall};
const DATA: u16 = 0x3f8;
const LSR: u16 = 0x3fd;
pub const OWNER_WORLD_TICKS: u64 = 65_536;
pub const OWNER_PARENT_CPU: u64 = 131_072;
pub const MAX_PROMPT_TICKS: u64 = 60_000;
pub const ACTION_RESERVE: u64 = 2048;
const POLLS: u32 = 1_000_000;
const BYTES: u32 = 128;

pub trait Io {
    fn input(&mut self, port: u16) -> Result<u8, u64>;
    fn output(&mut self, port: u16, byte: u8) -> Result<(), u64>;
    fn now(&mut self) -> Result<u64, u64>;
    fn yield_now(&mut self) -> Result<(), u64>;
}
pub struct KernelIo {
    pub capability: u64,
}
impl Io for KernelIo {
    fn input(&mut self, port: u16) -> Result<u8, u64> {
        let reply = rt::call4(syscall::PORT_INPUT, self.capability, u64::from(port), 1, 0);
        if reply.status != 0 {
            return Err(reply.status);
        }
        if reply.capability != 0 || reply.serial != 0 {
            return Err(u64::MAX);
        }
        u8::try_from(reply.value).map_err(|_| u64::MAX)
    }
    fn output(&mut self, port: u16, byte: u8) -> Result<(), u64> {
        let reply = rt::call4(
            syscall::PORT_OUTPUT,
            self.capability,
            u64::from(port),
            1,
            u64::from(byte),
        );
        if reply.status != 0 {
            return Err(reply.status);
        }
        if reply.value != 0 || reply.capability != 0 || reply.serial != 0 {
            return Err(u64::MAX);
        }
        Ok(())
    }
    fn now(&mut self) -> Result<u64, u64> {
        let reply = rt::monotonic();
        if reply.status != 0 {
            Err(reply.status)
        } else if reply.capability != 0 {
            Err(u64::MAX)
        } else {
            Ok(reply.value)
        }
    }
    fn yield_now(&mut self) -> Result<(), u64> {
        let reply = rt::yield_now();
        if reply.status != 0 {
            Err(reply.status)
        } else if reply.value != 0 || reply.capability != 0 {
            Err(u64::MAX)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Io(u64),
    ClockReversed,
    Deadline,
    PollBudget,
    Format,
    Policy,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub decision: OwnerDecision,
    pub source_byte: Option<u8>,
    pub received: u32,
    pub invalid_lines: u32,
    pub armed: u64,
    pub deadline: u64,
}
pub struct Prompt<'a> {
    pub failed: &'a LastFailure,
    pub selected: GenerationId,
    pub known_good: GenerationId,
    pub build: [u8; 32],
    pub catalogue: [u8; 32],
    pub operation: u64,
    pub prompt_ticks: u64,
    pub world_stop: u64,
}
pub struct Console<P> {
    io: P,
    polls: u32,
    last: Option<u64>,
    deadline: u64,
    write_error: Option<Error>,
}
impl<P: Io> Console<P> {
    pub fn new(io: P) -> Self {
        Self {
            io,
            polls: POLLS,
            last: None,
            deadline: 0,
            write_error: None,
        }
    }
    pub fn into_io(self) -> P {
        self.io
    }
    fn tick(&mut self) -> Result<u64, Error> {
        if self.polls == 0 {
            return Err(Error::PollBudget);
        }
        self.polls -= 1;
        let now = self.io.now().map_err(Error::Io)?;
        if self.last.is_some_and(|old| now < old) {
            return Err(Error::ClockReversed);
        }
        self.last = Some(now);
        if now >= self.deadline {
            return Err(Error::Deadline);
        }
        Ok(now)
    }
    fn byte(&mut self, byte: u8) -> Result<(), Error> {
        loop {
            self.tick()?;
            let status = self.io.input(LSR).map_err(Error::Io)?;
            if status & 0x20 != 0 {
                return self.io.output(DATA, byte).map_err(Error::Io);
            }
            self.io.yield_now().map_err(Error::Io)?;
        }
    }
    fn format(&mut self, args: fmt::Arguments<'_>) -> Result<(), Error> {
        fmt::write(self, args).map_err(|_| self.write_error.take().unwrap_or(Error::Format))
    }
    fn hex(&mut self, digest: &[u8; 32]) -> Result<(), Error> {
        for byte in digest {
            self.format(format_args!("{byte:02x}"))?;
        }
        Ok(())
    }
    /// Print trusted typed failure metadata, discard bytes predating the prompt,
    /// then accept a whole r/q line. Invalid lines never approve or reset time.
    /// UART has no EOF signal: host EOF must abort/reap its own waiting VM.
    pub fn choose(&mut self, prompt: Prompt<'_>) -> Result<Outcome, Error> {
        if prompt.prompt_ticks == 0 || prompt.prompt_ticks > MAX_PROMPT_TICKS {
            return Err(Error::Policy);
        }
        let latest = prompt
            .world_stop
            .checked_sub(ACTION_RESERVE)
            .ok_or(Error::Policy)?;
        self.deadline = latest;
        // Bounded stale-input drain before publishing a fresh prompt epoch.
        let mut received = 0;
        for _ in 0..BYTES {
            self.tick()?;
            if self.io.input(LSR).map_err(Error::Io)? & 1 == 0 {
                break;
            }
            self.io.input(DATA).map_err(Error::Io)?;
            received += 1;
        }
        // Stale bytes also consume the one total RX budget; never accept a
        // leftover old command or attempt a 129th hardware DATA read.
        if received == BYTES {
            return Err(Error::PollBudget);
        }
        let reason = match prompt.failed.reason {
            LastFailureReason::ProcessFault => "a process fault",
            LastFailureReason::MissingProgress => "missing progress",
            LastFailureReason::StorageFailure => "a storage failure",
            LastFailureReason::AttemptBudgetExhausted => "its boot attempt limit",
            LastFailureReason::CriticalComponentFault => "an actual critical component fault",
        };
        self.format(format_args!(
            "\r\nEvrosion generation {} could not start: {}.\r\nFailed image: ",
            prompt.failed.generation.get(),
            reason
        ))?;
        self.hex(&prompt.failed.supervisor_image)?;
        self.format(format_args!("\r\nCurrent selection: generation {} (pending validation).\r\nKnown-good generation {} is available. Returning keeps your files.\r\nType r then Enter to continue with known-good, or q then Enter to cancel.\r\n",prompt.selected.get(),prompt.known_good.get()))?;
        let armed = self.tick()?;
        let deadline = armed
            .checked_add(prompt.prompt_ticks)
            .filter(|d| *d <= latest)
            .ok_or(Error::Policy)?;
        // Interactive frontend hides this diagnostic line but retains raw TX.
        self.format(format_args!("EVROSION_M3_OWNER_PROMPT protocol=1 build="))?;
        self.hex(&prompt.build)?;
        self.format(format_args!(" catalogue="))?;
        self.hex(&prompt.catalogue)?;
        self.format(format_args!(" operation={} selected={} known_good={} failure_generation={} failure_serial={} deadline={} actions=r,q\n",prompt.operation,prompt.selected.get(),prompt.known_good.get(),prompt.failed.generation.get(),prompt.failed.boot_serial,deadline))?;
        self.deadline = deadline;
        let mut invalid_lines = 0;
        let mut command = None;
        let mut invalid = false;
        loop {
            if received == BYTES {
                return Ok(Outcome {
                    decision: OwnerDecision::InputBudget,
                    source_byte: None,
                    received,
                    invalid_lines,
                    armed,
                    deadline,
                });
            }
            match self.tick() {
                Ok(_) => (),
                Err(Error::Deadline) => {
                    return Ok(Outcome {
                        decision: OwnerDecision::Timeout,
                        source_byte: None,
                        received,
                        invalid_lines,
                        armed,
                        deadline,
                    });
                }
                Err(e) => return Err(e),
            }
            if self.io.input(LSR).map_err(Error::Io)? & 1 == 0 {
                self.io.yield_now().map_err(Error::Io)?;
                continue;
            }
            let byte = self.io.input(DATA).map_err(Error::Io)?;
            received += 1;
            if matches!(byte, b'\r' | b'\n') {
                if !invalid && let Some(choice) = command {
                    return Ok(Outcome {
                        decision: if matches!(choice, b'r' | b'R') {
                            OwnerDecision::Continue
                        } else {
                            OwnerDecision::Cancel
                        },
                        source_byte: Some(choice),
                        received,
                        invalid_lines,
                        armed,
                        deadline,
                    });
                }
                if invalid || command.is_some() {
                    invalid_lines += 1;
                    self.format(format_args!("Please type r or q, then Enter.\r\n"))?;
                }
                command = None;
                invalid = false;
                continue;
            }
            if matches!(byte, b' ' | b'\t') && command.is_none() && !invalid {
                continue;
            }
            if command.is_none() && !invalid && matches!(byte, b'r' | b'R' | b'q' | b'Q') {
                command = Some(byte);
            } else {
                invalid = true;
            }
        }
    }
}
impl<P: Io> Write for Console<P> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for byte in text.bytes() {
            if let Err(error) = self.byte(byte) {
                self.write_error = Some(error);
                return Err(fmt::Error);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{collections::VecDeque, vec::Vec};
    struct Model {
        out: Vec<u8>,
        rx: VecDeque<u8>,
        stale: VecDeque<u8>,
        armed: bool,
        now: u64,
        reverse: bool,
    }
    impl Io for Model {
        fn input(&mut self, port: u16) -> Result<u8, u64> {
            match port {
                LSR => Ok(0x20
                    | u8::from(if self.armed {
                        !self.rx.is_empty()
                    } else {
                        !self.stale.is_empty()
                    })),
                DATA => Ok(if self.armed {
                    self.rx.pop_front()
                } else {
                    self.stale.pop_front()
                }
                .unwrap()),
                _ => Err(1),
            }
        }
        fn output(&mut self, port: u16, byte: u8) -> Result<(), u64> {
            assert_eq!(port, DATA);
            self.out.push(byte);
            if byte == b'\n'
                && self
                    .out
                    .windows(b"EVROSION_M3_OWNER_PROMPT ".len())
                    .any(|w| w == b"EVROSION_M3_OWNER_PROMPT ")
            {
                self.armed = true;
            }
            Ok(())
        }
        fn now(&mut self) -> Result<u64, u64> {
            if self.reverse && self.now > 2 {
                self.now = 1;
            }
            Ok(self.now)
        }
        fn yield_now(&mut self) -> Result<(), u64> {
            self.now += 1;
            Ok(())
        }
    }
    fn model(bytes: &[u8]) -> Model {
        Model {
            out: Vec::new(),
            rx: bytes.iter().copied().collect(),
            stale: VecDeque::new(),
            armed: false,
            now: 10,
            reverse: false,
        }
    }
    fn failure() -> LastFailure {
        LastFailure {
            generation: GenerationId::new(2).unwrap(),
            boot_serial: 2,
            attempts: 1,
            reason: LastFailureReason::ProcessFault,
            evidence: None,
            supervisor_image: [2; 32],
            process_stamp: Some([3; 32]),
            operation: ev_store::OperationId::new(10).unwrap(),
            sequence: 11,
        }
    }
    fn run(model: Model) -> (Result<Outcome, Error>, Model) {
        let mut console = Console::new(model);
        let failed = failure();
        let result = console.choose(Prompt {
            failed: &failed,
            selected: GenerationId::new(3).unwrap(),
            known_good: GenerationId::new(1).unwrap(),
            build: [1; 32],
            catalogue: [4; 32],
            operation: 16,
            prompt_ticks: 20,
            world_stop: OWNER_WORLD_TICKS,
        });
        (result, console.into_io())
    }
    #[test]
    fn actual_lines_choose_continue_or_cancel_only_after_prompt() {
        for (bytes, choice) in [
            (b"r\n".as_slice(), OwnerDecision::Continue),
            (b"Q\r".as_slice(), OwnerDecision::Cancel),
        ] {
            let (result, model) = run(model(bytes));
            assert_eq!(result.unwrap().decision, choice);
            assert!(model.armed);
            assert!(
                model
                    .out
                    .windows(b"EVROSION_M3_OWNER_PROMPT ".len())
                    .any(|w| w == b"EVROSION_M3_OWNER_PROMPT ")
            );
        }
    }
    #[test]
    fn stale_or_invalid_input_never_approves_and_does_not_extend_deadline() {
        let mut io = model(b"noise r\n");
        io.stale = b"r\n".iter().copied().collect();
        let (result, _) = run(io);
        let result = result.unwrap();
        assert_eq!(result.decision, OwnerDecision::Timeout);
        assert_eq!(result.source_byte, None);
        assert_eq!(result.deadline - result.armed, 20);
        assert_eq!(result.invalid_lines, 1);
    }
    #[test]
    fn invalid_line_can_be_followed_by_a_new_explicit_choice() {
        let (result, _) = run(model(b"rubbish\nr\n"));
        let result = result.unwrap();
        assert_eq!(result.decision, OwnerDecision::Continue);
        assert_eq!(result.invalid_lines, 1);
    }
    #[test]
    fn silence_is_timeout_and_no_hardware_eof_is_invented() {
        let (result, _) = run(model(b""));
        assert_eq!(result.unwrap().decision, OwnerDecision::Timeout);
    }
    #[test]
    fn clock_reversal_is_an_error_not_a_choice() {
        let mut io = model(b"");
        io.reverse = true;
        let (result, _) = run(io);
        assert!(result.is_err());
    }
    #[test]
    fn total_rx_limit_stops_before_the_129th_hardware_read() {
        let bytes = std::vec![b'x';129];
        let (result, after) = run(model(&bytes));
        let outcome = result.unwrap();
        assert_eq!(outcome.decision, OwnerDecision::InputBudget);
        assert_eq!(outcome.received, 128);
        assert_eq!(after.rx.len(), 1);
        let mut io = model(b"r\n");
        io.stale = std::vec![b'x';128].into_iter().collect();
        let (result, model) = run(io);
        assert_eq!(result, Err(Error::PollBudget));
        assert!(!model.armed);
        assert_eq!(model.rx.len(), 2);
    }
}
