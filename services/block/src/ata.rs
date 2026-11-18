//! ATA protocol lives entirely in userspace. This closed reference profile uses
//! one master on the dedicated non-DMA QEMU ISA channel, LBA28, 512-byte sectors
//! and one sector per command. No automatic replay follows an ambiguous failure.
use crate::{CONTROL_PORT, DISK_SECTORS, PORT_BASE, SECTOR_BYTES, SERIAL};

#[cfg(feature = "native-session")]
mod session;
#[cfg(feature = "native-session")]
pub use session::{Quarantine, SessionDisk, SessionOutcome, SessionWindow};

const DATA: u16 = PORT_BASE;
const ERROR: u16 = PORT_BASE + 1;
const COUNT: u16 = PORT_BASE + 2;
const LOW: u16 = PORT_BASE + 3;
const MID: u16 = PORT_BASE + 4;
const HIGH: u16 = PORT_BASE + 5;
const SELECT: u16 = PORT_BASE + 6;
const COMMAND: u16 = PORT_BASE + 7;
const BUSY: u8 = 0x80;
const READY: u8 = 0x40;
const FAULT: u8 = 0x20;
const DRQ: u8 = 0x08;
const ERR: u8 = 0x01;
const IDENTIFY: u8 = 0xec;
const READ: u8 = 0x20;
const WRITE: u8 = 0x30;
const FLUSH: u8 = 0xe7;
const POLLS: u32 = 8192;

/// Actual mediated scalar operations. A test implementation may model device
/// state; it never establishes hardware acceptance. Production methods carry
/// no user pointer, caller identity, range policy or caller-ready boolean.
pub trait Ports {
    fn input(&mut self, port: u16, width: u8) -> Result<u32, u64>;
    fn output(&mut self, port: u16, width: u8, value: u32) -> Result<(), u64>;
    fn now(&mut self) -> Result<u64, u64>;
    fn yield_now(&mut self) -> Result<(), u64>;
    /// Selected workspace profile only. The native adapter negotiates the
    /// fixed trap and supplies its own private byte buffer. Model defaults
    /// preserve input publication until all256 modeled words complete.
    #[cfg(feature = "pio-words256")]
    fn input_words256(
        &mut self,
        port: u16,
        _deadline: u64,
        bytes: &mut [u8; 512],
    ) -> Result<(), u64> {
        let mut scratch = [0; 512];
        for pair in scratch.as_chunks_mut::<2>().0 {
            pair.copy_from_slice(
                &u16::try_from(self.input(port, 2)?)
                    .map_err(|_| u64::MAX)?
                    .to_le_bytes(),
            );
        }
        *bytes = scratch;
        Ok(())
    }
    #[cfg(feature = "pio-words256")]
    fn output_words256(&mut self, port: u16, _deadline: u64, bytes: &[u8; 512]) -> Result<(), u64> {
        for pair in bytes.as_chunks::<2>().0 {
            self.output(port, 2, u32::from(u16::from_le_bytes(*pair)))?;
        }
        Ok(())
    }
    /// Fixed four Word operations. Production batch adapters negotiate and
    /// use one bounded Kernel trap; the default keeps model/scalar adapters
    /// usable and may fail after a prefix, which is always uncertain progress.
    #[cfg(feature = "pio-word4")]
    fn input_words4(&mut self, port: u16, _deadline: u64) -> Result<u64, u64> {
        let mut packed = 0;
        for word in 0..4 {
            let value = u16::try_from(self.input(port, 2)?).map_err(|_| u64::MAX)?;
            packed |= u64::from(value) << (word * 16);
        }
        Ok(packed)
    }
    #[cfg(feature = "pio-word4")]
    fn output_words4(&mut self, port: u16, value: u64, _deadline: u64) -> Result<(), u64> {
        for word in 0..4 {
            self.output(port, 2, u32::from((value >> (word * 16)) as u16))?;
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Io(u64),
    Deadline,
    ClockReversed,
    PollBudget,
    NoDevice,
    Device { status: u8, error: u8 },
    Protocol,
    Identity,
    Geometry,
    Unsupported,
    Bounds,
    NotIdentified,
    NeedsReset,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    NotIssued,
    MayHaveExecuted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Failure {
    pub error: Error,
    pub progress: Progress,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub sectors: u32,
    pub sector_bytes: u16,
}
#[derive(Clone, Copy)]
enum State {
    Unidentified,
    Ready(Info),
    NeedsReset,
}
struct Budget {
    deadline: u64,
    last: u64,
    polls: u32,
}
impl Budget {
    fn new<P: Ports>(io: &mut P, deadline: u64) -> Result<Self, Error> {
        let now = io.now().map_err(Error::Io)?;
        if deadline <= now {
            return Err(Error::Deadline);
        }
        Ok(Self {
            deadline,
            last: now,
            polls: POLLS,
        })
    }
    fn step<P: Ports>(&mut self, io: &mut P) -> Result<u64, Error> {
        self.step_units(io, 1)
    }
    fn step_units<P: Ports>(&mut self, io: &mut P, units: u32) -> Result<u64, Error> {
        if self.polls < units {
            return Err(Error::PollBudget);
        }
        self.polls -= units;
        let now = io.now().map_err(Error::Io)?;
        if now < self.last {
            return Err(Error::ClockReversed);
        }
        self.last = now;
        if now >= self.deadline {
            return Err(Error::Deadline);
        }
        Ok(now)
    }
    /// Each new fixed four-instruction trap gets its own bounded authorization
    /// cut. This neither changes the retained ATA/RPC deadline nor retries an
    /// accepted trap. Reserve the same four scalar poll units before any PIO.
    #[cfg(feature = "pio-word4")]
    fn words4_cut<P: Ports>(&mut self, io: &mut P) -> Result<u64, Error> {
        let now = self.step_units(io, 4)?;
        let cut = now
            .checked_add(ev_userspace_contract::syscall::PORT_BATCH_MAX_TICKS)
            .filter(|&cut| cut != u64::MAX)
            .ok_or(Error::Deadline)?;
        Ok(self.deadline.min(cut))
    }
    #[cfg(feature = "pio-words256")]
    fn words256_cut<P: Ports>(&mut self, io: &mut P) -> Result<u64, Error> {
        let now = self.step_units(io, 256)?;
        let cut = now
            .checked_add(ev_userspace_contract::syscall::PORT_WORDS256_MAX_TICKS)
            .filter(|&cut| cut != u64::MAX)
            .ok_or(Error::Deadline)?;
        Ok(self.deadline.min(cut))
    }
}
pub struct AtaPio<P, const PROFILE: u8 = 0> {
    io: P,
    state: State,
}
impl<P: Ports> AtaPio<P> {
    pub fn new(io: P) -> Self {
        Self {
            io,
            state: State::Unidentified,
        }
    }
    /// Explicitly compiled profile1 device identity. The original constructor
    /// and parser still require the exact4MiB legacy device. Const selection
    /// adds no mutable policy flag to an existing physical driver owner.
    #[cfg(feature = "workspace-storage")]
    pub fn new_workspace(io: P) -> AtaPio<P, 1> {
        AtaPio {
            io,
            state: State::Unidentified,
        }
    }
}
impl<P: Ports, const PROFILE: u8> AtaPio<P, PROFILE> {
    pub fn into_ports(self) -> P {
        self.io
    }
    fn before(error: Error) -> Failure {
        Failure {
            error,
            progress: Progress::NotIssued,
        }
    }
    fn finish<T>(&mut self, result: Result<T, Error>, issued: bool) -> Result<T, Failure> {
        result.map_err(|error| {
            self.state = State::NeedsReset;
            Failure {
                error,
                progress: if issued {
                    Progress::MayHaveExecuted
                } else {
                    Progress::NotIssued
                },
            }
        })
    }
    fn info(&self) -> Result<Info, Failure> {
        match self.state {
            State::Ready(info) => Ok(info),
            State::Unidentified => Err(Self::before(Error::NotIdentified)),
            State::NeedsReset => Err(Self::before(Error::NeedsReset)),
        }
    }
    fn byte(&mut self, port: u16) -> Result<u8, Error> {
        let value = self.io.input(port, 1).map_err(Error::Io)?;
        u8::try_from(value).map_err(|_| Error::Protocol)
    }
    fn out(&mut self, port: u16, value: u8) -> Result<(), Error> {
        self.io.output(port, 1, u32::from(value)).map_err(Error::Io)
    }
    fn settle(&mut self, budget: &mut Budget) -> Result<(), Error> {
        // Four alternate-status transactions meet the taskfile selection delay;
        // mediated syscalls add further delay. Alternate status does not ack IRQ.
        for _ in 0..4 {
            budget.step(&mut self.io)?;
            self.byte(CONTROL_PORT)?;
        }
        Ok(())
    }
    fn wait(&mut self, budget: &mut Budget, data: bool) -> Result<(), Error> {
        loop {
            budget.step(&mut self.io)?;
            let status = self.byte(CONTROL_PORT)?;
            if matches!(status, 0 | 0xff) {
                return Err(Error::NoDevice);
            }
            if status & BUSY == 0 {
                if status & (ERR | FAULT) != 0 {
                    let error = if status & ERR != 0 {
                        self.byte(ERROR)?
                    } else {
                        0
                    };
                    return Err(Error::Device { status, error });
                }
                if status & READY != 0 && (status & DRQ != 0) == data {
                    return Ok(());
                }
            }
            self.io.yield_now().map_err(Error::Io)?;
        }
    }
    fn select(&mut self, budget: &mut Budget, device: u8) -> Result<(), Error> {
        self.wait(budget, false)?;
        self.out(SELECT, device)?;
        self.settle(budget)?;
        self.wait(budget, false)
    }
    /// Explicit reset invalidates identification. It is never an automatic
    /// write retry or proof that an earlier accepted operation had no effect.
    pub fn reset(&mut self, deadline: u64) -> Result<(), Failure> {
        let mut budget = Budget::new(&mut self.io, deadline).map_err(Self::before)?;
        self.state = State::Unidentified;
        let result = (|| {
            self.out(CONTROL_PORT, 0x06)?; // nIEN plus software reset.
            let until = budget.last.checked_add(1).ok_or(Error::Deadline)?;
            while budget.step(&mut self.io)? < until {
                self.io.yield_now().map_err(Error::Io)?;
            }
            self.out(CONTROL_PORT, 0x02)?;
            self.settle(&mut budget)?;
            self.wait(&mut budget, false)
        })();
        self.finish(result, true)
    }
    pub fn identify(&mut self, deadline: u64) -> Result<Info, Failure> {
        if matches!(self.state, State::NeedsReset) {
            return Err(Self::before(Error::NeedsReset));
        }
        let mut budget = Budget::new(&mut self.io, deadline).map_err(Self::before)?;
        let mut issued = false;
        let result = (|| {
            self.out(CONTROL_PORT, 0x02)?; // All progress is polled, IRQ disabled.
            self.select(&mut budget, 0xa0)?;
            for port in [COUNT, LOW, MID, HIGH] {
                self.out(port, 0)?;
            }
            issued = true;
            self.out(COMMAND, IDENTIFY)?;
            self.settle(&mut budget)?;
            self.wait(&mut budget, true)?;
            if self.byte(MID)? != 0 || self.byte(HIGH)? != 0 {
                return Err(Error::Unsupported);
            }
            let mut bytes = [0u8; SECTOR_BYTES];
            self.read_data(&mut budget, &mut bytes)?;
            self.wait(&mut budget, false)?;
            if PROFILE == 0 {
                parse_identify(&bytes)
            } else {
                #[cfg(feature = "workspace-storage")]
                if PROFILE == 1 {
                    return parse_workspace_identify(&bytes);
                }
                Err(Error::Unsupported)
            }
        })();
        let info = self.finish(result, issued)?;
        self.state = State::Ready(info);
        Ok(info)
    }
    fn taskfile(&mut self, budget: &mut Budget, lba: u32) -> Result<(), Error> {
        self.select(budget, 0xe0 | ((lba >> 24) as u8 & 0x0f))?;
        self.out(COUNT, 1)?; // Zero would mean256; this profile never emits it.
        self.out(LOW, lba as u8)?;
        self.out(MID, (lba >> 8) as u8)?;
        self.out(HIGH, (lba >> 16) as u8)
    }
    fn read_data(
        &mut self,
        budget: &mut Budget,
        bytes: &mut [u8; SECTOR_BYTES],
    ) -> Result<(), Error> {
        #[cfg(feature = "pio-words256")]
        if PROFILE == 1 {
            let cut = budget.words256_cut(&mut self.io)?;
            return self.io.input_words256(DATA, cut, bytes).map_err(Error::Io);
        }
        #[cfg(feature = "pio-word4")]
        for group in bytes.as_chunks_mut::<8>().0 {
            let cut = budget.words4_cut(&mut self.io)?;
            let value = self.io.input_words4(DATA, cut).map_err(Error::Io)?;
            group.copy_from_slice(&value.to_le_bytes());
        }
        #[cfg(not(feature = "pio-word4"))]
        for pair in bytes.as_chunks_mut::<2>().0 {
            budget.step(&mut self.io)?;
            let word = self.io.input(DATA, 2).map_err(Error::Io)?;
            let word = u16::try_from(word)
                .map_err(|_| Error::Protocol)?
                .to_le_bytes();
            pair.copy_from_slice(&word);
        }
        Ok(())
    }
    pub fn read_sector(
        &mut self,
        lba: u32,
        bytes: &mut [u8; SECTOR_BYTES],
        deadline: u64,
    ) -> Result<(), Failure> {
        if lba >= self.info()?.sectors || lba >= 1 << 28 {
            return Err(Self::before(Error::Bounds));
        }
        let mut budget = Budget::new(&mut self.io, deadline).map_err(Self::before)?;
        let mut issued = false;
        let result = (|| {
            self.taskfile(&mut budget, lba)?;
            issued = true;
            self.out(COMMAND, READ)?;
            self.settle(&mut budget)?;
            self.wait(&mut budget, true)?;
            self.read_data(&mut budget, bytes)?;
            self.wait(&mut budget, false)
        })();
        self.finish(result, issued)
    }
    pub fn write_sector(
        &mut self,
        lba: u32,
        bytes: &[u8; SECTOR_BYTES],
        deadline: u64,
    ) -> Result<(), Failure> {
        if lba >= self.info()?.sectors || lba >= 1 << 28 {
            return Err(Self::before(Error::Bounds));
        }
        let mut budget = Budget::new(&mut self.io, deadline).map_err(Self::before)?;
        let mut issued = false;
        let result = (|| {
            self.taskfile(&mut budget, lba)?;
            issued = true;
            self.out(COMMAND, WRITE)?;
            self.settle(&mut budget)?;
            self.wait(&mut budget, true)?;
            self.write_data(&mut budget, bytes)?;
            self.wait(&mut budget, false)
        })();
        self.finish(result, issued)
    }
    fn write_data(&mut self, budget: &mut Budget, bytes: &[u8; SECTOR_BYTES]) -> Result<(), Error> {
        #[cfg(feature = "pio-words256")]
        if PROFILE == 1 {
            let cut = budget.words256_cut(&mut self.io)?;
            return self.io.output_words256(DATA, cut, bytes).map_err(Error::Io);
        }
        #[cfg(feature = "pio-word4")]
        for group in bytes.as_chunks::<8>().0 {
            let cut = budget.words4_cut(&mut self.io)?;
            self.io
                .output_words4(DATA, u64::from_le_bytes(*group), cut)
                .map_err(Error::Io)?;
        }
        #[cfg(not(feature = "pio-word4"))]
        for pair in bytes.as_chunks::<2>().0 {
            budget.step(&mut self.io)?;
            self.io
                .output(DATA, 2, u32::from(u16::from_le_bytes([pair[0], pair[1]])))
                .map_err(Error::Io)?;
        }
        Ok(())
    }
    /// Success means the device completed FLUSH CACHE without BSY/DRQ/ERR/DF;
    /// readback alone and command acceptance alone are never durable completion.
    pub fn flush(&mut self, deadline: u64) -> Result<(), Failure> {
        self.info()?;
        let mut budget = Budget::new(&mut self.io, deadline).map_err(Self::before)?;
        let mut issued = false;
        let result = (|| {
            self.wait(&mut budget, false)?;
            issued = true;
            self.out(COMMAND, FLUSH)?;
            self.settle(&mut budget)?;
            self.wait(&mut budget, false)
        })();
        self.finish(result, issued)
    }
    pub fn idle(&mut self, deadline: u64) -> Result<(), Failure> {
        self.info()?;
        let mut budget = Budget::new(&mut self.io, deadline).map_err(Self::before)?;
        let result = self.wait(&mut budget, false);
        self.finish(result, false)
    }
}
fn word(bytes: &[u8; SECTOR_BYTES], index: usize) -> u16 {
    u16::from_le_bytes([bytes[index * 2], bytes[index * 2 + 1]])
}
pub fn parse_identify(bytes: &[u8; SECTOR_BYTES]) -> Result<Info, Error> {
    parse_identify_for(bytes, SERIAL, DISK_SECTORS)
}
#[cfg(feature = "workspace-storage")]
pub fn parse_workspace_identify(bytes: &[u8; SECTOR_BYTES]) -> Result<Info, Error> {
    parse_identify_for(
        bytes,
        crate::workspace::SERIAL,
        crate::workspace::DISK_SECTORS,
    )
}
fn parse_identify_for(
    bytes: &[u8; SECTOR_BYTES],
    expected_serial: [u8; 20],
    expected_sectors: u32,
) -> Result<Info, Error> {
    if word(bytes, 0) & 0x8000 != 0 {
        return Err(Error::Unsupported);
    }
    let mut serial = [0; 20];
    for (i, byte) in serial.iter_mut().enumerate() {
        *byte = bytes[20 + (i ^ 1)];
    }
    if serial != expected_serial {
        return Err(Error::Identity);
    }
    if word(bytes, 49) & (1 << 9) == 0 {
        return Err(Error::Unsupported);
    }
    let commands = word(bytes, 83);
    if commands & 0xc000 != 0x4000 || commands & (1 << 12) == 0 {
        return Err(Error::Unsupported);
    }
    let sectors = u32::from(word(bytes, 60)) | (u32::from(word(bytes, 61)) << 16);
    if sectors != expected_sectors {
        return Err(Error::Geometry);
    }
    if word(bytes, 106) & 0xd000 == 0x5000 {
        let logical_words = u32::from(word(bytes, 117)) | (u32::from(word(bytes, 118)) << 16);
        if logical_words != 256 {
            return Err(Error::Geometry);
        }
    }
    Ok(Info {
        sectors,
        sector_bytes: SECTOR_BYTES as u16,
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::{RECORD, SEED};
    use std::vec::Vec;
    #[cfg(feature = "native-session")]
    #[path = "session_tests.rs"]
    mod session_tests;
    #[cfg(feature = "workspace-storage")]
    #[path = "workspace_tests.rs"]
    mod workspace_tests;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Op {
        Input(u16, u8),
        Output(u16, u8, u32),
    }
    fn identify_bytes() -> [u8; 512] {
        let mut bytes = [0; 512];
        for (index, value) in [
            (0, 0x0040u16),
            (49, 1 << 9),
            (60, DISK_SECTORS as u16),
            (83, 0x5000),
            (106, 0x4000),
        ] {
            bytes[index * 2..index * 2 + 2].copy_from_slice(&value.to_le_bytes());
        }
        for (i, &byte) in SERIAL.iter().enumerate() {
            bytes[20 + (i ^ 1)] = byte;
        }
        bytes
    }
    struct Bus {
        regs: [u8; 8],
        status: u8,
        error: u8,
        data: [u8; 512],
        identify: [u8; 512],
        disk: [[u8; 512]; 2],
        position: usize,
        writing: bool,
        lba: u32,
        lba_base: u32,
        now: u64,
        advance: bool,
        backward: bool,
        flush_busy: u8,
        stuck: bool,
        fail_command: Option<u8>,
        commands: Vec<u8>,
        trace: Vec<Op>,
        yields: u32,
        completed_flushes: u32,
    }
    impl Bus {
        fn new() -> Self {
            Self {
                regs: [0; 8],
                status: READY,
                error: 0,
                data: [0; 512],
                identify: identify_bytes(),
                disk: [SEED, [0; 512]],
                position: 0,
                writing: false,
                lba: 0,
                lba_base: 0,
                now: 0,
                advance: true,
                backward: false,
                flush_busy: 0,
                stuck: false,
                fail_command: None,
                commands: Vec::new(),
                trace: Vec::new(),
                yields: 0,
                completed_flushes: 0,
            }
        }
        fn command(&mut self, command: u8) -> Result<(), u64> {
            self.commands.push(command);
            if self.fail_command == Some(command) {
                self.status = READY | ERR;
                self.error = 4;
                return Ok(());
            }
            self.position = 0;
            self.writing = false;
            match command {
                IDENTIFY => {
                    self.data = self.identify;
                    self.status = READY | DRQ;
                }
                READ | WRITE => {
                    if self.regs[2] != 1 {
                        return Err(80);
                    }
                    let physical = u32::from(self.regs[3])
                        | (u32::from(self.regs[4]) << 8)
                        | (u32::from(self.regs[5]) << 16)
                        | (u32::from(self.regs[6] & 15) << 24);
                    // Two sparse model sectors may stand at a real physical
                    // region boundary without allocating an8192-sector array.
                    self.lba = physical.checked_sub(self.lba_base).ok_or(81u64)?;
                    if self.lba >= 2 {
                        return Err(81);
                    }
                    self.status = READY | DRQ;
                    if command == READ {
                        self.data = self.disk[self.lba as usize];
                    } else {
                        self.data.fill(0);
                        self.writing = true;
                    }
                }
                FLUSH => {
                    self.status = BUSY;
                    self.flush_busy = 8;
                }
                _ => return Err(82),
            }
            Ok(())
        }
    }
    // A scripted device, not port authority or hardware acceptance. Every
    // successful word read/write changes the model's real buffer position.
    impl Ports for Bus {
        fn input(&mut self, port: u16, width: u8) -> Result<u32, u64> {
            self.trace.push(Op::Input(port, width));
            if port == CONTROL_PORT && width == 1 {
                if self.flush_busy != 0 && !self.stuck {
                    self.flush_busy -= 1;
                    if self.flush_busy == 0 {
                        self.status = READY;
                        self.completed_flushes += 1;
                    }
                }
                return Ok(u32::from(self.status));
            }
            if port == DATA && width == 2 {
                if self.status & DRQ == 0 || self.writing || self.position >= 512 {
                    return Err(83);
                }
                let p = self.position;
                self.position += 2;
                let value = u16::from_le_bytes([self.data[p], self.data[p + 1]]);
                if self.position == 512 {
                    self.status = READY;
                }
                return Ok(u32::from(value));
            }
            if width == 1 && (ERROR..=COMMAND).contains(&port) {
                return Ok(u32::from(if port == ERROR {
                    self.error
                } else {
                    self.regs[(port - PORT_BASE) as usize]
                }));
            }
            Err(84)
        }
        fn output(&mut self, port: u16, width: u8, value: u32) -> Result<(), u64> {
            self.trace.push(Op::Output(port, width, value));
            if port == CONTROL_PORT && width == 1 {
                if value & 4 != 0 {
                    self.status = BUSY;
                } else {
                    self.status = READY;
                    self.error = 0;
                    self.stuck = false;
                }
                return Ok(());
            }
            if port == DATA && width == 2 {
                if !self.writing || self.status & DRQ == 0 || self.position >= 512 {
                    return Err(85);
                }
                let p = self.position;
                self.position += 2;
                self.data[p..p + 2].copy_from_slice(&(value as u16).to_le_bytes());
                if self.position == 512 {
                    self.disk[self.lba as usize] = self.data;
                    self.status = READY;
                    self.writing = false;
                }
                return Ok(());
            }
            if width == 1 && (ERROR..=COMMAND).contains(&port) {
                self.regs[(port - PORT_BASE) as usize] = u8::try_from(value).map_err(|_| 86u64)?;
                if port == COMMAND {
                    self.command(value as u8)?;
                }
                return Ok(());
            }
            Err(87)
        }
        fn now(&mut self) -> Result<u64, u64> {
            let result = self.now;
            if self.backward && self.now != 0 {
                self.now -= 1;
            }
            Ok(result)
        }
        fn yield_now(&mut self) -> Result<(), u64> {
            self.yields += 1;
            if self.advance {
                self.now += 1;
            }
            Ok(())
        }
    }
    #[cfg(feature = "pio-word4")]
    struct BatchBus {
        bus: Bus,
        batches: Vec<(bool, u16, u64, u64)>,
        fail_batch: Option<usize>,
        clocks: usize,
    }
    #[cfg(feature = "pio-word4")]
    impl BatchBus {
        fn new() -> Self {
            Self {
                bus: Bus::new(),
                batches: Vec::new(),
                fail_batch: None,
                clocks: 0,
            }
        }
        fn batch(&mut self, output: bool, port: u16, cut: u64) -> Result<bool, u64> {
            let ordinal = self.batches.len();
            self.batches.push((output, port, cut, self.bus.now));
            if port != DATA || cut <= self.bus.now || cut - self.bus.now > 1024 {
                return Err(169);
            }
            Ok(self.fail_batch == Some(ordinal))
        }
    }
    #[cfg(feature = "pio-word4")]
    impl Ports for BatchBus {
        fn input(&mut self, port: u16, width: u8) -> Result<u32, u64> {
            self.bus.input(port, width)
        }
        fn output(&mut self, port: u16, width: u8, value: u32) -> Result<(), u64> {
            self.bus.output(port, width, value)
        }
        fn now(&mut self) -> Result<u64, u64> {
            self.clocks += 1;
            self.bus.now()
        }
        fn yield_now(&mut self) -> Result<(), u64> {
            self.bus.yield_now()
        }
        fn input_words4(&mut self, port: u16, cut: u64) -> Result<u64, u64> {
            let fail = self.batch(false, port, cut)?;
            let mut value = 0;
            for word in 0..4 {
                if fail && word == 2 {
                    return Err(170);
                }
                value |= u64::from(self.bus.input(port, 2)?) << (16 * word);
            }
            Ok(value)
        }
        fn output_words4(&mut self, port: u16, value: u64, cut: u64) -> Result<(), u64> {
            let fail = self.batch(true, port, cut)?;
            for word in 0..4 {
                if fail && word == 2 {
                    return Err(170);
                }
                self.bus
                    .output(port, 2, u32::from((value >> (16 * word)) as u16))?;
            }
            Ok(())
        }
    }
    #[cfg(feature = "pio-word4")]
    #[test]
    fn each_word4_cut_clamps_the_original_horizon_and_reserves_four_units() {
        let mut io = BatchBus::new();
        let mut budget = Budget::new(&mut io, 100_000).unwrap();
        for now in [1, 100, 5000, 99_800, 99_999] {
            io.bus.now = now;
            let clocks = io.clocks;
            let polls = budget.polls;
            assert_eq!(budget.words4_cut(&mut io), Ok(100_000.min(now + 1024)));
            assert_eq!((budget.deadline, budget.polls), (100_000, polls - 4));
            assert_eq!(io.clocks, clocks + 1);
            assert!(io.bus.trace.is_empty());
        }
        budget.polls = 3;
        let clocks = io.clocks;
        assert_eq!(budget.words4_cut(&mut io), Err(Error::PollBudget));
        assert_eq!((budget.polls, io.clocks), (3, clocks));
        assert!(io.batches.is_empty());
        budget.step(&mut io).unwrap();
        assert_eq!(budget.polls, 2); // The scalar path still reserves exactly one.
        for (last, now, deadline, error) in [
            (5, 4, 100, Error::ClockReversed),
            (5, 100, 100, Error::Deadline),
            (
                u64::MAX - 100,
                u64::MAX - 100,
                u64::MAX - 1,
                Error::Deadline,
            ),
            (
                u64::MAX - 1024,
                u64::MAX - 1024,
                u64::MAX - 1,
                Error::Deadline,
            ),
        ] {
            let mut budget = Budget {
                deadline,
                last,
                polls: 4,
            };
            io.bus.now = now;
            assert_eq!(budget.words4_cut(&mut io), Err(error));
            assert_eq!((budget.deadline, budget.polls), (deadline, 0));
            assert!(io.batches.is_empty());
        }
    }
    #[cfg(feature = "pio-word4")]
    #[test]
    fn word4_sectors_keep_exact_words_endianness_and_ata_command_sequence() {
        let mut disk = AtaPio::new(BatchBus::new());
        disk.reset(100_000).unwrap();
        disk.identify(100_000).unwrap();
        let mut bytes = [0; 512];
        disk.read_sector(0, &mut bytes, 100_000).unwrap();
        assert_eq!(bytes, SEED);
        disk.write_sector(1, &RECORD, 100_000).unwrap();
        disk.flush(100_000).unwrap();
        disk.read_sector(1, &mut bytes, 100_000).unwrap();
        assert_eq!(bytes, RECORD);
        let io = disk.into_ports();
        assert_eq!(io.bus.commands, [IDENTIFY, READ, WRITE, FLUSH, READ]);
        assert_eq!(io.bus.completed_flushes, 1);
        assert_eq!(io.batches.iter().filter(|b| !b.0).count(), 3 * 64);
        assert_eq!(io.batches.iter().filter(|b| b.0).count(), 64);
        assert!(io.batches.iter().all(|&(_, port, cut, now)| port == DATA
            && cut > now
            && cut - now <= 1024
            && cut <= 100_000));
        assert_eq!(
            io.bus
                .trace
                .iter()
                .filter(|op| matches!(op, Op::Input(DATA, 2)))
                .count(),
            3 * 256
        );
        assert_eq!(
            io.bus
                .trace
                .iter()
                .filter(|op| matches!(op, Op::Output(DATA, 2, _)))
                .count(),
            256
        );
    }
    #[cfg(feature = "pio-word4")]
    #[test]
    fn partial_word4_error_is_uncertain_without_retry_or_partial_reply_copy() {
        for write in [false, true] {
            let mut disk = AtaPio::new(BatchBus::new());
            disk.identify(100_000).unwrap();
            disk.io.batches.clear();
            disk.io.fail_batch = Some(1);
            let mut read = [0xa5; 512];
            let outcome = if write {
                disk.write_sector(1, &RECORD, 100_000)
            } else {
                disk.read_sector(0, &mut read, 100_000)
            };
            assert_eq!(
                outcome,
                Err(Failure {
                    error: Error::Io(170),
                    progress: Progress::MayHaveExecuted,
                })
            );
            assert_eq!(disk.io.bus.position, 12); // Four accepted words + two-word prefix.
            assert_eq!(disk.io.batches.len(), 2);
            if !write {
                assert_eq!(&read[..8], &SEED[..8]);
                assert_eq!(&read[8..], &[0xa5; 504]); // The failed packed reply was not copied.
            }
            let trace = disk.io.bus.trace.len();
            assert_eq!(
                disk.read_sector(0, &mut read, 100_000),
                Err(Failure {
                    error: Error::NeedsReset,
                    progress: Progress::NotIssued,
                })
            );
            assert_eq!((disk.io.bus.trace.len(), disk.io.batches.len()), (trace, 2));
            assert_eq!(
                disk.io.bus.commands,
                [IDENTIFY, if write { WRITE } else { READ }]
            );
        }
    }
    #[test]
    fn complete_write_flush_readback_then_fresh_driver_verify_reads_only() {
        let mut disk = AtaPio::new(Bus::new());
        disk.reset(1000).unwrap();
        assert_eq!(
            disk.identify(1000),
            Ok(Info {
                sectors: 8192,
                sector_bytes: 512
            })
        );
        let mut bytes = [0; 512];
        disk.read_sector(0, &mut bytes, 1000).unwrap();
        assert_eq!(bytes, SEED);
        disk.write_sector(1, &RECORD, 1000).unwrap();
        disk.flush(1000).unwrap();
        disk.read_sector(1, &mut bytes, 1000).unwrap();
        disk.idle(1000).unwrap();
        assert_eq!(bytes, RECORD);
        let first = disk.into_ports();
        assert_eq!(first.commands, [IDENTIFY, READ, WRITE, FLUSH, READ]);
        assert_eq!(first.completed_flushes, 1);
        assert!(first.yields > 1);
        assert_eq!(first.disk[0], SEED);
        assert_eq!(first.disk[1], RECORD);
        assert_eq!(
            first
                .trace
                .iter()
                .filter(|op| matches!(op, Op::Output(DATA, 2, _)))
                .count(),
            256
        );
        let mut reopened = Bus::new();
        reopened.disk = first.disk;
        let mut verify = AtaPio::new(reopened);
        verify.reset(1000).unwrap();
        verify.identify(1000).unwrap();
        verify.read_sector(0, &mut bytes, 1000).unwrap();
        assert_eq!(bytes, SEED);
        verify.read_sector(1, &mut bytes, 1000).unwrap();
        assert_eq!(bytes, RECORD);
        verify.idle(1000).unwrap();
        let fresh = verify.into_ports();
        assert_eq!(fresh.commands, [IDENTIFY, READ, READ]);
        assert_eq!(fresh.completed_flushes, 0);
        assert!(
            fresh
                .trace
                .iter()
                .all(|op| !matches!(op, Op::Output(DATA, 2, _)))
        );
    }
    #[test]
    fn identify_rejects_wrong_device_capacity_lba_flush_and_sector_size() {
        let good = identify_bytes();
        assert!(parse_identify(&good).is_ok());
        for (index, value, expected) in [
            (0, 0x8040, Error::Unsupported),
            (49, 0, Error::Unsupported),
            (60, 8191, Error::Geometry),
            (83, 0x4000, Error::Unsupported),
            (83, 0xd000, Error::Unsupported),
            (106, 0x5000, Error::Geometry),
        ] {
            let mut bad = good;
            bad[index * 2..index * 2 + 2].copy_from_slice(&(value as u16).to_le_bytes());
            assert_eq!(parse_identify(&bad), Err(expected));
        }
        let mut bad = good;
        bad[20] ^= 1;
        assert_eq!(parse_identify(&bad), Err(Error::Identity));
        let mut bus = Bus::new();
        bus.identify = bad;
        let mut disk = AtaPio::new(bus);
        assert_eq!(
            disk.identify(100),
            Err(Failure {
                error: Error::Identity,
                progress: Progress::MayHaveExecuted
            })
        );
        assert_eq!(disk.into_ports().commands, [IDENTIFY]);
    }
    #[test]
    fn out_of_bounds_requests_do_not_touch_device_or_poison_ready_state() {
        let mut disk = AtaPio::new(Bus::new());
        disk.identify(100).unwrap();
        let before = disk.io.trace.len();
        let mut bytes = [0; 512];
        for lba in [DISK_SECTORS, 1 << 28, u32::MAX] {
            assert_eq!(
                disk.read_sector(lba, &mut bytes, 100),
                Err(Failure {
                    error: Error::Bounds,
                    progress: Progress::NotIssued
                })
            );
            assert_eq!(
                disk.write_sector(lba, &RECORD, 100),
                Err(Failure {
                    error: Error::Bounds,
                    progress: Progress::NotIssued
                })
            );
            assert_eq!(disk.io.trace.len(), before);
        }
        disk.read_sector(0, &mut bytes, 100).unwrap();
        assert_eq!(bytes, SEED);
    }
    #[test]
    fn errored_write_is_ambiguous_and_never_replayed_automatically() {
        let mut disk = AtaPio::new(Bus::new());
        disk.identify(100).unwrap();
        disk.io.fail_command = Some(WRITE);
        assert_eq!(
            disk.write_sector(1, &RECORD, 100),
            Err(Failure {
                error: Error::Device {
                    status: READY | ERR,
                    error: 4
                },
                progress: Progress::MayHaveExecuted
            })
        );
        let before = disk.io.trace.len();
        assert_eq!(
            disk.write_sector(1, &RECORD, 100),
            Err(Failure {
                error: Error::NeedsReset,
                progress: Progress::NotIssued
            })
        );
        assert_eq!(disk.io.trace.len(), before);
        assert_eq!(disk.io.commands, [IDENTIFY, WRITE]);
    }
    #[test]
    fn failed_flush_never_reports_completion_even_after_data_changed() {
        let mut disk = AtaPio::new(Bus::new());
        disk.identify(100).unwrap();
        disk.write_sector(1, &RECORD, 100).unwrap();
        disk.io.stuck = true;
        assert_eq!(
            disk.flush(3),
            Err(Failure {
                error: Error::Deadline,
                progress: Progress::MayHaveExecuted
            })
        );
        assert_eq!(disk.io.completed_flushes, 0);
        assert_eq!(disk.io.disk[1], RECORD);
        assert_eq!(
            disk.idle(100),
            Err(Failure {
                error: Error::NeedsReset,
                progress: Progress::NotIssued
            })
        );
        assert_eq!(disk.io.commands, [IDENTIFY, WRITE, FLUSH]);
    }
    #[test]
    fn stalled_clock_has_exact_poll_bound_and_no_command_is_accepted() {
        let mut bus = Bus::new();
        bus.status = BUSY;
        bus.advance = false;
        let mut disk = AtaPio::new(bus);
        // The nIEN control transaction must not clear our simulated stuckBSY.
        disk.io.stuck = true;
        struct Stalled(Bus);
        impl Ports for Stalled {
            fn input(&mut self, p: u16, w: u8) -> Result<u32, u64> {
                self.0.input(p, w)
            }
            fn output(&mut self, p: u16, w: u8, v: u32) -> Result<(), u64> {
                if p == CONTROL_PORT {
                    self.0.trace.push(Op::Output(p, w, v));
                    Ok(())
                } else {
                    self.0.output(p, w, v)
                }
            }
            fn now(&mut self) -> Result<u64, u64> {
                self.0.now()
            }
            fn yield_now(&mut self) -> Result<(), u64> {
                self.0.yield_now()
            }
        }
        let mut disk = AtaPio::new(Stalled(disk.into_ports()));
        assert_eq!(
            disk.identify(100),
            Err(Failure {
                error: Error::PollBudget,
                progress: Progress::NotIssued
            })
        );
        let bus = disk.into_ports().0;
        assert_eq!(bus.yields, POLLS);
        assert!(bus.commands.is_empty());
        assert!(bus.trace.len() <= POLLS as usize + 1);
    }
    #[test]
    fn expired_and_reversed_clock_never_issue_an_ata_command() {
        let mut bus = Bus::new();
        bus.now = 10;
        let mut disk = AtaPio::new(bus);
        assert_eq!(
            disk.identify(10),
            Err(Failure {
                error: Error::Deadline,
                progress: Progress::NotIssued
            })
        );
        assert!(disk.io.trace.is_empty());
        disk.io.backward = true;
        assert_eq!(
            disk.identify(100),
            Err(Failure {
                error: Error::ClockReversed,
                progress: Progress::NotIssued
            })
        );
        assert!(disk.io.commands.is_empty());
    }
}
