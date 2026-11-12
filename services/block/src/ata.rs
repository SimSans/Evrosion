//! ATA protocol lives entirely in userspace. This closed reference profile uses
//! one master on the dedicated non-DMA QEMU ISA channel, LBA28, 512-byte sectors
//! and one sector per command. No automatic replay follows an ambiguous failure.
use crate::{CONTROL_PORT, DISK_SECTORS, PORT_BASE, SECTOR_BYTES, SERIAL};

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
        if self.polls == 0 {
            return Err(Error::PollBudget);
        }
        self.polls -= 1;
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
}
pub struct AtaPio<P> {
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
            parse_identify(&bytes)
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
            for pair in bytes.as_chunks::<2>().0 {
                budget.step(&mut self.io)?;
                self.io
                    .output(DATA, 2, u32::from(u16::from_le_bytes([pair[0], pair[1]])))
                    .map_err(Error::Io)?;
            }
            self.wait(&mut budget, false)
        })();
        self.finish(result, issued)
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
    if word(bytes, 0) & 0x8000 != 0 {
        return Err(Error::Unsupported);
    }
    let mut serial = [0; 20];
    for (i, byte) in serial.iter_mut().enumerate() {
        *byte = bytes[20 + (i ^ 1)];
    }
    if serial != SERIAL {
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
    if sectors != DISK_SECTORS {
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
                    self.lba = u32::from(self.regs[3])
                        | (u32::from(self.regs[4]) << 8)
                        | (u32::from(self.regs[5]) << 16)
                        | (u32::from(self.regs[6] & 15) << 24);
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
