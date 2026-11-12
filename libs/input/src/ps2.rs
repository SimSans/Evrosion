//! Bounded exclusive userspace i8042/PS2 owner for the reference QEMU machine.
//! Only byte ports60/64 are used. This is no IRQ/PIC/kernel configuration API.
use crate::stream::Stream;
pub const DATA: u16 = 0x60;
pub const STATUS: u16 = 0x64;
const POLLS: u32 = 16_384;
const QUIET_TICKS: u64 = 2;
const MAX_DRAIN: u32 = 256;
pub trait Ports {
    type Error;
    fn input(&mut self, port: u16) -> Result<u8, Self::Error>;
    fn output(&mut self, port: u16, value: u8) -> Result<(), Self::Error>;
    fn now(&mut self) -> Result<u64, Self::Error>;
    fn yield_now(&mut self) -> Result<(), Self::Error>;
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Io(E),
    Unavailable,
    ClockReversed,
    Deadline,
    PollBudget,
    Controller,
    DrainLimit,
    UnexpectedAck(u8),
    ResendLimit,
    Configuration,
    ScanSet,
    Stream(crate::stream::Error),
    IncompleteSequence,
}
struct Budget {
    deadline: u64,
    remaining: u32,
}
pub struct Driver<P> {
    ports: P,
    last: u64,
    used: bool,
    initialized: bool,
    failed: bool,
}
impl<P: Ports> Driver<P> {
    pub fn new(ports: P) -> Self {
        Self {
            ports,
            last: 0,
            used: false,
            initialized: false,
            failed: false,
        }
    }
    pub fn into_ports(self) -> P {
        self.ports
    }
    fn step(&mut self, b: &mut Budget) -> Result<u64, Error<P::Error>> {
        if b.remaining == 0 {
            return Err(Error::PollBudget);
        }
        b.remaining -= 1;
        let now = self.ports.now().map_err(Error::Io)?;
        if now < self.last {
            return Err(Error::ClockReversed);
        }
        self.last = now;
        if b.deadline == u64::MAX || now >= b.deadline {
            return Err(Error::Deadline);
        }
        Ok(now)
    }
    fn pause(&mut self, b: &mut Budget) -> Result<(), Error<P::Error>> {
        self.step(b)?;
        self.ports.yield_now().map_err(Error::Io)?;
        self.step(b)?;
        Ok(())
    }
    fn status(&mut self, b: &mut Budget) -> Result<u8, Error<P::Error>> {
        self.step(b)?;
        let status = self.ports.input(STATUS).map_err(Error::Io)?;
        if status & 0xc0 != 0 {
            return Err(Error::Controller);
        }
        Ok(status)
    }
    fn write(&mut self, b: &mut Budget, port: u16, value: u8) -> Result<(), Error<P::Error>> {
        loop {
            if self.status(b)? & 2 == 0 {
                self.step(b)?;
                return self.ports.output(port, value).map_err(Error::Io);
            }
            self.pause(b)?;
        }
    }
    fn read_keyboard(&mut self, b: &mut Budget) -> Result<u8, Error<P::Error>> {
        loop {
            let status = self.status(b)?;
            if status & 1 != 0 {
                self.step(b)?;
                let byte = self.ports.input(DATA).map_err(Error::Io)?;
                if status & 0x20 == 0 {
                    return Ok(byte);
                }
            }
            self.pause(b)?;
        }
    }
    fn ack(&mut self, b: &mut Budget, byte: u8, initial: bool) -> Result<(), Error<P::Error>> {
        for _ in 0..3 {
            self.write(b, DATA, byte)?;
            for _ in 0..MAX_DRAIN {
                match self.read_keyboard(b)? {
                    0xfa => return Ok(()),
                    0xfe => break,
                    other if initial => {
                        let _ = other;
                    }
                    other => return Err(Error::UnexpectedAck(other)),
                }
            }
        }
        Err(Error::ResendLimit)
    }
    fn raw_quiet(&mut self, b: &mut Budget) -> Result<(), Error<P::Error>> {
        let mut since = self.step(b)?;
        let mut drained = 0;
        loop {
            let status = self.status(b)?;
            let now = self.last;
            if status & 1 != 0 {
                if drained == MAX_DRAIN {
                    return Err(Error::DrainLimit);
                }
                drained += 1;
                self.step(b)?;
                self.ports.input(DATA).map_err(Error::Io)?;
                since = self.last;
            } else if now.saturating_sub(since) >= QUIET_TICKS {
                return Ok(());
            }
            self.pause(b)?;
        }
    }
    /// Cold supervised initialization only. Never reinitialize/reset a running
    /// Input to satisfy a barrier: that could forget a held Enter. Initial held
    /// state is unknown and cannot approve until a real set1 break is observed.
    pub fn initialize(&mut self, deadline: u64) -> Result<(), Error<P::Error>> {
        if self.used || self.failed {
            return Err(Error::Unavailable);
        }
        self.used = true;
        let mut b = Budget {
            deadline,
            remaining: POLLS,
        };
        let result = (|| {
            self.write(&mut b, STATUS, 0xad)?; // stop primary interface
            self.write(&mut b, STATUS, 0xa7)?; // no AUX stream or IRQ12
            self.raw_quiet(&mut b)?;
            self.write(&mut b, STATUS, 0xae)?;
            // F5 disables scanning and selects the keyboard's defaults. Old
            // unknown-format bytes are discarded only during this cold phase.
            self.ack(&mut b, 0xf5, true)?;
            self.raw_quiet(&mut b)?;
            self.write(&mut b, STATUS, 0x20)?;
            let old = self.read_keyboard(&mut b)?;
            let mode = (old & 0x0c) | 0x20; // preserve system/keylock, polling, raw, AUX disabled
            self.write(&mut b, STATUS, 0x60)?;
            self.write(&mut b, DATA, mode)?;
            self.write(&mut b, STATUS, 0x20)?;
            if self.read_keyboard(&mut b)? != mode {
                return Err(Error::Configuration);
            }
            self.ack(&mut b, 0xf0, false)?;
            self.ack(&mut b, 1, false)?;
            self.ack(&mut b, 0xf0, false)?;
            self.ack(&mut b, 0, false)?;
            if self.read_keyboard(&mut b)? != 1 {
                return Err(Error::ScanSet);
            }
            self.ack(&mut b, 0xf4, false)?;
            Ok(())
        })();
        if result.is_ok() {
            self.initialized = true;
        } else {
            self.failed = true;
        }
        result
    }
    /// One actual output-buffer byte, never stale data read without OBF.
    pub fn poll(&mut self, deadline: u64) -> Result<Option<(u8, u8)>, Error<P::Error>> {
        if !self.initialized || self.failed {
            return Err(Error::Unavailable);
        }
        let mut b = Budget {
            deadline,
            remaining: 64,
        };
        let result = (|| {
            let status = self.status(&mut b)?;
            if status & 1 == 0 {
                return Ok(None);
            }
            self.step(&mut b)?;
            let byte = self.ports.input(DATA).map_err(Error::Io)?;
            Ok(Some((status, byte)))
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    /// Caller first drops pending output via Stream::begin_barrier. Keep this
    /// SAME stream across the drain. Two quiet ticks cover QEMU's1ms i8042
    /// throttle; one absolute deadline+poll budget bounds even a stalled clock.
    pub fn drain(&mut self, stream: &mut Stream, deadline: u64) -> Result<(), Error<P::Error>> {
        if !self.initialized || self.failed {
            return Err(Error::Unavailable);
        }
        let mut b = Budget {
            deadline,
            remaining: POLLS,
        };
        let result = (|| {
            let mut since = self.step(&mut b)?;
            let mut drained = 0;
            loop {
                let status = self.status(&mut b)?;
                let now = self.last;
                if status & 1 != 0 {
                    if drained == MAX_DRAIN {
                        return Err(Error::DrainLimit);
                    }
                    drained += 1;
                    self.step(&mut b)?;
                    let data = self.ports.input(DATA).map_err(Error::Io)?;
                    stream.discard(status, data).map_err(Error::Stream)?;
                    since = self.last;
                } else if now.saturating_sub(since) >= QUIET_TICKS {
                    if !stream.at_boundary() {
                        return Err(Error::IncompleteSequence);
                    }
                    return Ok(());
                }
                self.pause(&mut b)?;
            }
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{collections::VecDeque, vec::Vec};
    #[derive(Default)]
    struct Model {
        time: u64,
        mode: u8,
        scanset: u8,
        command: Option<u8>,
        queue: VecDeque<(u8, u8)>,
        outputs: Vec<(u16, u8)>,
        stall: bool,
        resends: u8,
        bad_set: bool,
        io_fail: bool,
    }
    impl Ports for Model {
        type Error = ();
        fn input(&mut self, port: u16) -> Result<u8, ()> {
            if self.io_fail {
                return Err(());
            }
            match port {
                STATUS => Ok(self.queue.front().map_or(0, |p| p.0)),
                DATA => Ok(self.queue.pop_front().expect("data read requires OBF").1),
                _ => panic!("forbidden port"),
            }
        }
        fn output(&mut self, port: u16, value: u8) -> Result<(), ()> {
            assert!(matches!(port, DATA | STATUS));
            self.outputs.push((port, value));
            if port == STATUS {
                match value {
                    0xad => self.mode |= 16,
                    0xae => self.mode &= !16,
                    0xa7 => self.mode |= 32,
                    0x20 => self.queue.push_back((1, self.mode)),
                    0x60 => self.command = Some(0x60),
                    _ => panic!("forbidden controller command"),
                };
                return Ok(());
            }
            if self.command == Some(0x60) {
                self.mode = value;
                self.command = None;
                return Ok(());
            }
            if self.resends > 0 {
                self.resends -= 1;
                self.queue.push_back((1, 0xfe));
                return Ok(());
            }
            match self.command.take() {
                Some(0xf0) => {
                    self.queue.push_back((1, 0xfa));
                    if value == 0 {
                        self.queue
                            .push_back((1, if self.bad_set { 2 } else { self.scanset }));
                    } else {
                        self.scanset = value;
                    }
                }
                None => match value {
                    0xf5 => {
                        self.scanset = 2;
                        self.queue.clear();
                        self.queue.push_back((1, 0xfa));
                    }
                    0xf0 => {
                        self.command = Some(0xf0);
                        self.queue.push_back((1, 0xfa));
                    }
                    0xf4 => self.queue.push_back((1, 0xfa)),
                    _ => panic!("unexpected keyboard command"),
                },
                _ => panic!("unexpected pending command"),
            };
            Ok(())
        }
        fn now(&mut self) -> Result<u64, ()> {
            Ok(self.time)
        }
        fn yield_now(&mut self) -> Result<(), ()> {
            if !self.stall {
                self.time += 1;
            }
            Ok(())
        }
    }
    #[test]
    fn initializes_only_actual_scoped_ports_with_query_and_finite_resends() {
        let mut driver = Driver::new(Model {
            mode: 0x47,
            resends: 2,
            ..Model::default()
        });
        driver.initialize(100).unwrap();
        let m = driver.into_ports();
        assert_eq!(m.scanset, 1);
        assert_eq!(m.mode & 0x73, 0x20);
        assert!(m.outputs.contains(&(DATA, 0xf4)));
        assert_eq!(m.outputs.iter().filter(|p| **p == (DATA, 0xf5)).count(), 3);
    }
    #[test]
    fn wrong_encoding_clock_and_controller_failures_latch_refusal() {
        let mut d = Driver::new(Model {
            bad_set: true,
            ..Model::default()
        });
        assert_eq!(d.initialize(100), Err(Error::ScanSet));
        assert_eq!(d.poll(100), Err(Error::Unavailable));
        let mut d = Driver::new(Model {
            resends: 3,
            ..Model::default()
        });
        assert_eq!(d.initialize(100), Err(Error::ResendLimit));
        let mut d = Driver::new(Model {
            stall: true,
            ..Model::default()
        });
        assert_eq!(d.initialize(100), Err(Error::PollBudget));
        let mut d = Driver::new(Model::default());
        d.initialize(100).unwrap();
        d.ports.time = 0;
        assert_eq!(d.poll(100), Err(Error::ClockReversed));
        let mut d = Driver::new(Model::default());
        d.initialize(100).unwrap();
        d.ports.queue.push_back((0x81, 0x1c));
        assert_eq!(d.poll(100), Err(Error::Controller));
        assert_eq!(d.poll(100), Err(Error::Unavailable));
    }
    #[test]
    fn stale_drain_updates_held_state_and_never_emits_a_pending_key() {
        let mut d = Driver::new(Model::default());
        d.initialize(100).unwrap();
        d.ports.queue.extend([(1, 0x9c), (1, 0x1c)]);
        let mut stream = Stream::new();
        d.drain(&mut stream, 100).unwrap();
        assert!(stream.pending().is_none());
        assert_eq!(stream.sequence(), 1);
        stream.begin_barrier();
        d.drain(&mut stream, 100).unwrap();
        assert!(stream.barrier_reply().enter.main_held);
        stream.push(1, 0x1c).unwrap();
        assert!(stream.pending().is_none());
        stream.push(1, 0x9c).unwrap();
        stream.push(1, 0x1c).unwrap();
        assert!(stream.pending().unwrap().approval_ready);
    }
    #[test]
    fn barrier_drain_requires_complete_encoding_and_a_real_finite_quiet_interval() {
        let mut d = Driver::new(Model::default());
        d.initialize(100).unwrap();
        d.ports.queue.push_back((1, 0xe0));
        let mut stream = Stream::new();
        stream.begin_barrier();
        assert_eq!(d.drain(&mut stream, 100), Err(Error::IncompleteSequence));
        let mut d = Driver::new(Model::default());
        d.initialize(100).unwrap();
        let now = d.ports.time;
        let mut stream = Stream::new();
        assert_eq!(d.drain(&mut stream, now + 1), Err(Error::Deadline));
        let mut d = Driver::new(Model::default());
        d.initialize(100).unwrap();
        d.ports.io_fail = true;
        assert_eq!(d.poll(100), Err(Error::Io(())));
    }
}
