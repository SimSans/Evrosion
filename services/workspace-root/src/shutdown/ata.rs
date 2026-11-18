//! Bounded terminal ATA FLUSH on the already selected reference channel.
//! Construction grants no port authority or exclusion. Native Root calls this
//! only after Kernel power BEGIN froze the exact prior device owner.
pub trait Ports {
    type Error;
    fn now(&mut self) -> Result<u64, Self::Error>;
    fn input(&mut self, port: u16) -> Result<u8, Self::Error>;
    fn output(&mut self, port: u16, value: u8) -> Result<(), Self::Error>;
    fn pause(&mut self) -> Result<(), Self::Error>;
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Io(E),
    Clock,
    Deadline,
    Device(u8),
    PollBudget,
}
/// Move-only completion of the real FLUSH and fresh final status reads. It
/// cannot be constructed from an ACK, a counter or a shutdown model transition.
pub struct Flushed {
    cut: u64,
    status: u8,
}
impl Flushed {
    pub const fn cut(&self) -> u64 {
        self.cut
    }
    pub const fn status(&self) -> u8 {
        self.status
    }
}
struct Budget {
    cut: u64,
    last: u64,
    polls: u16,
}
impl Budget {
    fn check<P: Ports>(&mut self, ports: &mut P) -> Result<(), Error<P::Error>> {
        let now = ports.now().map_err(Error::Io)?;
        if now == u64::MAX || now < self.last {
            return Err(Error::Clock);
        }
        self.last = now;
        if now >= self.cut {
            return Err(Error::Deadline);
        }
        self.polls = self.polls.checked_add(1).ok_or(Error::PollBudget)?;
        if self.polls > 8192 {
            return Err(Error::PollBudget);
        }
        Ok(())
    }
    fn input<P: Ports>(&mut self, ports: &mut P, port: u16) -> Result<u8, Error<P::Error>> {
        self.check(ports)?;
        ports.input(port).map_err(Error::Io)
    }
    fn ready<P: Ports>(&mut self, ports: &mut P) -> Result<u8, Error<P::Error>> {
        loop {
            let status = self.input(ports, 0x1ef)?;
            if status == 0 || status == 0xff || status & (0x20 | 1) != 0 {
                return Err(Error::Device(status));
            }
            if status & 0x80 == 0 {
                if status & 8 != 0 {
                    return Err(Error::Device(status));
                }
                if status & 0x40 != 0 {
                    return Ok(status);
                }
            }
            self.check(ports)?;
            ports.pause().map_err(Error::Io)?;
        }
    }
    fn settle<P: Ports>(&mut self, ports: &mut P) -> Result<(), Error<P::Error>> {
        for _ in 0..4 {
            self.input(ports, 0x3ee)?;
        }
        Ok(())
    }
}
pub fn flush<P: Ports>(ports: &mut P, cut: u64) -> Result<Flushed, Error<P::Error>> {
    let now = ports.now().map_err(Error::Io)?;
    if now == u64::MAX || cut == u64::MAX || cut <= now || cut - now > 8192 {
        return Err(Error::Deadline);
    }
    let mut b = Budget {
        cut,
        last: now,
        polls: 0,
    };
    b.ready(ports)?;
    b.check(ports)?;
    // Exact selected workspace channel/unit0, no sector/data/reset operation.
    ports.output(0x1ee, 0xe0).map_err(Error::Io)?;
    b.settle(ports)?;
    b.ready(ports)?;
    b.check(ports)?;
    ports.output(0x1ef, 0xe7).map_err(Error::Io)?;
    b.settle(ports)?;
    let status = b.ready(ports)?;
    b.check(ports)?;
    Ok(Flushed { cut, status })
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;
    struct Device {
        tick: u64,
        status: u8,
        writes: Vec<(u16, u8)>,
        busy_after_flush: bool,
    }
    impl Ports for Device {
        type Error = ();
        fn now(&mut self) -> Result<u64, ()> {
            let now = self.tick;
            self.tick += 1;
            Ok(now)
        }
        fn input(&mut self, port: u16) -> Result<u8, ()> {
            assert!(matches!(port, 0x1ef | 0x3ee));
            Ok(self.status)
        }
        fn output(&mut self, p: u16, v: u8) -> Result<(), ()> {
            self.writes.push((p, v));
            if p == 0x1ef && self.busy_after_flush {
                self.status = 0x80;
            }
            Ok(())
        }
        fn pause(&mut self) -> Result<(), ()> {
            Ok(())
        }
    }
    #[test]
    fn real_flush_and_fresh_idle_are_required_under_the_original_cut() {
        let mut d = Device {
            tick: 1,
            status: 0x50,
            writes: Vec::new(),
            busy_after_flush: false,
        };
        let receipt = flush(&mut d, 100).unwrap();
        assert_eq!(receipt.cut(), 100);
        assert_eq!(receipt.status(), 0x50);
        assert_eq!(d.writes, [(0x1ee, 0xe0), (0x1ef, 0xe7)]);
        let mut busy = Device {
            tick: 1,
            status: 0x50,
            writes: Vec::new(),
            busy_after_flush: true,
        };
        assert_eq!(flush(&mut busy, 100).err(), Some(Error::Deadline));
        assert_eq!(busy.writes.len(), 2);
    }
    #[test]
    fn drq_error_absence_and_bad_cut_refuse_without_a_command() {
        for status in [0, 0xff, 0x51, 0x70, 0x58] {
            let mut d = Device {
                tick: 1,
                status,
                writes: Vec::new(),
                busy_after_flush: false,
            };
            assert!(flush(&mut d, 100).is_err());
            assert!(d.writes.is_empty());
        }
    }
}
