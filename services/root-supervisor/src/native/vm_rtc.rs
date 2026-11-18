//! Actual Root-only calendar-port adapter. Only the fixed reviewed launcher
//! selects this profile; calendar labels themselves never authenticate UTC.
use super::*;
use ev_root_supervisor::vm_rtc::{Clock, Error, Io};
use ev_time_contract::{Domain, Instant};
use ev_userspace_contract::root_v4 as v4;

struct Ports {
    capability: u64,
    last: u64,
}
impl Ports {
    fn check(&mut self, cut: u64) -> Result<(), Error> {
        let tick = now();
        if tick < self.last {
            return Err(Error::Clock);
        }
        self.last = tick;
        if tick >= cut {
            return Err(Error::Deadline);
        }
        Ok(())
    }
}
impl Io for Ports {
    fn tick(&mut self) -> u64 {
        now()
    }
    fn read(&mut self, register: u8, original_cut: u64) -> Result<u8, Error> {
        if !matches!(
            register,
            0 | 2 | 4 | 7 | 8 | 9 | 10 | 11 | 13 | v4::RTC_CENTURY
        ) {
            return Err(Error::Configuration);
        }
        self.check(original_cut)?;
        // Reviewed Q35 ignores index bit7. Only a calendar selector is written;
        // this is not a portable physical-machine NMI mask policy. Data71 has
        // immutable Input direction, so no caller can set/adjust the RTC here.
        let r = rt::call4(
            syscall::PORT_OUTPUT,
            self.capability,
            u64::from(v4::RTC_INDEX_PORT),
            1,
            u64::from(register),
        );
        if r.status != 0 || r.value != 0 || r.capability != 0 || r.serial != 0 {
            return Err(Error::Unavailable);
        }
        self.check(original_cut)?;
        let r = rt::call4(
            syscall::PORT_INPUT,
            self.capability,
            u64::from(v4::RTC_DATA_PORT),
            1,
            0,
        );
        self.check(original_cut)?;
        if r.status != 0 || r.value > 255 || r.capability != 0 || r.serial != 0 {
            return Err(Error::Unavailable);
        }
        Ok(r.value as u8)
    }
}
pub(super) struct Source {
    clock: Clock,
    domain: Option<Domain>,
    next: u64,
    samples: u8,
    pending: Option<([u8; 8], u64)>,
    failed: bool,
}
impl Source {
    pub(super) const fn new() -> Self {
        Self {
            clock: Clock::new(),
            domain: None,
            next: 0,
            samples: 0,
            pending: None,
            failed: false,
        }
    }
    /// This private call consumes fresh bytes from this actual Root's qualified
    /// generator. A repeated catalogue epoch is never used as a public domain.
    pub(super) fn bind_domain(&mut self, random: &mut vm_entropy::Random) -> Result<(), Error> {
        if self.domain.is_some() || self.failed {
            return Err(Error::Failed);
        }
        let mut bytes = [0; 8];
        if random.fill(now(), &mut bytes).is_err() {
            self.failed = true;
            self.report(3, 1, 0);
            return Err(Error::Unavailable);
        }
        let value = u64::from_le_bytes(bytes);
        bytes.fill(0);
        let domain = match Domain::new(value) {
            Ok(domain) => domain,
            Err(_) => {
                self.failed = true;
                self.report(3, 1, 0);
                return Err(Error::Unavailable);
            }
        };
        self.domain = Some(domain);
        Ok(())
    }
    fn report(&mut self, stage: u8, result: u8, seconds: u32) {
        if self.samples >= 16 || self.pending.is_some() {
            return;
        }
        if let Some(cut) = now().checked_add(4096).filter(|n| *n != u64::MAX) {
            let mut frame = [b'T', b'M', stage, result, 0, 0, 0, 0];
            frame[4..].copy_from_slice(&seconds.to_le_bytes());
            self.pending = Some((frame, cut));
            self.samples += 1;
        }
    }
    pub(super) fn sample(&mut self, capability: u64) -> Result<Instant, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        let result = self
            .clock
            .sample(&mut Ports {
                capability,
                last: now(),
            })
            .and_then(|sample| {
                let next = sample
                    .captured_tick
                    .checked_add(1024)
                    .filter(|v| *v != u64::MAX)
                    .ok_or(Error::Overflow)?;
                let seconds = u32::try_from(sample.elapsed_seconds).map_err(|_| Error::Overflow)?;
                Ok((sample, next, seconds))
            });
        match result {
            Ok((sample, next, seconds)) => {
                self.next = next;
                self.report(if self.samples == 0 { 1 } else { 2 }, 0, seconds);
                self.domain
                    .map(|d| d.at(sample.elapsed_seconds))
                    .ok_or(Error::Unavailable)
            }
            Err(error) => {
                self.failed = true;
                self.report(
                    3,
                    match error {
                        Error::Unavailable => 1,
                        Error::Clock => 2,
                        _ => 3,
                    },
                    0,
                );
                Err(error)
            }
        }
    }
    pub(super) fn due(&self) -> bool {
        !self.failed && self.domain.is_some() && now() >= self.next
    }
    pub(super) fn failed(&self) -> bool {
        self.failed
    }
    pub(super) fn pending(&self) -> bool {
        self.pending.is_some()
    }
    /// One ordinary-tick attempt retains the exact frame and original local
    /// cut on Busy. Scalar SEND success consumes once, even across preemption.
    pub(super) fn flush(&mut self, events: u64) -> bool {
        let Some((frame, cut)) = self.pending else {
            return false;
        };
        if now() >= cut {
            self.pending = None;
            return true;
        }
        let r = rt::send(events, frame);
        // Accepted is consumed once; a refusal also retires this diagnostic.
        // Only canonical Busy preserves the exact unaccepted frame.
        if r.status != 2 || r.value != 0 || r.capability != 0 {
            self.pending = None;
        }
        true
    }
}

impl Root<'_> {
    /// Fresh coarse elapsed observation from the retained actual Root provider.
    /// This is not QualifiedWindow/UTC and must be sampled around publication
    /// and verification by any later signed-time adapter.
    pub(super) fn native_elapsed(&mut self) -> Result<Instant, Error> {
        let capability = self.bootstrap.handle(Role::RtcPorts);
        self.native
            .as_mut()
            .unwrap()
            .network_clock
            .sample(capability)
    }
}
