//! Register and ring bounds for the explicitly selected QEMU ISA NE2000.
//!
//! "Remote DMA" below addresses the emulated device's private RAM. None of these
//! addresses are guest physical addresses, and no method grants an I/O permit.
use crate::packet::{MAX_FRAME_BYTES, MIN_FRAME_BYTES, MIN_RECEIVE_FRAME_BYTES};

pub const IO_BASE: u16 = 0x300;
pub const IO_BYTES: u16 = 0x20;
pub const DATA_OFFSET: u16 = 0x10;
pub const RESET_OFFSET: u16 = 0x1f;
pub const TX_PAGE: u8 = 0x40;
pub const RX_START: u8 = 0x46;
pub const RX_STOP: u8 = 0x80;
pub const PAGE_BYTES: u16 = 256;
pub const PACKET_RAM_BYTES: u16 = 0x4000;
pub const STOP_COMMAND: u8 = 0x21;
pub const START_COMMAND: u8 = 0x22;
pub const RESET_COMPLETED: u8 = 0x80;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    FrameLength,
    Page,
    Status,
    Count,
    NextPage,
    NotStopped,
    InvalidBudget,
    TimedOut,
    ClockRegression,
    Exhausted,
    Stale,
    Busy,
    Quarantined,
}

/// One bounded device-local read. An RX frame may wrap into a second span.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub address: u16,
    pub bytes: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receive {
    pub frame_bytes: u16,
    pub first: Span,
    pub second: Option<Span>,
    /// Acknowledge this page only after all validated bytes were copied.
    pub boundary: u8,
    pub next_page: u8,
}

pub fn transmit(frame_bytes: usize) -> Result<Span, Error> {
    if !(MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&frame_bytes) {
        return Err(Error::FrameLength);
    }
    Ok(Span {
        address: u16::from(TX_PAGE) * PAGE_BYTES,
        bytes: frame_bytes as u16,
    })
}

fn valid_page(page: u8) -> bool {
    (RX_START..RX_STOP).contains(&page)
}

/// Validate the actual four-byte device header before deriving a data transfer.
/// The selected QEMU model stores count=frame+4 and reserves header+frame+4
/// bytes rounded up to a page. Do not substitute a physical NIC's convention.
pub fn receive(page: u8, current: u8, header: [u8; 4]) -> Result<Receive, Error> {
    if !valid_page(page) || !valid_page(current) {
        return Err(Error::Page);
    }
    // RXOK, optionally physical/multicast. Every error/reserved bit refuses.
    if header[0] & !0x20 != 1 {
        return Err(Error::Status);
    }
    let count = u16::from_le_bytes([header[2], header[3]]);
    let frame_bytes = count.checked_sub(4).ok_or(Error::Count)?;
    if !(MIN_RECEIVE_FRAME_BYTES as u16..=MAX_FRAME_BYTES as u16).contains(&frame_bytes) {
        return Err(Error::Count);
    }
    let pages = (count + 4).div_ceil(PAGE_BYTES);
    let ring_pages = u16::from(RX_STOP - RX_START);
    let expected = RX_START + ((u16::from(page - RX_START) + pages) % ring_pages) as u8;
    if header[1] != expected {
        return Err(Error::NextPage);
    }
    // A corrupt count must not cross the current producer into unwritten RAM.
    let available =
        (u16::from(current - RX_START) + ring_pages - u16::from(page - RX_START)) % ring_pages;
    if pages > available || available == 0 {
        return Err(Error::NextPage);
    }
    let start = u16::from(page) * PAGE_BYTES + 4;
    let first_bytes = frame_bytes.min(u16::from(RX_STOP) * PAGE_BYTES - start);
    let remaining = frame_bytes - first_bytes;
    Ok(Receive {
        frame_bytes,
        first: Span {
            address: start,
            bytes: first_bytes,
        },
        second: (remaining != 0).then_some(Span {
            address: u16::from(RX_START) * PAGE_BYTES,
            bytes: remaining,
        }),
        boundary: if expected == RX_START {
            RX_STOP - 1
        } else {
            expected - 1
        },
        next_page: expected,
    })
}

/// An explicit stop sequence, not a claim that reading RESET stopped anything.
/// The caller first fences dispatch and revokes the old holder, then obtains
/// exclusive device authority for these byte writes and verifies command STOP.
/// Scrubbing/reinitialization follows separately before restart/remint.
pub const STOP_WRITES: [(u8, u8); 6] = [
    (0x00, STOP_COMMAND),
    (0x0f, 0), // mask device interrupts
    (0x0a, 0), // abort/reset remote byte count
    (0x0b, 0),
    (0x0c, 0x20), // monitor mode; STOP is the actual receive fence
    (0x07, 0x7f), // acknowledge old status, preserving RESET semantics
];

pub fn verify_stopped(command: u8) -> Result<(), Error> {
    if command == STOP_COMMAND {
        Ok(())
    } else {
        Err(Error::NotStopped)
    }
}

/// A finite poll guard: no mutable wall time, wrapping, or renewed retry deadline.
pub struct PollBudget {
    deadline: u64,
    last: u64,
    remaining: u32,
    failure: Option<Error>,
}

impl PollBudget {
    pub fn new(now: u64, ticks: u64, max_polls: u32) -> Result<Self, Error> {
        if ticks == 0 || max_polls == 0 {
            return Err(Error::InvalidBudget);
        }
        Ok(Self {
            deadline: now.checked_add(ticks).ok_or(Error::InvalidBudget)?,
            last: now,
            remaining: max_polls,
            failure: None,
        })
    }

    /// Call before every status read, even after a transport reports Busy.
    pub fn before_poll(&mut self, now: u64) -> Result<(), Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if now < self.last {
            self.failure = Some(Error::ClockRegression);
            return Err(Error::ClockRegression);
        }
        self.last = now;
        if now >= self.deadline || self.remaining == 0 {
            self.failure = Some(Error::TimedOut);
            return Err(Error::TimedOut);
        }
        self.remaining -= 1;
        Ok(())
    }
}

/// One accepted local transmit at a time. Completion never implies remote
/// delivery; a timeout quarantines the incarnation until stop/reset/recreation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transfer {
    incarnation: u64,
    sequence: u64,
}

pub struct Transmitter {
    incarnation: u64,
    next: u64,
    pending: Option<Transfer>,
    quarantined: bool,
}

impl Transmitter {
    pub fn new(incarnation: u64) -> Result<Self, Error> {
        if incarnation == 0 {
            return Err(Error::Stale);
        }
        Ok(Self {
            incarnation,
            next: 1,
            pending: None,
            quarantined: false,
        })
    }

    /// Reserve before the first mutating device operation. On an uncertain I/O
    /// result, quarantine rather than retrying an accepted transmit command.
    pub fn begin(&mut self, bytes: usize) -> Result<Transfer, Error> {
        if self.quarantined {
            return Err(Error::Quarantined);
        }
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        transmit(bytes)?;
        let next = self.next.checked_add(1).ok_or(Error::Exhausted)?;
        let transfer = Transfer {
            incarnation: self.incarnation,
            sequence: self.next,
        };
        self.next = next;
        self.pending = Some(transfer);
        Ok(transfer)
    }

    pub fn complete(&mut self, transfer: Transfer, isr: u8, tsr: u8) -> Result<(), Error> {
        if self.quarantined {
            return Err(Error::Quarantined);
        }
        if self.pending != Some(transfer) {
            return Err(Error::Stale);
        }
        if isr & 0x0a != 0x02 || tsr & 0xf9 != 0x01 {
            self.quarantined = true;
            return Err(Error::Status);
        }
        self.pending = None;
        Ok(())
    }

    pub fn quarantine(&mut self) {
        self.quarantined = true;
    }
}
