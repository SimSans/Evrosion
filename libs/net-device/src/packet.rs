//! Fixed packet storage with explicit saturation and incarnation-safe handles.
//!
//! This is local userspace storage. Retiring it is not a DMA/Memory Object
//! quiescence witness; externally shared memory needs its own lifetime protocol.

/// Untagged Ethernet frame including its header, excluding the Ethernet FCS.
pub const MAX_FRAME_BYTES: usize = 1514;
/// Minimum complete Ethernet header accepted from the selected virtual NIC.
/// QEMU preserves a backend's exact received length, including short TCP/ARP
/// frames without physical-wire padding. Never invent padding on receive.
pub const MIN_RECEIVE_FRAME_BYTES: usize = 14;
/// Minimum transmitted Ethernet frame, excluding FCS; TX owners zero-pad.
pub const MIN_FRAME_BYTES: usize = 60;
pub const PACKET_SLOTS: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    FrameLength,
    Full,
    Stale,
    Retired,
    Exhausted,
    InvalidIncarnation,
}

/// Opaque local reference. A copied/stale reference never authorizes slot reuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket {
    incarnation: u64,
    generation: u64,
    slot: u8,
}

struct Slot {
    bytes: [u8; MAX_FRAME_BYTES],
    len: usize,
    generation: u64,
}

impl Slot {
    const EMPTY: Self = Self {
        bytes: [0; MAX_FRAME_BYTES],
        len: 0,
        generation: 0,
    };
}

/// Exactly four packets: bounded storage and bounded lookup; no hidden queue.
pub struct Pool {
    slots: [Slot; PACKET_SLOTS],
    incarnation: u64,
    next_generation: u64,
    retired: bool,
}

impl Pool {
    /// The caller obtains the nonzero incarnation from its actual lifecycle.
    /// A number supplied by an untrusted peer cannot authenticate a pool.
    pub fn new(incarnation: u64) -> Result<Self, Error> {
        if incarnation == 0 {
            return Err(Error::InvalidIncarnation);
        }
        Ok(Self {
            slots: [const { Slot::EMPTY }; PACKET_SLOTS],
            incarnation,
            next_generation: 1,
            retired: false,
        })
    }

    /// Copies one already validated untagged frame into owned local storage.
    /// All refusals leave every existing packet and generation unchanged.
    pub fn insert(&mut self, frame: &[u8]) -> Result<Ticket, Error> {
        if self.retired {
            return Err(Error::Retired);
        }
        if !(MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&frame.len()) {
            return Err(Error::FrameLength);
        }
        let next = self
            .next_generation
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        let index = self
            .slots
            .iter()
            .position(|slot| slot.len == 0)
            .ok_or(Error::Full)?;
        let slot = &mut self.slots[index];
        slot.bytes[..frame.len()].copy_from_slice(frame);
        slot.len = frame.len();
        slot.generation = self.next_generation;
        self.next_generation = next;
        Ok(Ticket {
            incarnation: self.incarnation,
            generation: slot.generation,
            slot: index as u8,
        })
    }

    fn index(&self, ticket: Ticket) -> Result<usize, Error> {
        if self.retired {
            return Err(Error::Retired);
        }
        let index = usize::from(ticket.slot);
        let slot = self.slots.get(index).ok_or(Error::Stale)?;
        if ticket.incarnation != self.incarnation
            || slot.len == 0
            || ticket.generation != slot.generation
        {
            return Err(Error::Stale);
        }
        Ok(index)
    }

    pub fn get(&self, ticket: Ticket) -> Result<&[u8], Error> {
        let index = self.index(ticket)?;
        let slot = &self.slots[index];
        Ok(&slot.bytes[..slot.len])
    }

    /// Completion/cancel releases only this exact packet. Scrub before reuse.
    pub fn release(&mut self, ticket: Ticket) -> Result<(), Error> {
        let index = self.index(ticket)?;
        let slot = &mut self.slots[index];
        slot.bytes.fill(0);
        slot.len = 0;
        Ok(())
    }

    pub fn pending(&self) -> usize {
        self.slots.iter().filter(|slot| slot.len != 0).count()
    }

    /// Close this local owner permanently and scrub all locally owned packets.
    /// Existing borrows prevent simultaneous access; no shared/device memory is
    /// reclaimed by this operation. A replacement needs a fresh actual identity.
    pub fn retire(&mut self) {
        self.retired = true;
        for slot in &mut self.slots {
            slot.bytes.fill(0);
            slot.len = 0;
        }
    }
}

#[cfg(test)]
impl Pool {
    pub(crate) fn set_generation_for_test(&mut self, generation: u64) {
        self.next_generation = generation;
    }

    pub(crate) fn all_scrubbed(&self) -> bool {
        self.slots
            .iter()
            .all(|slot| slot.bytes.iter().all(|byte| *byte == 0))
    }
}
