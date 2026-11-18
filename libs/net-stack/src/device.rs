//! Four RX/four TX borrowed local slots. No heap, hidden growth or automatic
//! retry of a submitted/uncertain transmission. Shared-memory retirement and
//! authenticated NIC results remain actual service-owner responsibilities.
use ev_net_device::packet::{MAX_FRAME_BYTES, MIN_FRAME_BYTES, MIN_RECEIVE_FRAME_BYTES};
use smoltcp::{phy, time::Instant};

pub const SLOTS: usize = 4;

pub struct Frame {
    bytes: [u8; MAX_FRAME_BYTES],
    len: usize,
}

impl Frame {
    pub const EMPTY: Self = Self {
        bytes: [0; MAX_FRAME_BYTES],
        len: 0,
    };
    fn clear(&mut self) {
        self.bytes.fill(0);
        self.len = 0;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Full,
    Busy,
    NoPending,
    Quarantined,
}

pub struct Queues<'a> {
    rx: &'a mut [Frame; SLOTS],
    tx: &'a mut [Frame; SLOTS],
    rx_head: usize,
    rx_count: usize,
    tx_head: usize,
    tx_count: usize,
    in_flight: bool,
    failed: bool,
}

impl<'a> Queues<'a> {
    /// New local owner only; externally accepted IPC/DMA work must already be
    /// quiescent before recycling the backing. No actual authority is minted.
    pub fn new(rx: &'a mut [Frame; SLOTS], tx: &'a mut [Frame; SLOTS]) -> Self {
        for slot in rx.iter_mut().chain(tx.iter_mut()) {
            slot.clear();
        }
        Self {
            rx,
            tx,
            rx_head: 0,
            rx_count: 0,
            tx_head: 0,
            tx_count: 0,
            in_flight: false,
            failed: false,
        }
    }

    pub fn enqueue_rx(&mut self, frame: &[u8]) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Quarantined);
        }
        if !(MIN_RECEIVE_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&frame.len()) {
            return Err(Error::Length);
        }
        if self.rx_count == SLOTS {
            return Err(Error::Full);
        }
        let slot = &mut self.rx[(self.rx_head + self.rx_count) % SLOTS];
        slot.bytes[..frame.len()].copy_from_slice(frame);
        slot.len = frame.len();
        self.rx_count += 1;
        Ok(())
    }

    /// Mark one queued frame before asking the actual driver to transmit it.
    /// It stays pinned until an actual completion or terminal uncertainty.
    pub fn begin_tx(&mut self) -> Result<Option<&[u8]>, Error> {
        if self.failed {
            return Err(Error::Quarantined);
        }
        if self.in_flight {
            return Err(Error::Busy);
        }
        if self.tx_count == 0 {
            return Ok(None);
        }
        self.in_flight = true;
        let slot = &self.tx[self.tx_head];
        Ok(Some(&slot.bytes[..slot.len]))
    }

    /// Call only after the independently authenticated actual driver completion.
    /// This is local queue bookkeeping, not a remote-delivery acknowledgement.
    pub fn complete_tx(&mut self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Quarantined);
        }
        if !self.in_flight {
            return Err(Error::NoPending);
        }
        self.tx[self.tx_head].clear();
        self.tx_head = (self.tx_head + 1) % SLOTS;
        self.tx_count -= 1;
        self.in_flight = false;
        Ok(())
    }

    /// Unknown/failed submission retains bytes and blocks automatic resubmission.
    pub fn quarantine(&mut self) {
        self.failed = true;
    }
    pub fn pending_tx(&self) -> usize {
        self.tx_count
    }
    pub fn pending_rx(&self) -> usize {
        self.rx_count
    }
}

pub struct Rx<'a> {
    slot: &'a mut Frame,
    head: &'a mut usize,
    count: &'a mut usize,
}
pub struct Tx<'a> {
    slot: &'a mut Frame,
    count: &'a mut usize,
}

impl phy::RxToken for Rx<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let result = f(&self.slot.bytes[..self.slot.len]);
        self.slot.clear();
        *self.head = (*self.head + 1) % SLOTS;
        *self.count -= 1;
        result
    }
}

impl phy::TxToken for Tx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // Non-fallible upstream token contract: only the trusted, MTU-bounded
        // stack invokes it. Application/IPC input never selects this len directly.
        assert!((14..=MAX_FRAME_BYTES).contains(&len));
        self.slot.clear();
        let result = f(&mut self.slot.bytes[..len]);
        self.slot.len = len.max(MIN_FRAME_BYTES); // zero Ethernet padding
        *self.count += 1;
        result
    }
}

impl phy::Device for Queues<'_> {
    type RxToken<'a>
        = Rx<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = Tx<'a>
    where
        Self: 'a;
    fn receive(&mut self, _: Instant) -> Option<(Rx<'_>, Tx<'_>)> {
        if self.failed || self.rx_count == 0 || self.tx_count == SLOTS {
            return None;
        }
        let tx_tail = (self.tx_head + self.tx_count) % SLOTS;
        Some((
            Rx {
                slot: &mut self.rx[self.rx_head],
                head: &mut self.rx_head,
                count: &mut self.rx_count,
            },
            Tx {
                slot: &mut self.tx[tx_tail],
                count: &mut self.tx_count,
            },
        ))
    }
    fn transmit(&mut self, _: Instant) -> Option<Tx<'_>> {
        if self.failed || self.tx_count == SLOTS {
            return None;
        }
        Some(Tx {
            slot: &mut self.tx[(self.tx_head + self.tx_count) % SLOTS],
            count: &mut self.tx_count,
        })
    }
    fn capabilities(&self) -> phy::DeviceCapabilities {
        let mut caps = phy::DeviceCapabilities::default();
        caps.medium = phy::Medium::Ethernet;
        caps.max_transmission_unit = MAX_FRAME_BYTES;
        caps.max_burst_size = Some(SLOTS);
        caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::{Device, RxToken, TxToken};

    #[test]
    fn small_stack_frames_are_zero_padded_before_actual_nic_submission() {
        let mut rx = [const { Frame::EMPTY }; SLOTS];
        let mut tx = [const { Frame::EMPTY }; SLOTS];
        let mut queues = Queues::new(&mut rx, &mut tx);
        queues
            .transmit(Instant::from_millis(0))
            .unwrap()
            .consume(42, |bytes| bytes.fill(0x6b));
        let frame = queues.begin_tx().unwrap().unwrap();
        assert_eq!(&frame[..42], &[0x6b; 42]);
        assert_eq!(&frame[42..], &[0; 18]);
        assert_eq!(queues.begin_tx(), Err(Error::Busy));
        queues.complete_tx().unwrap();
        assert_eq!(queues.pending_tx(), 0);
        assert_eq!(queues.complete_tx(), Err(Error::NoPending));
    }

    #[test]
    fn receive_preserves_short_virtual_frames_exactly_without_padding_or_truncation() {
        let mut rx = [const { Frame::EMPTY }; SLOTS];
        let mut tx = [const { Frame::EMPTY }; SLOTS];
        let mut queues = Queues::new(&mut rx, &mut tx);
        for len in [14, 54, 58, 1514] {
            let mut frame = [0; MAX_FRAME_BYTES];
            for (n, byte) in frame[..len].iter_mut().enumerate() {
                *byte = n as u8;
            }
            queues.enqueue_rx(&frame[..len]).unwrap();
            let (received, _) = queues.receive(Instant::from_millis(0)).unwrap();
            received.consume(|bytes| assert_eq!(bytes, &frame[..len]));
            assert_eq!(queues.pending_rx(), 0);
        }
        for len in [0, 13, 1515] {
            assert_eq!(queues.enqueue_rx(&[0; 1515][..len]), Err(Error::Length));
            assert_eq!(queues.pending_rx(), 0);
        }
    }

    #[test]
    fn saturation_preserves_frames_and_rx_requires_reply_headroom() {
        let mut rx = [const { Frame::EMPTY }; SLOTS];
        let mut tx = [const { Frame::EMPTY }; SLOTS];
        let mut queues = Queues::new(&mut rx, &mut tx);
        queues.enqueue_rx(&[1; 60]).unwrap();
        for value in 0..4 {
            queues
                .transmit(Instant::from_millis(0))
                .unwrap()
                .consume(60, |bytes| bytes.fill(value));
        }
        assert!(queues.transmit(Instant::from_millis(0)).is_none());
        assert!(queues.receive(Instant::from_millis(0)).is_none());
        assert_eq!(queues.pending_rx(), 1);
        for value in 0..4 {
            assert_eq!(queues.begin_tx().unwrap().unwrap(), &[value; 60]);
            queues.complete_tx().unwrap();
        }
        let (rx, _unused_tx) = queues.receive(Instant::from_millis(0)).unwrap();
        rx.consume(|bytes| assert_eq!(bytes, &[1; 60]));
        assert_eq!(queues.pending_rx(), 0);
        assert_eq!(queues.pending_tx(), 0);
    }

    #[test]
    fn unknown_submission_retains_its_bytes_and_blocks_automatic_retry() {
        let mut rx = [const { Frame::EMPTY }; SLOTS];
        let mut tx = [const { Frame::EMPTY }; SLOTS];
        let mut queues = Queues::new(&mut rx, &mut tx);
        queues
            .transmit(Instant::from_millis(0))
            .unwrap()
            .consume(60, |bytes| bytes.fill(9));
        assert_eq!(queues.begin_tx().unwrap().unwrap(), &[9; 60]);
        queues.quarantine();
        assert_eq!(queues.begin_tx(), Err(Error::Quarantined));
        assert_eq!(queues.complete_tx(), Err(Error::Quarantined));
        assert_eq!(queues.enqueue_rx(&[1; 60]), Err(Error::Quarantined));
        assert_eq!(queues.pending_tx(), 1);
        assert!(queues.transmit(Instant::from_millis(0)).is_none());
    }

    #[test]
    fn invalid_or_excess_rx_refuses_without_mutating_accepted_frames() {
        let mut rx = [const { Frame::EMPTY }; SLOTS];
        let mut tx = [const { Frame::EMPTY }; SLOTS];
        let mut queues = Queues::new(&mut rx, &mut tx);
        for value in 0..4 {
            queues.enqueue_rx(&[value; 60]).unwrap();
        }
        assert_eq!(queues.enqueue_rx(&[8; 60]), Err(Error::Full));
        assert_eq!(queues.enqueue_rx(&[8; 13]), Err(Error::Length));
        assert_eq!(queues.enqueue_rx(&[8; 1515]), Err(Error::Length));
        for value in 0..4 {
            let (rx, _unused_tx) = queues.receive(Instant::from_millis(0)).unwrap();
            rx.consume(|bytes| assert_eq!(bytes, &[value; 60]));
        }
        assert_eq!(queues.pending_rx(), 0);
    }
}
