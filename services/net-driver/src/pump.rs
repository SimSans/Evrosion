//! One actual driver route/window and one TX/RX per stack turn. This is not a
//! transport engine: the executable adapter uses the existing protected RPC
//! call and the Kernel's accepted-work retirement. Unknown results pin bytes.
use crate::protocol::{Failure, Notice, Operation, Packet, Status, Window};
use ev_net_stack::stack::Stack;

pub trait Transport {
    type Error;
    /// Implement with the canonical protected RPC transport. The exact window
    /// stays owned until this returns; never reissue an accepted unknown call.
    fn call(&mut self, request: [u8; 8], deadline: u64) -> Result<[u8; 8], Self::Error>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error<W, T> {
    Quarantined,
    Counter,
    Window(Failure<W>),
    Transport(T),
    Response,
    Remote(Status),
    Stack(ev_net_stack::stack::Error),
    Queue(ev_net_stack::device::Error),
}
pub type PollResult<'a, W, T> = Result<Option<&'a [u8]>, Error<W, T>>;

pub struct Client<W, T> {
    window: W,
    transport: T,
    sequence: u32,
    transmit_sequence: u64,
    failed: bool,
    stop_cut: Option<u64>,
    stop_done: u16,
}
impl<W: Window, T: Transport> Client<W, T> {
    /// Actual owner supplies the distinct live NICWindow and its scoped route.
    /// One client exclusively owns them for this driver incarnation.
    pub fn new(window: W, transport: T) -> Self {
        Self {
            window,
            transport,
            sequence: 0,
            transmit_sequence: 0,
            failed: false,
            stop_cut: None,
            stop_done: 0,
        }
    }
    pub fn quarantined(&self) -> bool {
        self.failed
    }
    fn request(
        &mut self,
        operation: Operation,
        data: &[u8],
        deadline: u64,
        packet: &mut Packet,
    ) -> Result<Status, Error<W::Error, T::Error>> {
        if self.failed {
            return Err(Error::Quarantined);
        }
        if self.stop_cut.is_some() && !matches!(operation, Operation::StopStep) {
            return Err(Error::Quarantined);
        }
        // Latch before any window mutation or possible acceptance. Only an
        // exact joined response below returns this owner to reusable state.
        self.failed = true;
        self.sequence = self
            .sequence
            .checked_add(1)
            .filter(|n| *n != u32::MAX)
            .ok_or(Error::Counter)?;
        let notice = Notice {
            operation,
            sequence: self.sequence,
        };
        packet
            .write_request(&mut self.window, notice, data)
            .map_err(Error::Window)?;
        let response = self
            .transport
            .call(notice.encode().map_err(|_| Error::Response)?, deadline)
            .map_err(Error::Transport)?;
        let status = notice
            .response_status(response)
            .map_err(|_| Error::Response)?;
        packet
            .read_response(&mut self.window, notice, status)
            .map_err(Error::Window)?;
        if !matches!(status, Status::Complete | Status::Empty | Status::Progress) {
            return Err(Error::Remote(status));
        }
        self.failed = false;
        Ok(status)
    }
    pub fn start(
        &mut self,
        deadline: u64,
        packet: &mut Packet,
    ) -> Result<(), Error<W::Error, T::Error>> {
        self.request(Operation::Start, &[], deadline, packet)
            .map(|_| ())
    }
    pub fn stop(
        &mut self,
        deadline: u64,
        packet: &mut Packet,
    ) -> Result<(), Error<W::Error, T::Error>> {
        self.request(Operation::Stop, &[], deadline, packet)
            .map(|_| ())
    }
    pub fn stop_begin(
        &mut self,
        aggregate: u64,
        deadline: u64,
        packet: &mut Packet,
    ) -> Result<(), Error<W::Error, T::Error>> {
        if self.stop_cut.is_some() || deadline > aggregate {
            return Err(Error::Quarantined);
        }
        let status = self.request(
            Operation::StopBegin,
            &aggregate.to_le_bytes(),
            deadline,
            packet,
        )?;
        let progress = crate::device::StopProgress::decode(packet.payload()).ok_or_else(|| {
            self.failed = true;
            Error::Response
        })?;
        if status != Status::Progress || progress.done != 0 {
            self.failed = true;
            return Err(Error::Response);
        }
        self.stop_cut = Some(aggregate);
        self.stop_done = 0;
        Ok(())
    }
    pub fn stop_step(
        &mut self,
        deadline: u64,
        packet: &mut Packet,
    ) -> Result<bool, Error<W::Error, T::Error>> {
        let cut = self.stop_cut.ok_or(Error::Quarantined)?;
        if deadline > cut || self.stop_done == ev_net_device::ne2000::PACKET_RAM_BYTES {
            return Err(Error::Quarantined);
        }
        let status = self.request(Operation::StopStep, &[], deadline, packet)?;
        let progress = crate::device::StopProgress::decode(packet.payload()).ok_or_else(|| {
            self.failed = true;
            Error::Response
        })?;
        if self.stop_done.checked_add(crate::device::STOP_CHUNK_BYTES) != Some(progress.done)
            || (status == Status::Complete) != progress.complete()
            || !matches!(status, Status::Complete | Status::Progress)
        {
            self.failed = true;
            return Err(Error::Response);
        }
        self.stop_done = progress.done;
        Ok(progress.complete())
    }
    pub fn transmit(
        &mut self,
        frame: &[u8],
        deadline: u64,
        packet: &mut Packet,
    ) -> Result<(), Error<W::Error, T::Error>> {
        self.request(Operation::Transmit, frame, deadline, packet)?;
        let response = packet.payload();
        let sequence = u64::from_le_bytes(response[..8].try_into().unwrap());
        let bytes = usize::from(u16::from_le_bytes(response[8..10].try_into().unwrap()));
        if self.transmit_sequence.checked_add(1) != Some(sequence) || bytes != frame.len() {
            self.failed = true;
            return Err(Error::Response);
        }
        self.transmit_sequence = sequence;
        Ok(())
    }
    pub fn poll<'a>(
        &mut self,
        deadline: u64,
        packet: &'a mut Packet,
    ) -> PollResult<'a, W::Error, T::Error> {
        match self.request(Operation::Poll, &[], deadline, packet)? {
            Status::Complete => Ok(Some(packet.payload())),
            Status::Empty => Ok(None),
            _ => unreachable!(),
        }
    }
}

pub struct Pump<W, T> {
    driver: Client<W, T>,
    packet: Packet,
    operation: u8,
}
impl<W: Window, T: Transport> Pump<W, T> {
    pub fn new(driver: Client<W, T>) -> Self {
        Self {
            driver,
            packet: Packet::new(),
            operation: 0,
        }
    }
    pub fn operation(&self) -> u8 {
        self.operation
    }
    pub fn stop_cut(&self) -> Option<u64> {
        self.driver.stop_cut
    }
    pub fn start(&mut self, deadline: u64) -> Result<(), Error<W::Error, T::Error>> {
        self.operation = Operation::Start as u8;
        self.driver.start(deadline, &mut self.packet)
    }
    pub fn stop(&mut self, deadline: u64) -> Result<(), Error<W::Error, T::Error>> {
        self.operation = Operation::Stop as u8;
        self.driver.stop(deadline, &mut self.packet)
    }
    pub fn stop_begin(
        &mut self,
        aggregate: u64,
        deadline: u64,
    ) -> Result<(), Error<W::Error, T::Error>> {
        self.operation = Operation::StopBegin as u8;
        self.driver
            .stop_begin(aggregate, deadline, &mut self.packet)
    }
    pub fn stop_step(&mut self, deadline: u64) -> Result<bool, Error<W::Error, T::Error>> {
        self.operation = Operation::StopStep as u8;
        self.driver.stop_step(deadline, &mut self.packet)
    }
    /// `now_millis` comes from the actual same-boot monotonic provider. The
    /// executable yields between turns and supplies the actual enclosing bound.
    pub fn turn(
        &mut self,
        stack: &mut Stack<'_>,
        now_millis: u64,
        deadline: u64,
    ) -> Result<(), Error<W::Error, T::Error>> {
        if self.driver.stop_cut.is_some() {
            return Err(Error::Quarantined);
        }
        self.operation = 0;
        stack.turn(now_millis).map_err(Error::Stack)?;
        if let Some(frame) = stack.device().begin_tx().map_err(Error::Queue)? {
            self.operation = Operation::Transmit as u8;
            if let Err(error) = self.driver.transmit(frame, deadline, &mut self.packet) {
                stack.device().quarantine();
                return Err(error);
            }
            stack.device().complete_tx().map_err(Error::Queue)?;
        }
        // Preserve accepted local packets under pressure; do not consume and
        // drop a driver frame when there is no private RX slot available.
        if stack.device().pending_rx() < ev_net_stack::device::SLOTS {
            self.operation = Operation::Poll as u8;
            match self.driver.poll(deadline, &mut self.packet) {
                Ok(Some(frame)) => stack.device().enqueue_rx(frame).map_err(Error::Queue)?,
                Ok(None) => {}
                Err(error) => {
                    stack.device().quarantine();
                    return Err(error);
                }
            }
        }
        Ok(())
    }
}

/// Actual source adapter: all retry/acceptance/retirement semantics are owned
/// by the existing runtime and Kernel, never inferred from shared packet bytes.
pub struct ProtectedRpc {
    endpoint: u64,
}
impl ProtectedRpc {
    pub fn new(endpoint: u64) -> Option<Self> {
        (endpoint != 0).then_some(Self { endpoint })
    }
}
impl Transport for ProtectedRpc {
    type Error = ev_userspace_runtime::rpc::Error;
    fn call(&mut self, request: [u8; 8], deadline: u64) -> Result<[u8; 8], Self::Error> {
        ev_userspace_runtime::rpc::call(self.endpoint, request, deadline)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{cell::RefCell, rc::Rc, vec::Vec};
    struct Memory {
        data: [u8; 4096],
        writes: usize,
        calls: usize,
        transmitted: Vec<Vec<u8>>,
    }
    #[derive(Clone)]
    struct Shared(Rc<RefCell<Memory>>);
    impl Window for Shared {
        type Error = ();
        fn read(&mut self, n: usize) -> Result<u8, ()> {
            self.0.borrow().data.get(n).copied().ok_or(())
        }
        fn write(&mut self, n: usize, b: u8) -> Result<(), ()> {
            let mut memory = self.0.borrow_mut();
            *memory.data.get_mut(n).ok_or(())? = b;
            memory.writes += 1;
            Ok(())
        }
    }
    struct Remote {
        memory: Shared,
        fail: bool,
        wrong_length: bool,
        tx: u64,
        received: Option<Vec<u8>>,
        stop_done: u16,
        wrong_stop: bool,
    }
    impl Transport for Remote {
        type Error = u8;
        fn call(&mut self, bytes: [u8; 8], _: u64) -> Result<[u8; 8], u8> {
            self.memory.0.borrow_mut().calls += 1;
            if self.fail {
                return Err(9);
            }
            let notice = Notice::decode(bytes).unwrap();
            let mut packet = Packet::new();
            packet.read_request(&mut self.memory, notice).unwrap();
            let status = match notice.operation {
                Operation::StopBegin | Operation::StopStep => {
                    if notice.operation == Operation::StopBegin {
                        assert_eq!(packet.payload(), &8192u64.to_le_bytes());
                        self.stop_done = 0;
                    } else {
                        self.stop_done += crate::device::STOP_CHUNK_BYTES;
                    }
                    let done = self.stop_done + if self.wrong_stop { 128 } else { 0 };
                    packet.payload[..8]
                        .copy_from_slice(&crate::device::StopProgress { done }.encode());
                    packet.length = 8;
                    if done == 16384 {
                        Status::Complete
                    } else {
                        Status::Progress
                    }
                }
                Operation::Transmit => {
                    self.memory
                        .0
                        .borrow_mut()
                        .transmitted
                        .push(packet.payload().to_vec());
                    let length = packet.payload().len() as u16 + u16::from(self.wrong_length);
                    self.tx += 1;
                    packet.payload[..16].fill(0);
                    packet.payload[..8].copy_from_slice(&self.tx.to_le_bytes());
                    packet.payload[8..10].copy_from_slice(&length.to_le_bytes());
                    packet.length = 16;
                    Status::Complete
                }
                Operation::Poll => {
                    if let Some(frame) = self.received.take() {
                        packet.payload[..frame.len()].copy_from_slice(&frame);
                        packet.length = frame.len();
                        Status::Complete
                    } else {
                        packet.length = 0;
                        Status::Empty
                    }
                }
                _ => {
                    packet.length = 0;
                    Status::Complete
                }
            };
            packet.publish(&mut self.memory, notice, status).unwrap();
            Ok(notice.response(status))
        }
    }
    fn fixture(fail: bool, wrong_length: bool) -> (Shared, Client<Shared, Remote>) {
        let memory = Shared(Rc::new(RefCell::new(Memory {
            data: [0; 4096],
            writes: 0,
            calls: 0,
            transmitted: Vec::new(),
        })));
        let remote = Remote {
            memory: memory.clone(),
            fail,
            wrong_length,
            tx: 0,
            received: None,
            stop_done: 0,
            wrong_stop: false,
        };
        (memory.clone(), Client::new(memory, remote))
    }
    #[test]
    fn unknown_accepted_result_pins_window_and_never_reissues_or_rewrites() {
        let (memory, mut client) = fixture(true, false);
        let mut packet = Packet::new();
        assert_eq!(
            client.transmit(&[1; 60], 20, &mut packet),
            Err(Error::Transport(9))
        );
        let writes = memory.0.borrow().writes;
        assert_eq!(
            client.transmit(&[2; 60], 30, &mut packet),
            Err(Error::Quarantined)
        );
        assert_eq!(client.poll(40, &mut packet), Err(Error::Quarantined));
        assert_eq!(memory.0.borrow().calls, 1);
        assert_eq!(memory.0.borrow().writes, writes);
    }
    #[test]
    fn only_exact_joined_tx_completion_releases_local_submission() {
        let (_, mut good) = fixture(false, false);
        let mut packet = Packet::new();
        good.start(10, &mut packet).unwrap();
        good.transmit(&[1; 60], 20, &mut packet).unwrap();
        good.transmit(&[2; 61], 30, &mut packet).unwrap();
        assert_eq!(good.poll(40, &mut packet), Ok(None));
        let (memory, mut wrong) = fixture(false, true);
        assert_eq!(
            wrong.transmit(&[1; 60], 20, &mut packet),
            Err(Error::Response)
        );
        assert!(wrong.quarantined());
        assert_eq!(
            wrong.transmit(&[1; 60], 30, &mut packet),
            Err(Error::Quarantined)
        );
        assert_eq!(memory.0.borrow().calls, 1);
    }
    #[test]
    fn actual_stack_discover_pumps_once_and_unknown_tx_retains_its_private_slot() {
        use ev_net_stack::stack::{Stack, Storage};
        let mut storage = Storage::EMPTY;
        let mut stack = Stack::new(9, crate::REFERENCE_MAC, 123, 0, storage.buffers()).unwrap();
        let (memory, driver) = fixture(false, false);
        let mut pump = Pump::new(driver);
        pump.start(100).unwrap();
        pump.turn(&mut stack, 0, 100).unwrap();
        {
            let actual = memory.0.borrow();
            assert_eq!(actual.calls, 3); // Start, one actual frame, one Poll.
            assert_eq!(actual.transmitted.len(), 1);
            let frame = &actual.transmitted[0];
            assert_eq!(&frame[..6], &[255; 6]);
            assert_eq!(&frame[6..12], &crate::REFERENCE_MAC);
            assert_eq!(&frame[34..38], &[0, 68, 0, 67]);
            assert_eq!(&frame[278..282], &[0x63, 0x82, 0x53, 0x63]);
        }
        assert_eq!(stack.device().pending_tx(), 0);
        assert_eq!(stack.lease(), None); // TX is not address configuration.

        let mut storage = Storage::EMPTY;
        let mut stack = Stack::new(10, crate::REFERENCE_MAC, 124, 0, storage.buffers()).unwrap();
        let (memory, driver) = fixture(false, false);
        let mut pump = Pump::new(driver);
        pump.start(100).unwrap();
        pump.driver.transport.fail = true;
        assert_eq!(pump.turn(&mut stack, 0, 100), Err(Error::Transport(9)));
        assert_eq!(pump.operation(), Operation::Transmit as u8);
        assert_eq!(stack.device().pending_tx(), 1);
        assert_eq!(memory.0.borrow().calls, 2); // No subsequent Poll or retry.
        assert!(pump.turn(&mut stack, 1, 100).is_err());
        assert_eq!(memory.0.borrow().calls, 2);
        assert_eq!(stack.device().pending_tx(), 1);
    }

    #[test]
    fn short_complete_driver_packets_reach_the_real_stack_queue_without_quarantine() {
        use ev_net_stack::stack::{Stack, Storage};
        for len in [14, 54, 58, 1514] {
            let mut storage = Storage::EMPTY;
            let mut stack = Stack::new(9, crate::REFERENCE_MAC, 123, 0, storage.buffers()).unwrap();
            let (_, mut driver) = fixture(false, false);
            driver.transport.received = Some(std::vec![0x6b; len]);
            let mut pump = Pump::new(driver);
            pump.start(100).unwrap();
            pump.turn(&mut stack, 0, 100).unwrap();
            assert_eq!(stack.device().pending_rx(), 1);
            assert!(!pump.driver.quarantined());
        }
        let mut storage = Storage::EMPTY;
        let mut stack = Stack::new(9, crate::REFERENCE_MAC, 123, 0, storage.buffers()).unwrap();
        let (_, mut driver) = fixture(false, false);
        driver.transport.received = Some(std::vec![0x6b; 13]);
        let mut pump = Pump::new(driver);
        pump.start(100).unwrap();
        assert!(pump.turn(&mut stack, 0, 100).is_err());
        assert_eq!(pump.operation(), Operation::Poll as u8);
        assert!(pump.driver.quarantined());
        assert_eq!(stack.device().pending_rx(), 0);
    }

    #[test]
    fn stop_continuation_joins_every_cursor_and_blocks_stack_pumping_and_cut_replacement() {
        let (memory, driver) = fixture(false, false);
        let mut pump = Pump::new(driver);
        let before = memory.0.borrow().calls;
        assert!(pump.stop_step(512).is_err());
        assert_eq!(memory.0.borrow().calls, before);
        pump.stop_begin(8192, 512).unwrap();
        assert_eq!(pump.stop_cut(), Some(8192));
        let mut storage = ev_net_stack::stack::Storage::EMPTY;
        let mut stack = Stack::new(9, crate::REFERENCE_MAC, 123, 0, storage.buffers()).unwrap();
        let calls = memory.0.borrow().calls;
        assert!(pump.turn(&mut stack, 0, 512).is_err());
        assert_eq!(stack.device().pending_tx(), 0);
        assert!(pump.stop_begin(8193, 512).is_err());
        assert!(pump.stop_step(8193).is_err());
        assert_eq!(memory.0.borrow().calls, calls);
        for n in 1..=128 {
            assert_eq!(pump.stop_step(512).unwrap(), n == 128);
        }
        let calls = memory.0.borrow().calls;
        assert_eq!(calls, 129);
        assert!(pump.stop_step(512).is_err());
        assert_eq!(memory.0.borrow().calls, calls);
    }

    #[test]
    fn lost_stop_ack_or_wrong_cursor_pins_original_bytes_without_accepted_retry() {
        for unknown in [false, true] {
            let (memory, driver) = fixture(false, false);
            let mut pump = Pump::new(driver);
            pump.stop_begin(8192, 512).unwrap();
            pump.driver.transport.fail = unknown;
            pump.driver.transport.wrong_stop = !unknown;
            assert!(pump.stop_step(512).is_err());
            assert!(pump.driver.quarantined());
            let before = (memory.0.borrow().calls, memory.0.borrow().writes);
            assert!(pump.stop_step(512).is_err());
            assert!(pump.stop_begin(8192, 512).is_err());
            assert_eq!((memory.0.borrow().calls, memory.0.borrow().writes), before);
        }
    }
}
