//! Scalar transport stays in the existing runtime. This reducer runs only after
//! actual protected receive and preserves the captured reply nonce externally.
use crate::{
    REFERENCE_MAC,
    device::{Driver, Error as DeviceError, Ports, Progress, State},
    protocol::{Failure, Notice, Operation, Packet, Status, Window},
};

pub struct Service<P: Ports> {
    driver: Driver<P>,
    sequence: u32,
    last_failure: Option<(Operation, crate::device::Failure<P::Error>)>,
}
impl<P: Ports> Service<P> {
    pub fn new(ports: P) -> Self {
        Self {
            driver: Driver::new(ports),
            sequence: 0,
            last_failure: None,
        }
    }
    pub fn state(&self) -> State {
        self.driver.state()
    }
    /// A diagnostic projection is taken only after the caller has completed
    /// its actual protected reply. This never permits device/window reuse.
    pub fn take_failure(&mut self) -> Option<(Operation, crate::device::Failure<P::Error>)> {
        self.last_failure.take()
    }
    /// Cold startup outside accepted client work; publish actual Prepared only
    /// after all real initialization/readback completes. Caller supplies a real
    /// finite startup deadline; this does not manufacture a protected RPC context.
    pub fn prepare(&mut self, deadline: u64) -> Result<(), crate::device::Failure<P::Error>> {
        self.driver.initialize(REFERENCE_MAC, deadline)
    }
    pub fn handle<W: Window>(
        &mut self,
        window: &mut W,
        notice: Notice,
        deadline: u64,
        packet: &mut Packet,
    ) -> Result<[u8; 8], Failure<W::Error>> {
        notice.encode().map_err(Failure::Frame)?;
        if self.sequence.checked_add(1) != Some(notice.sequence) {
            packet.length = 0;
            packet.publish(window, notice, Status::Stale)?;
            return Ok(notice.response(Status::Stale));
        }
        match packet.read_request(window, notice) {
            Ok(()) => {}
            Err(Failure::Frame(_)) => {
                packet.length = 0;
                packet.publish(window, notice, Status::Malformed)?;
                return Ok(notice.response(Status::Malformed));
            }
            Err(error) => return Err(error),
        }
        self.sequence = notice.sequence;
        let result = match notice.operation {
            Operation::Initialize => self.driver.initialize(REFERENCE_MAC, deadline),
            Operation::Start => self.driver.start(deadline),
            Operation::Stop => self.driver.stop_and_scrub(deadline),
            Operation::StopBegin | Operation::StopStep => {
                let result = if notice.operation == Operation::StopBegin {
                    self.driver.stop_begin(
                        u64::from_le_bytes(packet.payload()[..8].try_into().unwrap()),
                        deadline,
                    )
                } else {
                    self.driver.stop_step(deadline)
                };
                match result {
                    Ok(progress) => {
                        packet.payload[..8].copy_from_slice(&progress.encode());
                        packet.length = 8;
                        let status = if progress.complete() {
                            Status::Complete
                        } else {
                            Status::Progress
                        };
                        packet.publish(window, notice, status)?;
                        return Ok(notice.response(status));
                    }
                    Err(e) => Err(e),
                }
            }
            Operation::Transmit => match self.driver.transmit(packet.payload(), deadline) {
                Ok(receipt) => {
                    packet.payload[..16].fill(0);
                    packet.payload[..8].copy_from_slice(&receipt.sequence.to_le_bytes());
                    packet.payload[8..10].copy_from_slice(&receipt.bytes.to_le_bytes());
                    packet.length = 16;
                    packet.publish(window, notice, Status::Complete)?;
                    return Ok(notice.response(Status::Complete));
                }
                Err(error) => Err(error),
            },
            Operation::Poll => match self.driver.receive(&mut packet.payload, deadline) {
                Ok(Some(length)) => {
                    packet.length = length;
                    packet.publish(window, notice, Status::Complete)?;
                    return Ok(notice.response(Status::Complete));
                }
                Ok(None) => {
                    packet.length = 0;
                    packet.publish(window, notice, Status::Empty)?;
                    return Ok(notice.response(Status::Empty));
                }
                Err(error) => Err(error),
            },
        };
        packet.length = 0;
        let status = match result {
            Ok(()) => Status::Complete,
            Err(failure) => {
                let status = if failure.progress == Progress::MayHaveSubmitted {
                    Status::Uncertain
                } else if matches!(
                    failure.error,
                    DeviceError::State
                        | DeviceError::Protocol(ev_net_device::ne2000::Error::FrameLength)
                ) {
                    Status::Refused
                } else {
                    Status::Quarantined
                };
                if self.last_failure.is_none() {
                    self.last_failure = Some((notice.operation, failure));
                }
                status
            }
        };
        packet.publish(window, notice, status)?;
        Ok(notice.response(status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct NoIo;
    impl Ports for NoIo {
        type Error = ();
        fn input(&mut self, _: u16) -> Result<u8, ()> {
            panic!("refused frame must not touch ports")
        }
        fn output(&mut self, _: u16, _: u8) -> Result<(), ()> {
            panic!("refused frame must not touch ports")
        }
        fn now(&mut self) -> Result<u64, ()> {
            panic!("refused frame must not touch clock")
        }
        fn yield_now(&mut self) -> Result<(), ()> {
            panic!("refused frame must not yield")
        }
    }
    struct Memory([u8; 4096]);
    impl Window for Memory {
        type Error = ();
        fn read(&mut self, n: usize) -> Result<u8, ()> {
            self.0.get(n).copied().ok_or(())
        }
        fn write(&mut self, n: usize, b: u8) -> Result<(), ()> {
            *self.0.get_mut(n).ok_or(())? = b;
            Ok(())
        }
    }
    #[test]
    fn malformed_replayed_and_skipped_work_never_reexecutes_device_operations() {
        let mut service = Service::new(NoIo);
        let mut memory = Memory([0; 4096]);
        let mut packet = Packet::new();
        let notice = Notice {
            operation: Operation::Start,
            sequence: 1,
        };
        packet.write_request(&mut memory, notice, &[]).unwrap();
        memory.0[4095] = 1;
        assert_eq!(
            notice.response_status(
                service
                    .handle(&mut memory, notice, 50, &mut packet)
                    .unwrap()
            ),
            Ok(Status::Malformed)
        );
        assert!(service.take_failure().is_none()); // rejected framing is not device work
        packet.write_request(&mut memory, notice, &[]).unwrap();
        assert_eq!(
            notice.response_status(
                service
                    .handle(&mut memory, notice, 50, &mut packet)
                    .unwrap()
            ),
            Ok(Status::Refused)
        );
        let (operation, failure) = service.take_failure().unwrap();
        assert_eq!(operation, Operation::Start);
        assert_eq!(failure.error, DeviceError::State);
        assert_eq!(failure.progress, Progress::NoFrameSubmitted);
        assert!(service.take_failure().is_none());
        assert_eq!(
            notice.response_status(
                service
                    .handle(&mut memory, notice, 50, &mut packet)
                    .unwrap()
            ),
            Ok(Status::Stale)
        );
        let skipped = Notice {
            sequence: 3,
            ..notice
        };
        assert_eq!(
            skipped.response_status(
                service
                    .handle(&mut memory, skipped, 50, &mut packet)
                    .unwrap()
            ),
            Ok(Status::Stale)
        );
        assert_eq!(service.state(), State::Fresh);
    }
}
