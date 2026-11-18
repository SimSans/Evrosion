use ev_net_device::{ne2000 as nic, packet::MAX_FRAME_BYTES};

const MAX_STEPS: u32 = 131_072;
const TURN_STEPS: u32 = 64;
const ISR: u8 = 7;
const RDC: u8 = 0x40;

pub trait Ports {
    type Error;
    fn input(&mut self, port: u16) -> Result<u8, Self::Error>;
    fn output(&mut self, port: u16, value: u8) -> Result<(), Self::Error>;
    /// Opt in only when the same actual Core supplies a nondecreasing clock
    /// and checks each physical Byte4 group's deadline before any byte I/O.
    /// Portable/model backends retain every fresh precheck by default.
    fn may_reuse_byte4_clock(&self) -> bool {
        false
    }
    /// Exactly four Byte transactions at the same port, not consecutive ports.
    /// The actual mediated backend overrides this with negotiated Byte4. The
    /// scalar default supports deterministic device models without authority.
    fn input_bytes4(&mut self, port: u16, _deadline: u64) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        for byte in &mut bytes {
            *byte = self.input(port)?;
        }
        Ok(u32::from_le_bytes(bytes))
    }
    fn output_bytes4(&mut self, port: u16, value: u32, _deadline: u64) -> Result<(), Self::Error> {
        for byte in value.to_le_bytes() {
            self.output(port, byte)?;
        }
        Ok(())
    }
    fn now(&mut self) -> Result<u64, Self::Error>;
    fn yield_now(&mut self) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Fresh,
    Prepared,
    Running,
    Stopping,
    Stopped,
    Quarantined,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    NoFrameSubmitted,
    MayHaveSubmitted,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Io(E),
    State,
    Bounds,
    Mac,
    Prom,
    Readback,
    Device(u8),
    ClockReversed,
    Deadline,
    PollBudget,
    Protocol(nic::Error),
    Counter,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Failure<E> {
    pub error: Error<E>,
    pub progress: Progress,
}

/// Local device completion only. Remote delivery is not asserted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transmitted {
    pub sequence: u64,
    pub bytes: u16,
}
pub const STOP_CHUNK_BYTES: u16 = 128;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StopProgress {
    pub done: u16,
}
impl StopProgress {
    pub fn complete(self) -> bool {
        self.done == nic::PACKET_RAM_BYTES
    }
    pub fn encode(self) -> [u8; 8] {
        let mut b = [0; 8];
        b[..2].copy_from_slice(&self.done.to_le_bytes());
        b[2..4].copy_from_slice(&nic::PACKET_RAM_BYTES.to_le_bytes());
        b[4..6].copy_from_slice(&STOP_CHUNK_BYTES.to_le_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != 8
            || b[2..4] != nic::PACKET_RAM_BYTES.to_le_bytes()
            || b[4..6] != STOP_CHUNK_BYTES.to_le_bytes()
            || b[6..] != [0; 2]
        {
            return None;
        }
        let done = u16::from_le_bytes(b[..2].try_into().ok()?);
        (done <= nic::PACKET_RAM_BYTES && done.is_multiple_of(STOP_CHUNK_BYTES))
            .then_some(Self { done })
    }
}
struct Stop {
    aggregate: u64,
    done: u16,
}

struct Budget {
    deadline: u64,
    steps: u32,
}

pub struct Driver<P> {
    ports: P,
    state: State,
    last_tick: u64,
    next_rx: u8,
    transmitted: u64,
    stop: Option<Stop>,
}

impl<P: Ports> Driver<P> {
    pub fn new(ports: P) -> Self {
        Self {
            ports,
            state: State::Fresh,
            last_tick: 0,
            next_rx: nic::RX_START + 1,
            transmitted: 0,
            stop: None,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    fn failure(error: Error<P::Error>) -> Failure<P::Error> {
        Failure {
            error,
            progress: Progress::NoFrameSubmitted,
        }
    }

    fn clock(&mut self, budget: &Budget) -> Result<(), Error<P::Error>> {
        let now = self.ports.now().map_err(Error::Io)?;
        if now < self.last_tick {
            return Err(Error::ClockReversed);
        }
        self.last_tick = now;
        if budget.deadline == u64::MAX || now >= budget.deadline {
            return Err(Error::Deadline);
        }
        Ok(())
    }

    fn step(&mut self, budget: &mut Budget) -> Result<(), Error<P::Error>> {
        if budget.steps == MAX_STEPS {
            return Err(Error::PollBudget);
        }
        self.clock(budget)?;
        budget.steps += 1;
        if budget.steps.is_multiple_of(TURN_STEPS) {
            self.ports.yield_now().map_err(Error::Io)?;
            self.clock(budget)?;
        }
        Ok(())
    }

    fn data_step4(
        &mut self,
        budget: &mut Budget,
        reuse_clock: bool,
    ) -> Result<(), Error<P::Error>> {
        if budget.steps > MAX_STEPS - 4 {
            return Err(Error::PollBudget);
        }
        if !reuse_clock {
            self.clock(budget)?;
        }
        let next = budget.steps + 4;
        // Yield before a group crossing the old64-operation turn boundary;
        // IF0 fixed4 cannot yield midway. At most64 data ops separate yields.
        if budget.steps / TURN_STEPS != next / TURN_STEPS {
            self.ports.yield_now().map_err(Error::Io)?;
            self.clock(budget)?;
        }
        budget.steps = next;
        Ok(())
    }
    fn read_data4(
        &mut self,
        budget: &mut Budget,
        reuse_clock: bool,
    ) -> Result<u32, Error<P::Error>> {
        self.data_step4(budget, reuse_clock)?;
        let value = if budget.deadline - self.last_tick
            <= ev_userspace_contract::syscall::PORT_BATCH_MAX_TICKS
        {
            self.ports
                .input_bytes4(nic::IO_BASE + 0x10, budget.deadline)
                .map_err(Error::Io)?
        } else {
            // Cold8192 aggregate is not a valid1024 batch child. Choose four
            // guarded scalar bytes BEFORE any attempt, never retry a batch.
            let mut bytes = [0; 4];
            for byte in &mut bytes {
                *byte = self.ports.input(nic::IO_BASE + 0x10).map_err(Error::Io)?;
            }
            u32::from_le_bytes(bytes)
        };
        self.clock(budget)?;
        Ok(value)
    }
    fn write_data4(&mut self, value: u32, budget: &mut Budget) -> Result<(), Error<P::Error>> {
        self.data_step4(budget, false)?;
        if budget.deadline - self.last_tick <= ev_userspace_contract::syscall::PORT_BATCH_MAX_TICKS
        {
            self.ports
                .output_bytes4(nic::IO_BASE + 0x10, value, budget.deadline)
                .map_err(Error::Io)?;
        } else {
            for byte in value.to_le_bytes() {
                self.ports
                    .output(nic::IO_BASE + 0x10, byte)
                    .map_err(Error::Io)?;
            }
        }
        self.clock(budget)
    }
    fn read(&mut self, register: u8, budget: &mut Budget) -> Result<u8, Error<P::Error>> {
        if u16::from(register) >= nic::IO_BYTES {
            return Err(Error::Bounds);
        }
        self.step(budget)?;
        self.ports
            .input(nic::IO_BASE + u16::from(register))
            .map_err(Error::Io)
    }

    fn write(
        &mut self,
        register: u8,
        value: u8,
        budget: &mut Budget,
    ) -> Result<(), Error<P::Error>> {
        if u16::from(register) >= nic::IO_BYTES {
            return Err(Error::Bounds);
        }
        self.step(budget)?;
        self.ports
            .output(nic::IO_BASE + u16::from(register), value)
            .map_err(Error::Io)
    }

    fn wait(&mut self, bit: u8, budget: &mut Budget) -> Result<u8, Error<P::Error>> {
        loop {
            let status = self.read(ISR, budget)?;
            if status & bit != 0 {
                return Ok(status);
            }
            self.ports.yield_now().map_err(Error::Io)?;
        }
    }

    fn stop_inner(&mut self, budget: &mut Budget) -> Result<(), Error<P::Error>> {
        for (register, value) in nic::STOP_WRITES {
            self.write(register, value, budget)?;
        }
        self.write(0x0d, 2, budget)?; // loopback while stopped/preparing
        nic::verify_stopped(self.read(0, budget)?).map_err(Error::Protocol)?;
        // A previous holder may have changed byte mode or remote wrap bounds.
        // Without restoring them, a long scrub could loop over one tiny area
        // and falsely verify while leaving the rest of packet RAM untouched.
        self.write(0x0e, 0x48, budget)?;
        self.write(1, nic::TX_PAGE, budget)?;
        self.write(2, nic::RX_STOP, budget)?;
        self.write(0, 0xa1, budget)?;
        if self.read(1, budget)? != nic::TX_PAGE || self.read(2, budget)? != nic::RX_STOP {
            return Err(Error::Readback);
        }
        self.write(0, nic::STOP_COMMAND, budget)
    }
    fn stopped_bounds(&mut self, b: &mut Budget) -> Result<(), Error<P::Error>> {
        nic::verify_stopped(self.read(0, b)?).map_err(Error::Protocol)?;
        self.write(0, 0xa1, b)?; // page2, STOP remains asserted
        if self.read(1, b)? != nic::TX_PAGE || self.read(2, b)? != nic::RX_STOP {
            return Err(Error::Readback);
        }
        self.write(0, nic::STOP_COMMAND, b)?;
        nic::verify_stopped(self.read(0, b)?).map_err(Error::Protocol)
    }
    fn stop_cut(&mut self, aggregate: u64, child: u64) -> Result<(), Error<P::Error>> {
        let now = self.ports.now().map_err(Error::Io)?;
        if now < self.last_tick {
            return Err(Error::ClockReversed);
        }
        self.last_tick = now;
        if aggregate == u64::MAX
            || child == u64::MAX
            || child > aggregate
            || child <= now
            || child - now > 1024
            || now >= aggregate
        {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    /// Only STOPped packet-RAM scrub data. Each group has at most four fixed
    /// byte-port operations, a pre/post clock check and the existing physical
    /// step/yield accounting. Preemption can leave at most four data operations
    /// after expiry; no expired group can publish progress or release custody.
    fn scrub_data(&mut self, write: bool, b: &mut Budget) -> Result<(), Error<P::Error>> {
        for _ in 0..STOP_CHUNK_BYTES / 4 {
            if write {
                self.write_data4(0, b)?;
            } else if self.read_data4(b, false)? != 0 {
                return Err(Error::Readback);
            }
        }
        Ok(())
    }
    /// Begin exactly once; real STOP/bounds precede every acknowledged chunk.
    /// No RESET port access, renewed transaction cut or accepted unknown retry.
    pub fn stop_begin(
        &mut self,
        aggregate: u64,
        child: u64,
    ) -> Result<StopProgress, Failure<P::Error>> {
        if !matches!(self.state, State::Running | State::Prepared) || self.stop.is_some() {
            return Err(Self::failure(Error::State));
        }
        self.begin_stop(aggregate, child)
    }
    fn begin_stop(
        &mut self,
        aggregate: u64,
        child: u64,
    ) -> Result<StopProgress, Failure<P::Error>> {
        self.stop_cut(aggregate, child).map_err(Self::failure)?;
        if aggregate - self.last_tick > 8192 {
            return Err(Self::failure(Error::Deadline));
        }
        self.state = State::Quarantined;
        let mut b = Budget {
            deadline: child,
            steps: 0,
        };
        self.stop_inner(&mut b)
            .and_then(|()| self.stopped_bounds(&mut b))
            .and_then(|()| self.clock(&b))
            .map_err(Self::failure)?;
        self.stop = Some(Stop { aggregate, done: 0 });
        self.state = State::Stopping;
        Ok(StopProgress { done: 0 })
    }
    /// One new quiescent command, fixed128B, with exact physical readback.
    /// Unknown/partial I/O leaves Quarantined and the cursor never advances.
    pub fn stop_step(&mut self, child: u64) -> Result<StopProgress, Failure<P::Error>> {
        if self.state != State::Stopping {
            return Err(Self::failure(Error::State));
        }
        let stop = self
            .stop
            .as_ref()
            .ok_or_else(|| Self::failure(Error::State))?;
        let (aggregate, done) = (stop.aggregate, stop.done);
        self.state = State::Quarantined;
        self.stop_cut(aggregate, child).map_err(Self::failure)?;
        let mut b = Budget {
            deadline: child,
            steps: 0,
        };
        let result = (|| {
            self.stopped_bounds(&mut b)?;
            let address = 0x4000u16.checked_add(done).ok_or(Error::Bounds)?;
            self.transfer(address, STOP_CHUNK_BYTES, true, true, &mut b)?;
            self.scrub_data(true, &mut b)?;
            self.transfer_done(true, &mut b)?;
            self.transfer(address, STOP_CHUNK_BYTES, false, true, &mut b)?;
            self.scrub_data(false, &mut b)?;
            self.transfer_done(true, &mut b)?;
            self.stopped_bounds(&mut b)?;
            self.clock(&b)
        })();
        result.map_err(Self::failure)?;
        let done = done
            .checked_add(STOP_CHUNK_BYTES)
            .filter(|v| *v <= nic::PACKET_RAM_BYTES)
            .ok_or_else(|| Self::failure(Error::Counter))?;
        self.stop.as_mut().unwrap().done = done;
        self.state = if done == nic::PACKET_RAM_BYTES {
            State::Stopped
        } else {
            State::Stopping
        };
        Ok(StopProgress { done })
    }

    fn transfer(
        &mut self,
        address: u16,
        bytes: u16,
        write: bool,
        stopped: bool,
        budget: &mut Budget,
    ) -> Result<(), Error<P::Error>> {
        let end = u32::from(address) + u32::from(bytes);
        let packet = address >= 0x4000 && end <= 0x8000;
        let prom = !write && end <= 32;
        if bytes == 0 || !(packet || prom) {
            return Err(Error::Bounds);
        }
        self.write(
            0,
            if stopped {
                nic::STOP_COMMAND
            } else {
                nic::START_COMMAND
            },
            budget,
        )?;
        self.write(ISR, RDC, budget)?;
        self.write(8, address as u8, budget)?;
        self.write(9, (address >> 8) as u8, budget)?;
        self.write(0x0a, bytes as u8, budget)?;
        self.write(0x0b, (bytes >> 8) as u8, budget)?;
        // The qualified model permits its device-local ASIC data path while
        // STOP remains asserted. Keep RX fenced throughout initialization.
        let command = (if stopped { 1 } else { 2 }) | if write { 0x10 } else { 8 };
        self.write(0, command, budget)
    }

    fn transfer_done(&mut self, stopped: bool, budget: &mut Budget) -> Result<(), Error<P::Error>> {
        self.wait(RDC, budget)?;
        self.write(
            0,
            if stopped {
                nic::STOP_COMMAND
            } else {
                nic::START_COMMAND
            },
            budget,
        )
    }

    fn read_bytes(
        &mut self,
        address: u16,
        bytes: &mut [u8],
        stopped: bool,
        budget: &mut Budget,
    ) -> Result<(), Error<P::Error>> {
        let count = u16::try_from(bytes.len()).map_err(|_| Error::Bounds)?;
        self.transfer(address, count, false, stopped, budget)?;
        let (groups, tail) = bytes.as_chunks_mut::<4>();
        for (index, group) in groups.iter_mut().enumerate() {
            // Only a later normal-RX group has a successful prior POST clock.
            // The trusted backend checks actual time again before its Byte4
            // I/O. Preemption can only shrink this positive eligible span or
            // cause a pre-I/O refusal; no scalar fallback follows an attempt.
            let reuse_clock = !stopped
                && index > 0
                && self.ports.may_reuse_byte4_clock()
                && budget.deadline != u64::MAX
                && budget
                    .deadline
                    .checked_sub(self.last_tick)
                    .is_some_and(|span| {
                        span > 0 && span <= ev_userspace_contract::syscall::PORT_BATCH_MAX_TICKS
                    });
            *group = self.read_data4(budget, reuse_clock)?.to_le_bytes();
        }
        for byte in tail {
            *byte = self.read(0x10, budget)?;
        }
        self.transfer_done(stopped, budget)
    }

    fn scrub(&mut self, budget: &mut Budget) -> Result<(), Error<P::Error>> {
        self.transfer(0x4000, nic::PACKET_RAM_BYTES, true, true, budget)?;
        for _ in 0..nic::PACKET_RAM_BYTES / 4 {
            self.write_data4(0, budget)?;
        }
        self.transfer_done(true, budget)?;
        self.transfer(0x4000, nic::PACKET_RAM_BYTES, false, true, budget)?;
        for _ in 0..nic::PACKET_RAM_BYTES / 4 {
            if self.read_data4(budget, false)? != 0 {
                return Err(Error::Readback);
            }
        }
        self.transfer_done(true, budget)
    }

    /// One cold/exclusive initialization only. Expected MAC comes from the
    /// actual trusted device profile, not the PROM itself. Failure quarantines.
    pub fn initialize(&mut self, mac: [u8; 6], deadline: u64) -> Result<(), Failure<P::Error>> {
        if self.state != State::Fresh {
            return Err(Self::failure(Error::State));
        }
        if mac[0] & 1 != 0 || mac == [0; 6] {
            return Err(Self::failure(Error::Mac));
        }
        self.state = State::Quarantined;
        let mut b = Budget { deadline, steps: 0 };
        let result = (|| {
            self.stop_inner(&mut b)?;
            let reset = self.read(0x1f, &mut b)?;
            self.write(0x1f, reset, &mut b)?;
            self.wait(nic::RESET_COMPLETED, &mut b)?;
            self.write(0x0e, 0x48, &mut b)?; // eight-bit data, no guest-memory DMA
            let mut prom = [0u8; 32];
            self.read_bytes(0, &mut prom, true, &mut b)?;
            for (index, byte) in mac.iter().enumerate() {
                if prom[index * 2] != *byte || prom[index * 2 + 1] != *byte {
                    return Err(Error::Mac);
                }
            }
            if prom[28..] != [0x57; 4] {
                return Err(Error::Prom);
            }
            self.scrub(&mut b)?;
            self.write(1, nic::RX_START, &mut b)?;
            self.write(2, nic::RX_STOP, &mut b)?;
            self.write(3, nic::RX_START, &mut b)?;
            self.write(0x0c, 4, &mut b)?; // unicast + broadcast, no promiscuous mode
            self.write(0, 0x61, &mut b)?;
            for (index, byte) in mac.iter().enumerate() {
                self.write(1 + index as u8, *byte, &mut b)?;
            }
            self.write(7, nic::RX_START + 1, &mut b)?;
            for register in 8..=15 {
                self.write(register, 0, &mut b)?;
            }
            for (index, byte) in mac.iter().enumerate() {
                if self.read(1 + index as u8, &mut b)? != *byte {
                    return Err(Error::Readback);
                }
            }
            if self.read(7, &mut b)? != nic::RX_START + 1 {
                return Err(Error::Readback);
            }
            self.write(0, 0xa1, &mut b)?;
            if self.read(1, &mut b)? != nic::RX_START || self.read(2, &mut b)? != nic::RX_STOP {
                return Err(Error::Readback);
            }
            self.write(0, nic::STOP_COMMAND, &mut b)?;
            self.write(ISR, 0x7f, &mut b)?;
            nic::verify_stopped(self.read(0, &mut b)?).map_err(Error::Protocol)
        })();
        result.map_err(Self::failure)?;
        self.next_rx = nic::RX_START + 1;
        self.state = State::Prepared;
        Ok(())
    }

    pub fn start(&mut self, deadline: u64) -> Result<(), Failure<P::Error>> {
        if self.state != State::Prepared {
            return Err(Self::failure(Error::State));
        }
        self.state = State::Quarantined;
        let mut b = Budget { deadline, steps: 0 };
        let result = (|| {
            self.write(0x0d, 0, &mut b)?;
            self.write(0x0f, 0, &mut b)?;
            self.write(ISR, 0x7f, &mut b)?;
            self.write(0, nic::START_COMMAND, &mut b)?;
            if self.read(0, &mut b)? != nic::START_COMMAND {
                return Err(Error::Readback);
            }
            Ok(())
        })();
        result.map_err(Self::failure)?;
        self.state = State::Running;
        Ok(())
    }

    /// One synchronous local command; no accepted command retry. A failure after
    /// the TX write was attempted reports uncertainty and quarantines the actor.
    pub fn transmit(
        &mut self,
        frame: &[u8],
        deadline: u64,
    ) -> Result<Transmitted, Failure<P::Error>> {
        if self.state != State::Running {
            return Err(Self::failure(Error::State));
        }
        let span = nic::transmit(frame.len()).map_err(|e| Self::failure(Error::Protocol(e)))?;
        let sequence = self
            .transmitted
            .checked_add(1)
            .ok_or_else(|| Self::failure(Error::Counter))?;
        self.state = State::Quarantined;
        let mut b = Budget { deadline, steps: 0 };
        let mut progress = Progress::NoFrameSubmitted;
        let result = (|| {
            self.transfer(span.address, span.bytes, true, false, &mut b)?;
            let (groups, tail) = frame.as_chunks::<4>();
            for group in groups {
                self.write_data4(u32::from_le_bytes(*group), &mut b)?;
            }
            for byte in tail {
                self.write(0x10, *byte, &mut b)?;
            }
            self.transfer_done(false, &mut b)?;
            self.write(4, nic::TX_PAGE, &mut b)?;
            self.write(5, span.bytes as u8, &mut b)?;
            self.write(6, (span.bytes >> 8) as u8, &mut b)?;
            self.write(ISR, 0x0a, &mut b)?; // clear stale TX/error before new command
            progress = Progress::MayHaveSubmitted;
            self.write(0, 0x26, &mut b)?;
            let isr = self.wait(0x0a, &mut b)?;
            let tsr = self.read(4, &mut b)?;
            if isr & 0x0a != 2 || tsr & 0xf9 != 1 {
                return Err(Error::Device(isr));
            }
            self.write(ISR, 0x0a, &mut b)?;
            Ok(())
        })();
        result.map_err(|error| Failure { error, progress })?;
        self.transmitted = sequence;
        self.state = State::Running;
        Ok(Transmitted {
            sequence,
            bytes: span.bytes,
        })
    }

    pub fn receive(
        &mut self,
        output: &mut [u8; MAX_FRAME_BYTES],
        deadline: u64,
    ) -> Result<Option<usize>, Failure<P::Error>> {
        if self.state != State::Running {
            return Err(Self::failure(Error::State));
        }
        self.state = State::Quarantined;
        let mut b = Budget { deadline, steps: 0 };
        let result = (|| {
            let isr = self.read(ISR, &mut b)?;
            if isr & 0x14 != 0 {
                return Err(Error::Device(isr));
            }
            self.write(0, 0x62, &mut b)?;
            let current = self.read(7, &mut b)?;
            self.write(0, nic::START_COMMAND, &mut b)?;
            if !(nic::RX_START..nic::RX_STOP).contains(&current) {
                return Err(Error::Protocol(nic::Error::Page));
            }
            if current == self.next_rx {
                return Ok(None);
            }
            let mut header = [0u8; 4];
            self.read_bytes(u16::from(self.next_rx) * 256, &mut header, false, &mut b)?;
            let plan = nic::receive(self.next_rx, current, header).map_err(Error::Protocol)?;
            let first = usize::from(plan.first.bytes);
            self.read_bytes(plan.first.address, &mut output[..first], false, &mut b)?;
            if let Some(second) = plan.second {
                self.read_bytes(
                    second.address,
                    &mut output[first..usize::from(plan.frame_bytes)],
                    false,
                    &mut b,
                )?;
            }
            let isr = self.read(ISR, &mut b)?;
            if isr & 0x14 != 0 {
                return Err(Error::Device(isr));
            }
            // Publish consumer advancement only after every validated byte was
            // copied and a fresh overflow check succeeded.
            self.write(3, plan.boundary, &mut b)?;
            self.next_rx = plan.next_page;
            self.write(ISR, 1, &mut b)?;
            Ok(Some(usize::from(plan.frame_bytes)))
        })();
        let received = result.map_err(Self::failure)?;
        self.state = State::Running;
        Ok(received)
    }

    /// Cooperative stop/scrub under exclusive actual authority. The supervisor
    /// separately fences/revokes the old holder before any replacement starts.
    /// This cannot retract host/remote packets already emitted.
    pub fn stop_and_scrub(&mut self, deadline: u64) -> Result<(), Failure<P::Error>> {
        if matches!(self.state, State::Stopped | State::Stopping) {
            return Err(Self::failure(Error::State));
        }
        self.state = State::Quarantined;
        let mut b = Budget { deadline, steps: 0 };
        let result = (|| {
            self.stop_inner(&mut b)?;
            self.scrub(&mut b)?;
            nic::verify_stopped(self.read(0, &mut b)?).map_err(Error::Protocol)
        })();
        result.map_err(Self::failure)?;
        self.state = State::Stopped;
        Ok(())
    }
}

pub mod recovery;

#[cfg(test)]
mod tests;
