extern crate std;
use super::*;
use crate::REFERENCE_MAC;
use std::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Port,
    Injected,
    CoreDeadline,
}
#[derive(Clone, Copy)]
enum DataEvent {
    Clock(u64),
    Io,
}

struct Model {
    memory: [u8; 0x8000],
    command: u8,
    start: u8,
    stop: u8,
    boundary: u8,
    current: u8,
    physical: [u8; 6],
    isr: u8,
    tsr: u8,
    dcfg: u8,
    imr: u8,
    address: u16,
    count: u16,
    tx_page: u8,
    tx_bytes: u16,
    tick: u64,
    stalled: bool,
    tx_silent: bool,
    tx_error: bool,
    tx_ack_lost: bool,
    ignore_bounds: bool,
    dirty_byte: Option<usize>,
    overflow_after: Option<usize>,
    data_reads: usize,
    data_writes: usize,
    commands: usize,
    tx: Vec<Vec<u8>>,
    forbid_start: bool,
    data_event: Option<(usize, DataEvent)>,
    clock_reads: usize,
    byte_read_groups: usize,
    byte_write_groups: usize,
    batch_cuts: Vec<u64>,
    reuse_clock: bool,
    core_deadlines: bool,
    preempt_byte4: Option<(usize, u64)>,
    expire_after_transfer: Option<u64>,
    port_trace: Option<Vec<(bool, u16, u8)>>,
    yields: usize,
}

impl Model {
    fn new() -> Self {
        Self {
            memory: [0xa5; 0x8000],
            command: 0x22,
            start: 0x47,
            stop: 0x48,
            boundary: 0x47,
            current: 0x47,
            physical: [0; 6],
            isr: 2,
            tsr: 1,
            dcfg: 1,
            imr: 0xff,
            address: 0,
            count: 0,
            tx_page: 0,
            tx_bytes: 0,
            tick: 0,
            stalled: false,
            tx_silent: false,
            tx_error: false,
            tx_ack_lost: false,
            ignore_bounds: false,
            dirty_byte: None,
            overflow_after: None,
            data_reads: 0,
            data_writes: 0,
            commands: 0,
            tx: Vec::new(),
            forbid_start: false,
            data_event: None,
            clock_reads: 0,
            byte_read_groups: 0,
            byte_write_groups: 0,
            batch_cuts: Vec::new(),
            reuse_clock: false,
            core_deadlines: false,
            preempt_byte4: None,
            expire_after_transfer: None,
            port_trace: None,
            yields: 0,
        }
    }
    fn remote_step(&mut self) {
        let width = if self.dcfg & 1 == 0 { 1 } else { 2 };
        self.address = self.address.wrapping_add(width);
        if self.address == u16::from(self.stop) * 256 {
            self.address = u16::from(self.start) * 256;
        }
        self.count = self.count.saturating_sub(width);
        if self.count == 0 {
            self.isr |= RDC;
        }
    }
    fn register(port: u16) -> Result<u8, Fault> {
        if !(0x300..0x320).contains(&port) {
            return Err(Fault::Port);
        }
        Ok((port - 0x300) as u8)
    }
    fn data_event(&mut self) -> Result<(), Fault> {
        if let Some((at, event)) = self.data_event
            && self.data_reads + self.data_writes == at
        {
            match event {
                DataEvent::Clock(tick) => self.tick = tick,
                DataEvent::Io => return Err(Fault::Injected),
            }
        }
        Ok(())
    }
}

impl Ports for Model {
    type Error = Fault;
    fn may_reuse_byte4_clock(&self) -> bool {
        self.reuse_clock
    }
    fn input(&mut self, port: u16) -> Result<u8, Fault> {
        if let Some(trace) = &mut self.port_trace {
            trace.push((false, port, 0));
        }
        let register = Self::register(port)?;
        if register == 0x1f {
            assert!(!self.forbid_start, "continuation cannot reset the device");
            self.isr = 0x80;
            for (index, byte) in REFERENCE_MAC.iter().enumerate() {
                self.memory[index * 2] = *byte;
                self.memory[index * 2 + 1] = *byte;
            }
            self.memory[28..32].fill(0x57);
            return Ok(0);
        }
        if register == 0x10 {
            // A stale word-mode owner must not control recovery transfers.
            assert_eq!(self.dcfg & 1, 0);
            let value = self.memory[usize::from(self.address)];
            self.data_reads += 1;
            if self.overflow_after == Some(self.data_reads) {
                self.isr |= 0x10;
            }
            self.remote_step();
            self.data_event()?;
            return Ok(value);
        }
        if register == 0 {
            return Ok(self.command);
        }
        match (self.command >> 6, register) {
            (0, 3) => Ok(self.boundary),
            (0, 4) => Ok(self.tsr),
            (0, 7) => Ok(self.isr),
            (1, 1..=6) => Ok(self.physical[usize::from(register - 1)]),
            (1, 7) => Ok(self.current),
            (2, 1) => Ok(self.start),
            (2, 2) => Ok(self.stop),
            _ => Ok(0),
        }
    }
    fn output(&mut self, port: u16, value: u8) -> Result<(), Fault> {
        if let Some(trace) = &mut self.port_trace {
            trace.push((true, port, value));
        }
        let register = Self::register(port)?;
        self.commands += 1;
        if register == 0x1f {
            assert!(!self.forbid_start, "continuation cannot reset the device");
            return Ok(());
        }
        if register == 0x10 {
            assert_eq!(self.dcfg & 1, 0);
            assert!((0x4000..0x8000).contains(&self.address));
            if self.dirty_byte != Some(usize::from(self.address)) {
                self.memory[usize::from(self.address)] = value;
            }
            self.data_writes += 1;
            self.remote_step();
            self.data_event()?;
            return Ok(());
        }
        if register == 0 {
            assert!(
                !self.forbid_start || value & 2 == 0,
                "STOP must remain asserted"
            );
            self.command = value;
            if value == 0x0a
                && let Some(tick) = self.expire_after_transfer.take()
            {
                self.tick = tick;
            }
            if value & 1 == 0 {
                self.isr &= !0x80;
            }
            if value & 4 != 0 {
                let address = usize::from(self.tx_page) * 256;
                self.tx
                    .push(self.memory[address..address + usize::from(self.tx_bytes)].to_vec());
                if !self.tx_silent {
                    self.isr |= if self.tx_error { 8 } else { 2 };
                    self.tsr = if self.tx_error { 8 } else { 1 };
                    self.command &= !4;
                }
                if self.tx_ack_lost {
                    return Err(Fault::Injected);
                }
            }
            return Ok(());
        }
        match (self.command >> 6, register) {
            (0, 1) if !self.ignore_bounds => self.start = value,
            (0, 2) if !self.ignore_bounds => self.stop = value,
            (0, 3) => self.boundary = value,
            (0, 4) => self.tx_page = value,
            (0, 5) => self.tx_bytes = (self.tx_bytes & 0xff00) | u16::from(value),
            (0, 6) => self.tx_bytes = (self.tx_bytes & 0xff) | (u16::from(value) << 8),
            (0, 7) => self.isr &= !(value & 0x7f),
            (0, 8) => self.address = (self.address & 0xff00) | u16::from(value),
            (0, 9) => self.address = (self.address & 0xff) | (u16::from(value) << 8),
            (0, 0xa) => self.count = (self.count & 0xff00) | u16::from(value),
            (0, 0xb) => self.count = (self.count & 0xff) | (u16::from(value) << 8),
            (0, 0xe) => self.dcfg = value,
            (0, 0xf) => self.imr = value,
            (1, 1..=6) => self.physical[usize::from(register - 1)] = value,
            (1, 7) => self.current = value,
            _ => {}
        }
        Ok(())
    }
    fn input_bytes4(&mut self, port: u16, deadline: u64) -> Result<u32, Fault> {
        assert_eq!(port, nic::IO_BASE + 0x10);
        self.byte_read_groups += 1;
        self.batch_cuts.push(deadline);
        if let Some((attempt, tick)) = self.preempt_byte4
            && attempt == self.byte_read_groups
        {
            self.tick = tick;
        }
        if self.core_deadlines
            && (deadline == 0
                || deadline == u64::MAX
                || deadline <= self.tick
                || deadline - self.tick > ev_userspace_contract::syscall::PORT_BATCH_MAX_TICKS)
        {
            return Err(Fault::CoreDeadline);
        }
        let mut bytes = [0; 4];
        for b in &mut bytes {
            *b = self.input(port)?;
        }
        Ok(u32::from_le_bytes(bytes))
    }
    fn output_bytes4(&mut self, port: u16, value: u32, deadline: u64) -> Result<(), Fault> {
        assert_eq!(port, nic::IO_BASE + 0x10);
        self.byte_write_groups += 1;
        self.batch_cuts.push(deadline);
        for b in value.to_le_bytes() {
            self.output(port, b)?;
        }
        Ok(())
    }
    fn now(&mut self) -> Result<u64, Fault> {
        self.clock_reads += 1;
        Ok(self.tick)
    }
    fn yield_now(&mut self) -> Result<(), Fault> {
        self.yields += 1;
        if !self.stalled {
            self.tick += 1;
        }
        Ok(())
    }
}

fn running() -> Driver<Model> {
    let mut driver = Driver::new(Model::new());
    driver.initialize(REFERENCE_MAC, 8192).unwrap();
    driver.start(8192).unwrap();
    driver
}

#[test]
fn initialization_corrects_hostile_wrap_and_word_mode_then_verifies_all_ram() {
    let mut driver = Driver::new(Model::new());
    driver.initialize(REFERENCE_MAC, 8192).unwrap();
    assert_eq!(driver.state(), State::Prepared);
    assert_eq!(driver.ports.data_writes, 0x4000);
    assert_eq!(driver.ports.data_reads, 0x4000 + 32);
    assert!(driver.ports.memory[0x4000..0x8000].iter().all(|b| *b == 0));
    assert!(driver.ports.memory[32..0x4000].iter().all(|b| *b == 0xa5));
    assert_eq!(
        (driver.ports.start, driver.ports.stop, driver.ports.imr),
        (nic::RX_START, nic::RX_STOP, 0)
    );
    assert_eq!(driver.ports.command, nic::STOP_COMMAND);
    assert!(driver.ports.tx.is_empty());
}

#[test]
fn false_bound_or_scrub_readback_never_prepares_the_device() {
    let mut model = Model::new();
    model.ignore_bounds = true;
    let mut driver = Driver::new(model);
    assert_eq!(
        driver.initialize(REFERENCE_MAC, 8192).unwrap_err().error,
        Error::Readback
    );
    assert_eq!(driver.ports.data_writes, 0);
    assert_eq!(driver.state(), State::Quarantined);
    let mut model = Model::new();
    model.dirty_byte = Some(0x7ffe);
    let mut driver = Driver::new(model);
    assert_eq!(
        driver.initialize(REFERENCE_MAC, 8192).unwrap_err().error,
        Error::Readback
    );
    assert_eq!(driver.state(), State::Quarantined);
    assert!(driver.start(8192).is_err());
    assert!(driver.ports.tx.is_empty());
}

#[test]
fn invalid_identity_and_lifecycle_refuse_before_io() {
    let mut driver = Driver::new(Model::new());
    for mac in [[0; 6], [0xff; 6], [1, 0, 0, 0, 0, 1]] {
        assert_eq!(driver.initialize(mac, 8192).unwrap_err().error, Error::Mac);
        assert_eq!(driver.ports.commands, 0);
    }
    assert_eq!(driver.start(8192).unwrap_err().error, Error::State);
    driver.initialize(REFERENCE_MAC, 8192).unwrap();
    let commands = driver.ports.commands;
    assert_eq!(
        driver.initialize(REFERENCE_MAC, 8192).unwrap_err().error,
        Error::State
    );
    assert_eq!(driver.ports.commands, commands);
}

#[test]
fn transmit_clears_old_status_copies_exact_frame_and_reports_local_completion() {
    let mut driver = running();
    driver.ports.isr |= 2;
    driver.ports.tsr = 1;
    let frame = [0x6b; 60];
    assert_eq!(
        driver.transmit(&frame, 8192).unwrap(),
        Transmitted {
            sequence: 1,
            bytes: 60
        }
    );
    assert_eq!(driver.ports.tx, [frame.to_vec()]);
    assert_eq!(driver.state(), State::Running);
    let commands = driver.ports.commands;
    assert_eq!(
        driver.transmit(&[0; 59], 8192).unwrap_err().progress,
        Progress::NoFrameSubmitted
    );
    assert_eq!(driver.ports.commands, commands);
}

#[test]
fn accepted_unknown_or_failed_tx_never_retries_and_stop_does_not_retract_it() {
    for lost_ack in [false, true] {
        let mut driver = running();
        driver.ports.tx_ack_lost = lost_ack;
        driver.ports.tx_error = !lost_ack;
        let failure = driver.transmit(&[1; 60], 8192).unwrap_err();
        assert_eq!(failure.progress, Progress::MayHaveSubmitted);
        assert_eq!(driver.ports.tx.len(), 1);
        assert_eq!(driver.state(), State::Quarantined);
        assert!(driver.transmit(&[1; 60], 8192).is_err());
        driver.stop_and_scrub(8192).unwrap();
        assert_eq!(driver.state(), State::Stopped);
        assert_eq!(driver.ports.tx.len(), 1);
        assert!(driver.ports.memory[0x4000..].iter().all(|b| *b == 0));
        assert!(driver.start(8192).is_err());
    }
}

#[test]
fn stale_tx_done_cannot_hide_a_real_deadline_or_stalled_clock() {
    let mut driver = running();
    driver.ports.tx_silent = true;
    driver.ports.isr |= 2;
    let deadline = driver.ports.tick + 3;
    assert_eq!(
        driver.transmit(&[2; 60], deadline).unwrap_err().error,
        Error::Deadline
    );
    assert_eq!(driver.ports.tx.len(), 1);
    let mut driver = running();
    driver.ports.tx_silent = true;
    driver.ports.stalled = true;
    assert_eq!(
        driver.transmit(&[2; 60], 8192).unwrap_err().error,
        Error::PollBudget
    );
    assert_eq!(driver.ports.tx.len(), 1);
}

#[test]
fn receive_copies_a_wrapped_frame_before_releasing_its_exact_pages() {
    let mut driver = running();
    driver.next_rx = 0x7f;
    driver.ports.current = 0x4b;
    driver.ports.memory[0x7f00..0x7f04].copy_from_slice(&[1, 0x4b, 0xee, 5]);
    let mut expected = [0u8; MAX_FRAME_BYTES];
    for (index, byte) in expected.iter_mut().enumerate() {
        *byte = index as u8;
    }
    driver.ports.memory[0x7f04..0x8000].copy_from_slice(&expected[..252]);
    driver.ports.memory[0x4600..0x4600 + 1262].copy_from_slice(&expected[252..]);
    let mut output = [0u8; MAX_FRAME_BYTES];
    assert_eq!(driver.receive(&mut output, 8192).unwrap(), Some(1514));
    assert_eq!(output, expected);
    assert_eq!(driver.ports.boundary, 0x4a);
    assert_eq!(driver.next_rx, 0x4b);
    assert_eq!(driver.receive(&mut output, 8192).unwrap(), None);
}

#[test]
fn exact_virtual_receive_lengths_survive_device_copy_and_poll_codec() {
    use crate::protocol::{Notice, Operation, Packet, Status, Window};
    struct Memory([u8; 4096]);
    impl Window for Memory {
        type Error = ();
        fn read(&mut self, n: usize) -> Result<u8, ()> {
            self.0.get(n).copied().ok_or(())
        }
        fn write(&mut self, n: usize, byte: u8) -> Result<(), ()> {
            *self.0.get_mut(n).ok_or(())? = byte;
            Ok(())
        }
    }
    let notice = Notice {
        operation: Operation::Poll,
        sequence: 1,
    };
    for len in [14, 54, 58, MAX_FRAME_BYTES] {
        let mut driver = running();
        let mut frame = [0x6b; MAX_FRAME_BYTES];
        if matches!(len, 54 | 58) {
            // Ethernet + IPv4 + ACK20/SYNACK24 TCP header shapes. This is a
            // device/codec model, not a TCP handshake or wire capture claim.
            frame[..6].copy_from_slice(&REFERENCE_MAC);
            frame[12..14].copy_from_slice(&[8, 0]);
            frame[14] = 0x45;
            frame[16..18].copy_from_slice(&((len - 14) as u16).to_be_bytes());
            frame[23] = 6;
            frame[46] = ((len - 34) / 4) as u8 * 16;
            frame[47] = if len == 54 { 0x10 } else { 0x12 };
        }
        let count = len as u16 + 4;
        let next = 0x47 + (count + 4).div_ceil(256) as u8;
        driver.ports.current = next;
        driver.ports.memory[0x4700..0x4704].copy_from_slice(&[
            1,
            next,
            count as u8,
            (count >> 8) as u8,
        ]);
        driver.ports.memory[0x4704..0x4704 + len].copy_from_slice(&frame[..len]);
        let mut output = [0xa5; MAX_FRAME_BYTES];
        assert_eq!(driver.receive(&mut output, 8192).unwrap(), Some(len));
        assert_eq!(&output[..len], &frame[..len]);
        assert!(output[len..].iter().all(|b| *b == 0xa5));
        assert_eq!(driver.ports.boundary, next - 1);
        assert_eq!(driver.next_rx, next);

        let mut memory = Memory([0xa5; 4096]);
        let mut packet = Packet::new();
        packet.payload[..len].copy_from_slice(&output[..len]);
        packet.length = len;
        packet
            .publish(&mut memory, notice, Status::Complete)
            .unwrap();
        let mut received = Packet::new();
        received
            .read_response(&mut memory, notice, Status::Complete)
            .unwrap();
        assert_eq!(received.payload(), &frame[..len]);
        // Complete frames remain exact; the canonical window tail is separate.
        assert!(memory.0[64 + len..].iter().all(|b| *b == 0));
    }
    for len in [0, 13, MAX_FRAME_BYTES + 1] {
        let mut memory = Memory([0; 4096]);
        let mut packet = Packet::new();
        // The codec must independently reject impossible device lengths.
        memory.0[..8].copy_from_slice(b"EVNIO001");
        memory.0[8..10].copy_from_slice(&1u16.to_le_bytes());
        memory.0[10] = 1;
        memory.0[11] = Operation::Poll as u8;
        memory.0[14..16].copy_from_slice(&(len as u16).to_le_bytes());
        memory.0[16..20].copy_from_slice(&1u32.to_le_bytes());
        assert!(
            packet
                .read_response(&mut memory, notice, Status::Complete)
                .is_err()
        );
        assert!(packet.payload().is_empty());
    }
    let mut driver = running();
    driver.ports.current = 0x48;
    driver.ports.memory[0x4700..0x4704].copy_from_slice(&[1, 0x48, 17, 0]);
    let mut output = [0xa5; MAX_FRAME_BYTES];
    assert!(driver.receive(&mut output, 8192).is_err());
    assert_eq!(output, [0xa5; MAX_FRAME_BYTES]);
    assert_eq!(driver.ports.boundary, nic::RX_START);
    assert_eq!(driver.next_rx, nic::RX_START + 1);
}

#[test]
fn corrupt_header_or_overflow_never_advances_consumer_or_publishes_a_frame() {
    let mut driver = running();
    driver.ports.current = 0x48;
    driver.ports.memory[0x4700..0x4704].copy_from_slice(&[1, 0, 64, 0]);
    let mut output = [0xa5; MAX_FRAME_BYTES];
    assert!(driver.receive(&mut output, 8192).is_err());
    assert_eq!(output, [0xa5; MAX_FRAME_BYTES]);
    assert_eq!(driver.ports.boundary, nic::RX_START);
    assert_eq!(driver.next_rx, nic::RX_START + 1);
    let mut driver = running();
    driver.ports.current = 0x48;
    driver.ports.memory[0x4700..0x4704].copy_from_slice(&[1, 0x48, 64, 0]);
    driver.ports.overflow_after = Some(driver.ports.data_reads + 10);
    assert!(driver.receive(&mut output, 8192).is_err());
    assert_eq!(driver.ports.boundary, nic::RX_START);
    assert_eq!(driver.next_rx, nic::RX_START + 1);
    assert_eq!(driver.state(), State::Quarantined);
}

#[test]
fn controller_clock_regression_quarantines_before_another_port_operation() {
    let mut driver = running();
    driver.ports.tick = driver.last_tick - 1;
    let commands = driver.ports.commands;
    let mut output = [0; MAX_FRAME_BYTES];
    assert_eq!(
        driver.receive(&mut output, 8192).unwrap_err().error,
        Error::ClockReversed
    );
    assert_eq!(driver.ports.commands, commands);
    assert_eq!(driver.state(), State::Quarantined);
}

#[test]
fn stop_v2_covers_all_ram_in_exact_verified_chunks_without_reset_start_or_early_complete() {
    let mut d = running();
    d.ports.memory[0x4000..0x8000].fill(0xa5);
    d.ports.forbid_start = true;
    let start = d.ports.tick;
    let aggregate = start + 8192;
    let reads = d.ports.data_reads;
    let writes = d.ports.data_writes;
    assert_eq!(d.stop_begin(aggregate, start + 512).unwrap().done, 0);
    assert_eq!(d.state(), State::Stopping);
    let commands = d.ports.commands;
    assert!(d.stop_begin(aggregate + 1, start + 512).is_err());
    assert_eq!(d.ports.commands, commands);
    assert!(d.transmit(&[0; 60], start + 512).is_err());
    assert!(d.receive(&mut [0; MAX_FRAME_BYTES], start + 512).is_err());
    assert!(d.stop_and_scrub(start + 512).is_err());
    assert_eq!(d.ports.commands, commands);
    for step in 1..=128 {
        let progress = d.stop_step(d.ports.tick + 512).unwrap();
        assert_eq!(progress.done, step * 128);
        assert_eq!(progress.complete(), step == 128);
        let end = 0x4000 + usize::from(progress.done);
        assert!(d.ports.memory[0x4000..end].iter().all(|v| *v == 0));
        assert!(d.ports.memory[end..0x8000].iter().all(|v| *v == 0xa5));
        assert_eq!(d.ports.command, nic::STOP_COMMAND);
        assert_eq!(
            d.state(),
            if step == 128 {
                State::Stopped
            } else {
                State::Stopping
            }
        );
    }
    assert_eq!(d.ports.data_reads - reads, 16384);
    assert_eq!(d.ports.data_writes - writes, 16384);
    assert!(d.ports.tick < aggregate);
    let commands = d.ports.commands;
    assert!(d.stop_step(d.ports.tick + 512).is_err());
    assert_eq!(d.ports.commands, commands);
}
#[test]
fn stop_v2_wrong_phase_cut_expiry_regression_corruption_and_bounds_never_advance_or_retry() {
    let mut d = running();
    let commands = d.ports.commands;
    assert!(d.stop_step(d.ports.tick + 512).is_err());
    assert_eq!(d.ports.commands, commands);
    for mode in 0..5 {
        let mut d = running();
        d.ports.memory[0x4000..0x8000].fill(0xa5);
        let now = d.ports.tick;
        let end = now + 8192;
        d.stop_begin(end, now + 512).unwrap();
        let child = match mode {
            0 => end + 1,
            1 => {
                d.ports.tick = now + 512;
                now + 512
            }
            2 => {
                d.ports.tick = now - 1;
                now + 512
            }
            3 => {
                d.ports.dirty_byte = Some(0x4044);
                now + 512
            }
            _ => {
                d.ports.start = 0x47;
                now + 512
            }
        };
        let commands = d.ports.commands;
        assert!(d.stop_step(child).is_err());
        assert_eq!(d.stop.as_ref().unwrap().done, 0);
        assert_eq!(d.state(), State::Quarantined);
        if mode < 3 {
            assert_eq!(d.ports.commands, commands);
        }
        let commands = d.ports.commands;
        assert!(d.stop_step(d.ports.tick + 512).is_err());
        assert_eq!(d.ports.commands, commands);
    }
}

#[test]
fn stop_scrub_groups_bound_every_midgroup_expiry_regression_or_partial_io_to_four_fixed_bytes() {
    for read in [false, true] {
        for position in 1..=4 {
            for mode in 0..3 {
                let mut d = running();
                d.ports.memory[0x4000..0x8000].fill(0xa5);
                d.ports.forbid_start = true;
                let start = d.ports.tick;
                let child = start + 512;
                d.stop_begin(start + 8192, child).unwrap();
                let before = d.ports.data_reads + d.ports.data_writes;
                let at = before + if read { 128 } else { 0 } + position;
                d.ports.data_event = Some((
                    at,
                    match mode {
                        0 => DataEvent::Clock(child),
                        1 => {
                            d.ports.stalled = true;
                            DataEvent::Clock(0)
                        }
                        _ => DataEvent::Io,
                    },
                ));
                let e = d.stop_step(child).unwrap_err();
                assert_eq!(e.progress, Progress::NoFrameSubmitted);
                match mode {
                    0 => assert_eq!(e.error, Error::Deadline),
                    1 => assert_eq!(e.error, Error::ClockReversed),
                    _ => assert_eq!(e.error, Error::Io(Fault::Injected)),
                }
                let attempted = d.ports.data_reads + d.ports.data_writes;
                assert!(attempted >= at && attempted <= at + 3);
                assert_eq!(d.stop.as_ref().unwrap().done, 0);
                assert_eq!(d.state(), State::Quarantined);
                assert!(d.ports.memory[0x4080..0x8000].iter().all(|b| *b == 0xa5));
                let commands = d.ports.commands;
                assert!(d.stop_step(child).is_err());
                assert_eq!(d.ports.commands, commands);
            }
        }
    }
}

#[test]
fn grouped_scrub_counts_all_physical_work_and_reduces_clock_traps_only_for_new_stop_step() {
    let mut d = running();
    let start = d.ports.tick;
    d.stop_begin(start + 8192, start + 512).unwrap();
    let clocks = d.ports.clock_reads;
    let reads = d.ports.data_reads;
    let writes = d.ports.data_writes;
    let ticks = d.ports.tick;
    let progress = d.stop_step(start + 512).unwrap();
    assert_eq!(progress.done, 128);
    assert_eq!(d.ports.data_reads - reads, 128);
    assert_eq!(d.ports.data_writes - writes, 128);
    assert!(d.ports.clock_reads - clocks < 256);
    assert!(d.ports.tick - ticks >= 4); // every64 physical operations still yields
}

#[test]
fn recovery_stops_hostile_previous_state_without_reset_start_or_early_completion() {
    let mut model = Model::new();
    model.forbid_start = true;
    let mut recovery = recovery::Recovery::new(model);
    recovery = match recovery.finish() {
        Err(owner) => owner,
        Ok(_) => panic!("fresh owner has no physical witness"),
    };
    assert_eq!(recovery.begin(8192, 512).unwrap().done, 0);
    assert_eq!(recovery.driver.state(), State::Stopping);
    assert_eq!(recovery.driver.ports.data_writes, 0);
    assert_eq!(recovery.driver.ports.data_reads, 0);
    let commands = recovery.driver.ports.commands;
    assert!(recovery.begin(8193, 512).is_err());
    assert_eq!(recovery.driver.ports.commands, commands);
    for step in 1..=128 {
        let cut = recovery.driver.ports.tick + 512;
        let progress = recovery.step(cut).unwrap();
        assert_eq!(progress.done, step * 128);
        assert_eq!(progress.complete(), step == 128);
        assert_eq!(recovery.driver.ports.command, nic::STOP_COMMAND);
        if step < 128 {
            recovery = match recovery.finish() {
                Err(owner) => owner,
                Ok(_) => panic!("partial scrub cannot produce physical witness"),
            };
        }
    }
    assert_eq!(recovery.driver.ports.data_writes, 16384);
    assert_eq!(recovery.driver.ports.data_reads, 16384);
    assert!(
        recovery.driver.ports.memory[0x4000..]
            .iter()
            .all(|v| *v == 0)
    );
    assert!(
        recovery.driver.ports.memory[..0x4000]
            .iter()
            .all(|v| *v == 0xa5)
    );
    assert!(recovery.driver.ports.tx.is_empty());
    assert!(recovery.driver.ports.tick < 8192);
    let stopped = match recovery.finish() {
        Ok(physical) => physical,
        Err(_) => panic!("complete final actual STOP readback must finish"),
    };
    assert_eq!(stopped.bytes(), 16384);
}

#[test]
fn recovery_wrong_bounds_corrupt_readback_and_unknown_io_keep_the_exact_owner_fenced() {
    for mode in 0..6 {
        let mut model = Model::new();
        model.forbid_start = true;
        if mode == 0 {
            model.ignore_bounds = true;
        } else if mode < 5 {
            model.dirty_byte = Some([0x4000, 0x407f, 0x4080, 0x7fff][mode - 1]);
        } else {
            model.data_event = Some((3, DataEvent::Io));
        }
        let mut recovery = recovery::Recovery::new(model);
        let began = recovery.begin(8192, 512);
        if mode == 0 {
            assert_eq!(began.unwrap_err().error, Error::Readback);
        } else {
            began.unwrap();
            let mut failed = false;
            for _ in 0..128 {
                if recovery.step(recovery.driver.ports.tick + 512).is_err() {
                    failed = true;
                    break;
                }
            }
            assert!(failed);
        }
        assert_eq!(recovery.driver.state(), State::Quarantined);
        recovery = match recovery.finish() {
            Err(owner) => owner,
            Ok(_) => panic!("failed physical readback cannot authorize retirement"),
        };
        let commands = recovery.driver.ports.commands;
        assert!(recovery.begin(9000, 512).is_err());
        assert!(recovery.step(recovery.driver.ports.tick + 512).is_err());
        assert_eq!(recovery.driver.ports.commands, commands);
        assert!(recovery.driver.ports.tx.is_empty());
    }
}

#[test]
fn recovery_has_one_original_aggregate_and_refuses_expired_or_reversed_steps() {
    for mode in 0..3 {
        let mut recovery = recovery::Recovery::new(Model::new());
        recovery.begin(8192, 512).unwrap();
        let cut = match mode {
            0 => 8193,
            1 => {
                recovery.driver.ports.tick = 512;
                512
            }
            _ => {
                recovery.driver.ports.tick = 0;
                recovery.driver.last_tick = 1;
                512
            }
        };
        let commands = recovery.driver.ports.commands;
        assert!(recovery.step(cut).is_err());
        assert_eq!(recovery.driver.ports.commands, commands);
        assert_eq!(recovery.driver.stop.as_ref().unwrap().done, 0);
        assert_eq!(recovery.driver.state(), State::Quarantined);
        assert!(recovery.finish().is_err());
    }
}

fn received_frame(len: usize) -> Driver<Model> {
    let mut d = running();
    let count = len as u16 + 4;
    let next = 0x47 + (count + 4).div_ceil(256) as u8;
    d.ports.current = next;
    d.ports.memory[0x4700..0x4704].copy_from_slice(&[1, next, count as u8, (count >> 8) as u8]);
    for (i, b) in d.ports.memory[0x4704..0x4704 + len].iter_mut().enumerate() {
        *b = i as u8;
    }
    d.ports.byte_read_groups = 0;
    d.ports.byte_write_groups = 0;
    d.ports.batch_cuts.clear();
    d
}
#[test]
fn byte4_receive_keeps_exact_body_tail_same_cut_and_reduces_model_trap_work() {
    for len in [14, 54, 58, 60, 61, 62, 63, 64, 1511, 1512, 1513, 1514] {
        let mut d = received_frame(len);
        let cut = d.ports.tick + 512;
        let before = d.ports.data_reads;
        let clocks = d.ports.clock_reads;
        let mut out = [0xa5; MAX_FRAME_BYTES];
        assert_eq!(d.receive(&mut out, cut).unwrap(), Some(len));
        for (i, b) in out[..len].iter().enumerate() {
            assert_eq!(*b, i as u8);
        }
        assert!(out[len..].iter().all(|b| *b == 0xa5));
        assert_eq!(d.ports.data_reads - before, 4 + len);
        assert_eq!(d.ports.byte_read_groups, 1 + len / 4);
        assert!(d.ports.batch_cuts.iter().all(|c| *c == cut));
        if len == 1514 {
            assert!(
                d.ports.clock_reads - clocks < len,
                "clock transitions reduce versus one per byte; not an actual elapsed-time proof"
            );
        }
    }
}
#[test]
fn byte4_partial_receive_or_midgroup_expiry_never_advances_rx_or_retries() {
    for at in 1..=4 {
        for fault in 0..3 {
            let mut d = received_frame(1514);
            let cut = d.ports.tick + 512;
            let reads = d.ports.data_reads;
            let boundary = d.ports.boundary;
            let next = d.next_rx;
            let event = match fault {
                0 => DataEvent::Clock(cut),
                1 => DataEvent::Clock(d.ports.tick - 1),
                _ => DataEvent::Io,
            };
            d.ports.data_event = Some((reads + d.ports.data_writes + 4 + at, event));
            let mut out = [0xa5; MAX_FRAME_BYTES];
            assert!(d.receive(&mut out, cut).is_err());
            assert_eq!(d.state(), State::Quarantined);
            assert_eq!((d.next_rx, d.ports.boundary), (next, boundary));
            assert!(d.ports.data_reads - reads <= 8);
            assert!(out.iter().all(|b| *b == 0xa5));
            let reads = d.ports.data_reads;
            let commands = d.ports.commands;
            assert!(d.receive(&mut out, cut).is_err());
            assert_eq!((d.ports.data_reads, d.ports.commands), (reads, commands));
        }
    }
}
#[test]
fn byte4_transmit_exact_groups_and_tail_do_not_change_byte_mode_or_submission_identity() {
    for len in [60, 61, 62, 63, 1514] {
        let mut d = running();
        d.ports.byte_write_groups = 0;
        d.ports.batch_cuts.clear();
        let frame: Vec<_> = (0..len).map(|i| i as u8).collect();
        let cut = d.ports.tick + 512;
        assert_eq!(d.transmit(&frame, cut).unwrap().bytes as usize, len);
        assert_eq!(d.ports.byte_write_groups, len / 4);
        assert_eq!(d.ports.tx.last().unwrap(), &frame);
        assert_eq!(d.ports.dcfg, 0x48);
        assert!(d.ports.batch_cuts.iter().all(|c| *c == cut));
    }
}

#[test]
fn cold_aggregate_does_not_attempt_overlong_batch_or_renew_its_cut() {
    let mut d = Driver::new(Model::new());
    d.initialize(REFERENCE_MAC, 8192).unwrap();
    assert_eq!(d.state(), State::Prepared);
    assert_eq!(d.ports.dcfg, 0x48);
    assert_eq!(
        (d.ports.byte_read_groups, d.ports.byte_write_groups),
        (0, 0)
    );
    assert!(d.ports.batch_cuts.is_empty());
    assert!(d.ports.tick < 8192 - 1024);
    assert!(d.ports.memory[0x4000..0x8000].iter().all(|b| *b == 0));
}

fn checked_receive(len: usize, wrapped: bool, reuse: bool) -> Driver<Model> {
    let mut d = received_frame(len);
    if wrapped {
        assert_eq!(len, MAX_FRAME_BYTES);
        d.next_rx = 0x7f;
        d.ports.current = 0x4b;
        d.ports.memory[0x7f00..0x7f04].copy_from_slice(&[1, 0x4b, 0xee, 5]);
        for index in 0..len {
            let address = if index < 252 {
                0x7f04 + index
            } else {
                0x4600 + index - 252
            };
            d.ports.memory[address] = index as u8;
        }
    }
    d.ports.reuse_clock = reuse;
    d.ports.core_deadlines = true;
    d.ports.port_trace = Some(Vec::new());
    d
}

#[test]
fn trusted_rx_reuses_only_later_group_prechecks_with_identical_physical_work() {
    for (len, wrapped) in [
        (14, false),
        (60, false),
        (63, false),
        (1514, false),
        (1514, true),
    ] {
        let mut before = checked_receive(len, wrapped, false);
        let mut after = checked_receive(len, wrapped, true);
        let cut = before.ports.tick + 512;
        let clocks = (before.ports.clock_reads, after.ports.clock_reads);
        let yields = (before.ports.yields, after.ports.yields);
        let mut left = [0xa5; MAX_FRAME_BYTES];
        let mut right = left;
        assert_eq!(
            before.receive(&mut left, cut),
            after.receive(&mut right, cut)
        );
        assert_eq!(before.state(), State::Running);
        assert_eq!(left, right);
        for (index, byte) in right[..len].iter().enumerate() {
            assert_eq!(*byte, index as u8);
        }
        assert!(right[len..].iter().all(|byte| *byte == 0xa5));
        assert_eq!(before.ports.port_trace, after.ports.port_trace);
        assert_eq!(before.ports.data_reads, after.ports.data_reads);
        assert_eq!(before.ports.batch_cuts, after.ports.batch_cuts);
        assert!(after.ports.batch_cuts.iter().all(|value| *value == cut));
        assert_eq!(
            (before.next_rx, before.ports.boundary),
            (after.next_rx, after.ports.boundary)
        );
        assert_eq!(
            before.ports.yields - yields.0,
            after.ports.yields - yields.1
        );
        let skipped = if wrapped {
            (252 / 4 - 1) + (1262 / 4 - 1)
        } else {
            len / 4 - 1
        };
        assert_eq!(
            before.ports.clock_reads - clocks.0,
            after.ports.clock_reads - clocks.1 + skipped
        );
    }
}

#[test]
fn actual_core_preemption_refuses_before_any_expired_group_and_never_retries() {
    let mut d = checked_receive(60, false, true);
    let cut = d.ports.tick + 512;
    // Header, first body group, then actual Core admission of the later group.
    d.ports.preempt_byte4 = Some((3, cut));
    let reads = d.ports.data_reads;
    let next = (d.next_rx, d.ports.boundary);
    let mut out = [0xa5; MAX_FRAME_BYTES];
    assert_eq!(
        d.receive(&mut out, cut).unwrap_err().error,
        Error::Io(Fault::CoreDeadline)
    );
    assert_eq!(d.ports.data_reads - reads, 8);
    assert_eq!(&out[..4], &[0, 1, 2, 3]);
    assert!(out[4..].iter().all(|byte| *byte == 0xa5));
    assert_eq!((d.next_rx, d.ports.boundary), next);
    assert_eq!(d.state(), State::Quarantined);
    let attempts = (
        d.ports.data_reads,
        d.ports.commands,
        d.ports.byte_read_groups,
    );
    assert_eq!(d.receive(&mut out, cut).unwrap_err().error, Error::State);
    assert_eq!(
        (
            d.ports.data_reads,
            d.ports.commands,
            d.ports.byte_read_groups
        ),
        attempts
    );
}

#[test]
fn later_group_partial_error_expiry_or_reversal_never_copies_that_group() {
    for at in 1..=4 {
        for fault in 0..3 {
            let mut d = checked_receive(60, false, true);
            let cut = d.ports.tick + 512;
            let reads = d.ports.data_reads;
            let event = match fault {
                0 => DataEvent::Clock(cut),
                1 => DataEvent::Clock(d.ports.tick - 1),
                _ => DataEvent::Io,
            };
            d.ports.data_event = Some((reads + d.ports.data_writes + 8 + at, event));
            let next = (d.next_rx, d.ports.boundary);
            let mut out = [0xa5; MAX_FRAME_BYTES];
            assert!(d.receive(&mut out, cut).is_err());
            assert_eq!(&out[..4], &[0, 1, 2, 3]);
            assert!(out[4..].iter().all(|byte| *byte == 0xa5));
            assert_eq!((d.next_rx, d.ports.boundary), next);
            assert_eq!(d.state(), State::Quarantined);
        }
    }
}

#[test]
fn first_group_and_default_false_keep_fresh_clock_guards_and_step_bound() {
    for reuse in [false, true] {
        let mut d = checked_receive(60, false, reuse);
        let cut = d.ports.tick + 512;
        d.ports.expire_after_transfer = Some(cut);
        let reads = d.ports.data_reads;
        let mut bytes = [0xa5; 8];
        let mut b = Budget {
            deadline: cut,
            steps: 0,
        };
        assert_eq!(
            d.read_bytes(0x4704, &mut bytes, false, &mut b),
            Err(Error::Deadline)
        );
        assert_eq!(d.ports.byte_read_groups, 0);
        assert_eq!(d.ports.data_reads, reads);
        assert_eq!(bytes, [0xa5; 8]);
    }
    let mut d = checked_receive(60, false, false);
    let cut = d.ports.tick + 512;
    d.ports.tick = d.last_tick - 1;
    let mut b = Budget {
        deadline: cut,
        steps: 0,
    };
    let attempts = d.ports.byte_read_groups;
    assert_eq!(d.read_data4(&mut b, false), Err(Error::ClockReversed));
    assert_eq!(d.ports.byte_read_groups, attempts);
    b.steps = MAX_STEPS - 3;
    assert_eq!(d.read_data4(&mut b, true), Err(Error::PollBudget));
    assert_eq!(d.ports.byte_read_groups, attempts);
}

#[test]
fn cold_stop_tx_and_overlong_scalar_paths_do_not_elide_any_clock() {
    for operation in 0..4 {
        let mut before = checked_receive(1514, false, false);
        let mut after = checked_receive(1514, false, true);
        let clocks = (before.ports.clock_reads, after.ports.clock_reads);
        match operation {
            0 => {
                let mut left = [0; MAX_FRAME_BYTES];
                let mut right = left;
                let cut = before.ports.tick + 8192;
                assert_eq!(
                    before.receive(&mut left, cut),
                    after.receive(&mut right, cut)
                );
                assert_eq!(left, right);
                assert_eq!(after.ports.byte_read_groups, 0);
            }
            1 => {
                let cut = before.ports.tick + 512;
                assert_eq!(
                    before.transmit(&[7; 60], cut),
                    after.transmit(&[7; 60], cut)
                );
            }
            2 => {
                let cut = before.ports.tick + 512;
                assert_eq!(
                    before.stop_begin(cut + 7680, cut),
                    after.stop_begin(cut + 7680, cut)
                );
                assert_eq!(before.stop_step(cut), after.stop_step(cut));
            }
            _ => {
                let mut left = [0; 8];
                let mut right = left;
                let cut = before.ports.tick + 512;
                let mut a = Budget {
                    deadline: cut,
                    steps: 0,
                };
                let mut b = Budget {
                    deadline: cut,
                    steps: 0,
                };
                assert_eq!(
                    before.read_bytes(0x4704, &mut left, true, &mut a),
                    after.read_bytes(0x4704, &mut right, true, &mut b)
                );
            }
        }
        assert_eq!(
            before.ports.clock_reads - clocks.0,
            after.ports.clock_reads - clocks.1
        );
        assert_eq!(before.ports.port_trace, after.ports.port_trace);
    }
}
