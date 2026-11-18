//! Explicit negative-fixture observations and one deterministic captured-call
//! stop. Never selected by ordinary V4, App bytes, or host timing guesses.
use super::*;
use core::fmt::{self, Write};
mod cpu;
mod returned;

pub(super) struct Probe {
    sequence: u16,
    denied: u8,
    watch_cut: u64,
    watching: bool,
    armed: usize,
    injected: bool,
    omitted: u64,
    read_pending: bool,
    returned: returned::Returned,
    cpu_samples: u8,
    work_delivered: u8,
}
impl Probe {
    pub const fn new() -> Self {
        Self {
            sequence: 0,
            denied: 0,
            watch_cut: 0,
            watching: false,
            armed: 0,
            injected: false,
            omitted: 0,
            read_pending: false,
            returned: returned::Returned::new(),
            cpu_samples: 0,
            work_delivered: 0,
        }
    }
}
struct Hex([u8; 32]);
impl fmt::Display for Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
impl Runtime<'_, '_> {
    #[allow(clippy::too_many_arguments)] // One fixed actual-observation schema.
    #[inline(never)]
    fn negative_record(
        &mut self,
        kind: u8,
        actor: usize,
        pending: Option<Pending>,
        opcode: u64,
        status: u64,
        length: u64,
        value: u64,
        request: u64,
        payload: [u8; 32],
    ) {
        // Ninety-six fixed rows, never an unbounded frame/packet history.
        if kind != 8 && self.network_negative.sequence >= 96 {
            self.network_negative.omitted = self.network_negative.omitted.saturating_add(1);
            return;
        }
        self.network_negative.sequence += 1;
        let sequence = self.network_negative.sequence;
        let current = self.metadata(actor).unwrap();
        let (epoch, call, endpoint, ticket, deadline, cp, ct, dp, dt) =
            pending.map_or((0, 0, 0, 0, 0, 0, 0, 0, 0), |p| {
                let caller = self.metadata(p.caller).unwrap();
                let callee = self.metadata(p.callee).unwrap();
                (
                    p.id.epoch().get(),
                    p.id.serial(),
                    self.wires[p.wire].as_ref().unwrap().object as u64,
                    p.ticket.0,
                    p.deadline.tick(),
                    caller.process.diagnostic_id(),
                    caller.thread.diagnostic_id(),
                    callee.process.diagnostic_id(),
                    callee.thread.diagnostic_id(),
                )
            });
        let image = if actor == 0 {
            self.native.as_ref().unwrap().root_image_sha256
        } else {
            self.actors[actor - 1].as_ref().unwrap().image_sha256
        };
        let tick = crate::timer::now();
        let mut output = crate::serial::Serial::initialize(4096);
        let build = option_env!("EVROSION_BUILD_ID").unwrap_or("unrecorded");
        let _ = writeln!(
            output,
            "EVROSION_M6_NEGATIVE protocol=1 build={build} sequence={sequence} kind={kind} actor={actor} process={} thread={} tick={tick} call_epoch={epoch} call={call} endpoint={endpoint} ticket={ticket} deadline={deadline} caller_process={cp} caller_thread={ct} callee_process={dp} callee_thread={dt} opcode={opcode} status={status} length={length} value={value} request={request} payload_sha256={} image_sha256={}",
            current.process.diagnostic_id(),
            current.thread.diagnostic_id(),
            Hex(payload),
            Hex(image)
        );
    }
    pub(super) fn negative_arm(&mut self, operation: u64, cut: u64, now: u64) -> Result<(), u64> {
        if cut == u64::MAX || cut <= now || cut - now > 8192 {
            return Err(4);
        }
        if operation == 4 {
            if cut - now > 512 {
                return Err(4);
            }
            return self.negative_cpu_sample();
        }
        if operation == 3 {
            if self.network_negative.watch_cut != 0 {
                return Err(2);
            }
            self.network_negative.watch_cut = cut;
            self.network_negative.watching = true;
        } else {
            if !matches!(operation, 1 | 2)
                || self.network_negative.armed != 0
                || self.network_negative.injected
                || self.network_negative.watch_cut != cut
                || !self.network_negative.watching
            {
                return Err(2);
            }
            self.network_negative.armed = if operation == 1 { 7 } else { 8 };
        }
        self.negative_record(0, 0, None, operation, 0, 0, cut, 0, [0; 32]);
        Ok(())
    }
    /// Called only after the real syscall has written its canonical denial.
    pub(super) fn negative_denial(
        &mut self,
        actor: usize,
        opcode: u64,
        port: u64,
        request: u64,
        frame: &UserContext,
    ) {
        if actor != 5
            || frame.registers[14] != 1
            || frame.registers[9] != 0
            || frame.registers[11] != 0
            || frame.registers[5] != 0
        {
            return;
        }
        let bit = match opcode {
            35 if port == 0x300 => 1,
            36 if port == 0x300 => 2,
            ev_userspace_contract::syscall::RPC_CALL
                if request == u64::from_le_bytes(*b"S\x01\x05\0\x01\0\0\0") =>
            {
                4
            }
            53 => 8,
            50 if port == 0x310 && request == 0 => 16,
            51 if port == 0x310 && request == 0x12345678 => 32,
            _ => return,
        };
        if self.network_negative.denied & bit != 0 {
            return;
        }
        self.network_negative.denied |= bit;
        self.negative_record(1, actor, None, opcode, 1, 0, port, request, [0; 32]);
    }
    /// Actual fixed scalar mapping, captured sole writer, no user pointer.
    /// Stream full-window hashing avoids a4KiB automatic snapshot.
    fn negative_window(&self, which: Scalar) -> ([u8; 32], [u8; 32]) {
        let address = self.backing.alias(which);
        let mut hash = Sha256::new();
        let mut header = [0; 32];
        for block in 0..64 {
            let chunk: [u8; 64] = core::array::from_fn(|offset| {
                // SAFETY: retained actual scalar frame; all user CPUs captured
                // on the sole restored-CR3 controller. No borrow escapes.
                unsafe {
                    (address as *const u8)
                        .add(block * 64 + offset)
                        .read_volatile()
                }
            });
            hash.update(chunk);
            if block == 0 {
                header.copy_from_slice(&chunk[..32]);
            }
        }
        (hash.finalize().into(), header)
    }
    pub(super) fn negative_client(&mut self, p: Pending, reply: Option<u64>) {
        if !self.network_negative.watching || p.wire != 17 || p.caller != 0 || p.callee != 8 {
            return;
        }
        let (hash, h) = self.negative_window(Scalar::NetClient);
        let request = p.value.to_le_bytes();
        assert_eq!(&h[..8], b"EVNET001");
        assert_eq!(h[11], request[2]);
        assert_eq!(&h[16..20], &request[4..8]);
        assert_eq!(h[10], u8::from(reply.is_some()));
        let length = u16::from_le_bytes(h[14..16].try_into().unwrap()) as u64;
        let address = self.backing.alias(Scalar::NetClient) + 64;
        let value = u64::from_le_bytes(core::array::from_fn(|i| {
            // SAFETY: same captured retained frame as negative_window.
            unsafe { (address as *const u8).add(i).read_volatile() }
        }));
        // Polling is ordinary finite work, not an unbounded trace. Keep the
        // semantic successful status/query and first real Pending read. Any
        // residual overflow is reported explicitly, never a Kernel panic.
        if reply.is_none() && matches!(h[11], 2 | 4 | 7 | 11) {
            return;
        }
        if reply.is_some() {
            // Cooperative shutdown Pending is a bounded continuation, not a
            // new whole-device proof. Preserve only its actual final Complete
            // (or an actual refusal/uncertainty), plus all nested fault rows.
            if h[11] == 11 && h[12] == 1 {
                return;
            }
            if h[11] == 2
                && (h[12] != 0 || value.to_le_bytes()[1] != 1 || value.to_le_bytes()[2] != 4)
            {
                return;
            }
            if h[11] == 4 && h[12] != 0 {
                return;
            }
            if h[11] == 7 && h[12] == 1 {
                if self.network_negative.read_pending {
                    return;
                }
                self.network_negative.read_pending = true;
            }
        }
        if let Some(reply) = reply {
            let b = reply.to_le_bytes();
            assert_eq!(b[0], b's');
            assert_eq!(b[3], h[11]);
            assert_eq!(b[2], h[12]);
        }
        self.negative_record(
            if reply.is_some() { 3 } else { 2 },
            if reply.is_some() { 8 } else { 0 },
            Some(p),
            u64::from(h[11]),
            u64::from(h[12]),
            length,
            value,
            p.value,
            hash,
        );
        // Actual successful EOF closes this completed transfer's observation
        // scope. Later ordinary Finish has its own unchanged physical witness;
        // its128 cooperative steps are not part of a destination-denial trace.
        if reply.is_some() && h[11] == 7 && h[12] == 0 && length == 0 {
            self.network_negative.watching = false;
        }
    }
    /// This executes at the actual Driver's captured RECEIVE_RPC, after exact
    /// delivery, while Service is awaiting that child and Root awaits Service.
    /// Stop is a trusted fixture action, never a fabricated user fault/Exit.
    pub(super) fn negative_inject_current_call(&mut self, current: usize) -> bool {
        let victim = self.network_negative.armed;
        if current != 7 || !matches!(victim, 7 | 8) || self.network_negative.injected {
            return false;
        }
        let now = crate::timer::now();
        assert!(now < self.network_negative.watch_cut);
        let Some(inner) = self
            .pending
            .iter()
            .flatten()
            .copied()
            .find(|p| p.caller == 8 && p.callee == 7 && p.wire == 16 && p.delivered)
        else {
            return false;
        };
        let notice = inner.value.to_le_bytes();
        if notice[..4] != [b'N', 2, 6, 0] {
            return false;
        }
        let Some(outer) = self
            .pending
            .iter()
            .flatten()
            .copied()
            .find(|p| p.caller == 0 && p.callee == 8 && p.wire == 17 && p.delivered)
        else {
            return false;
        };
        assert_eq!(outer.value.to_le_bytes()[2], 10);
        assert!(inner.deadline.tick() <= outer.deadline.tick());
        assert!(outer.deadline.tick() <= self.network_negative.watch_cut);
        assert!(self.s.waiting(inner.wait) && self.s.waiting(outer.wait));
        assert_eq!(
            self.rpc.serving(self.metadata(7).unwrap().thread),
            Some(inner.id)
        );
        assert_eq!(
            self.rpc.serving(self.metadata(8).unwrap().thread),
            Some(outer.id)
        );
        let (hash, _) = self.negative_window(Scalar::Nic);
        self.negative_record(
            4,
            7,
            Some(inner),
            6,
            0,
            4096,
            outer.id.serial(),
            inner.value,
            hash,
        );
        let (outer_hash, _) = self.negative_window(Scalar::NetClient);
        self.negative_record(
            5,
            8,
            Some(outer),
            10,
            0,
            4096,
            inner.id.serial(),
            outer.value,
            outer_hash,
        );
        assert!(self.network_negative.returned.capture(
            Self::negative_call(inner),
            Self::negative_call(outer),
            self.network_negative.watch_cut,
            victim
        ));
        let target = self.metadata(victim).unwrap();
        if victim == current {
            assert_eq!(self.s.exit(0), Ok(target.thread));
        }
        self.s.terminate_process(target.process).unwrap();
        assert_eq!(self.s.state(target.thread), Ok(State::Exited));
        assert!(self.network_fault.record_controller_stop(victim));
        self.network_negative.injected = true;
        self.negative_record(
            6,
            victim,
            Some(inner),
            0,
            1,
            0,
            outer.id.serial(),
            inner.value,
            [0; 32],
        );
        victim == current
    }
    /// Emitted after canonical withdrawal/dead-callee quiescence removed the
    /// exact Pending and returned/woke its guarded owner, without a reply.
    pub(super) fn negative_cancelled(&mut self, p: Pending) {
        if self.network_negative.watch_cut == 0 {
            return;
        }
        assert!(!self.pending.iter().flatten().any(|q| q.id == p.id));
        assert!(!self.s.waiting(p.wait));
        let terminal = p.terminal.unwrap();
        let status = match terminal.status {
            Status::DeadlineExceeded => 4,
            Status::PeerDied => 5,
            Status::Cancelled => 6,
            Status::Ok => unreachable!(),
        };
        if self.network_negative.injected {
            let _ = self
                .network_negative
                .returned
                .record(Self::negative_call(p), terminal.status);
        }
        self.negative_record(7, p.caller, Some(p), 0, status, 0, 0, p.value, [0; 32]);
    }
    fn negative_call(p: Pending) -> returned::Call {
        returned::Call {
            epoch: p.id.epoch().get(),
            id: p.id.serial(),
            caller: p.caller,
            callee: p.callee,
            wire: p.wire,
            ticket: p.ticket.0,
            deadline: p.deadline.tick(),
            request: p.value,
        }
    }
    pub(super) fn negative_no_ack_returns(&self) -> u64 {
        self.network_negative
            .returned
            .completed_count()
            .expect("mandatory actual stopped-callee PeerDied guard return")
    }
    pub(super) fn negative_finish(&mut self) {
        let omitted = self.network_negative.omitted;
        self.negative_record(8, 0, None, 0, 0, 0, omitted, 0, [0; 32]);
    }
}
