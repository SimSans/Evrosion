//! Captured Root-only VM power fence. The Kernel proves actual CPU/capability/
//! IPC exclusion; sealed Root code must perform physical ATA FLUSH and NIC
//! STOP/scrub/readback before COMPLETE. No packet or Root EXIT is that proof.
use super::*;
use ev_kernel::session_power::{Intent, Phase};
impl World {
    pub(super) fn power_dialog_report(
        &mut self,
        index: usize,
        nonce: u64,
        frame: u64,
        input: u64,
        log: &mut dyn Write,
    ) -> Result<u64, u64> {
        if !self.power_root(index) {
            return Err(1);
        }
        let r = ev_kernel::session_power::Readiness::decode(nonce, frame, input).ok_or(1u64)?;
        self.power.note_dialog_report()?;
        let intent = if r.restart { "restart" } else { "shutdown" };
        let _ = writeln!(
            log,
            "EVROSION_M8_POWER_DIALOG phase=armed build={} intent={intent} nonce={} frame={} barrier={} main_held={} keypad_held={} main_released={} keypad_released={} pointer_held={} pointer_released={} root_process={} root_thread={} scope=trusted_root_pacing_only",
            crate::BUILD_ID,
            r.nonce,
            r.frame,
            r.sequence,
            r.main_held,
            r.keypad_held,
            r.main_released,
            r.keypad_released,
            r.pointer_held,
            r.pointer_released,
            self.root.meta.process.diagnostic_id(),
            self.root.meta.thread.diagnostic_id()
        );
        Ok(0)
    }
    /// Only the separately selected Internal Q35 test executor has this reset
    /// adapter. This is not generic hardware or normal-kernel support.
    pub(super) const fn restart_supported() -> bool {
        cfg!(all(
            feature = "test-m8-workspace-run",
            feature = "qemu-test-exit"
        ))
    }
    fn power_root(&self, index: usize) -> bool {
        index == 0
            && self.root.active.is_some()
            && ev_kernel::managed_send::Context {
                caller: self.current(index),
                root: self.root.meta,
                token: self.token,
            }
            .validate(self.core.a, self.core.s)
            .is_ok()
    }
    fn power_no_debt(&self) -> bool {
        self.core.rpc.outstanding() == 0
            && self.pending.iter().all(Option::is_none)
            && self.wires.iter().flatten().all(|w| !w.power_debt())
            && self.selected.iter().all(grant::Selected::power_drained)
    }
    pub(super) fn session_power(
        &mut self,
        index: usize,
        operation: u64,
        block: Handle,
        nic: Handle,
        extra: u64,
        log: &mut dyn Write,
    ) -> Result<u64, u64> {
        if !self.power_root(index) {
            return Err(1);
        }
        let bi = self.find_control(self.root.meta.domain, block)?;
        let ni = self.find_control(self.root.meta.domain, nic)?;
        let ba = self.actors[bi - 1].as_ref().ok_or(1u64)?;
        let na = self.actors[ni - 1].as_ref().ok_or(1u64)?;
        if ba.child != Child::Block
            || na.child != Child::NetDriver
            || !ba.admitted
            || !na.admitted
            || ba.retired
            || na.retired
        {
            return Err(1);
        }
        let pair = [
            ba.meta.process.diagnostic_id(),
            ba.meta.thread.diagnostic_id(),
            na.meta.process.diagnostic_id(),
            na.meta.thread.diagnostic_id(),
        ];
        let now = crate::timer::now();
        if operation == 1 && !Self::restart_supported() {
            return Err(1);
        }
        if !self.power_no_debt() {
            return Err(2);
        }
        if self.actors.iter().enumerate().any(|(i, a)| {
            a.as_ref().is_some_and(|a| {
                a.admitted
                    && i + 1 != bi
                    && i + 1 != ni
                    && self.core.s.state(a.meta.thread) != Ok(State::Exited)
            })
        }) {
            return Err(2);
        }
        match operation {
            0 | 1 => {
                let intent = if operation == 0 {
                    Intent::Shutdown
                } else {
                    Intent::Restart
                };
                let token = self.power.begin_intent(intent, pair, now, extra)?;
                // Latch BEFORE the first CPU/grant effect. Any failure leaves
                // that same partial fence and all physical owners retained.
                for i in [bi, ni] {
                    if self.stop_actor_inner(i, log, true).is_err() {
                        return Err(3);
                    }
                }
                let _ = writeln!(
                    log,
                    "EVROSION_M8_SESSION_POWER phase=devices_cpu_frozen token={token} cut={extra} tick={now} physical_proof=pending_trusted_root"
                );
                Ok(token)
            }
            2 => {
                if self.actors.iter().flatten().any(|a| {
                    a.admitted
                        && (self.core.s.state(a.meta.thread) != Ok(State::Exited)
                            || a.running.is_some())
                }) {
                    return Err(2);
                }
                self.power.complete(pair, extra, now)?;
                let phase = match self.power.completed_intent().ok_or(3u64)? {
                    Intent::Shutdown => "checked_shutdown",
                    Intent::Restart => "checked_restart",
                };
                let _ = writeln!(
                    log,
                    "EVROSION_M8_SESSION_POWER phase={phase} token={extra} tick={now} rpc=0 windows=0 async_debt=0 physical_proof=trusted_root_flush_stop_scrub sources_retained_until_power=true"
                );
                Ok(0)
            }
            _ => Err(1),
        }
    }
    pub(super) fn power_call_allowed(&self, call: &Call, now: u64) -> bool {
        if !self.power.active() {
            return true;
        }
        if matches!(
            call,
            Call::Yield
                | Call::Monotonic
                | Call::SessionPowerInfo { .. }
                | Call::SessionPower { .. }
        ) {
            return true;
        }
        self.power.live(now)
            && matches!(
                call,
                Call::PortInput { .. }
                    | Call::PortOutput { .. }
                    | Call::PortInputWords4 { .. }
                    | Call::PortOutputWords4 { .. }
                    | Call::PortInputBytes4 { .. }
                    | Call::PortOutputBytes4 { .. }
                    | Call::PortBatchInfo
                    | Call::PortByteBatchInfo
            )
    }
    pub(super) fn checked_power(&self) -> bool {
        self.power.phase() == Phase::Complete
    }
}
