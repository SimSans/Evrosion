//! Captured V4 Root retirement join. Core proves actual actor exclusion and
//! canonical call/queue quiescence; the sealed trusted Root/Driver code proves
//! the physical scoped PIO STOP/scrub/readback. No App or event supplies proof.
use super::*;
use core::fmt::Write;
impl Runtime<'_, '_> {
    #[inline(never)]
    pub(super) fn retire_network(
        &mut self,
        caller: Metadata,
        operation: u64,
        driver: Handle,
        service: Handle,
        extra: u64,
        now: u64,
    ) -> Result<u64, u64> {
        if caller != self.root.meta
            || self.find_control(caller.domain, driver)? != 7
            || self.find_control(caller.domain, service)? != 8
        {
            return Err(1);
        }
        let mut pair = [0; 4];
        for (i, index) in [7, 8].into_iter().enumerate() {
            let actor = self.actors[index - 1].as_ref().ok_or(1u64)?;
            let meta = actor.meta;
            if self.s.state(meta.thread) != Ok(State::Exited)
                || actor.running.is_some()
                || actor.returned.is_none()
                || self.rpc.serving(meta.thread).is_some()
                || self
                    .pending
                    .iter()
                    .flatten()
                    .any(|p| p.caller == index || p.callee == index)
            {
                return Err(2);
            }
            pair[i * 2] = meta.process.diagnostic_id();
            pair[i * 2 + 1] = meta.thread.diagnostic_id();
        }
        for wire in [16, 17] {
            let actual = self.wires[wire].as_ref().ok_or(1u64)?;
            if !actual.closed || actual.pending() != 0 {
                return Err(2);
            }
        }
        let value = match operation {
            0 => self.network_fault.begin_retirement(pair, now, extra)?,
            1 => self.network_fault.finish_retirement(pair, extra, now)?,
            _ => return Err(1),
        };
        // Bounded two-row source-bound context; this row alone never claims a
        // physical receipt or substitutes for the trusted Root implementation.
        let mut serial = crate::serial::Serial::initialize(2048);
        let build = option_env!("EVROSION_BUILD_ID").unwrap_or("unrecorded");
        let _ = writeln!(
            serial,
            "EVROSION_M6_NETWORK_RETIREMENT protocol=1 build={build} root_process={} root_thread={} operation={operation} driver_process={} driver_thread={} service_process={} service_thread={} extra={extra} tick={now} value={value} physical_proof=trusted-root-source",
            caller.process.diagnostic_id(),
            caller.thread.diagnostic_id(),
            pair[0],
            pair[1],
            pair[2],
            pair[3]
        );
        Ok(value)
    }
}
