//! Bounded actual profile and fatal finite-bound census. Reads retained state and never
//! completes, cancels, drops or retries a caller's accepted IPC operation.
use super::*;
use core::fmt::Write;
impl Runtime<'_, '_> {
    /// Serialized restored-CR3/IF0 sampling. Fixed slot counters are cumulative
    /// over actual captured incarnations, while current IDs/Job CPU are a later
    /// observation. Zero current IDs mean no retained actor in that slot.
    #[inline(never)]
    pub(super) fn emit_profile(&self, phase: &str) {
        let Some(native) = &self.native else {
            return;
        };
        assert!(matches!(phase, "bound" | "finished"));
        let mut serial = crate::serial::Serial::initialize(8192);
        let build = option_env!("EVROSION_BUILD_ID").unwrap_or("unrecorded");
        let elapsed_ticks = crate::timer::now()
            .checked_sub(native.profile.started)
            .unwrap();
        for (index, slot) in native.profile.slots.iter().enumerate() {
            let (process, thread, job, job_cpu) = self
                .metadata(index)
                .map(|m| {
                    (
                        m.process.diagnostic_id(),
                        m.thread.diagnostic_id(),
                        m.job.diagnostic_id(),
                        self.s.usage(m.job, Resource::CpuTicks).unwrap(),
                    )
                })
                .unwrap_or((0, 0, 0, 0));
            assert_eq!(slot.captures, slot.syscalls + slot.irqs + slot.faults);
            assert_eq!(slot.charged_cpu_ticks, slot.irqs);
            let _ = writeln!(
                serial,
                "EVROSION_M5_NATIVE_PROFILE protocol=1 build={build} phase={phase} scope=actor_slot index={index} current_process={process} current_thread={thread} current_job={job} incarnations={} elapsed_ticks={elapsed_ticks} captures={} syscalls={} irqs={} faults={} port_in={} port_out={} yields={} continuations={} charged_cpu_ticks={} current_job_cpu_ticks={job_cpu} cpu_scope=subtree",
                slot.incarnations,
                slot.captures,
                slot.syscalls,
                slot.irqs,
                slot.faults,
                slot.port_in,
                slot.port_out,
                slot.yields,
                slot.continuations,
                slot.charged_cpu_ticks
            );
        }
    }

    #[inline(never)]
    pub(super) fn diagnose_bound(&self, transitions: u64, now: u64) {
        self.emit_profile("bound");
        // Serialized restored-CR3/IF0 failure path only. The ordinary observer
        // is not called again. A separate finite UART counter emits at most
        // eight pending + seven actor + sixteen wire + four Events receipt
        // lines before the panic.
        let mut serial = crate::serial::Serial::initialize(12288);
        let build = option_env!("EVROSION_BUILD_ID").unwrap_or("unrecorded");
        let _ = writeln!(
            serial,
            "EVROSION_M5_NATIVE_BOUND protocol=1 build={build} ticks={now} transitions={transitions} outstanding={} calls={} replies={}",
            self.rpc.outstanding(),
            self.facts.calls,
            self.facts.replies
        );
        for (slot, pending) in self.pending.iter().enumerate() {
            if let Some(p) = pending {
                let _ = writeln!(
                    serial,
                    "EVROSION_M5_NATIVE_PENDING protocol=1 build={build} slot={slot} wire={} caller={} callee={} delivered={} value={:#018x} call_id={} waiting={}",
                    p.wire,
                    p.caller,
                    p.callee,
                    p.delivered,
                    p.value,
                    p.id.serial(),
                    self.s.waiting(p.wait)
                );
            }
        }
        for index in 0..7 {
            let Some(meta) = self.metadata(index) else {
                continue;
            };
            let context = if index == 0 {
                &self.root.context
            } else {
                &self.actors[index - 1].as_ref().unwrap().context
            };
            let syscall = self.native.as_ref().and_then(|n| n.last_syscall[index]);
            let _ = writeln!(
                serial,
                "EVROSION_M5_NATIVE_ACTOR protocol=1 build={build} index={index} process={} thread={} state={:?} rip={:#x} rsp={:#x} vector={} last_syscall={syscall:?} captured_rax={}",
                meta.process.diagnostic_id(),
                meta.thread.diagnostic_id(),
                self.s.state(meta.thread),
                context.rip,
                context.rsp,
                context.vector,
                context.registers[14]
            );
        }
        for (index, wire) in self.wires.iter().enumerate() {
            let Some(wire) = wire else {
                continue;
            };
            let receiver =
                (0..7).find(|&i| self.metadata(i).is_some_and(|m| m.domain == wire.receiver));
            let bound = wire.bound.map(ThreadId::diagnostic_id);
            let _ = writeln!(
                serial,
                "EVROSION_M5_NATIVE_WIRE protocol=1 build={build} index={index} endpoint={} receiver={receiver:?} bound_thread={bound:?} pending={} closed={}",
                wire.object,
                wire.pending(),
                wire.closed
            );
            if index == 15 {
                for (ticket, process, thread) in wire.accepted_senders() {
                    let _ = writeln!(
                        serial,
                        "EVROSION_M5_NATIVE_ACCEPTED protocol=1 build={build} wire={index} ticket={ticket} process={process} thread={thread}"
                    );
                }
            }
        }
    }
}
