//! Fixed sector transfer for the actual captured, selected Block actor only.
//! Physical private RAM ownership and IoPorts authority are independent joins.
use super::*;
#[derive(Default)]
pub(super) struct Metrics {
    pub inputs: u64,
    pub outputs: u64,
    pub cycles: u64,
    pub max_cycles: u64,
    pub handler_cycles: u64,
    pub max_handler_cycles: u64,
    pub denials: u64,
}
#[repr(align(2))]
struct Scratch([u8; 512]);
impl World {
    pub(super) fn selected_block(&self, index: usize) -> bool {
        let Some(actor) = index
            .checked_sub(1)
            .and_then(|i| self.actors.get(i))
            .and_then(Option::as_ref)
        else {
            return false;
        };
        let Some(running) = actor.running.as_ref() else {
            return false;
        };
        let m = running.image().metadata;
        actor.child == Child::Block
            && actor.admitted
            && !actor.retired
            && m.process == actor.meta.process
            && m.thread == actor.meta.thread
            && m.job == actor.meta.job
            && m.domain == actor.meta.domain
            && self.core.s.state(m.thread) == Ok(State::Running(0))
    }
    #[inline(never)] // Fixed scratch lifetime does not enlarge every syscall frame.
    pub(super) fn port_words256(&mut self, index: usize, call: Call, now: u64) -> Result<(), ()> {
        if !self.selected_block(index) {
            return Err(());
        }
        let began = crate::port_io::cycles();
        let (buffer, output) = match call {
            Call::PortInputWords256 { buffer, .. } => (buffer, false),
            Call::PortOutputWords256 { buffer, .. } => (buffer, true),
            _ => return Err(()),
        };
        let permit = self
            .core
            .backing
            .ports
            .words256_call(
                ev_kernel::io_ports::Caller {
                    authority: self.core.a,
                    scheduler: self.core.s,
                    rpc: self.core.rpc,
                    cpu: 0,
                },
                call,
                now,
            )
            .map_err(|_| ())?;
        let owner = &self.actors[index - 1]
            .as_ref()
            .unwrap()
            .running
            .as_ref()
            .unwrap()
            .image()
            .owner;
        // SAFETY: selected_block joined the actual captured Running image and
        // thread; executor restored controller CR3/IF0, APs remain parked.
        let span = unsafe { owner.block_io_buffer(buffer, self.hw.original) }.map_err(|_| ())?;
        let mut scratch = Scratch([0; 512]);
        let elapsed = match permit {
            ev_kernel::io_ports::Words256Permit::Input(permit) => {
                // SAFETY: both-page ownership/permission/direct-map preflight
                // completed before first IN; scratch is Kernel-owned aligned RAM.
                let elapsed = unsafe { crate::port_io::input_words256(permit, &mut scratch.0) };
                // A post-IN hardware/access failure is not a pre-effect refusal.
                // Retain all owners rather than reporting a reusable buffer.
                span.publish(&scratch.0)
                    .expect("PIO publish failed after IN; retain owners");
                elapsed
            }
            ev_kernel::io_ports::Words256Permit::Output(permit) => {
                span.snapshot(&mut scratch.0).map_err(|_| ())?;
                // SAFETY: full immutable Kernel snapshot and exact live port
                // permit retained; no user/IRQ/device-owner switch can intervene.
                unsafe { crate::port_io::output_words256(permit, &scratch.0) }
            }
        };
        let metric = &mut self.facts.pio;
        let counter = if output {
            &mut metric.outputs
        } else {
            &mut metric.inputs
        };
        *counter = counter.checked_add(1).expect("PIO count overflow");
        metric.cycles = metric
            .cycles
            .checked_add(elapsed)
            .expect("PIO cycle count overflow");
        metric.max_cycles = metric.max_cycles.max(elapsed);
        let handler = crate::port_io::cycles()
            .checked_sub(began)
            .expect("PIO handler TSC reversed");
        metric.handler_cycles = metric
            .handler_cycles
            .checked_add(handler)
            .expect("PIO handler cycle overflow");
        metric.max_handler_cycles = metric.max_handler_cycles.max(handler);
        Ok(())
    }
}
