//! Test-only actual cumulative samples. No counter, quota or Job is changed.
use super::*;
impl Runtime<'_, '_> {
    pub(super) fn negative_cpu_sample(&mut self) -> Result<(), u64> {
        if self.network_negative.cpu_samples >= 48 {
            return Err(2);
        }
        let root = self.metadata(0).ok_or(1u64)?;
        let shell = self.metadata(1).ok_or(1u64)?;
        let app = self.metadata(5).ok_or(1u64)?;
        if [shell, app]
            .iter()
            .any(|m| self.s.state(m.thread) == Ok(State::Exited))
        {
            return Err(1);
        }
        self.network_negative.cpu_samples += 1;
        let sample = self.network_negative.cpu_samples;
        let build = option_env!("EVROSION_BUILD_ID").unwrap_or("unrecorded");
        let tick = crate::timer::now();
        let mut output = crate::serial::Serial::initialize(4096);
        for (role, actor, m, job) in [
            ("boot", 0, root, self.boot),
            ("root", 0, root, root.job),
            ("shell", 1, shell, shell.job),
            ("app", 5, app, app.job),
        ] {
            let cpu = self.s.usage(job, Resource::CpuTicks).unwrap();
            let budget = self.s.cpu_budget(job).unwrap().ok_or(1u64)?;
            let image = if actor == 0 {
                self.native.as_ref().unwrap().root_image_sha256
            } else {
                self.actors[actor - 1].as_ref().unwrap().image_sha256
            };
            let _ = writeln!(
                output,
                "EVROSION_M6_NEGATIVE_CPU protocol=1 build={build} sample={sample} role={role} actor={actor} process={} thread={} job={} tick={tick} cpu={cpu} quota={} period={} window_start={} window_end={} used={} reserved={} remaining={} image_sha256={} cpu_scope=subtree",
                m.process.diagnostic_id(),
                m.thread.diagnostic_id(),
                job.diagnostic_id(),
                budget.quota_ticks,
                budget.period_ticks,
                budget.window_start,
                budget.window_end,
                budget.consumed_ticks,
                budget.reserved_ticks,
                budget.remaining_ticks,
                Hex(image)
            );
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)] // Exact actual protected-delivery observation.
    pub(in super::super) fn negative_work_delivery(
        &mut self,
        receiver: usize,
        wire: usize,
        process: ProcessId,
        thread: ThreadId,
        value: u64,
        ticket: Ticket,
        tick: u64,
    ) {
        let root = self.root.meta;
        if (process, thread) != (root.process, root.thread) {
            return;
        }
        let (role, bit) = if receiver == 5
            && wire == Channel::AppControl.index()
            && value == u64::from_le_bytes(*b"EVNABUS1")
        {
            ("app", 1)
        } else if receiver == 1
            && wire == Channel::ShellControl.index()
            && value == u64::from_le_bytes(*b"EVNWORK1")
        {
            ("shell", 2)
        } else {
            return;
        };
        if self.network_negative.work_delivered & bit != 0 {
            return;
        }
        self.network_negative.work_delivered |= bit;
        let m = self.metadata(receiver).unwrap();
        let image = self.actors[receiver - 1].as_ref().unwrap().image_sha256;
        let build = option_env!("EVROSION_BUILD_ID").unwrap_or("unrecorded");
        let mut output = crate::serial::Serial::initialize(2048);
        let _ = writeln!(
            output,
            "EVROSION_M6_NEGATIVE_WORK protocol=1 build={build} role={role} phase=delivered actor={receiver} process={} thread={} root_process={} root_thread={} endpoint={} ticket={} tick={tick} request={value} image_sha256={}",
            m.process.diagnostic_id(),
            m.thread.diagnostic_id(),
            root.process.diagnostic_id(),
            root.thread.diagnostic_id(),
            self.wires[wire].as_ref().unwrap().object,
            ticket.0,
            Hex(image)
        );
    }
}
