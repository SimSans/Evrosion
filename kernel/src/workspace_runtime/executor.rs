use super::*;
impl World {
    /// # Safety
    /// Sole resident BSP controller; each user trap restores original CR3/IF0
    /// before metadata or owners change. Every actual source/map/FX stays pinned.
    pub(super) unsafe fn execute(&mut self, frames: &mut BootstrapFrames, log: &mut dyn Write) {
        // SAFETY: sole IF0 controller, initialized owned PIC/IRQ0, APs parked.
        unsafe { crate::timer::start_runtime() };
        let mut retained = None;
        let mut transitions = 0u64;
        let mut sample = crate::timer::now();
        loop {
            transitions = transitions.checked_add(1).expect("V5 transition counter");
            let now = crate::timer::now();
            if self.stop.reached(now) {
                self.resources(log, "wall_bound", transitions);
                panic!("V5 finite runtime cut reached with owners retained");
            }
            self.maintain_calls().unwrap_or_else(|reason| {
                self.resources(log, "quiescence_bound", transitions);
                panic!("{reason}; all owners retained")
            });
            for wire in self.wires.iter_mut().flatten() {
                if wire.needs_async_expiry() {
                    wire.expire_async(self.core.a, now)
                        .expect("V5 actual async expiry");
                }
            }
            self.core.s.advance(now).expect("V5 monotonic scheduler");
            self.collect();
            let Some(dispatch) = retained
                .take()
                .or_else(|| self.core.s.dispatch(0).expect("V5 real scheduler dispatch"))
            else {
                crate::user_runtime::idle_tick();
                continue;
            };
            let index = self
                .index_thread(dispatch.thread)
                .expect("V5 retained actual thread");
            let meta = self.current(index);
            assert_eq!((dispatch.process, dispatch.job), (meta.process, meta.job));
            let checked = if index == 0 {
                self.root
                    .active
                    .as_ref()
                    .unwrap()
                    .image()
                    .owner
                    .check(self.core.a, &self.core.backing.extents)
            } else {
                self.actors[index - 1]
                    .as_ref()
                    .unwrap()
                    .running
                    .as_ref()
                    .unwrap()
                    .image()
                    .owner
                    .check(self.core.a, &self.core.backing.extents)
            };
            if checked.is_err() {
                let snapshot = *self.context_mut(index);
                self.contain(index, &snapshot, None, log);
                continue;
            }
            let (mut frame, address) = if index == 0 {
                self.root.active.as_ref().unwrap().image().owner.activate();
                // SAFETY: exact admitted Root/FX owner; capture restores the
                // distinct original CR3 before metadata can change.
                unsafe {
                    crate::user_runtime::resume_context(
                        &self.root.context,
                        &mut self.root.fx,
                        self.hw.original,
                    )
                }
            } else {
                let actor = self.actors[index - 1].as_mut().unwrap();
                actor.running.as_ref().unwrap().image().owner.activate();
                // SAFETY: exact scheduler owner, retained private/FX backing
                // and restored-controller return boundary.
                unsafe {
                    crate::user_runtime::resume_context(
                        &actor.context,
                        &mut actor.fx,
                        self.hw.original,
                    )
                }
            };
            let yielded = frame.vector == 128 && matches!(decode(&frame), Ok(Call::Yield));
            *self.context_mut(index) = frame;
            let blocked = match frame.vector {
                32 => {
                    self.core.s.advance(crate::timer::now()).unwrap();
                    if let Err(error) = self.core.s.charge_cpu(0, 1) {
                        self.resources(log, "cpu_bound", transitions);
                        panic!("V5 cumulative CPU refusal:{error:?}; no counter reset");
                    }
                    self.facts.irq_cpu += 1;
                    self.facts.irq_by_actor[index] += 1;
                    false
                }
                128 => self.syscall(index, &mut frame, frames, log),
                _ => {
                    let fault = ev_kernel::fault::Record {
                        process: meta.process.diagnostic_id(),
                        thread: meta.thread.diagnostic_id(),
                        vector: frame.vector,
                        error: frame.error,
                        address,
                        instruction: frame.rip,
                    };
                    self.contain(index, &frame, Some(fault), log);
                    true
                }
            };
            *self.context_mut(index) = frame;
            if !blocked {
                if frame.vector == 128 && !yielded && frame.registers[14] == 0 {
                    assert_eq!(self.core.s.state(meta.thread), Ok(State::Running(0)));
                    retained = Some(dispatch);
                } else {
                    self.core.s.yield_cpu(0).unwrap();
                }
            }
            if now.saturating_sub(sample) >= 1000 {
                self.resources(log, "sample", transitions);
                sample = now;
            }
            if self.root_exited || self.checked_power() {
                break;
            }
        }
        // SAFETY: every user context returned to the sole IF0 controller.
        unsafe { crate::timer::stop_runtime() };
        self.resources(
            log,
            if self.checked_power() {
                "checked_power_retained"
            } else {
                "root_exited_retained"
            },
            transitions,
        );
    }
    pub(super) fn contain(
        &mut self,
        index: usize,
        frame: &UserContext,
        fault: Option<ev_kernel::fault::Record>,
        log: &mut dyn Write,
    ) {
        let meta = self.current(index);
        assert_eq!(self.core.s.exit(0), Ok(meta.thread));
        if index == 0 {
            self.root_exited = true;
        } else {
            let actor = self.actors[index - 1].as_mut().unwrap();
            actor.fault = fault;
            actor.context = *frame;
            if let Some(running) = actor.running.as_mut() {
                running
                    .stop(self.core.a, self.core.s)
                    .expect("V5 captured faulty process grant revocation");
            }
        }
        self.core
            .s
            .terminate_process(meta.process)
            .expect("V5 captured process termination");
        let notifications = self
            .core
            .rpc
            .peer_died(self.core.s, meta.thread, crate::timer::now())
            .expect("V5 actual peer-death reservation");
        self.terminal_notifications(notifications, crate::timer::now())
            .expect("V5 retained peer outcomes");
        if let Some(f) = fault {
            let _ = writeln!(
                log,
                "EVROSION_M8_KERNEL_FAULT actor={index} process={} thread={} vector={} error={} address={} rip={}",
                f.process, f.thread, f.vector, f.error, f.address, f.instruction
            );
        }
        self.event(log, "contained", index);
    }
    fn resources(&mut self, log: &mut dyn Write, phase: &str, transitions: u64) {
        // Reuse the sustained-session complete-record retention mechanism.
        // Exhausting ordinary history never consumes the terminal ownership
        // reserve and never interrupts legitimate OS work.
        let mut measure = crate::session_log::Measure::default();
        self.resource_rows(&mut measure, phase, transitions);
        let bytes = measure
            .finish()
            .expect("complete bounded V5 resource record");
        let terminal = phase != "sample";
        match self
            .log_retention
            .record(bytes, terminal)
            .expect("bounded V5 diagnostic retention")
        {
            crate::session_log::Decision::Emit => self.resource_rows(log, phase, transitions),
            crate::session_log::Decision::FirstOmission => {
                let _ = writeln!(
                    log,
                    "EVROSION_M8_LOG_RETENTION phase=prefix_closed observed={} retained={} omitted={} detail_bytes={} scope=periodic_resource_records_only final_reserve=true",
                    self.log_retention.observed,
                    self.log_retention.retained,
                    self.log_retention.omitted,
                    self.log_retention.detail_bytes
                );
            }
            crate::session_log::Decision::Omit => {}
        }
        if terminal {
            let r = self.log_retention;
            let _ = writeln!(
                log,
                "EVROSION_M8_LOG_RETENTION phase=summary observed={} retained={} omitted={} detail_bytes={} final_bytes={} omitted_bytes={} complete_records=true",
                r.observed, r.retained, r.omitted, r.detail_bytes, r.final_bytes, r.omitted_bytes
            );
        }
    }
    fn resource_rows(&self, log: &mut dyn Write, phase: &str, transitions: u64) {
        let pio = &self.facts.pio;
        let _ = writeln!(
            log,
            "EVROSION_M8_KERNEL_PIO phase={phase} tick={} inputs={} outputs={} denials={} words_per_call=256 bytes_per_call=512 if0_loop_tsc_total={} if0_loop_tsc_max={} if0_handler_tsc_total={} if0_handler_tsc_max={} tsc_is_not_nanoseconds=true irq_charge_scope_unchanged=true",
            crate::timer::now(),
            pio.inputs,
            pio.outputs,
            pio.denials,
            pio.cycles,
            pio.max_cycles,
            pio.handler_cycles,
            pio.max_handler_cycles
        );
        let (spaces, handles, nodes, objects) = self.core.a.metadata_usage();
        let (jobs, processes, threads) = self.core.s.metadata_usage();
        let _ = writeln!(
            log,
            "EVROSION_M8_KERNEL_RESOURCES phase={phase} tick={} elapsed={} transitions={transitions} jobs={jobs} processes={processes} threads={threads} spaces={spaces} handles={handles} nodes={nodes} objects={objects} root_subtree_frames={} root_subtree_cpu={} boot_frames={} boot_cpu={} captured_irq_cpu={} starts={} calls={} replies={} outstanding={} accepted_windows={} claimed_30min=false",
            crate::timer::now(),
            crate::timer::now().saturating_sub(self.started),
            self.core
                .s
                .usage(self.core.root_job, Resource::Frames)
                .unwrap(),
            self.core
                .s
                .usage(self.core.root_job, Resource::CpuTicks)
                .unwrap(),
            self.core.s.usage(self.core.boot, Resource::Frames).unwrap(),
            self.core
                .s
                .usage(self.core.boot, Resource::CpuTicks)
                .unwrap(),
            self.facts.irq_cpu,
            self.facts.starts,
            self.facts.calls,
            self.facts.replies,
            self.core.rpc.outstanding(),
            self.pending.iter().flatten().count()
        );
        let _ = writeln!(
            log,
            "EVROSION_M8_KERNEL_CPU phase={phase} tick={} by_actor={:?} scope=captured_user_irq_only wall_time_not_inferred=true",
            crate::timer::now(),
            self.facts.irq_by_actor
        );
        for p in self.pending.iter().flatten() {
            let parent = p.credit.parent();
            let _ = writeln!(
                log,
                "EVROSION_M8_KERNEL_PENDING phase={phase} epoch={} serial={} parent_epoch={} parent_serial={} caller_actor={} caller_thread={} callee_actor={} callee_thread={} wire={} endpoint={} request={:#x} deadline={} ticket={} delivered={} terminal={:?} quiescence_cut={} tick={}",
                p.id.epoch(),
                p.id.serial(),
                parent.map_or(0, |id| id.epoch().get()),
                parent.map_or(0, CallId::serial),
                p.caller,
                p.credit.caller().diagnostic_id(),
                p.callee,
                p.credit.callee().diagnostic_id(),
                p.wire,
                p.credit.endpoint(),
                p.value,
                p.deadline,
                p.ticket.0,
                p.delivered,
                p.terminal,
                p.by,
                crate::timer::now()
            );
        }
        let b = &self.facts.block;
        let _ = writeln!(
            log,
            "EVROSION_M8_KERNEL_BLOCK phase={phase} attempts={} accepted={} replies={} last_at={} last_done={} caller_actor={} parent_epoch={} parent_serial={} epoch={} serial={} request={:#x} deadline={} outcome={} status={} response={:#x} error={:?} tick={}",
            b.attempts,
            b.accepted,
            b.replies,
            b.at,
            b.done,
            b.caller,
            b.parent.map_or(0, |id| id.epoch().get()),
            b.parent.map_or(0, CallId::serial),
            b.id.map_or(0, |id| id.epoch().get()),
            b.id.map_or(0, CallId::serial),
            b.request,
            b.deadline,
            b.outcome,
            b.status,
            b.response,
            b.error,
            crate::timer::now()
        );
    }
}
