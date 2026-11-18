//! Captured user execution under the sole restored-CR3 controller.
use super::*;
impl Runtime<'_, '_> {
    /// # Safety
    /// Sole BSP controller. Each resume restores original CR3/IF0 before any
    /// owner mutation; APs stay parked and no admitted deadline can expire.
    pub(super) unsafe fn run(&mut self, frames: &mut BootstrapFrames) {
        // SAFETY: initialized retained PIC/PIT, exclusively owned IRQ0 handler.
        unsafe { crate::timer::start_runtime() };
        #[cfg(feature = "test-m5-native")]
        let mut retained_dispatch: Option<ev_kernel::scheduler::Dispatch> = None;
        #[cfg(feature = "test-m5-native")]
        if let Some(native) = &mut self.native {
            native.profile.started = crate::timer::now();
        }
        let mut transitions = 0u64;
        loop {
            if !cfg!(feature = "test-m6-session") && transitions >= TRANSITIONS {
                #[cfg(feature = "test-m5-native")]
                self.diagnose_bound(TRANSITIONS, crate::timer::now());
                panic!("desktop finite transition budget exhausted");
            }
            transitions = transitions
                .checked_add(1)
                .expect("runtime transition counter overflow");
            let now = crate::timer::now();
            #[cfg(feature = "test-m6-session")]
            {
                // Queued-frame retention policy, not a delivery guarantee.
                // Expiry never ACKs or releases a delivered buffer lease.
                self.stop = Deadline::after(now, 9728).expect("bounded session message deadline");
            }
            #[cfg(feature = "test-m5-native")]
            if self.stop.reached(now) {
                #[cfg(feature = "test-m6-session")]
                self.emit_session_ui_counts("bound");
                self.diagnose_bound(transitions, now);
            }
            assert!(
                !self.stop.reached(now),
                "desktop bound transitions={transitions} calls={} replies={} starts={} stops={} reaps={} faults={}",
                self.facts.calls,
                self.facts.replies,
                self.facts.starts,
                self.facts.stops,
                self.facts.reaps,
                self.facts.faults
            );
            #[cfg(feature = "test-m6-session")]
            if let Err(error) = self.expire_calls(now) {
                self.emit_session_ui_counts("bound");
                // Prototype fail-closed terminal path: every actual user CPU
                // has returned to this sole controller; retain all live owners
                // and mappings until the VM terminates. This is not a normal
                // retirement/recovery PASS or the final service-containment path.
                use core::fmt::Write as _;
                let mut emergency = crate::serial::Serial::initialize(8192);
                let _ = writeln!(
                    emergency,
                    "EVROSION_M6_SESSION_ABORT reason=quiescence detail={error}"
                );
                crate::finish(false);
            }
            #[cfg(not(feature = "test-m6-session"))]
            assert!(self.rpc.expire(now).unwrap().is_empty());
            self.s.advance(now).unwrap();
            #[cfg(feature = "test-m5-native")]
            let selected = retained_dispatch
                .take()
                .or_else(|| self.s.dispatch(0).unwrap());
            #[cfg(feature = "test-m5-native")]
            let Some(dispatch) = selected else {
                #[cfg(feature = "test-m6-session")]
                {
                    // Same finite stalled-clock guard as ordinary user waits;
                    // a quota pause is not loss of the timer or a reset of usage.
                    crate::user_runtime::idle_tick();
                    continue;
                }
                #[cfg(not(feature = "test-m6-session"))]
                panic!("desktop runnable actual actor");
            };
            #[cfg(not(feature = "test-m5-native"))]
            let dispatch = self
                .s
                .dispatch(0)
                .unwrap()
                .expect("desktop runnable actual actor");
            let index = self
                .index_thread(dispatch.thread)
                .expect("retained dispatched owner");
            assert_eq!(self.metadata(index).unwrap().process, dispatch.process);
            #[cfg(feature = "test-m5-native")]
            {
                assert_eq!(self.s.thread_process(dispatch.thread), Ok(dispatch.process));
                assert_eq!(self.s.process_job(dispatch.process), Ok(dispatch.job));
                assert_eq!(self.metadata(index).unwrap().job, dispatch.job);
                assert_eq!(self.s.state(dispatch.thread), Ok(State::Running(0)));
            }
            self.check_mappings(index);
            let (mut frame, address) = if index == 0 {
                let owner = self.root.active.as_ref().unwrap();
                owner.image().loaded().root.activate();
                // SAFETY: checked real Root admission and retained physical/FX owner.
                unsafe {
                    crate::user_runtime::resume_context(
                        &self.root.context,
                        &mut self.root.fx,
                        self.hw.original,
                    )
                }
            } else {
                let actor = self.actors[index - 1].as_mut().unwrap();
                actor
                    .running
                    .as_ref()
                    .expect("admitted dispatch")
                    .image()
                    .image()
                    .root()
                    .activate();
                // SAFETY: exact generational scheduler identity and owned root/FX.
                unsafe {
                    crate::user_runtime::resume_context(
                        &actor.context,
                        &mut actor.fx,
                        self.hw.original,
                    )
                }
            };
            #[cfg(feature = "test-m5-native")]
            let explicit_yield = frame.vector == 128 && matches!(decode(&frame), Ok(Call::Yield));
            #[cfg(feature = "test-m5-native")]
            if let Some(native) = &mut self.native {
                native.profile.captured(
                    index,
                    dispatch.process,
                    dispatch.thread,
                    frame.vector,
                    frame.registers[14],
                );
            }
            let blocked = match frame.vector {
                32 => {
                    #[cfg(feature = "test-m6-session")]
                    self.s
                        .advance(crate::timer::now())
                        .expect("captured monotonic CPU window");
                    #[cfg(feature = "test-m5-native")]
                    let charged_before = self.s.usage(dispatch.job, Resource::CpuTicks).unwrap();
                    self.s.charge_cpu(0, 1).unwrap();
                    #[cfg(feature = "test-m5-native")]
                    if let Some(native) = &mut self.native {
                        let charged = self.s.usage(dispatch.job, Resource::CpuTicks).unwrap()
                            - charged_before;
                        assert_eq!(charged, 1);
                        native.profile.charged(index, charged);
                    }
                    false
                }
                128 => self.syscall(index, &mut frame, frames),
                _ => {
                    self.fault(index, &frame, address);
                    true
                }
            };
            *self.context_mut(index) = frame;
            if !blocked {
                #[cfg(feature = "test-m5-native")]
                if frame.vector == 128
                    && !explicit_yield
                    && frame.registers[14] == 0
                    && let Some(native) = &mut self.native
                {
                    // The live scheduler owner retains this preemptible quantum.
                    // IRQ32, explicit Yield and actual blocking all release it.
                    assert_eq!(self.s.state(dispatch.thread), Ok(State::Running(0)));
                    native.profile.continued(index);
                    retained_dispatch = Some(dispatch);
                } else {
                    self.s.yield_cpu(0).unwrap();
                }
                #[cfg(not(feature = "test-m5-native"))]
                self.s.yield_cpu(0).unwrap();
            }
            #[cfg(feature = "test-m5-native")]
            if self
                .native
                .as_ref()
                .is_some_and(|native| native.root_exited)
            {
                assert_eq!(self.rpc.outstanding(), 0);
                assert!(self.pending.iter().all(Option::is_none));
                #[cfg(feature = "test-m6-network-negative")]
                self.negative_finish();
                self.emit_profile("finished");
                #[cfg(feature = "test-m6-session")]
                self.emit_session_ui_counts("finished");
                return;
            }
            #[cfg(not(feature = "test-m5-native"))]
            if self.settled.is_some_and(|end| crate::timer::now() >= end)
                && self.pending.iter().all(Option::is_none)
            {
                assert_eq!(
                    (self.facts.faults, self.facts.restarts, self.facts.grants),
                    (2, 2, 3)
                );
                return;
            }
        }
    }
    fn fault(&mut self, index: usize, frame: &UserContext, address: u64) {
        #[cfg(feature = "test-m6-network")]
        let network = matches!(index, 7 | 8);
        #[cfg(not(feature = "test-m6-network"))]
        let network = false;
        assert!(
            index == Child::App.index() + 1 || index == Child::Shell.index() + 1 || network,
            "unexpected desktop actor fault index={index} vector={} error={} ip={:#x} address={address:#x}",
            frame.vector,
            frame.error,
            frame.rip
        );
        assert!(frame.ordinary_user_fault());
        let m = self.current(index);
        #[cfg(not(feature = "test-m6-session"))]
        {
            let base = self.actors[index - 1]
                .as_ref()
                .unwrap()
                .image()
                .unwrap()
                .root()
                .base();
            assert_eq!(
                (frame.vector, frame.error, address),
                (14, 4, base + 4 * 1024 * 1024)
            );
        }
        if !network {
            assert!(
                !self
                    .pending
                    .iter()
                    .flatten()
                    .any(|p| p.caller == index || p.callee == index),
                "crash cannot return outstanding shared credit"
            );
        }
        let record = Record {
            process: m.process.diagnostic_id(),
            thread: m.thread.diagnostic_id(),
            vector: frame.vector,
            error: frame.error,
            address,
            instruction: frame.rip,
        };
        assert_eq!(Record::decode(&record.encode()), Some(record));
        #[cfg(feature = "test-m5-native")]
        (self.observations)(Observation::NativeFault(NativeFault {
            actor: index as u8,
            image_sha256: self.actors[index - 1].as_ref().unwrap().image_sha256,
            root_epoch: EPOCH.get(),
            root_incarnation: self.root.active.as_ref().unwrap().token().number(),
            words: core::array::from_fn(|field| {
                record
                    .context_field(m.job, frame, field as u64)
                    .expect("actual captured fault field")
            }),
        }));
        self.actors[index - 1].as_mut().unwrap().fault = Some(record);
        assert_eq!(self.s.exit(0), Ok(m.thread));
        #[cfg(feature = "test-m6-network")]
        if network {
            // Only this actual CPU actor exited. Canonical session peer-death
            // and leaf-drain handles accepted work next turn. Retain all image,
            // MemoryObject and port owners; this is NOT device quiescence.
            self.network_fault.record(index);
            // The CPU has exited and every hardware owner remains retained.
            // Root's ordinary OBSERVE reports process termination, not merely
            // Thread::Exited; mark this exact process without reaping it.
            self.s.terminate_process(m.process).unwrap();
            self.facts.faults += 1;
            return;
        }
        self.stop_actor(index).unwrap();
        self.old[index - 1] = Some(m);
        self.facts.faults += 1;
        let display = self.metadata(Child::Display.index() + 1).unwrap();
        assert_ne!(self.s.state(display.thread), Ok(State::Exited));
        (self.observations)(Observation::Lifecycle(Lifecycle {
            actor: if index == Child::App.index() + 1 {
                Producer::App
            } else {
                Producer::Shell
            },
            fault: Some(record),
            process: record.process,
            thread: record.thread,
            replacement: 0,
            display_process: display.process.diagnostic_id(),
            grants: self.facts.grants,
        }));
    }
}
