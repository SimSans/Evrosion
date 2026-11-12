//! Fixture evidence from actual protected calls and authenticated senders. These
//! receipts are diagnostics; they never act as a capability or a health verdict.
use super::*;
#[derive(Clone, Copy)]
pub(super) struct Barrier {
    pub shell: ProcessId,
    pub frame: u64,
    pub tick: u64,
    pub flags: u8,
    pub call: CallId,
}
#[derive(Clone, Copy)]
pub(super) struct Selection {
    pub target: Metadata,
    pub request: u32,
    pub wire: usize,
    pub tick: u64,
}
#[derive(Clone, Copy, Default)]
pub(super) struct Snapshot {
    pub stage: u8,
    pub counter: u64,
    pub words: [u64; 4],
    pub tick: u64,
}
impl Snapshot {
    pub fn observe(&mut self, field: u8, value: u64, now: u64) {
        if field == 0 {
            if self.stage == 5 && value == self.counter {
                self.stage = 6;
                self.tick = now;
            } else {
                *self = Self {
                    stage: 1,
                    counter: value,
                    words: [0; 4],
                    tick: 0,
                };
            }
        } else if (1..=4).contains(&field) && self.stage == field {
            self.words[(field - 1) as usize] = value;
            self.stage += 1;
        } else {
            *self = Self::default();
        }
    }
}
impl Runtime<'_, '_> {
    pub(super) fn completed_opaque(&mut self, p: Pending, value: u64) {
        #[cfg(feature = "test-m5-native")]
        if p.file_replace
            && let Some(native) = &mut self.native
        {
            let address = self.backing.alias(Scalar::Application);
            let bytes = core::array::from_fn::<_, 256, _>(|offset| {
                // SAFETY: exact retained scalar frame; caller is blocked and
                // the captured File callee owns this completed reply window.
                unsafe { (address as *const u8).add(offset).read_volatile() }
            });
            if ev_userspace_contract::file::Response::decode(&bytes)
                == Ok(ev_userspace_contract::file::Response::Error {
                    code: ev_userspace_contract::file::ErrorCode::Denied,
                })
            {
                native.readonly_denial = Some((
                    self.actors[p.caller - 1].as_ref().unwrap().meta.process,
                    p.id,
                ));
            }
        }
        let request = p.value.to_le_bytes();
        let reply = value.to_le_bytes();
        if p.wire == Channel::InputBarrier.index()
            && p.caller == Child::Shell.index() + 1
            && p.callee == Child::Input.index() + 1
            && &request[..4] == b"KBR1"
            && reply[0..2] == [b'B', 1]
            && reply[2] & !15 == 0
            && reply[3] == 0
            && u32::from_le_bytes(reply[4..].try_into().unwrap()) != u32::MAX
            && let Some(step) = self.last_present[1]
        {
            let shell = self.metadata(p.caller).unwrap();
            if step.shell_process == shell.process.diagnostic_id()
                && u64::from(u32::from_le_bytes(request[4..].try_into().unwrap())) == step.frame
            {
                self.barrier = Some(Barrier {
                    shell: shell.process,
                    frame: step.frame,
                    tick: crate::timer::now(),
                    flags: reply[2],
                    call: p.id,
                });
            }
        }
        if p.caller == 0
            && p.callee == Child::File.index() + 1
            && let Some(index) = [Channel::NotesRead.index(), Channel::PrivateRead.index()]
                .iter()
                .position(|&w| w == p.wire)
            && &request[..4] == b"FMQ1"
            && request[5..] == [0, 0, 0]
        {
            self.snapshots[index].observe(request[4], value, crate::timer::now());
        }
    }
    pub(super) fn received_event(
        &mut self,
        receiver: usize,
        wire: usize,
        process: ProcessId,
        thread: ThreadId,
        value: u64,
    ) {
        if receiver != 0 || wire != 15 || value.to_le_bytes() != *b"EVOPEN01" {
            return;
        }
        let Some(actor) = self.actors[Child::App.index()].as_ref() else {
            return;
        };
        let actual = actor.meta;
        if actor.running.is_none()
            || actor.retired
            || !self
                .s
                .state(actual.thread)
                .is_ok_and(|state| state != State::Exited)
            || actual.process != process
            || actual.thread != thread
        {
            return;
        }
        #[cfg(feature = "test-m5-native")]
        if self.s.dispatch_inhibited(actual.process) != Ok(false) {
            return;
        }
        if self.open.is_none() {
            self.awaiting_open = Some(actual);
        }
    }
    pub(super) fn accepted_event(&mut self, index: usize, wire: usize, value: u64) {
        let body = value.to_le_bytes();
        #[cfg(feature = "test-m5-native")]
        if index == Child::Shell.index() + 1 && wire == 15 && body == *b"EVSHCRD1" {
            let actor = self.actors[Child::Shell.index()].as_ref().unwrap();
            assert!(actor.admitted && !actor.retired && actor.running.is_some());
            (self.observations)(Observation::NativeCriticalReady(NativeCriticalReady {
                process: actor.meta.process.diagnostic_id(),
                thread: actor.meta.thread.diagnostic_id(),
                image_sha256: actor.image_sha256,
                tick: crate::timer::now(),
            }));
        }
        #[cfg(feature = "test-m5-native")]
        if index == Child::Block.index() + 1
            && wire == 15
            && body == *b"EVBLRDY1"
            && self.native.as_ref().is_some_and(|n| !n.common_prefix)
        {
            self.check_mappings(0);
            self.check_mappings(index);
            self.check_scalar_guards();
            let actor = self.actors[Child::Block.index()].as_ref().unwrap();
            assert!(actor.admitted && !actor.retired && actor.running.is_some());
            let system = self.wires[Channel::SystemBlock.index()].as_ref().unwrap();
            assert!(
                !system.closed
                    && system.receiver == actor.meta.domain
                    && system.bound == Some(actor.meta.thread)
            );
            let native = self.native.as_mut().unwrap();
            native.common_prefix = true;
            (self.observations)(Observation::NativeCommonPrefix(NativeCommonPrefix {
                mode: native.boot_mode as u16,
                root_process: self.root.meta.process.diagnostic_id(),
                root_thread: self.root.meta.thread.diagnostic_id(),
                root_image_sha256: native.root_image_sha256,
                root_epoch: EPOCH.get(),
                root_incarnation: self.root.active.as_ref().unwrap().token().number(),
                root_manifest_sha256: native.root_manifest_sha256,
                block_process: actor.meta.process.diagnostic_id(),
                block_thread: actor.meta.thread.diagnostic_id(),
                block_image_sha256: actor.image_sha256,
                system_endpoint: system.object,
                root_frames: self.root.meta.frames,
                block_frames: actor.meta.frames,
            }));
        }
        #[cfg(feature = "test-m5-native")]
        if index == 0 && wire == 15 && body[..2] == *b"NR" {
            self.native_report(body);
        }
        #[cfg(feature = "test-m5-native")]
        if index == 0
            && wire == 15
            && body[0] == b'N'
            && matches!(body[1], b'C' | b'J' | b'S' | b'O')
        {
            self.native_diagnostic(body);
        }
        #[cfg(feature = "test-m5-native")]
        if wire == 15
            && let Some(native) = &mut self.native
        {
            if index == 0 && body == *b"EVNFIN01" {
                native.finish_requested = true;
            }
            if index == Child::App.index() + 1
                && body == *b"EVFLRO01"
                && native.readonly_denial.is_some_and(|(process, _)| {
                    self.actors[index - 1]
                        .as_ref()
                        .is_some_and(|actor| actor.meta.process == process)
                })
            {
                native.readonly_rejections += 1;
                native.readonly_denial = None;
            }
        }
        if index == 0 && wire == Channel::ShellControl.index() && body[0..4] == [b'R', 3, 0, 0] {
            let serial = u32::from_le_bytes(body[4..].try_into().unwrap());
            if let Some(target) = self.awaiting_open.take()
                && serial > self.request
                && serial != u32::MAX
                && self.metadata(Child::App.index() + 1) == Some(target)
                && self.actors[Child::App.index()]
                    .as_ref()
                    .is_some_and(|actor| actor.running.is_some() && !actor.retired)
                && self
                    .s
                    .state(target.thread)
                    .is_ok_and(|state| state != State::Exited)
            {
                self.request = serial;
                self.open = Some((target, serial));
                self.selection = None;
            }
        }
        if wire != 15 {
            return;
        }
        if index == Child::Shell.index() + 1 && body[0] == b'S' && body[3] == 0 {
            let word = u32::from_le_bytes(body[4..].try_into().unwrap());
            if body[1] == 6 && body[2] == 7 && self.facts.faults == 2 && self.facts.restarts == 2 {
                self.restored = self
                    .metadata(Child::App.index() + 1)
                    .map(|m| (m.process, crate::timer::now()));
            }
            if body[1] == 5
                && body[2] == 0
                && let (Some(step), Some(barrier)) = (self.last_present[1], self.barrier)
            {
                let current = self.metadata(index).unwrap();
                if step.frame == word as u64
                    && step.shell_process == current.process.diagnostic_id()
                    && barrier.shell == current.process
                    && barrier.frame == step.frame
                    && barrier.tick <= crate::timer::now()
                {
                    let _actual_call = barrier.call;
                    let mut ready = step;
                    ready.kind = StepKind::PickerReady;
                    ready.grants = self.facts.grants;
                    self.picker = Some((ready, crate::timer::now()));
                    (self.observations)(Observation::Step(ready));
                }
            }
            if body[1] == 2
                && matches!(body[2], 1 | 2)
                && let Some((target, request)) = self.open
                && request == word
                && self.picker.is_some()
            {
                self.selection = Some(Selection {
                    target,
                    request,
                    wire: if body[2] == 1 {
                        Channel::NotesRead.index()
                    } else {
                        Channel::PrivateRead.index()
                    },
                    tick: crate::timer::now(),
                });
            }
            if body[1] == 3 && body[2] == 0 && self.open.is_some_and(|(_, request)| request == word)
            {
                self.open = None;
                self.selection = None;
                self.picker = None;
            }
        }
        if index == 0
            && body == *b"EVHOLD01"
            && let Some((mut step, start)) = self.picker
        {
            let now = crate::timer::now();
            if now >= start.checked_add(64).unwrap()
                && step.grants == self.facts.grants
                && self
                    .barrier
                    .is_some_and(|b| b.frame == step.frame && b.flags & 12 != 0)
                && self.last_present[1].is_some_and(|last| {
                    last.frame == step.frame && last.shell_process == step.shell_process
                })
            {
                step.kind = StepKind::PickerHeld;
                step.held_ticks = now - start;
                (self.observations)(Observation::Step(step));
            }
        }
        if index == Child::App.index() + 1 && body == *b"EVFILRD1" {
            self.promote_grant();
            self.open = None;
            self.selection = None;
            self.picker = None;
        }
    }
}

#[cfg(feature = "test-m5-native")]
impl Runtime<'_, '_> {
    fn native_diagnostic(&mut self, body: [u8; 8]) {
        let root = self.current(0);
        let origin = (root.process.diagnostic_id(), root.thread.diagnostic_id());
        let Some(native) = &mut self.native else {
            return;
        };
        // Only accepted Events SENDs by the actual admitted Root reach here.
        // Queue acceptance/ordinary delivery are never changed by this observer.
        let beginning = body[3] == 0;
        match native.diagnostics.accept(body) {
            Ok(None) => {
                if beginning {
                    native.diagnostic_origin = Some(origin);
                }
            }
            Ok(Some(report)) => {
                let Some((root_process, root_thread)) = native.diagnostic_origin.take() else {
                    native.diagnostic_error = true;
                    return;
                };
                if origin != (root_process, root_thread) {
                    native.diagnostic_error = true;
                    return;
                }
                use ev_diagnostics::framing::Kind;
                match report.kind {
                    Kind::OwnerPrompt => {
                        let bytes: [u8; 416] = report.bytes[..416].try_into().unwrap();
                        if ev_diagnostics::owner::Prompt::decode(&bytes).is_err() {
                            native.diagnostic_error = true;
                            return;
                        }
                        (self.observations)(Observation::NativeOwnerPrompt(NativeDiagnostic {
                            report: report.serial,
                            root_process,
                            root_thread,
                            bytes,
                        }));
                    }
                    Kind::Crash => {
                        let bytes: [u8; 416] = report.bytes[..416].try_into().unwrap();
                        if ev_diagnostics::Crash::decode(&bytes).is_err() {
                            native.diagnostic_error = true;
                            return;
                        }
                        (self.observations)(Observation::NativeCrash(NativeDiagnostic {
                            report: report.serial,
                            root_process,
                            root_thread,
                            bytes,
                        }));
                    }
                    Kind::Job => {
                        let bytes: [u8; 192] = report.bytes[..192].try_into().unwrap();
                        if ev_diagnostics::live::Row::decode(&bytes).is_err() {
                            native.diagnostic_error = true;
                            return;
                        }
                        (self.observations)(Observation::NativeJob(NativeDiagnostic {
                            report: report.serial,
                            root_process,
                            root_thread,
                            bytes,
                        }));
                    }
                    Kind::System => {
                        let bytes: [u8; 384] = report.bytes[..384].try_into().unwrap();
                        if ev_diagnostics::system::Snapshot::decode(&bytes).is_err() {
                            native.diagnostic_error = true;
                            return;
                        }
                        (self.observations)(Observation::NativeSystem(NativeDiagnostic {
                            report: report.serial,
                            root_process,
                            root_thread,
                            bytes,
                        }));
                    }
                }
            }
            Err(_) => native.diagnostic_error = true,
        }
    }
    fn native_report(&mut self, body: [u8; 8]) {
        let actual = self.actors[Child::App.index()]
            .as_ref()
            .filter(|actor| {
                actor.admitted
                    && !actor.retired
                    && actor.running.is_some()
                    && self
                        .s
                        .state(actor.meta.thread)
                        .is_ok_and(|state| state != State::Exited)
            })
            .map(|actor| {
                (
                    actor.meta.process.diagnostic_id(),
                    actor.meta.thread.diagnostic_id(),
                    actor.image_sha256,
                )
            })
            .unwrap_or((0, 0, [0; 32]));
        let Some(native) = &mut self.native else {
            return;
        };
        let beginning = body[3] == 0;
        // The queue already accepted the ordinary opaque message. Diagnostic
        // rejection never changes that SEND result or consumes its delivery.
        match native.report.accept(body) {
            Ok(None) => {
                if beginning {
                    native.report_origin = Some((
                        u32::from_le_bytes(body[4..].try_into().unwrap()),
                        actual.0,
                        actual.1,
                        actual.2,
                    ));
                }
            }
            Ok(Some(snapshot)) => {
                let Some((report, process, thread, image)) = native.report_origin.take() else {
                    native.report_error = true;
                    return;
                };
                let identity_matches = (snapshot.process, snapshot.thread) == (process, thread);
                // Identity is captured at the actual accepted Begin, so a
                // subsequent unrelated child transition cannot forge the past
                // or panic the kernel over a stale userspace diagnostic.
                (self.observations)(Observation::NativeState(NativeSnapshot {
                    report,
                    snapshot,
                    actual_process: process,
                    actual_thread: thread,
                    actual_image_sha256: image,
                    identity_matches,
                }));
            }
            Err(_) => native.report_error = true,
        }
    }
}
