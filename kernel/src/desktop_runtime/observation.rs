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
        #[cfg(feature = "test-m6-session")]
        self.completed_session_ui(p, value);
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
            #[cfg(feature = "test-m6-session")]
            if &reply[..4] == b"FME1"
                && (1..=10).contains(&u32::from_le_bytes(reply[4..].try_into().unwrap()))
            {
                // Exact defined Internal errors are not content words. Fail
                // closed on the reserved-word collision too; never assemble
                // a fake counter/digest snapshot from repeated refusals.
                self.snapshots[index] = Snapshot::default();
                return;
            }
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
        _delivery: (Ticket, u64),
    ) {
        #[cfg(feature = "test-m6-network")]
        if receiver == 0 {
            self.startup_event(2, wire, (process, thread), value, _delivery);
        }
        #[cfg(feature = "test-m6-session")]
        self.received_session_note(receiver, wire, process, thread, value, _delivery);
        let body = value.to_le_bytes();
        #[cfg(feature = "test-m7-document")]
        let document = ev_userspace_contract::document_control::Request::decode(&body, 0)
            .ok()
            .filter(|r| {
                r.operation() != ev_userspace_contract::document_control::Operation::Publish
            });
        #[cfg(not(feature = "test-m7-document"))]
        let document: Option<()> = None;
        #[cfg(feature = "test-m7-document-observe")]
        if receiver == 0
            && wire == 15
            && self.document_samples < 128
            && let Ok(request) = ev_userspace_contract::document_control::Request::decode(&body, 0)
            && request.operation() == ev_userspace_contract::document_control::Operation::Publish
            && let Some(actual) = self.session_current_app()
            && (process, thread) == (actual.process, actual.thread)
        {
            #[cfg(feature = "test-m6-network")]
            let address = self.backing.alias(Scalar::Note);
            #[cfg(not(feature = "test-m6-network"))]
            let address = self.backing.alias(Scalar::Application);
            let bytes = core::array::from_fn(|offset| {
                // SAFETY: retained V3 semantic/AppFile page. This actual
                // requester holds its loan until the matching Root reply.
                unsafe { (address as *const u8).add(offset).read_volatile() }
            });
            self.document_samples += 1;
            (self.observations)(Observation::Document(DocumentObservation {
                process: actual.process.diagnostic_id(),
                thread: actual.thread.diagnostic_id(),
                endpoint: self.wires[wire].as_ref().unwrap().object,
                ticket: _delivery.0.0,
                nonce: request.nonce(),
                tick: crate::timer::now(),
                frame: self.last_present[0].map_or(0, |p| p.frame),
                bytes,
            }));
        }
        if receiver != 0 || wire != 15 || (body != *b"EVOPEN01" && document.is_none()) {
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
            #[cfg(feature = "test-m7-document")]
            {
                self.document_request = document.map(|r| (actual, r));
            }
        }
    }
    pub(super) fn accepted_event(
        &mut self,
        index: usize,
        wire: usize,
        value: u64,
        _ticket: Ticket,
        _tick: u64,
    ) {
        #[cfg(feature = "test-m6-network")]
        if index == Child::App.index() + 1 {
            let actual = self.current(index);
            self.startup_event(
                1,
                wire,
                (actual.process, actual.thread),
                value,
                (_ticket, _tick),
            );
        }
        #[cfg(feature = "test-m6-session")]
        self.accepted_session_note(index, wire, value, _ticket, _tick);
        let body = value.to_le_bytes();
        // Metadata cannot nominate another actor. Only the actual accepted
        // current Root Events route can request a later checked host restart.
        #[cfg(feature = "test-m6-network")]
        if index == 0
            && wire == 15
            && let Ok(request) =
                ev_userspace_contract::root_v4::owner_session::Restart::decode(body)
        {
            let root = self.root.meta;
            (self.observations)(Observation::SessionRestart(SessionRestart {
                root_process: root.process.diagnostic_id(),
                root_thread: root.thread.diagnostic_id(),
                endpoint: self.wires[wire].as_ref().unwrap().object,
                ticket: _ticket.0,
                tick: _tick,
                mode: request.mode(),
                generation: request.generation(),
            }));
        }
        // Opaque bounded diagnostic fields only: actual trap/endpoint binding
        // supplies identity. No Driver bytes may nominate Root or its layer.
        #[cfg(feature = "test-m6-network")]
        if wire == 15 && body[..2] == *b"NE" && body[4] != 0 && body[7] <= 1 {
            let expected_layer = match index {
                0 => 3,
                7 => 1,
                8 => 2,
                _ => 0,
            };
            if expected_layer != 0 && body[2] == expected_layer {
                let actual = self.metadata(index).unwrap();
                (self.observations)(Observation::SessionNetworkError(SessionNetworkError {
                    actor: index as u8,
                    process: actual.process.diagnostic_id(),
                    thread: actual.thread.diagnostic_id(),
                    endpoint: self.wires[wire].as_ref().unwrap().object,
                    ticket: _ticket.0,
                    tick: _tick,
                    layer: body[2],
                    operation: body[3],
                    class: body[4],
                    detail: body[5],
                    subdetail: body[6],
                    progress: body[7],
                }));
            }
        }
        // Diagnostic policy facts from an actually accepted Root frame only.
        // Child bytes cannot nominate Root identity. These do not grant health,
        // device quiescence, entropy quality or permission to retire an owner.
        #[cfg(feature = "test-m6-network")]
        if index == 0
            && wire == 15
            && body[..2] == *b"NW"
            && (1..=8).contains(&body[2])
            && body[3] <= 4
        {
            let root = self.root.meta;
            (self.observations)(Observation::SessionNetworkProgress(
                SessionNetworkProgress {
                    root_process: root.process.diagnostic_id(),
                    root_thread: root.thread.diagnostic_id(),
                    endpoint: self.wires[wire].as_ref().unwrap().object,
                    ticket: _ticket.0,
                    tick: _tick,
                    stage: body[2],
                    result: body[3],
                    argument: u32::from_le_bytes(body[4..].try_into().unwrap()),
                },
            ));
        }
        #[cfg(feature = "test-m6-network")]
        if index == 0
            && wire == 15
            && body[..2] == *b"TM"
            && (1..=3).contains(&body[2])
            && body[3] <= 3
        {
            let root = self.root.meta;
            (self.observations)(Observation::SessionTimeProgress(SessionNetworkProgress {
                root_process: root.process.diagnostic_id(),
                root_thread: root.thread.diagnostic_id(),
                endpoint: self.wires[wire].as_ref().unwrap().object,
                ticket: _ticket.0,
                tick: _tick,
                stage: body[2],
                result: body[3],
                argument: u32::from_le_bytes(body[4..].try_into().unwrap()),
            }));
        }
        #[cfg(feature = "test-m6-network")]
        if index == 0
            && wire == 15
            && body[..2] == *b"TP"
            && (1..=4).contains(&body[2])
            && body[3] <= 5
        {
            let root = self.root.meta;
            (self.observations)(Observation::SessionTimeProof(SessionNetworkProgress {
                root_process: root.process.diagnostic_id(),
                root_thread: root.thread.diagnostic_id(),
                endpoint: self.wires[wire].as_ref().unwrap().object,
                ticket: _ticket.0,
                tick: _tick,
                stage: body[2],
                result: body[3],
                argument: u32::from_le_bytes(body[4..].try_into().unwrap()),
            }));
        }
        #[cfg(feature = "test-m6-network")]
        if index == 0
            && wire == 15
            && body[..3] == *b"TE\x01"
            && (1..=10).contains(&body[3])
            && (body[4] <= 10 || body[4] == 255)
            && body[5] <= 128
            && (1..=6).contains(&body[6])
            && ((body[6] == 6 && (1..=8).contains(&body[7])) || (body[6] != 6 && body[7] == 0))
        {
            let root = self.root.meta;
            (self.observations)(Observation::SessionTimeExchange(SessionTimeExchange {
                root_process: root.process.diagnostic_id(),
                root_thread: root.thread.diagnostic_id(),
                endpoint: self.wires[wire].as_ref().unwrap().object,
                ticket: _ticket.0,
                tick: _tick,
                phase: body[3],
                tcp: body[4],
                calls: body[5],
                error: body[6],
                detail: body[7],
            }));
        }
        #[cfg(feature = "test-m6-network")]
        if index == 0 && wire == 15 && body[..2] == *b"TC" && body[2] == 1 && body[3] <= 3 {
            let root = self.root.meta;
            (self.observations)(Observation::SessionTimeCheck(SessionNetworkProgress {
                root_process: root.process.diagnostic_id(),
                root_thread: root.thread.diagnostic_id(),
                endpoint: self.wires[wire].as_ref().unwrap().object,
                ticket: _ticket.0,
                tick: _tick,
                stage: body[2],
                result: body[3],
                argument: u32::from_le_bytes(body[4..].try_into().unwrap()),
            }));
        }
        #[cfg(feature = "test-m6-network")]
        if index == 0
            && wire == 15
            && body[..2] == *b"UP"
            && (((1..=4).contains(&body[2]) && body[3] == 0)
                || (body[2] == 5 && (1..=6).contains(&body[3])))
        {
            let root = self.root.meta;
            (self.observations)(Observation::SessionUpdateProgress(SessionNetworkProgress {
                root_process: root.process.diagnostic_id(),
                root_thread: root.thread.diagnostic_id(),
                endpoint: self.wires[wire].as_ref().unwrap().object,
                ticket: _ticket.0,
                tick: _tick,
                stage: body[2],
                result: body[3],
                argument: u32::from_le_bytes(body[4..].try_into().unwrap()),
            }));
        }
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
        if index == 0
            && wire == Channel::ShellControl.index()
            && body[0] == b'R'
            && body[2..4] == [0, 0]
            && (body[1] == 3 || (cfg!(feature = "test-m7-document") && matches!(body[1], 19 | 20)))
        {
            #[cfg(feature = "test-m7-document")]
            if !match (body[1], self.document_request) {
                (3, None) => true,
                (19 | 20, Some((target, request))) => {
                    self.awaiting_open == Some(target)
                        && (body[1] == 20)
                            == (request.operation()
                                == ev_userspace_contract::document_control::Operation::OpenEdit)
                }
                _ => false,
            } {
                return;
            }
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
                    wire: {
                        #[cfg(feature = "test-m7-document")]
                        let edit = self.document_request.is_some_and(|(actual, request)| {
                            actual == target
                                && request.operation()
                                    == ev_userspace_contract::document_control::Operation::OpenEdit
                        });
                        #[cfg(not(feature = "test-m7-document"))]
                        let edit = false;
                        match (body[2], edit) {
                            (1, true) => Channel::NotesWrite.index(),
                            (2, true) => Channel::PrivateWrite.index(),
                            (1, false) => Channel::NotesRead.index(),
                            _ => Channel::PrivateRead.index(),
                        }
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
                        let Ok(snapshot) = ev_diagnostics::system::Snapshot::decode(&bytes) else {
                            native.diagnostic_error = true;
                            return;
                        };
                        (self.observations)(Observation::NativeSystem(NativeDiagnostic {
                            report: report.serial,
                            root_process,
                            root_thread,
                            bytes,
                        }));
                        #[cfg(feature = "test-m6-network")]
                        if snapshot.current.is_some_and(|current| {
                            matches!(
                                current.phase,
                                ev_diagnostics::system::Phase::Healthy
                                    | ev_diagnostics::system::Phase::Failed
                            )
                        }) {
                            self.startup_flush();
                        }
                        #[cfg(not(feature = "test-m6-network"))]
                        let _ = snapshot;
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

#[cfg(feature = "test-m6-session")]
impl Runtime<'_, '_> {
    fn completed_session_ui(&mut self, pending: Pending, value: u64) {
        let request = pending.value;
        let caller = self.metadata(pending.caller).unwrap();
        let callee = self.metadata(pending.callee).unwrap();
        let endpoint = self.wires[pending.wire].as_ref().unwrap().object;
        if pending.wire == Channel::InputBarrier.index()
            && pending.caller == Child::Shell.index() + 1
            && pending.callee == Child::Input.index() + 1
            && let Some(presented) = self.last_present[1]
            && let Some(update) = session_ui::barrier_at_present(
                request,
                value,
                caller.process.diagnostic_id(),
                presented.shell_process,
                presented.frame,
                &mut self.session_ui[0],
            )
        {
            let fields = update.fields;
            // Preserve the same actual Shell/Input/Present join as KBR1.
            // Operational freshness must continue after the serial sample cap.
            self.barrier = Some(Barrier {
                shell: caller.process,
                frame: u64::from(fields.frame),
                tick: crate::timer::now(),
                flags: fields.flags,
                call: pending.id,
            });
            if let Some(count) = update.sample {
                (self.observations)(Observation::SessionBarrier(SessionBarrier {
                    count,
                    call_epoch: pending.id.epoch().get(),
                    call: pending.id.serial(),
                    endpoint,
                    caller_process: caller.process.diagnostic_id(),
                    caller_thread: caller.thread.diagnostic_id(),
                    callee_process: callee.process.diagnostic_id(),
                    callee_thread: callee.thread.diagnostic_id(),
                    frame: fields.frame,
                    sequence: fields.sequence,
                    flags: fields.flags,
                    buttons: fields.buttons,
                    request,
                    reply: value,
                    tick: crate::timer::now(),
                }));
            }
        }
        if pending.wire == Channel::ShellWindow.index()
            && pending.caller == Child::Shell.index() + 1
            && pending.callee == Child::Display.index() + 1
            && let Some(fields) = session_ui::cursor(request, value)
            && let Some(count) = session_ui::sample(&mut self.session_ui[1])
        {
            (self.observations)(Observation::SessionCursor(SessionCursor {
                count,
                call_epoch: pending.id.epoch().get(),
                call: pending.id.serial(),
                endpoint,
                caller_process: caller.process.diagnostic_id(),
                caller_thread: caller.thread.diagnostic_id(),
                callee_process: callee.process.diagnostic_id(),
                callee_thread: callee.thread.diagnostic_id(),
                x: fields.x,
                y: fields.y,
                sequence: fields.sequence,
                request,
                reply: value,
                tick: crate::timer::now(),
            }));
        }
    }
    fn session_current_app(&self) -> Option<Metadata> {
        let app = self.actors[Child::App.index()].as_ref()?;
        (!app.retired
            && app.running.is_some()
            && self
                .s
                .state(app.meta.thread)
                .is_ok_and(|state| state != State::Exited))
        .then_some(app.meta)
    }
    fn accepted_session_note(
        &mut self,
        index: usize,
        wire: usize,
        value: u64,
        ticket: Ticket,
        tick: u64,
    ) {
        if index != 0 || wire != Channel::AppControl.index() {
            return;
        }
        let Some(app) = self.session_current_app() else {
            return;
        };
        if self.wires[wire].as_ref().unwrap().receiver != app.domain {
            return;
        }
        self.session_note_observation(
            SessionNotePhase::Accepted,
            self.root.meta,
            app,
            (wire, ticket, value, tick),
        );
    }
    fn received_session_note(
        &mut self,
        receiver: usize,
        wire: usize,
        process: ProcessId,
        thread: ThreadId,
        value: u64,
        delivery: (Ticket, u64),
    ) {
        let (ticket, tick) = delivery;
        #[cfg(feature = "test-m6-network-negative")]
        self.negative_work_delivery(receiver, wire, process, thread, value, ticket, tick);
        let Some(app) = self.session_current_app() else {
            return;
        };
        if receiver == 0 && wire == 15 && (process, thread) == (app.process, app.thread) {
            self.session_note_observation(
                SessionNotePhase::Request,
                app,
                self.root.meta,
                (wire, ticket, value, tick),
            );
        } else if receiver == Child::App.index() + 1
            && wire == Channel::AppControl.index()
            && (process, thread) == (self.root.meta.process, self.root.meta.thread)
        {
            self.session_note_observation(
                SessionNotePhase::Delivered,
                self.root.meta,
                app,
                (wire, ticket, value, tick),
            );
        }
    }
    fn session_note_observation(
        &mut self,
        phase: SessionNotePhase,
        sender: Metadata,
        receiver: Metadata,
        delivery: (usize, Ticket, u64, u64),
    ) {
        use ev_userspace_contract::session_note;
        let (wire, ticket, value, tick) = delivery;
        #[cfg(feature = "test-m6-network")]
        if matches!(phase, SessionNotePhase::Delivered) {
            self.startup_note_delivered(sender, receiver, delivery);
        }
        let bytes = value.to_le_bytes();
        let (counter, nonce) = match phase {
            SessionNotePhase::Request => match session_note::Request::decode(&bytes, 0) {
                Ok(request) => (2, request.nonce()),
                Err(_) => return,
            },
            SessionNotePhase::Accepted | SessionNotePhase::Delivered => {
                let Ok(reply) = session_note::Response::decode(&bytes, 0) else {
                    return;
                };
                (
                    if matches!(phase, SessionNotePhase::Accepted) {
                        3
                    } else {
                        4
                    },
                    reply.nonce(),
                )
            }
        };
        let Some(count) = session_ui::sample(&mut self.session_ui[counter]) else {
            return;
        };
        (self.observations)(Observation::SessionNote(SessionNote {
            phase,
            count,
            endpoint: self.wires[wire].as_ref().unwrap().object,
            ticket: ticket.0,
            sender_process: sender.process.diagnostic_id(),
            sender_thread: sender.thread.diagnostic_id(),
            receiver_process: receiver.process.diagnostic_id(),
            receiver_thread: receiver.thread.diagnostic_id(),
            nonce,
            opcode: bytes[3],
            message: value,
            tick,
        }));
    }
    pub(super) fn emit_session_ui_counts(&mut self, phase: &'static str) {
        assert!(matches!(phase, "finished" | "bound"));
        (self.observations)(Observation::SessionUiCounts(SessionUiCounts {
            phase,
            barriers: self.session_ui[0],
            cursors: self.session_ui[1],
            note_requests: self.session_ui[2],
            note_accepted: self.session_ui[3],
            note_delivered: self.session_ui[4],
        }));
    }
}
