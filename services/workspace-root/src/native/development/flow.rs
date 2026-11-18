//! Finite actual native transfer, allocation and exact slot retirement/start.
use super::*;
use ev_userspace_contract::root_v5::dynamic::Operation;
fn scalar(r: rt::CapReply) -> bool {
    r.value == 0 && r.capability == 0 && r.serial == 0
}
fn call(p: &mut Pending, op: u64, args: [u64; 4]) -> Result<rt::CapReply, ()> {
    if now() >= p.approval.cut() {
        return Err(());
    }
    let r = rt::call4(op, args[0], args[1], args[2], args[3]);
    p.last_call = Some((op, args, r));
    if now() >= p.approval.cut() {
        return Err(());
    }
    Ok(r)
}
impl Root<'_> {
    pub(in crate::native) fn development_tick(&mut self) -> bool {
        if !self.development.active() {
            return false;
        }
        for _ in 0..32 {
            if !self.receive() {
                break;
            }
        }
        if self.development.pending.is_some() {
            // ND owns its own exact original reply cut. Ordinary controls from
            // commit_scene must instead use the accepted Run's retained call
            // owner below; generic flush has an independent failure policy.
            self.app_data_flush();
        } else {
            self.flush();
        }
        if let Some((cut, false)) = self
            .development
            .dialog
            .as_ref()
            .map(|d| (d.drain_cut, d.drained))
        {
            if now() >= cut {
                self.development_cancel();
                self.status = b"Recent actions did not settle; no installation started";
            } else if !self.outbox.has_pending() {
                match self.inspector_self_shutdown(cut) {
                    Ok(true) => {
                        self.development.dialog.as_mut().unwrap().drained = true;
                        self.owner.dirty = true;
                    }
                    Ok(false) => (),
                    Err(()) => {
                        self.development_cancel();
                        self.status = b"Inspection cleanup is unsettled; no installation started";
                    }
                }
            }
        }
        let executing_view = self.development.view();
        if let Some(mut pending) = self.development.pending.take() {
            self.development.executing_cut = Some(pending.approval.cut());
            self.development.executing_view = executing_view;
            if pending.step != Step::Fenced {
                if now() >= pending.approval.cut() {
                    pending.step = Step::Fenced;
                } else if let Err(failure) = self.development_step(&mut pending) {
                    match failure {
                        storage::Failure::NotInstalled if pending.step == Step::CheckRegistry => {
                            self.status = b"No exact installed package exists; use Install first";
                            self.development.executing_cut = None;
                            self.development.executing_view = None;
                            self.owner.dirty = true;
                            checked(s::YIELD, 0, 0, 0);
                            return true;
                        }
                        storage::Failure::Refused
                            if !pending.storage_started
                                && matches!(
                                    pending.step,
                                    Step::CheckRegistry | Step::Allocate | Step::Initialize
                                ) =>
                        {
                            self.status=b"Local development request refused; existing data and application retained";
                            self.development.executing_cut = None;
                            self.development.executing_view = None;
                            self.owner.dirty = true;
                            checked(s::YIELD, 0, 0, 0);
                            return true;
                        }
                        storage::Failure::Retained => {
                            pending.step = Step::Fenced;
                        }
                        _ => pending.step = Step::Fenced,
                    }
                }
            }
            self.development.executing_cut = None;
            self.development.executing_view = None;
            if pending.step == Step::Complete {
                self.status = if pending.approval.intent() == Intent::Install {
                    b"Local development package installed; choose Run separately"
                } else {
                    b"Independent local application started"
                };
                self.development.status = self.status;
                self.owner.dirty = true;
            } else {
                if pending.step == Step::Fenced {
                    self.development.status=b"Installation/run incomplete; exact accepted work and owners remain retained";
                }
            }
            // Keep the sole accepted owner through the actual final Root
            // frame, including its original cut and any unresolved Display RPC.
            self.development.pending = Some(pending);
        }
        if self.owner.dirty && self.try_present_owner().is_err() {
            if let Some(p) = self.development.pending.as_mut() {
                p.step = Step::Fenced;
            } else {
                self.development_cancel();
            }
            // Unknown Present/control retains Protected's exact source and
            // attempt and fences writes. Never retry or exit to fake cleanup.
            self.owner.dirty = false;
        }
        // The known completed workflow ends at its verified final Root frame
        // before the cut. Later scheduling is independent of that completion.
        if self
            .development
            .pending
            .as_ref()
            .is_some_and(|p| p.step == Step::Complete)
        {
            let p = self.development.pending.as_mut().unwrap();
            if now() >= p.approval.cut() {
                p.step = Step::Fenced;
            } else {
                self.development.pending = None;
                self.owner.dirty = true;
            }
        }
        let r = rt::call4(s::YIELD, 0, 0, 0, 0);
        if (r.status != 0 || !scalar(r))
            && let Some(p) = self.development.pending.as_mut()
        {
            p.step = Step::Fenced;
        }
        true
    }
    fn development_step(&mut self, p: &mut Pending) -> Result<(), storage::Failure> {
        if !self.development_flush_pending(p)? {
            return Ok(());
        }
        let cut = p.approval.cut();
        if now() >= cut {
            return Err(storage::Failure::Retained);
        }
        let source = p.approval.facts().source;
        let fail = || storage::Failure::Retained;
        match p.step {
            Step::CheckRegistry => {
                self.development_registry(p, false)?;
                p.step = Step::Initialize;
            }
            Step::Initialize => {
                if self
                    .development
                    .registered
                    .is_some_and(|(s, _)| s == source)
                {
                    p.slot = self.development.registered.map(|(_, slot)| slot);
                    p.step = if p.approval.intent() == Intent::Install {
                        Step::Allocate
                    } else {
                        Step::CloseOld
                    };
                } else {
                    if self.development.images.is_none() {
                        let io = kernel::Kernel::new(self.bootstrap.handle(Role::CreatorJob), cut)
                            .map_err(|_| fail())?;
                        self.development.images =
                            Some(Images::new(io, BASE as u64).map_err(|_| fail())?);
                        self.development
                            .images
                            .as_mut()
                            .unwrap()
                            .initialize(now())
                            .map_err(|_| fail())?;
                    }
                    p.step = Step::Begin;
                }
            }
            Step::Begin => {
                let loaded = self.development_loaded().map_err(|_| fail())?;
                let available = self.app_data_available();
                let support =
                    ev_workspace_root::requirements::PrivateDataContracts::new(&loaded, available);
                let bytes = source_bytes(&self.catalogue).map_err(|_| fail())?;
                let checked = ev_workspace_root::requirements::private_file_app(bytes, &support)
                    .map_err(|_| fail())?;
                if model::Source::of(checked.package()) != source {
                    return Err(fail());
                }
                let header =
                    ev_workspace_root::install_plan::header(&checked).map_err(|_| fail())?;
                let slot = self
                    .development
                    .images
                    .as_mut()
                    .unwrap()
                    .begin(header, now(), cut)
                    .map_err(|_| fail())?;
                p.slot = Some(slot);
                p.offset = 0;
                p.step = Step::Copy;
            }
            Step::Copy => {
                let bytes = source_bytes(&self.catalogue).map_err(|_| fail())?;
                let end = (p.offset + 4096).min(bytes.len());
                self.development
                    .images
                    .as_mut()
                    .unwrap()
                    .write_chunk(p.slot.ok_or_else(fail)?, now(), &bytes[p.offset..end])
                    .map_err(|_| fail())?;
                p.offset = end;
                if end == bytes.len() {
                    p.step = Step::Seal;
                }
            }
            Step::Seal => {
                self.development
                    .images
                    .as_mut()
                    .unwrap()
                    .seal(p.slot.ok_or_else(fail)?, now())
                    .map_err(|_| fail())?;
                p.step = Step::Verify;
            }
            Step::Verify => {
                if self
                    .development
                    .images
                    .as_mut()
                    .unwrap()
                    .verify_step(p.slot.ok_or_else(fail)?, now())
                    .map_err(|_| fail())?
                {
                    p.step = Step::Register;
                }
            }
            Step::Register => {
                let loaded = self.development_loaded().map_err(|_| fail())?;
                // Images' historical public path does not advertise ND. Its
                // actual package requirements are checked under this loaded
                // native context, then the exact same sealed source is bound.
                let available = self.app_data_available();
                let support =
                    ev_workspace_root::requirements::PrivateDataContracts::new(&loaded, available);
                let slot = p.slot.ok_or_else(fail)?;
                let images = self.development.images.as_mut().unwrap();
                let checked = ev_workspace_root::requirements::private_file_app(
                    images.bytes(slot).map_err(|_| fail())?,
                    &support,
                )
                .map_err(|_| fail())?;
                if model::Source::of(checked.package()) != source {
                    return Err(fail());
                }
                images
                    .register_private(slot, now(), &support)
                    .map_err(|_| fail())?;
                self.development.registered = Some((source, slot));
                p.step = if p.approval.intent() == Intent::Install {
                    Step::Allocate
                } else {
                    Step::CloseOld
                };
            }
            Step::Allocate => {
                self.development_allocate(p)?;
                p.step = Step::Complete;
            }
            Step::CloseOld => {
                if self.actors[Child::EditorTwo.index()].is_none_or(|a| !same_actor(a, p.old)) {
                    return Err(fail());
                }
                if !self.app_data_can_stop() {
                    return Err(fail());
                }
                self.app_data_seal(cut).map_err(|_| fail())?;
                if actual(p.old).map_err(|_| fail())? {
                    p.step = Step::RetireFile;
                } else {
                    let bytes = Command::Close { discard: false }.encode().unwrap();
                    let r = call(
                        p,
                        s::SEND,
                        [
                            self.channel(Channel::EditorTwoControl),
                            u64::from_le_bytes(bytes),
                            0,
                            0,
                        ],
                    )
                    .map_err(|_| fail())?;
                    if !scalar(r) {
                        return Err(fail());
                    }
                    match r.status {
                        0 => p.step = Step::AwaitOld,
                        2 => (),
                        _ => return Err(fail()),
                    }
                }
            }
            Step::AwaitOld => {
                if actual(p.old).map_err(|_| fail())? {
                    p.step = Step::RetireFile;
                }
            }
            Step::RetireFile => {
                if self.shutdown_retire_file(2, cut).map_err(|_| fail())? {
                    p.step = Step::StopOld;
                }
            }
            Step::StopOld => {
                if !self.app_data_can_stop() {
                    return Err(fail());
                }
                let r = call(p, s::STOP_PROCESS, [p.old.control, 0, 0, 0]).map_err(|_| fail())?;
                if !scalar(r) {
                    return Err(fail());
                }
                match r.status {
                    0 => {
                        let target =
                            ev_workspace_root::shutdown::Target::captured(Child::EditorTwo, p.old)
                                .ok_or_else(fail)?;
                        self.app_data_stopped(target).map_err(|_| fail())?;
                        p.step = Step::DrainOld;
                    }
                    2 => (),
                    _ => return Err(fail()),
                }
            }
            Step::DrainOld => {
                if p.empty_after_stop && self.app_data_quiescent() {
                    p.step = Step::ReapOld;
                }
            }
            Step::ReapOld => {
                let r = call(p, s::REAP, [p.old.control, 0, 0, 0]).map_err(|_| fail())?;
                if !scalar(r) {
                    return Err(fail());
                }
                match r.status {
                    0 => p.step = Step::CloseOldControl,
                    2 => (),
                    _ => return Err(fail()),
                }
            }
            Step::CloseOldControl => {
                let r = call(p, s::CLOSE, [p.old.control, 0, 0, 0]).map_err(|_| fail())?;
                if r.status != 0 || !scalar(r) {
                    return Err(fail());
                }
                let _ = self.policy.as_mut().unwrap().retire(2, p.old.identity);
                self.outbox.retire(2);
                self.actors[Child::EditorTwo.index()] = None;
                self.states[2] = None;
                self.closing[2] = false;
                self.file_may_be_held[2] = false;
                self.paused[2] = None;
                self.lease_rights[2] = 0;
                self.development.running = None;
                p.step = Step::CreateJob;
            }
            Step::CreateJob => {
                let r = call(
                    p,
                    s::CREATE_JOB,
                    [
                        self.bootstrap.handle(Role::CreatorJob),
                        Child::EditorTwo.job_template(),
                        0,
                        0,
                    ],
                )
                .map_err(|_| fail())?;
                if r.status != 0
                    || r.capability != 0
                    || r.serial != 0
                    || matches!(r.value, 0 | u64::MAX)
                {
                    return Err(fail());
                }
                p.job = Some(r.value);
                p.step = Step::CreateProcess;
            }
            Step::CreateProcess => {
                let cap = self
                    .development
                    .images
                    .as_ref()
                    .unwrap()
                    .registered_capability(p.slot.ok_or_else(fail)?)
                    .ok_or_else(fail)?;
                let r = call(p, s::CREATE_PROCESS, [p.job.ok_or_else(fail)?, cap, 0, 0])
                    .map_err(|_| fail())?;
                if r.status != 0
                    || r.capability != 0
                    || r.serial != 0
                    || matches!(r.value, 0 | u64::MAX)
                {
                    return Err(fail());
                }
                let held = Actor {
                    control: r.value,
                    identity: identity(r.value, self.bootstrap.context().incarnation),
                    ready: false,
                    mapping_epoch: 1,
                    failed: false,
                };
                p.held = Some(held);
                p.step = Step::Delegate;
            }
            Step::Delegate => {
                let held = p.held.ok_or_else(fail)?;
                if let Some(grant) = graph::grants(Child::EditorTwo).nth(p.delegated) {
                    let r = call(
                        p,
                        s::DELEGATE,
                        [
                            held.control,
                            self.source(grant.source),
                            p.delegated as u64 + 1,
                            0,
                        ],
                    )
                    .map_err(|_| fail())?;
                    if r.status != 0 || r.capability != 0 || r.serial != 0 || r.value == 0 {
                        return Err(fail());
                    }
                    if grant.kind == 2
                        && grant.rights & 16 != 0
                        && let graph::Source::Endpoint(channel) = grant.source
                    {
                        let r = call(
                            p,
                            s::BIND_RECEIVER,
                            [self.channel(channel), held.control, 0, 0],
                        )
                        .map_err(|_| fail())?;
                        if r.status != 0 || !scalar(r) {
                            return Err(fail());
                        }
                    }
                    p.delegated += 1;
                } else {
                    p.step = Step::Prepare;
                }
            }
            Step::Prepare => {
                let held = p.held.ok_or_else(fail)?;
                let r = call(
                    p,
                    s::IMAGE_CONTROL,
                    [
                        self.bootstrap.handle(Role::CreatorJob),
                        Operation::PrepareProcess as u64,
                        held.control,
                        0,
                    ],
                )
                .map_err(|_| fail())?;
                if r.status != 0 || !scalar(r) {
                    return Err(fail());
                }
                p.step = Step::Enroll;
            }
            Step::Enroll => {
                let loaded = self.development_loaded().map_err(|_| fail())?;
                let available = self.app_data_available();
                let support =
                    ev_workspace_root::requirements::PrivateDataContracts::new(&loaded, available);
                // Ingress and sealed registered bytes are independently bound
                // to this exact full source before the actual held handoff.
                let bytes = source_bytes(&self.catalogue).map_err(|_| fail())?;
                let checked = ev_workspace_root::requirements::private_file_app(bytes, &support)
                    .map_err(|_| fail())?;
                let descriptor =
                    ev_workspace_root::app_data::descriptor::Descriptor::for_enrolled_app(
                        checked.package().app().claimed_app,
                        1,
                    )
                    .ok_or_else(fail)?;
                let held = p.held.ok_or_else(fail)?;
                // Do not borrow self's bank through this call: its actual fixed
                // immutable source is revalidated by the dedicated native seam.
                self.development_enroll_exact(held, descriptor, cut)
                    .map_err(|_| fail())?;
                p.step = Step::Activate;
            }
            Step::Activate => {
                self.development_registry(p, true)?;
                p.activated = true;
                p.step = Step::Start;
            }
            Step::Start => {
                if !p.activated {
                    return Err(fail());
                }
                let held = p.held.ok_or_else(fail)?;
                let r = call(p, s::START, [held.control, 0, 0, 0]).map_err(|_| fail())?;
                if r.status != 0 || !scalar(r) {
                    return Err(fail());
                }
                self.actors[Child::EditorTwo.index()] = Some(held);
                self.policy
                    .as_mut()
                    .unwrap()
                    .install(2, held)
                    .map_err(|_| fail())?;
                self.development.running = Some(Running {
                    slot: p.slot.ok_or_else(fail)?,
                    source,
                    target: held,
                });
                self.try_commit_scene().map_err(|_| fail())?;
                self.scene_dirty = false;
                let job = p.job.ok_or_else(fail)?;
                let a =
                    call(p, s::PROCESS_JOB_INFO, [held.control, 0, 0, 0]).map_err(|_| fail())?;
                let b = call(p, s::JOB_INFO, [job, 0, 0, 0]).map_err(|_| fail())?;
                if a.status != 0
                    || b.status != 0
                    || a.capability != 0
                    || b.capability != 0
                    || a.value == 0
                    || a.value != b.value
                {
                    return Err(fail());
                }
                let r = call(p, s::CLOSE, [job, 0, 0, 0]).map_err(|_| fail())?;
                if r.status != 0 || !scalar(r) {
                    return Err(fail());
                }
                p.job = None;
                p.step = Step::WaitReady;
            }
            Step::WaitReady => {
                let current = self.actor(Child::EditorTwo);
                if !same_actor(current, p.held.ok_or_else(fail)?)
                    || actual(current).map_err(|_| fail())?
                {
                    return Err(fail());
                }
                if current.ready
                    && matches!(self.states[2], Some(AppState::Saved | AppState::NoFile))
                {
                    p.step = Step::Complete;
                }
            }
            Step::Complete | Step::Fenced => (),
        }
        // Parsing/hash/readback and ordinary state observation can also consume
        // time. Even a terminal phase cannot publish success past this one cut.
        if now() >= cut {
            return Err(storage::Failure::Retained);
        }
        if p.step != Step::Complete {
            self.development.status = match p.step {
                Step::CloseOld
                | Step::AwaitOld
                | Step::RetireFile
                | Step::StopOld
                | Step::DrainOld
                | Step::ReapOld
                | Step::CloseOldControl => {
                    b"Closing exact old Editor2; file/private reply and window debts must settle"
                }
                Step::CreateJob
                | Step::CreateProcess
                | Step::Delegate
                | Step::Prepare
                | Step::Enroll
                | Step::Activate
                | Step::Start
                | Step::WaitReady => {
                    b"Preparing exact held local application; no completed-run or health claim"
                }
                _ => b"Checking and durably installing exact local development package",
            };
            self.owner.dirty = true;
        }
        Ok(())
    }
    fn development_flush_pending(&mut self, p: &mut Pending) -> Result<bool, storage::Failure> {
        for index in 0..5 {
            let Some(command) = self.outbox.next(index) else {
                continue;
            };
            let child = if index == 4 {
                Child::Shell
            } else {
                app_child(index).ok_or(storage::Failure::Retained)?
            };
            if self.actors[child.index()].is_none_or(|a| a.failed) {
                return Err(storage::Failure::Retained);
            }
            let bytes = command.encode().map_err(|_| storage::Failure::Retained)?;
            let r = call(
                p,
                s::SEND,
                [
                    self.channel(control_channel(child).ok_or(storage::Failure::Retained)?),
                    u64::from_le_bytes(bytes),
                    0,
                    0,
                ],
            )
            .map_err(|_| storage::Failure::Retained)?;
            if !scalar(r) {
                return Err(storage::Failure::Retained);
            }
            match r.status {
                0 if self.outbox.accepted(index) => (),
                2 => (), // Exact preaccept Full; same frame and original cut.
                _ => return Err(storage::Failure::Retained),
            }
        }
        Ok(!self.outbox.has_pending())
    }
}
