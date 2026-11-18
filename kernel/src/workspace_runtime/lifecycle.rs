use super::*;
impl World {
    pub(super) fn create_process(
        &mut self,
        caller: SpaceId,
        job: Handle,
        image: Handle,
    ) -> Result<Handle, u64> {
        let object = self
            .core
            .a
            .authorize(caller, image, Kind::Memory, Rights::READ)
            .map_err(|_| 1u64)?
            .identity();
        let dynamic_slot = self.dynamic.object_slot(self.core.a, caller, image);
        let editor = dynamic_slot.is_some()
            || self.core.backing.identity(self.core.a, Role::EditorImage) == object;
        let selected = if editor {
            [Child::EditorOne, Child::EditorTwo]
                .into_iter()
                .find(|c| self.actors[c.index()].is_none())
        } else {
            graph::CHILDREN.into_iter().find(|c| {
                self.actors[c.index()].is_none()
                    && self.core.backing.identity(self.core.a, c.image()) == object
            })
        };
        let (index, child, bound) = match selected {
            Some(child) => (child.index(), child, true),
            None if editor && self.actors[11].is_none() => (11, Child::EditorOne, false),
            _ => return Err(2),
        };
        let control = self
            .core
            .registry
            .create_process(self.core.a, self.core.s, caller, job, image)
            .map_err(|_| 1u64)?;
        let meta = self
            .core
            .registry
            .metadata(self.core.a, caller, control)
            .unwrap();
        let object = self
            .core
            .a
            .authorize(caller, control, Kind::Process, Rights::CONTROL)
            .unwrap()
            .identity();
        self.core
            .s
            .configure_cpu_budget(
                meta.job,
                v5::resources::CHILD_QUOTA_TICKS,
                v5::resources::PERIOD_TICKS,
            )
            .expect("closed V5 child scheduling quota");
        self.core
            .rpc
            .register_thread(
                self.core.a,
                self.core.s,
                meta.thread,
                meta.job,
                meta.domain,
                Some(self.token),
            )
            .unwrap();
        self.actors[index] = Some(Actor {
            child,
            meta,
            control,
            object,
            running: None,
            returned: None,
            context: UserContext::ZERO,
            fx: FxState::CLEAN,
            admitted: false,
            retired: false,
            fault: None,
            bound,
            prepared: None,
            dynamic_slot,
        });
        self.facts.created += 1;
        Ok(control)
    }
    /// Only the exact actual source can bind the extra held File App to one
    /// declared instance. No packet ordinal, app name or PID selects a source.
    pub(super) fn delegate_child(
        &mut self,
        caller: SpaceId,
        process: Handle,
        source: Handle,
        selector: u64,
    ) -> Result<Handle, u64> {
        let index = self.find_control(caller, process)? - 1;
        let actor = self.actors[index].as_ref().ok_or(1u64)?;
        if actor.admitted || actor.retired || actor.prepared.is_some() {
            return Err(1);
        }
        let child = if !actor.bound {
            if index != 11 || selector != 1 {
                return Err(1);
            }
            let object = self
                .core
                .a
                .authorize(
                    caller,
                    source,
                    Kind::Memory,
                    Rights::READ | Rights::WRITE | Rights::MAP,
                )
                .map_err(|_| 1u64)?
                .identity();
            [Child::EditorOne, Child::EditorTwo]
                .into_iter()
                .find(|c| {
                    self.core
                        .backing
                        .identity(self.core.a, c.surface().unwrap())
                        == object
                })
                .ok_or(1u64)?
        } else {
            actor.child
        };
        let grant = graph::grants(child)
            .nth(selector.checked_sub(1).ok_or(1u64)? as usize)
            .ok_or(1u64)?;
        let actual = self
            .core
            .a
            .authorize(
                caller,
                source,
                kind(grant.kind),
                Rights::from_bits(grant.rights).ok_or(1u64)?,
            )
            .map_err(|_| 1u64)?
            .identity();
        let expected = match grant.source {
            graph::Source::Root(role) => self.core.backing.identity(self.core.a, role),
            graph::Source::Endpoint(channel) => {
                self.wires[channel.index()].as_ref().ok_or(1u64)?.object
            }
        };
        if actual != expected {
            return Err(1);
        }
        let installed = self
            .core
            .registry
            .delegate(self.core.a, caller, process, source, selector)
            .map_err(|_| 1u64)?;
        let actor = self.actors[index].as_mut().unwrap();
        actor.child = child;
        actor.bound = true;
        Ok(installed)
    }
    /// # Safety
    /// Captured actual Root, sole IF0 allocator/controller, complete trusted
    /// grants. Loads actual private bytes only; it cannot admit or map shared
    /// instance buffers while the previous process is still live.
    #[inline(never)]
    pub(super) unsafe fn prepare_process(
        &mut self,
        caller: SpaceId,
        cap: Handle,
        frames: &mut BootstrapFrames,
        log: &mut dyn Write,
    ) -> Result<(), u64> {
        let index = self.find_control(caller, cap)? - 1;
        let actor = self.actors[index].as_ref().ok_or(1u64)?;
        if actor.admitted || actor.retired || !actor.bound {
            return Err(1);
        }
        if actor.prepared.is_some() {
            return Ok(());
        }
        if index == 11
            && self.spare_claimed
            && [Child::EditorOne.index(), Child::EditorTwo.index(), 11]
                .into_iter()
                .all(|i| self.vacant[i].is_none())
        {
            return Err(2);
        }
        let child = actor.child;
        let meta = actor.meta;
        let dynamic_slot = actor.dynamic_slot;
        let startup = self
            .core
            .registry
            .startup_m8(self.core.a, caller, cap, EPOCH)
            .map_err(|_| 1u64)?;
        let record = startup.record().map_err(|_| 1u64)?;
        let free_before = frames.remaining_frames();
        // SAFETY: exact pinned immutable descriptor/owner; no mutable package
        // reference survives this load. Failed physical loads retain allocator
        // claims and are fatal rather than recycling half-prepared owners.
        let loaded = if let Some(slot) = dynamic_slot {
            // SAFETY: exact registered sealed owner/held metadata and typed
            // startup, retained by this sole captured controller throughout.
            unsafe {
                self.dynamic.load_app(
                    slot,
                    self.core.registry,
                    self.core.a,
                    self.core.s,
                    caller,
                    cap,
                    record,
                    self.hw,
                    frames,
                )
            }
            .unwrap_or_else(|reason| {
                panic!("actual V5 sealed private load:{reason}; owners retained")
            })
        } else {
            let plan = self
                .core
                .registry
                .plan(self.core.a, caller, cap)
                .map_err(|_| 1u64)?;
            // SAFETY: Registry-held immutable plan and exact startup under the
            // same exclusive physical allocator/controller as sealed loading.
            unsafe { PhysicalImage::load(self.hw, Some(child.image_slot()), &plan, record, frames) }
                .expect("actual V5 compiled private load; owners retained")
        };
        let actual_private_frames = free_before
            .checked_sub(frames.remaining_frames())
            .expect("V5 private preparation cannot refund allocator claims");
        let expected_private_frames = meta.frames - if child == Child::Display { 2 } else { 0 };
        assert_eq!(
            actual_private_frames, expected_private_frames,
            "actual V5 prepared allocator claims vs descriptor frame charge"
        );
        let owner = if index == 11 {
            let vacant = [Child::EditorOne.index(), Child::EditorTwo.index(), 11]
                .into_iter()
                .find_map(|i| self.vacant[i].take());
            if let Some(slot) = vacant {
                *slot = loaded;
                slot
            } else {
                // One bounded extra physical owner. A second load is never
                // allowed to overwrite its retained backing or borrow.
                assert!(!self.spare_claimed, "V5 extra prepared owner retained");
                self.spare_claimed = true;
                // SAFETY: the permanent extra slot is claimed exactly once;
                // later reuse consumes an exclusive empty tombstone above.
                unsafe { resident::place_image(12, loaded) }
            }
        } else if let Some(slot) = self.vacant[index].take() {
            *slot = loaded;
            slot
        } else {
            // SAFETY: first allocation of this declared actor slot; subsequent
            // generations can reach this branch only through its tombstone.
            unsafe { resident::place_image(index + 1, loaded) }
        };
        self.actors[index].as_mut().unwrap().prepared = Some(owner);
        if let Some(slot) = dynamic_slot {
            self.dynamic.record_action(slot, 0);
        }
        self.event(log, "prepared_private_held", index + 1);
        let _ = writeln!(
            log,
            "EVROSION_M8_KERNEL_PREPARED actor={} process={} thread={} job={} actual_private_frames={actual_private_frames} charged_loader_frames={} held=true shared_mappings=0 tick={}",
            index + 1,
            meta.process.diagnostic_id(),
            meta.thread.diagnostic_id(),
            meta.job.diagnostic_id(),
            meta.frames,
            crate::timer::now()
        );
        Ok(())
    }
    pub(super) unsafe fn start(
        &mut self,
        caller: SpaceId,
        cap: Handle,
        frames: &mut BootstrapFrames,
        log: &mut dyn Write,
    ) -> Result<(), u64> {
        let mut index = self.find_control(caller, cap)? - 1;
        let actor = self.actors[index].as_ref().unwrap();
        if actor.admitted || actor.retired || !actor.bound {
            return Err(1);
        }
        if index == 11 {
            let target = actor.child.index();
            // The previous actual Process row is collected only after Reap
            // AND closure of its final ProcessCONTROL. No cooperative ACK can
            // substitute for this retained-owner fence.
            if self.actors[target].is_some() {
                return Err(2);
            }
        }
        // SAFETY: same held process, retained quota/grants and allocator.
        unsafe {
            self.prepare_process(caller, cap, frames, log)?;
        }
        if index == 11 {
            let target = self.actors[index].as_ref().unwrap().child.index();
            self.actors[target] = self.actors[index].take();
            index = target;
        }
        let actor = self.actors[index].as_mut().unwrap();
        let meta = actor.meta;
        let child = actor.child;
        let owner = actor.prepared.take().ok_or(1u64)?;
        for spec in mapping::for_child(child) {
            let selector = graph::grants(child)
                .position(|g| g.source == graph::Source::Root(spec.role))
                .ok_or(1u64)? as u64
                + 1;
            let grant = self
                .core
                .registry
                .grant(self.core.a, caller, cap, selector)
                .map_err(|_| 1u64)?;
            let extent = self.core.backing.extents[spec.role.selector() as usize - 1]
                .as_mut()
                .ok_or(1u64)?;
            // SAFETY: previous instance fully retired/closed/scrubbed; actual
            // held image and exact fixed grant/extent remain pinned.
            unsafe { owner.install(self.core.a, extent, meta.domain, grant, spec) }
                .expect("actual child shared PTE/lease join");
        }
        if child == Child::Display {
            let selector = graph::grants(child)
                .position(|g| g.source == graph::Source::Root(Role::Display))
                .unwrap() as u64
                + 1;
            let grant = self
                .core
                .registry
                .grant(self.core.a, caller, cap, selector)
                .unwrap();
            let plan = self
                .core
                .registry
                .plan(self.core.a, caller, cap)
                .map_err(|_| 1u64)?;
            // SAFETY: actual held Display lease/owner and charged table budget.
            unsafe {
                owner.install_display(
                    self.core.a,
                    self.core.s,
                    self.core.backing.device.as_mut().unwrap(),
                    grant,
                    &plan,
                    meta,
                    frames,
                    self.hw,
                )
            }
            .expect("actual Display two-table/GOP owner");
        }
        owner
            .check(self.core.a, &self.core.backing.extents)
            .expect("actual child shared readback");
        let lease = ImageLease::new(owner, meta, Some(child));
        match self
            .core
            .registry
            .start(self.core.a, self.core.s, caller, cap, EPOCH, lease)
        {
            Ok(running) => {
                let context = running.initial_context().unwrap();
                let actor = self.actors[index].as_mut().unwrap();
                actor.context = context;
                actor.running = Some(running);
                actor.admitted = true;
                if let Some(slot) = actor.dynamic_slot {
                    self.dynamic.record_action(slot, 1);
                }
                self.facts.starts += 1;
                self.event(log, "started", index + 1);
                Ok(())
            }
            Err(rejected) => {
                self.actors[index].as_mut().unwrap().returned = Some(rejected.image);
                Err(1)
            }
        }
    }
    pub(super) fn stop_actor(&mut self, index: usize, log: &mut dyn Write) -> Result<(), u64> {
        self.stop_actor_inner(index, log, false)
    }
    // allow_device_cpu_freeze is reachable only from the captured power fence;
    // sources/ports/backing remain retained and no physical stop is inferred.
    pub(super) fn stop_actor_inner(
        &mut self,
        index: usize,
        log: &mut dyn Write,
        allow_device_cpu_freeze: bool,
    ) -> Result<(), u64> {
        let meta = self.metadata(index).ok_or(1u64)?;
        // This initial runner has no actual ATA/NE2000 device-stop handshake.
        // Keep the active provider, its ports and backing pinned; an empty RPC
        // table or a stopped CPU alone never authorizes a second device owner.
        if !allow_device_cpu_freeze
            && index != 0
            && self.actors[index - 1].as_ref().is_some_and(|actor| {
                actor.admitted && matches!(actor.child, Child::Block | Child::NetDriver)
            })
        {
            return Err(2);
        }
        if index == 0
            || self
                .pending
                .iter()
                .flatten()
                .any(|p| p.caller == index || p.callee == index)
            || matches!(self.core.s.state(meta.thread), Ok(State::Running(_)))
        {
            return Err(2);
        }
        if self.actors[index - 1]
            .as_ref()
            .is_some_and(|actor| actor.admitted)
        {
            self.stop_selected(index)?;
        }
        for wire in self.wires.iter_mut().flatten() {
            if wire.receiver == meta.domain && wire.mailbox.is_some() {
                wire.close(self.core.a, crate::timer::now())
                    .map_err(|_| 2u64)?;
            }
        }
        let actor = self.actors[index - 1].as_mut().unwrap();
        if let Some(running) = &mut actor.running {
            running.stop(self.core.a, self.core.s).map_err(|_| 1u64)?;
        }
        self.core
            .s
            .terminate_process(meta.process)
            .map_err(|_| 1u64)?;
        let events = self
            .core
            .rpc
            .peer_died(self.core.s, meta.thread, crate::timer::now())
            .map_err(|_| 1u64)?;
        if !events.is_empty() {
            return Err(2);
        }
        if let Some(running) = actor.running.take() {
            actor.returned = Some(
                running
                    .finish(self.core.s)
                    .unwrap_or_else(|_| panic!("actual V5 stopped owner")),
            );
        }
        self.facts.stops += 1;
        if let Some(slot) = actor.dynamic_slot {
            self.dynamic.record_action(slot, 2);
        }
        self.event(log, "stopped", index);
        Ok(())
    }
    pub(super) unsafe fn reap_actor(
        &mut self,
        index: usize,
        frames: &mut BootstrapFrames,
        log: &mut dyn Write,
    ) -> Result<(), u64> {
        let meta = self.metadata(index).ok_or(1u64)?;
        if self.core.s.state(meta.thread) != Ok(State::Exited)
            || self
                .pending
                .iter()
                .flatten()
                .any(|p| p.caller == index || p.callee == index)
        {
            return Err(2);
        }
        if self.actors[index - 1]
            .as_ref()
            .is_some_and(|actor| actor.admitted)
        {
            self.retire_selected(index)?;
        }
        let actor = self.actors[index - 1].as_mut().ok_or(1u64)?;
        let shared_was_installed = actor.returned.is_some() || actor.admitted;
        if let Some(lease) = actor.returned.take() {
            // SAFETY: actual exited process, no accepted call; returned unique
            // lease retains every mapping/device claim until detachment.
            let returned = unsafe {
                lease.owner.retire(
                    &mut self.core.backing.extents,
                    self.core.backing.device.as_mut().unwrap(),
                    self.core.s,
                    meta,
                    frames,
                )
            }
            .expect("actual V5 physical stopped detachment");
            assert_eq!(
                returned as u64, meta.frames,
                "actual private+display frame accounting"
            );
            self.vacant[index - 1] = Some(lease.owner);
        } else if let Some(owner) = actor.prepared.take() {
            // SAFETY: cancelled held process never executed or mapped its
            // shared instance windows; retain exact actual private RAM until
            // real stopped teardown, with the original Job charge intact.
            let returned = unsafe {
                owner.retire(
                    &mut self.core.backing.extents,
                    self.core.backing.device.as_mut().unwrap(),
                    self.core.s,
                    meta,
                    frames,
                )
            }
            .expect("actual V5 prepared private owner retirement");
            assert_eq!(returned as u64, meta.frames);
            self.vacant[index - 1] = Some(owner);
        } else if actor.admitted {
            return Err(2);
        }
        // SAFETY: old app is actually exited, accepted calls and selected
        // deliveries settled above, and its physical mapping owner just
        // detached. The stopped record remains retained until this completes.
        let scrubbed = if shared_was_installed {
            // SAFETY: the exact stopped mapping owner detached above and all
            // accepted calls/selected deliveries settled before retirement.
            unsafe {
                self.core
                    .backing
                    .scrub_retired_app(self.core.a, self.core.s, meta, actor.child)
            }
            .expect("actual V5 retired app buffer scrub/readback")
        } else {
            0
        };
        let _ = writeln!(
            log,
            "EVROSION_M8_KERNEL_SCRUB actor={index} process={} pages={scrubbed} tick={} scope=retired_app_surface_and_file_frame",
            meta.process.diagnostic_id(),
            crate::timer::now()
        );
        self.core
            .s
            .release_frames(meta.job, meta.frames)
            .map_err(|_| 1u64)?;
        self.core
            .registry
            .retire_stopped(self.core.a, self.core.s, meta.process)
            .map_err(|_| 1u64)?;
        self.core
            .rpc
            .forget_thread(self.core.s, meta.thread)
            .map_err(|_| 2u64)?;
        actor.retired = true;
        self.facts.reaps += 1;
        self.event(log, "reaped", index);
        Ok(())
    }
    pub(super) fn collect(&mut self) {
        for slot in &mut self.actors {
            if let Some(actor) = slot.as_ref()
                && actor.retired
                && self
                    .core
                    .registry
                    .forget_retired(self.core.a, self.core.s, actor.meta.process)
                    .is_ok()
            {
                self.core.s.reclaim_process(actor.meta.process).unwrap();
                *slot = None;
            }
        }
        for slot in &mut self.jobs {
            if let Some(job) = *slot
                && self
                    .core
                    .registry
                    .forget_job(self.core.a, self.core.s, self.core.rpc, job)
                    .is_ok()
            {
                *slot = None;
            }
        }
    }
}
