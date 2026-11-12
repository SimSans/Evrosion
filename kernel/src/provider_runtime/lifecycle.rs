//! Source-controlled lifecycle with retained actual private image claims.
use super::*;
impl<'image> Runtime<'image, '_> {
    pub(super) fn create_process(
        &mut self,
        caller: SpaceId,
        job: Handle,
        image: Handle,
    ) -> Result<Handle, u64> {
        let object = self
            .a
            .authorize(caller, image, Kind::Memory, Rights::READ)
            .map_err(|_| 1u64)?
            .identity();
        let which = self
            .images
            .iter()
            .take(self.assets.images.len())
            .position(|&id| id == object)
            .ok_or(1u64)?;
        let kind = self.assets.images[which].actor;
        let slot = match kind {
            ActorKind::Consumer => 0,
            ActorKind::Provider => 1,
            ActorKind::Root => return Err(1),
        };
        if self.actors[slot].is_some() {
            return Err(2);
        }
        let storage = self.slots[slot].take().ok_or(2u64)?;
        let cap = match self
            .registry
            .create_process(self.a, self.s, caller, job, image)
        {
            Ok(cap) => cap,
            Err(_) => {
                self.slots[slot] = Some(storage);
                return Err(1);
            }
        };
        let meta = self.registry.metadata(self.a, caller, cap).unwrap();
        let process_object = self
            .a
            .authorize(caller, cap, Kind::Process, Rights::CONTROL)
            .unwrap()
            .identity();
        self.rpc
            .register_thread(
                self.a,
                self.s,
                meta.thread,
                meta.job,
                meta.domain,
                Some(self.token),
            )
            .unwrap();
        self.actors[slot] = Some(Actor {
            meta,
            object: process_object,
            image: which,
            kind,
            image_sha256: self.assets.images[which].sha,
            vacant: Some(storage),
            running: None,
            returned: None,
            context: UserContext::ZERO,
            fx: FxState::CLEAN,
            admitted: false,
            retired: false,
            registered: true,
        });
        self.facts.actors += 1;
        Ok(cap)
    }
    pub(super) fn start(
        &mut self,
        caller: SpaceId,
        cap: Handle,
        frames: &mut BootstrapFrames,
    ) -> Result<(), u64> {
        let index = self.find_control(caller, cap)?;
        let actor = self.actors[index - 1].as_mut().unwrap();
        if actor.admitted || actor.retired {
            return Err(1);
        }
        let startup = self
            .registry
            .startup(self.a, caller, cap, EPOCH)
            .map_err(|_| 1u64)?;
        let plan = self.registry.plan(self.a, caller, cap).map_err(|_| 1u64)?;
        let storage = actor.vacant.take().ok_or(1u64)?;
        // SAFETY: held actual process, retained measured immutable plan/startup and
        // sole exclusive private RAM slot; every prior owner retired before reuse.
        let loaded = unsafe {
            LoadedImage::load_startup(
                self.offset,
                self.bits,
                self.original & ADDRESS_MASK,
                &plan,
                Some(&startup),
                frames,
            )
        };
        match loaded {
            Ok(loaded) => *storage = loaded,
            Err(_) => {
                // Loader refusal occurs before RAM allocation; preserve this
                // vacant exclusive storage owner for ordinary held retirement.
                actor.vacant = Some(storage);
                return Err(1);
            }
        }
        let owner = ProcessImage {
            loaded: storage,
            process: actor.meta.process,
            frames: actor.meta.frames,
        };
        match self
            .registry
            .start(self.a, self.s, caller, cap, EPOCH, owner)
        {
            Ok(running) => {
                actor.context = running.initial_context().unwrap();
                actor.context.registers[11] = self.stop.tick();
                actor.fx = FxState::CLEAN;
                actor.running = Some(running);
                actor.admitted = true;
                self.facts.starts += 1;
                self.observe_life(index, LifeKind::Start, None);
                Ok(())
            }
            Err(rejected) => {
                actor.returned = Some(rejected.image);
                Err(1)
            }
        }
    }
    pub(super) fn bind(
        &mut self,
        index: usize,
        endpoint: Handle,
        process: Handle,
    ) -> Result<(), u64> {
        let caller = self.current(index);
        let wire = self
            .wire(
                caller,
                endpoint,
                if process.0 == 0 {
                    RECEIVE
                } else {
                    Rights::CONTROL
                },
            )
            .ok_or(1u64)?;
        let (target, receive, provider) = if process.0 == 0 {
            (
                caller,
                endpoint,
                index != 0 && self.actors[index - 1].as_ref().unwrap().kind == ActorKind::Provider,
            )
        } else {
            if index != 0 {
                return Err(1);
            }
            let target_index = self.find_control(caller.domain, process)?;
            let actor = self.actors[target_index - 1].as_ref().unwrap();
            let wanted = self.wires[wire].as_ref().unwrap().object;
            let receive = self.assets.images[actor.image]
                .roles
                .iter()
                .filter(|r| r.kind == Kind::Endpoint && r.rights.contains(RECEIVE))
                .find_map(|role| {
                    let grant = self
                        .registry
                        .grant(self.a, caller.domain, process, role.selector)
                        .ok()?;
                    self.a
                        .authorize(actor.meta.domain, grant, Kind::Endpoint, RECEIVE)
                        .ok()
                        .filter(|a| a.identity() == wanted)
                        .map(|_| grant)
                })
                .ok_or(1u64)?;
            (actor.meta, receive, actor.kind == ActorKind::Provider)
        };
        let route = self.wires[wire].as_mut().unwrap();
        let changed = route.receiver != target.domain || route.closed;
        route
            .bind(self.a, caller.domain, endpoint, target, receive)
            .map_err(|_| 2u64)?;
        if route.bound != Some(target.thread) {
            self.rpc
                .bind_endpoint(
                    self.a,
                    target.domain,
                    receive,
                    target.thread,
                    Policy::new(8, 0).unwrap(),
                )
                .map_err(|_| 1u64)?;
            route.bound = Some(target.thread);
        }
        if index == 0 && process.0 != 0 && provider && changed {
            self.facts.bindings += 1;
            let binding = Binding {
                owner: self.identity(0),
                endpoint: self.wires[wire].as_ref().unwrap().object as u64,
                target: self.identity(self.index_thread(target.thread).unwrap()),
            };
            (self.observations)(Observation::Binding(binding));
        }
        Ok(())
    }
    pub(super) fn stop_actor(&mut self, index: usize, explicit: bool) -> Result<(), u64> {
        let meta = self.current(index);
        if self
            .pending
            .is_some_and(|p| p.caller == index || p.callee == index)
            || matches!(self.s.state(meta.thread), Ok(State::Running(_)))
        {
            return Err(2);
        }
        for wire in self.wires.iter_mut().flatten() {
            if wire.receiver == meta.domain && wire.mailbox.is_some() {
                wire.close(self.a, crate::timer::now()).unwrap();
            }
        }
        let actor = self.actors[index - 1].as_mut().unwrap();
        if actor.retired {
            return Err(1);
        }
        if let Some(running) = &mut actor.running {
            running.stop(self.a, self.s).map_err(|_| 1u64)?;
        }
        self.s.terminate_process(meta.process).map_err(|_| 1u64)?;
        if actor.registered {
            assert!(
                self.rpc
                    .peer_died(self.s, meta.thread, crate::timer::now())
                    .unwrap()
                    .is_empty()
            );
        }
        if let Some(running) = actor.running.take() {
            actor.returned = Some(
                running
                    .finish(self.s)
                    .unwrap_or_else(|_| panic!("actual stopped provider image")),
            );
            if explicit {
                self.facts.stops += 1;
                self.observe_life(index, LifeKind::Stop, None);
            }
        }
        Ok(())
    }
    /// # Safety
    /// Actual process stopped/CR3 restored, no outstanding call/window/access;
    /// retained physical owner returns before scheduler/authority generations reuse.
    pub(super) unsafe fn reap(
        &mut self,
        index: usize,
        frames: &mut BootstrapFrames,
    ) -> Result<(), u64> {
        let m = self.current(index);
        if self.s.state(m.thread) != Ok(State::Exited)
            || self
                .pending
                .is_some_and(|p| p.caller == index || p.callee == index)
        {
            return Err(2);
        }
        let actor = self.actors[index - 1].as_mut().unwrap();
        if actor.retired {
            return Err(1);
        }
        let owner = actor.returned.take().ok_or(1u64)?;
        // SAFETY: exact Running.finish returned actual private root; no shared/device
        // mapping exists in this ordinary actor, and controller CR3 is active.
        let returned = unsafe { owner.loaded.root.retire_in_place(frames) };
        assert_eq!(returned as u64, m.frames);
        self.s.release_frames(m.job, m.frames).unwrap();
        self.registry
            .retire_stopped(self.a, self.s, m.process)
            .unwrap();
        if actor.registered {
            self.rpc.forget_thread(self.s, m.thread).unwrap();
            actor.registered = false;
        }
        actor.vacant = Some(owner.loaded);
        actor.retired = true;
        self.facts.reaps += 1;
        self.observe_life(index, LifeKind::Reap, None);
        Ok(())
    }
    pub(super) fn collect(&mut self) {
        for index in 0..2 {
            let Some(actor) = self.actors[index].as_ref() else {
                continue;
            };
            if !actor.retired
                || self
                    .registry
                    .forget_retired(self.a, self.s, actor.meta.process)
                    .is_err()
            {
                continue;
            }
            let mut actor = self.actors[index].take().unwrap();
            self.s.reclaim_process(actor.meta.process).unwrap();
            self.slots[index] = actor.vacant.take();
        }
        for job in &mut self.jobs {
            if let Some(actual) = *job
                && self
                    .registry
                    .forget_job(self.a, self.s, self.rpc, actual)
                    .is_ok()
            {
                *job = None;
            }
        }
    }
}
