//! Actual admitted service image owners, retained through stopped detachment.
use super::*;
use crate::{display_runtime::OwnedDisplayTables, graphics_image::DesktopMappings};

pub(super) struct Actor<'a> {
    pub child: Child,
    pub meta: Metadata,
    pub object: usize,
    #[cfg(feature = "test-m5-native")]
    pub image_object: usize,
    #[cfg(feature = "test-m5-native")]
    pub image_sha256: [u8; 32],
    pub vacant: Option<&'a mut GraphicsImage>,
    pub running: Option<Running<GraphicsProcessImage<'a>>>,
    pub returned: Option<GraphicsProcessImage<'a>>,
    pub context: UserContext,
    pub fx: FxState,
    pub registered: bool,
    pub admitted: bool,
    pub retired: bool,
    pub fault: Option<Record>,
}
impl<'a> Actor<'a> {
    pub fn held(child: Child, meta: Metadata, object: usize, slot: &'a mut GraphicsImage) -> Self {
        Self {
            child,
            meta,
            object,
            #[cfg(feature = "test-m5-native")]
            image_object: 0,
            #[cfg(feature = "test-m5-native")]
            image_sha256: [0; 32],
            vacant: Some(slot),
            running: None,
            returned: None,
            context: UserContext::ZERO,
            fx: FxState::CLEAN,
            registered: false,
            admitted: false,
            retired: false,
            fault: None,
        }
    }
    pub fn image(&self) -> Option<&GraphicsImage> {
        self.running
            .as_ref()
            .map(|r| r.image().image())
            .or_else(|| self.returned.as_ref().map(GraphicsProcessImage::image))
    }
}
impl<'image> Runtime<'image, '_> {
    pub(super) fn find_control(&self, caller: SpaceId, cap: Handle) -> Result<usize, u64> {
        let meta = self
            .registry
            .metadata(self.a, caller, cap)
            .map_err(|_| 1u64)?;
        let object = self
            .a
            .authorize(caller, cap, Kind::Process, Rights::CONTROL)
            .map_err(|_| 1u64)?
            .identity();
        self.actors
            .iter()
            .position(|x| {
                x.as_ref()
                    .is_some_and(|x| x.meta == meta && x.object == object)
            })
            .map(|x| x + 1)
            .ok_or(1)
    }
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
        let child = CHILDREN
            .into_iter()
            .find(|c| self.source_identity(c.index(), Kind::Memory) == object);
        #[cfg(feature = "test-m5-native")]
        let child = child.or_else(|| {
            self.native
                .as_ref()
                .filter(|state| state.image_objects[1] == object)
                .map(|_| Child::App)
        });
        #[cfg(feature = "test-m5-native")]
        let child = child.or_else(|| {
            self.native
                .as_ref()
                .filter(|n| n.bad_shell_object == object)
                .map(|_| Child::Shell)
        });
        let child = child.ok_or(1u64)?;
        let index = child.index();
        if self.actors[index].is_some() {
            return Err(2);
        }
        let slot = self.slots[index].take().ok_or(2u64)?;
        let cap = match self
            .registry
            .create_process(self.a, self.s, caller, job, image)
        {
            Ok(cap) => cap,
            Err(_) => {
                self.slots[index] = Some(slot);
                return Err(1);
            }
        };
        let meta = self.registry.metadata(self.a, caller, cap).unwrap();
        let object = self
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
        let mut actor = Actor::held(child, meta, object, slot);
        #[cfg(feature = "test-m5-native")]
        {
            actor.image_object = self
                .a
                .authorize(caller, image, Kind::Memory, Rights::READ)
                .unwrap()
                .identity();
            actor.image_sha256 = self.image_shas[index];
            if let Some(native) = &self.native
                && native.image_objects[1] == actor.image_object
            {
                actor.image_sha256 = native.image_shas[1];
            }
            if let Some(native) = &self.native
                && native.bad_shell_object == actor.image_object
            {
                actor.image_sha256 = native.bad_shell_sha;
            }
        }
        actor.registered = true;
        self.actors[index] = Some(actor);
        #[cfg(feature = "test-m5-native")]
        if let Some(native) = &mut self.native {
            native.last_syscall[index + 1] = None;
        }
        self.facts.created += 1;
        Ok(cap)
    }
    /// # Safety
    /// Actual held target, exclusive image slot and allocator, controller IF0.
    pub(super) unsafe fn start(
        &mut self,
        caller: SpaceId,
        cap: Handle,
        frames: &mut BootstrapFrames,
    ) -> Result<(), u64> {
        let index = self.find_control(caller, cap)? - 1;
        if self.actors[index].as_ref().unwrap().admitted {
            return Err(1);
        }
        let child = self.actors[index].as_ref().unwrap().child;
        if matches!(child, Child::App | Child::Shell) {
            if self
                .pending
                .iter()
                .flatten()
                .any(|p| p.caller == index + 1 || p.callee == index + 1)
            {
                return Err(2);
            }
            // SAFETY: no prior writer exists in this reusable slot; previous
            // stopped owner returned every claim before collection. No Present
            // or File RPC retains read/write credit; Display keeps only RO maps.
            unsafe {
                if child == Child::App {
                    self.backing.scrub_app(self.a)
                } else {
                    self.backing.scrub_shell(self.a)
                }
            };
        }
        let plan = self.registry.plan(self.a, caller, cap).map_err(|_| 1u64)?;
        let record = self
            .registry
            .startup(self.a, caller, cap, EPOCH)
            .map_err(|_| 1u64)?;
        let meta = self.actors[index].as_ref().unwrap().meta;
        let slot = self.actors[index]
            .as_mut()
            .unwrap()
            .vacant
            .take()
            .ok_or(2u64)?;
        // SAFETY: measured plan and immutable startup belong to this exact held
        // metadata; the caller retains all partial image/mapping owners.
        if let Err(error) = unsafe {
            slot.load_private(
                &plan,
                meta,
                &record,
                self.hw.offset,
                self.hw.bits,
                self.hw.original & ADDRESS_MASK,
                frames,
            )
        } {
            self.actors[index].as_mut().unwrap().vacant = Some(slot);
            panic!("desktop private load {index}: {error:?}");
        }
        let child = CHILDREN[index];
        let grant = |selector| self.registry.grant(self.a, caller, cap, selector).unwrap();
        match child {
            Child::Shell | Child::App | Child::Display => {
                let extent = if child == Child::Shell {
                    &mut self.backing.shell
                } else {
                    &mut self.backing.app
                };
                let lease = extent
                    .map(self.a, meta.domain, grant(1), child != Child::Display)
                    .unwrap();
                slot.retain_surface(lease)
                    .unwrap_or_else(|_| panic!("retained surface slot"));
                // SAFETY: held exact root; real initialized parent-owned extent.
                unsafe { slot.install_surface(self.a, extent) }.unwrap();
                self.facts.mapped += 1;
                if child == Child::Display {
                    let lease = self
                        .backing
                        .shell
                        .map(self.a, meta.domain, grant(3), false)
                        .unwrap();
                    slot.retain_auxiliary_surface(lease)
                        .unwrap_or_else(|_| panic!("aux surface slot"));
                    // SAFETY: same held root, distinct fixed304..366 reservation.
                    unsafe { slot.install_auxiliary_surface(self.a, &self.backing.shell, &plan) }
                        .unwrap();
                    let lease = self
                        .backing
                        .device
                        .map(self.a, meta.domain, grant(7))
                        .unwrap();
                    let geometry = self
                        .backing
                        .device
                        .backing_for(self.a, &lease)
                        .unwrap()
                        .plan()
                        .geometry();
                    assert_eq!((geometry.width(), geometry.height()), self.dimensions);
                    slot.retain_display(OwnedDisplayTables::uninstalled(lease))
                        .unwrap_or_else(|_| panic!("retained device owner"));
                    // SAFETY: actual trusted non-RAM aperture and measured two-PT budget.
                    unsafe {
                        slot.install_display(
                            &self.backing.device,
                            self.a,
                            &plan,
                            self.s,
                            frames,
                            self.hw.offset,
                        )
                    }
                    .unwrap();
                    self.facts.mapped += 2;
                }
            }
            _ => {}
        }
        let scalars: &[(u64, Scalar, bool)] = match child {
            Child::Block => &[(2, Scalar::System, false), (4, Scalar::File, true)],
            Child::File => &[(1, Scalar::File, false), (3, Scalar::Application, true)],
            Child::App => &[(5, Scalar::Application, false)],
            _ => &[],
        };
        for &(selector, which, auxiliary) in scalars {
            let object = self.backing.scalar_mut(which);
            let lease = object
                .map(self.a, meta.domain, grant(selector), true)
                .unwrap();
            // SAFETY: exact held image and immutable fixed page/object binding;
            // failure returns the original move-only lease to its owner.
            unsafe { slot.install_scalar(self.a, object, lease, auxiliary) }.unwrap_or_else(
                |rejected| {
                    panic!(
                        "desktop scalar map: {:?} retained={:#x}",
                        rejected.error,
                        rejected.lease.physical()
                    )
                },
            );
            self.facts.mapped += 1;
        }
        let requirements = match child {
            Child::Input => DesktopMappings::PrivateOnly,
            Child::Block | Child::File => DesktopMappings::DualBuffers,
            Child::App => DesktopMappings::SurfaceBuffer,
            Child::Shell => DesktopMappings::SurfaceOnly,
            Child::Display => DesktopMappings::Compositor,
        };
        let owner = slot.lease_desktop(requirements).unwrap();
        match self
            .registry
            .start(self.a, self.s, caller, cap, EPOCH, owner)
        {
            Ok(running) => {
                let actor = self.actors[index].as_mut().unwrap();
                actor.context = running.initial_context().unwrap();
                actor.context.registers[11] = self.stop.tick();
                actor.fx = FxState::CLEAN;
                actor.running = Some(running);
                actor.admitted = true;
                self.facts.starts += 1;
                #[cfg(feature = "test-m5-native")]
                self.native_action(index + 1, NativeActionKind::Start);
                if child == Child::App {
                    self.configure_grants(cap);
                }
                self.on_admitted(index + 1);
                Ok(())
            }
            Err(rejected) => {
                self.actors[index].as_mut().unwrap().returned = Some(rejected.image);
                Err(1)
            }
        }
    }
    pub(super) fn stop_actor(&mut self, index: usize) -> Result<(), u64> {
        let meta = self.metadata(index).ok_or(1u64)?;
        // Shared-window/surface credit is returned only after genuine callee
        // completion. Cancelling a caller's wait would not establish that fact.
        if self
            .pending
            .iter()
            .flatten()
            .any(|p| p.caller == index || p.callee == index)
        {
            return Err(2);
        }
        if matches!(self.s.state(meta.thread), Ok(State::Running(_))) {
            return Err(2);
        }
        for wire in self.wires.iter_mut().flatten() {
            if wire.receiver == meta.domain && wire.mailbox.is_some() {
                wire.close(self.a, crate::timer::now()).unwrap();
            }
        }
        if index == Child::Shell.index() + 1 {
            self.picker = None;
            self.barrier = None;
            self.selection = None;
            self.open = None;
            self.awaiting_open = None;
        }
        let actor = self.actors[index - 1].as_mut().unwrap();
        if let Some(running) = &mut actor.running {
            running.stop(self.a, self.s).map_err(|_| 1u64)?;
        }
        self.s.terminate_process(meta.process).map_err(|_| 1u64)?;
        if index == Child::App.index() + 1 {
            self.stop_grants();
            #[cfg(feature = "test-m5-native")]
            if let Some(native) = &mut self.native {
                native.readonly_denial = None;
            }
        }
        let actor = self.actors[index - 1].as_mut().unwrap();
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
                    .unwrap_or_else(|_| panic!("stopped desktop owner")),
            );
            self.facts.stops += 1;
            #[cfg(feature = "test-m5-native")]
            self.native_action(index, NativeActionKind::Stop);
        }
        Ok(())
    }
    /// # Safety
    /// Actual stop/finish, no accepted calls/CPU/device access to this root.
    pub(super) unsafe fn reap_actor(
        &mut self,
        index: usize,
        frames: &mut BootstrapFrames,
    ) -> Result<(), u64> {
        let meta = self.metadata(index).ok_or(1u64)?;
        if self.s.state(meta.thread) != Ok(State::Exited)
            || self
                .pending
                .iter()
                .flatten()
                .any(|p| p.caller == index || p.callee == index)
        {
            return Err(2);
        }
        let actor = self.actors[index - 1].as_mut().unwrap();
        if actor.retired {
            return Err(1);
        }
        let slot = if let Some(owner) = actor.returned.take() {
            owner.into_image()
        } else {
            actor.vacant.take().ok_or(1u64)?
        };
        if actor.admitted {
            match actor.child {
                Child::Shell | Child::App | Child::Display => {
                    let extent = if actor.child == Child::Shell {
                        &mut self.backing.shell
                    } else {
                        &mut self.backing.app
                    };
                    // SAFETY: exact stopped image and unchanged retained mapping receipt.
                    let lease = unsafe { slot.detach_surface(self.s, extent) }.unwrap();
                    extent.unmap(lease).unwrap();
                    if actor.child == Child::Display {
                        // SAFETY: same stopped root; distinct auxiliary mapping.
                        let lease =
                            unsafe { slot.detach_auxiliary_surface(self.s, &self.backing.shell) }
                                .unwrap();
                        self.backing.shell.unmap(lease).unwrap();
                        // SAFETY: no CPU can execute this root; private tables remain owned.
                        unsafe { slot.detach_display(self.s) }.unwrap();
                        // SAFETY: detached real two-table owner, not device frames.
                        let retired = unsafe { slot.retire_display_tables(frames) }.unwrap();
                        assert_eq!(retired.returned, 2);
                        self.backing.device.unmap(retired.lease).unwrap_or_else(
                            |(error, _lease)| panic!("device claim return: {error:?}"),
                        );
                    }
                }
                _ => {}
            }
            let scalars: &[(Scalar, bool)] = match actor.child {
                Child::Block => &[(Scalar::System, false), (Scalar::File, true)],
                Child::File => &[(Scalar::File, false), (Scalar::Application, true)],
                Child::App => &[(Scalar::Application, false)],
                _ => &[],
            };
            for &(which, aux) in scalars {
                // SAFETY: returned exclusive stopped image; actual matching scalar owner.
                unsafe { slot.detach_scalar(self.s, self.backing.scalar_mut(which), aux) }.unwrap();
            }
            // SAFETY: all external mapping/device claims were returned above.
            let returned = unsafe { slot.retire_private(self.s, frames) }.unwrap();
            let tables = if actor.child == Child::Display { 2 } else { 0 };
            assert_eq!(returned + tables, meta.frames);
        }
        self.s.release_frames(meta.job, meta.frames).unwrap();
        self.registry
            .retire_stopped(self.a, self.s, meta.process)
            .unwrap();
        if actor.registered {
            self.rpc.forget_thread(self.s, meta.thread).unwrap();
            actor.registered = false;
        }
        actor.retired = true;
        actor.vacant = Some(slot);
        self.facts.reaps += 1;
        #[cfg(feature = "test-m5-native")]
        self.native_action(index, NativeActionKind::Reap);
        Ok(())
    }
    pub(super) fn collect_closed(&mut self) {
        for index in 0..6 {
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
    }
}

#[cfg(feature = "test-m5-native")]
impl Runtime<'_, '_> {
    fn native_action(&mut self, index: usize, kind: NativeActionKind) {
        let Some(native) = &mut self.native else {
            return;
        };
        let actor = self.actors[index - 1].as_ref().unwrap();
        if matches!(kind, NativeActionKind::Start) {
            native.started_mappings += match actor.child {
                Child::App => 2,
                Child::Shell => 1,
                Child::Display => 3,
                Child::Block | Child::File => 2,
                Child::Input => 0,
            };
        }
        if actor.child == Child::Shell && matches!(kind, NativeActionKind::Start) {
            native.shell_starts += 1;
        }
        if actor.child != Child::App {
            return;
        }
        let slot = native
            .app(actor.image_object)
            .expect("actual registered App image identity");
        match kind {
            NativeActionKind::Start => native.app_starts[slot] += 1,
            NativeActionKind::Stop => native.app_stops[slot] += 1,
            NativeActionKind::Reap => native.app_reaps[slot] += 1,
        }
        native.last_process[slot] = actor.meta.process.diagnostic_id();
        native.last_thread[slot] = actor.meta.thread.diagnostic_id();
        (self.observations)(Observation::NativeAction(NativeAction {
            kind,
            image_sha256: actor.image_sha256,
            process: native.last_process[slot],
            thread: native.last_thread[slot],
        }));
    }
}
