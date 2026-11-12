//! Explicit metadata maintenance after actual stopped owners return their claims.
use super::*;
impl Runtime<'_, '_> {
    pub(super) fn collect_channels(&mut self) {
        // Only the per-incarnation selected inbox is replaced. Ordinary logical
        // routes remain retained and preserve tickets across provider restarts.
        let index = Channel::GrantInbox.index();
        let Some(wire) = self.wires[index].as_mut() else {
            return;
        };
        if !wire.closed || wire.pending() != 0 || self.receipts[0].is_some() {
            return;
        }
        let Some(control) = wire.control else {
            return;
        };
        if self
            .a
            .authorize(
                self.root.meta.domain,
                control,
                Kind::Endpoint,
                Rights::CONTROL,
            )
            .is_ok_and(|access| access.identity() == wire.object)
        {
            return;
        }
        let Some(mailbox) = wire.mailbox.take() else {
            return;
        };
        match mailbox.retire_managed(self.a) {
            Ok(receipt) => {
                self.receipts[0] = Some(receipt);
                self.wires[index] = None;
            }
            Err(rejected) => self.wires[index].as_mut().unwrap().mailbox = Some(rejected.mailbox),
        }
    }
    pub(super) fn collect_jobs(&mut self) {
        for job in &mut self.jobs {
            if let Some(actual) = *job {
                let used = self.s.usage(actual, Resource::CpuTicks).unwrap();
                if self
                    .registry
                    .forget_job(self.a, self.s, self.rpc, actual)
                    .is_ok()
                {
                    self.facts.retired_cpu += used;
                    *job = None;
                }
            }
        }
    }
    /// # Safety
    /// Controller CR3/IF0 restored, no outstanding protected execution. Devices
    /// remain exclusively assigned, no DMA was enabled and actors will not run.
    pub(super) unsafe fn shutdown(&mut self, frames: &mut BootstrapFrames) {
        assert_eq!(self.rpc.outstanding(), 0);
        assert!(self.pending.iter().all(Option::is_none));
        // Input/Block/File/Display are alive until the observed scenario ends;
        // stopping one never masquerades as preserving it across App/Shell restart.
        for index in 1..=6 {
            if let Some(actor) = self.actors[index - 1].as_ref() {
                if actor.retired {
                    continue;
                }
                self.stop_actor(index).unwrap();
            }
        }
        for index in 1..=6 {
            if let Some(actor) = self.actors[index - 1].as_ref() {
                if actor.retired {
                    continue;
                }
                // SAFETY: all actual threads terminated, all calls settled;
                // exclusive image/map owners are returned by Running.finish.
                unsafe { self.reap_actor(index, frames) }.unwrap();
            }
        }
        let active = self.root.active.as_mut().unwrap();
        active.revoke(self.a, self.s, self.token).unwrap();
        self.s.terminate_process(self.root.meta.process).unwrap();
        assert!(
            self.rpc
                .peer_died(self.s, self.root.meta.thread, crate::timer::now())
                .unwrap()
                .is_empty()
        );
        // Root's public cap closure follows revocation; owned cleanup never
        // attempts to reauthorize those now-revoked process/control handles.
        self.a.close_space(self.root.meta.domain).unwrap();
        self.a.close_space(self.root_branches).unwrap();
        for wire in self.wires.iter_mut().flatten() {
            if wire.mailbox.is_some() {
                wire.close(self.a, crate::timer::now()).unwrap();
            }
        }
        self.collect_closed();
        self.collect_channels();
        self.collect_jobs();
        assert!(self.actors.iter().all(Option::is_none));
        assert!(self.jobs.iter().all(Option::is_none));
        for index in 0..16 {
            let Some(mut wire) = self.wires[index].take() else {
                continue;
            };
            let mut mailbox = wire.mailbox.take().unwrap();
            if index == 15 {
                // External boot event escrow has no managed-object retirement
                // privilege. Retain its owner until into_empty_escrow below.
                mailbox.retire_empty(self.a).unwrap();
            } else {
                let _receipt = mailbox
                    .retire_managed(self.a)
                    .unwrap_or_else(|r| panic!("managed desktop queue: {:?}", r.error));
            }
        }
        self.rpc
            .forget_thread(self.s, self.root.meta.thread)
            .unwrap();
        let active = self.root.active.take().unwrap();
        let (_binding, owner) = active
            .finish(self.s, self.token)
            .unwrap_or_else(|_| panic!("Root owned finish"));
        let returned = match owner {
            #[cfg(not(feature = "test-m5-native"))]
            RootImage::Desktop(owner) => {
                let loaded = owner.loaded;
                for (which, aux) in [(Scalar::System, false), (Scalar::Catalogue, true)] {
                    // SAFETY: actual Root terminated and its exclusive image returned;
                    // all outgoing operations settled, exact scalar owners retained.
                    // SAFETY: exact returned Root image and retained scalar owners;
                    // actual termination/CR3 restoration happened before this loop.
                    unsafe {
                        if aux {
                            loaded
                                .root
                                .unmap_catalogue_inactive(self.backing.scalar_mut(which))
                        } else {
                            loaded
                                .root
                                .unmap_shared_inactive(self.backing.scalar_mut(which))
                        }
                    }
                    .unwrap();
                }
                // SAFETY: no external mapping or CPU reference remains in Root's root.
                unsafe { loaded.root.retire_in_place(frames) }
            }
            #[cfg(feature = "test-m5-native")]
            RootImage::Native(owner) => {
                let image = owner.into_image();
                let loaded = image.loaded_inactive(self.s).unwrap();
                for (which, aux) in [(Scalar::System, false), (Scalar::Catalogue, true)] {
                    // SAFETY: exact stopped Root, actual scalar owner and restored CR3.
                    unsafe {
                        if aux {
                            loaded
                                .root
                                .unmap_catalogue_inactive(self.backing.scalar_mut(which))
                        } else {
                            loaded
                                .root
                                .unmap_shared_inactive(self.backing.scalar_mut(which))
                        }
                    }
                    .unwrap();
                }
                let native = self.native.as_mut().expect("native outer image backing");
                for index in 0..2 {
                    // SAFETY: Active.finish returned this actual stopped owner;
                    // public grants may be revoked, exact physical leases persist.
                    let lease =
                        unsafe { image.detach_bank(index, self.s, native.backing.bank(index)) }
                            .unwrap();
                    native.backing.bank_mut(index).return_lease(lease).unwrap();
                    native.bank_detaches += 1;
                }
                // SAFETY: both bank/scalar claims returned before private scrub/free.
                unsafe { image.retire_private(self.s, frames) }.unwrap()
            }
        };
        assert_eq!(returned as u64, self.root.meta.frames);
        self.s
            .release_frames(self.root.meta.job, self.root.meta.frames)
            .unwrap();
        self.s.reclaim_process(self.root.meta.process).unwrap();
        let root_cpu = self
            .s
            .usage(self.root.meta.job, Resource::CpuTicks)
            .unwrap();
        assert_eq!(
            self.s.usage(self.boot, Resource::CpuTicks).unwrap(),
            root_cpu + self.facts.retired_cpu
        );
        self.s.reclaim_job(self.root.meta.job).unwrap();
    }
}
