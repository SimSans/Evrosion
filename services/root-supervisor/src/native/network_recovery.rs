//! Failed-NIC retirement only. Existing actual scoped ports and process
//! controls supply authority. No new actor, Root IOPL, DMA assumption or restart.
use super::*;
use ev_net_driver::{device::recovery, mediated::Mediated};
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Dormant,
    Exclude,
    Scrub,
    Joined,
    Failed,
}
pub(super) struct Recovery {
    phase: Phase,
    cut: u64,
    token: u64,
    owner: Option<recovery::Recovery<Mediated>>,
    stopped: Option<recovery::Stopped<Mediated>>,
}
impl Recovery {
    pub(super) const fn new() -> Self {
        Self {
            phase: Phase::Dormant,
            cut: 0,
            token: 0,
            owner: None,
            stopped: None,
        }
    }
    pub(super) fn arm(&mut self, tick: u64) {
        if self.phase == Phase::Dormant {
            if let Some(cut) = tick.checked_add(8192).filter(|v| *v != u64::MAX) {
                self.cut = cut;
                self.phase = Phase::Exclude;
            } else {
                self.phase = Phase::Failed;
            }
        }
    }
}
impl Root<'_> {
    #[inline(never)]
    pub(super) fn native_network_recovery_tick(&mut self) {
        let result = self.native_network_recovery_step();
        if result.is_err() {
            // Keep exact unknown/partial owner and all old capabilities/images.
            // No automatic accepted-IO retry, renewed cut or fabricated cleanup.
            self.native.as_mut().unwrap().network_recovery.phase = Phase::Failed;
        }
    }
    #[inline(never)]
    fn native_network_recovery_step(&mut self) -> Result<(), ()> {
        let phase = self.native.as_ref().unwrap().network_recovery.phase;
        if !matches!(phase, Phase::Exclude | Phase::Scrub) {
            return Ok(());
        }
        let tick = now();
        let cut = self.native.as_ref().unwrap().network_recovery.cut;
        if tick >= cut {
            return Err(());
        }
        let driver = self.actors[Child::NetDriver.index()].ok_or(())?.control;
        let service = self.actors[Child::NetService.index()].ok_or(())?.control;
        let child_cut = tick.checked_add(512).ok_or(())?.min(cut);
        if phase == Phase::Exclude {
            for control in [service, driver] {
                let r = rt::call4(syscall::STOP_PROCESS, control, 0, 0, 0);
                if r.value != 0 || r.capability != 0 || r.serial != 0 {
                    return Err(());
                }
                if r.status == 2 {
                    return Ok(()); // actual accepted nested work still owns credit
                }
                if r.status != 0 {
                    return Err(());
                }
            }
            let bound = rt::call4(syscall::NETWORK_RETIREMENT, 0, driver, service, cut);
            if bound.status != 0 || bound.value == 0 || bound.capability != 0 || bound.serial != 0 {
                return Err(());
            }
            let ports = Mediated::new(self.bootstrap.handle(Role::NicPorts)).map_err(|_| ())?;
            let n = self.native.as_mut().unwrap();
            n.network_time.stop();
            n.network_random.source_failed();
            n.network_recovery.token = bound.value;
            n.network_recovery.owner = Some(recovery::Recovery::new(ports));
            n.network_recovery
                .owner
                .as_mut()
                .unwrap()
                .begin(cut, child_cut)
                .map_err(|_| ())?;
            n.network_recovery.phase = Phase::Scrub;
            return Ok(());
        }
        let n = self.native.as_mut().unwrap();
        let progress = n
            .network_recovery
            .owner
            .as_mut()
            .ok_or(())?
            .step(child_cut)
            .map_err(|_| ())?;
        if !progress.complete() {
            return Ok(());
        }
        let owner = n.network_recovery.owner.take().ok_or(())?;
        match owner.finish() {
            Ok(stopped) => n.network_recovery.stopped = Some(stopped),
            Err(owner) => {
                n.network_recovery.owner = Some(owner);
                return Err(());
            }
        }
        // The sealed State method consumes the move-only exact physical proof
        // before this private completion adapter issues its packet. Core then
        // rechecks the same pair/token/original cut and real no-work conditions.
        // A failed join leaves State Unavailable and never reports fake Stop.
        let token = n.network_recovery.token;
        let physical = n.network_recovery.stopped.take().ok_or(())?;
        n.network
            .recovered(physical, now(), || {
                let joined = rt::call4(syscall::NETWORK_RETIREMENT, 1, driver, service, token);
                joined.status == 0
                    && joined.value == 0
                    && joined.capability == 0
                    && joined.serial == 0
            })
            .map_err(|_| ())?;
        n.network_recovery.phase = Phase::Joined;
        // Same physical + CPU shutdown semantics; the separate Core records
        // and retained original fault distinguish this recovery from nominal.
        self.native_network_report(ev_root_supervisor::native_network::transfer::Progress {
            stage: 7,
            result: 0,
            argument: 2,
        });
        Ok(())
    }
}
