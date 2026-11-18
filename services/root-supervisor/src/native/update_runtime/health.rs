//! Local health/evidence uses the same resident affine Store/Commit owners.
use super::*;
impl<T: ev_block_service::store_io::Wire, W: ev_block_service::store_io::Window>
    Update<content::OwnedBackend<T, W>>
{
    #[inline(never)]
    pub fn begin_known_good(
        &mut self,
        receipt: crate::downloaded_health::HealthReceipt,
        state: &crate::native_plan::state::State<T, W>,
        now: u64,
    ) -> Result<bool, Failure> {
        if !self.observe(now) {
            return Err(Failure::Clock);
        }
        let decision = self
            .authorization_store()
            .ok_or(Failure::Authentication)?
            .reconcile_known_good(state, receipt)
            .map_err(|_| Failure::Authentication)?;
        let Some(decision) = decision else {
            return Ok(false);
        };
        if !self.commit.is_empty() {
            return Err(Failure::Authentication);
        }
        let store = self.store();
        match decision.begin_into(store, state, &mut self.commit, self.transfer.unwrap(), now) {
            Ok(()) => {
                self.outcome = None;
                self.phase = Phase::Commit;
                self.stage = Stage::Checkpoint;
                Ok(true)
            }
            Err(r) => {
                self.io = Some(Io::Store(r.owner));
                self.fail(Failure::Authentication);
                Err(Failure::Authentication)
            }
        }
    }
}
impl<B: Backend> Update<B> {
    /// The full immutable Reader has consumed the exact encoded capsule before
    /// its Object reference can enter the separate System CriticalFault journal.
    #[inline(never)]
    pub fn finish_fault_capsule(
        &mut self,
        capsule: &crate::downloaded_health::FaultCapsule,
        now: u64,
    ) -> Result<ev_store::CriticalFaultReport, Failure> {
        if !self.observe(now) {
            return Err(Failure::Clock);
        }
        if self.command != Some(Command::Local) || self.retained_remaining() != Some(0) {
            return Err(Failure::Authentication);
        }
        let read = self.read();
        match read.finish() {
            Ok(stored) => {
                // Only this complete actual Reader supplies the object. Move
                // its same affine Store directly into the existing IO slot.
                let report = capsule.checked_readback(stored.object);
                self.io = Some(Io::Store(stored.store));
                match report {
                    Some(report) => Ok(report),
                    None => {
                        self.fail(Failure::Authentication);
                        Err(Failure::Authentication)
                    }
                }
            }
            Err(r) => {
                self.io = Some(Io::Store(r.owner));
                self.fail(Failure::Storage);
                Err(Failure::Storage)
            }
        }
    }
}
