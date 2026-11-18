//! Local prior System health completion through the same canonical Commit.
use super::*;
use crate::{
    downloaded_health::HealthReceipt,
    native_plan::{state::State, storage::content::OwnedBackend},
};
use ev_block_service::store_io::{Window, Wire};
use ev_content_store::TransferCut;
/// Small move-only receipt, no second Snapshot or Backend.
pub struct KnownGoodDecision {
    binding: AuthorizationBinding,
    health: HealthReceipt,
}
impl KnownGoodDecision {
    #[allow(clippy::result_large_err)]
    pub fn begin_into<T: Wire, W: Window>(
        self,
        store: Store<OwnedBackend<T, W>>,
        state: &State<T, W>,
        workspace: &mut Commit<OwnedBackend<T, W>>,
        transfer: TransferCut,
        now: u64,
    ) -> Result<(), Rejected<OwnedBackend<T, W>>> {
        let next = match self.record(&store, state) {
            Ok(next) => next,
            Err(error) => {
                return Err(Rejected {
                    owner: store,
                    error: Failure::Policy(error),
                });
            }
        };
        store.begin_record_into(next, workspace, transfer, now)
    }

    /// Record construction borrows the same Store; its scratch ends before the
    /// affine owner is handed to the canonical commit/cold-authentication path.
    #[inline(never)]
    fn record<T: Wire, W: Window>(
        &self,
        store: &Store<OwnedBackend<T, W>>,
        state: &State<T, W>,
    ) -> Result<codec::Record, Fault> {
        let content = match checked(store, state, &self.health) {
            Ok(c) if store.authorization_binding() == Some(self.binding) => c,
            _ => return Err(Fault::Phase),
        };
        let current = &store.state.as_ref().unwrap().record;
        let Some(revision) = current.revision.checked_add(1).filter(|v| *v != u64::MAX) else {
            return Err(Fault::Capacity);
        };
        let next = codec::Record {
            revision,
            replay: current.replay,
            roots: current.roots,
            metadata: current.metadata,
            candidate: current.candidate,
            active: current.active,
            known_good: Some(content),
            authorizations: [
                current.authorizations[0],
                current.authorizations[1],
                current.authorization(content),
            ],
        };
        next.validate()?;
        Ok(next)
    }
}
impl<T: Wire, W: Window> Store<OwnedBackend<T, W>> {
    pub fn reconcile_known_good(
        &self,
        state: &State<T, W>,
        health: HealthReceipt,
    ) -> Result<Option<KnownGoodDecision>, Fault> {
        let content = checked(self, state, &health)?;
        if self.state.as_ref().unwrap().record.known_good == Some(content) {
            return Ok(None);
        }
        Ok(Some(KnownGoodDecision {
            binding: self.authorization_binding().ok_or(Fault::Unprovisioned)?,
            health,
        }))
    }
}
fn checked<T: Wire, W: Window>(
    store: &Store<OwnedBackend<T, W>>,
    state: &State<T, W>,
    health: &HealthReceipt,
) -> Result<Content, Fault> {
    if store.has_unresolved_io()
        || !state.matches_downloaded_health(health)
        || store.arena.backend().selection_owner() != Some(health.selected.owner())
        || health.cohort == [0; 32]
        || health.generation != health.selected.version()
    {
        return Err(Fault::Phase);
    }
    let current = store.state.as_ref().ok_or(Fault::Unprovisioned)?;
    let content = current.record.active.ok_or(Fault::Candidate)?;
    if content.package != health.selected.package() || content.version != health.generation {
        return Err(Fault::Candidate);
    }
    Ok(content)
}
