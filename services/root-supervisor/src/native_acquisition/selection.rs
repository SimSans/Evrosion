//! Reconcile local Registry selection before replacing a sole candidate. The
//! same actual Store/loan and the existing Decision/Commit protocol are used.
use super::*;
use crate::native_plan::{
    state::{RegistrySelection, State},
    storage::content::OwnedBackend,
};
use ev_block_service::store_io::{Window, Wire};
use ev_content_store::TransferCut;
type CommitResult<T, W> = Result<Commit<OwnedBackend<T, W>>, Rejected<OwnedBackend<T, W>>>;

/// A local decision retains its exact Registry/loan receipt through consumption.
/// It cannot be converted into a generic remote Decision for another backend.
#[must_use = "persist through the same actual State loan or discard the decision"]
pub struct SelectionDecision {
    binding: AuthorizationBinding,
    selected: RegistrySelection,
}
impl SelectionDecision {
    #[allow(clippy::result_large_err)]
    // Rejection preserves the actual owner.
    // Fold this affine forwarding frame into its caller. The canonical
    // record/Cold handoff remains out of line; no duplicate large Store result.
    #[inline(always)]
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

    /// Borrow the current owner while preparing syntax-only metadata. Its
    /// construction scratch does not overlap the later affine commit handoff.
    #[inline(never)]
    fn record<T: Wire, W: Window>(
        &self,
        store: &Store<OwnedBackend<T, W>>,
        state: &State<T, W>,
    ) -> Result<codec::Record, Fault> {
        let result = if store.authorization_binding() != Some(self.binding) {
            Err(Fault::Phase)
        } else {
            selected_content(store, state, &self.selected)
        };
        let content = result?;
        let current = &store.state.as_ref().unwrap().record;
        let Some(revision) = current.revision.checked_add(1).filter(|n| *n != u64::MAX) else {
            return Err(Fault::Capacity);
        };
        let next = codec::Record {
            revision,
            replay: current.replay,
            roots: current.roots,
            metadata: current.metadata,
            candidate: current.candidate,
            active: Some(content),
            known_good: current.known_good,
            authorizations: [
                current.authorizations[0],
                current.authorization(content),
                current.authorizations[2],
            ],
        };
        next.validate()?;
        Ok(next)
    }
    #[allow(clippy::result_large_err)] // Same canonical affine Commit.
    pub fn begin<T: Wire, W: Window>(
        self,
        store: Store<OwnedBackend<T, W>>,
        state: &State<T, W>,
        transfer: TransferCut,
        now: u64,
    ) -> CommitResult<T, W> {
        let mut workspace = Commit::empty();
        self.begin_into(store, state, &mut workspace, transfer, now)?;
        Ok(workspace)
    }
}

impl<T: Wire, W: Window> Store<OwnedBackend<T, W>> {
    /// Local retention of previously authenticated selected content. No fresh
    /// remote decision, UTC/floor advance, lifecycle health or KnownGood claim.
    /// A successful no-op still checks the exact owner, loan and current state.
    pub fn reconcile_selection(
        &self,
        state: &State<T, W>,
        selected: RegistrySelection,
    ) -> Result<Option<SelectionDecision>, Fault> {
        let content = selected_content(self, state, &selected)?;
        let current = self.state.as_ref().ok_or(Fault::Unprovisioned)?;
        if current.record.active == Some(content) {
            return Ok(None);
        }
        current
            .record
            .revision
            .checked_add(1)
            .filter(|n| *n != u64::MAX)
            .ok_or(Fault::Capacity)?;
        Ok(Some(SelectionDecision {
            binding: self.authorization_binding().ok_or(Fault::Unprovisioned)?,
            selected,
        }))
    }
}

fn selected_content<T: Wire, W: Window>(
    store: &Store<OwnedBackend<T, W>>,
    state: &State<T, W>,
    selected: &RegistrySelection,
) -> Result<Content, Fault> {
    if store.has_unresolved_io()
        || !state.matches_registry_selection(selected)
        || store.arena.backend().selection_owner() != Some(selected.owner())
    {
        return Err(Fault::Phase);
    }
    let current = store.state.as_ref().ok_or(Fault::Unprovisioned)?;
    [
        current.record.candidate,
        current.record.active,
        current.record.known_good,
    ]
    .into_iter()
    .flatten()
    .find(|c| c.package == selected.package() && c.version == selected.version())
    .ok_or(Fault::Candidate)
}
