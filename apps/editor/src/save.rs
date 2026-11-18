//! Descriptive join for the native owner's already-validated File2 completion.
//! This cannot establish sender authority, delivery or actual loan return on
//! its own. The native callsite supplies its held FileClient's current fence
//! and the exact original request cut; model callers prove no guest execution.
use ev_userspace_contract::{
    file_v2::Method,
    workspace::{Deadline, Outcome},
};
use ev_workspace_client::Completion;
use ev_workspace_editor::{AbortReceipt, BeginRefusal, PendingInfo, Phase};

pub use ev_workspace_client::ui::EDITOR_CANCEL_SAVE_ACTION as CANCEL_SAVE_ACTION;

/// Pointer activation remains bound to the last actually accepted fourth
/// button label. Dedicated keyboard intent is cancellation-only in all states.
pub fn is_cancel_action(command: ev_workspace_client::ui::Command, cancel_presented: bool) -> bool {
    matches!(
        command,
        ev_workspace_client::ui::Command::Activate(CANCEL_SAVE_ACTION)
    ) || cancel_presented && command == ev_workspace_client::ui::Command::Activate(4)
}

pub fn settled_begin_refusal(
    pending: PendingInfo,
    completion: Completion,
    client_fenced: bool,
    original_request_cut: Deadline,
) -> Option<BeginRefusal> {
    if client_fenced
        || pending.phase != Phase::Begin
        || pending.transfer != 0
        || pending.staged != 0
        || pending.read_back != 0
        || pending.in_flight.is_some()
        || pending.abort_operation.is_some()
    {
        return None;
    }
    let request = completion.request;
    let proposal = pending.proposal;
    let length = u32::try_from(proposal.length).ok()?;
    if request.operation_id != proposal.operation
        || request.expected_revision != proposal.base_revision
        || request.deadline != original_request_cut
        || request.method
            != (Method::BeginWrite {
                length,
                digest: proposal.digest,
            })
    {
        return None;
    }
    request.encode().ok()?;
    completion.response.encode().ok()?;
    let response = completion.response.matches(request).ok()?;
    match response.outcome {
        Outcome::NoSpace => Some(BeginRefusal::NoSpace),
        Outcome::Conflict => Some(BeginRefusal::Conflict),
        _ => None,
    }
}

/// Native owner supplies the exact current FileClient completion and the same
/// original request cut it passed to issue. A settled refusal does not qualify.
pub fn confirmed_abort(
    pending: PendingInfo,
    completion: Completion,
    client_fenced: bool,
    original_request_cut: Deadline,
) -> Option<AbortReceipt> {
    if client_fenced || pending.phase != Phase::AbortSent || pending.in_flight.is_some() {
        return None;
    }
    let request = completion.request;
    if pending.abort_operation != Some(request.operation_id)
        || request.expected_revision != pending.proposal.base_revision
        || request.deadline != original_request_cut
        || request.method
            != (Method::Abort {
                transfer_id: pending.transfer,
            })
    {
        return None;
    }
    request.encode().ok()?;
    completion.response.encode().ok()?;
    let response = completion.response.matches(request).ok()?;
    if response.outcome != Outcome::Completed {
        return None;
    }
    Some(AbortReceipt {
        operation: request.operation_id,
        transfer: response.transfer_id,
        revision: response.revision,
    })
}
