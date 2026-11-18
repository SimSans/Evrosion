//! Actual File transition adapter. A Released packet correlates cooperation;
//! only actual61 or an exact never-enqueued setup path constructs retirement.
use super::*;
use ev_userspace_contract::workspace::{DatasetId, Entry};
use ev_workspace_client::ui::ReleaseMode;
use ev_workspace_root::{inbox_channel, lease_channel, retirement::ReleaseWait};
use ev_workspace_service::{Rights as FileRights, control};
use ev_workspace_shell::{ActionScope, ActionTarget, Effect, Rights};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Purpose {
    Open,
    SaveAs,
    Revoke,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Facts {
    identity: Identity,
    held_control: u64,
    epoch: u64,
    nonce: u32,
}
enum ReceiptKind {
    Drained,
    NeverDelivered,
}
/// Private, nonclone evidence retained by this actual Root adapter. Packet
/// decoding, App ACKs and timers have no constructor for this type.
struct Receipt {
    facts: Facts,
    held_control: u64,
    _kind: ReceiptKind,
}
pub(super) struct Lease {
    facts: Facts,
    selection: owner::Request,
    dataset: DatasetId,
    receipt: Option<Receipt>,
}
enum Phase {
    Start,
    QueueRelease,
    AwaitRelease,
    Drain,
    Reconcile,
    Install,
    Fenced,
}
pub(super) struct Pending {
    request: owner::Request,
    entry: Entry,
    dataset: DatasetId,
    effect: Effect,
    by: u64,
    old: Option<Facts>,
    wait: Option<ReleaseWait>,
    mode: ReleaseMode,
    phase: Phase,
    cancelled: bool,
    visible: bool,
}
impl Pending {
    pub fn recipient(&self) -> ev_workspace_root::render::Recipient {
        ev_workspace_root::render::Recipient {
            editor: self.request.index as u8,
            process: self.request.identity.process,
            thread: self.request.identity.thread,
            nonce: self.effect.nonce(),
        }
    }
    pub fn view(&self) -> (&'static [u8], Entry, bool) {
        (
            if self.request.purpose == Purpose::Revoke {
                match self.phase {
                    Phase::Start => b"Confirmed exact revoke; no app cooperation or new grant",
                    Phase::Drain => b"Revoking exact Kernel SEND branch; retained calls must drain",
                    Phase::Reconcile => {
                        b"Reconciling exact revoked route; copied private bytes remain"
                    }
                    _ => b"Revoke incomplete; original scope, request and debt remain retained",
                }
            } else if self.cancelled {
                b"Cancel requested; completing old File retirement only"
            } else {
                match self.phase {
                    Phase::Start => b"Preparing approved transition; no new File SEND is installed",
                    Phase::QueueRelease | Phase::AwaitRelease => {
                        b"Waiting for Editor release; ACK alone grants no authority"
                    }
                    Phase::Drain => b"Retiring actual Kernel SEND branches and retained calls",
                    Phase::Reconcile => {
                        b"Reconciling exact retired Workspace route and durable stage"
                    }
                    Phase::Install => {
                        b"Rechecking approved object and installing exact scoped access"
                    }
                    Phase::Fenced => b"File transition fenced; scope and debt remain retained",
                }
            },
            self.entry,
            self.request.writable,
        )
    }
    pub fn dataset(&self) -> [u8; 16] {
        self.dataset.0
    }
    pub fn revoking(&self) -> bool {
        self.request.purpose == Purpose::Revoke
    }
    pub fn modal(&self) -> bool {
        !matches!(self.phase, Phase::Fenced) || self.visible
    }
}
impl Root<'_> {
    pub(super) fn file_transition_modal(&self) -> bool {
        self.grant.as_ref().is_some_and(Pending::modal)
    }
    pub(super) fn file_notice_fenced(&self) -> bool {
        self.grant
            .as_ref()
            .is_some_and(|g| matches!(g.phase, Phase::Fenced))
    }
    /// Only immutable Root-installed metadata can describe a revoke. Current
    /// storage revisions/names may have changed; authority reduction targets
    /// the exact recorded binding rather than choosing a different object.
    pub(super) fn revoke_scope(&self, request: owner::Request) -> Option<ActionScope> {
        if request.purpose != Purpose::Revoke || !matches!(request.index, 1 | 2) {
            return None;
        }
        let lease = self.leases[request.index].as_ref()?;
        let mut expected = lease.selection;
        expected.purpose = Purpose::Revoke;
        expected.revoke = Some(lease.facts);
        if request != expected || request.identity != lease.facts.identity {
            return None;
        }
        let actor = self.actors[app_child(request.index)?.index()]?;
        if actor.identity != lease.facts.identity
            || actor.control != lease.facts.held_control
            || identity(actor.control, actor.identity.registered) != actor.identity
        {
            return None;
        }
        ev_workspace_root::retirement::file_scope(
            lease.dataset,
            request.entry?,
            request.identity,
            request.writable,
        )
    }
    pub(super) fn revoke_dataset(&self, request: owner::Request) -> Option<DatasetId> {
        self.revoke_scope(request)?;
        Some(self.leases[request.index].as_ref()?.dataset)
    }
    pub(super) fn request_revoke(&mut self, index: usize) {
        if self.owner.pending.is_some() {
            return;
        }
        if let Some(grant) = self.grant.as_mut() {
            if matches!(grant.phase, Phase::Fenced) {
                grant.visible = true;
                self.owner.dirty = true;
            }
            return;
        }
        if !matches!(index, 1 | 2) {
            self.status =
                b"Focus Editor1 or Editor2 to inspect its exact recorded File revoke scope";
            self.owner.dirty = true;
            return;
        }
        let Some(lease) = self.leases[index].as_ref() else {
            self.status = b"No installed File scope for the focused Editor; nothing to revoke";
            self.owner.dirty = true;
            return;
        };
        let mut request = lease.selection;
        request.purpose = Purpose::Revoke;
        request.revoke = Some(lease.facts);
        let actor = self.actor(app_child(index).unwrap());
        if actor.failed
            || actor.control != lease.facts.held_control
            || actor.identity != lease.facts.identity
            || self.grant_actor(request).is_none()
            || self.revoke_scope(request).is_none()
        {
            self.status = b"Recorded File owner changed; retained scope cannot be relabeled";
            self.owner.dirty = true;
            return;
        }
        self.cancel_owner();
        self.owner.pending = Some(request);
        self.owner.rearm = true;
        self.owner.dirty = true;
        self.status = b"Revoke exact recorded File access; copied bytes and already accepted effects are not undone";
    }
    pub(super) fn begin_grant(&mut self, request: owner::Request, effect: Effect) {
        if request.purpose != Purpose::Revoke
            && !self.development_file_allowed(request.index, request.writable)
        {
            self.status = b"This actual application did not request the selected File rights";
            self.owner.dirty = true;
            return;
        }
        let Some(entry) = request.entry else {
            return;
        };
        let Some(dataset) = self.selection_dataset(request) else {
            return;
        };
        if self.grant.is_some() {
            return;
        }
        let old = self.leases[request.index].as_ref().map(|l| l.facts);
        if request.purpose == Purpose::Revoke
            && (old.is_none() || self.revoke_scope(request) != Some(effect.scope()))
        {
            return;
        }
        let needs_release = request.purpose != Purpose::Revoke
            && (old.is_some()
                || self.file_may_be_held[request.index]
                || self.paused[request.index].is_some()
                || request.purpose == Purpose::SaveAs);
        let by = deadline(v5::resources::FILE_TRANSACTION_TICKS);
        let mode = if request.purpose == Purpose::SaveAs {
            ReleaseMode::KeepDocument
        } else {
            ReleaseMode::CloseSaved
        };
        let wait = if needs_release {
            self.next_release = self
                .next_release
                .checked_add(1)
                .filter(|n| *n != u32::MAX)
                .unwrap_or_else(|| rt::exit(1663));
            Some(ReleaseWait::new(request.identity, self.next_release, by).unwrap())
        } else {
            None
        };
        self.cancel_owner();
        self.grant = Some(Pending {
            request,
            entry,
            dataset,
            effect,
            by,
            old,
            wait,
            mode,
            phase: Phase::Start,
            cancelled: false,
            visible: true,
        });
        self.status = b"Only the approved exact object, recipient and rights can be installed";
        self.owner.dirty = true;
    }
    pub(super) fn cancel_grant(&mut self) {
        if let Some(grant) = self.grant.as_mut() {
            if matches!(grant.phase, Phase::Fenced) {
                // Hide only the notice. Keep the exact operation, lease,
                // deadline, accepted work and physical-window fence retained.
                grant.visible = false;
                self.status = b"Unresolved File debt retained; Root inspection/navigation available; no new file operation";
                self.owner.dirty = true;
                self.input.cancel();
                return;
            }
            // A release may already be accepted by the mailbox. Finish its
            // retirement, but never install the cancelled destination.
            grant.cancelled = true;
            self.status = if grant.revoking() {
                b"Cancel cannot restore an already revoked branch; exact retirement stays retained"
            } else {
                b"Cancelling future binding; old authority is not automatically restored"
            };
            self.owner.dirty = true;
        }
    }
    pub(super) fn grant_released(&mut self, child: Child, nonce: u32) {
        let actual = self.actor(child).identity;
        let Some(grant) = self.grant.as_mut() else {
            return;
        };
        if app_child(grant.request.index) == Some(child)
            && matches!(grant.phase, Phase::AwaitRelease)
            && grant
                .wait
                .as_mut()
                .is_some_and(|w| w.observe(actual, nonce, now()))
        {
            self.paused[grant.request.index] = Some(grant.mode);
            self.file_may_be_held[grant.request.index] = false;
            self.owner.dirty = true;
        }
    }
    pub(super) fn grant_refused(&mut self, child: Child, reason: u8) {
        if reason == 7
            && self.grant.as_ref().is_some_and(|g| {
                app_child(g.request.index) == Some(child)
                    && g.request.identity == self.actor(child).identity
                    && matches!(g.phase, Phase::AwaitRelease)
            })
        {
            // Refused has no nonce: it can only cancel future authority, never
            // establish cooperation/quiescence or clear the retained lease.
            self.grant = None;
            self.status = b"Editor release refused; old lease/document retained; no new binding";
            self.owner.dirty = true;
        }
    }
    fn grant_actor(&self, request: owner::Request) -> Option<Actor> {
        let actor = self.actors[app_child(request.index)?.index()]?;
        if actor.failed && request.purpose != Purpose::Revoke
            || actor.identity != request.identity
            || identity(actor.control, actor.identity.registered) != actor.identity
        {
            return None;
        }
        let observed = rt::call(s::OBSERVE, actor.control, 0, 0);
        (observed.status == 0
            && observed.capability == 0
            && (observed.value == 0 || request.purpose == Purpose::Revoke && observed.value == 1))
            .then_some(actor)
    }
    fn drain_file(&mut self, index: usize, actor: Actor, facts: Facts) -> Result<bool, ()> {
        if facts.identity != actor.identity || facts.held_control != actor.control {
            return Err(());
        }
        let lease = self.leases[index]
            .as_ref()
            .filter(|l| l.facts == facts)
            .ok_or(())?;
        if lease
            .receipt
            .as_ref()
            .is_some_and(|r| r.facts == facts && r.held_control == actor.control)
        {
            return Ok(true);
        }
        let info = rt::call4(s::MANAGED_SEND_RETIRE_INFO, 0, 0, 0, 0);
        if info.status != 0
            || info.value != s::MANAGED_SEND_RETIRE_V1
            || info.capability != 0
            || info.serial != 0
        {
            return Err(());
        }
        let retired = rt::call4(
            s::MANAGED_SEND_RETIRE,
            actor.control,
            u64::from(facts.nonce),
            0,
            0,
        );
        if retired.status != 0 || retired.capability != 0 || retired.serial != 0 {
            return Err(());
        }
        match retired.value {
            0 => {
                // The exact actual held ProcessCONTROL and old44 nonce answered
                // Drained. This is the sole accepted-branch receipt constructor.
                self.leases[index].as_mut().unwrap().receipt = Some(Receipt {
                    facts,
                    held_control: actor.control,
                    _kind: ReceiptKind::Drained,
                });
                self.lease_rights[index] = 0;
                Ok(true)
            }
            1 => {
                self.lease_rights[index] = 0;
                Ok(false)
            }
            _ => Err(()), // Retained is not permission to reuse a route.
        }
    }
    fn reconcile_file(
        &mut self,
        index: usize,
        actor: Actor,
        facts: Facts,
        by: u64,
    ) -> Result<bool, ()> {
        if facts.identity != actor.identity || facts.held_control != actor.control {
            return Err(());
        }
        let receipt = self.leases[index]
            .as_ref()
            .filter(|l| l.facts == facts)
            .and_then(|l| l.receipt.as_ref())
            .filter(|r| r.facts == facts && r.held_control == actor.control)
            .ok_or(())?;
        let response = self.workspace.control_until(
            self.channel(Channel::RootWorkspaceControl),
            control::Command::ReconcileFile {
                slot: index as u8,
                lease_epoch: receipt.facts.epoch,
                old: control::RetiredOwner {
                    process: facts.identity.process,
                    thread: facts.identity.thread,
                    registered: facts.identity.registered,
                },
                grant_nonce: facts.nonce,
            },
            by,
        )?;
        match response.status {
            control::Status::Applied => {
                self.leases[index] = None;
                self.lease_rights[index] = 0;
                Ok(true)
            }
            control::Status::Busy => Ok(false),
            _ => Err(()),
        }
    }
    /// Checked shutdown only: callers have frozen new Root effects and retain
    /// one original aggregate cut. An actual stopped process, exact installed
    /// facts, Kernel61 Drained and service reconciliation remain independent
    /// obligations. No close/release packet or timer supplies their receipts.
    pub(super) fn shutdown_retire_file(&mut self, index: usize, cut: u64) -> Result<bool, ()> {
        if !matches!(index, 1 | 2)
            || now() >= cut
            || cut == u64::MAX
            || self.grant.is_some()
            || self.owner.pending.is_some()
        {
            return Err(());
        }
        let Some(facts) = self.leases[index].as_ref().map(|lease| lease.facts) else {
            return Ok(true); // no installed route is invented or cleared
        };
        let actor = self.actor(app_child(index).ok_or(())?);
        if facts.identity != actor.identity || facts.held_control != actor.control {
            return Err(());
        }
        let observed = rt::call4(s::OBSERVE, actor.control, 0, 0, 0);
        if observed.status != 0
            || observed.value != 1
            || observed.capability != 0
            || observed.serial != 0
        {
            return Err(());
        }
        if !self.drain_file(index, actor, facts)? {
            return Ok(false);
        }
        self.reconcile_file(index, actor, facts, cut)
    }
    fn install_grant(&mut self, grant: &Pending, actor: Actor) -> Result<(), ()> {
        let request = grant.request;
        if request.purpose == Purpose::Revoke {
            return Err(()); // a reducing effect can never authorize a new Bind
        }
        if !self.development_file_allowed(request.index, request.writable) {
            return Err(());
        }
        let index = request.index;
        let expected = ActionScope {
            kind: request.source.consent(),
            requester: ev_workspace_root::policy::owner(actor.identity),
            target: ActionTarget::Object {
                dataset: grant.dataset.0,
                slot: grant.entry.object.slot,
                generation: grant.entry.object.generation,
                revision: grant.entry.revision,
            },
            rights: if request.writable {
                Rights::READ.union(Rights::EDIT)
            } else {
                Rights::READ
            },
        };
        if let owner::Source::Legacy(object) = request.source
            && !request.legacy.is_some_and(|metadata| {
                ev_workspace_root::legacy_selection::matches_effect(
                    object,
                    metadata,
                    ev_workspace_root::policy::owner(actor.identity),
                    &grant.effect,
                )
            })
        {
            return Err(());
        }
        if self.leases[index].is_some()
            || grant.effect.scope() != expected
            || self.selection_dataset(request) != Some(grant.dataset)
            || request.source
                == owner::Source::Legacy(ev_workspace_service::legacy::Object::Private)
                && self.policy.as_ref().unwrap().desktop.view().layer != Layer::AbsoluteAccess
        {
            return Err(());
        }
        if !self.inspect_selection(request, grant.by) || self.grant_actor(request).is_none() {
            return Err(());
        }
        self.next_lease = self
            .next_lease
            .checked_add(1)
            .filter(|v| *v != u64::MAX)
            .unwrap_or_else(|| rt::exit(1664));
        let epoch = self.next_lease;
        let command = match request.source {
            owner::Source::Workspace => control::Command::Bind(control::Bind {
                slot: index as u8,
                dataset: grant.dataset.0,
                object: grant.entry.object,
                target_process: actor.identity.process,
                target_thread: actor.identity.thread,
                target_registered_token: actor.identity.registered,
                lease_epoch: epoch,
                rights: if request.writable {
                    FileRights::ReadWrite
                } else {
                    FileRights::ReadOnly
                },
            }),
            owner::Source::Legacy(object) => {
                if request.writable || request.purpose == Purpose::SaveAs {
                    return Err(());
                }
                control::Command::BindLegacyReadOnly(control::LegacyBind {
                    slot: index as u8,
                    object,
                    target_process: actor.identity.process,
                    target_thread: actor.identity.thread,
                    target_registered_token: actor.identity.registered,
                    lease_epoch: epoch,
                    expected: request.legacy.ok_or(())?,
                })
            }
        };
        let response = if let control::Command::Bind(bind) = command {
            self.bind_workspace_file(index, bind, grant.by)?
        } else {
            self.workspace.control_until(
                self.channel(Channel::RootWorkspaceControl),
                command,
                grant.by,
            )?
        };
        if response.status != control::Status::Applied {
            return Err(());
        }
        let nonce = u32::try_from(response.request_id)
            .ok()
            .filter(|n| !matches!(*n, 0 | u32::MAX))
            .ok_or(())?;
        let facts = Facts {
            identity: actor.identity,
            held_control: actor.control,
            epoch,
            nonce,
        };
        // Bind alone has delivered no SEND. This private proof is removed before
        // any44 attempt, and never survives an unknown/accepted result.
        self.leases[index] = Some(Lease {
            facts,
            selection: request,
            dataset: grant.dataset,
            receipt: Some(Receipt {
                facts,
                held_control: actor.control,
                _kind: ReceiptKind::NeverDelivered,
            }),
        });
        // Rename/move preserve file revision. Bracket the service's Selection
        // capture with the monotonic namespace revision and full exact Entry;
        // no changed metadata is handed off under an old protected descriptor.
        if !self.inspect_selection(request, grant.by) {
            return Err(());
        }
        if now() >= grant.by || self.grant_actor(request).is_none() {
            return Err(());
        }
        // Recheck the actual immutable service identity immediately before44;
        // a cached feature response cannot survive stop/replacement or fencing.
        self.workspace_file_support()?;
        self.leases[index].as_mut().unwrap().receipt = None;
        let previously_held = self.file_may_be_held[index];
        // Unknown delivery may have left a local capability, even if a later
        // revoke drains the Kernel branch. Do not manufacture an App pause.
        self.file_may_be_held[index] = true;
        let selected = rt::call4(
            s::ENQUEUE_MANAGED_READ,
            actor.control,
            self.channel(lease_channel(index).unwrap()),
            self.channel(inbox_channel(index).unwrap()),
            u64::from(nonce),
        );
        if selected.status == 0
            && selected.value != 0
            && selected.capability == 0
            && selected.serial == 0
        {
            self.paused[index] = None;
            self.lease_rights[index] = if request.writable { 3 } else { 1 };
            self.status = if request.purpose == Purpose::SaveAs {
                b"RW destination delivered; Editor must save and independently read it back"
            } else {
                b"Exact scoped File SEND delivered; Editor verifies its own route"
            };
            Ok(())
        } else {
            // Kernel44's canonical1/2 refusals install nothing, or close and
            // retire its fresh failed one-shot atomically before user execution.
            // This says nothing about older branches, already retired above.
            if matches!(selected.status, 1 | 2)
                && selected.value == 0
                && selected.capability == 0
                && selected.serial == 0
            {
                self.file_may_be_held[index] = previously_held;
                self.leases[index].as_mut().unwrap().receipt = Some(Receipt {
                    facts,
                    held_control: actor.control,
                    _kind: ReceiptKind::NeverDelivered,
                });
            }
            Err(())
        }
    }
    pub(super) fn grant_tick(&mut self) {
        let Some(mut grant) = self.grant.take() else {
            return;
        };
        if matches!(grant.phase, Phase::Fenced) {
            self.grant = Some(grant);
            return;
        }
        if now() >= grant.by {
            self.status =
                b"File transition expired; retained lease/document are not reset or rebound";
            self.owner.dirty = true;
            grant.phase = Phase::Fenced;
            self.grant = Some(grant);
            return;
        }
        let Some(actor) = self.grant_actor(grant.request) else {
            self.status = b"Recipient stopped or changed; no fresh binding; old lease retained";
            self.owner.dirty = true;
            grant.phase = Phase::Fenced;
            self.grant = Some(grant);
            return;
        };
        let index = grant.request.index;
        let outcome = match grant.phase {
            Phase::Start => {
                if grant.revoking() {
                    if grant.cancelled {
                        self.status = b"Revoke cancelled before Kernel retirement; existing scope unchanged";
                        self.owner.dirty = true;
                        return;
                    }
                    if self.revoke_scope(grant.request) != Some(grant.effect.scope())
                        || grant.old.is_none_or(|facts| {
                            facts.identity != actor.identity || facts.held_control != actor.control
                        })
                    {
                        grant.phase = Phase::Fenced;
                        self.grant = Some(grant);
                        self.owner.dirty = true;
                        return;
                    }
                }
                grant.phase = if grant.revoking() {
                    Phase::Drain
                } else if grant.wait.is_some() {
                    Phase::QueueRelease
                } else {
                    Phase::Install
                };
                self.owner.dirty = true;
                Ok(false)
            }
            Phase::QueueRelease => {
                if grant.cancelled {
                    self.status =
                        b"Binding cancelled before release; existing File access is unchanged";
                    self.owner.dirty = true;
                    return;
                }
                let command = Command::ReleaseFile {
                    nonce: grant.wait.as_ref().unwrap().nonce(),
                    mode: grant.mode,
                };
                if self.outbox.release(index, actor.identity, command) {
                    grant.phase = Phase::AwaitRelease;
                    self.owner.dirty = true;
                }
                Ok(false)
            }
            Phase::AwaitRelease => {
                if grant.wait.as_ref().unwrap().acknowledged() {
                    grant.phase = if grant.old.is_some() {
                        Phase::Drain
                    } else {
                        Phase::Install
                    };
                    self.owner.dirty = true;
                }
                Ok(false)
            }
            Phase::Drain => self
                .drain_file(index, actor, grant.old.unwrap())
                .map(|done| {
                    if done {
                        grant.phase = Phase::Reconcile;
                        self.owner.dirty = true;
                    }
                    false
                }),
            Phase::Reconcile => self
                .reconcile_file(index, actor, grant.old.unwrap(), grant.by)
                .map(|done| {
                    if done {
                        self.owner.dirty = true;
                        if grant.revoking() {
                            self.status = b"Exact recorded File access revoked; copied private bytes remain; ordinary Private access is still refused";
                            return true;
                        }
                        grant.phase = Phase::Install;
                    }
                    false
                }),
            Phase::Install => {
                if grant.cancelled {
                    self.status = b"Binding cancelled; document remains private; retired authority stays retired";
                    Ok(true)
                } else {
                    self.install_grant(&grant, actor).map(|()| true)
                }
            }
            Phase::Fenced => unreachable!(),
        };
        match outcome {
            Ok(false) => self.grant = Some(grant),
            Ok(true) => self.owner.dirty = true,
            Err(()) => {
                self.status =
                    b"File transition refused or uncertain; retained lease/document are not reset";
                self.owner.dirty = true;
                grant.phase = Phase::Fenced;
                self.grant = Some(grant);
            }
        }
    }
}
