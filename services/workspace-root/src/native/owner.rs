use super::filegrant::Purpose;
use super::*;
use ev_userspace_contract::workspace::{Entry, EntryState, Kind, ObjectId, Operation, Outcome};
use ev_workspace_root::{policy::owner as model_owner, render::Mode};
use ev_workspace_service::{control, legacy};
use ev_workspace_shell::{
    ActionScope, ActionTarget, Challenge, ConfirmationSource, PresentedWitness, ProtectedKind,
    Rights,
};
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Source {
    Workspace,
    Legacy(legacy::Object),
}
impl Source {
    pub fn consent(self) -> ProtectedKind {
        match self {
            Self::Workspace => ProtectedKind::PickerConsent,
            Self::Legacy(object) => ev_workspace_root::legacy_selection::kind(object),
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Request {
    pub index: usize,
    pub identity: Identity,
    pub directory: ObjectId,
    pub cursor: u16,
    pub next: Option<u16>,
    pub entry: Option<Entry>,
    pub writable: bool,
    pub purpose: Purpose,
    pub namespace_revision: Option<u64>,
    pub source: Source,
    pub legacy: Option<legacy::Metadata>,
    pub revoke: Option<filegrant::Facts>,
}
pub(super) struct OwnerFlow {
    pub pending: Option<Request>,
    pub challenge: Option<Challenge>,
    pub witness: Option<PresentedWitness>,
    pub dirty: bool,
    pub rearm: bool,
    pub input_nonce: u32,
    refused: bool,
    private_policy_refusal: bool,
}
impl OwnerFlow {
    pub const fn new() -> Self {
        Self {
            pending: None,
            challenge: None,
            witness: None,
            dirty: false,
            rearm: false,
            input_nonce: 0,
            refused: false,
            private_policy_refusal: false,
        }
    }
    pub fn cancel(&mut self) {
        self.pending = None;
        self.challenge = None;
        self.witness = None;
        self.rearm = false;
        self.dirty = true;
        self.refused = false;
        self.private_policy_refusal = false;
    }
    pub fn nonce(&self) -> u64 {
        self.challenge.map_or(0, |c| c.nonce)
    }
    pub fn needs_barrier(&self) -> bool {
        self.rearm
    }
    pub fn view(&self) -> (Mode, &'static [u8], Option<Entry>, bool) {
        if self.refused {
            return (
                Mode::Refused,
                if self.private_policy_refusal {
                    b"Original EVRO-USERS-VOL01 / local2 Private refused; cancel and deliberately enter L3"
                } else {
                    b"Root refused operation; no authority was changed"
                },
                self.pending.and_then(|p| p.entry),
                false,
            );
        }
        match self.pending {
            Some(p) if p.purpose == Purpose::Revoke => (
                Mode::Revoke,
                match p.source {
                    Source::Legacy(legacy::Object::Private) => {
                        b"Revoke original Private READ; copied bytes remain"
                    }
                    Source::Legacy(legacy::Object::Notes) => {
                        b"Revoke original Notes READ; copied bytes remain"
                    }
                    Source::Workspace => b"Revoke File access; copies/accepted effects remain",
                },
                p.entry,
                p.writable,
            ),
            Some(p) => (
                if self.challenge.is_some() {
                    Mode::Consent
                } else {
                    Mode::Picker
                },
                if p.source == Source::Legacy(legacy::Object::Private) {
                    if self.challenge.is_some() {
                        b"Confirm L3 override: original EVRO-USERS-VOL01 / local2 Private READ ONLY"
                    } else {
                        b"Original EVRO-USERS-VOL01 / local2 Private: deliberate L3 READ override"
                    }
                } else if p.source == Source::Legacy(legacy::Object::Notes) {
                    if self.challenge.is_some() {
                        b"Confirm original EVRO-USERS-VOL01 / local1 Notes READ ONLY"
                    } else {
                        b"Original EVRO-USERS-VOL01 / local1 Notes READ ONLY"
                    }
                } else if self.challenge.is_some() && p.purpose == Purpose::SaveAs {
                    b"Confirm Save As overwrite: exact Editor and RW destination below"
                } else if self.challenge.is_some() {
                    b"Confirm Open: exact Editor, object and access rights below"
                } else if p.purpose == Purpose::SaveAs {
                    b"Root Save As: approve exact RW destination; private document is retained"
                } else {
                    b"Root file chooser: arrows browse; Enter selects then confirms"
                },
                p.entry,
                p.writable,
            ),
            None => (
                Mode::Desktop,
                b"Evrosion workspace | independent protected Root controls",
                None,
                false,
            ),
        }
    }
}
impl Root<'_> {
    pub(super) fn cancel_requester(&mut self, identity: Identity) {
        if self.owner.pending.is_some_and(|p| p.identity == identity) {
            self.cancel_owner();
        }
    }
    pub(super) fn cancel_owner(&mut self) {
        self.semantic_cancel_confirmation();
        let semantic_consent = self.semantic_consent();
        if let Some(policy) = self.policy.as_mut() {
            let _ = policy.trusted.cancel(&mut policy.desktop);
        }
        self.owner.cancel();
        self.input.cancel();
        if semantic_consent {
            self.semantic_revoke(true);
        }
    }
    pub(super) fn request_picker(&mut self, index: usize) {
        self.request_file(index, Purpose::Open);
    }
    pub(super) fn request_save_as(&mut self, index: usize) {
        self.request_file(index, Purpose::SaveAs);
    }
    fn request_file(&mut self, index: usize, purpose: Purpose) {
        if self.owner.pending.is_some() || self.grant.is_some() || !matches!(index, 1 | 2) {
            return;
        }
        let actor = self.actor(app_child(index).unwrap());
        if actor.failed {
            return;
        }
        self.owner.pending = Some(Request {
            index,
            identity: actor.identity,
            directory: ObjectId {
                slot: 0,
                generation: 1,
            },
            cursor: 0,
            next: None,
            entry: None,
            writable: purpose == Purpose::SaveAs,
            purpose,
            namespace_revision: None,
            source: Source::Workspace,
            legacy: None,
            revoke: None,
        });
        self.owner.refused = false;
        self.refresh_picker();
    }
    pub(super) fn picker_source(&mut self) {
        let Some(mut pending) = self.owner.pending else {
            return;
        };
        if self.owner.challenge.is_some() || pending.purpose != Purpose::Open {
            return;
        }
        pending.source = match pending.source {
            Source::Workspace => Source::Legacy(legacy::Object::Notes),
            Source::Legacy(legacy::Object::Notes) => Source::Legacy(legacy::Object::Private),
            Source::Legacy(legacy::Object::Private) => Source::Workspace,
        };
        pending.legacy = None;
        pending.directory = ObjectId {
            slot: 0,
            generation: 1,
        };
        pending.cursor = 0;
        pending.namespace_revision = None;
        pending.writable = false;
        self.owner.pending = Some(pending);
        self.refresh_picker();
    }
    pub(super) fn selection_dataset(
        &self,
        request: Request,
    ) -> Option<ev_userspace_contract::workspace::DatasetId> {
        if request.purpose == Purpose::Revoke {
            return self.revoke_dataset(request);
        }
        match request.source {
            Source::Workspace => self.workspace.dataset,
            Source::Legacy(object) => request
                .legacy
                .filter(|m| m.identity == legacy::Identity::for_object(object))
                .map(|m| ev_userspace_contract::workspace::DatasetId(m.identity.volume)),
        }
    }
    pub(super) fn inspect_selection(&mut self, request: Request, cut: u64) -> bool {
        if request.purpose == Purpose::Revoke {
            // Authority reduction is bound to immutable installed metadata,
            // even when a later Save/rename changed the current store revision.
            return self.revoke_scope(request).is_some();
        }
        let Some(entry) = request.entry else {
            return false;
        };
        match request.source {
            Source::Workspace => self
                .workspace
                .namespace_until(
                    self.channel(Channel::RootWorkspaceControl),
                    Operation::Inspect {
                        object: entry.object,
                    },
                    cut,
                )
                .is_ok_and(|r| {
                    r.outcome == Outcome::Completed
                        && r.entry == Some(entry)
                        && request.namespace_revision == Some(r.namespace_revision)
                }),
            Source::Legacy(object) => {
                !request.writable
                    && request.legacy.is_some()
                    && self
                        .workspace
                        .legacy_inspect_until(
                            self.channel(Channel::RootWorkspaceControl),
                            object,
                            self.next_lease.saturating_add(1),
                            cut,
                        )
                        .is_ok_and(|r| {
                            r.status == control::Status::Applied && r.metadata == request.legacy
                        })
            }
        }
    }
    fn refresh_picker(&mut self) {
        self.semantic_cancel_confirmation();
        let Some(mut pending) = self.owner.pending else {
            return;
        };
        self.owner.challenge = None;
        self.owner.witness = None;
        self.owner.refused = false;
        self.owner.private_policy_refusal = false;
        if let Some(policy) = self.policy.as_mut() {
            let _ = policy.trusted.cancel(&mut policy.desktop);
        }
        let cut = deadline(v5::resources::FILE_TRANSACTION_TICKS);
        if let Source::Legacy(object) = pending.source {
            pending.entry = None;
            pending.next = None;
            pending.namespace_revision = None;
            pending.writable = false;
            pending.legacy = None;
            let observed = self.workspace.legacy_inspect_until(
                self.channel(Channel::RootWorkspaceControl),
                object,
                self.next_lease.saturating_add(1),
                cut,
            );
            if let Ok(response) = observed
                && response.status == control::Status::Applied
                && let Some(metadata) = response.metadata
            {
                pending.legacy = Some(metadata);
                pending.entry = ev_workspace_root::legacy_selection::entry(object, metadata);
                self.owner.refused = false;
                self.owner.rearm = true;
                self.status = b"Original volume/local identity retained; READ only; Save As creates a new workspace copy";
            } else {
                self.owner.refused = true;
                self.owner.rearm = false;
                self.status = b"Original file is unavailable, foreign, corrupt or needs separate recovery; nothing was formatted";
            }
            self.owner.pending = Some(pending);
            self.owner.dirty = true;
            return;
        }
        pending.entry = None;
        pending.next = None;
        self.owner.pending = Some(pending);
        let mut result = Err(());
        // One bounded retry handles a revision changing between Inspect/List;
        // neither read renews this chooser transaction's original cut.
        for attempt in 0..2 {
            let Ok(inspected) = self.workspace.namespace_until(
                self.channel(Channel::RootWorkspaceControl),
                Operation::Inspect {
                    object: pending.directory,
                },
                cut,
            ) else {
                break;
            };
            let Some(query) = ev_workspace_root::picker::after_inspect(
                pending.directory,
                pending.cursor,
                pending.namespace_revision,
                inspected,
            ) else {
                break;
            };
            pending.cursor = query.cursor;
            pending.namespace_revision = Some(query.revision);
            result = self.workspace.namespace_until(
                self.channel(Channel::RootWorkspaceControl),
                query.operation,
                cut,
            );
            if attempt == 0
                && result
                    .as_ref()
                    .is_ok_and(|r| r.outcome == Outcome::Conflict)
            {
                pending.cursor = 0;
                pending.namespace_revision = None;
                continue;
            }
            break;
        }
        match result {
            Ok(response) if matches!(response.outcome, Outcome::Completed | Outcome::End) => {
                pending.entry = response.entry;
                pending.next = response.next_cursor;
                self.owner.pending = Some(pending);
                self.owner.rearm = true;
                self.owner.dirty = true;
                self.status =
                    b"Only Root's actual namespace response supplies this object/name/revision";
            }
            _ => {
                self.status = b"Workspace namespace refused or is uncertain; no file grant";
                self.owner.refused = true;
                self.owner.rearm = false;
                self.owner.dirty = true;
            }
        }
    }
    pub(super) fn browse(&mut self, direction: i8) {
        if self
            .owner
            .pending
            .is_some_and(|p| p.purpose == Purpose::Revoke)
        {
            return;
        }
        if self.owner.challenge.is_some() {
            self.cancel_owner();
            return;
        }
        if let Some(pending) = self.owner.pending.as_mut() {
            if pending.source != Source::Workspace {
                return;
            }
            if direction > 0 {
                let Some(next) = pending.next else {
                    return;
                };
                pending.cursor = next;
            } else {
                pending.cursor = pending.cursor.saturating_sub(1);
            }
            self.refresh_picker();
        }
    }
    pub(super) fn picker_up(&mut self) {
        let Some(mut p) = self.owner.pending else {
            return;
        };
        if self.owner.challenge.is_some()
            || p.purpose == Purpose::Revoke
            || p.source != Source::Workspace
        {
            return;
        }
        if let Ok(response) = self.workspace.namespace(
            self.channel(Channel::RootWorkspaceControl),
            Operation::Inspect {
                object: p.directory,
            },
        ) && response.outcome == Outcome::Completed
            && let Some(entry) = response.entry
        {
            p.directory = entry.parent;
            p.cursor = 0;
            p.namespace_revision = None;
            self.owner.pending = Some(p);
            self.refresh_picker();
        }
    }
    pub(super) fn choose_rights(&mut self) {
        if self.owner.challenge.is_some() {
            return;
        }
        if let Some(p) = self.owner.pending.as_mut() {
            if p.purpose == Purpose::Revoke {
                return; // exact installed rights cannot be relabeled here
            }
            if matches!(p.source, Source::Legacy(_)) {
                self.status =
                    b"Original File-v1 objects are READ only; Save As uses the new workspace";
                self.owner.dirty = true;
                return;
            }
            if p.purpose == Purpose::SaveAs {
                self.status = b"Save As requires explicit RW destination approval; cancel to keep existing access";
                self.owner.dirty = true;
                return;
            }
            p.writable = !p.writable;
            self.owner.rearm = true;
            self.owner.dirty = true;
        }
    }
    pub(super) fn choose(&mut self, serial: u32) {
        let Some(mut pending) = self.owner.pending else {
            return;
        };
        let Some(entry) = pending.entry else {
            return;
        };
        if self.owner.challenge.is_some() {
            self.confirm_grant(serial);
            return;
        }
        if entry.state != EntryState::Live {
            return;
        }
        if entry.kind == Kind::Directory {
            pending.directory = entry.object;
            pending.cursor = 0;
            pending.namespace_revision = None;
            self.owner.pending = Some(pending);
            self.refresh_picker();
            return;
        }
        if self.actor(app_child(pending.index).unwrap()).identity != pending.identity {
            return;
        }
        if pending.purpose == Purpose::Revoke {
            let Some(scope) = self.revoke_scope(pending) else {
                self.cancel_owner();
                self.status = b"Installed File scope or recipient changed; revoke cancelled";
                return;
            };
            self.challenge_file_scope(scope, serial);
            return;
        }
        if pending.source == Source::Legacy(legacy::Object::Private)
            && self.policy.as_ref().unwrap().desktop.view().layer != Layer::AbsoluteAccess
        {
            self.owner.refused = true;
            self.owner.private_policy_refusal = true;
            self.owner.dirty = true;
            self.status = b"Original Private is ordinarily refused; cancel, choose L3, then deliberately approve the exact READ-only override";
            return;
        }
        if !self.inspect_selection(pending, deadline(v5::resources::FILE_TRANSACTION_TICKS)) {
            self.status = b"Selected source metadata changed or is unavailable; choose it again";
            self.refresh_picker();
            return;
        }
        let Some(dataset) = self.selection_dataset(pending) else {
            return;
        };
        let scope = ActionScope {
            kind: pending.source.consent(),
            requester: model_owner(pending.identity),
            target: ActionTarget::Object {
                dataset: dataset.0,
                slot: entry.object.slot,
                generation: entry.object.generation,
                revision: entry.revision,
            },
            rights: if pending.writable {
                Rights::READ.union(Rights::EDIT)
            } else {
                Rights::READ
            },
        };
        self.challenge_file_scope(scope, serial);
    }
    fn challenge_file_scope(&mut self, scope: ActionScope, serial: u32) {
        let policy = self.policy.as_mut().unwrap();
        // This method is reached only from an independently authenticated Input
        // event in the Root UI. An App Open intent never calls this attestation.
        let Ok(attention) = policy
            .trusted
            .attest_attention(&mut policy.desktop, self.input.serial(serial))
        else {
            return;
        };
        let Ok(challenge) = policy
            .trusted
            .challenge(&mut policy.desktop, attention, scope)
        else {
            return;
        };
        self.owner.challenge = Some(challenge);
        self.owner.witness = None;
        self.owner.rearm = true;
        self.owner.dirty = true;
    }
    pub(super) fn arm_owner_after_present(&mut self, frame: u64) {
        self.owner.input_nonce = self
            .owner
            .input_nonce
            .checked_add(1)
            .filter(|v| *v != u32::MAX)
            .unwrap_or_else(|| rt::exit(1645));
        let request = ev_input::SessionBarrierRequest::new(self.owner.input_nonce).unwrap();
        let reply = rt::rpc::call(
            self.channel(Channel::InputBarrier),
            request.encode(),
            deadline(v5::resources::RPC_TICKS),
        );
        let Some(reply) = reply
            .ok()
            .and_then(|bytes| ev_input::SessionBarrierReply::decode(bytes).ok())
        else {
            self.cancel_owner();
            self.status =
                b"Input barrier failed or is uncertain; no protected confirmation is armed";
            return;
        };
        self.input.arm(reply);
        self.owner.rearm = false;
        if let Some(challenge) = self.owner.challenge {
            let policy = self.policy.as_mut().unwrap();
            self.owner.witness = Some(
                policy
                    .trusted
                    .attest_presented(
                        &mut policy.desktop,
                        challenge,
                        challenge.scope,
                        frame,
                        self.input.serial(reply.sequence),
                    )
                    .unwrap_or_else(|_| rt::exit(1648)),
            );
        }
    }
    fn confirm_grant(&mut self, serial: u32) {
        self.confirm_grant_source(self.input.serial(serial), ConfirmationSource::Physical);
    }
    pub(super) fn confirm_grant_assistive(
        &mut self,
        input_serial: u64,
        provider: ev_workspace_shell::ProviderLease,
    ) {
        self.confirm_grant_source(
            input_serial,
            ConfirmationSource::Assistive {
                sender: model_owner(self.actor(Child::Inspector).identity),
                provider,
            },
        );
    }
    fn confirm_grant_source(&mut self, input_serial: u64, source: ConfirmationSource) {
        let Some(pending) = self.owner.pending else {
            return;
        };
        let Some(challenge) = self.owner.challenge else {
            return;
        };
        let actor = self.actor(app_child(pending.index).unwrap());
        if actor.failed || actor.identity != pending.identity || self.grant.is_some() {
            self.cancel_owner();
            return;
        }
        if identity(actor.control, actor.identity.registered) != actor.identity {
            self.cancel_owner();
            return;
        }
        let current = if pending.purpose == Purpose::Revoke {
            self.revoke_scope(pending) == Some(challenge.scope)
        } else {
            self.inspect_selection(pending, deadline(v5::resources::FILE_TRANSACTION_TICKS))
                && self
                    .selection_dataset(pending)
                    .is_some_and(|d| match challenge.scope.target {
                        ActionTarget::Object { dataset, .. } => dataset == d.0,
                        _ => false,
                    })
                && (pending.source != Source::Legacy(legacy::Object::Private)
                    || self.policy.as_ref().unwrap().desktop.view().layer == Layer::AbsoluteAccess)
        };
        if !current {
            if pending.purpose == Purpose::Revoke {
                self.cancel_owner();
                self.status = b"Recorded File scope changed; no revoke was applied";
            } else {
                self.refresh_picker();
            }
            return;
        }
        let Some(witness) = self.owner.witness.take() else {
            return;
        };
        let policy = self.policy.as_mut().unwrap();
        let Ok(effect) = policy.trusted.attest_confirmation(
            &mut policy.desktop,
            witness,
            challenge.scope,
            input_serial,
            source,
        ) else {
            self.cancel_owner();
            return;
        };
        self.begin_grant(pending, effect);
    }
    pub(super) fn request_discard(&mut self, _index: usize) {
        self.status = b"Discard confirmation is pending the scoped owner-control adapter";
        self.owner.dirty = true;
    }
}
