//! Native document policy on the actual current App route. The trusted Shell
//! displays a separate edit action; READ approvals never choose a writer route.
use super::*;
use ev_picker::{EditDelivery, EditHandoff, EditObjectView};
use ev_userspace_contract::{
    document::{Access, Snapshot},
    document_control::{Operation, Outcome, Request},
};

impl PendingMode {
    pub(super) fn picker(self) -> bool {
        matches!(self, Self::InteractivePicker | Self::Document(_))
    }
    pub(super) fn control(self, serial: u32) -> RootControl {
        match self {
            Self::Document(request) => RootControl::DocumentPicker {
                request: serial,
                access: request.operation().access(),
            },
            _ => RootControl::PickFile(serial),
        }
    }
}
struct EditGrant(Grant);
impl EditHandoff for EditGrant {
    type Delivered = u64;
    type Error = u64;
    fn revalidate_and_deliver_edit(&mut self, _: EditDelivery<'_>) -> Delivery<u64, u64> {
        self.0.deliver()
    }
}
impl Root<'_> {
    fn document_reply(&self, request: Request, outcome: Outcome) {
        self.queue_control(
            delivery::Peer::App,
            request.reply(outcome).encode(),
            delivery::Kind::Data,
        );
    }
    pub(super) fn document_cancel(&mut self, serial: u32) -> bool {
        let Some(p) = self.pending.filter(|p| p.request == serial && !p.queued) else {
            return false;
        };
        let PendingMode::Document(request) = p.mode else {
            return false;
        };
        self.document_reply(request, Outcome::Cancelled);
        self.pending = None;
        true
    }
    #[inline(never)]
    pub(super) fn document_event(&mut self, bytes: [u8; 8]) {
        let Ok(request) = Request::decode(&bytes, 0) else {
            return;
        };
        if request.operation() == Operation::Publish {
            // The caller holds the actual semantic frame until this matching
            // reply. Copy privately before parsing; never keep a shared slice.
            let n = self.native.as_mut().unwrap();
            let bytes = n.document_snapshot();
            let outcome = if Snapshot::decode(&bytes, 0).is_ok() {
                Outcome::Published
            } else {
                Outcome::Malformed
            };
            self.document_reply(request, outcome);
            return;
        }
        if self.pending.is_some() {
            self.document_reply(request, Outcome::Busy);
            return;
        }
        let app = self.child(Child::App);
        let requester = self.requester(app);
        if !self.native_document_allowed(requester, request.operation().access()) {
            self.document_reply(request, Outcome::Denied);
            return;
        }
        self.request = self
            .request
            .checked_add(1)
            .filter(|n| *n != u32::MAX)
            .unwrap_or_else(|| fail(925));
        let mode = PendingMode::Document(request);
        self.pending = Some(Pending {
            request: self.request,
            app,
            ready: false,
            queued: false,
            file: None,
            ready_tick: 0,
            held_reported: false,
            mode,
        });
        self.control_shell(mode.control(self.request));
    }
    #[inline(never)]
    pub(super) fn document_select(&mut self, serial: u32, file: FileChoice) {
        let Some(mut pending) = self
            .pending
            .filter(|p| p.request == serial && p.ready && !p.queued)
        else {
            return;
        };
        let PendingMode::Document(request) = pending.mode else {
            return;
        };
        let app = self.child(Child::App);
        let requester = self.requester(app);
        let access = request.operation().access();
        if app.control != pending.app.control
            || app.identity != pending.app.identity
            || self.native_grants_fenced()
            || !self.native_document_allowed(requester, access)
        {
            self.document_refused(pending, Outcome::Denied);
            return;
        }
        let deadline = self.storage_deadline();
        let Some(view) = self.metadata_until(file, deadline) else {
            self.document_refused(pending, Outcome::Denied);
            return;
        };
        let approval = if access == Access::Edit {
            self.picker.prepare_edit(
                requester,
                EditObjectView {
                    object: view,
                    writable: true,
                },
                now(),
                deadline,
            )
        } else {
            self.picker.prepare(
                requester,
                view,
                Persistence::ThisIncarnation,
                now(),
                deadline,
            )
        };
        let Ok(approval) = approval else {
            self.document_refused(pending, Outcome::Denied);
            return;
        };
        let consent = Consent {
            displayed_action: approval.selection().action_digest(),
            approver: self.owner,
            origin: Origin::TrustedPicker,
        };
        let channel = match (file, access) {
            (FileChoice::Notes, Access::Edit) => Channel::NotesWrite,
            (FileChoice::Private, Access::Edit) => Channel::PrivateWrite,
            (FileChoice::Notes, _) => Channel::NotesRead,
            _ => Channel::PrivateRead,
        };
        let mut grant = Grant {
            process: app.control,
            parent: self.channels[channel.index()],
            inbox: self.channels[Channel::GrantInbox.index()],
            request: serial,
            bound: self.bound,
        };
        let Some(current) = self.metadata_until(file, deadline) else {
            self.document_refused(pending, Outcome::Denied);
            return;
        };
        if !self.native_document_allowed(self.requester(app), access) {
            self.document_refused(pending, Outcome::Denied);
            return;
        }
        let result = if access == Access::Edit {
            self.picker.commit_edit(
                approval,
                consent,
                self.requester(app),
                EditObjectView {
                    object: current,
                    writable: true,
                },
                now(),
                &mut EditGrant(grant),
            )
        } else {
            self.picker.commit(
                approval,
                consent,
                self.requester(app),
                current,
                now(),
                &mut grant,
            )
        };
        if matches!(result, Ok(Delivery::Delivered(_))) {
            pending.queued = true;
            pending.file = Some(file);
            self.pending = Some(pending);
        } else {
            self.document_refused(pending, Outcome::Denied);
        }
    }
    fn document_refused(&mut self, pending: Pending, outcome: Outcome) {
        if let PendingMode::Document(request) = pending.mode {
            self.document_reply(request, outcome);
        }
        self.control_shell(RootControl::FileRefused(pending.request));
        self.pending = None;
    }
}
