//! Selected-file handoff ownership. All operations are trusted kernel
//! owner APIs, not a user ABI taking numeric domain/process/approval authority.
//! Actual protected consent and service-side current revision resolution remain
//! mandatory integration boundaries. Portable tests certify no hardware/input.
use crate::{
    capability::{Authority, Error as CapError, Handle, Kind, Rights, SpaceId},
    incarnation::Token,
    ipc::{self, Delivery, Mailbox, Outgoing, Reclaimed, Ticket},
    scheduler::{self, Scheduler, ThreadId},
    service::{self, Metadata, Registry},
    time::Deadline,
};
use ev_picker as picker;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Authority(CapError),
    Service(service::Error),
    Scheduler(scheduler::Error),
    Ipc(ipc::Error),
    StaleRoot,
    StaleTarget,
    WrongThread,
    WrongObject,
    ChangedSelection,
    Expired,
}
impl From<CapError> for Error {
    fn from(e: CapError) -> Self {
        Self::Authority(e)
    }
}
impl From<service::Error> for Error {
    fn from(e: service::Error) -> Self {
        Self::Service(e)
    }
}
impl From<scheduler::Error> for Error {
    fn from(e: scheduler::Error) -> Self {
        Self::Scheduler(e)
    }
}
impl From<ipc::Error> for Error {
    fn from(e: ipc::Error) -> Self {
        Self::Ipc(e)
    }
}

#[must_use = "retain or explicitly retire the selected mailbox/escrow owner"]
pub struct SelectedReadRoute {
    root: Token,
    controller: SpaceId,
    process_control: Handle,
    process_object: usize,
    target: Metadata,
    receive: Handle,
    mailbox: Mailbox,
}
pub struct RejectedRouteCreation {
    pub mailbox: Mailbox,
    pub error: Error,
}
pub struct RejectedRouteRetirement {
    pub route: SelectedReadRoute,
    pub error: Error,
}
/// Unique actual-stopped selected-inbox owner. It preserves immutable selected
/// policy and ticket/escrow history; no raw PID or boolean can construct it.
#[cfg(feature = "workspace-authority")]
pub struct StoppedSelectedRoute {
    root: Token,
    controller: SpaceId,
    target: Metadata,
    mailbox: Mailbox,
}
#[cfg(feature = "workspace-authority")]
pub struct RejectedStoppedSelectedRoute {
    pub owner: StoppedSelectedRoute,
    pub error: Error,
}
#[cfg(feature = "workspace-authority")]
impl StoppedSelectedRoute {
    pub fn target_metadata(&self) -> Metadata {
        self.target
    }
    #[allow(clippy::too_many_arguments, clippy::result_large_err)]
    pub fn rebind(
        mut self,
        a: &Authority,
        s: &Scheduler,
        r: &Registry<'_>,
        current: Token,
        process_control: Handle,
        receive_selector: u64,
        endpoint_control: Handle,
    ) -> Result<SelectedReadRoute, RejectedStoppedSelectedRoute> {
        let checked = (|| -> Result<_, Error> {
            if current != self.root
                || !a.is_live_space(self.controller)
                || s.process_terminated(current.process())
                || s.process_job(current.process())? != current.job()
            {
                return Err(Error::StaleRoot);
            }
            let target = r.active_metadata(a, s, self.controller, process_control)?;
            let process_object = a
                .authorize(
                    self.controller,
                    process_control,
                    Kind::Process,
                    Rights::CONTROL,
                )?
                .identity();
            let receive = r.grant(a, self.controller, process_control, receive_selector)?;
            self.mailbox.reopen_selected_empty(
                a,
                self.controller,
                endpoint_control,
                target.domain,
                receive,
            )?;
            Ok((target, process_object, receive))
        })();
        match checked {
            Ok((target, process_object, receive)) => Ok(SelectedReadRoute {
                root: self.root,
                controller: self.controller,
                process_control,
                process_object,
                target,
                receive,
                mailbox: self.mailbox,
            }),
            Err(error) => Err(RejectedStoppedSelectedRoute { owner: self, error }),
        }
    }
}
impl SelectedReadRoute {
    /// Produce only after the same old Registry owner is actually terminated
    /// and every queued capability/escrow is settled. Must precede forgetting
    /// that old row. Rebinding later cannot reset message sequence or policy.
    #[cfg(feature = "workspace-authority")]
    #[allow(clippy::result_large_err)]
    pub fn into_stopped_route(
        self,
        a: &Authority,
        s: &Scheduler,
        r: &Registry<'_>,
    ) -> Result<StoppedSelectedRoute, RejectedRouteRetirement> {
        let root = self.root;
        let controller = self.controller;
        let target = self.target;
        self.into_stopped_mailbox(a, s, r)
            .map(|mailbox| StoppedSelectedRoute {
                root,
                controller,
                target,
                mailbox,
            })
    }
    /// Production constructor: consumes the one actual managed mailbox after
    /// live ProcessCONTROL/active-row/RX validation, never allocates another
    /// escrow and never accepts a caller-selected process/domain identity.
    #[allow(clippy::too_many_arguments, clippy::result_large_err)]
    pub fn from_managed(
        a: &Authority,
        s: &Scheduler,
        r: &Registry<'_>,
        root: Token,
        controller: SpaceId,
        process_control: Handle,
        receive_selector: u64,
        endpoint_control: Handle,
        mailbox: Mailbox,
    ) -> Result<Self, RejectedRouteCreation> {
        let prepared = (|| -> Result<_, Error> {
            let target = r.active_metadata(a, s, controller, process_control)?;
            let process_object = a
                .authorize(controller, process_control, Kind::Process, Rights::CONTROL)?
                .identity();
            let receive = r.grant(a, controller, process_control, receive_selector)?;
            Ok((target, process_object, receive))
        })();
        let (target, process_object, receive) = match prepared {
            Ok(value) => value,
            Err(error) => return Err(RejectedRouteCreation { mailbox, error }),
        };
        let mailbox = match mailbox.into_selected_file(
            a,
            controller,
            endpoint_control,
            target.domain,
            receive,
        ) {
            Ok(mailbox) => mailbox,
            Err(rejected) => {
                return Err(RejectedRouteCreation {
                    mailbox: rejected.mailbox,
                    error: rejected.error.into(),
                });
            }
        };
        Ok(Self {
            root,
            controller,
            process_control,
            process_object,
            target,
            receive,
            mailbox,
        })
    }
    /// Consume only after the same retained full Registry/Scheduler identity is
    /// actually terminated and no message/escrow remains. This decreases owned
    /// authority; revoked RX/Root branches and a closed public ProcessCONTROL
    /// handle do not block cleanup. Must precede Registry.forget_retired.
    #[allow(clippy::result_large_err)]
    pub fn into_stopped_mailbox(
        mut self,
        a: &Authority,
        s: &Scheduler,
        r: &Registry<'_>,
    ) -> Result<Mailbox, RejectedRouteRetirement> {
        let prepared = (|| -> Result<(), Error> {
            r.require_stopped_owner(s, self.process_object, self.target)?;
            self.mailbox.check_settled(a)?;
            Ok(())
        })();
        if let Err(error) = prepared {
            return Err(RejectedRouteRetirement { route: self, error });
        }
        if let Err(error) = self.mailbox.receiver_died(self.target.domain) {
            return Err(RejectedRouteRetirement {
                route: self,
                error: error.into(),
            });
        }
        Ok(self.mailbox)
    }
    /// Root/caller supplies its installed ProcessCONTROL and declared receive
    /// role selector. Registry, not the request packet, resolves actual target.
    /// The controller is serialized with this same Authority/Scheduler/Registry
    /// and obtains the full current Root token from its trusted runtime owner.
    #[cfg(test)] // Old external-owner models only, no production escrow allocation.
    pub fn new(
        a: &mut Authority,
        s: &Scheduler,
        r: &Registry<'_>,
        root: Token,
        controller: SpaceId,
        process_control: Handle,
        receive_selector: u64,
    ) -> Result<Self, Error> {
        let target = r.active_metadata(a, s, controller, process_control)?;
        let receive = r.grant(a, controller, process_control, receive_selector)?;
        a.authorize(
            target.domain,
            receive,
            Kind::Endpoint,
            Rights::RECEIVE | Rights::CONTROL,
        )?;
        let mailbox = Mailbox::new_selected_file(a, target.domain, receive)?;
        let process_object = a
            .authorize(controller, process_control, Kind::Process, Rights::CONTROL)?
            .identity();
        Ok(Self {
            root,
            controller,
            process_control,
            process_object,
            target,
            receive,
            mailbox,
        })
    }
    fn validate(
        &self,
        a: &Authority,
        s: &Scheduler,
        r: &Registry<'_>,
        current: Token,
    ) -> Result<(), Error> {
        if current != self.root {
            return Err(Error::StaleRoot);
        }
        if r.active_metadata(a, s, self.controller, self.process_control)? != self.target
            || !a.is_live_space(self.target.domain)
        {
            return Err(Error::StaleTarget);
        }
        Ok(())
    }
    /// no queue/ticket/branch mutation; prepare the exact later enqueue
    /// under the same exclusive Authority/Registry/Scheduler/route owner.
    #[allow(clippy::too_many_arguments)] // Same explicit trusted owners as enqueue; not a userspace ABI.
    pub(crate) fn check_enqueue(
        &self,
        a: &Authority,
        s: &Scheduler,
        r: &Registry<'_>,
        current: Token,
        send: Handle,
        bytes: &[u8],
        deadline: Deadline,
        now: u64,
    ) -> Result<(), Error> {
        self.validate(a, s, r, current)?;
        self.mailbox
            .check_selected_send(a, self.controller, send, bytes, deadline, now)?;
        Ok(())
    }
    /// Enqueue moves the ORIGINAL source into private escrow. Ticket is only an
    /// acceptance receipt; the receiver owns no capability until receive.
    #[allow(clippy::too_many_arguments)] // Explicit trusted tables/context; this is no userspace ABI.
    pub fn enqueue(
        &mut self,
        a: &mut Authority,
        s: &Scheduler,
        r: &Registry<'_>,
        current: Token,
        send: Handle,
        source: Handle,
        bytes: &[u8],
        deadline: Deadline,
        now: u64,
    ) -> Result<Ticket, Error> {
        self.validate(a, s, r, current)?;
        Ok(self.mailbox.send(
            a,
            self.controller,
            send,
            Outgoing {
                bytes,
                capability: Some(source),
                deadline,
            },
            now,
        )?)
    }
    /// Caller thread comes from actual protected dispatch, never a raw userspace
    /// thread number. Only this exact registered target can consume its escrow.
    pub fn receive(
        &mut self,
        a: &mut Authority,
        s: &Scheduler,
        r: &Registry<'_>,
        current: Token,
        actual_thread: ThreadId,
        now: u64,
    ) -> Result<Delivery, Error> {
        self.validate(a, s, r, current)?;
        if actual_thread != self.target.thread
            || s.thread_process(actual_thread)? != self.target.process
        {
            return Err(Error::WrongThread);
        }
        Ok(self
            .mailbox
            .receive(a, self.target.domain, self.receive, now)?)
    }
    /// Actual scheduler death only. Domain closure alone is not hardware proof.
    pub fn receiver_died(&mut self, s: &Scheduler) -> Result<(), Error> {
        if !s.process_terminated(self.target.process) {
            return Err(Error::StaleTarget);
        }
        Ok(self.mailbox.receiver_died(self.target.domain)?)
    }
    pub fn reclaim(
        &mut self,
        a: &mut Authority,
        ticket: Ticket,
        now: u64,
    ) -> Result<Reclaimed, Error> {
        Ok(self.mailbox.reclaim(a, self.controller, ticket, now)?)
    }
    /// Serialized controller-owned withdrawal before delivery. A stale receipt
    /// never cancels another message, and accepted delivery cannot be refunded.
    pub fn cancel(
        &mut self,
        a: &mut Authority,
        ticket: Ticket,
        now: u64,
    ) -> Result<Reclaimed, Error> {
        Ok(self
            .mailbox
            .withdraw_undelivered(a, self.controller, ticket, now)?)
    }
    /// Only truly dead/closed sender domains permit this ordinary bounded
    /// disposal; live foreign owners are never force-closed or refunded.
    pub fn discard_dead_senders(&mut self, a: &mut Authority, now: u64) -> Result<usize, Error> {
        Ok(self.mailbox.reap_dead_senders(a, now)?)
    }
    /// Exact immutable target retained by this managed route's admitted binding.
    /// This readback is not a new binding or user-provided ready assertion.
    pub fn target_metadata(&self) -> Metadata {
        self.target
    }
    pub fn pending(&self) -> usize {
        self.mailbox.pending()
    }
}

/// Concrete trusted File owner row: logical ID/revision selects a pre-existing
/// installed Endpoint branch. No object tuple or approval can create authority.
pub struct SelectedObject {
    owner: SpaceId,
    source: Handle,
    identity: usize,
    view: picker::ObjectView,
}
impl SelectedObject {
    /// Trusted File service binding only. The view must be read from the actual
    /// single-writer object/version state, not accepted from the application.
    pub fn bind(
        a: &Authority,
        owner: SpaceId,
        source: Handle,
        view: picker::ObjectView,
    ) -> Result<Self, Error> {
        let access = a.authorize(
            owner,
            source,
            Kind::Endpoint,
            Rights::SEND | Rights::DERIVE | Rights::TRANSFER,
        )?;
        Ok(Self {
            owner,
            source,
            identity: access.identity(),
            view,
        })
    }
}
/// Acceptance is explicitly queued, never a claim that a runtime handle is
/// already installed. The ticket grants no permission and is not an app handle.
#[derive(Debug, PartialEq, Eq)]
pub enum AcceptedGrant {
    Queued(Ticket),
}
pub struct PickerHandoff<'a, 'm> {
    pub authority: &'a mut Authority,
    pub scheduler: &'a Scheduler,
    pub registry: &'a Registry<'m>,
    pub route: &'a mut SelectedReadRoute,
    pub root: Token,
    pub send: Handle,
    pub object: &'a SelectedObject,
    /// The application registry's CURRENT actual requester projection for the
    /// retained ProcessCONTROL target. This is trusted metadata, never authority.
    pub requester: picker::Requester,
    pub now: u64,
}
impl picker::Handoff for PickerHandoff<'_, '_> {
    type Delivered = AcceptedGrant;
    type Error = Error;
    fn revalidate_and_deliver_read(
        &mut self,
        request: picker::ReadDelivery<'_>,
    ) -> picker::Delivery<Self::Delivered, Error> {
        let selection = request.selection();
        let checked = (|| {
            if self.now >= selection.expiry() {
                return Err(Error::Expired);
            }
            if self.requester != selection.requester()
                || self.object.view != selection.object()
                || !self.requester.alive
                || !self.object.view.readable
            {
                return Err(Error::ChangedSelection);
            }
            if self.object.owner != self.route.controller {
                return Err(Error::WrongObject);
            }
            let actual = self.authority.authorize(
                self.object.owner,
                self.object.source,
                Kind::Endpoint,
                Rights::SEND | Rights::DERIVE | Rights::TRANSFER,
            )?;
            if actual.identity() != self.object.identity {
                return Err(Error::WrongObject);
            }
            let deadline =
                Deadline::after(self.now, selection.expiry() - self.now).ok_or(Error::Expired)?;
            self.route.enqueue(
                self.authority,
                self.scheduler,
                self.registry,
                self.root,
                self.send,
                self.object.source,
                b"EVREAD01",
                deadline,
                self.now,
            )
        })();
        match checked {
            Ok(ticket) => picker::Delivery::Delivered(AcceptedGrant::Queued(ticket)),
            Err(error) => picker::Delivery::Refused(error),
        }
    }
}

#[cfg(test)]
mod tests;
