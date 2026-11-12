//! One actual App incarnation, with distinct current/pending revocation parents.
//! The fixed FileRO object is rechecked independently of the UI request packet.
use super::*;
#[cfg(feature = "test-m5-native")]
mod managed;
use ev_kernel::{live_grant::SelectedReadRoute, service::ActiveGrantBranch};
struct PendingGrant {
    branch: ActiveGrantBranch,
    ticket: Ticket,
    delivered: bool,
}
pub(super) struct Grants {
    route: Option<SelectedReadRoute>,
    current: Option<ActiveGrantBranch>,
    pending: Option<PendingGrant>,
}
impl Grants {
    pub fn new() -> Self {
        Self {
            route: None,
            current: None,
            pending: None,
        }
    }
    #[cfg(not(feature = "test-m5-native"))]
    pub fn current_target(&self) -> Option<Metadata> {
        self.current.as_ref().map(ActiveGrantBranch::metadata)
    }
}
impl Runtime<'_, '_> {
    pub(super) fn configure_grants(&mut self, control: Handle) {
        let wire = self.wires[Channel::GrantInbox.index()].as_mut().unwrap();
        assert!(self.grants.route.is_none());
        let mailbox = wire.mailbox.take().unwrap();
        // The endpoint's retained Root CONTROL capability is the exact same
        // identity; its handle is retained by the trusted bind receipt below.
        let endpoint = wire.control.expect("actual Root endpoint control");
        self.grants.route = Some(
            SelectedReadRoute::from_managed(
                self.a,
                self.s,
                self.registry,
                self.token,
                self.root.meta.domain,
                control,
                6,
                endpoint,
                mailbox,
            )
            .unwrap_or_else(|r| panic!("selected managed route: {:?}", r.error)),
        );
    }
    pub(super) fn grant_selected(&mut self, index: usize, frame: &mut UserContext) {
        if index != 0 {
            extended(frame, 1, 0, 0);
            return;
        }
        let target = Handle(frame.registers[8]);
        let source = Handle(frame.registers[9]);
        let inbox = Handle(frame.registers[11]);
        let request = frame.registers[5];
        let Some(selection) = self.selection else {
            extended(frame, 1, 0, 0);
            return;
        };
        let Some((actual, serial)) = self.open else {
            extended(frame, 1, 0, 0);
            return;
        };
        if request != serial as u64
            || selection.request != serial
            || selection.target != actual
            || self.find_control(self.root.meta.domain, target) != Ok(Child::App.index() + 1)
            || self.metadata(Child::App.index() + 1) != Some(actual)
        {
            extended(frame, 1, 0, 0);
            return;
        }
        let Some(w) = self.wire(self.root.meta, inbox, Rights::SEND) else {
            extended(frame, 1, 0, 0);
            return;
        };
        if w != Channel::GrantInbox.index()
            || !self
                .a
                .authorize(
                    self.root.meta.domain,
                    source,
                    Kind::Endpoint,
                    Rights::SEND | Rights::DERIVE | Rights::TRANSFER | Rights::REVOKE,
                )
                .is_ok_and(|access| {
                    self.wires[selection.wire]
                        .as_ref()
                        .is_some_and(|w| w.object == access.identity())
                })
        {
            extended(frame, 1, 0, 0);
            return;
        }
        let snapshot = self.snapshots[usize::from(selection.wire == Channel::PrivateRead.index())];
        if snapshot.stage != 6 || snapshot.tick < selection.tick || snapshot.words == [0; 4] {
            extended(frame, 1, 0, 0);
            return;
        }
        if self.grants.pending.is_some()
            || self.grants.route.as_ref().is_none_or(|r| r.pending() != 0)
        {
            extended(frame, 2, 0, 0);
            return;
        }
        let (branch, one_shot) = match self.registry.prepare_active_send(
            self.a,
            self.s,
            self.root.meta.domain,
            target,
            source,
        ) {
            Ok(x) => x,
            Err(_) => {
                extended(frame, 1, 0, 0);
                return;
            }
        };
        let result = self.grants.route.as_mut().unwrap().enqueue(
            self.a,
            self.s,
            self.registry,
            self.token,
            inbox,
            one_shot,
            b"EVREAD01",
            self.stop,
            crate::timer::now(),
        );
        match result {
            Ok(ticket) => {
                self.grants.pending = Some(PendingGrant {
                    branch,
                    ticket,
                    delivered: false,
                });
                extended(frame, 0, ticket.0, 0);
            }
            Err(error) => {
                // No acceptance occurred. Preserve the private parent owner on
                // any unexpected refusal; source/file receiver remain intact.
                self.a.close(self.root.meta.domain, one_shot).unwrap();
                branch
                    .retire(self.a)
                    .unwrap_or_else(|r| panic!("grant refusal parent: {:?}", r.error));
                extended(
                    frame,
                    if matches!(error, ev_kernel::live_grant::Error::Ipc(IpcError::Full)) {
                        2
                    } else {
                        1
                    },
                    0,
                    0,
                );
            }
        }
    }
    pub(super) fn receive_grant(&mut self, index: usize, frame: &mut UserContext) {
        if index != Child::App.index() + 1 {
            scalar(frame, 1, 0);
            return;
        }
        let thread = self.current(index).thread;
        let Some(route) = self.grants.route.as_mut() else {
            scalar(frame, 1, 0);
            return;
        };
        match route.receive(
            self.a,
            self.s,
            self.registry,
            self.token,
            thread,
            crate::timer::now(),
        ) {
            Ok(delivery) => {
                let pending = self.grants.pending.as_mut().expect("actual accepted grant");
                assert_eq!(pending.ticket, delivery.ticket);
                assert!(!pending.delivered);
                pending.delivered = true;
                self.facts.grants += 1;
                scalar(
                    frame,
                    0,
                    u64::from_le_bytes(delivery.bytes[..8].try_into().unwrap()),
                );
                frame.registers[11] = delivery.capability.unwrap().0;
            }
            Err(ev_kernel::live_grant::Error::Ipc(IpcError::Empty)) => scalar(frame, 2, 0),
            Err(_) => scalar(frame, 1, 0),
        }
    }
    pub(super) fn promote_grant(&mut self) {
        if let Some(pending) = self.grants.pending.take() {
            assert!(
                pending.delivered,
                "read event must follow actual capability delivery"
            );
            if let Some(old) = self.grants.current.take() {
                old.retire(self.a)
                    .unwrap_or_else(|r| panic!("previous selected parent: {:?}", r.error));
            }
            self.grants.current = Some(pending.branch);
        }
    }
    pub(super) fn stop_grants(&mut self) {
        if let Some(pending) = self.grants.pending.take() {
            if !pending.delivered {
                let reclaimed = self
                    .grants
                    .route
                    .as_mut()
                    .unwrap()
                    .cancel(self.a, pending.ticket, crate::timer::now())
                    .unwrap();
                if let ev_kernel::ipc::Reclaimed::Capability(cap) = reclaimed {
                    self.a.close(self.root.meta.domain, cap).unwrap();
                }
            }
            pending
                .branch
                .retire(self.a)
                .unwrap_or_else(|r| panic!("stopped pending grant: {:?}", r.error));
        }
        if let Some(current) = self.grants.current.take() {
            current
                .retire(self.a)
                .unwrap_or_else(|r| panic!("stopped current grant: {:?}", r.error));
        }
        if let Some(mut route) = self.grants.route.take() {
            route.receiver_died(self.s).unwrap();
            let mailbox = route
                .into_stopped_mailbox(self.a, self.s, self.registry)
                .unwrap_or_else(|r| panic!("stopped selected owner: {:?}", r.error));
            let wire = self.wires[Channel::GrantInbox.index()].as_mut().unwrap();
            wire.mailbox = Some(mailbox);
            wire.closed = true;
        }
        self.open = None;
        self.awaiting_open = None;
        self.selection = None;
        self.picker = None;
    }
}
