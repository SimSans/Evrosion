//! Native3 Root-only live authority mechanisms. Durable owner policy and
//! choices remain SourceRoot's responsibility; accepted work retains its owners.
use super::*;
use ev_kernel::service::managed_read::{self, Context, Mode, Open, Request};
use ev_userspace_contract::root_v2::native::catalogue::BootMode;
impl Runtime<'_, '_> {
    pub(in crate::desktop_runtime) fn grant_managed(
        &mut self,
        index: usize,
        process: Handle,
        source: Handle,
        inbox: Handle,
        nonce: u32,
        frame: &mut UserContext,
    ) {
        if index != 0
            || self
                .native
                .as_ref()
                .is_none_or(|n| n.boot_mode == BootMode::Recovery)
            || self.find_control(self.root.meta.domain, process) != Ok(Child::App.index() + 1)
        {
            extended(frame, 1, 0, 0);
            return;
        }
        let Some(app) = self.metadata(Child::App.index() + 1) else {
            extended(frame, 1, 0, 0);
            return;
        };
        let Some(file) = self.metadata(Child::File.index() + 1) else {
            extended(frame, 1, 0, 0);
            return;
        };
        let Some(route) = self.grants.route.as_ref() else {
            extended(frame, 2, 0, 0);
            return;
        };
        let target = route.target_metadata();
        let read_wire = |channel: Channel| {
            self.wires[channel.index()]
                .as_ref()
                .map(|w| managed_read::Wire {
                    object: w.object,
                    receiver: w.receiver,
                    bound: w.bound,
                    closed: w.closed,
                })
        };
        let [Some(notes), Some(private)] = [
            read_wire(Channel::NotesRead),
            read_wire(Channel::PrivateRead),
        ] else {
            extended(frame, 1, 0, 0);
            return;
        };
        let Some(wire) = self.wires[Channel::GrantInbox.index()].as_ref() else {
            extended(frame, 1, 0, 0);
            return;
        };
        let context = Context {
            mode: Mode::ManagedNative3,
            caller: self.current(index),
            root: self.root.meta,
            token: self.token,
            app,
            file,
            read_sources: [notes, private],
            // GrantInbox is a selected mailbox, not an RPC endpoint. Its exact
            // receiving thread comes from the retained admitted route readback.
            inbox: managed_read::Wire {
                object: wire.object,
                receiver: wire.receiver,
                bound: Some(target.thread),
                closed: wire.closed,
            },
            selection_submitted: self.selection.is_some(),
        };
        let grant::Grants { route, pending, .. } = &mut self.grants;
        let result = managed_read::enqueue(
            self.a,
            self.s,
            self.registry,
            &context,
            Open {
                last_nonce: &mut self.request,
                awaiting: &mut self.awaiting_open,
                active: &mut self.open,
            },
            pending.as_ref().map(|p| &p.branch),
            route.as_mut().unwrap(),
            Request {
                process,
                source,
                inbox,
                nonce,
            },
            self.stop,
            crate::timer::now(),
        );
        match result {
            Ok(queued) => {
                let ticket = queued.ticket;
                *pending = Some(PendingGrant {
                    branch: queued.branch,
                    ticket,
                    delivered: false,
                });
                (self.observations)(Observation::NativeManagedRead(NativeManagedRead {
                    root_process: self.root.meta.process.diagnostic_id(),
                    root_thread: self.root.meta.thread.diagnostic_id(),
                    process: app.process.diagnostic_id(),
                    thread: app.thread.diagnostic_id(),
                    image_sha256: self.actors[Child::App.index()]
                        .as_ref()
                        .unwrap()
                        .image_sha256,
                    source_endpoint: queued.source_object,
                    inbox_endpoint: context.inbox.object,
                    nonce: queued.nonce,
                    ticket: ticket.0,
                }));
                // The pending request changed route only after real acceptance.
                // Invalidate old GUI bookkeeping; never fabricate selection.
                self.selection = None;
                self.picker = None;
                self.barrier = None;
                extended(frame, 0, ticket.0, 0);
            }
            Err(managed_read::Error::Busy) => extended(frame, 2, 0, 0),
            Err(_) => extended(frame, 1, 0, 0),
        }
    }
    pub(in crate::desktop_runtime) fn inhibit_managed(
        &mut self,
        index: usize,
        cap: Handle,
    ) -> Result<(), u64> {
        if index != 0
            || self
                .native
                .as_ref()
                .is_none_or(|n| n.boot_mode == BootMode::Recovery)
            || self.s.state(self.root.meta.thread) != Ok(State::Running(0))
        {
            return Err(1);
        }
        let target = self.find_control(self.root.meta.domain, cap)?;
        if target != Child::App.index() + 1 {
            return Err(1);
        }
        let actor = self.actors[target - 1].as_ref().ok_or(1u64)?;
        if !actor.admitted
            || actor.retired
            || actor.running.is_none()
            || self.s.thread_process(actor.meta.thread) != Ok(actor.meta.process)
            || self.s.process_job(actor.meta.process) != Ok(actor.meta.job)
            || self.s.state(actor.meta.thread) == Ok(State::Exited)
        {
            return Err(1);
        }
        // Refuse BEFORE mutation: a serving App must execute to complete its
        // accepted request, even if it is itself waiting on a nested callee.
        if self.pending.iter().flatten().any(|p| p.callee == target)
            || matches!(self.s.state(actor.meta.thread), Ok(State::Running(_)))
        {
            return Err(2);
        }
        let receipt = NativeInhibit {
            root_process: self.root.meta.process.diagnostic_id(),
            root_thread: self.root.meta.thread.diagnostic_id(),
            process: actor.meta.process.diagnostic_id(),
            thread: actor.meta.thread.diagnostic_id(),
            image_sha256: actor.image_sha256,
            outbound_pending: self
                .pending
                .iter()
                .flatten()
                .filter(|p| p.caller == target)
                .count() as u64,
        };
        let context = managed_read::InhibitContext {
            mode: Mode::ManagedNative3,
            caller: self.current(index),
            root: self.root.meta,
            token: self.token,
            app: actor.meta,
        };
        managed_read::inhibit(
            self.a,
            self.s,
            self.registry,
            self.rpc,
            &context,
            cap,
            self.actors[target - 1]
                .as_mut()
                .unwrap()
                .running
                .as_mut()
                .unwrap(),
        )
        .map_err(|e| {
            if matches!(e, managed_read::Error::Busy) {
                2u64
            } else {
                1u64
            }
        })?;
        (self.observations)(Observation::NativeInhibit(receipt));
        Ok(())
    }
}
