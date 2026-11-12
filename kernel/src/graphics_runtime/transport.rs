//! Capability-selected opaque cap-free RPC, with one real retained wait/nonce.
//! Present syntax and rendering are owned by the measured user services.
use super::*;

impl Runtime<'_, '_> {
    fn endpoint(&self, domain: SpaceId, cap: Handle, rights: Rights) -> bool {
        self.a
            .authorize(domain, cap, Kind::Endpoint, rights)
            .is_ok_and(|access| access.identity() == self.present_object)
    }
    pub(super) fn call(
        &mut self,
        index: usize,
        endpoint: Handle,
        value: u64,
        absolute: u64,
        frame: &mut UserContext,
    ) -> bool {
        let caller = self.current(index);
        // Rejection precedes RPC acceptance, enqueue, wait generation and any
        // surface-credit transfer. No accepted timeout/cancellation is claimed.
        if absolute <= self.stop.tick() || absolute > self.stop.tick().checked_add(1024).unwrap() {
            scalar(frame, 4, 0);
            return false;
        }
        if !self.endpoint(caller.domain, endpoint, Rights::SEND) {
            scalar(frame, 1, 0);
            return false;
        }
        if self.pending.is_some() || self.present_box.pending() != 0 {
            scalar(frame, 2, 0);
            return false;
        }
        let deadline = Deadline::after(0, absolute).unwrap();
        if self.s.check_block(0, deadline).is_err() {
            scalar(frame, 4, 0);
            return false;
        }
        let now = crate::timer::now();
        let id = match self.rpc.begin(
            self.a,
            caller.thread,
            endpoint,
            deadline,
            MessageShape {
                bytes: 8,
                capabilities: 0,
            },
            now,
        ) {
            Ok(id) => id,
            Err(_) => {
                scalar(frame, 1, 0);
                return false;
            }
        };
        let callee = self.meta[0];
        let ticket = match self.present_box.send(
            self.a,
            caller.domain,
            endpoint,
            Outgoing {
                bytes: &value.to_le_bytes(),
                capability: None,
                deadline,
            },
            now,
        ) {
            Ok(ticket) => ticket,
            Err(_) => {
                self.rpc.cancel(caller.thread, id, now).unwrap();
                self.rpc.complete(callee.thread, id, now).unwrap();
                scalar(frame, 2, 0);
                return false;
            }
        };
        let context = self.rpc.context(id).unwrap();
        assert_eq!(context.origin_job, caller.job);
        assert_eq!(context.parent_call_id, None);
        assert_eq!(context.depth, 1);
        assert_eq!(context.trace_id.root(), id);
        assert_eq!(context.deadline, deadline);
        assert_eq!(context.root_incarnation, None);
        let wait = self
            .s
            .block(0, deadline)
            .expect("serialized actual wait preflight");
        assert!(self.s.waiting(wait));
        self.pending = Some(Pending {
            id,
            wait,
            ticket,
            request: value,
            delivered: false,
        });
        self.counters.calls += 1;
        self.counters.blocks += 1;
        scalar(frame, 0, 0);
        true
    }
    pub(super) fn receive(&mut self, index: usize, endpoint: Handle, frame: &mut UserContext) {
        let receiver = self.current(index);
        if !self.endpoint(receiver.domain, endpoint, RECEIVE) || receiver != self.meta[0] {
            extended(frame, 1, 0, 0);
            return;
        }
        let Some(mut pending) = self.pending else {
            extended(frame, 2, 0, 0);
            return;
        };
        if pending.delivered {
            extended(frame, 11, 0, 0);
            return;
        }
        assert_eq!(self.rpc.serving(receiver.thread), Some(pending.id));
        assert!(self.s.waiting(pending.wait));
        match self
            .present_box
            .receive(self.a, receiver.domain, endpoint, crate::timer::now())
        {
            Ok(delivery) => {
                assert_eq!(delivery.ticket, pending.ticket);
                assert_eq!((delivery.length, delivery.capability), (8, None));
                assert_eq!(&delivery.bytes[..8], &pending.request.to_le_bytes());
                pending.delivered = true;
                self.pending = Some(pending);
                extended(frame, 0, pending.request, pending.id.serial());
            }
            Err(IpcError::Empty) => extended(frame, 2, 0, 0),
            Err(_) => extended(frame, 1, 0, 0),
        }
    }
    pub(super) fn reply(
        &mut self,
        index: usize,
        endpoint: Handle,
        value: u64,
        serial: u64,
        frame: &mut UserContext,
    ) {
        let receiver = self.current(index);
        if !self.endpoint(receiver.domain, endpoint, RECEIVE) || receiver != self.meta[0] {
            extended(frame, 1, 0, 0);
            return;
        }
        let Some(pending) = self
            .pending
            .filter(|pending| pending.delivered && pending.id.serial() == serial)
        else {
            extended(frame, 11, 0, 0);
            return;
        };
        assert_eq!(self.rpc.serving(receiver.thread), Some(pending.id));
        assert!(self.s.waiting(pending.wait));
        // The sole App thread remains blocked through actual delivery and the
        // full userspace Display copy. No Rust/kernel internal lock is held.
        assert_eq!(
            self.s.state(self.meta[1].thread),
            Ok(State::Blocked {
                deadline: self.rpc.context(pending.id).unwrap().deadline,
                ticket: pending.wait
            })
        );
        let completion = self
            .rpc
            .complete(receiver.thread, pending.id, crate::timer::now())
            .unwrap();
        assert_eq!(completion.call, pending.id);
        assert_eq!(completion.caller, self.meta[1].thread);
        assert_eq!(completion.status, Status::Ok);
        assert!(completion.deliver_reply && completion.wake_caller);
        scalar(&mut self.actors[1].as_mut().unwrap().context, 0, value);
        assert!(self.s.wake(pending.wait));
        assert!(!self.s.wake(pending.wait));
        self.pending = None;
        self.counters.replies += 1;
        self.counters.wakes += 1;
        extended(frame, 0, 0, 0);
    }
}
