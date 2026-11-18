//! Root-owned pending scalar production, not a second IPC/authority model.
//! A slot is reserved before a source transition; only an actual SEND success
//! consumes its published entry. Actual target controls/identities are checked
//! by the adapter on every attempt. This module never retries accepted work.
#![forbid(unsafe_code)]
#[path = "desktop_outbox/dispatch.rs"]
pub mod dispatch;
const PER_PEER: usize = 8;
const SLOTS: usize = PER_PEER * 2;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Peer {
    App,
    Shell,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    pub peer: Peer,
    pub endpoint: u64,
    pub control: u64,
    pub process: u64,
    pub thread: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Control,
    Input,
    Data,
    Note,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ticket(u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub ticket: Ticket,
    pub target: Target,
    pub bytes: [u8; 8],
    pub deadline: u64,
    pub kind: Kind,
}
#[derive(Clone, Copy)]
enum Slot {
    Reserved(Ticket, Target),
    Ready(Entry),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Full,
    Batch,
    Counter,
    Reservation,
    Deadline,
    Target,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Accepted,
    Expired,
    Cancelled,
    Refused,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub accepted: u64,
    pub expired: u64,
    pub cancelled: u64,
    pub refused: u64,
}
pub struct Outbox {
    slots: [Option<Slot>; SLOTS],
    serial: u64,
    batch: bool,
    turn: usize,
    stats: Stats,
}
impl Default for Outbox {
    fn default() -> Self {
        Self::new()
    }
}
impl Outbox {
    pub const fn new() -> Self {
        Self {
            slots: [None; SLOTS],
            serial: 0,
            batch: false,
            turn: 0,
            stats: Stats {
                accepted: 0,
                expired: 0,
                cancelled: 0,
                refused: 0,
            },
        }
    }
    pub fn stats(&self) -> Stats {
        self.stats
    }
    pub fn pending(&self) -> bool {
        self.slots
            .iter()
            .flatten()
            .any(|s| matches!(s, Slot::Ready(_)))
    }
    pub fn available(&self, peer: Peer) -> usize {
        self.slots[peer as usize * PER_PEER..(peer as usize + 1) * PER_PEER]
            .iter()
            .filter(|s| s.is_none())
            .count()
    }
    /// Reserve an entire fanout before source state/I/O changes. A missing peer
    /// requires no output; an existing peer's full queue cannot steal the other
    /// peer's capacity. Counter exhaustion is preflighted before any reservation.
    pub fn begin(&mut self, targets: [Option<Target>; 2], needed: [usize; 2]) -> Result<(), Error> {
        if self.batch {
            return Err(Error::Batch);
        }
        for (index, target) in targets.iter().enumerate() {
            if let Some(t) = target {
                if t.peer as usize != index
                    || [t.endpoint, t.control, t.process, t.thread].contains(&0)
                {
                    return Err(Error::Target);
                }
                if needed[index] > self.available(t.peer) {
                    return Err(Error::Full);
                }
            }
        }
        let count = targets
            .iter()
            .zip(needed)
            .filter_map(|(t, n)| t.map(|_| n))
            .sum::<usize>();
        let end = self
            .serial
            .checked_add(count as u64)
            .ok_or(Error::Counter)?;
        for (index, target) in targets.into_iter().enumerate() {
            if let Some(target) = target {
                let mut left = needed[index];
                for slot in &mut self.slots[index * PER_PEER..(index + 1) * PER_PEER] {
                    if left == 0 {
                        break;
                    }
                    if slot.is_none() {
                        self.serial += 1;
                        *slot = Some(Slot::Reserved(Ticket(self.serial), target));
                        left -= 1;
                    }
                }
                debug_assert_eq!(left, 0);
            }
        }
        debug_assert_eq!(self.serial, end);
        self.batch = true;
        Ok(())
    }
    pub fn reserved(&self, target: Target) -> Option<Ticket> {
        self.slots
            .iter()
            .flatten()
            .filter_map(|s| match s {
                Slot::Reserved(ticket, t) if *t == target => Some(*ticket),
                _ => None,
            })
            .min_by_key(|t| t.0)
    }
    pub fn publish(
        &mut self,
        ticket: Ticket,
        bytes: [u8; 8],
        deadline: u64,
        kind: Kind,
    ) -> Result<(), Error> {
        if !self.batch {
            return Err(Error::Batch);
        }
        if matches!(deadline, 0 | u64::MAX) {
            return Err(Error::Deadline);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|s| matches!(s,Some(Slot::Reserved(t,_))if *t==ticket))
            .ok_or(Error::Reservation)?;
        let Some(Slot::Reserved(_, target)) = *slot else {
            unreachable!()
        };
        *slot = Some(Slot::Ready(Entry {
            ticket,
            target,
            bytes,
            deadline,
            kind,
        }));
        Ok(())
    }
    pub fn end(&mut self) {
        for s in &mut self.slots {
            if matches!(s, Some(Slot::Reserved(..))) {
                *s = None
            }
        }
        self.batch = false;
    }
    /// At most one actual attempt per ordinary tick. Busy rotates to the other
    /// peer on its next tick, while each peer retains its own exact FIFO head.
    pub fn next_attempt(&mut self) -> Option<Entry> {
        if self.batch {
            return None;
        }
        for offset in 0..2 {
            let peer = (self.turn + offset) % 2;
            // Compare retained entries by reference, then copy only the exact
            // selected FIFO head. Tickets are unique across all retained slots.
            let mut first: Option<&Entry> = None;
            for slot in &self.slots[peer * PER_PEER..(peer + 1) * PER_PEER] {
                if let Some(Slot::Ready(entry)) = slot
                    && first.is_none_or(|old| entry.ticket.0 < old.ticket.0)
                {
                    first = Some(entry);
                }
            }
            if let Some(entry) = first {
                self.turn = 1 - peer;
                return Some(*entry);
            }
        }
        None
    }
    pub fn finish(&mut self, ticket: Ticket, outcome: Outcome) -> Option<Entry> {
        let slot = self
            .slots
            .iter_mut()
            .find(|s| matches!(s,Some(Slot::Ready(e))if e.ticket==ticket))?;
        let Some(Slot::Ready(entry)) = *slot else {
            unreachable!()
        };
        let counter = match outcome {
            Outcome::Accepted => &mut self.stats.accepted,
            Outcome::Expired => &mut self.stats.expired,
            Outcome::Cancelled => &mut self.stats.cancelled,
            Outcome::Refused => &mut self.stats.refused,
        };
        *counter = counter
            .checked_add(1)
            .expect("source outbox outcome counter exhausted");
        *slot = None;
        Some(entry)
    }
    pub fn cancel_target(&mut self, target: Target) -> Option<Entry> {
        let ticket = self
            .slots
            .iter()
            .flatten()
            .filter_map(|s| match s {
                Slot::Ready(e) if e.target == target => Some(e.ticket),
                _ => None,
            })
            .min_by_key(|t| t.0)?;
        self.finish(ticket, Outcome::Cancelled)
    }
}
/// Shell actually acknowledges every applied typed control. Only deliberate
/// CrashShell completes through the real fault/reap path instead of an ACK.
#[cfg(feature = "desktop-root")]
pub fn control_needs_settlement(bytes: [u8; 8]) -> bool {
    use ev_desktop::protocol::RootControl;
    RootControl::decode(bytes).is_ok_and(|v| v != RootControl::CrashShell)
}
/// A later control's ACK cannot jump an earlier debt, and one actual ACK can
/// consume only one front entry for the actual full target incarnation.
pub fn matching_front<'a>(
    entries: impl Iterator<Item = (usize, &'a Entry)>,
    target: Target,
    bytes: [u8; 8],
) -> Option<usize> {
    entries
        .filter(|(_, entry)| entry.target == target)
        .min_by_key(|(_, entry)| entry.ticket)
        .filter(|(_, entry)| entry.bytes == bytes)
        .map(|(i, _)| i)
}
/// An already stopped App cannot consume its output. Its retirement emits
/// only the Shell notification, and must reach actual reap before cancelling
/// old App output/loan debt. Shell retirement can notify both surviving peers.
pub const fn retirement_slots(stopped: Peer) -> [usize; 2] {
    match stopped {
        Peer::App => [0, 1],
        Peer::Shell => [1, 1],
    }
}
/// Bounded source ingress. App work has a four-item ceiling so it cannot
/// consume the trusted peer's entire staging space. Ready-peer selection skips
/// a blocked peer while preserving every retained peer's own arrival order.
pub struct Ingress<T: Copy> {
    slots: [Option<(Peer, T)>; 8],
}
impl<T: Copy> Default for Ingress<T> {
    fn default() -> Self {
        Self::new()
    }
}
impl<T: Copy> Ingress<T> {
    pub const fn new() -> Self {
        Self { slots: [None; 8] }
    }
    pub fn pending(&self) -> bool {
        self.slots.iter().any(Option::is_some)
    }
    pub fn push(&mut self, peer: Peer, item: T) -> Result<(), T> {
        if peer == Peer::App
            && self
                .slots
                .iter()
                .flatten()
                .filter(|(p, _)| *p == peer)
                .count()
                >= 4
        {
            return Err(item);
        }
        let Some(slot) = self.slots.iter_mut().find(|s| s.is_none()) else {
            return Err(item);
        };
        *slot = Some((peer, item));
        Ok(())
    }
    pub fn first_ready(&self, ready: [bool; 2]) -> Option<(usize, T)> {
        self.slots.iter().enumerate().find_map(|(i, slot)| {
            slot.filter(|(peer, _)| ready[*peer as usize])
                .map(|(_, item)| (i, item))
        })
    }
    pub fn remove(&mut self, index: usize) -> Option<T> {
        let (_, item) = self.slots.get_mut(index)?.take()?;
        self.slots[index..].rotate_left(1);
        self.slots[7] = None;
        Some(item)
    }
    pub fn retain(&mut self, mut keep: impl FnMut(T) -> bool) {
        let mut i = 0;
        while i < self.slots.len() {
            if self.slots[i].is_some_and(|(_, item)| !keep(item)) {
                self.remove(i);
            } else {
                i += 1;
            }
        }
    }
}
/// An overload debt remains bound to exactly the old App. Repeated traffic is
/// counted without replacing the first request. Only the adapter's actual
/// stop/reap path may clear this debt or release a retained reply/body.
#[derive(Clone, Copy)]
pub struct Quarantine {
    pub target: Target,
    pub first: [u8; 8],
    pub messages: u64,
    pub inhibited: bool,
    pub stopped: bool,
}
impl Quarantine {
    pub fn new(target: Target, first: [u8; 8]) -> Self {
        Self {
            target,
            first,
            messages: 1,
            inhibited: false,
            stopped: false,
        }
    }
    pub fn record(&mut self, target: Target) -> bool {
        if self.target != target {
            return false;
        }
        self.messages = self
            .messages
            .checked_add(1)
            .expect("quarantine ingress count exhausted");
        true
    }
    pub fn is_target(&self, target: Target) -> bool {
        self.target == target
    }
}
/// UI work is bound at receipt, before deferred handling or output enqueue.
/// Sequence numbers carried by the sender alone cannot name a replacement App.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UiContext {
    pub app: Option<Target>,
    pub app_epoch: u32,
    pub ui_revision: u64,
    pub input_epoch: u32,
    pub shell_epoch: u32,
    pub picker: Option<(u32, bool, bool)>,
    pub ready: bool,
}
impl UiContext {
    pub fn matches(self, current: Self) -> bool {
        self == current
    }
}
/// One retained source reply copy. This is private producer work, not evidence
/// that hardware/shared backing quiesced. Cancelled may be supplied only after
/// the adapter establishes actual old-target stop/reap or equivalent identity.
pub struct RetainedReply {
    ticket: Ticket,
    target: Target,
    body: Option<[u8; 256]>,
    failed: bool,
    released: bool,
}
impl RetainedReply {
    pub fn new(ticket: Ticket, target: Target, body: Option<[u8; 256]>) -> Self {
        Self {
            ticket,
            target,
            body,
            failed: false,
            released: false,
        }
    }
    pub fn ready(&self, entry: Entry) -> bool {
        !self.failed
            && !self.released
            && self.ticket == entry.ticket
            && self.target == entry.target
            && entry.kind == Kind::Note
    }
    pub fn body(&self) -> Option<&[u8; 256]> {
        self.body.as_ref()
    }
    pub fn complete(&mut self, entry: Entry, outcome: Outcome) -> bool {
        if self.released
            || self.ticket != entry.ticket
            || self.target != entry.target
            || entry.kind != Kind::Note
        {
            return false;
        }
        match outcome {
            Outcome::Accepted | Outcome::Cancelled => {
                self.released = true;
                true
            }
            Outcome::Expired | Outcome::Refused => {
                self.failed = true;
                false
            }
        }
    }
    pub fn cancelled_target(&self, target: Target) -> bool {
        !self.released && self.target == target
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn target(peer: Peer, process: u64) -> Target {
        Target {
            peer,
            endpoint: 11 + peer as u64,
            control: 21 + process,
            process,
            thread: process,
        }
    }
    fn queue(q: &mut Outbox, t: Target, value: u8, cut: u64) -> Ticket {
        let mut targets = [None; 2];
        targets[t.peer as usize] = Some(t);
        let mut needs = [0; 2];
        needs[t.peer as usize] = 1;
        q.begin(targets, needs).unwrap();
        let ticket = q.reserved(t).unwrap();
        q.publish(ticket, [value; 8], cut, Kind::Control).unwrap();
        q.end();
        ticket
    }
    #[test]
    fn busy_retains_exact_head_rotates_peer_and_never_replays_accepted_send() {
        let mut q = Outbox::new();
        let app = target(Peer::App, 1);
        let shell = target(Peer::Shell, 2);
        let a = queue(&mut q, app, 3, 512);
        let b = queue(&mut q, app, 4, 513);
        let s = queue(&mut q, shell, 5, 514);
        let first = q.next_attempt().unwrap();
        assert_eq!(first.ticket, a);
        assert_eq!(
            q.next_attempt().unwrap().ticket,
            s,
            "blocked App does not monopolize Shell"
        );
        q.finish(s, Outcome::Accepted).unwrap();
        assert_eq!(
            q.next_attempt().unwrap(),
            first,
            "Busy changes no bytes/cut/target/ticket"
        );
        q.finish(a, Outcome::Accepted).unwrap();
        assert!(q.finish(a, Outcome::Accepted).is_none());
        assert_eq!(q.next_attempt().unwrap().ticket, b);
        assert_eq!(q.stats().accepted, 2);
    }
    #[test]
    fn fanout_reservation_refuses_before_any_change_and_unused_slots_release() {
        let mut q = Outbox::new();
        let app = target(Peer::App, 1);
        let shell = target(Peer::Shell, 2);
        for _ in 0..8 {
            queue(&mut q, app, 3, 512);
        }
        let serial = q.serial;
        assert_eq!(q.begin([Some(app), Some(shell)], [1, 2]), Err(Error::Full));
        assert_eq!(q.serial, serial);
        assert_eq!(q.available(Peer::Shell), 8);
        q.begin([None, Some(shell)], [0, 2]).unwrap();
        let t = q.reserved(shell).unwrap();
        q.publish(t, [9; 8], 512, Kind::Control).unwrap();
        assert!(q.next_attempt().is_none());
        q.end();
        assert_eq!(q.available(Peer::Shell), 7);
    }
    #[test]
    fn cancellation_matches_full_old_target_and_stale_ticket_never_consumes_replacement() {
        let mut q = Outbox::new();
        let old = target(Peer::App, 1);
        let new = target(Peer::App, 3);
        let a = queue(&mut q, old, 3, 512);
        let b = queue(&mut q, new, 4, 513);
        assert_eq!(q.cancel_target(old).unwrap().ticket, a);
        assert!(q.cancel_target(old).is_none());
        assert!(q.finish(a, Outcome::Accepted).is_none());
        assert_eq!(q.next_attempt().unwrap().ticket, b);
    }
    #[test]
    fn invalid_targets_cuts_and_exhaustion_never_publish_or_wrap() {
        let mut q = Outbox::new();
        let app = target(Peer::App, 1);
        q.serial = u64::MAX;
        assert_eq!(q.begin([Some(app), None], [1, 0]), Err(Error::Counter));
        assert_eq!(q.available(Peer::App), 8);
        q.serial = 0;
        q.begin([Some(app), None], [1, 0]).unwrap();
        let t = q.reserved(app).unwrap();
        for cut in [0, u64::MAX] {
            assert_eq!(q.publish(t, [3; 8], cut, Kind::Note), Err(Error::Deadline));
        }
        q.end();
        assert!(!q.pending());
    }
    #[test]
    fn note_reply_failure_retains_exact_body_and_route_until_real_cancel_or_accept() {
        let mut q = Outbox::new();
        let target = target(Peer::App, 1);
        let ticket = queue(&mut q, target, 3, 512);
        let mut entry = q.next_attempt().unwrap();
        entry.kind = Kind::Note;
        let mut reply = RetainedReply::new(ticket, target, Some([7; 256]));
        assert!(reply.ready(entry));
        assert!(!reply.complete(entry, Outcome::Expired));
        assert_eq!(reply.body(), Some(&[7; 256]));
        assert!(!reply.ready(entry));
        let mut wrong = entry;
        wrong.target.process += 1;
        assert!(!reply.complete(wrong, Outcome::Cancelled));
        assert!(!reply.cancelled_target(wrong.target));
        assert!(reply.complete(entry, Outcome::Cancelled));
        assert!(!reply.complete(entry, Outcome::Accepted));
    }
    #[test]
    fn reply_cannot_publish_or_release_for_other_ticket_or_new_incarnation() {
        let mut q = Outbox::new();
        let old = target(Peer::App, 1);
        let ticket = queue(&mut q, old, 3, 512);
        let mut entry = q.next_attempt().unwrap();
        entry.kind = Kind::Note;
        let mut reply = RetainedReply::new(ticket, old, None);
        assert!(reply.ready(entry));
        let mut new = entry;
        new.target = target(Peer::App, 2);
        assert!(!reply.ready(new));
        assert!(!reply.complete(new, Outcome::Accepted));
        assert!(reply.ready(entry));
        assert!(reply.complete(entry, Outcome::Accepted));
        assert!(!reply.ready(entry));
    }
    #[test]
    fn inbound_busy_before_old_note_attempt_keeps_exact_old_body_and_fifo() {
        use ev_userspace_contract::session_note::{
            Operation, Outcome as NoteOutcome, Refusal, Request,
        };
        let mut q = Outbox::new();
        let old = target(Peer::App, 1);
        q.begin([Some(old), None], [1, 0]).unwrap();
        let note = q.reserved(old).unwrap();
        q.publish(note, [3; 8], 512, Kind::Note).unwrap();
        q.end();
        let mut retained = RetainedReply::new(note, old, Some([7; 256]));
        // New inbound work may now precede the existing outbound attempt.
        // Its Busy response must stay behind the retained old Note head.
        q.begin([Some(old), None], [1, 0]).unwrap();
        let busy = q.reserved(old).unwrap();
        let request = Request::new(Operation::Read, 2).unwrap();
        q.publish(
            busy,
            request.reply(NoteOutcome::Refused(Refusal::Busy)).encode(),
            512,
            Kind::Data,
        )
        .unwrap();
        q.end();
        let entry = q.next_attempt().unwrap();
        assert_eq!(entry.ticket, note);
        assert!(retained.ready(entry));
        assert_eq!(retained.body(), Some(&[7; 256]));
        let mut foreign = entry;
        foreign.target = target(Peer::App, 2);
        assert!(!retained.complete(foreign, Outcome::Cancelled));
        assert!(retained.ready(entry));
        assert_eq!(retained.body(), Some(&[7; 256]));
        q.finish(note, Outcome::Accepted).unwrap();
        assert!(retained.complete(entry, Outcome::Accepted));
        assert_eq!(q.next_attempt().unwrap().ticket, busy);
        assert!(!retained.complete(entry, Outcome::Accepted));
    }
    #[test]
    fn blocked_app_does_not_hold_trusted_ingress_and_each_peer_keeps_order() {
        let mut q = Ingress::new();
        for n in 0..4 {
            q.push(Peer::App, n).unwrap();
        }
        assert_eq!(q.push(Peer::App, 99), Err(99));
        q.push(Peer::Shell, 10).unwrap();
        q.push(Peer::Shell, 11).unwrap();
        let (at, value) = q.first_ready([false, true]).unwrap();
        assert_eq!(value, 10);
        q.remove(at);
        assert_eq!(q.first_ready([false, true]).unwrap().1, 11);
        assert_eq!(q.first_ready([true, true]).unwrap().1, 0);
        q.retain(|n| n >= 10);
        assert_eq!(q.first_ready([true, true]).unwrap().1, 11);
    }
    #[test]
    fn overload_retains_first_old_request_and_never_matches_replacement() {
        let old = target(Peer::App, 1);
        let new = target(Peer::App, 2);
        let mut q = Quarantine::new(old, *b"NT-first");
        assert!(q.record(old));
        assert_eq!(q.messages, 2);
        assert_eq!(q.first, *b"NT-first");
        assert!(!q.record(new));
        assert_eq!(q.messages, 2);
        assert!(!q.is_target(new));
        assert!(!q.inhibited && !q.stopped);
    }
    #[test]
    fn deferred_ui_rejects_new_incarnation_epoch_picker_or_readiness() {
        let original = UiContext {
            app: Some(target(Peer::App, 1)),
            app_epoch: 1,
            ui_revision: 1,
            input_epoch: 2,
            shell_epoch: 3,
            picker: Some((4, true, false)),
            ready: true,
        };
        assert!(original.matches(original));
        let mut changed = original;
        changed.app = Some(target(Peer::App, 2));
        assert!(!original.matches(changed));
        changed = original;
        changed.app_epoch += 1;
        assert!(!original.matches(changed));
        changed = original;
        changed.ui_revision += 1;
        assert!(!original.matches(changed));
        changed = original;
        changed.input_epoch += 1;
        assert!(!original.matches(changed));
        changed = original;
        changed.shell_epoch += 1;
        assert!(!original.matches(changed));
        changed = original;
        changed.picker = Some((5, true, false));
        assert!(!original.matches(changed));
        changed = original;
        changed.ready = false;
        assert!(!original.matches(changed));
    }
    #[test]
    fn stopped_app_retirement_reserves_shell_even_when_old_app_output_is_full() {
        let mut q = Outbox::new();
        let app = target(Peer::App, 1);
        let shell = target(Peer::Shell, 2);
        for n in 0..8 {
            queue(&mut q, app, n, 512);
        }
        assert_eq!(q.available(Peer::App), 0);
        q.begin([Some(app), Some(shell)], retirement_slots(Peer::App))
            .unwrap();
        assert!(q.reserved(app).is_none());
        let ticket = q.reserved(shell).unwrap();
        q.publish(ticket, *b"APP-STOP", 512, Kind::Control).unwrap();
        q.end();
        // Reservation/notification alone releases no old request or reply.
        assert_eq!(q.available(Peer::App), 0);
        assert_eq!(q.stats().cancelled, 0);
        for _ in 0..8 {
            assert!(q.cancel_target(app).is_some());
        }
        assert_eq!(q.stats().cancelled, 8);
        assert_eq!(q.available(Peer::Shell), 7);
    }
    #[cfg(feature = "desktop-root")]
    #[test]
    fn every_applied_shell_control_has_real_settlement_except_deliberate_fault() {
        use ev_desktop::protocol::RootControl as C;
        for control in [
            C::AppStarted(1),
            C::AppStopped(1),
            C::PickFile(1),
            C::FileDelivered(1),
            C::FileRefused(1),
            C::InputRestarted(1),
            C::AppRestored(1),
            C::LaunchRefused,
            C::OwnerFilePending(1),
            C::OwnerFileDelivered(1),
            C::OwnerFileRefused(1),
            C::ManagedFilePending(1),
            C::ManagedFileDelivered(1),
            C::ManagedFileRefused(1),
            C::OwnerActionPending(1),
            C::OwnerActionDone(1),
        ] {
            assert!(
                control_needs_settlement(control.encode().unwrap()),
                "{control:?}"
            );
        }
        assert!(!control_needs_settlement(C::CrashShell.encode().unwrap()));
        assert!(!control_needs_settlement(*b"INVALID!"));
    }
    #[test]
    fn exact_front_ack_rejects_later_control_duplicate_and_other_incarnation() {
        let mut q = Outbox::new();
        let shell = target(Peer::Shell, 2);
        queue(&mut q, shell, 1, 512);
        let a = q.next_attempt().unwrap();
        q.finish(a.ticket, Outcome::Accepted);
        queue(&mut q, shell, 2, 512);
        let b = q.next_attempt().unwrap();
        q.finish(b.ticket, Outcome::Accepted);
        let mut entries = [Some(a), Some(b)];
        let find = |entries: &[Option<Entry>; 2], target, bytes| {
            matching_front(
                entries
                    .iter()
                    .enumerate()
                    .filter_map(|(i, e)| e.as_ref().map(|e| (i, e))),
                target,
                bytes,
            )
        };
        assert_eq!(find(&entries, shell, b.bytes), None);
        assert_eq!(find(&entries, target(Peer::Shell, 3), a.bytes), None);
        assert_eq!(find(&entries, shell, a.bytes), Some(0));
        entries[0] = None;
        assert_eq!(
            find(&entries, shell, a.bytes),
            None,
            "old ACK cannot settle next control"
        );
        assert_eq!(find(&entries, shell, b.bytes), Some(1));
    }
    #[test]
    fn selection_preserves_complete_heads_and_bounds_for_all_eight_slot_hole_masks() {
        for app_mask in 0u8..=u8::MAX {
            let shell_mask = app_mask.rotate_left(3) ^ 0xa5;
            for turn in 0..2 {
                let mut q = Outbox::new();
                let targets = [target(Peer::App, 17), target(Peer::Shell, 29)];
                let mut expected = [[None; PER_PEER]; 2];
                let mut counts = [0; 2];
                for (peer, keep) in [app_mask, shell_mask].into_iter().enumerate() {
                    let mut cancelled = [None; PER_PEER];
                    for (slot, cancelled_slot) in cancelled.iter_mut().enumerate() {
                        let byte = (peer * PER_PEER + slot + 1) as u8;
                        let cut = 512 + u64::from(byte);
                        let ticket = queue(&mut q, targets[peer], byte, cut);
                        let entry = Entry {
                            ticket,
                            target: targets[peer],
                            bytes: [byte; 8],
                            deadline: cut,
                            kind: Kind::Control,
                        };
                        if keep & (1 << slot) != 0 {
                            expected[peer][counts[peer]] = Some(entry);
                            counts[peer] += 1;
                        } else {
                            *cancelled_slot = Some(entry);
                        }
                    }
                    for entry in cancelled.into_iter().flatten() {
                        assert_eq!(q.finish(entry.ticket, Outcome::Cancelled), Some(entry));
                    }
                }
                for peer in 0..2 {
                    assert_eq!(q.available(targets[peer].peer), PER_PEER - counts[peer]);
                }
                // An in-progress fanout cannot dispatch an older ready head.
                q.begin(targets.map(Some), [0, 0]).unwrap();
                assert!(q.next_attempt().is_none());
                q.end();
                q.turn = turn;
                let stats = q.stats();
                let primary = expected[turn][0];
                let secondary = expected[1 - turn][0];
                let chosen = primary.or(secondary);
                assert_eq!(q.next_attempt(), chosen);
                assert_eq!(
                    q.stats(),
                    stats,
                    "selection never consumes or reports acceptance"
                );
                if let Some(entry) = chosen {
                    assert_eq!(q.turn, 1 - entry.target.peer as usize);
                    let next = expected[q.turn][0].or(Some(entry));
                    assert_eq!(
                        q.next_attempt(),
                        next,
                        "Busy preserves both exact peer heads"
                    );
                    assert_eq!(q.finish(entry.ticket, Outcome::Accepted), Some(entry));
                    assert!(q.finish(entry.ticket, Outcome::Accepted).is_none());
                } else {
                    assert!(!q.pending());
                    assert_eq!(q.turn, turn);
                }
            }
        }
    }
}
