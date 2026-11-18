//! Private Shell production, distinct from accepted Kernel messages. No handle,
//! input proof or grant is created here. The adapter checks actual SEND status.
const SEMANTIC: usize = 16;
const INPUT: usize = 32;
const SLOTS: usize = SEMANTIC + INPUT;
pub const SEMANTIC_TICKS: u64 = 4096;
/// One bounded Root Store transaction plus the independent UI settlement cut.
pub const INPUT_TICKS: u64 = 8192 + SEMANTIC_TICKS;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Ready,
    Settled,
    PickerReady,
    Action,
    Cancel,
    Repaint,
    Input,
}
impl Kind {
    fn semantic(self) -> bool {
        !matches!(self, Self::Input | Self::Repaint)
    }
    fn span(self) -> u64 {
        match self {
            Self::Ready | Self::Settled | Self::PickerReady => SEMANTIC_TICKS,
            Self::Action | Self::Cancel | Self::Repaint | Self::Input => INPUT_TICKS,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub ticket: u64,
    pub endpoint: u64,
    pub bytes: [u8; 8],
    pub cut: u64,
    pub kind: Kind,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Full,
    Clock,
    Counter,
    Degraded,
    Refused,
    Expired,
}
pub struct Outbox {
    entries: [Option<Entry>; SLOTS],
    serial: u64,
    degraded: bool,
    failure: Option<Error>,
}
impl Default for Outbox {
    fn default() -> Self {
        Self::new()
    }
}
impl Outbox {
    pub const fn new() -> Self {
        Self {
            entries: [None; SLOTS],
            serial: 0,
            degraded: false,
            failure: None,
        }
    }
    pub fn degraded(&self) -> bool {
        self.degraded
    }
    pub fn input_pending(&self) -> bool {
        self.entries[SEMANTIC..].iter().any(Option::is_some)
    }
    pub fn input_room(&self) -> bool {
        !self.degraded
            && self.entries[SEMANTIC..].iter().any(Option::is_none)
            // Input may produce a modal action, while Root control always has
            // separate capacity for PickerReady/Settled and a cancellation.
            && self.entries[..SEMANTIC].iter().filter(|e| e.is_none()).count() >= 3
    }
    pub fn fail(&mut self, error: Error) {
        self.degraded = true;
        self.failure.get_or_insert(error);
    }
    pub fn take_failure(&mut self) -> Option<Error> {
        self.failure.take()
    }
    pub fn failure_pending(&self) -> bool {
        self.failure.is_some()
    }
    pub fn enqueue(
        &mut self,
        endpoint: u64,
        bytes: [u8; 8],
        kind: Kind,
        now: u64,
    ) -> Result<u64, Error> {
        if endpoint == 0 || now == u64::MAX {
            return Err(Error::Clock);
        }
        if self.degraded && matches!(kind, Kind::Input | Kind::Action) {
            return Err(Error::Degraded);
        }
        let cut = now
            .checked_add(kind.span())
            .filter(|n| *n != u64::MAX)
            .ok_or(Error::Clock)?;
        let ticket = self
            .serial
            .checked_add(1)
            .filter(|n| *n != u64::MAX)
            .ok_or(Error::Counter)?;
        let mut range = if kind.semantic() {
            0..SEMANTIC
        } else {
            SEMANTIC..SLOTS
        };
        let slot = range
            .find(|&i| self.entries[i].is_none())
            .ok_or(Error::Full)?;
        self.entries[slot] = Some(Entry {
            ticket,
            endpoint,
            bytes,
            cut,
            kind,
        });
        self.serial = ticket;
        Ok(ticket)
    }
    /// Root controls invalidate old modal/App context. A local redraw keeps its
    /// already-produced PickerReady prerequisite until the following action;
    /// ordinary input and older unsent actions never cross either boundary.
    pub fn context_changed(&mut self, root_control: bool) {
        for entry in &mut self.entries {
            if entry.is_some_and(|e| {
                matches!(
                    e.kind,
                    Kind::Input | Kind::Action | Kind::Cancel | Kind::Repaint
                ) || root_control && e.kind == Kind::PickerReady
            }) {
                *entry = None;
            }
        }
    }
    /// Only the adapter's actual new control/context, protected Present and
    /// successful freshness barrier can authorize this local recovery step.
    pub fn recovered_after_fresh_context(&mut self) {
        self.degraded = false;
        self.failure = None;
    }
    /// Semantic FIFO precedes ordinary input, but neither FIFO is reordered.
    /// No method advances a cut on Full or interprets an enqueue as acceptance.
    pub fn next_attempt(&self) -> Option<Entry> {
        self.entries[..SEMANTIC]
            .iter()
            .flatten()
            .copied()
            .min_by_key(|e| e.ticket)
            .or_else(|| {
                self.entries[SEMANTIC..]
                    .iter()
                    .flatten()
                    .copied()
                    .min_by_key(|e| e.ticket)
            })
    }
    pub fn complete(&mut self, entry: Entry, error: Option<Error>) -> bool {
        let Some(slot) = self.entries.iter_mut().find(|e| **e == Some(entry)) else {
            return false;
        };
        *slot = None;
        if let Some(error) = error {
            self.fail(error);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn put(q: &mut Outbox, kind: Kind, byte: u8) -> Entry {
        let ticket = q.enqueue(11, [byte; 8], kind, 7).unwrap();
        *q.entries
            .iter()
            .flatten()
            .find(|e| e.ticket == ticket)
            .unwrap()
    }
    #[test]
    fn busy_keeps_bytes_original_cut_and_ticket_but_acceptance_is_never_replayed() {
        let mut q = Outbox::new();
        let a = put(&mut q, Kind::Input, 1);
        let b = put(&mut q, Kind::Input, 2);
        assert_eq!(a.cut, 7 + 12_288);
        for _ in 0..100 {
            assert_eq!(q.next_attempt(), Some(a));
        }
        assert!(q.complete(a, None));
        assert!(!q.complete(a, None));
        assert_eq!(q.next_attempt(), Some(b));
    }
    #[test]
    fn full_input_has_reserved_semantic_progress_and_preserves_prerequisite_ack_order() {
        let mut q = Outbox::new();
        for n in 0..32 {
            put(&mut q, Kind::Input, n);
        }
        assert!(!q.input_room());
        assert_eq!(q.enqueue(11, [99; 8], Kind::Input, 8), Err(Error::Full));
        let p = put(&mut q, Kind::PickerReady, 40);
        let a = put(&mut q, Kind::Settled, 41);
        assert_eq!(q.next_attempt(), Some(p));
        q.complete(p, None);
        assert_eq!(q.next_attempt(), Some(a));
    }
    #[test]
    fn fresh_context_purges_only_unsent_obsolete_work_never_prior_settlement() {
        let mut q = Outbox::new();
        let accepted = put(&mut q, Kind::Input, 1);
        q.complete(accepted, None);
        put(&mut q, Kind::Input, 2);
        put(&mut q, Kind::Action, 3);
        let p = put(&mut q, Kind::PickerReady, 4);
        let a = put(&mut q, Kind::Settled, 5);
        q.context_changed(false);
        assert_eq!(q.next_attempt(), Some(p));
        q.context_changed(true);
        assert_eq!(q.next_attempt(), Some(a));
        assert!(!q.complete(accepted, None));
    }
    #[test]
    fn failure_fences_interaction_until_explicit_actual_context_recovery_but_allows_ack() {
        let mut q = Outbox::new();
        let a = put(&mut q, Kind::Action, 1);
        q.complete(a, Some(Error::Expired));
        assert!(q.degraded());
        assert_eq!(q.take_failure(), Some(Error::Expired));
        assert_eq!(q.take_failure(), None);
        assert_eq!(q.enqueue(11, [2; 8], Kind::Action, 9), Err(Error::Degraded));
        let ack = put(&mut q, Kind::Settled, 3);
        assert_eq!(q.next_attempt(), Some(ack));
        q.context_changed(true);
        assert!(q.degraded());
        q.recovered_after_fresh_context();
        assert!(!q.degraded());
        assert!(q.enqueue(11, [4; 8], Kind::Input, 10).is_ok());
    }
    #[test]
    fn invalid_cut_exhaustion_and_stale_completion_never_mutate_live_entries() {
        let mut q = Outbox::new();
        let a = put(&mut q, Kind::Input, 1);
        let mut forged = a;
        forged.cut += 1;
        assert!(!q.complete(forged, None));
        q.serial = u64::MAX - 1;
        assert_eq!(q.enqueue(11, [2; 8], Kind::Input, 7), Err(Error::Counter));
        q.serial = 1;
        assert_eq!(
            q.enqueue(11, [2; 8], Kind::Input, u64::MAX - 10),
            Err(Error::Clock)
        );
        assert_eq!(q.next_attempt(), Some(a));
    }
}
