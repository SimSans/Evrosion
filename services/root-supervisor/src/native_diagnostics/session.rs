//! Explicit sustained-session policy for bounded volatile diagnostic history.
//! Completed UART framing is not a durable host-export acknowledgement.
use ev_diagnostics::{
    Crash,
    framing::{ArchiveError, CrashArchive},
};
pub fn next_input_count(current: usize, session: bool) -> Option<usize> {
    if !session && current >= 4096 {
        return None;
    }
    current.checked_add(1)
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    OutputPending,
    Counter,
    Archive(ArchiveError),
}
pub struct History {
    archive: CrashArchive,
    next: usize,
    evicted: u64,
}
impl Default for History {
    fn default() -> Self {
        Self::new()
    }
}
impl History {
    pub const fn new() -> Self {
        Self {
            archive: CrashArchive::new(),
            next: 0,
            evicted: 0,
        }
    }
    pub fn evicted(&self) -> u64 {
        self.evicted
    }
    pub fn push_after_output(
        &mut self,
        crash: Crash,
        output_pending: bool,
    ) -> Result<usize, Error> {
        if output_pending {
            return Err(Error::OutputPending);
        }
        match self.archive.push(crash) {
            Ok(slot) => Ok(slot),
            Err(ArchiveError::Full) => {
                let count = self.evicted.checked_add(1).ok_or(Error::Counter)?;
                self.archive.remove(self.next).map_err(Error::Archive)?;
                let slot = self
                    .archive
                    .push(crash)
                    .expect("same serialized unique crash after explicit eviction");
                self.next = (self.next + 1) % 2;
                self.evicted = count;
                Ok(slot)
            }
            Err(error) => Err(Error::Archive(error)),
        }
    }
    pub fn payload(&self, slot: usize) -> Result<&[u8; ev_diagnostics::BYTES], ArchiveError> {
        self.archive.payload(slot)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn crash(process: u64) -> Crash {
        Crash::new(
            ev_diagnostics::Provenance {
                component: ev_diagnostics::Component::Service(1),
                image: [2; 32],
                package: None,
                component_build: [3; 32],
                generation: None,
                epoch: 501,
                incarnation: 1,
            },
            ev_diagnostics::Capture {
                job: 17,
                process,
                thread: process,
                vector: 14,
                error: 4,
                address: 0x8000400000,
                instruction: 0x8000012340,
                stack: 0x8000103f00,
                flags: 0x202,
                registers: [0; 15],
            },
        )
        .unwrap()
    }
    #[test]
    fn ordinary_session_input_has_checked_cumulative_count_while_finite_limit_stays() {
        assert_eq!(next_input_count(4095, false), Some(4096));
        assert_eq!(next_input_count(4096, false), None);
        assert_eq!(next_input_count(4096, true), Some(4097));
        assert_eq!(next_input_count(100000, true), Some(100001));
        assert_eq!(next_input_count(usize::MAX, true), None);
    }
    #[test]
    fn repeated_completed_crashes_roll_two_ram_slots_without_evicting_active_output() {
        let mut h = History::new();
        let a = h.push_after_output(crash(1), false).unwrap();
        let b = h.push_after_output(crash(2), false).unwrap();
        let before = (*h.payload(a).unwrap(), *h.payload(b).unwrap());
        assert_eq!(
            h.push_after_output(crash(3), true),
            Err(Error::OutputPending)
        );
        assert_eq!((*h.payload(a).unwrap(), *h.payload(b).unwrap()), before);
        assert_eq!(
            h.push_after_output(crash(1), false),
            Err(Error::Archive(ArchiveError::Duplicate))
        );
        assert_eq!(h.evicted(), 0);
        for process in 3..=12 {
            h.push_after_output(crash(process), false).unwrap();
        }
        assert_eq!(h.evicted(), 10);
        let mut processes = [
            Crash::decode(h.payload(0).unwrap())
                .unwrap()
                .capture()
                .process,
            Crash::decode(h.payload(1).unwrap())
                .unwrap()
                .capture()
                .process,
        ];
        processes.sort();
        assert_eq!(processes, [11, 12]);
    }
    #[test]
    fn eviction_counter_exhaustion_preserves_both_original_capsules() {
        let mut h = History::new();
        h.push_after_output(crash(1), false).unwrap();
        h.push_after_output(crash(2), false).unwrap();
        h.evicted = u64::MAX;
        let before = (*h.payload(0).unwrap(), *h.payload(1).unwrap());
        assert_eq!(h.push_after_output(crash(3), false), Err(Error::Counter));
        assert_eq!((*h.payload(0).unwrap(), *h.payload(1).unwrap()), before);
    }
}
