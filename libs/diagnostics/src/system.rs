//! Read-only System metadata diagnostics. A committed manifest does not attest
//! that the current process was selected/admitted from that System generation.
use crate::framing::SYSTEM_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    NotCollected,
    Unformatted,
    NeedsRecovery,
    Unavailable,
    Committed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub generation: u64,
    pub cohort: [u8; 32],
    pub supervisor_image: [u8; 32],
    pub abi: [u8; 32],
    pub health_contract: [u8; 32],
    pub health_version: u16,
    pub required_checks: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Failure {
    pub generation: u64,
    pub boot_serial: u64,
    pub attempts: u8,
    /// RootProcessFault1, MissingProgress2, StorageFailure3, AttemptBudgetExhausted4,
    /// CriticalComponentFault5 (actual child fault, distinct from Root fault).
    pub reason: u8,
    pub supervisor_image: [u8; 32],
    pub process_stamp: Option<[u8; 32]>,
    pub operation: u64,
    pub sequence: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub state: State,
    pub first_tick: u64,
    pub last_tick: u64,
    pub selected: Option<Manifest>,
    pub known_good: Option<u64>,
    pub last_failure: Option<Failure>,
    /// Actual durable admission of this Root execution, independent of the
    /// selected next boot. None is explicit pre-admission/Standalone state.
    pub current: Option<Admission>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Phase {
    Probation = 1,
    Healthy = 2,
    Failed = 3,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admission {
    /// Native System manifest-reference digest, not a live handle or Store
    /// creation manifest and not an inferred KnownGood selection.
    pub manifest: [u8; 32],
    pub generation: u64,
    pub boot_serial: u64,
    pub process_stamp: [u8; 32],
    pub phase: Phase,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Wire,
    Reserved,
    Identity,
    Clock,
}
fn put(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn word(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
impl Snapshot {
    pub fn new(state: State, first_tick: u64, last_tick: u64) -> Self {
        Self {
            state,
            first_tick,
            last_tick,
            selected: None,
            known_good: None,
            last_failure: None,
            current: None,
        }
    }
    fn validate(self) -> Result<(), Error> {
        if self.first_tick > self.last_tick {
            return Err(Error::Clock);
        }
        if let Some(current) = self.current
            && (current.manifest == [0; 32]
                || current.generation == 0
                || current.generation == u64::MAX
                || current.boot_serial == 0
                || current.process_stamp == [0; 32])
        {
            return Err(Error::Identity);
        }
        if (self.state == State::Committed) != self.selected.is_some()
            || matches!(self.known_good, Some(0 | u64::MAX))
            || (self.state != State::Committed
                && (self.known_good.is_some() || self.last_failure.is_some()))
        {
            return Err(Error::Identity);
        }
        if let Some(m) = self.selected
            && (m.generation == 0
                || m.generation == u64::MAX
                || !matches!(m.health_version, 1 | 2)
                || m.required_checks != 3
                || [m.cohort, m.supervisor_image, m.abi, m.health_contract].contains(&[0; 32]))
        {
            return Err(Error::Identity);
        }
        if let Some(f) = self.last_failure
            && (f.generation == 0
                || f.generation == u64::MAX
                || f.boot_serial == 0
                || !(1..=8).contains(&f.attempts)
                || !(1..=5).contains(&f.reason)
                || f.supervisor_image == [0; 32]
                || f.process_stamp == Some([0; 32])
                || f.operation == 0
                || f.sequence == 0)
        {
            return Err(Error::Identity);
        }
        Ok(())
    }
    pub fn encode(self) -> Result<[u8; SYSTEM_BYTES], Error> {
        self.validate()?;
        let mut out = [0; SYSTEM_BYTES];
        out[..8].copy_from_slice(b"EVSYSM01");
        out[8..10].copy_from_slice(&2u16.to_le_bytes());
        out[10..12].copy_from_slice(&(SYSTEM_BYTES as u16).to_le_bytes());
        out[12] = self.state as u8;
        if let Some(m) = self.selected {
            put(&mut out, 16, m.generation);
            for (at, digest) in [
                (24, m.cohort),
                (56, m.supervisor_image),
                (88, m.abi),
                (120, m.health_contract),
            ] {
                out[at..at + 32].copy_from_slice(&digest);
            }
            out[152..154].copy_from_slice(&m.health_version.to_le_bytes());
            out[156..160].copy_from_slice(&m.required_checks.to_le_bytes());
        }
        if let Some(good) = self.known_good {
            out[13] |= 1;
            put(&mut out, 160, good);
        }
        if let Some(f) = self.last_failure {
            out[13] |= 2;
            put(&mut out, 168, f.generation);
            put(&mut out, 176, f.boot_serial);
            out[184] = f.attempts;
            out[185] = f.reason;
            out[192..224].copy_from_slice(&f.supervisor_image);
            if let Some(stamp) = f.process_stamp {
                out[13] |= 4;
                out[224..256].copy_from_slice(&stamp);
            }
            put(&mut out, 256, f.operation);
            put(&mut out, 264, f.sequence);
        }
        put(&mut out, 272, self.first_tick);
        put(&mut out, 280, self.last_tick);
        if let Some(c) = self.current {
            out[288..320].copy_from_slice(&c.manifest);
            put(&mut out, 320, c.generation);
            put(&mut out, 328, c.boot_serial);
            out[336..368].copy_from_slice(&c.process_stamp);
            put(&mut out, 368, c.phase as u64);
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SYSTEM_BYTES
            || &bytes[..8] != b"EVSYSM01"
            || !matches!(u16::from_le_bytes(bytes[8..10].try_into().unwrap()), 1 | 2)
            || bytes[10..12] != (SYSTEM_BYTES as u16).to_le_bytes()
            || bytes[13] & !7 != 0
        {
            return Err(Error::Wire);
        }
        if bytes[14..16] != [0; 2]
            || bytes[154..156] != [0; 2]
            || bytes[186..192] != [0; 6]
            || bytes[376..].iter().any(|b| *b != 0)
        {
            return Err(Error::Reserved);
        }
        let state = match bytes[12] {
            0 => State::NotCollected,
            1 => State::Unformatted,
            2 => State::NeedsRecovery,
            3 => State::Unavailable,
            4 => State::Committed,
            _ => return Err(Error::Wire),
        };
        let mut value = Self::new(state, word(bytes, 272), word(bytes, 280));
        if bytes[8..10] == 1u16.to_le_bytes() || word(bytes, 368) == 0 {
            if bytes[288..].iter().any(|b| *b != 0) {
                return Err(Error::Reserved);
            }
        } else {
            let phase = match word(bytes, 368) {
                1 => Phase::Probation,
                2 => Phase::Healthy,
                3 => Phase::Failed,
                _ => return Err(Error::Identity),
            };
            value.current = Some(Admission {
                manifest: bytes[288..320].try_into().unwrap(),
                generation: word(bytes, 320),
                boot_serial: word(bytes, 328),
                process_stamp: bytes[336..368].try_into().unwrap(),
                phase,
            });
        }
        if state == State::Committed {
            value.selected = Some(Manifest {
                generation: word(bytes, 16),
                cohort: bytes[24..56].try_into().unwrap(),
                supervisor_image: bytes[56..88].try_into().unwrap(),
                abi: bytes[88..120].try_into().unwrap(),
                health_contract: bytes[120..152].try_into().unwrap(),
                health_version: u16::from_le_bytes(bytes[152..154].try_into().unwrap()),
                required_checks: u32::from_le_bytes(bytes[156..160].try_into().unwrap()),
            });
        } else if bytes[16..160].iter().any(|b| *b != 0) {
            return Err(Error::Reserved);
        }
        if bytes[13] & 1 != 0 {
            value.known_good = Some(word(bytes, 160));
        } else if word(bytes, 160) != 0 {
            return Err(Error::Reserved);
        }
        if bytes[13] & 2 != 0 {
            value.last_failure = Some(Failure {
                generation: word(bytes, 168),
                boot_serial: word(bytes, 176),
                attempts: bytes[184],
                reason: bytes[185],
                supervisor_image: bytes[192..224].try_into().unwrap(),
                process_stamp: if bytes[13] & 4 != 0 {
                    Some(bytes[224..256].try_into().unwrap())
                } else {
                    if bytes[224..256] != [0; 32] {
                        return Err(Error::Reserved);
                    }
                    None
                },
                operation: word(bytes, 256),
                sequence: word(bytes, 264),
            });
        } else if bytes[13] & 4 != 0 || bytes[168..272].iter().any(|b| *b != 0) {
            return Err(Error::Reserved);
        }
        if bytes[8..10] == 1u16.to_le_bytes()
            && value
                .last_failure
                .is_some_and(|failure| failure.reason == 5)
        {
            return Err(Error::Identity);
        }
        value.validate()?;
        Ok(value)
    }
}

#[cfg(test)]
mod critical_component_tests {
    use super::*;
    #[test]
    fn child_fault_reason_is_distinct_and_roundtrips_only_current_wire() {
        let mut snapshot = Snapshot::new(State::Committed, 10, 11);
        snapshot.selected = Some(Manifest {
            generation: 2,
            cohort: [1; 32],
            supervisor_image: [2; 32],
            abi: [3; 32],
            health_contract: [4; 32],
            health_version: 1,
            required_checks: 3,
        });
        snapshot.known_good = Some(2);
        snapshot.last_failure = Some(Failure {
            generation: 3,
            boot_serial: 4,
            attempts: 1,
            reason: 5,
            supervisor_image: [2; 32],
            process_stamp: Some([5; 32]),
            operation: 9,
            sequence: 9,
        });
        let bytes = snapshot.encode().unwrap();
        assert_eq!(Snapshot::decode(&bytes), Ok(snapshot));
        let mut old = bytes;
        old[8..10].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(Snapshot::decode(&old), Err(Error::Identity));
        let mut unknown = bytes;
        unknown[185] = 6;
        assert_eq!(Snapshot::decode(&unknown), Err(Error::Identity));
        let mut root = snapshot;
        root.last_failure.as_mut().unwrap().reason = 1;
        assert_ne!(root.encode().unwrap(), bytes);
        assert_eq!(Snapshot::decode(&root.encode().unwrap()), Ok(root));
    }
}
