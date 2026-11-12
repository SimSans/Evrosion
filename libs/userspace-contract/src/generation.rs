//! Internal sealed generation catalogue. A read-only mapping and its actual
//! capability binding establish trust; checksums/this parser do not authenticate
//! a publisher. Cohorts bind build INPUT identity, never a circular kernel hash.
pub const BYTES: usize = 512;
pub type Digest = [u8; 32];
pub const HEALTH_DESCRIPTION: &[u8] = b"evrosion.internal.generation.health.v1; exact current process/thread Ready provenance; admitted image+ABI+cohort; live supervisor or actual typed fault; durable current mutable-object SHA256; no caller healthy boolean";
const COHORT_DOMAIN: &[u8] = b"evrosion.generation.cohort.v1\0";
pub const COHORT_BYTES: usize = COHORT_DOMAIN.len() + 8 + 6 * 32 + 2 + 4;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    A,
    B,
}
impl Slot {
    pub const fn generation(self) -> u64 {
        match self {
            Self::A => 1,
            Self::B => 2,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Magic,
    Version,
    Reserved,
    Empty,
    Images,
    Health,
    Mode,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Catalogue {
    pub kernel_build: Digest,
    pub controller: Digest,
    pub driver: Digest,
    pub image_a: Digest,
    pub image_b: Digest,
    pub abi: Digest,
    pub health: Digest,
    pub health_version: u16,
    pub required_checks: u16,
}
impl Catalogue {
    pub fn encode(self) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        bytes[..8].copy_from_slice(b"EVGCAT01");
        bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
        bytes[10..12].copy_from_slice(&(BYTES as u16).to_le_bytes());
        bytes[12..14].copy_from_slice(&self.health_version.to_le_bytes());
        bytes[14..16].copy_from_slice(&self.required_checks.to_le_bytes());
        for (i, digest) in [
            self.kernel_build,
            self.controller,
            self.driver,
            self.image_a,
            self.image_b,
            self.abi,
            self.health,
        ]
        .into_iter()
        .enumerate()
        {
            bytes[16 + i * 32..48 + i * 32].copy_from_slice(&digest);
        }
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BYTES {
            return Err(Error::Length);
        }
        if &bytes[..8] != b"EVGCAT01" {
            return Err(Error::Magic);
        }
        if bytes[8..10] != 1u16.to_le_bytes() || bytes[10..12] != (BYTES as u16).to_le_bytes() {
            return Err(Error::Version);
        }
        if bytes[240..].iter().any(|b| *b != 0) {
            return Err(Error::Reserved);
        }
        let health_version = u16::from_le_bytes([bytes[12], bytes[13]]);
        let required_checks = u16::from_le_bytes([bytes[14], bytes[15]]);
        if health_version != 1 || required_checks != 3 {
            return Err(Error::Health);
        }
        let mut digests = [[0u8; 32]; 7];
        for (i, digest) in digests.iter_mut().enumerate() {
            digest.copy_from_slice(&bytes[16 + i * 32..48 + i * 32]);
            if *digest == [0; 32] {
                return Err(Error::Empty);
            }
        }
        if digests[3] == digests[4] {
            return Err(Error::Images);
        }
        Ok(Self {
            kernel_build: digests[0],
            controller: digests[1],
            driver: digests[2],
            image_a: digests[3],
            image_b: digests[4],
            abi: digests[5],
            health: digests[6],
            health_version,
            required_checks,
        })
    }
    pub const fn image(self, slot: Slot) -> Digest {
        match slot {
            Slot::A => self.image_a,
            Slot::B => self.image_b,
        }
    }
    /// Canonical complete six-component capsule transcript, shared by producer
    /// and measured controller. Hash it with SHA-256; no authority is minted.
    pub fn cohort_input(self, slot: Slot) -> [u8; COHORT_BYTES] {
        self.cohort_input_for(slot, slot.generation())
    }
    pub fn cohort_input_for(self, slot: Slot, generation: u64) -> [u8; COHORT_BYTES] {
        let mut out = [0; COHORT_BYTES];
        let mut offset = COHORT_DOMAIN.len();
        out[..offset].copy_from_slice(COHORT_DOMAIN);
        out[offset..offset + 8].copy_from_slice(&generation.to_le_bytes());
        offset += 8;
        for digest in [
            self.kernel_build,
            self.controller,
            self.driver,
            self.image(slot),
            self.abi,
            self.health,
        ] {
            out[offset..offset + 32].copy_from_slice(&digest);
            offset += 32;
        }
        out[offset..offset + 2].copy_from_slice(&self.health_version.to_le_bytes());
        out[offset + 2..].copy_from_slice(&u32::from(self.required_checks).to_le_bytes());
        out
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    ProvisionA = 0,
    FailB = 1,
    AutoA = 2,
    ManualA = 3,
    Verify = 4,
    OwnerPrepare3 = 5,
    OwnerRecover = 6,
}
fn mode(byte: u8) -> Result<Mode, Error> {
    match byte {
        0 => Ok(Mode::ProvisionA),
        1 => Ok(Mode::FailB),
        2 => Ok(Mode::AutoA),
        3 => Ok(Mode::ManualA),
        4 => Ok(Mode::Verify),
        5 => Ok(Mode::OwnerPrepare3),
        6 => Ok(Mode::OwnerRecover),
        _ => Err(Error::Mode),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Control {
    pub mode: Mode,
    pub prompt_ticks: u64,
}
impl Control {
    pub const fn new(mode: Mode) -> Self {
        Self {
            mode,
            prompt_ticks: if matches!(mode, Mode::OwnerRecover) {
                60_000
            } else {
                0
            },
        }
    }
    pub const fn owner_recover(prompt_ticks: u64) -> Option<Self> {
        if prompt_ticks == 0 || prompt_ticks > 60_000 {
            None
        } else {
            Some(Self {
                mode: Mode::OwnerRecover,
                prompt_ticks,
            })
        }
    }
    pub fn encode(self) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        bytes[..4].copy_from_slice(b"EVGT");
        bytes[4] = 1;
        bytes[5] = self.mode as u8;
        bytes[8..16].copy_from_slice(&self.prompt_ticks.to_le_bytes());
        bytes[16..20].copy_from_slice(&16u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&14u32.to_le_bytes());
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BYTES {
            return Err(Error::Length);
        }
        if &bytes[..4] != b"EVGT" {
            return Err(Error::Magic);
        }
        if bytes[4] != 1 {
            return Err(Error::Version);
        }
        if bytes[6..8].iter().chain(&bytes[24..]).any(|b| *b != 0) {
            return Err(Error::Reserved);
        }
        if bytes[16..20] != 16u32.to_le_bytes() || bytes[20..24] != 14u32.to_le_bytes() {
            return Err(Error::Version);
        }
        let mode = mode(bytes[5])?;
        let mut word = [0; 8];
        word.copy_from_slice(&bytes[8..16]);
        let prompt_ticks = u64::from_le_bytes(word);
        if if mode == Mode::OwnerRecover {
            prompt_ticks == 0 || prompt_ticks > 60_000
        } else {
            prompt_ticks != 0
        } {
            return Err(Error::Version);
        }
        Ok(Self { mode, prompt_ticks })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OwnerDecision {
    None = 0,
    Continue = 1,
    Cancel = 2,
    Timeout = 3,
    InputFault = 4,
    InputBudget = 5,
}
impl OwnerDecision {
    pub fn decode(value: u8) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Continue),
            2 => Ok(Self::Cancel),
            3 => Ok(Self::Timeout),
            4 => Ok(Self::InputFault),
            5 => Ok(Self::InputBudget),
            _ => Err(Error::Version),
        }
    }
}
/// Diagnostics of the measured controller, independently checked against the
/// kernel's actual identities/events/faults/IO and cold persistent snapshots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    pub mode: Mode,
    pub owner_decision: OwnerDecision,
    pub booted: u64,
    pub selected: u64,
    pub known_good: u64,
    pub boot_serial: u64,
    pub process: u64,
    pub thread: u64,
    pub failure_generation: u64,
    pub failure_serial: u64,
    pub failure_reason: u64,
    /// Count of actually received forged events rejected by authenticated origin.
    pub negatives: u64,
    pub mutations: u64,
    pub operation: u64,
    pub sequence: u64,
    pub failure_operation: u64,
    pub failure_sequence: u64,
    pub catalogue: Digest,
    pub process_stamp: Digest,
    pub storage_probe: Digest,
    pub booted_cohort: Digest,
}
impl Completion {
    pub const fn flags(self) -> u8 {
        match self.mode {
            Mode::FailB => 5,
            Mode::Verify | Mode::OwnerPrepare3 => 9,
            Mode::OwnerRecover if !matches!(self.owner_decision, OwnerDecision::Continue) => 9,
            _ => 3,
        }
    }
    pub fn encode(self) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        bytes[..4].copy_from_slice(b"EVGR");
        bytes[4] = 1;
        bytes[5] = self.mode as u8;
        bytes[6] = self.flags();
        bytes[7] = self.owner_decision as u8;
        for (i, value) in [
            self.booted,
            self.selected,
            self.known_good,
            self.boot_serial,
            self.process,
            self.thread,
            self.failure_generation,
            self.failure_serial,
            self.failure_reason,
            self.negatives,
            self.mutations,
            self.operation,
            self.sequence,
            self.failure_operation,
            self.failure_sequence,
        ]
        .into_iter()
        .enumerate()
        {
            bytes[8 + i * 8..16 + i * 8].copy_from_slice(&value.to_le_bytes());
        }
        for (i, digest) in [
            self.catalogue,
            self.process_stamp,
            self.storage_probe,
            self.booted_cohort,
        ]
        .into_iter()
        .enumerate()
        {
            bytes[128 + i * 32..160 + i * 32].copy_from_slice(&digest);
        }
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BYTES {
            return Err(Error::Length);
        }
        if &bytes[..4] != b"EVGR" {
            return Err(Error::Magic);
        }
        if bytes[4] != 1 {
            return Err(Error::Version);
        }
        if bytes[256..].iter().any(|b| *b != 0) {
            return Err(Error::Reserved);
        }
        let mut values = [0u64; 15];
        for (i, value) in values.iter_mut().enumerate() {
            let mut word = [0; 8];
            word.copy_from_slice(&bytes[8 + i * 8..16 + i * 8]);
            *value = u64::from_le_bytes(word);
        }
        let mut digests = [[0; 32]; 4];
        for (i, digest) in digests.iter_mut().enumerate() {
            digest.copy_from_slice(&bytes[128 + i * 32..160 + i * 32]);
        }
        let report = Self {
            mode: mode(bytes[5])?,
            owner_decision: OwnerDecision::decode(bytes[7])?,
            booted: values[0],
            selected: values[1],
            known_good: values[2],
            boot_serial: values[3],
            process: values[4],
            thread: values[5],
            failure_generation: values[6],
            failure_serial: values[7],
            failure_reason: values[8],
            negatives: values[9],
            mutations: values[10],
            operation: values[11],
            sequence: values[12],
            failure_operation: values[13],
            failure_sequence: values[14],
            catalogue: digests[0],
            process_stamp: digests[1],
            storage_probe: digests[2],
            booted_cohort: digests[3],
        };
        let owner_no_action =
            report.mode == Mode::OwnerRecover && report.owner_decision != OwnerDecision::Continue;
        let owner_selected = report.mode == Mode::OwnerPrepare3 || owner_no_action;
        if if report.mode == Mode::OwnerRecover {
            report.owner_decision == OwnerDecision::None
        } else {
            report.owner_decision != OwnerDecision::None
        } {
            return Err(Error::Version);
        }
        if owner_no_action && report.mutations != 0 {
            return Err(Error::Version);
        }
        if bytes[6] != report.flags()
            || report.selected != if owner_selected { 3 } else { 1 }
            || report.known_good != 1
            || report.catalogue == [0; 32]
            || report.storage_probe == [0; 32]
            || report.sequence != report.operation.checked_add(1).ok_or(Error::Version)?
        {
            return Err(Error::Version);
        }
        if report.mode == Mode::Verify || owner_selected {
            if report.booted != 0
                || report.boot_serial != 0
                || report.process != 0
                || report.thread != 0
                || report.process_stamp != [0; 32]
                || report.booted_cohort != [0; 32]
                || report.negatives != 0
            {
                return Err(Error::Version);
            }
        } else if report.booted != if report.mode == Mode::FailB { 2 } else { 1 }
            || report.boot_serial == 0
            || report.process == 0
            || report.thread == 0
            || report.process_stamp == [0; 32]
            || report.booted_cohort == [0; 32]
            || report.negatives != 4
        {
            return Err(Error::Version);
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn catalogue() -> Catalogue {
        Catalogue {
            kernel_build: [1; 32],
            controller: [2; 32],
            driver: [3; 32],
            image_a: [4; 32],
            image_b: [5; 32],
            abi: [6; 32],
            health: [7; 32],
            health_version: 1,
            required_checks: 3,
        }
    }
    #[test]
    fn catalogue_is_canonical_and_rejects_unbounded_or_ambiguous_identity() {
        let c = catalogue();
        let bytes = c.encode();
        assert_eq!(Catalogue::decode(&bytes), Ok(c));
        for len in 0..BYTES {
            assert_eq!(Catalogue::decode(&bytes[..len]), Err(Error::Length));
        }
        for index in 240..BYTES {
            let mut bad = bytes;
            bad[index] = 1;
            assert_eq!(Catalogue::decode(&bad), Err(Error::Reserved));
        }
        for index in 0..7 {
            let mut bad = bytes;
            bad[16 + index * 32..48 + index * 32].fill(0);
            assert_eq!(Catalogue::decode(&bad), Err(Error::Empty));
        }
        let mut same = c;
        same.image_b = same.image_a;
        assert_eq!(Catalogue::decode(&same.encode()), Err(Error::Images));
        for index in 12..16 {
            let mut bad = bytes;
            bad[index] ^= 8;
            assert_eq!(Catalogue::decode(&bad), Err(Error::Health));
        }
    }
    #[test]
    fn every_capsule_component_and_role_selection_changes_the_transcript() {
        let c = catalogue();
        let original = c.cohort_input(Slot::A);
        assert_ne!(c.cohort_input(Slot::B), c.cohort_input_for(Slot::B, 3));
        assert_ne!(original, c.cohort_input(Slot::B));
        for index in 0..7 {
            let mut bytes = c.encode();
            bytes[16 + index * 32] ^= 0x80;
            let changed = Catalogue::decode(&bytes).unwrap();
            if index == 4 {
                assert_eq!(original, changed.cohort_input(Slot::A));
                assert_ne!(c.cohort_input(Slot::B), changed.cohort_input(Slot::B));
            } else {
                assert_ne!(original, changed.cohort_input(Slot::A));
            }
        }
    }
    #[test]
    fn control_and_completion_are_total_canonical_and_cannot_bless_verify() {
        for mode in [
            Mode::ProvisionA,
            Mode::FailB,
            Mode::AutoA,
            Mode::ManualA,
            Mode::Verify,
        ] {
            let c = Control::new(mode);
            assert_eq!(Control::decode(&c.encode()), Ok(c));
            for len in 0..BYTES {
                assert_eq!(Control::decode(&c.encode()[..len]), Err(Error::Length));
            }
            for i in (6..16).chain(24..BYTES) {
                let mut bad = c.encode();
                bad[i] = 1;
                assert!(Control::decode(&bad).is_err());
            }
        }
        let good = Completion {
            mode: Mode::ProvisionA,
            owner_decision: OwnerDecision::None,
            booted: 1,
            selected: 1,
            known_good: 1,
            boot_serial: 1,
            process: 7,
            thread: 8,
            failure_generation: 0,
            failure_serial: 0,
            failure_reason: 0,
            negatives: 4,
            mutations: 23,
            operation: 4,
            sequence: 5,
            failure_operation: 0,
            failure_sequence: 0,
            catalogue: [1; 32],
            process_stamp: [2; 32],
            storage_probe: [3; 32],
            booted_cohort: [4; 32],
        };
        assert_eq!(Completion::decode(&good.encode()), Ok(good));
        for i in [6, 7].into_iter().chain(256..BYTES) {
            let mut bad = good.encode();
            bad[i] ^= 1;
            assert!(Completion::decode(&bad).is_err());
        }
        let mut wrong = good;
        wrong.negatives = 3;
        assert!(Completion::decode(&wrong.encode()).is_err());
        wrong = good;
        wrong.mode = Mode::Verify;
        assert!(Completion::decode(&wrong.encode()).is_err());
        let verify = Completion {
            mode: Mode::Verify,
            booted: 0,
            boot_serial: 0,
            process: 0,
            thread: 0,
            negatives: 0,
            process_stamp: [0; 32],
            booted_cohort: [0; 32],
            ..good
        };
        assert_eq!(Completion::decode(&verify.encode()), Ok(verify));
    }
    #[test]
    fn owner_prompt_control_cannot_encode_a_choice_or_an_unbounded_wait() {
        for ticks in [1, 500, 60_000] {
            let control = Control::owner_recover(ticks).unwrap();
            assert_eq!(Control::decode(&control.encode()), Ok(control));
        }
        assert!(Control::owner_recover(0).is_none());
        assert!(Control::owner_recover(60_001).is_none());
        assert_eq!(Control::new(Mode::OwnerRecover).prompt_ticks, 60_000);
        let mut bad = Control::new(Mode::OwnerPrepare3).encode();
        bad[8] = 1;
        assert!(Control::decode(&bad).is_err());
        let mut bad = Control::new(Mode::OwnerRecover).encode();
        bad[7] = 1;
        assert!(Control::decode(&bad).is_err());
    }
    #[test]
    fn owner_cancel_cannot_claim_execution_health_selection_or_storage_mutation() {
        let prepared = Completion {
            mode: Mode::OwnerPrepare3,
            owner_decision: OwnerDecision::None,
            booted: 0,
            selected: 3,
            known_good: 1,
            boot_serial: 0,
            process: 0,
            thread: 0,
            failure_generation: 2,
            failure_serial: 2,
            failure_reason: 1,
            negatives: 0,
            mutations: 10,
            operation: 16,
            sequence: 17,
            failure_operation: 10,
            failure_sequence: 11,
            catalogue: [1; 32],
            process_stamp: [0; 32],
            storage_probe: [2; 32],
            booted_cohort: [0; 32],
        };
        assert_eq!(Completion::decode(&prepared.encode()), Ok(prepared));
        for choice in [
            OwnerDecision::Cancel,
            OwnerDecision::Timeout,
            OwnerDecision::InputFault,
            OwnerDecision::InputBudget,
        ] {
            let cancelled = Completion {
                mode: Mode::OwnerRecover,
                owner_decision: choice,
                mutations: 0,
                ..prepared
            };
            assert_eq!(Completion::decode(&cancelled.encode()), Ok(cancelled));
            for wrong in [
                Completion {
                    selected: 1,
                    ..cancelled
                },
                Completion {
                    mutations: 1,
                    ..cancelled
                },
                Completion {
                    process: 7,
                    ..cancelled
                },
                Completion {
                    owner_decision: OwnerDecision::Continue,
                    ..cancelled
                },
            ] {
                assert!(Completion::decode(&wrong.encode()).is_err());
            }
        }
        let resumed = Completion {
            mode: Mode::OwnerRecover,
            owner_decision: OwnerDecision::Continue,
            booted: 1,
            selected: 1,
            boot_serial: 4,
            process: 7,
            thread: 8,
            process_stamp: [3; 32],
            booted_cohort: [4; 32],
            negatives: 4,
            mutations: 22,
            operation: 21,
            sequence: 22,
            ..prepared
        };
        assert_eq!(Completion::decode(&resumed.encode()), Ok(resumed));
        let wrong = Completion {
            mode: Mode::ProvisionA,
            ..resumed
        };
        assert!(Completion::decode(&wrong.encode()).is_err());
    }
}
