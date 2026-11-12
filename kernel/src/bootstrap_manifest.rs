//! Internal bounded bootstrap artifact validation, not authority minting.
//!
//! Expected manifest digest and ABI fingerprint must come from trusted boot
//! selection/compiled contract data, never from the untrusted artifact itself.
//! No secure-boot, signature, executable loading or BAC integration is implied.
use crate::{
    capability::{Kind, Rights},
    restart, scheduler,
};
use sha2::{Digest, Sha256};

pub const HEADER_BYTES: usize = 168;
pub const GRANT_BYTES: usize = 32;
pub const MAX_GRANTS: usize = 8;
pub const MAX_BYTES: usize = HEADER_BYTES + MAX_GRANTS * GRANT_BYTES;
pub const MAX_IMAGE_BYTES: usize = 1024 * 1024;
const MAGIC: &[u8; 8] = b"EVBM0001";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    ManifestDigest,
    Version,
    Reserved,
    Selector,
    GrantCount,
    GrantOrder,
    Kind,
    Rights,
    Constraint,
    JobLimits,
    RestartPolicy,
    Abi,
    ImageLength,
    ImageDigest,
}

/// Boot-catalog selector, never a runtime capability handle. A future resolver
/// must bind it to a sealed object before grants may be minted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selector(u64);
impl Selector {
    pub fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Constraint {
    WholeObject,
    /// Page-aligned byte extent. Future mapping/minting must enforce this range;
    /// successful parsing alone must never strip a constraint from a grant.
    MemoryRange {
        start: u64,
        length: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    pub selector: Selector,
    pub kind: Kind,
    pub rights: Rights,
    pub constraint: Constraint,
}

/// Holds an immutable borrow of the exact measured bytes. No public constructor
/// or mutable grant view can bypass validation.
pub struct Manifest<'a> {
    bytes: &'a [u8],
    image: &'a [u8],
    digest: [u8; 32],
    executable: Selector,
    grants: [Option<Grant>; MAX_GRANTS],
    limits: scheduler::Limits,
    restart: restart::Policy,
    authority_digest: [u8; 32],
}
impl<'a> Manifest<'a> {
    /// Keep the measured image borrowed until the trusted loader has consumed it.
    pub fn root_image(&self) -> &'a [u8] {
        self.image
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn abi_fingerprint(&self) -> [u8; 32] {
        self.bytes[48..80].try_into().unwrap()
    }
    pub fn executable(&self) -> Selector {
        self.executable
    }
    pub fn grants(&self) -> impl Iterator<Item = &Grant> {
        self.grants.iter().flatten()
    }
    pub fn limits(&self) -> scheduler::Limits {
        self.limits
    }
    pub fn restart_policy(&self) -> restart::Policy {
        self.restart
    }
    /// Claimed expected set digest, authenticated by the manifest measurement.
    /// A future resolver must compute the actual canonical authority-set digest
    /// from sealed object identities, rights, constraints and custody lineage.
    pub fn expected_authority_digest(&self) -> [u8; 32] {
        self.authority_digest
    }
}

// Called only on fixed-size slices after the total record length is validated.
fn word(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}
fn digest(bytes: &[u8], offset: usize) -> [u8; 32] {
    let mut value = [0; 32];
    value.copy_from_slice(&bytes[offset..offset + 32]);
    value
}

/// Validate the bounded canonical Internal format and both content measurements.
/// All lengths are checked before hashing/parsing; no heap, pointer casts or
/// attacker-controlled iteration bounds. Policy is data, not a grant of access.
pub fn verify<'a>(
    bytes: &'a [u8],
    expected_manifest: [u8; 32],
    root_image: &'a [u8],
    expected_abi: [u8; 32],
) -> Result<Manifest<'a>, Error> {
    if !(HEADER_BYTES..=MAX_BYTES).contains(&bytes.len()) {
        return Err(Error::Length);
    }
    let measured: [u8; 32] = Sha256::digest(bytes).into();
    if measured != expected_manifest {
        return Err(Error::ManifestDigest);
    }
    if &bytes[..8] != MAGIC {
        return Err(Error::Version);
    }
    if bytes[113..120]
        .iter()
        .chain(&bytes[161..168])
        .any(|b| *b != 0)
    {
        return Err(Error::Reserved);
    }
    let count = usize::from(bytes[160]);
    if count == 0 || count > MAX_GRANTS {
        return Err(Error::GrantCount);
    }
    if bytes.len() != HEADER_BYTES + count * GRANT_BYTES {
        return Err(Error::Length);
    }
    let executable = Selector(word(bytes, 8));
    if executable.0 == 0 {
        return Err(Error::Selector);
    }
    if digest(bytes, 48) != expected_abi {
        return Err(Error::Abi);
    }
    let cpu = word(bytes, 80);
    let frames = word(bytes, 88);
    let processes = word(bytes, 96);
    let threads = word(bytes, 104);
    if [cpu, frames, processes, threads]
        .iter()
        .any(|v| *v == 0 || *v == u64::MAX)
        || processes > scheduler::MAX_PROCESSES as u64
        || threads > scheduler::MAX_THREADS as u64
    {
        return Err(Error::JobLimits);
    }
    let restart =
        restart::Policy::new(bytes[112], word(bytes, 120)).map_err(|_| Error::RestartPolicy)?;
    let mut grants = [None; MAX_GRANTS];
    let mut previous = 0;
    for (slot, record) in grants
        .iter_mut()
        .zip(bytes[HEADER_BYTES..].as_chunks::<GRANT_BYTES>().0)
    {
        let selector = Selector(word(record, 0));
        if selector.0 == 0 || selector == executable {
            return Err(Error::Selector);
        }
        if selector.0 <= previous {
            return Err(Error::GrantOrder);
        }
        previous = selector.0;
        if record[9] != 0 || record[12..16].iter().any(|b| *b != 0) {
            return Err(Error::Reserved);
        }
        let kind = match record[8] {
            1 => Kind::Memory,
            2 => Kind::Endpoint,
            3 => Kind::Process,
            4 => Kind::Thread,
            5 => Kind::Job,
            6 => Kind::Mutex,
            7 => Kind::IoPorts,
            8 => Kind::Display,
            _ => return Err(Error::Kind),
        };
        let bits = u16::from_le_bytes([record[10], record[11]]);
        let rights = Rights::from_bits(bits).ok_or(Error::Rights)?;
        if bits == 0 || !kind.permits(rights) {
            return Err(Error::Rights);
        }
        let start = word(record, 16);
        let length = word(record, 24);
        let constraint = if start == 0 && length == 0 {
            Constraint::WholeObject
        } else if kind == Kind::Memory
            && length != 0
            && start.is_multiple_of(4096)
            && length.is_multiple_of(4096)
            && start.checked_add(length).is_some()
        {
            Constraint::MemoryRange { start, length }
        } else {
            return Err(Error::Constraint);
        };
        *slot = Some(Grant {
            selector,
            kind,
            rights,
            constraint,
        });
    }
    if root_image.is_empty() || root_image.len() > MAX_IMAGE_BYTES {
        return Err(Error::ImageLength);
    }
    let image_digest: [u8; 32] = Sha256::digest(root_image).into();
    if image_digest != digest(bytes, 16) {
        return Err(Error::ImageDigest);
    }
    Ok(Manifest {
        bytes,
        image: root_image,
        digest: measured,
        executable,
        grants,
        limits: scheduler::Limits::new(cpu, frames, processes, threads),
        restart,
        authority_digest: digest(bytes, 128),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const IMAGE: &[u8] = b"abc";
    const ABI: [u8; 32] = [42; 32];
    const IMAGE_SHA256: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    fn put(b: &mut [u8], offset: usize, v: u64) {
        b[offset..offset + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn fixture() -> [u8; HEADER_BYTES + 2 * GRANT_BYTES] {
        let mut b = [0; HEADER_BYTES + 2 * GRANT_BYTES];
        b[..8].copy_from_slice(MAGIC);
        put(&mut b, 8, 100);
        b[16..48].copy_from_slice(&IMAGE_SHA256);
        b[48..80].copy_from_slice(&ABI);
        for (offset, v) in [(80, 1000), (88, 64), (96, 4), (104, 8), (120, 60)] {
            put(&mut b, offset, v);
        }
        b[112] = 3;
        b[128..160].fill(7);
        b[160] = 2;
        put(&mut b, 168, 1);
        b[176] = 1;
        b[178] = 1; // memory READ
        put(&mut b, 184, 4096);
        put(&mut b, 192, 8192);
        put(&mut b, 200, 2);
        b[208] = 2;
        b[210] = 8; // endpoint SEND
        b
    }
    fn check(b: &[u8]) -> Result<Manifest<'_>, Error> {
        verify(b, Sha256::digest(b).into(), IMAGE, ABI)
    }
    #[test]
    fn validated_measurement_preserves_descriptions_and_drives_existing_budget() {
        let b = fixture();
        let m = check(&b).unwrap();
        assert_eq!(m.bytes(), b);
        assert_eq!(m.executable().value(), 100);
        assert_eq!(m.digest(), <[u8; 32]>::from(Sha256::digest(b)));
        // Independently encoded with Python struct.pack and hashlib.sha256.
        assert_eq!(
            m.digest(),
            [
                0xa0, 0xf1, 0x8c, 0x27, 0x5c, 0xfb, 0x86, 0x9c, 0x04, 0xa6, 0xa8, 0xab, 0x19, 0xae,
                0x61, 0xf9, 0x36, 0x77, 0x1c, 0x3c, 0x1a, 0x60, 0xfc, 0xb8, 0xab, 0x97, 0x7a, 0x81,
                0x04, 0x61, 0xba, 0x4d,
            ]
        );
        assert_eq!(m.expected_authority_digest(), [7; 32]);
        let mut grants = m.grants();
        let first = grants.next().unwrap();
        assert_eq!(
            first.constraint,
            Constraint::MemoryRange {
                start: 4096,
                length: 8192
            }
        );
        assert_eq!(first.rights, Rights::READ);
        assert_eq!(grants.next().unwrap().kind, Kind::Endpoint);
        assert!(grants.next().is_none());
        let mut budget = restart::Budget::new(m.restart_policy());
        for _ in 0..3 {
            assert_eq!(budget.admit(0), Ok(()));
        }
        assert_eq!(
            budget.admit(0),
            Err(restart::RecoveryRequired::BudgetExhausted)
        );
    }
    #[test]
    fn every_single_bit_mutation_is_rejected_against_trusted_manifest_measurement() {
        let original = fixture();
        let expected = Sha256::digest(original).into();
        for bit in 0..original.len() * 8 {
            let mut b = original;
            b[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(
                verify(&b, expected, IMAGE, ABI).err(),
                Some(Error::ManifestDigest)
            );
        }
    }
    #[test]
    fn truncation_trailing_data_and_unbounded_inputs_are_rejected() {
        let b = fixture();
        for length in 0..b.len() {
            assert!(check(&b[..length]).is_err());
        }
        let mut padded = [0; MAX_BYTES + 1];
        padded[..b.len()].copy_from_slice(&b);
        for length in b.len() + 1..=padded.len() {
            assert!(check(&padded[..length]).is_err());
        }
        for count in [0, 9, 255] {
            let mut b = b;
            b[160] = count;
            assert_eq!(check(&b).err(), Some(Error::GrantCount));
        }
    }
    #[test]
    fn measured_but_semantically_invalid_records_are_rejected() {
        for (offset, value, error) in [
            (0, 0, Error::Version),
            (113, 1, Error::Reserved),
            (161, 1, Error::Reserved),
            (177, 1, Error::Reserved),
            (180, 1, Error::Reserved),
            (176, 0, Error::Kind),
            (178, 0, Error::Rights),
            (178, 8, Error::Rights),
            (179, 2, Error::Rights),
            (208, 1, Error::Rights),
            (112, 9, Error::RestartPolicy),
        ] {
            let mut b = fixture();
            b[offset] = value;
            assert_eq!(check(&b).err(), Some(error), "offset={offset}");
        }
        for (offset, value, error) in [
            (8, 0, Error::Selector),
            (168, 0, Error::Selector),
            (168, 100, Error::Selector),
            (200, 1, Error::GrantOrder),
            (168, 3, Error::GrantOrder),
            (184, 1, Error::Constraint),
            (192, 0, Error::Constraint),
            (192, u64::MAX - 4095, Error::Constraint),
            (216, 4096, Error::Constraint),
            (120, 0, Error::RestartPolicy),
            (80, 0, Error::JobLimits),
            (88, u64::MAX, Error::JobLimits),
            (96, 17, Error::JobLimits),
            (104, 33, Error::JobLimits),
        ] {
            let mut b = fixture();
            put(&mut b, offset, value);
            assert_eq!(check(&b).err(), Some(error), "offset={offset}");
        }
    }
    #[test]
    fn image_and_abi_are_independently_verified() {
        let b = fixture();
        let expected = Sha256::digest(b).into();
        assert_eq!(
            verify(&b, expected, b"abd", ABI).err(),
            Some(Error::ImageDigest)
        );
        assert_eq!(verify(&b, expected, IMAGE, [0; 32]).err(), Some(Error::Abi));
        assert_eq!(
            verify(&b, expected, &[], ABI).err(),
            Some(Error::ImageLength)
        );
        // A big static avoids overflowing the host test thread's stack.
        static LARGE: [u8; MAX_IMAGE_BYTES + 1] = [0; MAX_IMAGE_BYTES + 1];
        assert_eq!(
            verify(&b, expected, &LARGE, ABI).err(),
            Some(Error::ImageLength)
        );
    }

    #[test]
    fn validated_job_limits_are_enforced_by_the_existing_scheduler() {
        let bytes = fixture();
        let manifest = check(&bytes).unwrap();
        assert_eq!(manifest.root_image(), IMAGE);
        let mut scheduler = scheduler::Scheduler::new();
        let job = scheduler.create_job_with_limits(manifest.limits()).unwrap();
        assert_eq!(scheduler.charge_frames(job, 64), Ok(()));
        assert_eq!(
            scheduler.charge_frames(job, 1),
            Err(scheduler::Error::Budget)
        );
        assert_eq!(scheduler.usage(job, scheduler::Resource::Frames), Ok(64));
        for _ in 0..4 {
            assert!(scheduler.create_process(job).is_ok());
        }
        assert_eq!(scheduler.create_process(job), Err(scheduler::Error::Budget));
    }
    #[test]
    fn maximum_grants_and_disabled_restarts_are_supported_without_clamping() {
        let mut b = [0; MAX_BYTES];
        b[..232].copy_from_slice(&fixture());
        b[160] = 8;
        b[112] = 0;
        for i in 2..8 {
            let offset = HEADER_BYTES + i * GRANT_BYTES;
            put(&mut b, offset, i as u64 + 1);
            b[offset + 8] = 5;
            b[offset + 10] = 1;
        }
        let m = check(&b).unwrap();
        assert_eq!(m.grants().count(), 8);
        assert_eq!(
            restart::Budget::new(m.restart_policy()).admit(0),
            Err(restart::RecoveryRequired::BudgetExhausted)
        );
    }
    #[test]
    fn bounded_arbitrary_authenticated_input_never_panics() {
        let mut seed = 17u64;
        for _ in 0..4096 {
            let mut b = fixture();
            for _ in 0..4 {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let index = (seed >> 32) as usize % b.len();
                b[index] = (seed >> 8) as u8;
            }
            let _ = check(&b);
        }
    }
}

#[cfg(test)]
mod mutex_wire_tests {
    use super::*;
    const ELF: &[u8] = include_bytes!("../fixtures/bootstrap-static-v1.elf");
    #[test]
    fn mutex_tag_six_accepts_only_common_rights_and_whole_object() {
        let mut bytes = *include_bytes!("../fixtures/bootstrap-static-v1.bin");
        bytes[168 + 8] = 6;
        bytes[168 + 10..168 + 12].copy_from_slice(&Rights::CONTROL.bits().to_le_bytes());
        let expected: [u8; 32] = Sha256::digest(bytes).into();
        let m = verify(&bytes, expected, ELF, [42; 32]).unwrap();
        assert_eq!(m.grants().next().unwrap().kind, Kind::Mutex);
        for right in [
            Rights::READ,
            Rights::WRITE,
            Rights::MAP,
            Rights::SEND,
            Rights::RECEIVE,
        ] {
            bytes[168 + 10..168 + 12].copy_from_slice(&right.bits().to_le_bytes());
            assert_eq!(
                verify(&bytes, Sha256::digest(bytes).into(), ELF, [42; 32]).err(),
                Some(Error::Rights)
            );
        }
    }
}
