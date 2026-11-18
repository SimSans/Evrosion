//! Canonical fixed-record metadata. Parsing is syntax, never trust or admission.
use crate::signature::{self, Envelope, KeySet, PublicKey, Role};
use sha2::{Digest, Sha256};

pub const HEADER_BYTES: usize = 160;
pub const ROOT_BYTES: usize = HEADER_BYTES + signature::MAX_KEYS * 32 + 32;
pub const TARGET_BYTES: usize = 288;
pub const MAX_TARGETS: usize = 8;
pub const LINK_BYTES: usize = 48;
pub const MAX_ROOT_THRESHOLD: u8 = (signature::MAX_SIGNATURES / 2) as u8;
const MAGIC: &[u8; 8] = b"EVRMD001";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Signature(signature::Error),
    Length,
    Version,
    Reserved,
    Role,
    Binding,
    Validity,
    KeyOrder,
    Policy,
    TargetOrder,
    Identity,
    Cohort,
}
impl From<signature::Error> for Error {
    fn from(value: signature::Error) -> Self {
        Self::Signature(value)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    pub namespace: [u8; 32],
    pub channel: [u8; 32],
    pub platform: [u8; 32],
}
impl Binding {
    pub fn validate(self) -> Result<(), Error> {
        if [self.namespace, self.channel, self.platform].contains(&[0; 32]) {
            Err(Error::Binding)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Common {
    pub binding: Binding,
    pub version: u64,
    pub root_version: u64,
    pub not_before: u64,
    pub expires: u64,
}
impl Common {
    fn validate(self) -> Result<(), Error> {
        self.binding.validate()?;
        if matches!(self.version, 0 | u64::MAX) || matches!(self.root_version, 0 | u64::MAX) {
            return Err(Error::Version);
        }
        if self.not_before >= self.expires {
            return Err(Error::Validity);
        }
        Ok(())
    }
}
fn word(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn put(bytes: &mut [u8], at: usize, v: u64) {
    bytes[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
fn hash(bytes: &[u8], at: usize) -> [u8; 32] {
    bytes[at..at + 32].try_into().unwrap()
}
fn parse_common(bytes: &[u8], role: Role) -> Result<(Common, usize), Error> {
    if bytes.len() < HEADER_BYTES {
        return Err(Error::Length);
    }
    if &bytes[..8] != MAGIC || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != 1 {
        return Err(Error::Version);
    }
    if bytes[10] != role as u8 {
        return Err(Error::Role);
    }
    if bytes[11..16]
        .iter()
        .chain(bytes[146..HEADER_BYTES].iter())
        .any(|v| *v != 0)
    {
        return Err(Error::Reserved);
    }
    let common = Common {
        binding: Binding {
            namespace: hash(bytes, 40),
            channel: hash(bytes, 72),
            platform: hash(bytes, 104),
        },
        version: word(bytes, 16),
        not_before: word(bytes, 24),
        expires: word(bytes, 32),
        root_version: word(bytes, 136),
    };
    common.validate()?;
    Ok((
        common,
        u16::from_le_bytes(bytes[144..146].try_into().unwrap()) as usize,
    ))
}
fn encode_common(out: &mut [u8], role: Role, common: Common, count: usize) -> Result<(), Error> {
    common.validate()?;
    if out.len() < HEADER_BYTES || count > u16::MAX as usize {
        return Err(Error::Length);
    }
    out[..HEADER_BYTES].fill(0);
    out[..8].copy_from_slice(MAGIC);
    out[8..10].copy_from_slice(&1u16.to_le_bytes());
    out[10] = role as u8;
    put(out, 16, common.version);
    put(out, 24, common.not_before);
    put(out, 32, common.expires);
    out[40..72].copy_from_slice(&common.binding.namespace);
    out[72..104].copy_from_slice(&common.binding.channel);
    out[104..136].copy_from_slice(&common.binding.platform);
    put(out, 136, common.root_version);
    out[144..146].copy_from_slice(&(count as u16).to_le_bytes());
    Ok(())
}
/// Exact whole signed-envelope identity. Its link hash includes signatures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub version: u64,
    pub length: u64,
    pub sha256: [u8; 32],
}
impl Identity {
    pub fn of(envelope: &Envelope<'_>, version: u64) -> Self {
        Self {
            version,
            length: envelope.bytes().len() as u64,
            sha256: Sha256::digest(envelope.bytes()).into(),
        }
    }
    pub fn validate(self) -> Result<(), Error> {
        if matches!(self.version, 0 | u64::MAX)
            || self.length < (signature::HEADER_BYTES + 1 + signature::SIGNATURE_BYTES) as u64
            || self.length > signature::MAX_ENVELOPE_BYTES as u64
            || self.sha256 == [0; 32]
        {
            Err(Error::Identity)
        } else {
            Ok(())
        }
    }
    pub fn matches(self, envelope: &Envelope<'_>, version: u64) -> bool {
        self == Self::of(envelope, version)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RolePolicy {
    pub mask: u8,
    pub threshold: u8,
    pub max_validity_secs: u32,
}
/// Cached canonical public keys are fixed256B; no payload copy/allocator.
#[derive(Clone)]
pub struct Root<'a> {
    envelope: Envelope<'a>,
    common: Common,
    keys: [PublicKey; signature::MAX_KEYS],
    count: usize,
    policies: [RolePolicy; 4],
}
impl<'a> Root<'a> {
    pub fn parse(envelope: &Envelope<'a>) -> Result<Self, Error> {
        if envelope.role() != Role::Root {
            return Err(Error::Role);
        }
        let bytes = envelope.payload();
        let (common, count) = parse_common(bytes, Role::Root)?;
        if bytes.len() != ROOT_BYTES || !(4..=signature::MAX_KEYS).contains(&count) {
            return Err(Error::Length);
        }
        if common.root_version != common.version {
            return Err(Error::Version);
        }
        let first = PublicKey::parse(hash(bytes, HEADER_BYTES))?;
        let mut keys = [first; signature::MAX_KEYS];
        let mut previous = None;
        for (i, key) in keys.iter_mut().enumerate().take(count) {
            *key = PublicKey::parse(hash(bytes, HEADER_BYTES + i * 32))?;
            let id = key.id();
            if previous.is_some_and(|p| p >= id) {
                return Err(Error::KeyOrder);
            }
            previous = Some(id);
        }
        if bytes[HEADER_BYTES + count * 32..HEADER_BYTES + signature::MAX_KEYS * 32]
            .iter()
            .any(|v| *v != 0)
        {
            return Err(Error::Reserved);
        }
        let mut policies = [RolePolicy {
            mask: 0,
            threshold: 0,
            max_validity_secs: 0,
        }; 4];
        let mut used = 0u8;
        for (i, policy) in policies.iter_mut().enumerate() {
            let at = HEADER_BYTES + signature::MAX_KEYS * 32 + i * 8;
            if bytes[at] != i as u8 + 1 || bytes[at + 3] != 0 {
                return Err(Error::Policy);
            }
            *policy = RolePolicy {
                mask: bytes[at + 1],
                threshold: bytes[at + 2],
                max_validity_secs: u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()),
            };
            let valid_mask = ((1u16 << count) - 1) as u8;
            if policy.mask == 0
                || policy.mask & !valid_mask != 0
                || policy.mask & used != 0
                || policy.threshold == 0
                || policy.max_validity_secs == 0
                || u32::from(policy.threshold) > policy.mask.count_ones()
                || (i == 0 && policy.threshold > MAX_ROOT_THRESHOLD)
            {
                return Err(Error::Policy);
            }
            used |= policy.mask;
        }
        if used.count_ones() as usize != count {
            return Err(Error::Policy);
        }
        if common.expires - common.not_before > u64::from(policies[0].max_validity_secs) {
            return Err(Error::Validity);
        }
        Ok(Self {
            envelope: *envelope,
            common,
            keys,
            count,
            policies,
        })
    }
    pub fn common(&self) -> Common {
        self.common
    }
    pub fn identity(&self) -> Identity {
        Identity::of(&self.envelope, self.common.version)
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.envelope.bytes()
    }
    pub fn authenticate(&self, envelope: &Envelope<'_>) -> Result<(), Error> {
        let policy = self.policies[envelope.role() as usize - 1];
        let mut selected = [self.keys[0]; signature::MAX_KEYS];
        let mut count = 0;
        for (i, key) in self.keys.iter().enumerate().take(self.count) {
            if policy.mask & (1 << i) != 0 {
                selected[count] = *key;
                count += 1;
            }
        }
        KeySet::checked_configuration(envelope.role(), &selected[..count], policy.threshold)?
            .verify(envelope)?;
        Ok(())
    }
    pub(crate) fn check_lifetime(&self, role: Role, common: Common) -> Result<(), Error> {
        if common.expires - common.not_before
            > u64::from(self.policies[role as usize - 1].max_validity_secs)
        {
            Err(Error::Validity)
        } else {
            Ok(())
        }
    }
}
/// Public signing-tool helper. Root key records must already be sorted by ID.
pub fn encode_root(
    out: &mut [u8],
    common: Common,
    keys: &[PublicKey],
    policies: [RolePolicy; 4],
) -> Result<usize, Error> {
    if out.len() < ROOT_BYTES || !(4..=signature::MAX_KEYS).contains(&keys.len()) {
        return Err(Error::Length);
    }
    out[..ROOT_BYTES].fill(0);
    encode_common(out, Role::Root, common, keys.len())?;
    for (i, key) in keys.iter().enumerate() {
        out[HEADER_BYTES + i * 32..HEADER_BYTES + (i + 1) * 32].copy_from_slice(&key.bytes());
    }
    for (i, policy) in policies.into_iter().enumerate() {
        let at = HEADER_BYTES + signature::MAX_KEYS * 32 + i * 8;
        out[at] = i as u8 + 1;
        out[at + 1] = policy.mask;
        out[at + 2] = policy.threshold;
        out[at + 4..at + 8].copy_from_slice(&policy.max_validity_secs.to_le_bytes());
    }
    // Exact canonical validation occurs when the signed envelope is parsed.
    Ok(ROOT_BYTES)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetSpec {
    pub name: [u8; 32],
    pub version: u64,
    pub length: u64,
    pub sha256: [u8; 32],
    pub generation: [u8; 32],
    pub release: [u8; 32],
    pub source_revision: [u8; 32],
    pub build: [u8; 32],
    pub provenance: [u8; 32],
    pub contract: [u8; 32],
}
#[derive(Clone, Copy)]
pub struct Target<'a> {
    bytes: &'a [u8],
}
impl Target<'_> {
    pub fn spec(self) -> TargetSpec {
        TargetSpec {
            name: hash(self.bytes, 0),
            version: word(self.bytes, 32),
            length: word(self.bytes, 40),
            sha256: hash(self.bytes, 48),
            generation: hash(self.bytes, 80),
            release: hash(self.bytes, 112),
            source_revision: hash(self.bytes, 144),
            build: hash(self.bytes, 176),
            provenance: hash(self.bytes, 208),
            contract: hash(self.bytes, 240),
        }
    }
    pub fn identity(self) -> [u8; 32] {
        Sha256::digest(self.bytes).into()
    }
    pub fn verify_bytes(self, bytes: &[u8], max_bytes: u64) -> Result<(), Error> {
        let s = self.spec();
        if bytes.len() as u64 != s.length
            || s.length > max_bytes
            || <[u8; 32]>::from(Sha256::digest(bytes)) != s.sha256
        {
            Err(Error::Identity)
        } else {
            Ok(())
        }
    }
    fn validate(self) -> Result<(), Error> {
        let s = self.spec();
        if [
            s.name,
            s.sha256,
            s.generation,
            s.release,
            s.source_revision,
            s.build,
            s.provenance,
            s.contract,
        ]
        .contains(&[0; 32])
            || matches!(s.version, 0 | u64::MAX)
            || matches!(s.length, 0 | u64::MAX)
        {
            return Err(Error::Identity);
        }
        if self.bytes[272..].iter().any(|v| *v != 0) {
            return Err(Error::Reserved);
        }
        Ok(())
    }
}
pub struct Targets<'a> {
    envelope: Envelope<'a>,
    common: Common,
    count: usize,
}
impl<'a> Targets<'a> {
    pub fn parse(envelope: &Envelope<'a>) -> Result<Self, Error> {
        if envelope.role() != Role::Targets {
            return Err(Error::Role);
        }
        let b = envelope.payload();
        let (common, count) = parse_common(b, Role::Targets)?;
        if count > MAX_TARGETS || b.len() != HEADER_BYTES + count * TARGET_BYTES {
            return Err(Error::Length);
        }
        let out = Self {
            envelope: *envelope,
            common,
            count,
        };
        let mut previous = None;
        let mut cohort = None;
        for target in out.iter() {
            target.validate()?;
            let spec = target.spec();
            if previous.is_some_and(|p| p >= spec.name) {
                return Err(Error::TargetOrder);
            }
            previous = Some(spec.name);
            let id = (spec.generation, spec.release);
            if cohort.is_some_and(|p| p != id) {
                return Err(Error::Cohort);
            }
            cohort = Some(id);
        }
        Ok(out)
    }
    pub fn common(&self) -> Common {
        self.common
    }
    pub fn identity(&self) -> Identity {
        Identity::of(&self.envelope, self.common.version)
    }
    pub fn iter(&self) -> impl ExactSizeIterator<Item = Target<'a>> + '_ {
        self.envelope.payload()[HEADER_BYTES..]
            .as_chunks::<TARGET_BYTES>()
            .0
            .iter()
            .map(|b| Target { bytes: b })
    }
    pub fn count(&self) -> usize {
        self.count
    }
}
pub fn encode_targets(
    out: &mut [u8],
    common: Common,
    targets: &[TargetSpec],
) -> Result<usize, Error> {
    if targets.len() > MAX_TARGETS {
        return Err(Error::Length);
    }
    let len = HEADER_BYTES + targets.len() * TARGET_BYTES;
    if out.len() < len {
        return Err(Error::Length);
    }
    out[..len].fill(0);
    encode_common(out, Role::Targets, common, targets.len())?;
    for (i, s) in targets.iter().enumerate() {
        let b = &mut out[HEADER_BYTES + i * TARGET_BYTES..HEADER_BYTES + (i + 1) * TARGET_BYTES];
        b[..32].copy_from_slice(&s.name);
        put(b, 32, s.version);
        put(b, 40, s.length);
        for (at, value) in [
            (48, s.sha256),
            (80, s.generation),
            (112, s.release),
            (144, s.source_revision),
            (176, s.build),
            (208, s.provenance),
            (240, s.contract),
        ] {
            b[at..at + 32].copy_from_slice(&value);
        }
    }
    Ok(len)
}
pub struct Linked<'a> {
    envelope: Envelope<'a>,
    common: Common,
    link: Identity,
}
impl<'a> Linked<'a> {
    pub fn parse(envelope: &Envelope<'a>) -> Result<Self, Error> {
        let role = envelope.role();
        if !matches!(role, Role::Timestamp | Role::Snapshot) {
            return Err(Error::Role);
        }
        let b = envelope.payload();
        let (common, count) = parse_common(b, role)?;
        if count != 1 || b.len() != HEADER_BYTES + LINK_BYTES {
            return Err(Error::Length);
        }
        let link = Identity {
            version: word(b, HEADER_BYTES),
            length: word(b, HEADER_BYTES + 8),
            sha256: hash(b, HEADER_BYTES + 16),
        };
        link.validate()?;
        Ok(Self {
            envelope: *envelope,
            common,
            link,
        })
    }
    pub fn common(&self) -> Common {
        self.common
    }
    pub fn identity(&self) -> Identity {
        Identity::of(&self.envelope, self.common.version)
    }
    pub fn link(&self) -> Identity {
        self.link
    }
}
pub fn encode_link(
    out: &mut [u8],
    role: Role,
    common: Common,
    link: Identity,
) -> Result<usize, Error> {
    if !matches!(role, Role::Timestamp | Role::Snapshot) {
        return Err(Error::Role);
    }
    link.validate()?;
    let len = HEADER_BYTES + LINK_BYTES;
    if out.len() < len {
        return Err(Error::Length);
    }
    out[..len].fill(0);
    encode_common(out, role, common, 1)?;
    put(out, HEADER_BYTES, link.version);
    put(out, HEADER_BYTES + 8, link.length);
    out[HEADER_BYTES + 16..len].copy_from_slice(&link.sha256);
    Ok(len)
}
