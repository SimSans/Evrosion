//! Root-only v2 manifest. Measurement comes from trusted boot selection.
//! Syntax and a role description confer no device/memory authority.
use crate::{
    capability::{Kind, Rights},
    restart, scheduler,
};
use ev_userspace_contract::root_v2;
use sha2::{Digest, Sha256};
pub const HEADER: usize = root_v2::MANIFEST_HEADER;
pub const GRANT_BYTES: usize = 32;
pub const MAX_BYTES: usize = HEADER + root_v2::MAX_GRANTS * GRANT_BYTES;
const MAGIC: &[u8; 8] = b"EVBM0002";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Measurement,
    Version,
    Reserved,
    Abi,
    Startup,
    Profile,
    Image,
    Limits,
    Restart,
    Count,
    Order,
    Kind,
    Rights,
    Constraint,
    Roles,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    pub selector: u64,
    pub kind: Kind,
    pub rights: Rights,
}
pub struct Manifest<'a> {
    bytes: &'a [u8],
    image: &'a [u8],
    measurement: [u8; 32],
    limits: scheduler::Limits,
    restart: restart::Policy,
    count: usize,
}
fn word(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn kind(tag: u8) -> Option<Kind> {
    Some(match tag {
        1 => Kind::Memory,
        2 => Kind::Endpoint,
        3 => Kind::Process,
        4 => Kind::Thread,
        5 => Kind::Job,
        6 => Kind::Mutex,
        7 => Kind::IoPorts,
        8 => Kind::Display,
        _ => return None,
    })
}
pub fn kind_tag(kind: Kind) -> u8 {
    match kind {
        Kind::Memory => 1,
        Kind::Endpoint => 2,
        Kind::Process => 3,
        Kind::Thread => 4,
        Kind::Job => 5,
        Kind::Mutex => 6,
        Kind::IoPorts => 7,
        Kind::Display => 8,
    }
}
impl<'a> Manifest<'a> {
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub fn root_image(&self) -> &'a [u8] {
        self.image
    }
    pub fn digest(&self) -> [u8; 32] {
        self.measurement
    }
    pub fn executable(&self) -> u64 {
        word(self.bytes, 8)
    }
    pub fn abi_fingerprint(&self) -> [u8; 32] {
        self.bytes[48..80].try_into().unwrap()
    }
    pub fn profile(&self) -> u16 {
        u16::from_le_bytes(self.bytes[172..174].try_into().unwrap())
    }
    pub fn limits(&self) -> scheduler::Limits {
        self.limits
    }
    pub fn restart_policy(&self) -> restart::Policy {
        self.restart
    }
    pub fn expected_authority_digest(&self) -> [u8; 32] {
        self.bytes[128..160].try_into().unwrap()
    }
    pub fn expected_catalogue_digest(&self) -> [u8; 32] {
        self.bytes[176..208].try_into().unwrap()
    }

    pub fn grants(&self) -> impl Iterator<Item = Grant> + '_ {
        (0..self.count).map(|i| {
            let b = &self.bytes[HEADER + i * GRANT_BYTES..];
            Grant {
                selector: word(b, 0),
                kind: kind(b[8]).unwrap(),
                rights: Rights::from_bits(u16::from_le_bytes(b[10..12].try_into().unwrap()))
                    .unwrap(),
            }
        })
    }
    /// Narrow the measured description to the original desktop profile only.
    /// Extra wire capacity is not permission to attach arbitrary new resources.
    pub fn current_profile(self) -> Result<CurrentRoot<'a>, Error> {
        if self.profile() != root_v2::PROFILE || self.abi_fingerprint() != root_v2::ABI {
            return Err(Error::Profile);
        }
        if self.count != root_v2::CURRENT_GRANTS
            || self.executable() != root_v2::EXECUTABLE_SELECTOR
        {
            return Err(Error::Roles);
        }
        for (g, s) in self.grants().zip(root_v2::ROLES) {
            if (g.selector, kind_tag(g.kind), g.rights.bits())
                != (s.role.selector(), s.kind, s.rights)
            {
                return Err(Error::Roles);
            }
        }
        Ok(CurrentRoot { manifest: self })
    }
    /// Native profile3 has an independent ABI and exactly22 declared sources.
    /// Spare wire capacity never grants permission for arbitrary extra roles.
    pub fn native_profile(self) -> Result<NativeRoot<'a>, Error> {
        if self.profile() != root_v2::native::PROFILE
            || self.abi_fingerprint() != root_v2::native::ABI
        {
            return Err(Error::Profile);
        }
        if self.count != root_v2::native::CURRENT_GRANTS
            || self.executable() != root_v2::EXECUTABLE_SELECTOR
        {
            return Err(Error::Roles);
        }
        for (g, s) in self.grants().zip(root_v2::native::ROLES) {
            if (g.selector, kind_tag(g.kind), g.rights.bits()) != (s.selector, s.kind, s.rights) {
                return Err(Error::Roles);
            }
        }
        Ok(NativeRoot { manifest: self })
    }
}
/// Only this wrapper can select the RootV2 executable/activation path.
pub struct CurrentRoot<'a> {
    manifest: Manifest<'a>,
}
impl<'a> CurrentRoot<'a> {
    pub fn manifest(&self) -> &Manifest<'a> {
        &self.manifest
    }
}
/// Explicit native profile selection. This cannot be constructed by parsing a
/// desktop record, merely supplying22 roles, or naming a known ABI integer.
pub struct NativeRoot<'a> {
    manifest: Manifest<'a>,
}
impl<'a> NativeRoot<'a> {
    pub fn manifest(&self) -> &Manifest<'a> {
        &self.manifest
    }
}
pub fn verify<'a>(
    bytes: &'a [u8],
    expected: [u8; 32],
    image: &'a [u8],
) -> Result<Manifest<'a>, Error> {
    if !(HEADER..=MAX_BYTES).contains(&bytes.len()) {
        return Err(Error::Length);
    }
    if <[u8; 32]>::from(Sha256::digest(bytes)) != expected {
        return Err(Error::Measurement);
    }
    if &bytes[..8] != MAGIC {
        return Err(Error::Version);
    }
    if bytes[113..120]
        .iter()
        .chain(&bytes[161..168])
        .chain(&bytes[174..176])
        .any(|&x| x != 0)
    {
        return Err(Error::Reserved);
    }
    if bytes[48..80] != root_v2::ABI && bytes[48..80] != root_v2::native::ABI {
        return Err(Error::Abi);
    }
    let startup_version = if bytes[48..80] == root_v2::native::ABI {
        root_v2::native::VERSION
    } else {
        root_v2::VERSION
    };
    if u16::from_le_bytes(bytes[168..170].try_into().unwrap()) != startup_version
        || usize::from(u16::from_le_bytes(bytes[170..172].try_into().unwrap())) != root_v2::SIZE
    {
        return Err(Error::Startup);
    }
    let profile = u16::from_le_bytes(bytes[172..174].try_into().unwrap());
    if !((profile == root_v2::PROFILE && bytes[48..80] == root_v2::ABI)
        || (profile == root_v2::native::PROFILE && bytes[48..80] == root_v2::native::ABI))
    {
        return Err(Error::Profile);
    }
    let count = usize::from(bytes[160]);
    if !(1..=root_v2::MAX_GRANTS).contains(&count) {
        return Err(Error::Count);
    }
    if bytes.len() != HEADER + count * GRANT_BYTES {
        return Err(Error::Length);
    }
    let executable = word(bytes, 8);
    if executable == 0 {
        return Err(Error::Order);
    }
    let limits = [80, 88, 96, 104].map(|i| word(bytes, i));
    if limits.iter().any(|x| matches!(*x, 0 | u64::MAX))
        || limits[2] > scheduler::MAX_PROCESSES as u64
        || limits[3] > scheduler::MAX_THREADS as u64
    {
        return Err(Error::Limits);
    }
    let restart = restart::Policy::new(bytes[112], word(bytes, 120)).map_err(|_| Error::Restart)?;
    let mut previous = 0;
    for b in bytes[HEADER..].as_chunks::<GRANT_BYTES>().0 {
        let selector = word(b, 0);
        if selector <= previous || selector == executable {
            return Err(Error::Order);
        }
        previous = selector;
        if b[9] != 0 || b[12..16].iter().any(|&x| x != 0) {
            return Err(Error::Reserved);
        }
        let kind = kind(b[8]).ok_or(Error::Kind)?;
        let rights = Rights::from_bits(u16::from_le_bytes(b[10..12].try_into().unwrap()))
            .ok_or(Error::Rights)?;
        if rights.bits() == 0 || !kind.permits(rights) {
            return Err(Error::Rights);
        }
        // No production range authority exists yet. Do not parse then discard it.
        if b[16..32].iter().any(|&x| x != 0) {
            return Err(Error::Constraint);
        }
    }
    if image.is_empty()
        || image.len() > crate::bootstrap_manifest::MAX_IMAGE_BYTES
        || Sha256::digest(image).as_slice() != &bytes[16..48]
    {
        return Err(Error::Image);
    }
    Ok(Manifest {
        bytes,
        image,
        measurement: expected,
        limits: scheduler::Limits::new(limits[0], limits[1], limits[2], limits[3]),
        restart,
        count,
    })
}

#[cfg(test)]
mod native_tests;
