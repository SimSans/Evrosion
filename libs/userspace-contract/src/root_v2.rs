//! Root-only additive bootstrap. A decoded handle or catalogue is not authority.
#![forbid(unsafe_code)]
use crate::{Context, Grant};
pub mod catalogue;
pub mod graph;
pub mod native;

pub const VERSION: u16 = 2;
pub const PROFILE: u16 = 1;
pub const SIZE: usize = 720;
pub const HEADER: usize = 144;
pub const GRANT_BYTES: usize = 24;
pub const MAX_GRANTS: usize = 24;
pub const CURRENT_GRANTS: usize = 18;
/// Canonical measured Root manifest profile. This is separate from the720-byte
/// volatile startup record and never contains live capability handles.
pub const MANIFEST_HEADER: usize = 208;
pub const MANIFEST_GRANT_BYTES: usize = 32;
pub const MANIFEST_CURRENT_BYTES: usize = MANIFEST_HEADER + CURRENT_GRANTS * MANIFEST_GRANT_BYTES;
pub const EXECUTABLE_SELECTOR: u64 = 1000;

pub const ABI_DESCRIPTION: &[u8] = b"Evrosion Internal Root bootstrap v2; x86_64; readonly720; max24 explicit grants; full-graph profile1=18 with App/Shell surfaces; rdi=record;rsi=720; int80 scalar v1; not ServiceImage v1";
pub const ABI: [u8; 32] = [
    0x81, 0xb2, 0x31, 0xf5, 0x60, 0xf1, 0xa9, 0x42, 0xde, 0x5f, 0x02, 0xbb, 0x06, 0x15, 0xfc, 0x5b,
    0x72, 0x8b, 0xf3, 0x64, 0x5f, 0x74, 0x7f, 0x7f, 0xa6, 0xea, 0x7d, 0xa6, 0xfd, 0x94, 0xe6, 0x1e,
];
const MAGIC: &[u8; 8] = b"EVROOT02";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Role {
    ShellImage = 1,
    InputImage = 2,
    FileImage = 3,
    BlockImage = 4,
    AppImage = 5,
    DisplayImage = 6,
    CreatorJob = 7,
    Events = 8,
    Surface = 9,
    SystemIo = 10,
    FileIo = 11,
    AppFile = 12,
    Catalogue = 13,
    ShellSurface = 14,
    AtaPorts = 15,
    InputPorts = 16,
    Display = 17,
    OwnerUart = 18,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoleSpec {
    pub role: Role,
    pub kind: u8,
    pub rights: u16,
}
pub const ROLES: [RoleSpec; CURRENT_GRANTS] = [
    RoleSpec {
        role: Role::ShellImage,
        kind: 1,
        rights: 1,
    },
    RoleSpec {
        role: Role::InputImage,
        kind: 1,
        rights: 1,
    },
    RoleSpec {
        role: Role::FileImage,
        kind: 1,
        rights: 1,
    },
    RoleSpec {
        role: Role::BlockImage,
        kind: 1,
        rights: 1,
    },
    RoleSpec {
        role: Role::AppImage,
        kind: 1,
        rights: 1,
    },
    RoleSpec {
        role: Role::DisplayImage,
        kind: 1,
        rights: 1,
    },
    RoleSpec {
        role: Role::CreatorJob,
        kind: 5,
        rights: 256,
    },
    RoleSpec {
        role: Role::Events,
        kind: 2,
        rights: 504,
    },
    RoleSpec {
        role: Role::Surface,
        kind: 1,
        rights: 231,
    },
    RoleSpec {
        role: Role::SystemIo,
        kind: 1,
        rights: 231,
    },
    RoleSpec {
        role: Role::FileIo,
        kind: 1,
        rights: 231,
    },
    RoleSpec {
        role: Role::AppFile,
        kind: 1,
        rights: 231,
    },
    RoleSpec {
        role: Role::Catalogue,
        kind: 1,
        rights: 229,
    },
    RoleSpec {
        role: Role::ShellSurface,
        kind: 1,
        rights: 231,
    },
    RoleSpec {
        role: Role::AtaPorts,
        kind: 7,
        rights: 227,
    },
    RoleSpec {
        role: Role::InputPorts,
        kind: 7,
        rights: 227,
    },
    RoleSpec {
        role: Role::Display,
        kind: 8,
        rights: 231,
    },
    RoleSpec {
        role: Role::OwnerUart,
        kind: 7,
        rights: 3,
    },
];
impl Role {
    pub const fn selector(self) -> u64 {
        self as u64
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Version,
    Profile,
    Reserved,
    Identity,
    Limits,
    GrantCount,
    Grant,
    Order,
    Alias,
    Roles,
    Restart,
}
fn word(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
}
fn put(b: &mut [u8], i: usize, n: u64) {
    b[i..i + 8].copy_from_slice(&n.to_le_bytes());
}
fn valid(g: Grant) -> bool {
    let specific = match g.kind {
        1 | 8 => 7,
        2 => 24,
        3..=5 => 1,
        6 => 0,
        7 => 3,
        _ => return false,
    };
    g.selector != 0 && g.handle != 0 && g.rights != 0 && g.rights & !(480 | specific) == 0
}
/// Syntax-validated version2 only. FullGraph::parse additionally enforces its
/// exact measured profile; spare wire slots never silently authorize new roles.
pub struct Bootstrap<'a> {
    bytes: &'a [u8],
    count: usize,
}
impl<'a> Bootstrap<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        Self::parse_profile(bytes, PROFILE)
    }
    fn parse_profile(bytes: &'a [u8], profile: u16) -> Result<Self, Error> {
        Self::parse_profile_version(bytes, VERSION, profile)
    }
    fn parse_profile_version(bytes: &'a [u8], version: u16, profile: u16) -> Result<Self, Error> {
        if bytes.len() != SIZE {
            return Err(Error::Length);
        }
        if &bytes[..8] != MAGIC
            || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != version
            || usize::from(u16::from_le_bytes(bytes[10..12].try_into().unwrap())) != SIZE
        {
            return Err(Error::Version);
        }
        if u16::from_le_bytes(bytes[12..14].try_into().unwrap()) != profile {
            return Err(Error::Profile);
        }
        if bytes[14..16]
            .iter()
            .chain(&bytes[137..HEADER])
            .any(|&b| b != 0)
        {
            return Err(Error::Reserved);
        }
        if [16, 24, 32].into_iter().any(|i| word(bytes, i) == 0) {
            return Err(Error::Identity);
        }
        if [40, 48, 56, 64].into_iter().any(|i| word(bytes, i) == 0) {
            return Err(Error::Limits);
        }
        let count = usize::from(bytes[136]);
        if !(1..=MAX_GRANTS).contains(&count) {
            return Err(Error::GrantCount);
        }
        let value = Self { bytes, count };
        let mut previous = 0;
        let mut handles = [0; MAX_GRANTS];
        for (i, g) in value.grants().enumerate() {
            let b = &bytes[HEADER + i * GRANT_BYTES..HEADER + (i + 1) * GRANT_BYTES];
            if b[17] != 0 || b[20..].iter().any(|&x| x != 0) {
                return Err(Error::Reserved);
            }
            if !valid(g) {
                return Err(Error::Grant);
            }
            if g.selector <= previous {
                return Err(Error::Order);
            }
            if handles[..i].contains(&g.handle) {
                return Err(Error::Alias);
            }
            handles[i] = g.handle;
            previous = g.selector;
        }
        if bytes[HEADER + count * GRANT_BYTES..]
            .iter()
            .any(|&x| x != 0)
        {
            return Err(Error::Reserved);
        }
        Ok(value)
    }
    pub fn context(&self) -> Context {
        Context {
            epoch: word(self.bytes, 16),
            incarnation: word(self.bytes, 24),
            process: word(self.bytes, 32),
            limits: [40, 48, 56, 64].map(|i| word(self.bytes, i)),
            manifest: self.bytes[72..104].try_into().unwrap(),
            authority: self.bytes[104..136].try_into().unwrap(),
        }
    }
    pub fn grants(&self) -> impl Iterator<Item = Grant> + '_ {
        (0..self.count).map(|i| {
            let b = &self.bytes[HEADER + i * GRANT_BYTES..];
            Grant {
                selector: word(b, 0),
                handle: word(b, 8),
                kind: b[16],
                rights: u16::from_le_bytes(b[18..20].try_into().unwrap()),
            }
        })
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
}
pub struct FullGraph<'a>(Bootstrap<'a>);
impl<'a> FullGraph<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let bootstrap = Bootstrap::parse(bytes)?;
        if bootstrap.count != CURRENT_GRANTS {
            return Err(Error::Roles);
        }
        for (g, s) in bootstrap.grants().zip(ROLES) {
            if (g.selector, g.kind, g.rights) != (s.role.selector(), s.kind, s.rights) {
                return Err(Error::Roles);
            }
        }
        Ok(Self(bootstrap))
    }
    pub fn handle(&self, role: Role) -> u64 {
        self.0
            .grants()
            .find(|g| g.selector == role.selector())
            .unwrap()
            .handle
    }
    pub fn context(&self) -> Context {
        self.0.context()
    }
}
/// Raw encoding checks syntax. It is never an authority constructor.
pub fn encode(context: Context, grants: &[Grant]) -> Result<[u8; SIZE], Error> {
    encode_profile(context, grants, PROFILE)
}
fn encode_profile(context: Context, grants: &[Grant], profile: u16) -> Result<[u8; SIZE], Error> {
    encode_profile_version(context, grants, VERSION, profile)
}
fn encode_profile_version(
    context: Context,
    grants: &[Grant],
    version: u16,
    profile: u16,
) -> Result<[u8; SIZE], Error> {
    if !(1..=MAX_GRANTS).contains(&grants.len()) {
        return Err(Error::GrantCount);
    }
    let mut bytes = [0; SIZE];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&version.to_le_bytes());
    bytes[10..12].copy_from_slice(&(SIZE as u16).to_le_bytes());
    bytes[12..14].copy_from_slice(&profile.to_le_bytes());
    for (i, n) in [context.epoch, context.incarnation, context.process]
        .into_iter()
        .enumerate()
    {
        put(&mut bytes, 16 + i * 8, n);
    }
    for (i, n) in context.limits.into_iter().enumerate() {
        put(&mut bytes, 40 + i * 8, n);
    }
    bytes[72..104].copy_from_slice(&context.manifest);
    bytes[104..136].copy_from_slice(&context.authority);
    bytes[136] = grants.len() as u8;
    for (i, g) in grants.iter().enumerate() {
        let b = &mut bytes[HEADER + i * GRANT_BYTES..HEADER + (i + 1) * GRANT_BYTES];
        put(b, 0, g.selector);
        put(b, 8, g.handle);
        b[16] = g.kind;
        b[18..20].copy_from_slice(&g.rights.to_le_bytes());
    }
    Bootstrap::parse_profile_version(&bytes, version, profile)?;
    Ok(bytes)
}
pub fn encode_full_graph(
    context: Context,
    handles: [u64; CURRENT_GRANTS],
) -> Result<[u8; SIZE], Error> {
    let grants = core::array::from_fn::<_, CURRENT_GRANTS, _>(|i| Grant {
        selector: ROLES[i].role.selector(),
        handle: handles[i],
        kind: ROLES[i].kind,
        rights: ROLES[i].rights,
    });
    let bytes = encode(context, &grants)?;
    FullGraph::parse(&bytes)?;
    Ok(bytes)
}

/// Public measurement data, never authority or a loaded-image claim. The
/// consumer hashes actual readonly catalogue bytes and reconstructs this record
/// to compare against its kernel-bound startup Context.manifest.
pub struct ManifestInputs {
    pub root_image: [u8; 32],
    pub catalogue: [u8; 32],
    pub authority: [u8; 32],
    pub limits: [u64; 4],
    pub restart_attempts: u8,
    pub restart_window: u64,
}
pub fn manifest_profile(inputs: ManifestInputs) -> Result<[u8; MANIFEST_CURRENT_BYTES], Error> {
    manifest_profile_for(
        inputs,
        ABI,
        VERSION,
        PROFILE,
        ROLES.map(|s| (s.role.selector(), s.kind, s.rights)),
    )
}
fn manifest_profile_for<const N: usize, const C: usize>(
    inputs: ManifestInputs,
    abi: [u8; 32],
    version: u16,
    profile: u16,
    roles: [(u64, u8, u16); C],
) -> Result<[u8; N], Error> {
    if C == 0 || C > MAX_GRANTS || N != MANIFEST_HEADER + C * MANIFEST_GRANT_BYTES {
        return Err(Error::GrantCount);
    }
    if inputs.limits.iter().any(|n| matches!(*n, 0 | u64::MAX)) {
        return Err(Error::Limits);
    }
    if inputs.restart_attempts > 8 || inputs.restart_window == 0 {
        return Err(Error::Restart);
    }
    let mut bytes = [0; N];
    bytes[..8].copy_from_slice(b"EVBM0002");
    put(&mut bytes, 8, EXECUTABLE_SELECTOR);
    bytes[16..48].copy_from_slice(&inputs.root_image);
    bytes[48..80].copy_from_slice(&abi);
    for (i, n) in inputs.limits.into_iter().enumerate() {
        put(&mut bytes, 80 + i * 8, n);
    }
    bytes[112] = inputs.restart_attempts;
    put(&mut bytes, 120, inputs.restart_window);
    bytes[128..160].copy_from_slice(&inputs.authority);
    bytes[160] = C as u8;
    bytes[168..170].copy_from_slice(&version.to_le_bytes());
    bytes[170..172].copy_from_slice(&(SIZE as u16).to_le_bytes());
    bytes[172..174].copy_from_slice(&profile.to_le_bytes());
    bytes[176..208].copy_from_slice(&inputs.catalogue);
    for (i, (selector, kind, rights)) in roles.into_iter().enumerate() {
        let b = &mut bytes[MANIFEST_HEADER + i * MANIFEST_GRANT_BYTES..];
        put(b, 0, selector);
        b[8] = kind;
        b[10..12].copy_from_slice(&rights.to_le_bytes());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    fn context() -> Context {
        Context {
            epoch: 1,
            incarnation: 2,
            process: 3,
            limits: [4096, 256, 7, 7],
            manifest: [4; 32],
            authority: [5; 32],
        }
    }
    fn fixture() -> [u8; SIZE] {
        encode_full_graph(context(), core::array::from_fn(|i| 100 + i as u64)).unwrap()
    }
    #[test]
    fn root_v2_all_eighteen_roles_roundtrip_and_v1_is_disjoint() {
        let b = fixture();
        let p = FullGraph::parse(&b).unwrap();
        assert_eq!(p.context().incarnation, 2);
        for (i, s) in ROLES.iter().enumerate() {
            assert_eq!(p.handle(s.role), 100 + i as u64);
        }
        assert!(crate::Bootstrap::parse(&b).is_err());
        let old = crate::encode(
            context(),
            &[Grant {
                selector: 1,
                handle: 1,
                kind: 1,
                rights: 1,
            }],
        )
        .unwrap();
        assert!(Bootstrap::parse(&old).is_err());
        assert_eq!(crate::SIZE, 336);
        assert_eq!(crate::MAX_GRANTS, 8);
    }
    #[test]
    fn root_v2_lengths_versions_reserved_and_tail_are_total() {
        let b = fixture();
        for n in 0..b.len() {
            assert!(Bootstrap::parse(&b[..n]).is_err());
        }
        let mut long = std::vec::Vec::from(b);
        long.push(0);
        assert!(Bootstrap::parse(&long).is_err());
        for offset in [
            0,
            8,
            10,
            12,
            14,
            137,
            HEADER + 17,
            HEADER + 20,
            HEADER + CURRENT_GRANTS * GRANT_BYTES,
        ] {
            let mut changed = b;
            changed[offset] ^= 1;
            assert!(Bootstrap::parse(&changed).is_err(), "offset {offset}");
        }
        for count in [0, 25, 255] {
            let mut changed = b;
            changed[136] = count;
            assert!(Bootstrap::parse(&changed).is_err());
        }
    }
    #[test]
    fn root_v2_full_profile_rejects_every_kind_or_rights_drift() {
        let b = fixture();
        for (i, role) in ROLES.iter().enumerate() {
            let offset = HEADER + i * GRANT_BYTES;
            for bit in 0..16 {
                let mut c = b;
                let rights = role.rights ^ (1 << bit);
                c[offset + 18..offset + 20].copy_from_slice(&rights.to_le_bytes());
                assert!(FullGraph::parse(&c).is_err());
            }
            for kind in 0..=9 {
                if kind == role.kind {
                    continue;
                }
                let mut c = b;
                c[offset + 16] = kind;
                assert!(FullGraph::parse(&c).is_err());
            }
        }
    }
    #[test]
    fn root_v2_alias_order_bad_identity_and_max24_closed_shape() {
        let mut b = fixture();
        let first = b[HEADER + 8..HEADER + 16].to_vec();
        b[HEADER + GRANT_BYTES + 8..HEADER + GRANT_BYTES + 16].copy_from_slice(&first);
        assert!(matches!(Bootstrap::parse(&b), Err(Error::Alias)));
        let g = core::array::from_fn::<_, MAX_GRANTS, _>(|i| Grant {
            selector: i as u64 + 1,
            handle: 100 + i as u64,
            kind: 1,
            rights: 1,
        });
        let b = encode(context(), &g).unwrap();
        assert_eq!(Bootstrap::parse(&b).unwrap().grants().count(), 24);
        assert!(FullGraph::parse(&b).is_err());
        let mut c = context();
        c.epoch = u64::MAX;
        c.incarnation = u64::MAX;
        // Nonzero identities preserve v1's full u64 domain. Counter exhaustion
        // belongs to Custodian, not an undocumented wire-reserved identity.
        assert!(encode(c, &g).is_ok());
        c.epoch = 0;
        assert!(encode(c, &g).is_err());
        let mut g = g;
        g[1].selector = 1;
        assert!(encode(context(), &g).is_err());
    }
}
