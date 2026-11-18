//! Explicit Native Root profile3. Metadata/handles create no authority; actual
//! source ownership, content, mappings and admission are separate mandatory gates.
#![forbid(unsafe_code)]
pub use super::Error;
use super::{Context, Grant, ManifestInputs, Role};
pub mod catalogue;
pub mod report;
#[cfg(test)]
mod tests;
pub const VERSION: u16 = 3;
pub const SIZE: usize = super::SIZE;
pub const PROFILE: u16 = 3;
pub const MAX_GRANTS: usize = super::MAX_GRANTS;
pub const CURRENT_GRANTS: usize = 22;
pub const MANIFEST_CURRENT_BYTES: usize =
    super::MANIFEST_HEADER + CURRENT_GRANTS * super::MANIFEST_GRANT_BYTES;
pub const ABI_DESCRIPTION: &[u8] = b"Evrosion Internal Native Root bootstrap v3; x86_64; readonly720; max24 explicit grants; native profile3=22; Desktop18 sources plus AppBImage READ1, immutable PackageA/PackageB READ|MAP|BRANCH229, BadShellImage READ1; catalogue2560 with measured Standalone/SystemManaged/Recovery boot mode; RootSystem GrantPolicy wire48..61 physical96..109; managedREAD44 actualOpen and ProcessCONTROL, inhibit45 no early revoke; rdi=record;rsi=720; int80 scalar v1; Native Root private stack32KiB pages256..263 guards255/264; Native Root ProcessIdentity38 cap0 call4 outputs actualcapture tick inR10, childCONTROL/oldDesktop/provider retain legacyR10";
pub const ABI: [u8; 32] = [
    86, 20, 227, 21, 63, 165, 152, 254, 193, 63, 198, 167, 7, 142, 184, 21, 111, 54, 23, 234, 86,
    190, 175, 214, 27, 226, 201, 82, 255, 205, 25, 108,
];
pub const ROOT_STACK_FIRST_PAGE: u64 = 256;
pub const ROOT_STACK_PAGES: u64 = 8;
pub const ROOT_STACK_BYTES: u64 = ROOT_STACK_PAGES * 4096;
/// Additional measured layout for the separately built M6 session profile.
/// Existing Native3 bootstrap roles/bytes and finite-profile layout are intact.
pub const SESSION_NOTE_PAGE: u64 = 506;
pub const SESSION_SHARED_SLOTS: usize = 3;
pub const SESSION_LAYOUT: &[u8] = b"evrosion.session.layout.v1\0RootAppFileRW506;sharedClaims3;NoteDataWire64..77Physical112..125;NoteEnvelope2;InputCommonTextSequence1;duration0CPUWindowed;transaction8192;childRPC1024;quiescence1024;queuedRetention9728-not-delivery-guarantee\0";
pub const PACKAGE_MAX_PAGES: u64 = 63;
pub const PACKAGE_PAGE_BYTES: u64 = 4096;
pub const PACKAGE_MAX_BYTES: u64 = PACKAGE_MAX_PAGES * PACKAGE_PAGE_BYTES;
pub const PACKAGE_A_FIRST_PAGE: u64 = 384;
pub const PACKAGE_B_FIRST_PAGE: u64 = 304;
/// Finite executor extent, separate from sampled CPU quotas, RPC deadlines and
/// the Source-owned fixed critical-health window. The caller must obtain mode
/// from its verified full Native catalogue, never from an owner command.
pub const fn world_ticks(mode: catalogue::BootMode) -> u64 {
    match mode {
        catalogue::BootMode::SystemManaged => 32_768,
        catalogue::BootMode::Standalone | catalogue::BootMode::Recovery => 16_384,
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum ExtraRole {
    AppBImage = 19,
    PackageA = 20,
    PackageB = 21,
    BadShellImage = 22,
}
impl ExtraRole {
    pub const fn selector(self) -> u64 {
        self as u64
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoleSpec {
    pub selector: u64,
    pub kind: u8,
    pub rights: u16,
}
const fn roles() -> [RoleSpec; CURRENT_GRANTS] {
    let mut roles = [RoleSpec {
        selector: 0,
        kind: 0,
        rights: 0,
    }; CURRENT_GRANTS];
    let mut i = 0;
    while i < super::CURRENT_GRANTS {
        let base = super::ROLES[i];
        roles[i] = RoleSpec {
            selector: base.role.selector(),
            kind: base.kind,
            rights: base.rights,
        };
        i += 1;
    }
    roles[18] = RoleSpec {
        selector: 19,
        kind: 1,
        rights: 1,
    };
    roles[19] = RoleSpec {
        selector: 20,
        kind: 1,
        rights: 229,
    };
    roles[20] = RoleSpec {
        selector: 21,
        kind: 1,
        rights: 229,
    };
    roles[21] = RoleSpec {
        selector: 22,
        kind: 1,
        rights: 1,
    };
    roles
}
pub const ROLES: [RoleSpec; CURRENT_GRANTS] = roles();
/// Native syntax only, never an admission/authority receipt. FullGraph requires
/// exactly22 named grants; spare max24 slots never widen that profile.
pub struct Bootstrap<'a>(super::Bootstrap<'a>);
impl<'a> Bootstrap<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        super::Bootstrap::parse_profile_version(bytes, VERSION, PROFILE).map(Self)
    }
    pub fn context(&self) -> Context {
        self.0.context()
    }
    pub fn grants(&self) -> impl Iterator<Item = Grant> + '_ {
        self.0.grants()
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.0.bytes()
    }
}
pub struct FullGraph<'a>(Bootstrap<'a>);
impl<'a> FullGraph<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let value = Bootstrap::parse(bytes)?;
        if value.0.count != CURRENT_GRANTS {
            return Err(Error::Roles);
        }
        for (actual, expected) in value.grants().zip(ROLES) {
            if (actual.selector, actual.kind, actual.rights)
                != (expected.selector, expected.kind, expected.rights)
            {
                return Err(Error::Roles);
            }
        }
        Ok(Self(value))
    }
    pub fn handle(&self, role: Role) -> u64 {
        self.find(role.selector())
    }
    pub fn extra(&self, role: ExtraRole) -> u64 {
        self.find(role.selector())
    }
    fn find(&self, selector: u64) -> u64 {
        self.0
            .grants()
            .find(|g| g.selector == selector)
            .unwrap()
            .handle
    }
    pub fn context(&self) -> Context {
        self.0.context()
    }
    pub fn grants(&self) -> impl Iterator<Item = Grant> + '_ {
        self.0.grants()
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.0.bytes()
    }
}
/// Raw Native syntax encoding, not authority. Consumers requiring the current
/// profile must use FullGraph; additional roles remain explicitly rejected.
pub fn encode(context: Context, grants: &[Grant]) -> Result<[u8; SIZE], Error> {
    super::encode_profile_version(context, grants, VERSION, PROFILE)
}
pub fn encode_full_graph(
    context: Context,
    handles: [u64; CURRENT_GRANTS],
) -> Result<[u8; SIZE], Error> {
    let grants = core::array::from_fn::<_, CURRENT_GRANTS, _>(|i| Grant {
        selector: ROLES[i].selector,
        handle: handles[i],
        kind: ROLES[i].kind,
        rights: ROLES[i].rights,
    });
    let bytes = encode(context, &grants)?;
    FullGraph::parse(&bytes)?;
    Ok(bytes)
}
pub fn manifest_profile(inputs: ManifestInputs) -> Result<[u8; MANIFEST_CURRENT_BYTES], Error> {
    super::manifest_profile_for(
        inputs,
        ABI,
        VERSION,
        PROFILE,
        ROLES.map(|r| (r.selector, r.kind, r.rights)),
    )
}

/// Canonical Native root layout measurement input. It names fixed readonly
/// banks and all disk region bounds; it conveys no address or sector authority.
pub const LAYOUT_ROLES_OFFSET: usize = 256;
pub const LAYOUT_BYTES: usize = LAYOUT_ROLES_OFFSET + CURRENT_GRANTS * 16;
pub fn layout_description() -> [u8; LAYOUT_BYTES] {
    let mut bytes = [0; LAYOUT_BYTES];
    bytes[..8].copy_from_slice(b"EVNLAY03");
    bytes[8..10].copy_from_slice(&PROFILE.to_le_bytes());
    bytes[10..12].copy_from_slice(&(CURRENT_GRANTS as u16).to_le_bytes());
    bytes[16..48].copy_from_slice(&ABI);
    for (i, n) in [
        PACKAGE_A_FIRST_PAGE,
        PACKAGE_MAX_PAGES,
        PACKAGE_A_FIRST_PAGE - 1,
        PACKAGE_A_FIRST_PAGE + PACKAGE_MAX_PAGES,
        PACKAGE_B_FIRST_PAGE,
        PACKAGE_MAX_PAGES,
        PACKAGE_B_FIRST_PAGE - 1,
        PACKAGE_B_FIRST_PAGE + PACKAGE_MAX_PAGES,
        16,
        64,
        80,
        14,
        0,
        16,
        32,
        32,
        48,
        6,
        ROOT_STACK_FIRST_PAGE,
        ROOT_STACK_PAGES,
        ROOT_STACK_FIRST_PAGE - 1,
        ROOT_STACK_FIRST_PAGE + ROOT_STACK_PAGES,
        48,
        96,
        14,
    ]
    .into_iter()
    .enumerate()
    {
        super::put(&mut bytes, 48 + i * 8, n);
    }
    for (i, role) in ROLES.into_iter().enumerate() {
        let at = LAYOUT_ROLES_OFFSET + i * 16;
        super::put(&mut bytes, at, role.selector);
        bytes[at + 8] = role.kind;
        bytes[at + 10..at + 12].copy_from_slice(&role.rights.to_le_bytes());
    }
    bytes
}
