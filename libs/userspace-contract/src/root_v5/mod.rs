//! Additive Internal M8 workspace profile. Parsing never supplies actual
//! authority, admission, caller identity, source backing or device retirement.
//! No V1-V4 validated wrapper is accepted as this profile's proof.
use crate::{Context, Grant};
pub mod assistive;
pub mod catalogue;
pub mod child;
pub mod display_control;
pub mod dynamic;
pub mod graph;
pub mod resources;
pub mod surface;
pub use resources::{
    ROOT_LIMITS, ROOT_MAX_IMAGE_PAGES, ROOT_MAX_PRIVATE_FRAMES, ROOT_MAX_PRIVATE_PAGES,
};
#[cfg(test)]
mod tests;

pub const VERSION: u16 = 5;
pub const PROFILE: u16 = 5;
pub const HEADER: usize = 144;
pub const GRANT_BYTES: usize = 24;
pub const MAX_GRANTS: usize = 40;
pub const CURRENT_GRANTS: usize = 37;
pub const SIZE: usize = HEADER + MAX_GRANTS * GRANT_BYTES;
pub const MANIFEST_HEADER: usize = 208;
pub const MANIFEST_GRANT_BYTES: usize = 32;
pub const MANIFEST_CURRENT_BYTES: usize = MANIFEST_HEADER + CURRENT_GRANTS * MANIFEST_GRANT_BYTES;
pub const EXECUTABLE_SELECTOR: u64 = 1000;
pub const AUTHORITY_DOMAIN: &[u8] = b"evrosion.bootstrap.authority.root.v5\0";
pub const ABI_DESCRIPTION: &[u8] = b"Evrosion Internal workspace Root v5; independent EVROOT05/EVBM0005 profile5 readonly1104 max40 exact37 sources; explicit11children/23channels14RPC5async4selected RootEventswire23; sharedDisplayPresent actualServingOrigin57 INFO58 descriptor0000000100080001 noPacketCallerAuthority; RootWorkspaceControlwire22 RootSENDonly WorkspaceRecv16 separateFilesNamespace15/WorkspaceRecv10; fourAppinstances distinctsurface/control/inbox/twoPageFileWindow actualcaller/lease exactobject; metadata IDs no frame/quota/delegation authority; M8selected96objects512lineage64spaces Root96 ordinary16 legacy64/256/40/Root64 unchanged; serviceV1 336/8 unchanged WorkspaceDisplay serviceV5 528/16; setupJobCONTROLclosedonlyafterStart+negotiated55 descriptor0000000100090003 ProcessCONTROLretained stoppedBeforeRegistryRetirement;11children+Root+bootJob 13Jobs12Processes12Threads held14/13/13; proposedlowerbound82objects49spaces51held52channeloverlap306lineage340held actualcensuspending; x86_64 privatewindow512pages EditorImage384/private388 stack480..487 guards479/488 Surface384..446 loan506..507 startup509; Display5x63pages64,128,192,256,320+protected51pages384..434 guard435; RootProtected51pages448..498 guards447/499 Rootcatalog500..502 Workspace503..504 Net505 RootSystemIo508 NIC508NetDriverOnly startup509; DisplayImage80/private84/loader88including2aperturetables stack480..487;640x480logical protected640x80 referencecontent320x180 max320x200; actualRootJobCreator subtreeRootLimits4000000/4096/13/13 Boot8000000/8192/14/14 finiteCPU1000000 perM8child measuredaggregate58000ticks57887charged noCPUresets legacyCPUunchanged privateRootImage240/private244/base246 unchanged; M8templates32/64/128/512 onlyEditorImage384 UIWorkspace96 Display80 legacyCore64; cataloguePackage128 unchanged plus4x16 placementTable kind16/bank8/version1/offset32/exactlength64 CurrentRole19pages368..44679 CandidateRole20pages304..36663 strict16aligned/nonoverlap/perBankBounds Current323584 Candidate258048 individualZion63pages dynamicOwner64 selectedSharedExtent80 legacyExtent64 unchanged; independentSystem/userdata/legacyFile preserved; namespace/FileoneWorkspaceService Block8 first6legacy plusWorkspaceMemory506+WorkspaceBlockRX; offline signedEditorupdate KnownGood and independentRecovery retainactualcohortdata; RTC70indexwrite71dataread NE2000PIO300..31f noDMA claimfrommetadata; proposedresources beforeactualoptimizedlinked/VMqualification";
// SHA256(ABI_DESCRIPTION), independently checked by the source verification tool.
pub const ABI: [u8; 32] = [
    0xca, 0x5e, 0x7f, 0xd0, 0xbe, 0x76, 0x2c, 0xb0, 0x36, 0x84, 0xe0, 0xfb, 0x18, 0x1d, 0xd4, 0x1f,
    0x01, 0xab, 0x45, 0xf9, 0x6c, 0x48, 0x8c, 0x43, 0x7f, 0xb9, 0xd2, 0x4d, 0x3f, 0xd0, 0xc8, 0x60,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Version,
    Profile,
    Reserved,
    Identity,
    Limits,
    Count,
    Grant,
    Order,
    Alias,
    Roles,
    Restart,
    Abi,
    Image,
    Package,
    Layout,
    Policy,
    Budget,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Role {
    ShellImage = 1,
    InputImage = 2,
    WorkspaceImage = 3,
    BlockImage = 4,
    EditorImage = 5,
    DisplayImage = 6,
    CreatorJob = 7,
    RootEvents = 8,
    EditorOneSurface = 9,
    SystemIo = 10,
    LegacyFileIo = 11,
    EditorOneFrame = 12,
    Catalogue = 13,
    ShellSurface = 14,
    AtaPorts = 15,
    InputPorts = 16,
    Display = 17,
    OwnerUart = 18,
    PackageCurrent = 19,
    PackageCandidate = 20,
    NetDriverImage = 21,
    NetServiceImage = 22,
    NicPorts = 23,
    NicWindow = 24,
    NetClientWindow = 25,
    RtcPorts = 26,
    FilesImage = 27,
    InspectorImage = 28,
    FilesSurface = 29,
    EditorTwoSurface = 30,
    InspectorSurface = 31,
    ProtectedSurface = 32,
    FilesFrame = 33,
    EditorTwoFrame = 34,
    InspectorFrame = 35,
    WorkspaceBlockWindow = 36,
    RootWorkspaceFrame = 37,
}
impl Role {
    pub const fn selector(self) -> u64 {
        self as u64
    }
    pub const fn from_selector(value: u64) -> Option<Self> {
        if value == 0 || value > CURRENT_GRANTS as u64 {
            None
        } else {
            Some(ROLES[value as usize - 1].role)
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoleSpec {
    pub role: Role,
    pub kind: u8,
    pub rights: u16,
}
const fn r(role: Role, kind: u8, rights: u16) -> RoleSpec {
    RoleSpec { role, kind, rights }
}
pub const ROLES: [RoleSpec; CURRENT_GRANTS] = [
    r(Role::ShellImage, 1, 1),
    r(Role::InputImage, 1, 1),
    r(Role::WorkspaceImage, 1, 1),
    r(Role::BlockImage, 1, 1),
    r(Role::EditorImage, 1, 1),
    r(Role::DisplayImage, 1, 1),
    r(Role::CreatorJob, 5, 481),
    r(Role::RootEvents, 2, 504),
    r(Role::EditorOneSurface, 1, 231),
    r(Role::SystemIo, 1, 231),
    r(Role::LegacyFileIo, 1, 231),
    r(Role::EditorOneFrame, 1, 231),
    r(Role::Catalogue, 1, 5),
    r(Role::ShellSurface, 1, 231),
    r(Role::AtaPorts, 7, 227),
    r(Role::InputPorts, 7, 227),
    r(Role::Display, 8, 231),
    r(Role::OwnerUart, 7, 3),
    r(Role::PackageCurrent, 1, 5),
    r(Role::PackageCandidate, 1, 5),
    r(Role::NetDriverImage, 1, 1),
    r(Role::NetServiceImage, 1, 1),
    r(Role::NicPorts, 7, 227),
    r(Role::NicWindow, 1, 231),
    r(Role::NetClientWindow, 1, 231),
    r(Role::RtcPorts, 7, 3),
    r(Role::FilesImage, 1, 1),
    r(Role::InspectorImage, 1, 1),
    r(Role::FilesSurface, 1, 231),
    r(Role::EditorTwoSurface, 1, 231),
    r(Role::InspectorSurface, 1, 231),
    r(Role::ProtectedSurface, 1, 231),
    r(Role::FilesFrame, 1, 231),
    r(Role::EditorTwoFrame, 1, 231),
    r(Role::InspectorFrame, 1, 231),
    r(Role::WorkspaceBlockWindow, 1, 231),
    r(Role::RootWorkspaceFrame, 1, 231),
];
pub(crate) fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
pub(crate) fn put(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
pub(crate) fn nonzero(bytes: &[u8]) -> bool {
    bytes.iter().any(|value| *value != 0)
}
pub(crate) fn limits_valid(limits: [u64; 4]) -> bool {
    limits.into_iter().all(|v| !matches!(v, 0 | u64::MAX))
}

pub(crate) struct Record<'a> {
    pub bytes: &'a [u8],
    pub count: usize,
}
impl<'a> Record<'a> {
    pub(crate) fn parse(
        bytes: &'a [u8],
        magic: &[u8; 8],
        size: usize,
        max: usize,
    ) -> Result<Self, Error> {
        if bytes.len() != size {
            return Err(Error::Length);
        }
        if &bytes[..8] != magic
            || bytes[8..10] != VERSION.to_le_bytes()
            || bytes[10..12] != (size as u16).to_le_bytes()
        {
            return Err(Error::Version);
        }
        if bytes[12..14] != PROFILE.to_le_bytes() {
            return Err(Error::Profile);
        }
        if bytes[14..16]
            .iter()
            .chain(&bytes[137..HEADER])
            .any(|v| *v != 0)
        {
            return Err(Error::Reserved);
        }
        if [16, 24, 32]
            .into_iter()
            .any(|at| matches!(word(bytes, at), 0 | u64::MAX))
            || !nonzero(&bytes[72..104])
            || !nonzero(&bytes[104..136])
        {
            return Err(Error::Identity);
        }
        if !limits_valid([40, 48, 56, 64].map(|at| word(bytes, at))) {
            return Err(Error::Limits);
        }
        let count = usize::from(bytes[136]);
        if !(1..=max).contains(&count) {
            return Err(Error::Count);
        }
        let record = Self { bytes, count };
        let mut prior = 0;
        for (index, grant) in record.grants().enumerate() {
            let slot = &bytes[HEADER + index * GRANT_BYTES..HEADER + (index + 1) * GRANT_BYTES];
            if slot[17] != 0 || slot[20..].iter().any(|v| *v != 0) {
                return Err(Error::Reserved);
            }
            if !crate::valid_grant(grant) {
                return Err(Error::Grant);
            }
            if grant.selector <= prior {
                return Err(Error::Order);
            }
            if record
                .grants()
                .take(index)
                .any(|old| old.handle == grant.handle)
            {
                return Err(Error::Alias);
            }
            prior = grant.selector;
        }
        if bytes[HEADER + count * GRANT_BYTES..]
            .iter()
            .any(|v| *v != 0)
        {
            return Err(Error::Reserved);
        }
        Ok(record)
    }
    pub(crate) fn context(&self) -> Context {
        Context {
            epoch: word(self.bytes, 16),
            incarnation: word(self.bytes, 24),
            process: word(self.bytes, 32),
            limits: [40, 48, 56, 64].map(|at| word(self.bytes, at)),
            manifest: self.bytes[72..104].try_into().unwrap(),
            authority: self.bytes[104..136].try_into().unwrap(),
        }
    }
    pub(crate) fn grants(&self) -> impl ExactSizeIterator<Item = Grant> + '_ {
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
}
pub(crate) fn encode_record<const N: usize>(
    magic: &[u8; 8],
    max: usize,
    context: Context,
    grants: &[Grant],
) -> Result<[u8; N], Error> {
    if !(1..=max).contains(&grants.len()) {
        return Err(Error::Count);
    }
    let mut b = [0; N];
    b[..8].copy_from_slice(magic);
    b[8..10].copy_from_slice(&VERSION.to_le_bytes());
    b[10..12].copy_from_slice(&(N as u16).to_le_bytes());
    b[12..14].copy_from_slice(&PROFILE.to_le_bytes());
    for (i, v) in [context.epoch, context.incarnation, context.process]
        .into_iter()
        .enumerate()
    {
        put(&mut b, 16 + i * 8, v);
    }
    for (i, v) in context.limits.into_iter().enumerate() {
        put(&mut b, 40 + i * 8, v);
    }
    b[72..104].copy_from_slice(&context.manifest);
    b[104..136].copy_from_slice(&context.authority);
    b[136] = grants.len() as u8;
    for (i, g) in grants.iter().enumerate() {
        let slot = &mut b[HEADER + i * GRANT_BYTES..HEADER + (i + 1) * GRANT_BYTES];
        put(slot, 0, g.selector);
        put(slot, 8, g.handle);
        slot[16] = g.kind;
        slot[18..20].copy_from_slice(&g.rights.to_le_bytes());
    }
    Record::parse(&b, magic, N, max)?;
    Ok(b)
}
pub struct Bootstrap<'a>(Record<'a>);
impl<'a> Bootstrap<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        Record::parse(bytes, b"EVROOT05", SIZE, MAX_GRANTS).map(Self)
    }
    pub fn context(&self) -> Context {
        self.0.context()
    }
    pub fn grants(&self) -> impl ExactSizeIterator<Item = Grant> + '_ {
        self.0.grants()
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.0.bytes
    }
}
pub struct FullGraph<'a>(Bootstrap<'a>);
impl<'a> FullGraph<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let value = Bootstrap::parse(bytes)?;
        if value.context().limits != resources::ROOT_LIMITS {
            return Err(Error::Limits);
        }
        if value.0.count != CURRENT_GRANTS {
            return Err(Error::Roles);
        }
        for (actual, expected) in value.grants().zip(ROLES) {
            if (actual.selector, actual.kind, actual.rights)
                != (expected.role.selector(), expected.kind, expected.rights)
            {
                return Err(Error::Roles);
            }
        }
        Ok(Self(value))
    }
    pub fn context(&self) -> Context {
        self.0.context()
    }
    pub fn grants(&self) -> impl ExactSizeIterator<Item = Grant> + '_ {
        self.0.grants()
    }
    pub fn handle(&self, role: Role) -> u64 {
        self.grants()
            .find(|g| g.selector == role.selector())
            .unwrap()
            .handle
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.0.bytes()
    }
}
pub fn encode(context: Context, grants: &[Grant]) -> Result<[u8; SIZE], Error> {
    encode_record(b"EVROOT05", MAX_GRANTS, context, grants)
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
    let b = encode(context, &grants)?;
    FullGraph::parse(&b)?;
    Ok(b)
}
pub struct ManifestInputs {
    pub root_image: [u8; 32],
    pub catalogue: [u8; 32],
    pub authority: [u8; 32],
    pub restart_attempts: u8,
    pub restart_window: u64,
}
pub fn manifest_profile(input: ManifestInputs) -> Result<[u8; MANIFEST_CURRENT_BYTES], Error> {
    if !nonzero(&input.root_image) || !nonzero(&input.catalogue) || !nonzero(&input.authority) {
        return Err(Error::Identity);
    }
    if input.restart_attempts > 8 || matches!(input.restart_window, 0 | u64::MAX) {
        return Err(Error::Restart);
    }
    let mut b = [0; MANIFEST_CURRENT_BYTES];
    b[..8].copy_from_slice(b"EVBM0005");
    put(&mut b, 8, EXECUTABLE_SELECTOR);
    b[16..48].copy_from_slice(&input.root_image);
    b[48..80].copy_from_slice(&ABI);
    for (i, v) in resources::ROOT_LIMITS.into_iter().enumerate() {
        put(&mut b, 80 + i * 8, v);
    }
    b[112] = input.restart_attempts;
    put(&mut b, 120, input.restart_window);
    b[128..160].copy_from_slice(&input.authority);
    b[160] = CURRENT_GRANTS as u8;
    b[168..170].copy_from_slice(&VERSION.to_le_bytes());
    b[170..172].copy_from_slice(&(SIZE as u16).to_le_bytes());
    b[172..174].copy_from_slice(&PROFILE.to_le_bytes());
    b[176..208].copy_from_slice(&input.catalogue);
    for (i, r) in ROLES.into_iter().enumerate() {
        let at = MANIFEST_HEADER + i * MANIFEST_GRANT_BYTES;
        put(&mut b, at, r.role.selector());
        b[at + 8] = r.kind;
        b[at + 10..at + 12].copy_from_slice(&r.rights.to_le_bytes());
    }
    Ok(b)
}
