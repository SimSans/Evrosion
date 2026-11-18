//! Explicit Internal session-network profile. Syntax/metadata is not authority,
//! admission, entropy qualification or successful network/device retirement.
#![forbid(unsafe_code)]
pub use crate::root_v2::{Error, ManifestInputs};
use crate::{Context, Grant};
pub mod catalogue;
pub mod graph;
pub mod owner_session;
#[cfg(test)]
mod tests;

pub const VERSION: u16 = 4;
pub const PROFILE: u16 = 4;
pub const HEADER: usize = 144;
pub const GRANT_BYTES: usize = 24;
pub const MAX_GRANTS: usize = 32;
pub const CURRENT_GRANTS: usize = 29;
pub const SIZE: usize = HEADER + MAX_GRANTS * GRANT_BYTES;
pub const MANIFEST_HEADER: usize = 208;
pub const MANIFEST_GRANT_BYTES: usize = 32;
pub const MANIFEST_CURRENT_BYTES: usize = MANIFEST_HEADER + CURRENT_GRANTS * MANIFEST_GRANT_BYTES;
pub const EXECUTABLE_SELECTOR: u64 = 1000;
/// Root plus8 live children and exactly1 held replacement; cumulative CPU and
/// frame limits retain their previous values. Ordinary child limits stay1/1.
pub const ROOT_LIMITS: [u64; 4] = [65536, 512, 10, 10];
pub mod dynamic;
pub const HELD_REPLACEMENTS: u64 = 1;
/// V4 Root alone. Ordinary actors retain64 image/68 owner slots; Native3
/// retains96/100/102. These are admission ceilings, not a RAM quota grant.
pub const ROOT_MAX_IMAGE_PAGES: usize = 240;
pub const ROOT_MAX_PRIVATE_PAGES: usize = ROOT_MAX_IMAGE_PAGES + 4;
pub const ROOT_MAX_PRIVATE_FRAMES: u64 = ROOT_MAX_IMAGE_PAGES as u64 + 6;
/// Trusted Registry template0 for ordinary children, template1 for NetService.
/// These fixed limits do not reserve resources or bypass ancestor accounting.
pub const JOB_TEMPLATE_LIMITS: [[u64; 4]; 2] = [[16_384, 32, 1, 1], [16_384, 64, 1, 1]];
pub const ABI_DESCRIPTION:&[u8]=b"Evrosion Internal session-network Root v4; x86_64 readonly912 max32 exact29 sources; originalNative22 +NetDriverImage23 NetServiceImage24 NicPorts25 NicWindow26 NetClientWindow27 NoteWindow28 RtcPorts29; Root-onlyRTC70indexBYTEWRITE71dataBYTEREAD noDERIVE noChild; calendarcentury0x32 coherentdoubleSnapshot max4 UIPpoll8 original512tickcut; RTCelapsed1secondresolution notUTC noPITchange; AppNoteRole7at507 RootNote506 distinctfromAppFile508; catalogue4096 extensionEVNATV04; eightchildren legacyfirst6 +NetDriver6 NetService7; legacyroutes0..14 Events15 NetDriverRPC16 NetClientRPC17; Childbootstrapv1 max8; Rootstack32KiB guards255/264 Childstack16KiB guards255/260; fixedprivateELFstorage noheap; Driverframes32 NetService64 others32; trustedRegistrytemplate0=16384/32/1/1 template1=16384/64/1/1 NetServiceonly graphselected exactimageJoblimits; periodicchildCPU64/256 Root256/256 cumulativeusagepreserved; Rootcumulative65536CPU512frames10process10threads Rootplus8childrenplus1heldreplacement; fourFiletransactionroutes8192 aggregate; ordinaryBlockPresentInputNetRPC1024; eachstoragechildmin(parent,now+1024)capturedbeforepublication; Notecompletionretention9728finiteNOTdeliveryguarantee; QEMUISAne2000PIO0x300..31f pollingnoIRQ; nominalPIT1193182Hz divisor1193 notUTC; runtimequalifiedseed Root-onlyoncefixednamescope; Rootcap0ProcessIdentity38 R10actualmonotonictick viaCall4 childCONTROLlegacyR10preserved; V4Rootmaximage240private244loaderframes246 Native3unchanged96private100loader102 ordinary64private68; metadataalonecreatesnoauthority; dynamicIMAGE_CONTROL52 PD1only twoexternalRootframes privatecontrol192 stage256 RO1/67 pages64 layout1024 dynamicrecord24; dynamicdescriptionSHA256=3b3e1124c58b2e162af8ca16d2795101563d8c30dcb0297ed2e7fdf406807e91; cooperative stop continuation v2: N2 StopBegin6/Step7, S2 ShutdownBegin10/Step11, one8192 aggregate forwarded immutable, eachRPC1024 max and driver child512 preferred, fixed128B verified deviceRAM chunks, Progress notquiescence, Complete only16KiB+freshSTOP; local TCP port allocation v2: Initialize.local_port is inclusive ephemeral floor49152..65535; single socket allocates monotonically before each validated scoped Connect attempt; failed attempts consume; no wrap/reset/reuse within one service incarnation; exhaustion Refused; remote IPv4/port/name scope unchanged; Native report V4 opt-in NRv2: None0 A1 B2 DownloadedB3 DownloadedC4; active3bits@11 staged@14 previous@17 recovery@20 reserved>=21; strict NRv1 unchanged; thirteen32-bit words fifteen authenticated8-byte frames; NRv2 V4-only operation25 update-fetch reports bounded remote acquisition; strict NRv1 operations1..24 unchanged; no activation health or KnownGood; failedNICretirement53 V4capturedRootonly begin0 exactDriverServiceCONTROLpair original8192cut bothCPUExitedreturned noNestedOrQueuedWork; finish1 samepair token originalcut aftermoveOnlyactualScopedRootPIOSTOP whole16KiB128BzeroReadback freshSTOP; immutablefailureclass permitsoldretirementonly neverrecreate noRESET noNewGrant noDMA; NICPIOprofilefence Rootonlywhile53armedcutlive otheractorsdeniedafterfailure Rootdeniedafterjoin allactualIoPortscapchecksretained";
// SHA256(ABI_DESCRIPTION); checked independently by the producer/host tooling.
pub const ABI: [u8; 32] = [
    0xb4, 0xfd, 0x72, 0x51, 0x8e, 0x6b, 0x78, 0x6b, 0xb2, 0x90, 0xf5, 0x75, 0xe8, 0xc7, 0x8c, 0x9c,
    0xfe, 0xb9, 0x83, 0x9e, 0xcd, 0x89, 0x85, 0x75, 0x32, 0x77, 0x9c, 0x02, 0x3d, 0x99, 0xc7, 0xa6,
];
const MAGIC: &[u8; 8] = b"EVROOT04";

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
    AppBImage = 19,
    PackageA = 20,
    PackageB = 21,
    BadShellImage = 22,
    NetDriverImage = 23,
    NetServiceImage = 24,
    NicPorts = 25,
    NicWindow = 26,
    NetClientWindow = 27,
    NoteWindow = 28,
    RtcPorts = 29,
}
impl Role {
    pub const fn selector(self) -> u64 {
        self as u64
    }
    pub const fn from_selector(value: u64) -> Option<Self> {
        Some(match value {
            1 => Self::ShellImage,
            2 => Self::InputImage,
            3 => Self::FileImage,
            4 => Self::BlockImage,
            5 => Self::AppImage,
            6 => Self::DisplayImage,
            7 => Self::CreatorJob,
            8 => Self::Events,
            9 => Self::Surface,
            10 => Self::SystemIo,
            11 => Self::FileIo,
            12 => Self::AppFile,
            13 => Self::Catalogue,
            14 => Self::ShellSurface,
            15 => Self::AtaPorts,
            16 => Self::InputPorts,
            17 => Self::Display,
            18 => Self::OwnerUart,
            19 => Self::AppBImage,
            20 => Self::PackageA,
            21 => Self::PackageB,
            22 => Self::BadShellImage,
            23 => Self::NetDriverImage,
            24 => Self::NetServiceImage,
            25 => Self::NicPorts,
            26 => Self::NicWindow,
            27 => Self::NetClientWindow,
            28 => Self::NoteWindow,
            29 => Self::RtcPorts,
            _ => return None,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoleSpec {
    pub role: Role,
    pub kind: u8,
    pub rights: u16,
}
const fn roles() -> [RoleSpec; CURRENT_GRANTS] {
    let mut result = [RoleSpec {
        role: Role::ShellImage,
        kind: 0,
        rights: 0,
    }; CURRENT_GRANTS];
    let mut i = 0;
    while i < 22 {
        let old = crate::root_v2::native::ROLES[i];
        result[i] = RoleSpec {
            role: match Role::from_selector(old.selector) {
                Some(role) => role,
                None => panic!("closed original roles"),
            },
            kind: old.kind,
            rights: old.rights,
        };
        i += 1;
    }
    result[22] = RoleSpec {
        role: Role::NetDriverImage,
        kind: 1,
        rights: 1,
    };
    result[23] = RoleSpec {
        role: Role::NetServiceImage,
        kind: 1,
        rights: 1,
    };
    result[24] = RoleSpec {
        role: Role::NicPorts,
        kind: 7,
        rights: 227,
    };
    result[25] = RoleSpec {
        role: Role::NicWindow,
        kind: 1,
        rights: 231,
    };
    result[26] = RoleSpec {
        role: Role::NetClientWindow,
        kind: 1,
        rights: 231,
    };
    result[27] = RoleSpec {
        role: Role::NoteWindow,
        kind: 1,
        rights: 231,
    };
    result[28] = RoleSpec {
        role: Role::RtcPorts,
        kind: 7,
        rights: 3,
    };
    result
}
pub const ROLES: [RoleSpec; CURRENT_GRANTS] = roles();
pub const ROOT_STACK_FIRST_PAGE: u64 = 256;
pub const ROOT_STACK_PAGES: u64 = 8;
pub const ROOT_STACK_BYTES: u64 = 32768;
pub const ROOT_CATALOGUE_PAGE: u64 = 507;
pub const ROOT_STARTUP_PAGE: u64 = 509;
pub const ROOT_NOTE_PAGE: u64 = 506;
pub const APP_NOTE_PAGE: u64 = 507;
pub const ROOT_NET_CLIENT_PAGE: u64 = 505;
pub const NIC_WINDOW_PAGE: u64 = 508;
pub const NET_CLIENT_PAGE: u64 = 507;
pub const PACKAGE_A_FIRST_PAGE: u64 = 384;
pub const PACKAGE_B_FIRST_PAGE: u64 = 304;
pub const PACKAGE_MAX_PAGES: u64 = 63;
pub const PACKAGE_MAX_BYTES: u64 = PACKAGE_MAX_PAGES * 4096;
pub const CPU_QUOTA: u64 = 64;
pub const CPU_PERIOD: u64 = 256;
pub const ROOT_CPU_QUOTA: u64 = 256;
pub const RPC_MAX_TICKS: u64 = 1024;
pub const FILE_TRANSACTION_MAX_TICKS: u64 = 8192;
pub const COLD_PREPARE_MAX_TICKS: u64 = 8192;
pub const NOTE_COMPLETION_RETENTION_TICKS: u64 = 9728;
/// Exact reviewed Q35 read-only calendar adapter; index writes select only.
pub const RTC_INDEX_PORT: u16 = 0x70;
pub const RTC_DATA_PORT: u16 = 0x71;
pub const RTC_CENTURY: u8 = 0x32;
pub const RTC_READ_MAX_TICKS: u64 = 512;
pub const RTC_MAX_SNAPSHOTS: usize = 4;
pub const RTC_UIP_POLLS: usize = 8;
pub const PIT_INPUT_HZ: u64 = 1_193_182;
pub const PIT_DIVISOR: u64 = 1193;

pub(crate) fn word(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
pub(crate) fn put(b: &mut [u8], at: usize, value: u64) {
    b[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
pub(crate) fn nonzero(b: &[u8]) -> bool {
    b.iter().any(|b| *b != 0)
}
/// Independently typed v4 syntax. A v3 record cannot be parsed/cast into it.
pub struct Bootstrap<'a> {
    bytes: &'a [u8],
    count: usize,
}
impl<'a> Bootstrap<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() != SIZE {
            return Err(Error::Length);
        }
        if &bytes[..8] != MAGIC
            || bytes[8..10] != VERSION.to_le_bytes()
            || bytes[10..12] != (SIZE as u16).to_le_bytes()
        {
            return Err(Error::Version);
        }
        if bytes[12..14] != PROFILE.to_le_bytes() {
            return Err(Error::Profile);
        }
        if bytes[14..16]
            .iter()
            .chain(&bytes[137..HEADER])
            .any(|b| *b != 0)
        {
            return Err(Error::Reserved);
        }
        if [16, 24, 32].into_iter().any(|at| word(bytes, at) == 0)
            || !nonzero(&bytes[72..104])
            || !nonzero(&bytes[104..136])
        {
            return Err(Error::Identity);
        }
        if [40, 48, 56, 64]
            .into_iter()
            .any(|at| matches!(word(bytes, at), 0 | u64::MAX))
        {
            return Err(Error::Limits);
        }
        let count = usize::from(bytes[136]);
        if !(1..=MAX_GRANTS).contains(&count) {
            return Err(Error::GrantCount);
        }
        let value = Self { bytes, count };
        let mut prior = 0;
        let mut handles = [0; MAX_GRANTS];
        for (i, grant) in value.grants().enumerate() {
            let slot = &bytes[HEADER + i * GRANT_BYTES..HEADER + (i + 1) * GRANT_BYTES];
            if slot[17] != 0 || slot[20..].iter().any(|b| *b != 0) {
                return Err(Error::Reserved);
            }
            if !crate::valid_grant(grant) {
                return Err(Error::Grant);
            }
            if grant.selector <= prior {
                return Err(Error::Order);
            }
            if handles[..i].contains(&grant.handle) {
                return Err(Error::Alias);
            }
            prior = grant.selector;
            handles[i] = grant.handle;
        }
        if bytes[HEADER + count * GRANT_BYTES..]
            .iter()
            .any(|b| *b != 0)
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
            limits: [40, 48, 56, 64].map(|at| word(self.bytes, at)),
            manifest: self.bytes[72..104].try_into().unwrap(),
            authority: self.bytes[104..136].try_into().unwrap(),
        }
    }
    pub fn grants(&self) -> impl ExactSizeIterator<Item = Grant> + '_ {
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
        let value = Bootstrap::parse(bytes)?;
        if value.context().limits != ROOT_LIMITS {
            return Err(Error::Limits);
        }
        if value.count != CURRENT_GRANTS {
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
    pub fn grants(&self) -> impl ExactSizeIterator<Item = Grant> + '_ {
        self.0.grants()
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.0.bytes()
    }
}
pub fn encode(context: Context, grants: &[Grant]) -> Result<[u8; SIZE], Error> {
    if !(1..=MAX_GRANTS).contains(&grants.len()) {
        return Err(Error::GrantCount);
    }
    let mut bytes = [0; SIZE];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_le_bytes());
    bytes[10..12].copy_from_slice(&(SIZE as u16).to_le_bytes());
    bytes[12..14].copy_from_slice(&PROFILE.to_le_bytes());
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
    Bootstrap::parse(&bytes)?;
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
pub fn manifest_profile(inputs: ManifestInputs) -> Result<[u8; MANIFEST_CURRENT_BYTES], Error> {
    if inputs.limits.into_iter().any(|n| matches!(n, 0 | u64::MAX)) {
        return Err(Error::Limits);
    }
    if inputs.restart_attempts > 8 || matches!(inputs.restart_window, 0 | u64::MAX) {
        return Err(Error::Restart);
    }
    if !nonzero(&inputs.root_image) || !nonzero(&inputs.catalogue) || !nonzero(&inputs.authority) {
        return Err(Error::Identity);
    }
    let mut b = [0; MANIFEST_CURRENT_BYTES];
    b[..8].copy_from_slice(b"EVBM0004");
    put(&mut b, 8, EXECUTABLE_SELECTOR);
    b[16..48].copy_from_slice(&inputs.root_image);
    b[48..80].copy_from_slice(&ABI);
    for (i, n) in inputs.limits.into_iter().enumerate() {
        put(&mut b, 80 + i * 8, n);
    }
    b[112] = inputs.restart_attempts;
    put(&mut b, 120, inputs.restart_window);
    b[128..160].copy_from_slice(&inputs.authority);
    b[160] = CURRENT_GRANTS as u8;
    b[168..170].copy_from_slice(&VERSION.to_le_bytes());
    b[170..172].copy_from_slice(&(SIZE as u16).to_le_bytes());
    b[172..174].copy_from_slice(&PROFILE.to_le_bytes());
    b[176..208].copy_from_slice(&inputs.catalogue);
    for (i, r) in ROLES.into_iter().enumerate() {
        let slot = &mut b[MANIFEST_HEADER + i * MANIFEST_GRANT_BYTES
            ..MANIFEST_HEADER + (i + 1) * MANIFEST_GRANT_BYTES];
        put(slot, 0, r.role.selector());
        slot[8] = r.kind;
        slot[10..12].copy_from_slice(&r.rights.to_le_bytes());
    }
    Ok(b)
}
pub const LAYOUT_BYTES: usize = 1024;
pub fn layout_description() -> [u8; LAYOUT_BYTES] {
    let mut b = [0; LAYOUT_BYTES];
    b[..8].copy_from_slice(b"EVNLAY04");
    b[8..10].copy_from_slice(&PROFILE.to_le_bytes());
    b[10..12].copy_from_slice(&(CURRENT_GRANTS as u16).to_le_bytes());
    b[16..48].copy_from_slice(&ABI);
    let words = [
        PACKAGE_A_FIRST_PAGE,
        PACKAGE_MAX_PAGES,
        383,
        447,
        PACKAGE_B_FIRST_PAGE,
        PACKAGE_MAX_PAGES,
        303,
        367,
        ROOT_STACK_FIRST_PAGE,
        ROOT_STACK_PAGES,
        255,
        264,
        ROOT_CATALOGUE_PAGE,
        ROOT_STARTUP_PAGE,
        ROOT_NOTE_PAGE,
        ROOT_NET_CLIENT_PAGE,
        NIC_WINDOW_PAGE,
        NET_CLIENT_PAGE,
        APP_NOTE_PAGE,
        4,
        255,
        260,
        PIT_INPUT_HZ,
        PIT_DIVISOR,
        CPU_QUOTA,
        CPU_PERIOD,
        ROOT_CPU_QUOTA,
        RPC_MAX_TICKS,
        FILE_TRANSACTION_MAX_TICKS,
        COLD_PREPARE_MAX_TICKS,
        NOTE_COMPLETION_RETENTION_TICKS,
        32,
        64,
        graph::ROOT_EVENTS_WIRE as u64,
        graph::WIRE_SLOTS as u64,
        0x300,
        32,
        1,
        0,
        ROOT_LIMITS[2],
        ROOT_LIMITS[3],
        HELD_REPLACEMENTS,
    ];
    for (i, n) in words.into_iter().enumerate() {
        put(&mut b, 48 + i * 8, n);
    }
    for (i, r) in ROLES.into_iter().enumerate() {
        let at = 384 + i * 16;
        put(&mut b, at, r.role.selector());
        b[at + 8] = r.kind;
        b[at + 10..at + 12].copy_from_slice(&r.rights.to_le_bytes());
    }
    b[848..856].copy_from_slice(b"EVJTPL04");
    put(&mut b, 856, JOB_TEMPLATE_LIMITS.len() as u64);
    for (id, limits) in JOB_TEMPLATE_LIMITS.into_iter().enumerate() {
        let at = 864 + id * 40;
        put(&mut b, at, id as u64);
        for (resource, limit) in limits.into_iter().enumerate() {
            put(&mut b, at + 8 + resource * 8, limit);
        }
    }
    b[944..952].copy_from_slice(b"EVRCAP04");
    for (i, limit) in [
        ROOT_MAX_IMAGE_PAGES as u64,
        ROOT_MAX_PRIVATE_PAGES as u64,
        ROOT_MAX_PRIVATE_FRAMES,
    ]
    .into_iter()
    .enumerate()
    {
        put(&mut b, 952 + i * 8, limit);
    }
    b[976..984].copy_from_slice(b"EVRTC004");
    for (i, value) in [
        RTC_INDEX_PORT as u64,
        RTC_DATA_PORT as u64,
        RTC_CENTURY as u64,
        RTC_READ_MAX_TICKS,
        RTC_MAX_SNAPSHOTS as u64,
    ]
    .into_iter()
    .enumerate()
    {
        put(&mut b, 984 + i * 8, value);
    }
    b
}
