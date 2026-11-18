//! Independent M8 catalogue: no embedded V4 catalogue/base is treated as V5
//! admission. These hashes name actual artifacts for the trusted factory to join.
use super::{
    ABI, Error, Role, child,
    graph::{self, Child, ImageSlot},
    nonzero, put, resources, word,
};
pub const SIZE: usize = 12288;
pub const HEADER: usize = 256;
pub const IMAGE_BYTES: usize = 208;
pub const INSTANCE_BYTES: usize = 64;
pub const PACKAGE_BYTES: usize = 128;
pub const IMAGE_AT: usize = 256;
pub const INSTANCE_AT: usize = IMAGE_AT + graph::IMAGES.len() * IMAGE_BYTES;
pub const PACKAGE_AT: usize = INSTANCE_AT + graph::CHILDREN.len() * INSTANCE_BYTES;
pub const POLICY_AT: usize = PACKAGE_AT + 4 * PACKAGE_BYTES;
pub const DEVICE_AT: usize = POLICY_AT + 320;
pub const TIMER_AT: usize = DEVICE_AT + 128;
pub const BUDGET_AT: usize = TIMER_AT + 64;
pub const GRAPH_AT: usize = BUDGET_AT + 128;
pub const LAYOUT_AT: usize = GRAPH_AT + graph::DESCRIPTION_BYTES;
pub const CENSUS_AT: usize = LAYOUT_AT + resources::LAYOUT_BYTES;
pub const DYNAMIC_AT: usize = CENSUS_AT + resources::CENSUS_BYTES;
/// Existing image/instance/package/policy sections retain exact offsets. The
/// separate placement table binds physical package bank/offset/length metadata.
pub const PLACEMENT_AT: usize = DYNAMIC_AT + 128;
pub const PLACEMENT_BYTES: usize = 16;
pub const PLACEMENT_END: usize = PLACEMENT_AT + 4 * PLACEMENT_BYTES;
mod ingress;
pub use ingress::{
    ExternalIngress, INGRESS_AT, INGRESS_BYTES, INGRESS_END, IngressProvenance, ingress_offset,
};
pub const PACKAGE_ALIGNMENT: u32 = 16;
pub const MEASUREMENT_OFFSET: usize = 208;
pub const MEASUREMENT_DOMAIN: &[u8] = b"evrosion.workspace.fullgraph.v5\0";
pub const REFERENCE_MAC: [u8; 6] = [2, 0x45, 0x56, 0x52, 0, 1];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BootMode {
    Standalone = 0,
    SystemManaged = 1,
    Recovery = 2,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Image {
    pub image: [u8; 32],
    pub descriptor: [u8; 32],
    pub abi: [u8; 32],
    pub limits: [u64; 4],
    pub role_shape: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum PackageKind {
    Files = 0,
    Editor = 1,
    Inspector = 2,
    EditorCandidate = 3,
}
pub const PACKAGES: [PackageKind; 4] = [
    PackageKind::Files,
    PackageKind::Editor,
    PackageKind::Inspector,
    PackageKind::EditorCandidate,
];
impl PackageKind {
    pub const fn index(self) -> usize {
        self as usize
    }
    pub const fn image(self) -> ImageSlot {
        match self {
            Self::Files => ImageSlot::Files,
            Self::Editor | Self::EditorCandidate => ImageSlot::Editor,
            Self::Inspector => ImageSlot::Inspector,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PackageBank {
    Current = 0,
    Candidate = 1,
}
impl PackageBank {
    pub const fn role(self) -> Role {
        match self {
            Self::Current => Role::PackageCurrent,
            Self::Candidate => Role::PackageCandidate,
        }
    }
    pub const fn pages(self) -> u64 {
        match self {
            Self::Current => resources::PACKAGE_CURRENT_PAGES,
            Self::Candidate => resources::PACKAGE_CANDIDATE_PAGES,
        }
    }
    pub const fn capacity_bytes(self) -> u64 {
        self.pages() * 4096
    }
    pub const fn first_page(self) -> u64 {
        match self {
            Self::Current => resources::PACKAGE_A_FIRST_PAGE,
            Self::Candidate => resources::PACKAGE_B_FIRST_PAGE,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Package {
    pub app_id: [u8; 16],
    pub digest: [u8; 32],
    pub build: [u8; 32],
    pub image: [u8; 32],
    pub bytes: u64,
    pub bank: PackageBank,
    pub offset: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceWitness {
    pub mac: [u8; 6],
    pub model_source_sha256: [u8; 32],
    pub emulator_binary_sha256: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkPolicy<'a> {
    pub allowed_ipv4: [u8; 4],
    pub remote_port: u16,
    pub local_port: u16,
    pub dns_name: &'a str,
}
pub struct Description<'a> {
    pub root_image: [u8; 32],
    pub kernel_input: [u8; 32],
    pub graph_measurement: [u8; 32],
    pub layout_measurement: [u8; 32],
    pub measurement: [u8; 32],
    pub boot_mode: BootMode,
    pub restart_attempts: u8,
    pub restart_window: u64,
    pub images: [Image; 10],
    pub instance_bindings: [[u8; 32]; 11],
    pub packages: [Package; 4],
    pub device: DeviceWitness,
    pub network: NetworkPolicy<'a>,
}
fn image_record(slot: ImageSlot, image: Image) -> Result<[u8; IMAGE_BYTES], Error> {
    let actor = slot.representative();
    if !nonzero(&image.image) || !nonzero(&image.descriptor) || !nonzero(&image.role_shape) {
        return Err(Error::Image);
    }
    if image.abi != child::abi(actor) || image.limits != actor.limits() {
        return Err(Error::Image);
    }
    let mut b = [0; IMAGE_BYTES];
    b[..2].copy_from_slice(&(slot.index() as u16).to_le_bytes());
    b[2..4].copy_from_slice(&(resources::image_layout(slot) as u16).to_le_bytes());
    b[4] = graph::GRANT_COUNTS[actor.index()] as u8;
    b[6..8].copy_from_slice(&child::startup_version(actor).to_le_bytes());
    b[8..40].copy_from_slice(&image.image);
    b[40..72].copy_from_slice(&image.descriptor);
    b[72..104].copy_from_slice(&image.abi);
    for (i, v) in image.limits.into_iter().enumerate() {
        put(&mut b, 104 + i * 8, v);
    }
    b[136..168].copy_from_slice(&image.role_shape);
    put(&mut b, 168, resources::max_image_pages(slot));
    let (first, pages) = resources::stack(slot);
    put(&mut b, 176, first);
    put(&mut b, 184, pages);
    put(&mut b, 192, resources::max_private_pages(slot));
    put(&mut b, 200, resources::max_loader_frames(slot));
    Ok(b)
}
fn image(bytes: &[u8]) -> Image {
    Image {
        image: bytes[8..40].try_into().unwrap(),
        descriptor: bytes[40..72].try_into().unwrap(),
        abi: bytes[72..104].try_into().unwrap(),
        limits: [104, 112, 120, 128].map(|at| word(bytes, at)),
        role_shape: bytes[136..168].try_into().unwrap(),
    }
}
fn instance_record(actor: Child, binding: [u8; 32]) -> Result<[u8; INSTANCE_BYTES], Error> {
    if !nonzero(&binding) {
        return Err(Error::Identity);
    }
    let mut b = [0; INSTANCE_BYTES];
    b[..2].copy_from_slice(&(actor.index() as u16).to_le_bytes());
    b[2..4].copy_from_slice(&(actor.image_slot().index() as u16).to_le_bytes());
    b[4] = graph::GRANT_COUNTS[actor.index()] as u8;
    b[6..8].copy_from_slice(&actor.instance().to_le_bytes());
    put(&mut b, 8, actor.surface().map_or(0, Role::selector));
    put(&mut b, 16, actor.frame().map_or(0, Role::selector));
    for (at, channel) in [(24, actor.control()), (26, actor.inbox())] {
        b[at..at + 2].copy_from_slice(
            &(channel.map_or(u16::MAX, |value| value.wire_index() as u16)).to_le_bytes(),
        );
    }
    b[32..64].copy_from_slice(&binding);
    Ok(b)
}
fn package_record(kind: PackageKind, value: Package) -> Result<[u8; PACKAGE_BYTES], Error> {
    if !nonzero(&value.app_id)
        || !nonzero(&value.digest)
        || !nonzero(&value.build)
        || !nonzero(&value.image)
        || value.bytes == 0
        || value.bytes > resources::PACKAGE_MAX_BYTES
    {
        return Err(Error::Package);
    }
    let mut b = [0; PACKAGE_BYTES];
    b[..2].copy_from_slice(&(kind.index() as u16).to_le_bytes());
    b[2..4].copy_from_slice(&(kind.image().index() as u16).to_le_bytes());
    b[4] = u8::from(kind == PackageKind::EditorCandidate);
    b[8..24].copy_from_slice(&value.app_id);
    b[24..56].copy_from_slice(&value.digest);
    b[56..88].copy_from_slice(&value.build);
    b[88..120].copy_from_slice(&value.image);
    put(&mut b, 120, value.bytes);
    Ok(b)
}
fn package(bytes: &[u8], placement: &[u8]) -> Package {
    Package {
        app_id: bytes[8..24].try_into().unwrap(),
        digest: bytes[24..56].try_into().unwrap(),
        build: bytes[56..88].try_into().unwrap(),
        image: bytes[88..120].try_into().unwrap(),
        bytes: word(bytes, 120),
        // Unrecognized nonzero tags are normalized only inside the private
        // decoder, then fail exact canonical placement reencoding below.
        bank: if placement[2] == 0 {
            PackageBank::Current
        } else {
            PackageBank::Candidate
        },
        offset: u32::from_le_bytes(placement[4..8].try_into().unwrap()),
    }
}
fn placement_record(kind: PackageKind, value: Package) -> Result<[u8; PLACEMENT_BYTES], Error> {
    let expected = if kind == PackageKind::EditorCandidate {
        PackageBank::Candidate
    } else {
        PackageBank::Current
    };
    if value.bank != expected
        || !value.offset.is_multiple_of(PACKAGE_ALIGNMENT)
        || value.bytes == 0
        || u64::from(value.offset)
            .checked_add(value.bytes)
            .is_none_or(|end| end > value.bank.capacity_bytes())
    {
        return Err(Error::Package);
    }
    let mut bytes = [0; PLACEMENT_BYTES];
    bytes[..2].copy_from_slice(&(kind.index() as u16).to_le_bytes());
    bytes[2] = value.bank as u8;
    bytes[3] = 1;
    bytes[4..8].copy_from_slice(&value.offset.to_le_bytes());
    put(&mut bytes, 8, value.bytes);
    Ok(bytes)
}
fn policy_record(value: NetworkPolicy<'_>) -> Result<[u8; 320], Error> {
    let name = value.dns_name.as_bytes();
    if matches!(value.allowed_ipv4[0], 0 | 127 | 224..=255)
        || value.remote_port == 0
        || value.local_port < 49152
        || name.is_empty()
        || name.len() > 253
        || !name.split(|byte| *byte == b'.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && part[0].is_ascii_alphanumeric()
                && part[part.len() - 1].is_ascii_alphanumeric()
                && part
                    .iter()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        })
    {
        return Err(Error::Policy);
    }
    let mut b = [0; 320];
    b[..8].copy_from_slice(b"EVNPOL05");
    b[8..10].copy_from_slice(&5u16.to_le_bytes());
    b[10..12].copy_from_slice(&320u16.to_le_bytes());
    b[12] = name.len() as u8;
    b[16..20].copy_from_slice(&value.allowed_ipv4);
    b[20..22].copy_from_slice(&value.remote_port.to_le_bytes());
    b[22..24].copy_from_slice(&value.local_port.to_le_bytes());
    b[24..24 + name.len()].copy_from_slice(name);
    Ok(b)
}
fn device_record(value: DeviceWitness) -> Result<[u8; 128], Error> {
    if value.mac != REFERENCE_MAC
        || !nonzero(&value.model_source_sha256)
        || !nonzero(&value.emulator_binary_sha256)
    {
        return Err(Error::Policy);
    }
    let mut b = [0; 128];
    b[..8].copy_from_slice(b"EVNIC005");
    b[8..10].copy_from_slice(&5u16.to_le_bytes());
    b[10..12].copy_from_slice(&128u16.to_le_bytes());
    b[12..14].copy_from_slice(&1u16.to_le_bytes());
    b[16..18].copy_from_slice(&0x300u16.to_le_bytes());
    b[18..20].copy_from_slice(&32u16.to_le_bytes());
    b[24..30].copy_from_slice(&value.mac);
    b[32..64].copy_from_slice(&value.model_source_sha256);
    b[64..96].copy_from_slice(&value.emulator_binary_sha256);
    for (at, n) in [(96, 1514u16), (98, 60), (100, 4), (102, 4)] {
        b[at..at + 2].copy_from_slice(&n.to_le_bytes());
    }
    put(&mut b, 104, 0x4000);
    put(&mut b, 112, 0x8000);
    Ok(b)
}
fn timer_record() -> [u8; 64] {
    let mut b = [0; 64];
    b[..8].copy_from_slice(b"EVPIT005");
    for (i, v) in [1193182, 1193, 1000, 0x70, 0x71, 0x32, 512]
        .into_iter()
        .enumerate()
    {
        put(&mut b, 8 + i * 8, v);
    }
    b
}
fn budget_record() -> [u8; 128] {
    let mut b = [0; 128];
    b[..8].copy_from_slice(b"EVBUD005");
    for (i, v) in [
        resources::CHILD_QUOTA_TICKS,
        resources::PERIOD_TICKS,
        resources::ROOT_QUOTA_TICKS,
        resources::PERIOD_TICKS,
        resources::RPC_TICKS,
        resources::FILE_TRANSACTION_TICKS,
        13,
        14,
        23,
        14,
        5,
        4,
        640,
        480,
        1,
    ]
    .into_iter()
    .enumerate()
    {
        put(&mut b, 8 + i * 8, v);
    }
    b
}
fn dynamic_record() -> [u8; 128] {
    let mut b = [0; 128];
    b[..8].copy_from_slice(b"EVMDYN05");
    // Strict selected M8 admission is required; this does NOT widen legacy PD1.
    for (i, v) in [
        52,
        resources::LARGE_MAX_IMAGE_PAGES,
        resources::LARGE_MAX_PRIVATE_PAGES,
        resources::LARGE_MAX_PRIVATE_FRAMES,
        resources::PACKAGE_MAX_BYTES,
        resources::M8_STACK_FIRST_PAGE,
        resources::M8_STACK_PAGES,
        1, // Root-only issuer policy; not an IMAGE_CONTROL protocol version.
        2, // Two retained package owner buffers.
        1, // At most one held candidate process in the proposed envelope.
    ]
    .into_iter()
    .enumerate()
    {
        put(&mut b, 8 + i * 8, v);
    }
    b
}
pub struct Catalogue<'a> {
    bytes: &'a [u8],
}
impl<'a> Catalogue<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() != SIZE {
            return Err(Error::Length);
        }
        if &bytes[..8] != b"EVCOH005"
            || bytes[8..10] != 5u16.to_le_bytes()
            || bytes[10..12] != (SIZE as u16).to_le_bytes()
            || bytes[12..14] != 5u16.to_le_bytes()
            || bytes[14..16] != (HEADER as u16).to_le_bytes()
        {
            return Err(Error::Version);
        }
        if bytes[16..48] != ABI || bytes[48..80] != child::ABI {
            return Err(Error::Abi);
        }
        if [80, 112, 144, 176, 208]
            .into_iter()
            .any(|at| !nonzero(&bytes[at..at + 32]))
        {
            return Err(Error::Identity);
        }
        if bytes[240] > 2
            || bytes[241..244] != [4, 10, 11]
            || bytes[244] > 8
            || matches!(word(bytes, 248), 0 | u64::MAX)
        {
            return Err(Error::Policy);
        }
        if bytes[245..248]
            .iter()
            .chain(&bytes[INGRESS_END..])
            .any(|v| *v != 0)
        {
            return Err(Error::Reserved);
        }
        let value = Self { bytes };
        for slot in graph::IMAGES {
            let at = IMAGE_AT + slot.index() * IMAGE_BYTES;
            if bytes[at..at + IMAGE_BYTES] != image_record(slot, value.image(slot))? {
                return Err(Error::Image);
            }
        }
        for actor in graph::CHILDREN {
            let at = INSTANCE_AT + actor.index() * INSTANCE_BYTES;
            let binding = bytes[at + 32..at + 64].try_into().unwrap();
            if bytes[at..at + INSTANCE_BYTES] != instance_record(actor, binding)? {
                return Err(Error::Roles);
            }
        }
        let first = INSTANCE_AT + Child::EditorOne.index() * INSTANCE_BYTES + 32;
        let second = INSTANCE_AT + Child::EditorTwo.index() * INSTANCE_BYTES + 32;
        if bytes[first..first + 32] == bytes[second..second + 32] {
            return Err(Error::Alias);
        }
        for kind in PACKAGES {
            let at = PACKAGE_AT + kind.index() * PACKAGE_BYTES;
            if bytes[at..at + PACKAGE_BYTES] != package_record(kind, value.package(kind))? {
                return Err(Error::Package);
            }
            let location = PLACEMENT_AT + kind.index() * PLACEMENT_BYTES;
            let package = value.package(kind);
            if bytes[location..location + PLACEMENT_BYTES] != placement_record(kind, package)? {
                return Err(Error::Package);
            }
            for previous in PACKAGES.into_iter().take(kind.index()) {
                let old = value.package(previous);
                if old.bank == package.bank
                    && u64::from(old.offset) < u64::from(package.offset) + package.bytes
                    && u64::from(package.offset) < u64::from(old.offset) + old.bytes
                {
                    return Err(Error::Package);
                }
            }
            if kind != PackageKind::EditorCandidate
                && value.package(kind).image != value.image(kind.image()).image
            {
                return Err(Error::Package);
            }
        }
        let files = value.package(PackageKind::Files);
        let editor = value.package(PackageKind::Editor);
        let inspector = value.package(PackageKind::Inspector);
        let candidate = value.package(PackageKind::EditorCandidate);
        if files.app_id == editor.app_id
            || files.app_id == inspector.app_id
            || editor.app_id == inspector.app_id
            || candidate.app_id != editor.app_id
            || candidate.digest == editor.digest
            || candidate.image == editor.image
        {
            return Err(Error::Package);
        }
        if let Some(ingress) = value.external_ingress()
            && bytes[INGRESS_AT..INGRESS_END]
                != ingress::record(ingress, PACKAGES.map(|kind| value.package(kind)))?
        {
            return Err(Error::Package);
        }
        if bytes[POLICY_AT..POLICY_AT + 320] != policy_record(value.network_policy()?)?
            || bytes[DEVICE_AT..DEVICE_AT + 128] != device_record(value.device())?
        {
            return Err(Error::Policy);
        }
        if bytes[TIMER_AT..TIMER_AT + 64] != timer_record()
            || bytes[BUDGET_AT..BUDGET_AT + 128] != budget_record()
        {
            return Err(Error::Budget);
        }
        if bytes[GRAPH_AT..LAYOUT_AT] != graph::description()
            || bytes[LAYOUT_AT..CENSUS_AT] != resources::layout_description()
            || bytes[CENSUS_AT..DYNAMIC_AT] != resources::proposed_census()
            || bytes[DYNAMIC_AT..DYNAMIC_AT + 128] != dynamic_record()
        {
            return Err(Error::Layout);
        }
        Ok(value)
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub fn images(&self) -> impl ExactSizeIterator<Item = (ImageSlot, Image)> + '_ {
        graph::IMAGES
            .into_iter()
            .map(|slot| (slot, self.image(slot)))
    }
    pub fn packages(&self) -> impl ExactSizeIterator<Item = (PackageKind, Package)> + '_ {
        PACKAGES.into_iter().map(|kind| (kind, self.package(kind)))
    }
    pub fn external_ingress(&self) -> Option<ExternalIngress> {
        let record = &self.bytes[INGRESS_AT..INGRESS_END];
        record
            .iter()
            .any(|byte| *byte != 0)
            .then(|| ingress::read(record))
    }
    pub fn kernel_input(&self) -> [u8; 32] {
        self.bytes[112..144].try_into().unwrap()
    }
    pub fn measurement(&self) -> [u8; 32] {
        self.bytes[208..240].try_into().unwrap()
    }
    pub fn restart_attempts(&self) -> u8 {
        self.bytes[244]
    }
    pub fn restart_window(&self) -> u64 {
        word(self.bytes, 248)
    }
    pub fn image(&self, slot: ImageSlot) -> Image {
        image(&self.bytes[IMAGE_AT + slot.index() * IMAGE_BYTES..])
    }
    pub fn package(&self, kind: PackageKind) -> Package {
        package(
            &self.bytes[PACKAGE_AT + kind.index() * PACKAGE_BYTES..],
            &self.bytes[PLACEMENT_AT + kind.index() * PLACEMENT_BYTES..],
        )
    }
    pub fn instance_binding(&self, actor: Child) -> [u8; 32] {
        let at = INSTANCE_AT + actor.index() * INSTANCE_BYTES + 32;
        self.bytes[at..at + 32].try_into().unwrap()
    }
    pub fn boot_mode(&self) -> BootMode {
        match self.bytes[240] {
            0 => BootMode::Standalone,
            1 => BootMode::SystemManaged,
            _ => BootMode::Recovery,
        }
    }
    pub fn root_image(&self) -> [u8; 32] {
        self.bytes[80..112].try_into().unwrap()
    }
    pub fn graph_measurement(&self) -> [u8; 32] {
        self.bytes[144..176].try_into().unwrap()
    }
    pub fn layout_measurement(&self) -> [u8; 32] {
        self.bytes[176..208].try_into().unwrap()
    }
    pub fn device(&self) -> DeviceWitness {
        let b = &self.bytes[DEVICE_AT..];
        DeviceWitness {
            mac: b[24..30].try_into().unwrap(),
            model_source_sha256: b[32..64].try_into().unwrap(),
            emulator_binary_sha256: b[64..96].try_into().unwrap(),
        }
    }
    pub fn network_policy(&self) -> Result<NetworkPolicy<'a>, Error> {
        let b = &self.bytes[POLICY_AT..POLICY_AT + 320];
        let length = usize::from(b[12]);
        if length > 253 {
            return Err(Error::Policy);
        }
        Ok(NetworkPolicy {
            allowed_ipv4: b[16..20].try_into().unwrap(),
            remote_port: u16::from_le_bytes(b[20..22].try_into().unwrap()),
            local_port: u16::from_le_bytes(b[22..24].try_into().unwrap()),
            dns_name: core::str::from_utf8(&b[24..24 + length]).map_err(|_| Error::Policy)?,
        })
    }
    pub fn measurement_parts(&self) -> (&'a [u8], &'a [u8]) {
        (
            &self.bytes[..MEASUREMENT_OFFSET],
            &self.bytes[MEASUREMENT_OFFSET + 32..],
        )
    }
    pub fn cohort_parts(&self) -> (&'a [u8], &'a [u8], &'a [u8]) {
        (
            &self.bytes[..MEASUREMENT_OFFSET],
            &self.bytes[MEASUREMENT_OFFSET + 32..240],
            &self.bytes[241..],
        )
    }
}
pub fn encode(d: Description<'_>) -> Result<[u8; SIZE], Error> {
    encode_with_ingress(d, None)
}
pub fn encode_with_ingress(
    d: Description<'_>,
    external: Option<ExternalIngress>,
) -> Result<[u8; SIZE], Error> {
    let mut b = [0; SIZE];
    b[..8].copy_from_slice(b"EVCOH005");
    b[8..10].copy_from_slice(&5u16.to_le_bytes());
    b[10..12].copy_from_slice(&(SIZE as u16).to_le_bytes());
    b[12..14].copy_from_slice(&5u16.to_le_bytes());
    b[14..16].copy_from_slice(&(HEADER as u16).to_le_bytes());
    b[16..48].copy_from_slice(&ABI);
    b[48..80].copy_from_slice(&child::ABI);
    for (at, value) in [
        (80, d.root_image),
        (112, d.kernel_input),
        (144, d.graph_measurement),
        (176, d.layout_measurement),
        (208, d.measurement),
    ] {
        b[at..at + 32].copy_from_slice(&value);
    }
    b[240] = d.boot_mode as u8;
    b[241..244].copy_from_slice(&[4, 10, 11]);
    b[244] = d.restart_attempts;
    put(&mut b, 248, d.restart_window);
    for slot in graph::IMAGES {
        let at = IMAGE_AT + slot.index() * IMAGE_BYTES;
        b[at..at + IMAGE_BYTES].copy_from_slice(&image_record(slot, d.images[slot.index()])?);
    }
    for actor in graph::CHILDREN {
        let at = INSTANCE_AT + actor.index() * INSTANCE_BYTES;
        b[at..at + INSTANCE_BYTES]
            .copy_from_slice(&instance_record(actor, d.instance_bindings[actor.index()])?);
    }
    for kind in PACKAGES {
        let at = PACKAGE_AT + kind.index() * PACKAGE_BYTES;
        b[at..at + PACKAGE_BYTES].copy_from_slice(&package_record(kind, d.packages[kind.index()])?);
        let location = PLACEMENT_AT + kind.index() * PLACEMENT_BYTES;
        b[location..location + PLACEMENT_BYTES]
            .copy_from_slice(&placement_record(kind, d.packages[kind.index()])?);
    }
    b[POLICY_AT..POLICY_AT + 320].copy_from_slice(&policy_record(d.network)?);
    b[DEVICE_AT..DEVICE_AT + 128].copy_from_slice(&device_record(d.device)?);
    b[TIMER_AT..TIMER_AT + 64].copy_from_slice(&timer_record());
    b[BUDGET_AT..BUDGET_AT + 128].copy_from_slice(&budget_record());
    b[GRAPH_AT..LAYOUT_AT].copy_from_slice(&graph::description());
    b[LAYOUT_AT..CENSUS_AT].copy_from_slice(&resources::layout_description());
    b[CENSUS_AT..DYNAMIC_AT].copy_from_slice(&resources::proposed_census());
    b[DYNAMIC_AT..DYNAMIC_AT + 128].copy_from_slice(&dynamic_record());
    if let Some(external) = external {
        b[INGRESS_AT..INGRESS_END].copy_from_slice(&ingress::record(external, d.packages)?);
    }
    Catalogue::decode(&b)?;
    Ok(b)
}
