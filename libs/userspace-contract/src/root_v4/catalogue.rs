//! Full v4 metadata. Its explicit seven-role App component base is not a legacy
//! validated catalogue; this independent extension controls v4 profile semantics.
use super::{ABI, PROFILE, Role, nonzero, put, word};
use crate::root_v2::catalogue as base;
pub const BASE_SIZE: usize = base::SIZE;
pub const EXTENSION_SIZE: usize = 2560;
pub const SIZE: usize = BASE_SIZE + EXTENSION_SIZE;
pub const VERSION: u16 = 4;
pub const BASE_ROLE_COUNTS: [u8; base::IMAGES] = [8, 4, 8, 6, 7, 8];
/// Encode the actual six component descriptions under the explicit v4 counts.
/// Public legacy encode/decode remain App6-only and reject these App7 bytes.
pub fn encode_base(description: base::Description) -> Result<[u8; BASE_SIZE], base::Error> {
    base::encode_profile(description, BASE_ROLE_COUNTS)
}
pub const MEASUREMENT_OFFSET: usize = BASE_SIZE + 48;
pub const BOOT_MODE_OFFSET: usize = BASE_SIZE + 512;
pub const MEASUREMENT_DOMAIN: &[u8] = b"evrosion.session.network.fullgraph.v4\0";
const APP_B: usize = 160;
const BAD_SHELL: usize = 336;
const DRIVER: usize = 520;
const NETWORK: usize = 696;
const DEVICE: usize = 872;
const TIMER: usize = 1000;
const BUDGET: usize = 1064;
const POLICY: usize = 1192;
const LAYOUT: usize = 1512;
pub const REFERENCE_MAC: [u8; 6] = [2, 0x45, 0x56, 0x52, 0, 1];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Version,
    Reserved,
    Abi,
    Base(base::Error),
    Package,
    Image,
    Layout,
    Mode,
    Device,
    Timer,
    Budget,
    Policy,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum BootMode {
    Standalone = 0,
    SystemManaged = 1,
    Recovery = 2,
}
impl BootMode {
    fn decode(n: u16) -> Result<Self, Error> {
        match n {
            0 => Ok(Self::Standalone),
            1 => Ok(Self::SystemManaged),
            2 => Ok(Self::Recovery),
            _ => Err(Error::Mode),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Image {
    pub image: [u8; 32],
    pub descriptor: [u8; 32],
    pub abi: [u8; 32],
    pub limits: [u64; 4],
    pub roles: [u8; 32],
}
/// These digests name actual evidence to join; they do not automatically verify
/// downstream QEMU equivalence, lack of DMA, entropy or timestamps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceWitness {
    pub mac: [u8; 6],
    pub model_source_sha256: [u8; 32],
    pub emulator_binary_sha256: [u8; 32],
}
/// DNS diagnostics and transfer target are separate scopes. A DNS answer never
/// authorizes another destination or proves peer identity/TLS/update trust.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkPolicy<'a> {
    pub allowed_ipv4: [u8; 4],
    pub remote_port: u16,
    pub local_port: u16,
    pub dns_name: &'a str,
}
pub struct Description<'a> {
    pub base: &'a [u8],
    pub app_b: Image,
    pub bad_shell: Image,
    pub boot_mode: BootMode,
    pub package_b: [u8; 32],
    pub package_b_build: [u8; 32],
    pub package_a_bytes: u64,
    pub package_b_bytes: u64,
    pub net_driver: Image,
    pub net_service: Image,
    pub device: DeviceWitness,
    pub network_policy: NetworkPolicy<'a>,
    pub layout_measurement: [u8; 32],
}
pub const fn package_pages(bytes: u64) -> Option<u64> {
    if bytes == 0 || bytes > super::PACKAGE_MAX_BYTES {
        None
    } else {
        Some(bytes.div_ceil(4096))
    }
}
fn valid_name(b: &[u8]) -> bool {
    !b.is_empty()
        && b.len() <= 253
        && b.split(|n| *n == b'.').all(|s| {
            !s.is_empty()
                && s.len() <= 63
                && s[0].is_ascii_alphanumeric()
                && s[s.len() - 1].is_ascii_alphanumeric()
                && s.iter()
                    .all(|n| n.is_ascii_lowercase() || n.is_ascii_digit() || *n == b'-')
        })
}
fn valid_policy(p: NetworkPolicy<'_>) -> bool {
    !matches!(p.allowed_ipv4[0], 0 | 127 | 224..=255)
        && p.remote_port != 0
        && p.local_port >= 49152
        && valid_name(p.dns_name.as_bytes())
}
fn image(b: &[u8], at: usize) -> Image {
    let b = &b[at..at + base::IMAGE_BYTES];
    Image {
        image: b[8..40].try_into().unwrap(),
        descriptor: b[40..72].try_into().unwrap(),
        abi: b[72..104].try_into().unwrap(),
        limits: [104, 112, 120, 128].map(|n| word(b, n)),
        roles: b[144..176].try_into().unwrap(),
    }
}
fn check_image(b: &[u8], at: usize, role: Role, limits: [u64; 4], grants: u8) -> Result<(), Error> {
    let v = image(b, at);
    let s = &b[at..at + base::IMAGE_BYTES];
    if word(s, 0) != role.selector()
        || !nonzero(&v.image)
        || !nonzero(&v.descriptor)
        || !nonzero(&v.roles)
        || v.abi != crate::ABI
        || v.limits != limits
        || s[136] != 0
        || s[137] != grants
    {
        return Err(Error::Image);
    }
    if s[138..144].iter().any(|n| *n != 0) {
        return Err(Error::Reserved);
    }
    Ok(())
}
fn encode_image(b: &mut [u8], at: usize, role: Role, im: Image, grants: u8) {
    let s = &mut b[at..at + base::IMAGE_BYTES];
    put(s, 0, role.selector());
    s[8..40].copy_from_slice(&im.image);
    s[40..72].copy_from_slice(&im.descriptor);
    s[72..104].copy_from_slice(&im.abi);
    for (i, n) in im.limits.into_iter().enumerate() {
        put(s, 104 + i * 8, n);
    }
    s[137] = grants;
    s[144..176].copy_from_slice(&im.roles);
}
fn device_record(w: DeviceWitness) -> [u8; 128] {
    let mut b = [0; 128];
    b[..8].copy_from_slice(b"EVNIC004");
    b[8..10].copy_from_slice(&VERSION.to_le_bytes());
    b[10..12].copy_from_slice(&128u16.to_le_bytes());
    b[12..14].copy_from_slice(&1u16.to_le_bytes());
    b[14..16].copy_from_slice(&1u16.to_le_bytes());
    b[16..18].copy_from_slice(&0x300u16.to_le_bytes());
    b[18..20].copy_from_slice(&32u16.to_le_bytes());
    b[20..22].copy_from_slice(&1u16.to_le_bytes());
    b[24..30].copy_from_slice(&w.mac);
    b[32..64].copy_from_slice(&w.model_source_sha256);
    b[64..96].copy_from_slice(&w.emulator_binary_sha256);
    b[96..98].copy_from_slice(&1514u16.to_le_bytes());
    b[98..100].copy_from_slice(&60u16.to_le_bytes());
    b[100..102].copy_from_slice(&4u16.to_le_bytes());
    b[102..104].copy_from_slice(&4u16.to_le_bytes());
    put(&mut b, 104, 0x4000);
    put(&mut b, 112, 0x8000);
    b
}
fn timer_record() -> [u8; 64] {
    let mut b = [0; 64];
    b[..8].copy_from_slice(b"EVPIT004");
    put(&mut b, 8, super::PIT_INPUT_HZ);
    put(&mut b, 16, super::PIT_DIVISOR);
    put(&mut b, 24, 1000);
    b[32] = 1;
    b[33] = 1;
    b
}
fn budget_record() -> [u8; 128] {
    let mut b = [0; 128];
    b[..8].copy_from_slice(b"EVBUD004");
    for (i, n) in [
        super::CPU_QUOTA,
        super::CPU_PERIOD,
        super::ROOT_CPU_QUOTA,
        super::CPU_PERIOD,
        super::RPC_MAX_TICKS,
        super::COLD_PREPARE_MAX_TICKS,
        1514,
        1024,
        4,
        4,
        4,
        512,
        32,
        64,
        1,
    ]
    .into_iter()
    .enumerate()
    {
        put(&mut b, 8 + i * 8, n);
    }
    b
}
fn policy_record(p: NetworkPolicy<'_>) -> [u8; 320] {
    let mut b = [0; 320];
    b[..8].copy_from_slice(b"EVNPOL04");
    b[8..10].copy_from_slice(&VERSION.to_le_bytes());
    b[10..12].copy_from_slice(&320u16.to_le_bytes());
    b[12] = p.dns_name.len() as u8;
    b[16..20].copy_from_slice(&p.allowed_ipv4);
    b[20..22].copy_from_slice(&p.remote_port.to_le_bytes());
    b[22..24].copy_from_slice(&p.local_port.to_le_bytes());
    b[24..24 + p.dns_name.len()].copy_from_slice(p.dns_name.as_bytes());
    b
}

pub struct Catalogue<'a> {
    bytes: &'a [u8],
    base: base::Components<'a>,
}
impl<'a> Catalogue<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() != SIZE {
            return Err(Error::Length);
        }
        let base = base::Components::decode_profile(&bytes[..BASE_SIZE], BASE_ROLE_COUNTS)
            .map_err(Error::Base)?;
        let b = &bytes[BASE_SIZE..];
        if &b[..8] != b"EVNATV04"
            || b[8..10] != VERSION.to_le_bytes()
            || b[10..12] != (EXTENSION_SIZE as u16).to_le_bytes()
            || b[12..14] != PROFILE.to_le_bytes()
        {
            return Err(Error::Version);
        }
        if b[16..48] != ABI {
            return Err(Error::Abi);
        }
        if b[14..16].iter().chain(&b[514..520]).any(|n| *n != 0) {
            return Err(Error::Reserved);
        }
        if !nonzero(&b[48..80]) {
            return Err(Error::Layout);
        }
        if base.provenance() != base::Provenance::Zion
            || !nonzero(&b[80..112])
            || !nonzero(&b[112..144])
            || base.package() == b[80..112]
            || package_pages(word(b, 144)).is_none()
            || package_pages(word(b, 152)).is_none()
        {
            return Err(Error::Package);
        }
        check_image(b, APP_B, Role::AppBImage, base::CHILD_LIMITS, 7)?;
        check_image(b, BAD_SHELL, Role::BadShellImage, base::CHILD_LIMITS, 8)?;
        let a = base.images().nth(4).unwrap();
        let shell = base.images().next().unwrap();
        if image(b, APP_B).roles != a.roles
            || image(b, BAD_SHELL).roles != shell.roles
            || image(b, BAD_SHELL).image == shell.image
        {
            return Err(Error::Image);
        }
        check_image(
            b,
            DRIVER,
            Role::NetDriverImage,
            super::graph::Child::NetDriver.limits(),
            4,
        )?;
        check_image(
            b,
            NETWORK,
            Role::NetServiceImage,
            super::graph::Child::NetService.limits(),
            5,
        )?;
        BootMode::decode(u16::from_le_bytes(b[512..514].try_into().unwrap()))?;
        let value = Self { bytes, base };
        let witness = value.device();
        if witness.mac != REFERENCE_MAC
            || !nonzero(&witness.model_source_sha256)
            || !nonzero(&witness.emulator_binary_sha256)
            || b[DEVICE..DEVICE + 128] != device_record(witness)
        {
            return Err(Error::Device);
        }
        if b[TIMER..TIMER + 64] != timer_record() {
            return Err(Error::Timer);
        }
        if b[BUDGET..BUDGET + 128] != budget_record() {
            return Err(Error::Budget);
        }
        let p = &b[POLICY..POLICY + 320];
        let len = usize::from(p[12]);
        if len > 253 {
            return Err(Error::Policy);
        }
        let name = core::str::from_utf8(&p[24..24 + len]).map_err(|_| Error::Policy)?;
        let policy = NetworkPolicy {
            allowed_ipv4: p[16..20].try_into().unwrap(),
            remote_port: u16::from_le_bytes(p[20..22].try_into().unwrap()),
            local_port: u16::from_le_bytes(p[22..24].try_into().unwrap()),
            dns_name: name,
        };
        if !valid_policy(policy) || p != policy_record(policy) {
            return Err(Error::Policy);
        }
        if b[LAYOUT..LAYOUT + super::LAYOUT_BYTES] != super::layout_description() {
            return Err(Error::Layout);
        }
        if b[LAYOUT + super::LAYOUT_BYTES..] != super::dynamic::layout_record() {
            return Err(Error::Layout);
        }
        Ok(value)
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    /// V4-count-qualified components, never a legacy-validated catalogue or
    /// v4 Root admission ABI. AppA actually has seven declared roles.
    pub fn base(&self) -> &base::Components<'a> {
        &self.base
    }
    pub const fn root_abi(&self) -> [u8; 32] {
        ABI
    }
    pub const fn profile(&self) -> u16 {
        PROFILE
    }
    pub fn layout_measurement(&self) -> [u8; 32] {
        self.bytes[MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + 32]
            .try_into()
            .unwrap()
    }
    pub fn app_b(&self) -> Image {
        image(&self.bytes[BASE_SIZE..], APP_B)
    }
    pub fn bad_shell(&self) -> Image {
        image(&self.bytes[BASE_SIZE..], BAD_SHELL)
    }
    pub fn net_driver(&self) -> Image {
        image(&self.bytes[BASE_SIZE..], DRIVER)
    }
    pub fn net_service(&self) -> Image {
        image(&self.bytes[BASE_SIZE..], NETWORK)
    }
    pub fn package_a(&self) -> [u8; 32] {
        self.base.package()
    }
    pub fn package_b(&self) -> [u8; 32] {
        self.bytes[BASE_SIZE + 80..BASE_SIZE + 112]
            .try_into()
            .unwrap()
    }
    pub fn package_b_build(&self) -> [u8; 32] {
        self.bytes[BASE_SIZE + 112..BASE_SIZE + 144]
            .try_into()
            .unwrap()
    }
    pub fn package_a_bytes(&self) -> u64 {
        word(self.bytes, BASE_SIZE + 144)
    }
    pub fn package_b_bytes(&self) -> u64 {
        word(self.bytes, BASE_SIZE + 152)
    }
    pub fn boot_mode(&self) -> BootMode {
        BootMode::decode(u16::from_le_bytes(
            self.bytes[BOOT_MODE_OFFSET..BOOT_MODE_OFFSET + 2]
                .try_into()
                .unwrap(),
        ))
        .unwrap()
    }
    pub fn device(&self) -> DeviceWitness {
        let b = &self.bytes[BASE_SIZE + DEVICE..];
        DeviceWitness {
            mac: b[24..30].try_into().unwrap(),
            model_source_sha256: b[32..64].try_into().unwrap(),
            emulator_binary_sha256: b[64..96].try_into().unwrap(),
        }
    }
    pub fn network_policy(&self) -> NetworkPolicy<'a> {
        let p = &self.bytes[BASE_SIZE + POLICY..];
        let len = usize::from(p[12]);
        NetworkPolicy {
            allowed_ipv4: p[16..20].try_into().unwrap(),
            remote_port: u16::from_le_bytes(p[20..22].try_into().unwrap()),
            local_port: u16::from_le_bytes(p[22..24].try_into().unwrap()),
            dns_name: core::str::from_utf8(&p[24..24 + len]).unwrap(),
        }
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
            &self.bytes[MEASUREMENT_OFFSET + 32..BOOT_MODE_OFFSET],
            &self.bytes[BOOT_MODE_OFFSET + 2..],
        )
    }
}
pub fn encode(d: Description<'_>) -> Result<[u8; SIZE], Error> {
    if d.base.len() != BASE_SIZE {
        return Err(Error::Length);
    }
    if !valid_policy(d.network_policy) {
        return Err(Error::Policy);
    }
    let mut bytes = [0; SIZE];
    bytes[..BASE_SIZE].copy_from_slice(d.base);
    let b = &mut bytes[BASE_SIZE..];
    b[..8].copy_from_slice(b"EVNATV04");
    b[8..10].copy_from_slice(&VERSION.to_le_bytes());
    b[10..12].copy_from_slice(&(EXTENSION_SIZE as u16).to_le_bytes());
    b[12..14].copy_from_slice(&PROFILE.to_le_bytes());
    b[16..48].copy_from_slice(&ABI);
    b[48..80].copy_from_slice(&d.layout_measurement);
    b[80..112].copy_from_slice(&d.package_b);
    b[112..144].copy_from_slice(&d.package_b_build);
    put(b, 144, d.package_a_bytes);
    put(b, 152, d.package_b_bytes);
    encode_image(b, APP_B, Role::AppBImage, d.app_b, 7);
    encode_image(b, BAD_SHELL, Role::BadShellImage, d.bad_shell, 8);
    b[512..514].copy_from_slice(&(d.boot_mode as u16).to_le_bytes());
    encode_image(b, DRIVER, Role::NetDriverImage, d.net_driver, 4);
    encode_image(b, NETWORK, Role::NetServiceImage, d.net_service, 5);
    b[DEVICE..DEVICE + 128].copy_from_slice(&device_record(d.device));
    b[TIMER..TIMER + 64].copy_from_slice(&timer_record());
    b[BUDGET..BUDGET + 128].copy_from_slice(&budget_record());
    b[POLICY..POLICY + 320].copy_from_slice(&policy_record(d.network_policy));
    b[LAYOUT..LAYOUT + super::LAYOUT_BYTES].copy_from_slice(&super::layout_description());
    b[LAYOUT + super::LAYOUT_BYTES..].copy_from_slice(&super::dynamic::layout_record());
    Catalogue::decode(&bytes)?;
    Ok(bytes)
}
