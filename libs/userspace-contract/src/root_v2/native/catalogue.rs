//! Native catalogue = unchanged legacy component/A catalogue + versioned Native
//! extension. The base's Desktop ABI/disk fields describe that base only; this
//! extension is authoritative for Native Root ABI/profile/layout. Decode proves
//! syntax, not content ownership, package compatibility, mapping or admission.
#![forbid(unsafe_code)]
use super::{ABI, ExtraRole, PACKAGE_MAX_BYTES, PROFILE};
use crate::root_v2::catalogue as base;
pub const SIZE: usize = 2560;
pub const BASE_SIZE: usize = base::SIZE;
pub const EXTENSION_SIZE: usize = 1024;
pub const VERSION: u16 = 3;
pub const MEASUREMENT_OFFSET: usize = BASE_SIZE + 48;
pub const MEASUREMENT_DOMAIN: &[u8] = b"evrosion.native.fullgraph.v3\0";
const IMAGE_OFFSET: usize = 160;
const IMAGE_END: usize = IMAGE_OFFSET + base::IMAGE_BYTES;
const BAD_SHELL_OFFSET: usize = IMAGE_END;
const BAD_SHELL_END: usize = BAD_SHELL_OFFSET + base::IMAGE_BYTES;
const EXT_BOOT_MODE_OFFSET: usize = BAD_SHELL_END;
pub const BOOT_MODE_OFFSET: usize = BASE_SIZE + EXT_BOOT_MODE_OFFSET;
const MAGIC: &[u8; 8] = b"EVNATV03";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Version,
    Reserved,
    Abi,
    Base(base::Error),
    Image,
    Package,
    Layout,
    BootMode,
}
/// Fixed AppB slot: selector19, no device layout, exactly the same six roles,
/// limits and ABI as AppA. Actual ELF/descriptor verification is independent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppImage {
    pub image: [u8; 32],
    pub descriptor: [u8; 32],
    pub abi: [u8; 32],
    pub limits: [u64; 4],
    pub roles: [u8; 32],
}
/// Explicit measured boot selection. This is configuration, not an admission
/// token, owner decision, System-health assertion or permission to format.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u16)]
pub enum BootMode {
    #[default]
    Standalone = 0,
    SystemManaged = 1,
    Recovery = 2,
}
impl BootMode {
    fn decode(value: u16) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::Standalone),
            1 => Ok(Self::SystemManaged),
            2 => Ok(Self::Recovery),
            _ => Err(Error::BootMode),
        }
    }
}
pub struct Description<'a> {
    pub base: &'a [u8],
    pub app_b: AppImage,
    pub bad_shell: AppImage,
    pub boot_mode: BootMode,
    pub package_b: [u8; 32],
    pub package_b_build: [u8; 32],
    pub package_a_bytes: u64,
    pub package_b_bytes: u64,
    pub layout_measurement: [u8; 32],
}
fn word(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn put(b: &mut [u8], at: usize, value: u64) {
    b[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn nonzero(b: &[u8]) -> bool {
    b.iter().any(|&n| n != 0)
}
pub const fn package_pages(bytes: u64) -> Option<u64> {
    if bytes == 0 || bytes > PACKAGE_MAX_BYTES {
        return None;
    }
    Some(bytes.div_ceil(super::PACKAGE_PAGE_BYTES))
}
pub struct Catalogue<'a> {
    bytes: &'a [u8],
    base: base::Catalogue<'a>,
}
impl<'a> Catalogue<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() != SIZE {
            return Err(Error::Length);
        }
        let component = base::Catalogue::decode(&bytes[..BASE_SIZE]).map_err(Error::Base)?;
        let b = &bytes[BASE_SIZE..];
        if &b[..8] != MAGIC
            || b[8..10] != VERSION.to_le_bytes()
            || b[10..12] != (EXTENSION_SIZE as u16).to_le_bytes()
            || b[12..14] != PROFILE.to_le_bytes()
        {
            return Err(Error::Version);
        }
        if b[16..48] != ABI {
            return Err(Error::Abi);
        }
        if b[14..16]
            .iter()
            .chain(&b[EXT_BOOT_MODE_OFFSET + 2..])
            .any(|&n| n != 0)
        {
            return Err(Error::Reserved);
        }
        if !nonzero(&b[48..80]) {
            return Err(Error::Layout);
        }
        if component.provenance() != base::Provenance::Zion
            || !nonzero(&b[80..112])
            || !nonzero(&b[112..144])
            || component.package() == b[80..112]
            || package_pages(word(b, 144)).is_none()
            || package_pages(word(b, 152)).is_none()
        {
            return Err(Error::Package);
        }
        let value = Self {
            bytes,
            base: component,
        };
        let app_b = value.app_b();
        let a = value.base.images().nth(4).unwrap();
        let slot = &b[IMAGE_OFFSET..IMAGE_END];
        if word(slot, 0) != ExtraRole::AppBImage.selector()
            || !nonzero(&app_b.image)
            || !nonzero(&app_b.descriptor)
            || !nonzero(&app_b.roles)
            || app_b.abi != crate::ABI
            || app_b.limits != base::CHILD_LIMITS
            || app_b.roles != a.roles
            || slot[136] != 0
            || slot[137] != 6
        {
            return Err(Error::Image);
        }
        if slot[138..144].iter().any(|&n| n != 0) {
            return Err(Error::Reserved);
        }
        let bad = value.bad_shell();
        let good = value
            .base
            .images()
            .nth(crate::root_v2::graph::Child::Shell.index())
            .unwrap();
        let slot = &b[BAD_SHELL_OFFSET..BAD_SHELL_END];
        if word(slot, 0) != ExtraRole::BadShellImage.selector()
            || !nonzero(&bad.image)
            || bad.image == good.image
            || !nonzero(&bad.descriptor)
            || !nonzero(&bad.roles)
            || bad.abi != crate::ABI
            || bad.limits != base::CHILD_LIMITS
            || bad.roles != good.roles
            || slot[136] != 0
            || slot[137] != 8
        {
            return Err(Error::Image);
        }
        if slot[138..144].iter().any(|&n| n != 0) {
            return Err(Error::Reserved);
        }
        BootMode::decode(u16::from_le_bytes(
            b[EXT_BOOT_MODE_OFFSET..EXT_BOOT_MODE_OFFSET + 2]
                .try_into()
                .unwrap(),
        ))?;
        Ok(value)
    }
    /// Legacy component/A metadata only, never the Native Root ABI or disk scope.
    pub const fn base(&self) -> &base::Catalogue<'a> {
        &self.base
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub const fn root_abi(&self) -> [u8; 32] {
        ABI
    }
    pub const fn profile(&self) -> u16 {
        PROFILE
    }
    pub fn layout_measurement(&self) -> [u8; 32] {
        self.bytes[BASE_SIZE + 48..BASE_SIZE + 80]
            .try_into()
            .unwrap()
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
    pub fn app_b(&self) -> AppImage {
        let b = &self.bytes[BASE_SIZE + IMAGE_OFFSET..BASE_SIZE + IMAGE_END];
        AppImage {
            image: b[8..40].try_into().unwrap(),
            descriptor: b[40..72].try_into().unwrap(),
            abi: b[72..104].try_into().unwrap(),
            limits: [104, 112, 120, 128].map(|at| word(b, at)),
            roles: b[144..176].try_into().unwrap(),
        }
    }
    pub fn bad_shell(&self) -> AppImage {
        let b = &self.bytes[BASE_SIZE + BAD_SHELL_OFFSET..BASE_SIZE + BAD_SHELL_END];
        AppImage {
            image: b[8..40].try_into().unwrap(),
            descriptor: b[40..72].try_into().unwrap(),
            abi: b[72..104].try_into().unwrap(),
            limits: [104, 112, 120, 128].map(|at| word(b, at)),
            roles: b[144..176].try_into().unwrap(),
        }
    }
    pub fn boot_mode(&self) -> BootMode {
        BootMode::decode(u16::from_le_bytes(
            self.bytes[BOOT_MODE_OFFSET..BOOT_MODE_OFFSET + 2]
                .try_into()
                .unwrap(),
        ))
        .unwrap()
    }
    /// Hash the FULL2560-byte catalogue with only its layout field zeroed, plus
    /// the named Native layout description/wiring. The base alone is insufficient.
    /// Canonical cohort input slices. Hash these in order with32 zero bytes
    /// after the first and2 after the second. Only layout measurement and boot
    /// mode are excluded; actual wire decode/admission still binds BOTH. This
    /// is a content recipe, never an admission/health or durable-store receipt.
    pub fn cohort_parts(&self) -> (&'a [u8], &'a [u8], &'a [u8]) {
        (
            &self.bytes[..MEASUREMENT_OFFSET],
            &self.bytes[MEASUREMENT_OFFSET + 32..BOOT_MODE_OFFSET],
            &self.bytes[BOOT_MODE_OFFSET + 2..],
        )
    }
    pub fn measurement_parts(&self) -> (&'a [u8], &'a [u8]) {
        (
            &self.bytes[..MEASUREMENT_OFFSET],
            &self.bytes[MEASUREMENT_OFFSET + 32..],
        )
    }
}
/// A producer may seed a nonzero temporary measurement, hash measurement_parts
/// (zeroing that32-byte field), then encode with the actual digest. Neither
/// encoding step creates a mapping or a kernel content-validation receipt.
pub fn encode(d: Description<'_>) -> Result<[u8; SIZE], Error> {
    if d.base.len() != BASE_SIZE {
        return Err(Error::Length);
    }
    let mut bytes = [0; SIZE];
    bytes[..BASE_SIZE].copy_from_slice(d.base);
    let b = &mut bytes[BASE_SIZE..];
    b[..8].copy_from_slice(MAGIC);
    b[8..10].copy_from_slice(&VERSION.to_le_bytes());
    b[10..12].copy_from_slice(&(EXTENSION_SIZE as u16).to_le_bytes());
    b[12..14].copy_from_slice(&PROFILE.to_le_bytes());
    b[16..48].copy_from_slice(&ABI);
    b[48..80].copy_from_slice(&d.layout_measurement);
    b[80..112].copy_from_slice(&d.package_b);
    b[112..144].copy_from_slice(&d.package_b_build);
    put(b, 144, d.package_a_bytes);
    put(b, 152, d.package_b_bytes);
    let slot = &mut b[IMAGE_OFFSET..IMAGE_END];
    put(slot, 0, ExtraRole::AppBImage.selector());
    slot[8..40].copy_from_slice(&d.app_b.image);
    slot[40..72].copy_from_slice(&d.app_b.descriptor);
    slot[72..104].copy_from_slice(&d.app_b.abi);
    for (i, n) in d.app_b.limits.into_iter().enumerate() {
        put(slot, 104 + i * 8, n);
    }
    slot[137] = 6;
    slot[144..176].copy_from_slice(&d.app_b.roles);
    let slot = &mut b[BAD_SHELL_OFFSET..BAD_SHELL_END];
    put(slot, 0, ExtraRole::BadShellImage.selector());
    slot[8..40].copy_from_slice(&d.bad_shell.image);
    slot[40..72].copy_from_slice(&d.bad_shell.descriptor);
    slot[72..104].copy_from_slice(&d.bad_shell.abi);
    for (i, n) in d.bad_shell.limits.into_iter().enumerate() {
        put(slot, 104 + i * 8, n);
    }
    slot[137] = 8;
    slot[144..176].copy_from_slice(&d.bad_shell.roles);
    b[EXT_BOOT_MODE_OFFSET..EXT_BOOT_MODE_OFFSET + 2]
        .copy_from_slice(&(d.boot_mode as u16).to_le_bytes());
    Catalogue::decode(&bytes)?;
    Ok(bytes)
}
