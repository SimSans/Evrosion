//! Internal .zion container. Integrity/compatibility parsing grants
//! no authority and authenticates neither publisher nor claimed AppIdentity.
#![no_std]
#![forbid(unsafe_code)]
use sha2::{Digest, Sha256};
pub mod lifecycle;

pub const HEADER: usize = 96;
pub const ENTRY: usize = 128;
pub const MAX_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_MANIFEST: usize = 4096;
pub const MAX_ENTRIES: usize = 16;
pub const MAX_REQUIREMENTS: usize = 8;
const REQUIRED: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Magic,
    FormatVersion,
    ManifestVersion,
    Reserved,
    Overflow,
    Bounds,
    ManifestDigest,
    IndexDigest,
    ContentDigest,
    RequiredField(u16),
    MissingField(u16),
    Duplicate,
    Field,
    Text,
    Path,
    Architecture,
    Elf,
    UnsupportedCapability(u16),
    Platform,
    Abi,
    UnsupportedContract,
}
type Result<T> = core::result::Result<T, Error>;

/// Same canonical registry key used by selected-file policy.
pub use ev_app_identity::AppId;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublisherClaim([u8; 16]);
impl PublisherClaim {
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackageId([u8; 32]);
impl PackageId {
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Platform {
    pub minimum: u32,
    pub target: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataSchema {
    pub current: u32,
    pub oldest_readable: u32,
}
impl DataSchema {
    pub const fn reads(self, epoch: u32) -> bool {
        epoch >= self.oldest_readable && epoch <= self.current
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Executable,
    Resource,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub kind: Kind,
    pub path: &'a str,
    pub bytes: &'a [u8],
    pub digest: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Contract<'a> {
    pub name: &'a str,
    pub major: u16,
    pub minimum_minor: u16,
    pub features: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    SelectedFileRead,
    AppPrivateData,
    OwnSurfacePresent,
    FocusedInput,
    Diagnostics,
    UnknownOptional(u16),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityRequest {
    pub capability: Capability,
    pub required: bool,
}

/// Security-relevant fields of canonical E-016 AppIdentity, plus package
/// requirements. Human name/source, publisher, immutable package/build/version,
/// ABI, data schema and runtime instance remain separate concepts. The full
/// app registry's provenance/activation/runtime records are outside this parser.
#[derive(Clone, Copy, Debug)]
pub struct AppDescriptor<'a> {
    pub claimed_app: AppId,
    pub display_name: &'a str,
    pub developer_source: &'a str,
    pub publisher: Option<PublisherClaim>,
    pub version: Version,
    pub build_id: [u8; 32],
    pub platform: Platform,
    pub abi: [u8; 32],
    pub data_schema: DataSchema,
    pub entrypoint: &'a str,
    contracts: &'a [u8],
    capabilities: &'a [u8],
}
impl AppDescriptor<'_> {
    pub fn contracts(&self) -> impl Iterator<Item = Contract<'_>> {
        self.contracts[8..]
            .as_chunks::<64>()
            .0
            .iter()
            .map(|r| Contract {
                name: core::str::from_utf8(&r[16..16 + usize::from(r[0])])
                    .expect("validated contract"),
                major: u16::from_le_bytes([r[2], r[3]]),
                minimum_minor: u16::from_le_bytes([r[4], r[5]]),
                features: u64::from_le_bytes(r[8..16].try_into().expect("validated row")),
            })
    }
    pub fn capability_requests(&self) -> impl Iterator<Item = CapabilityRequest> + '_ {
        self.capabilities[8..]
            .as_chunks::<8>()
            .0
            .iter()
            .map(|r| CapabilityRequest {
                capability: capability(u16::from_le_bytes([r[0], r[1]])),
                required: r[2] == 1,
            })
    }
}

pub struct ContractSupport {
    pub minor: u16,
    pub features: u64,
}
pub trait Contracts {
    /// Advertisement/compatibility metadata only; discovery binds no endpoint
    /// or capabilities. Actual service binding remains separately authorized.
    fn supported(&self, name: &str, major: u16) -> Option<ContractSupport>;
}
/// Parsed package integrity is preserved by immutable fields and backing-byte
/// borrows. Plain detached AppDescriptor/Entry values are not validation receipts.
///
/// ```compile_fail,E0616
/// use ev_zion::Package;
/// fn rewrite_app(package: &mut Package<'_>) { package.app = *package.app(); }
/// ```
/// ```compile_fail,E0616
/// use ev_zion::Package;
/// fn rewrite_id(package: &mut Package<'_>) { package.id = package.id(); }
/// ```
/// ```compile_fail,E0616
/// use ev_zion::Package;
/// fn rewrite_format(package: &mut Package<'_>) { package.format_minor = 99; }
/// ```
/// ```compile_fail,E0594
/// use ev_zion::Package;
/// fn rewrite_through_view(package: &mut Package<'_>) { package.app().abi = [9; 32]; }
/// ```
/// ```compile_fail,E0506
/// use ev_zion::Package;
/// fn overwrite_backing(bytes: &mut [u8]) {
///     let package = Package::parse(bytes).unwrap();
///     bytes[0] ^= 1;
///     let _still_borrowed = package.id();
/// }
/// ```
pub struct Package<'a> {
    app: AppDescriptor<'a>,
    format_minor: u16,
    id: PackageId,
    executable: Entry<'a>,
    // Only the validated immutable table is retained. Materializing every
    // decoded Entry here inflated each Package/Result/compatibility stack copy.
    bytes: &'a [u8],
    table: &'a [[u8; ENTRY]],
}
/// Evidence only of this parser's platform/ABI/contract compatibility check.
/// Actual ELF admission, provenance authorization and capability policy remain
/// separate mandatory gates. This is not an activation or permission receipt.
pub struct CompatiblePackage<'package, 'bytes> {
    package: &'package Package<'bytes>,
}
impl CompatiblePackage<'_, '_> {
    pub fn package(&self) -> &Package<'_> {
        self.package
    }
}
impl<'a> Package<'a> {
    /// Exact immutable container whose complete contents were validated by
    /// `parse`. The shared borrow keeps a retained view tied to those bytes;
    /// it conveys neither current compatibility nor execution authority.
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    /// Shared view of the metadata validated against the immutable package.
    /// Copying this plain descriptor and editing that detached copy cannot
    /// change this Package or a compatibility receipt borrowed from it.
    pub const fn app(&self) -> &AppDescriptor<'a> {
        &self.app
    }
    pub const fn id(&self) -> PackageId {
        self.id
    }
    pub const fn format_minor(&self) -> u16 {
        self.format_minor
    }
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < HEADER || bytes.len() > MAX_BYTES {
            return Err(Error::Length);
        }
        if &bytes[..8] != b"EVZION01" {
            return Err(Error::Magic);
        }
        if u16_at(bytes, 8)? != 1 {
            return Err(Error::FormatVersion);
        }
        // Additive minor versions may carry explicitly ignorable optional TLVs;
        // unknown required semantics still fail. No silent major fallback.
        let format_minor = u16_at(bytes, 10)?;
        if usize::from(u16_at(bytes, 12)?) != HEADER || u16_at(bytes, 14)? != 0 {
            return Err(Error::Reserved);
        }
        if u16_at(bytes, 26)? != 1 {
            return Err(Error::ManifestVersion);
        }
        if bytes[28..32].iter().any(|b| *b != 0) {
            return Err(Error::Reserved);
        }
        if to_usize(u32_at(bytes, 16)?)? != bytes.len() {
            return Err(Error::Length);
        }
        let manifest_len = to_usize(u32_at(bytes, 20)?)?;
        let count = usize::from(u16_at(bytes, 24)?);
        if manifest_len == 0 || manifest_len > MAX_MANIFEST || count == 0 || count > MAX_ENTRIES {
            return Err(Error::Bounds);
        }
        let manifest_end = HEADER.checked_add(manifest_len).ok_or(Error::Overflow)?;
        let table_len = count.checked_mul(ENTRY).ok_or(Error::Overflow)?;
        let table_end = manifest_end.checked_add(table_len).ok_or(Error::Overflow)?;
        let manifest = bytes.get(HEADER..manifest_end).ok_or(Error::Bounds)?;
        let table = bytes.get(manifest_end..table_end).ok_or(Error::Bounds)?;
        if sha(manifest) != array32(bytes, 32)? {
            return Err(Error::ManifestDigest);
        }
        if sha(table) != array32(bytes, 64)? {
            return Err(Error::IndexDigest);
        }
        let app = parse_manifest(manifest)?;
        let mut executable = None;
        let (rows, trailing) = table.as_chunks::<ENTRY>();
        debug_assert!(trailing.is_empty());
        let mut cursor = table_end;
        let mut previous = "";
        for (index, row) in rows.iter().enumerate() {
            let kind = match row[0] {
                1 => Kind::Executable,
                2 => Kind::Resource,
                _ => return Err(Error::Field),
            };
            if row[1] != 0 || row[12..16].iter().chain(&row[112..]).any(|b| *b != 0) {
                return Err(Error::Reserved);
            }
            let path_len = usize::from(u16_at(row, 2)?);
            if path_len == 0 || path_len > 64 || row[48 + path_len..112].iter().any(|b| *b != 0) {
                return Err(Error::Path);
            }
            let path = path(&row[48..48 + path_len])?;
            if path <= previous {
                return Err(Error::Duplicate);
            }
            previous = path;
            let offset = to_usize(u32_at(row, 4)?)?;
            let length = to_usize(u32_at(row, 8)?)?;
            if offset != cursor || length == 0 {
                return Err(Error::Bounds);
            }
            cursor = offset.checked_add(length).ok_or(Error::Overflow)?;
            let body = bytes.get(offset..cursor).ok_or(Error::Bounds)?;
            let digest = array32(row, 16)?;
            if sha(body) != digest {
                return Err(Error::ContentDigest);
            }
            if index == 0 {
                if kind != Kind::Executable || path != app.entrypoint {
                    return Err(Error::Field);
                }
                elf(body)?;
            } else if kind != Kind::Resource {
                return Err(Error::Field);
            }
            if index == 0 {
                executable = Some(Entry {
                    kind,
                    path,
                    bytes: body,
                    digest,
                });
            }
        }
        if cursor != bytes.len() {
            return Err(Error::Length);
        }
        let executable = executable.ok_or(Error::Field)?;
        Ok(Self {
            app,
            format_minor,
            id: PackageId(sha(bytes)),
            executable,
            bytes,
            table: rows,
        })
    }
    pub const fn executable(&self) -> Entry<'a> {
        self.executable
    }
    pub fn resources(&self) -> impl Iterator<Item = Entry<'a>> + '_ {
        self.table[1..].iter().map(|row| {
            // Parse validated rows only. The Package's immutable backing borrow
            // prevents safe mutation after the complete eager integrity check.
            let path_len = u16::from_le_bytes([row[2], row[3]]) as usize;
            let offset =
                u32::from_le_bytes(row[4..8].try_into().expect("validated offset")) as usize;
            let length =
                u32::from_le_bytes(row[8..12].try_into().expect("validated length")) as usize;
            Entry {
                kind: Kind::Resource,
                path: core::str::from_utf8(&row[48..48 + path_len])
                    .expect("validated resource path"),
                bytes: &self.bytes[offset..offset + length],
                digest: row[16..48].try_into().expect("validated resource digest"),
            }
        })
    }
    pub fn check_requirements(
        &self,
        platform_level: u32,
        abi: [u8; 32],
        contracts: &impl Contracts,
    ) -> Result<()> {
        if platform_level < self.app.platform.minimum {
            return Err(Error::Platform);
        }
        if abi != self.app.abi {
            return Err(Error::Abi);
        }
        for required in self.app.contracts() {
            let found = contracts
                .supported(required.name, required.major)
                .ok_or(Error::UnsupportedContract)?;
            if found.minor < required.minimum_minor
                || found.features & required.features != required.features
            {
                return Err(Error::UnsupportedContract);
            }
        }
        Ok(())
    }
    pub fn compatible<'package>(
        &'package self,
        platform_level: u32,
        abi: [u8; 32],
        contracts: &impl Contracts,
    ) -> Result<CompatiblePackage<'package, 'a>> {
        self.check_requirements(platform_level, abi, contracts)?;
        Ok(CompatiblePackage { package: self })
    }
}

fn parse_manifest(bytes: &[u8]) -> Result<AppDescriptor<'_>> {
    let mut fields: [Option<&[u8]>; 14] = [None; 14];
    let mut cursor = 0;
    let mut previous = 0;
    while cursor < bytes.len() {
        let head = bytes
            .get(cursor..cursor.checked_add(8).ok_or(Error::Overflow)?)
            .ok_or(Error::Bounds)?;
        let tag = u16_at(head, 0)?;
        let flags = u16_at(head, 2)?;
        let len = to_usize(u32_at(head, 4)?)?;
        if tag == 0 || tag <= previous {
            return Err(Error::Duplicate);
        }
        previous = tag;
        if flags & !REQUIRED != 0 {
            return Err(Error::Reserved);
        }
        cursor = cursor.checked_add(8).ok_or(Error::Overflow)?;
        let end = cursor.checked_add(len).ok_or(Error::Overflow)?;
        let value = bytes.get(cursor..end).ok_or(Error::Bounds)?;
        cursor = end;
        if tag <= 13 {
            let required = tag != 4;
            if (flags == REQUIRED) != required {
                return Err(Error::Field);
            }
            fields[usize::from(tag)] = Some(value);
        } else if flags == REQUIRED {
            return Err(Error::RequiredField(tag));
        }
    }
    for tag in (1..=13).filter(|n| *n != 4) {
        if fields[tag].is_none() {
            return Err(Error::MissingField(tag as u16));
        }
    }
    let get = |tag: usize, len: usize| -> Result<&[u8]> {
        let b = fields[tag].ok_or(Error::MissingField(tag as u16))?;
        if b.len() != len {
            return Err(Error::Field);
        }
        Ok(b)
    };
    let claimed_app =
        AppId::new(get(1, 16)?.try_into().map_err(|_| Error::Field)?).ok_or(Error::Field)?;
    let publisher = fields[4]
        .map(|b| {
            if b.len() != 16 || !nonzero(b) {
                Err(Error::Field)
            } else {
                Ok(PublisherClaim(b.try_into().map_err(|_| Error::Field)?))
            }
        })
        .transpose()?;
    let version = get(5, 12)?;
    let build = get(6, 32)?;
    let platform = get(7, 8)?;
    if get(8, 4)? != [1, 0, 0, 0] {
        return Err(Error::Architecture);
    }
    let abi = get(9, 32)?;
    let schema = get(10, 8)?;
    if !nonzero(build) || !nonzero(abi) {
        return Err(Error::Field);
    }
    let platform = Platform {
        minimum: u32_at(platform, 0)?,
        target: u32_at(platform, 4)?,
    };
    if platform.target < platform.minimum {
        return Err(Error::Field);
    }
    let data_schema = DataSchema {
        current: u32_at(schema, 0)?,
        oldest_readable: u32_at(schema, 4)?,
    };
    if data_schema.oldest_readable == 0 || data_schema.current < data_schema.oldest_readable {
        return Err(Error::Field);
    }
    let contracts = fields[12].ok_or(Error::MissingField(12))?;
    validate_contracts(contracts)?;
    let capabilities = fields[13].ok_or(Error::MissingField(13))?;
    validate_capabilities(capabilities)?;
    Ok(AppDescriptor {
        claimed_app,
        display_name: text(fields[2].ok_or(Error::MissingField(2))?, 64)?,
        developer_source: text(fields[3].ok_or(Error::MissingField(3))?, 96)?,
        publisher,
        version: Version {
            major: u32_at(version, 0)?,
            minor: u32_at(version, 4)?,
            patch: u32_at(version, 8)?,
        },
        build_id: build.try_into().map_err(|_| Error::Field)?,
        platform,
        abi: abi.try_into().map_err(|_| Error::Field)?,
        data_schema,
        entrypoint: path(fields[11].ok_or(Error::MissingField(11))?)?,
        contracts,
        capabilities,
    })
}
fn rows(bytes: &[u8], width: usize) -> Result<&[u8]> {
    if bytes.len() < 8 || bytes[2..8].iter().any(|b| *b != 0) {
        return Err(Error::Field);
    }
    let count = usize::from(u16_at(bytes, 0)?);
    if count > MAX_REQUIREMENTS
        || bytes.len() != 8 + count.checked_mul(width).ok_or(Error::Overflow)?
    {
        return Err(Error::Bounds);
    }
    Ok(&bytes[8..])
}
fn validate_contracts(bytes: &[u8]) -> Result<()> {
    let mut previous = "";
    for row in rows(bytes, 64)?.as_chunks::<64>().0 {
        let len = usize::from(row[0]);
        if len == 0
            || len > 48
            || row[1] != 1
            || u16_at(row, 2)? == 0
            || row[6..8].iter().chain(&row[16 + len..]).any(|b| *b != 0)
        {
            return Err(Error::Field);
        }
        let name = core::str::from_utf8(&row[16..16 + len]).map_err(|_| Error::Text)?;
        if !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
            || name.starts_with('.')
            || name.ends_with('.')
            || name.contains("..")
        {
            return Err(Error::Field);
        }
        if name <= previous {
            return Err(Error::Duplicate);
        }
        previous = name;
    }
    Ok(())
}
fn capability(code: u16) -> Capability {
    match code {
        1 => Capability::SelectedFileRead,
        2 => Capability::AppPrivateData,
        3 => Capability::OwnSurfacePresent,
        4 => Capability::FocusedInput,
        5 => Capability::Diagnostics,
        n => Capability::UnknownOptional(n),
    }
}
fn validate_capabilities(bytes: &[u8]) -> Result<()> {
    let mut previous = 0;
    for row in rows(bytes, 8)?.as_chunks::<8>().0 {
        let code = u16_at(row, 0)?;
        let flags = u16_at(row, 2)?;
        if code == 0 || code <= previous {
            return Err(Error::Duplicate);
        }
        previous = code;
        if flags > 1 || row[4..].iter().any(|b| *b != 0) {
            return Err(Error::Reserved);
        }
        if code > 5 && flags == 1 {
            return Err(Error::UnsupportedCapability(code));
        }
    }
    Ok(())
}
fn text(bytes: &[u8], max: usize) -> Result<&str> {
    if bytes.is_empty() || bytes.len() > max {
        return Err(Error::Text);
    }
    let s = core::str::from_utf8(bytes).map_err(|_| Error::Text)?;
    if s.chars()
        .any(|c| c.is_control() || matches!(c,'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}'))
    {
        return Err(Error::Text);
    }
    Ok(s)
}
fn path(bytes: &[u8]) -> Result<&str> {
    let s = text(bytes, 64)?;
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
        || s.starts_with('/')
        || s.ends_with('/')
        || s.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(Error::Path);
    }
    Ok(s)
}
fn elf(b: &[u8]) -> Result<()> {
    if b.len() < 64
        || &b[..4] != b"\x7fELF"
        || b[4..7] != [2, 1, 1]
        || u16_at(b, 16)? != 2
        || u16_at(b, 18)? != 62
        || u32_at(b, 20)? != 1
        || u16_at(b, 52)? != 64
        || u16_at(b, 54)? != 56
    {
        return Err(Error::Elf);
    }
    let count = usize::from(u16_at(b, 56)?);
    let offset = usize::try_from(u64_at(b, 32)?).map_err(|_| Error::Overflow)?;
    if !(1..=8).contains(&count)
        || offset < 64
        || offset
            .checked_add(count * 56)
            .is_none_or(|end| end > b.len())
    {
        return Err(Error::Elf);
    }
    Ok(())
}
fn nonzero(b: &[u8]) -> bool {
    b.iter().any(|n| *n != 0)
}
fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
fn array32(b: &[u8], offset: usize) -> Result<[u8; 32]> {
    b.get(offset..offset.checked_add(32).ok_or(Error::Overflow)?)
        .ok_or(Error::Bounds)?
        .try_into()
        .map_err(|_| Error::Bounds)
}
fn u16_at(b: &[u8], o: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(o..o.checked_add(2).ok_or(Error::Overflow)?)
            .ok_or(Error::Bounds)?
            .try_into()
            .map_err(|_| Error::Bounds)?,
    ))
}
fn u32_at(b: &[u8], o: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(o..o.checked_add(4).ok_or(Error::Overflow)?)
            .ok_or(Error::Bounds)?
            .try_into()
            .map_err(|_| Error::Bounds)?,
    ))
}
fn u64_at(b: &[u8], o: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(o..o.checked_add(8).ok_or(Error::Overflow)?)
            .ok_or(Error::Bounds)?
            .try_into()
            .map_err(|_| Error::Bounds)?,
    ))
}
fn to_usize(n: u32) -> Result<usize> {
    usize::try_from(n).map_err(|_| Error::Overflow)
}

#[cfg(any(test, feature = "std"))]
extern crate std;
#[cfg(any(test, feature = "std"))]
pub mod producer;
#[cfg(test)]
mod tests;
