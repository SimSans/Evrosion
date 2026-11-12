//! Bounded source geometry and a device-only mapping plan. This plan is not a
//! PhysicalFrame, MemoryObject, public capability or loaded-executable receipt.
use crate::display_walk::{self as walk, PAGE, Snapshot, Tables, Translation};
use ev_boot_contract::{Framebuffer, MemoryKind, MemoryMap, PixelFormat};
use sha2::{Digest, Sha256};

pub use crate::executable::{
    DISPLAY_LOWER_GUARD as LOWER_GUARD, DISPLAY_MAXIMUM_BYTES as MAX_BYTES,
    DISPLAY_RELATIVE_START as RELATIVE_START, DISPLAY_TABLE_FRAMES as EXTRA_RAM_TABLE_FRAMES,
    DISPLAY_UPPER_GUARD as UPPER_GUARD,
};
pub const MAX_PAGES: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Geometry,
    Format,
    Span,
    Address,
    WritePermission,
    UsableRam,
    Changed,
    FrameBudget,
    Walk(walk::Error),
}
impl From<walk::Error> for Error {
    fn from(value: walk::Error) -> Self {
        Self::Walk(value)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    source_page: u64,
    offset: u16,
    pages: u16,
    bytes: u32,
    width: u32,
    height: u32,
    stride: u32,
    bgr: bool,
}
impl Geometry {
    pub fn checked(framebuffer: Framebuffer) -> Result<Self, Error> {
        framebuffer.validate().map_err(|_| Error::Geometry)?;
        if framebuffer.bytes_per_pixel != 4
            || !matches!(framebuffer.format, PixelFormat::Rgb | PixelFormat::Bgr)
        {
            return Err(Error::Format);
        }
        // Map only complete scanout rows, not an unexplained extra device BAR
        // tail. Page granularity can expose at most4095edge bytes to this one
        // privileged Display backend; applications never receive this object.
        let bytes = framebuffer
            .stride
            .checked_mul(framebuffer.height)
            .and_then(|n| n.checked_mul(4))
            .ok_or(Error::Span)? as u64;
        let offset = framebuffer.address & (PAGE - 1);
        let span = offset
            .checked_add(bytes)
            .and_then(|n| n.checked_add(PAGE - 1))
            .map(|n| n & !(PAGE - 1))
            .ok_or(Error::Span)?;
        if span == 0 || span > MAX_BYTES {
            return Err(Error::Span);
        }
        let source_page = framebuffer.address & !(PAGE - 1);
        let end = source_page.checked_add(span).ok_or(Error::Address)?;
        if !walk::canonical(source_page)
            || !walk::canonical(end - 1)
            || (source_page >> 47) != ((end - 1) >> 47)
        {
            return Err(Error::Address);
        }
        Ok(Self {
            source_page,
            offset: offset as u16,
            pages: (span / PAGE) as u16,
            bytes: bytes as u32,
            width: framebuffer.width as u32,
            height: framebuffer.height as u32,
            stride: framebuffer.stride as u32,
            bgr: framebuffer.format == PixelFormat::Bgr,
        })
    }
    pub const fn pages(self) -> usize {
        self.pages as usize
    }
    pub const fn byte_length(self) -> u32 {
        self.bytes
    }
    pub const fn byte_offset(self) -> u16 {
        self.offset
    }
    pub const fn width(self) -> u32 {
        self.width
    }
    pub const fn height(self) -> u32 {
        self.height
    }
    pub const fn stride(self) -> u32 {
        self.stride
    }
    pub const fn bgr(self) -> bool {
        self.bgr
    }
    pub fn source_page(self, index: usize) -> Result<u64, Error> {
        if index >= self.pages() {
            return Err(Error::Address);
        }
        self.source_page
            .checked_add(index as u64 * PAGE)
            .ok_or(Error::Address)
    }
    pub fn user_pointer(self, image_base: u64) -> Result<u64, Error> {
        user_base(image_base)?
            .checked_add(u64::from(self.offset))
            .ok_or(Error::Address)
    }
}
pub fn user_base(image_base: u64) -> Result<u64, Error> {
    if image_base == 0 || !image_base.is_multiple_of(1 << 39) || (image_base >> 39) >= 256 {
        return Err(Error::Address);
    }
    image_base.checked_add(RELATIVE_START).ok_or(Error::Address)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    geometry: Geometry,
    snapshot: Snapshot,
    fingerprint: [u8; 32],
}
impl Plan {
    /// Pure verification, not a hardware/capability factory. The runtime seals
    /// the observed source only after it supplies actual retained CPU/tables.
    pub fn checked(
        tables: &impl Tables,
        memory: &MemoryMap,
        geometry: Geometry,
        snapshot: Snapshot,
    ) -> Result<Self, Error> {
        let mut result = Self {
            geometry,
            snapshot,
            fingerprint: [0; 32],
        };
        result.fingerprint = result.walk(tables, Some(memory), |_, _| Ok(()))?;
        Ok(result)
    }
    pub const fn geometry(self) -> Geometry {
        self.geometry
    }
    pub const fn snapshot(self) -> Snapshot {
        self.snapshot
    }
    pub const fn fingerprint(self) -> [u8; 32] {
        self.fingerprint
    }
    fn walk(
        &self,
        tables: &impl Tables,
        memory: Option<&MemoryMap>,
        mut use_page: impl FnMut(usize, Translation) -> Result<(), Error>,
    ) -> Result<[u8; 32], Error> {
        let mut digest = Sha256::new();
        digest.update(b"evrosion.display.source.v1\0");
        digest.update(self.snapshot.root().to_le_bytes());
        digest.update(self.snapshot.pat().to_le_bytes());
        for index in 0..self.geometry.pages() {
            let page = walk::translate(tables, self.snapshot, self.geometry.source_page(index)?)?;
            page.user_rw_nx_entry()
                .map_err(|_| Error::WritePermission)?;
            let end = page.physical.checked_add(PAGE).ok_or(Error::Address)?;
            if memory.is_some_and(|memory| {
                memory.regions().iter().any(|region| {
                    region.kind == MemoryKind::Usable
                        && page.physical < region.end
                        && end > region.start
                })
            }) {
                return Err(Error::UsableRam);
            }
            digest.update(page.physical.to_le_bytes());
            digest.update([page.cache.index()]);
            use_page(index, page)?;
        }
        Ok(digest.finalize().into())
    }
    pub fn verify_unchanged(&self, tables: &impl Tables) -> Result<(), Error> {
        if self.walk(tables, None, |_, _| Ok(()))? != self.fingerprint {
            return Err(Error::Changed);
        }
        Ok(())
    }
    /// Only an inactive hardware owner may use these values to fill its two
    /// owned PTs. Do not publish the PD entries until verify_unchanged succeeds
    /// AFTER filling; a rejected source leaves that root inaccessible.
    pub fn entries(
        &self,
        tables: &impl Tables,
        mut use_entry: impl FnMut(usize, u64) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let actual = self.walk(tables, None, |index, page| {
            use_entry(index, page.user_rw_nx_entry()?)
        })?;
        if actual != self.fingerprint {
            return Err(Error::Changed);
        }
        Ok(())
    }
}
