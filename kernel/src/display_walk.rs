//! Safe four-level translation of a loader virtual address. Source entries are
//! observed through a reader; only the hardware bridge may assert provenance.
pub const PAGE: u64 = 4096;
pub const PRESENT: u64 = 1;
pub const WRITABLE: u64 = 2;
pub const USER: u64 = 4;
pub const PWT: u64 = 8;
pub const PCD: u64 = 16;
pub const HUGE_OR_PAT4K: u64 = 128;
pub const PAT_HUGE: u64 = 4096;
pub const NX: u64 = 1 << 63;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
const ALLOWED: u64 = ADDRESS | 0xfff | NX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Address,
    PhysicalWidth,
    Cr3,
    PagingMode,
    NxDisabled,
    Pat,
    Missing,
    Reserved,
    Read,
    ReadOnly,
}
pub trait Tables {
    fn entry(&self, physical_table: u64, index: usize) -> Result<u64, Error>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    root: u64,
    physical_bits: u8,
    pat: u64,
    one_gib: bool,
}
impl Snapshot {
    /// Actual runtime inputs must come from the retained CPU/root, never from a
    /// service request. Pure tests may use model snapshots without authority.
    pub fn checked(
        cr3: u64,
        cr4: u64,
        efer: u64,
        physical_bits: u8,
        pat: u64,
        one_gib: bool,
    ) -> Result<Self, Error> {
        if !(32..=52).contains(&physical_bits) {
            return Err(Error::PhysicalWidth);
        }
        if cr4 & ((1 << 12) | (1 << 17)) != 0 {
            return Err(Error::PagingMode);
        }
        if efer & (1 << 11) == 0 {
            return Err(Error::NxDisabled);
        }
        if cr3 & !(ADDRESS | PWT | PCD) != 0 {
            return Err(Error::Cr3);
        }
        let root = cr3 & ADDRESS;
        if root == 0 || root >= 1u64 << physical_bits {
            return Err(Error::Cr3);
        }
        for i in 0..8 {
            if !matches!((pat >> (8 * i)) & 255, 0 | 1 | 4 | 5 | 6 | 7) {
                return Err(Error::Pat);
            }
        }
        Ok(Self {
            root,
            physical_bits,
            pat,
            one_gib,
        })
    }
    pub const fn root(self) -> u64 {
        self.root
    }
    pub const fn physical_bits(self) -> u8 {
        self.physical_bits
    }
    pub const fn pat(self) -> u64 {
        self.pat
    }
    fn address(self, entry: u64) -> Result<u64, Error> {
        if entry & !ALLOWED != 0 || entry & ADDRESS >= 1u64 << self.physical_bits {
            return Err(Error::Reserved);
        }
        Ok(entry & ADDRESS)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cache {
    index: u8,
    memory_type: u8,
}
impl Cache {
    pub const fn index(self) -> u8 {
        self.index
    }
    pub const fn pat_memory_type(self) -> u8 {
        self.memory_type
    }
    /// Convert the *leaf* PAT index to the 4KiB PTE position. Ancestor PCD/PWT
    /// select caching for page-table reads, not framebuffer memory caching.
    pub const fn user_4k_bits(self) -> u64 {
        ((self.index as u64 & 1) << 3)
            | ((self.index as u64 & 2) << 3)
            | ((self.index as u64 & 4) << 5)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Translation {
    pub physical: u64,
    pub source_page_bytes: u64,
    pub cache: Cache,
    pub writable: bool,
    pub executable: bool,
}
impl Translation {
    pub fn user_rw_nx_entry(self) -> Result<u64, Error> {
        if !self.physical.is_multiple_of(PAGE) {
            return Err(Error::Address);
        }
        if !self.writable {
            return Err(Error::ReadOnly);
        }
        // No inherited GLOBAL, protection key, accessed/dirty or huge-page bit.
        Ok(self.physical | PRESENT | WRITABLE | USER | NX | self.cache.user_4k_bits())
    }
}
pub fn canonical(address: u64) -> bool {
    (((address << 16) as i64 >> 16) as u64) == address
}
pub fn translate(
    tables: &impl Tables,
    snapshot: Snapshot,
    address: u64,
) -> Result<Translation, Error> {
    if !canonical(address) {
        return Err(Error::Address);
    }
    let mut table = snapshot.root;
    let mut writable = true;
    let mut executable = true;
    for (level, shift) in [39, 30, 21, 12].into_iter().enumerate() {
        let entry = tables.entry(table, ((address >> shift) & 511) as usize)?;
        if entry & PRESENT == 0 {
            return Err(Error::Missing);
        }
        let raw = snapshot.address(entry)?;
        writable &= entry & WRITABLE != 0;
        executable &= entry & NX == 0;
        let huge = entry & HUGE_OR_PAT4K != 0 && level < 3;
        if level == 0 && huge {
            return Err(Error::Reserved);
        }
        if level == 1 && huge && !snapshot.one_gib {
            return Err(Error::PagingMode);
        }
        if huge || level == 3 {
            let bytes = if huge { 1u64 << shift } else { PAGE };
            // In a huge leaf bit12 is PAT, while other address bits below its
            // alignment are reserved. At4KiB PAT is bit7 outside ADDRESS.
            if huge && raw & ((bytes - 1) & !PAT_HUGE) != 0 {
                return Err(Error::Reserved);
            }
            let physical = (raw & !(bytes - 1)) | (address & (bytes - 1));
            let pat = if huge {
                entry & PAT_HUGE != 0
            } else {
                entry & HUGE_OR_PAT4K != 0
            };
            let index = u8::from(entry & PWT != 0)
                | (u8::from(entry & PCD != 0) << 1)
                | (u8::from(pat) << 2);
            let memory_type = ((snapshot.pat >> (8 * index)) & 255) as u8;
            return Ok(Translation {
                physical,
                source_page_bytes: bytes,
                cache: Cache { index, memory_type },
                writable,
                executable,
            });
        }
        if raw == 0 {
            return Err(Error::Reserved);
        }
        table = raw;
    }
    Err(Error::Missing)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::collections::BTreeMap;
    struct Model(BTreeMap<(u64, usize), u64>);
    impl Tables for Model {
        fn entry(&self, t: u64, i: usize) -> Result<u64, Error> {
            Ok(*self.0.get(&(t, i)).unwrap_or(&0))
        }
    }
    fn config() -> Snapshot {
        Snapshot::checked(0x1000, 0, 1 << 11, 48, 0x0007_0406_0007_0406, true).unwrap()
    }
    fn map(address: u64, leaf: u64, level: usize) -> Model {
        let mut m = Model(BTreeMap::new());
        let tables = [0x1000, 0x2000, 0x3000, 0x4000];
        for (i, shift) in [39, 30, 21, 12].into_iter().enumerate().take(level + 1) {
            m.0.insert(
                (tables[i], ((address >> shift) & 511) as usize),
                if i == level {
                    leaf
                } else {
                    tables[i + 1] | PRESENT | WRITABLE
                },
            );
        }
        m
    }
    #[test]
    fn source_kva_is_walked_and_leaf_cache_survives_4k_translation() {
        let kva = 0xffff_9000_1234_5000;
        let m = map(kva, 0xe123_4000 | PRESENT | WRITABLE | PCD | PWT | NX, 3);
        let p = translate(&m, config(), kva).unwrap();
        assert_eq!(p.physical, 0xe123_4000);
        assert_ne!(p.physical, kva);
        assert_eq!(p.cache.index(), 3);
        assert_eq!(p.cache.pat_memory_type(), 0);
        assert_eq!(
            p.user_rw_nx_entry().unwrap(),
            0xe123_4000 | PRESENT | WRITABLE | USER | NX | PCD | PWT
        );
    }
    #[test]
    fn all_pat_indices_are_normalized_from_2m_and_1g_huge_leaves() {
        for level in [1, 2, 3] {
            for index in 0u8..8 {
                let kva = 0xffff_9000_1234_5000;
                let shift = [39, 30, 21, 12][level];
                let base = 0xc000_0000;
                let flags = PRESENT
                    | WRITABLE
                    | ((index as u64 & 1) << 3)
                    | ((index as u64 & 2) << 3)
                    | if level == 3 {
                        if index & 4 != 0 { HUGE_OR_PAT4K } else { 0 }
                    } else {
                        HUGE_OR_PAT4K | if index & 4 != 0 { PAT_HUGE } else { 0 }
                    };
                let p = translate(&map(kva, base | flags, level), config(), kva).unwrap();
                assert_eq!(p.physical, base | (kva & ((1u64 << shift) - 1)));
                assert_eq!(p.cache.index(), index);
                let user = p.user_rw_nx_entry().unwrap();
                assert_eq!((user >> 7) & 1, u64::from(index & 4 != 0));
            }
        }
    }
    #[test]
    fn ancestor_permissions_are_effective_but_ancestor_cache_is_not_leaf_cache() {
        let kva = 0xffff_9000_1234_5000;
        let mut m = map(kva, 0xe000_0000 | PRESENT | WRITABLE, 3);
        let parent =
            m.0.get_mut(&(0x1000, ((kva >> 39) & 511) as usize))
                .unwrap();
        *parent = (*parent & !WRITABLE) | PCD | PWT | NX;
        let p = translate(&m, config(), kva).unwrap();
        assert_eq!(p.cache.index(), 0);
        assert!(!p.writable);
        assert!(!p.executable);
        assert_eq!(p.user_rw_nx_entry(), Err(Error::ReadOnly));
    }
    #[test]
    fn malformed_modes_reserved_bits_missing_leaves_and_physical_width_reject() {
        assert_eq!(
            Snapshot::checked(0x1000, 1 << 12, 1 << 11, 48, 0, true),
            Err(Error::PagingMode)
        );
        assert_eq!(
            Snapshot::checked(0x1000, 1 << 17, 1 << 11, 48, 0, true),
            Err(Error::PagingMode)
        );
        assert_eq!(
            Snapshot::checked(0x1001, 0, 1 << 11, 48, 0, true),
            Err(Error::Cr3)
        );
        assert_eq!(
            Snapshot::checked(0x1000, 0, 0, 48, 0, true),
            Err(Error::NxDisabled)
        );
        assert_eq!(
            Snapshot::checked(0x1000, 0, 1 << 11, 48, 2, true),
            Err(Error::Pat)
        );
        let kva = 0xffff_9000_1234_5000;
        let no_gib =
            Snapshot::checked(0x1000, 0, 1 << 11, 48, 0x0007_0406_0007_0406, false).unwrap();
        assert_eq!(
            translate(
                &map(kva, 0xc000_0000 | PRESENT | WRITABLE | HUGE_OR_PAT4K, 1),
                no_gib,
                kva
            ),
            Err(Error::PagingMode)
        );
        for (leaf, level) in [
            (0xe000_0000 | PRESENT | WRITABLE | (1 << 59), 3),
            (0xe000_2000 | PRESENT | WRITABLE | HUGE_OR_PAT4K, 2),
            (0xe000_0000 | PRESENT | HUGE_OR_PAT4K, 0),
            (0xe000_0000 | WRITABLE, 3),
            ((1 << 49) | PRESENT | WRITABLE, 3),
        ] {
            assert!(translate(&map(kva, leaf, level), config(), kva).is_err());
        }
        assert_eq!(
            translate(&map(kva, 0, 3), config(), 0x0000_8000_0000_0000),
            Err(Error::Address)
        );
    }
}
