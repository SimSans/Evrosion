//! Additive M8 dynamic2 control. Parsing supplies no mapping/admission authority.
//! V1/V4 headers and descriptor domains remain separate and unchanged.
pub const VERSION: u64 = 2;
pub const HEADER_BYTES: usize = 256;
pub const MAX_BYTES: u64 = 64 * 4096;
pub const OWNERS: usize = 2;
pub const DIRECTORY: usize = 1;
pub const REGION: u64 = 2 * 1024 * 1024;
pub const WINDOW_PAGES: usize = 64;
pub const READONLY_FIRST: [usize; OWNERS] = [1, 67];
pub const CONTROL: usize = 192;
pub const STAGING_FIRST: usize = 256;
pub const EXTERNAL_FRAMES: u64 = 2; // Actual PT + private control, separately charged.
pub const GUARDS: [usize; 9] = [0, 65, 66, 131, 191, 193, 255, 320, 511];
pub fn layout_record() -> [u8; 24] {
    let mut b = [0; 24];
    b[..8].copy_from_slice(b"EVDYNP02");
    for (i, n) in [
        DIRECTORY as u16,
        READONLY_FIRST[0] as u16,
        READONLY_FIRST[1] as u16,
        CONTROL as u16,
        STAGING_FIRST as u16,
        WINDOW_PAGES as u16,
        EXTERNAL_FRAMES as u16,
        crate::syscall::IMAGE_CONTROL as u16,
    ]
    .into_iter()
    .enumerate()
    {
        b[8 + i * 2..10 + i * 2].copy_from_slice(&n.to_le_bytes());
    }
    b
}
pub const DESCRIPTION: &[u8] = b"M8 dynamic2; IMAGE_CONTROL52 call4 actualRootCreatorJob,typedop,operand,extra; Initialize returns2; EVDYN002 exact256 header independent from V4 EVDYN001; fixedPD1 NX table/control192 and two64page package owners RO1..64/67..130 staging256..319 exactguards; twoexternalRootJobBootframes outsideRootprivateimage; selectedRootCPU4000000 frames4096 BootCPU8000000 frames8192; packageOwnerMax262144bytes not privateELFpage authority; wholepackage/ELFsha after actual writer removal and CR3TLB boundary; readonly readers retained until actual exit; physicaldetach before logical lease return; closed FileApp6 EditorImageSlot8 profile3 image384/private388/loader390 privatewindow512 stack480..487 guards479/488 startup509 entry511 ABI336 no extra display tables; immutable service.descriptor.m8.v5 domain binds RootV5ABI childABI slot13profilevalues exactlimits1000000/512/1/1 and6roles; no signedAppId policy in Kernel factory Root verifies package/signature/labels/persistence; PrepareProcess9 actualheldProcessCONTROL extra0 after exact6delegations allocates/readbacks private owner+typedbootstrap whileHeld and maps no sharedSurface/FileFrame; Start only after actual old stopped/reaped/finalCONTROLclose and exactsharedscrub; no V4cast oldfactorywidening scalarframe/quota or firstcaller authority; originalfinitecut no acceptedretry";

pub const DESCRIPTION_SHA256: [u8; 32] = [
    0xe4, 0xf4, 0xc2, 0x87, 0xd9, 0xe7, 0xb6, 0x7e, 0x8d, 0x9d, 0x15, 0xae, 0x20, 0xd9, 0x60, 0xe2,
    0xc5, 0x7e, 0x48, 0x96, 0xa0, 0x12, 0xe2, 0xcf, 0x22, 0x46, 0x83, 0x2b, 0xcc, 0xb3, 0xd8, 0x57,
];
/// Exact normalized Editor factory policy, independently mirrored by Kernel's
/// executable::m8::ServiceProfile::values. No scalar selects these envelopes.
pub const PROFILE_VALUES: [u64; 13] = [
    3,
    super::resources::max_image_pages(super::graph::ImageSlot::Editor),
    super::resources::max_private_pages(super::graph::ImageSlot::Editor),
    super::resources::max_loader_frames(super::graph::ImageSlot::Editor),
    512,
    480,
    8,
    479,
    488,
    509,
    511,
    super::child::startup_size(super::graph::Child::EditorOne) as u64,
    0,
];
/// Stream the distinct selected M8 descriptor for FileApp6. Package AppId and
/// signature policy remain Root obligations; this computes no release proof.
pub fn app_descriptor_transcript(elf_sha: &[u8; 32], mut output: impl FnMut(&[u8])) {
    output(b"evrosion.service.descriptor.m8.v5\0");
    output(elf_sha);
    output(&super::ABI);
    output(&crate::ABI);
    output(&(super::graph::ImageSlot::Editor.index() as u64).to_le_bytes());
    for value in PROFILE_VALUES {
        output(&value.to_le_bytes());
    }
    for value in super::graph::Child::EditorOne.limits() {
        output(&value.to_le_bytes());
    }
    output(&6u64.to_le_bytes());
    for (index, grant) in super::graph::grants(super::graph::Child::EditorOne).enumerate() {
        output(&(index as u64 + 1).to_le_bytes());
        output(&[grant.kind]);
        output(&grant.rights.to_le_bytes());
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Operation {
    Initialize = 0,
    Begin = 1,
    Written = 2,
    Seal = 3,
    Verify = 4,
    Register = 5,
    Abort = 6,
    Unregister = 7,
    Inspect = 8,
    PrepareProcess = 9,
}
impl Operation {
    pub const fn decode(n: u64) -> Option<Self> {
        Some(match n {
            0 => Self::Initialize,
            1 => Self::Begin,
            2 => Self::Written,
            3 => Self::Seal,
            4 => Self::Verify,
            5 => Self::Register,
            6 => Self::Abort,
            7 => Self::Unregister,
            8 => Self::Inspect,
            9 => Self::PrepareProcess,
            _ => return None,
        })
    }
    pub fn operands(self, operand: u64, extra: u64) -> bool {
        match self {
            Self::Initialize => operand == 0 && extra == 0,
            Self::PrepareProcess => operand > 0 && operand < u64::MAX && extra == 0,
            Self::Begin => operand > 0 && operand < u64::MAX && extra == 0,
            Self::Written => {
                (1..=2).contains(&operand)
                    && (extra >> 32) > 0
                    && (extra >> 32) <= 4096
                    && (extra as u32 as u64) < MAX_BYTES
            }
            Self::Inspect => {
                if operand == 0 {
                    extra <= 2
                } else {
                    (1..=2).contains(&operand) && extra <= 8
                }
            }
            _ => (1..=2).contains(&operand) && extra == 0,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub bytes: u64,
    pub elf_offset: u64,
    pub elf_bytes: u64,
    pub sha256: [u8; 32],
    pub elf_sha256: [u8; 32],
    pub package: [u8; 32],
    pub abi: [u8; 32],
    pub descriptor: [u8; 32],
}
impl Header {
    fn valid(&self) -> bool {
        self.bytes > 0
            && self.bytes <= MAX_BYTES
            && self.elf_bytes > 0
            && self
                .elf_offset
                .checked_add(self.elf_bytes)
                .is_some_and(|n| n <= self.bytes)
            && self.abi == crate::ABI
            && [self.sha256, self.elf_sha256, self.package, self.descriptor]
                .iter()
                .all(|n| *n != [0; 32])
    }
    pub fn encode(self) -> Option<[u8; HEADER_BYTES]> {
        if !self.valid() {
            return None;
        }
        let mut b = [0; HEADER_BYTES];
        b[..8].copy_from_slice(b"EVDYN002");
        b[8..10].copy_from_slice(&(VERSION as u16).to_le_bytes());
        b[10..12].copy_from_slice(&(HEADER_BYTES as u16).to_le_bytes());
        for (at, n) in [
            (16, self.bytes),
            (24, self.elf_offset),
            (32, self.elf_bytes),
        ] {
            b[at..at + 8].copy_from_slice(&n.to_le_bytes());
        }
        for (at, n) in [
            (40, self.sha256),
            (72, self.elf_sha256),
            (104, self.package),
            (136, self.abi),
            (168, self.descriptor),
        ] {
            b[at..at + 32].copy_from_slice(&n);
        }
        Some(b)
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != HEADER_BYTES
            || &b[..8] != b"EVDYN002"
            || b[8..10] != (VERSION as u16).to_le_bytes()
            || b[10..12] != (HEADER_BYTES as u16).to_le_bytes()
            || b[12..16].iter().chain(&b[200..]).any(|n| *n != 0)
        {
            return None;
        }
        let word = |at| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
        let row = Self {
            bytes: word(16),
            elf_offset: word(24),
            elf_bytes: word(32),
            sha256: b[40..72].try_into().unwrap(),
            elf_sha256: b[72..104].try_into().unwrap(),
            package: b[104..136].try_into().unwrap(),
            abi: b[136..168].try_into().unwrap(),
            descriptor: b[168..200].try_into().unwrap(),
        };
        row.valid().then_some(row)
    }
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    #[test]
    fn control_is_closed_canonical_and_binds_all_nonzero_identities() {
        let h = Header {
            bytes: MAX_BYTES,
            elf_offset: 64,
            elf_bytes: 8192,
            sha256: [1; 32],
            elf_sha256: [2; 32],
            package: [3; 32],
            abi: crate::ABI,
            descriptor: [4; 32],
        };
        let b = h.encode().unwrap();
        assert_eq!(Header::decode(&b), Some(h));
        for i in (0..16).chain(200..256) {
            let mut bad = b;
            bad[i] ^= 1;
            assert!(Header::decode(&bad).is_none());
        }
        for (at, len) in [(40, 32), (72, 32), (104, 32), (168, 32)] {
            let mut bad = b;
            bad[at..at + len].fill(0);
            assert!(Header::decode(&bad).is_none());
        }
        let mut bad = b;
        bad[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(Header::decode(&bad).is_none());
        let mut bad = b;
        bad[136] ^= 1;
        assert!(Header::decode(&bad).is_none());
        assert!(Header::decode(&b[..255]).is_none());
    }
    #[test]
    fn fixed_windows_and_guards_are_disjoint_without_low_private_page_reservation() {
        for page in 0..512 {
            let count = READONLY_FIRST
                .iter()
                .filter(|n| (**n..**n + WINDOW_PAGES).contains(&page))
                .count()
                + usize::from((STAGING_FIRST..STAGING_FIRST + WINDOW_PAGES).contains(&page))
                + usize::from(page == CONTROL);
            assert!(count <= 1);
            if GUARDS.contains(&page) {
                assert_eq!(count, 0);
            }
        }
        assert_eq!(Operation::decode(9), Some(Operation::PrepareProcess));
        assert!(Operation::decode(10).is_none());
        assert!(!Operation::PrepareProcess.operands(0, 0));
        assert!(!Operation::PrepareProcess.operands(u64::MAX, 0));
        assert!(!Operation::PrepareProcess.operands(1, 1));
        assert!(Operation::PrepareProcess.operands(1, 0));
        assert!(!Operation::Begin.operands(u64::MAX, 0));
        assert!(!Operation::Written.operands(1, 4097 << 32));
        assert!(!Operation::Written.operands(3, 1 << 32));
    }
    #[test]
    fn v4_headers_and_factory_descriptors_never_alias_dynamic2() {
        let old = crate::root_v4::dynamic::Header {
            bytes: MAX_BYTES,
            elf_offset: 64,
            elf_bytes: 8192,
            sha256: [1; 32],
            elf_sha256: [2; 32],
            package: [3; 32],
            abi: crate::ABI,
            descriptor: [4; 32],
        }
        .encode()
        .unwrap();
        assert!(Header::decode(&old).is_none());
        let new = Header {
            bytes: MAX_BYTES,
            elf_offset: 64,
            elf_bytes: 8192,
            sha256: [1; 32],
            elf_sha256: [2; 32],
            package: [3; 32],
            abi: crate::ABI,
            descriptor: [4; 32],
        }
        .encode()
        .unwrap();
        assert!(crate::root_v4::dynamic::Header::decode(&new).is_none());
        assert!(crate::root_v4::dynamic::Operation::decode(9).is_none());
        let mut before = std::vec::Vec::new();
        let mut after = std::vec::Vec::new();
        crate::root_v4::dynamic::app_descriptor_transcript(&[7; 32], |b| {
            before.extend_from_slice(b)
        });
        app_descriptor_transcript(&[7; 32], |b| after.extend_from_slice(b));
        assert_ne!(before, after);
        let mut expected = std::vec::Vec::new();
        expected.extend_from_slice(b"evrosion.service.descriptor.m8.v5\0");
        expected.extend_from_slice(&[7; 32]);
        expected.extend_from_slice(&super::super::ABI);
        expected.extend_from_slice(&crate::ABI);
        for n in [
            8u64, 3, 384, 388, 390, 512, 480, 8, 479, 488, 509, 511, 336, 0, 1_000_000, 512, 1, 1,
            6,
        ] {
            expected.extend_from_slice(&n.to_le_bytes());
        }
        for (i, (kind, rights)) in [(1u8, 7u16), (2, 8), (2, 8), (2, 272), (1, 7), (2, 272)]
            .into_iter()
            .enumerate()
        {
            expected.extend_from_slice(&(i as u64 + 1).to_le_bytes());
            expected.push(kind);
            expected.extend_from_slice(&rights.to_le_bytes());
        }
        assert_eq!(after, expected);
    }
}
