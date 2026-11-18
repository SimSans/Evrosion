//! Internal V4 fixed dynamic-image control. Metadata is not release authority.
pub const VERSION: u64 = 1;
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
    b[..8].copy_from_slice(b"EVDYNP01");
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
pub const DESCRIPTION: &[u8] = b"V4 dynamic1; IMAGE_CONTROL52 call4 CreatorJob,typedop,operand,extra; status/value/actualMemoryCapOrZero/zero; errorsreasonInValue cap0serial0; InitializeversionScalar BeginSlotWriterCap SealhashRemainingcap0 VerifyremainingOrCompletedROcap Registerscalar0;; no userpointer/newgrant/object; captured actualRoot only; PD1 fixed NX table +private control192 RW/NX =2externalRootJobBootframes outsideinitialLoadedImage246; ROslots1..64,67..130; staging256..319; guards0,65,66,131,191,193,255,320,511 otherszero; two64page physicalcontiguous owners chargedRootJob512 Boot1024; wholepackage+ELFhash afterallwritersremoved andactualCR3TLBboundary; RootROreaders retaineduntilexit; physicaldetachbeforelogicalleasereturn; closedApp7descriptor sameRegistry16; ordinary2MiBELF/legacyunchanged; originalfinitecut noacceptedretry";

pub const DESCRIPTION_SHA256: [u8; 32] = [
    0x3b, 0x3e, 0x11, 0x24, 0xc5, 0x8b, 0x2e, 0x16, 0x2a, 0xf8, 0xca, 0x16, 0xd2, 0x79, 0x51, 0x01,
    0x56, 0x3d, 0x8c, 0x30, 0xdc, 0xb0, 0x29, 0x7e, 0xd2, 0xe7, 0xfd, 0xf4, 0x06, 0x80, 0x7e, 0x91,
];
/// Stream the already-defined v1 descriptor request for the closed App7
/// template. No hash dependency, signature/admission authority or ELF parsing.
/// Core independently validates actual immutable bytes and computes policy.
pub fn app_descriptor_transcript(elf_sha: &[u8; 32], mut output: impl FnMut(&[u8])) {
    output(b"evrosion.service.descriptor.v1\0");
    output(elf_sha);
    output(&crate::ABI);
    for limit in super::graph::Child::App.limits() {
        output(&limit.to_le_bytes());
    }
    output(&7u64.to_le_bytes());
    for (i, grant) in super::graph::grants(super::graph::Child::App).enumerate() {
        output(&(i as u64 + 1).to_le_bytes());
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
            _ => return None,
        })
    }
    pub fn operands(self, operand: u64, extra: u64) -> bool {
        match self {
            Self::Initialize => operand == 0 && extra == 0,
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
        b[..8].copy_from_slice(b"EVDYN001");
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
            || &b[..8] != b"EVDYN001"
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
        assert!(Operation::decode(9).is_none());
        assert!(!Operation::Begin.operands(u64::MAX, 0));
        assert!(!Operation::Written.operands(1, 4097 << 32));
        assert!(!Operation::Written.operands(3, 1 << 32));
    }
}
