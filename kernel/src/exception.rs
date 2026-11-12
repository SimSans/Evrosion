//! Portable x86-64 descriptor encoding and exact bootstrap fault matching.
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct Gate {
    low: u16,
    selector: u16,
    ist: u8,
    attributes: u8,
    middle: u16,
    high: u32,
    reserved: u32,
}

impl Gate {
    pub const MISSING: Self = Self {
        low: 0,
        selector: 0,
        ist: 0,
        attributes: 0,
        middle: 0,
        high: 0,
        reserved: 0,
    };

    /// The one explicitly selected syscall vector may be invoked from CPL3.
    pub fn user_call(handler: u64, selector: u16) -> Option<Self> {
        let mut gate = Self::interrupt(handler, selector, 0)?;
        gate.attributes = 0xee;
        Some(gate)
    }

    pub fn interrupt(handler: u64, selector: u16, ist: u8) -> Option<Self> {
        if handler == 0
            || (((handler << 16) as i64 >> 16) as u64) != handler
            || selector == 0
            || selector & 7 != 0
            || ist > 7
        {
            return None;
        }
        Some(Self {
            low: handler as u16,
            selector,
            ist,
            attributes: 0x8e,
            middle: (handler >> 16) as u16,
            high: (handler >> 32) as u32,
            reserved: 0,
        })
    }
}

pub fn tss_descriptor(base: u64) -> [u64; 2] {
    // 104-byte 64-bit TSS, available type, present, DPL 0, byte granularity.
    [
        103 | ((base & 0xffff) << 16)
            | (((base >> 16) & 0xff) << 32)
            | (0x89 << 40)
            | (((base >> 24) & 0xff) << 56),
        base >> 32,
    ]
}

#[derive(Clone, Copy)]
pub struct Recovery {
    pub instruction: u64,
    pub resume: u64,
    pub address: u64,
    pub error: u64,
}

impl Recovery {
    pub fn matches(&self, vector: u64, error: u64, ip: u64, cs: u64, address: u64) -> bool {
        vector == 14
            && cs & 3 == 0
            && error == self.error
            && ip == self.instruction
            && address == self.address
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gates_encode_canonical_target_without_granting_user_interrupt_access() {
        assert_eq!(core::mem::size_of::<Gate>(), 16);
        let address = 0xffff_ffff_8000_1234;
        let gate = Gate::interrupt(address, 8, 2).unwrap();
        let decoded =
            u64::from(gate.low) | (u64::from(gate.middle) << 16) | (u64::from(gate.high) << 32);
        assert_eq!(decoded, address);
        assert_eq!(gate.attributes, 0x8e);
        assert_eq!(gate.ist, 2);
        let syscall = Gate::user_call(address, 8).unwrap();
        assert_eq!(syscall.attributes, 0xee);
        assert_eq!(syscall.ist, 0);
        for (target, selector, ist) in [
            (0, 8, 0),
            (0x800000000000, 8, 0),
            (address, 0, 0),
            (address, 11, 0),
            (address, 12, 0),
            (address, 8, 8),
        ] {
            assert!(Gate::interrupt(target, selector, ist).is_none());
        }
    }

    #[test]
    fn tss_descriptor_has_exact_size_type_and_full_base() {
        let base = 0xffff_ffff_8123_4560;
        let [low, high] = tss_descriptor(base);
        let decoded = ((low >> 16) & 0xffff)
            | (((low >> 32) & 0xff) << 16)
            | (((low >> 56) & 0xff) << 24)
            | (high << 32);
        assert_eq!(decoded, base);
        assert_eq!(low & 0xffff, 103);
        assert_eq!((low >> 40) & 0xff, 0x89);
        assert_eq!((low >> 48) & 0xff, 0);
        assert_eq!(high >> 32, 0);
    }

    #[test]
    fn recovery_matches_every_fault_field_and_never_recovers_a_user_fault() {
        let probe = Recovery {
            instruction: 0x1234,
            resume: 0x1236,
            address: 0xabcd000,
            error: 3,
        };
        assert!(probe.matches(14, 3, 0x1234, 8, 0xabcd000));
        for args in [
            (13, 3, 0x1234, 8, 0xabcd000),
            (14, 1, 0x1234, 8, 0xabcd000),
            (14, 3, 0x1235, 8, 0xabcd000),
            (14, 3, 0x1234, 11, 0xabcd000),
            (14, 3, 0x1234, 8, 0xabcd001),
        ] {
            assert!(!probe.matches(args.0, args.1, args.2, args.3, args.4));
        }
    }
}
