//! Private adapter for the reviewed developer VM launch profile.
//!
//! This is not generic physical-CPU RDRAND qualification. The trusted launcher
//! must first verify the reviewed QEMU executable and its fixed TCG arguments,
//! with user configuration, deterministic seed and replay modes excluded.
//! CPUID and catalogue digests below check the expected execution profile; they
//! cannot authenticate a hostile host or prove its launch arguments themselves.
use core::arch::{asm, x86_64::__cpuid};
use ev_random::{Generator, Receipt, seed::acquire_after_qualification};
use ev_time_contract::Domain;
use ev_userspace_contract::root_v4::catalogue::DeviceWitness;

// The exact binary whose package, Linux crypto backend and TCG RDRAND helper
// were reviewed. Changes require new source/binary qualification, not a label.
const REVIEWED_QEMU: [u8; 32] = [
    0x0c, 0xd4, 0x11, 0x2a, 0x8f, 0x0c, 0xb8, 0x91, 0xeb, 0x7c, 0x10, 0xe8, 0xdf, 0x38, 0xc9, 0xdf,
    0xee, 0xc8, 0xc7, 0x38, 0x9b, 0xb2, 0x2d, 0xb6, 0xaa, 0x42, 0x5f, 0x0d, 0x6f, 0xe7, 0x33, 0xdc,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Profile,
    Unsupported,
    Unavailable,
    GenerationExhausted,
    Generator(ev_random::Error),
}

/// No saved readiness, raw-word service, clone or deterministic fallback.
/// The caller retains this private owner for the actual Root incarnation.
pub(super) struct Random {
    domain: Domain,
    generator: Generator,
    generation: u64,
}
impl Random {
    pub(super) fn unavailable(domain: Domain) -> Self {
        Self {
            domain,
            generator: Generator::unavailable(domain),
            generation: 0,
        }
    }

    /// Only the actual trusted fixed-profile Root calls this at startup or
    /// before publishing its one owner-armed time challenge, after the launch
    /// qualification above. A downloaded witness cannot nominate a new trusted
    /// source. Failure immediately fences previous stream eligibility.
    pub(super) fn reseed_after_reviewed_vm_launch(
        &mut self,
        device: DeviceWitness,
        mut monotonic: impl FnMut() -> u64,
    ) -> Result<(), Error> {
        self.generator.source_failed();
        if device.emulator_binary_sha256 != REVIEWED_QEMU {
            return Err(Error::Profile);
        }
        if !supported_tcg() {
            return Err(Error::Unsupported);
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(Error::GenerationExhausted)?;
        let mut seed = [0; 32];
        // supported_tcg checked the instruction feature before this closure
        // can execute. Each failure flag consumes a finite acquisition attempt.
        acquire_after_qualification(rdrand_word, &mut seed).map_err(|_| Error::Unavailable)?;
        self.generator
            .reseed_after_authorized_source(self.domain.at(monotonic()), generation, &mut seed)
            .map_err(Error::Generator)?;
        self.generation = generation;
        Ok(())
    }

    pub(super) fn fill(&mut self, tick: u64, output: &mut [u8]) -> Result<Receipt, Error> {
        self.generator
            .fill(self.domain.at(tick), output)
            .map_err(Error::Generator)
    }

    pub(super) fn source_failed(&mut self) {
        self.generator.source_failed();
    }
}

fn supported_tcg() -> bool {
    // CPUID is a safe intrinsic in the pinned toolchain. It is available in
    // the admitted x86-64 ISA and has no memory or capability operands.
    let basic = __cpuid(0);
    if basic.eax < 1 {
        return false;
    }
    let features = __cpuid(1);
    if features.ecx & ((1 << 30) | (1 << 31)) != ((1 << 30) | (1 << 31)) {
        return false;
    }
    // An absent hypervisor leaf returns an unaccepted profile; it cannot enable
    // RDRAND instruction execution.
    let hypervisor = __cpuid(0x4000_0000);
    hypervisor.eax == 0x4000_0001
        && hypervisor.ebx.to_le_bytes() == *b"TCGT"
        && hypervisor.ecx.to_le_bytes() == *b"CGTC"
        && hypervisor.edx.to_le_bytes() == *b"GTCG"
}

fn rdrand_word() -> Option<u64> {
    let word: u64;
    let success: u8;
    // SAFETY: private adapter calls only after the actual RDRAND feature check
    // in supported_tcg. No memory operand, pointer or capability is involved.
    // Distinct output registers preserve the word while capturing actual CF.
    unsafe {
        asm!("rdrand {word}", "setc {success}",
            word = out(reg) word, success = out(reg_byte) success,
            options(nomem, nostack));
    }
    (success != 0).then_some(word)
}
