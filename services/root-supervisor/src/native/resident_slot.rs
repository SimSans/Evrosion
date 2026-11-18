//! Private fixed storage with one typed initialization claim. The backing is
//! bytes, never a fabricated static borrow of the value stored inside it.
//! There is no reset, read, automatic Drop or second mutable-reference API.
use core::{
    cell::UnsafeCell,
    marker::PhantomData,
    mem::{MaybeUninit, align_of, size_of},
    sync::atomic::{AtomicBool, Ordering},
};

/// Write one complete struct directly into its claimed, uninitialized storage.
/// The same field list drives an exhaustive compile-time pattern: adding a
/// field cannot silently leave new Controller bytes uninitialized.
///
/// Caller must hold the sole valid/aligned claim and use this inside its
/// documented unsafe initialization boundary, before constructing a reference.
#[macro_export]
macro_rules! resident_initialize_fields {
    ($pointer:expr, $ty:path; $($(#[$attribute:meta])* $field:ident: $value:expr),* $(,)?) => {{
        let _: fn($ty) = |$ty { $($(#[$attribute])* $field: _,)* }| {};
        let pointer = $pointer;
        $( $(#[$attribute])* core::ptr::addr_of_mut!((*pointer).$field).write($value);)*
    }};
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Layout,
    Claimed,
}

pub struct Slot<const WORDS: usize> {
    bytes: UnsafeCell<MaybeUninit<[u128; WORDS]>>,
    claimed: AtomicBool,
}
// SAFETY: typed data is never accessed through shared Slot references. The
// atomic gate admits only one Claim, permanently; that claim alone may expose
// the bytes, and its unsafe finalization requires actual initialized/exclusive
// T ownership. T's references retain the claim's chosen scoped lifetime.
unsafe impl<const WORDS: usize> Sync for Slot<WORDS> {}
impl<const WORDS: usize> Default for Slot<WORDS> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const WORDS: usize> Slot<WORDS> {
    pub const fn new() -> Self {
        Self {
            bytes: UnsafeCell::new(MaybeUninit::uninit()),
            claimed: AtomicBool::new(false),
        }
    }
    pub fn claim<'a, T: 'a>(&'a self) -> Result<Claim<'a, T, WORDS>, Error> {
        if size_of::<T>() == 0
            || size_of::<T>() > size_of::<[u128; WORDS]>()
            || align_of::<T>() > align_of::<[u128; WORDS]>()
        {
            return Err(Error::Layout);
        }
        self.claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::Claimed)?;
        Ok(Claim {
            slot: self,
            scope: PhantomData,
        })
    }
}
pub struct Claim<'a, T, const WORDS: usize> {
    slot: &'a Slot<WORDS>,
    scope: PhantomData<&'a mut T>,
}
impl<'a, T, const WORDS: usize> Claim<'a, T, WORDS> {
    pub fn pointer(&mut self) -> *mut T {
        self.slot.bytes.get().cast()
    }
    /// # Safety
    /// Every field of T has been fully initialized at pointer(), all contained
    /// references are valid for 'a, and no raw alias may be used afterward.
    /// Caller retains sole value ownership for that lifetime. Slot never reads
    /// or drops those bytes afterward; actual process retirement owns erasure.
    pub unsafe fn initialized(self) -> &'a mut T {
        // SAFETY: caller establishes validity/exclusivity; claim checked exact
        // extent/alignment and permanently excluded all other typed claims.
        unsafe { &mut *self.slot.bytes.get().cast::<T>() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    #[test]
    fn in_place_nonzero_and_actual_local_borrow_never_require_static_or_zero_validity() {
        struct Value<'a> {
            number: NonZeroU64,
            local: &'a mut u64,
        }
        let slot = Slot::<2>::new();
        let mut local = 7;
        let mut claim = slot.claim::<Value<'_>>().unwrap();
        let p = claim.pointer();
        // SAFETY: both distinct fields belong to this one checked claim, before
        // any reference exists. Local outlives the completed scoped borrow.
        unsafe {
            core::ptr::addr_of_mut!((*p).number).write(NonZeroU64::new(9).unwrap());
            core::ptr::addr_of_mut!((*p).local).write(&mut local);
        }
        // SAFETY: all fields initialized with valid values/references; no raw
        // pointer is used after this sole-reference handoff.
        let value = unsafe { claim.initialized() };
        assert_eq!(value.number.get(), 9);
        *value.local = 11;
        assert!(matches!(slot.claim::<u64>(), Err(Error::Claimed)));
        assert_eq!(local, 11);
    }
    #[test]
    fn oversized_overaligned_and_zero_types_refuse_before_consuming_claim() {
        #[repr(align(32))]
        struct Aligned(u8);
        let slot = Slot::<1>::new();
        assert!(matches!(slot.claim::<[u128; 2]>(), Err(Error::Layout)));
        assert!(matches!(slot.claim::<Aligned>(), Err(Error::Layout)));
        // Here the extent is sufficient; alignment independently refuses.
        let wide = Slot::<2>::new();
        assert!(matches!(wide.claim::<Aligned>(), Err(Error::Layout)));
        assert!(wide.claim::<[u128; 2]>().is_ok());
        assert!(matches!(slot.claim::<()>(), Err(Error::Layout)));
        let mut claim = slot.claim::<u128>().unwrap();
        // SAFETY: exact16-byte allocation, valid u128, exclusive claim.
        unsafe {
            claim.pointer().write(u128::MAX);
        }
        // SAFETY: initialized above; no retained raw alias is used afterward.
        assert_eq!(*unsafe { claim.initialized() }, u128::MAX);
        let aligned = Aligned(1);
        assert_eq!(aligned.0, 1);
    }
    #[test]
    fn abandoned_partial_initialization_never_resets_or_exposes_another_claim() {
        let slot = Slot::<2>::new();
        {
            let mut claim = slot.claim::<[u64; 2]>().unwrap();
            // SAFETY: write only the first initialized word; no complete array is
            // read/finalized, and abandoning this claim never runs T's destructor.
            unsafe {
                claim.pointer().cast::<u64>().write(42);
            }
        }
        assert!(matches!(slot.claim::<[u64; 2]>(), Err(Error::Claimed)));
    }
    #[test]
    fn racing_claims_have_exactly_one_winner_without_reading_uninitialized_bytes() {
        let slot = Slot::<1>::new();
        let winners = core::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..16 {
                scope.spawn(|| {
                    if slot.claim::<u64>().is_ok() {
                        winners.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });
        assert_eq!(winners.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn exact_initializer_macro_compiler_rejects_any_omitted_field() {
        use std::{
            fs,
            process::Command,
            time::{SystemTime, UNIX_EPOCH},
        };
        let source = fs::canonicalize(file!()).unwrap();
        let temp = std::env::temp_dir().join(format!(
            "evrosion-resident-fields-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&temp).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(temp.clone());
        for (name, fields, accepted) in [
            ("complete", "a: 1, b: 2", true),
            ("missing", "a: 1", false),
            (
                "conditional",
                "a: 1, #[cfg(all())] b: 2, #[cfg(any())] absent: 99",
                true,
            ),
            ("hidden_missing", "a: 1, #[cfg(any())] b: 2", false),
        ] {
            let input = temp.join(format!("{name}.rs"));
            fs::write(&input, format!("#[path={source:?}] mod slot;\nstruct Value {{ a:u64,b:u64 }}\nfn main() {{ let mut value=core::mem::MaybeUninit::<Value>::uninit(); unsafe {{ resident_initialize_fields!(value.as_mut_ptr(), Value; {fields}); }} }}\n")).unwrap();
            let output = Command::new("rustc")
                .args(["--edition", "2024"])
                .arg(&input)
                .arg("-o")
                .arg(temp.join(name))
                .output()
                .unwrap();
            assert_eq!(output.status.success(), accepted);
            if !accepted {
                let message = String::from_utf8_lossy(&output.stderr);
                // An exported macro may report inaccessible omitted fields
                // instead of E0027; both require the missing exhaustive field.
                assert!(
                    message.contains("E0027")
                        || message.contains("pattern requires `..` due to inaccessible fields"),
                    "{message}"
                );
            }
        }
    }
}
