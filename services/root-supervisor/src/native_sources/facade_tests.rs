use super::*;
use crate::native_sources::tests::{fixture, sealed_images, sealed_packages};
use ev_app_registry::Packages as _;

#[test]
fn absent_snapshot_is_exact_bank_resolution_even_when_unbound_sealed_bytes_exist() {
    let (cat, context, a, b) = fixture();
    let banks = Packages::verify_network(&cat, context, &a, &b).unwrap();
    let images = sealed_images(false);
    let snapshot = crate::native_acquisition::tests::retained_snapshot(false);
    let candidate = snapshot.candidate().unwrap();
    let resolver = Resolver::new(&banks, &images, None, [None, None]).unwrap();
    for slot in [Slot::A, Slot::B] {
        let digest = banks.digest(slot);
        assert_eq!(resolver.source(digest), Some(Source::Bank(slot)));
        assert_eq!(resolver.resolve(digest), Some(banks.bytes(slot)));
        assert!(core::ptr::eq(
            resolver.parsed(digest).unwrap().bytes(),
            banks.bytes(slot)
        ));
    }
    assert_eq!(resolver.source(candidate.package), None);
    assert!(resolver.resolve(candidate.package).is_none());
    assert!(
        resolver
            .checked_source(Source::Downloaded(DownloadedSlot::B))
            .is_err()
    );
    assert!(matches!(
        Resolver::new(&banks, &images, None, [Some((0, candidate)), None]),
        Err(Error::Snapshot)
    ));
}
#[test]
fn actual_parsed_b_and_c_views_share_only_the_supplied_images_and_snapshot() {
    let (cat, context, a, b) = fixture();
    let banks = Packages::verify_network(&cat, context, &a, &b).unwrap();
    let images = sealed_images(true);
    let snapshot = crate::native_acquisition::tests::retained_snapshot(true);
    // Prior Active/KG here is explicit TEST lifecycle authorization from the
    // existing signed Store fixture, not a claim that parsing establishes it.
    let b = snapshot.active().unwrap();
    let c = snapshot.candidate().unwrap();
    let resolver = Resolver::new(
        &banks,
        &images,
        Some(&snapshot),
        [Some((0, b)), Some((1, c))],
    )
    .unwrap();
    for (slot, kernel_slot, content) in [(DownloadedSlot::B, 0, b), (DownloadedSlot::C, 1, c)] {
        let source = Source::Downloaded(slot);
        assert_eq!(resolver.source(content.package), Some(source));
        assert_eq!(resolver.source_digest(source), Some(content.package));
        assert!(core::ptr::eq(
            resolver.resolve(content.package).unwrap(),
            images.bytes(kernel_slot).unwrap()
        ));
        assert!(core::ptr::eq(
            resolver.parsed(content.package).unwrap().bytes(),
            images.bytes(kernel_slot).unwrap()
        ));
        assert_eq!(
            resolver.checked_source(source).unwrap().id().bytes(),
            content.package
        );
        assert!(banks.slot(content.package).is_none());
    }
    assert_eq!(
        resolver.banks().catalogue().root_abi(),
        banks.catalogue().root_abi()
    );
    assert!(core::mem::size_of_val(&resolver) <= 1536);
}
#[test]
fn mismatched_membership_logical_kernel_slot_or_backing_never_uses_a_bank_fallback() {
    let (cat, context, a, b) = fixture();
    let banks = Packages::verify_network(&cat, context, &a, &b).unwrap();
    let images = sealed_images(true);
    let snapshot = crate::native_acquisition::tests::retained_snapshot(true);
    let b = snapshot.active().unwrap();
    let c = snapshot.candidate().unwrap();
    for bindings in [
        [None, Some((0, b))],         // B cannot occupy C's logical identity.
        [Some((2, b)), None],         // Out-of-bounds actual Kernel owner.
        [Some((0, b)), Some((0, c))], // Same Kernel bytes cannot serve both.
        [Some((1, b)), Some((0, c))], // Correct IDs do not select wrong bytes.
    ] {
        assert!(Resolver::new(&banks, &images, Some(&snapshot), bindings).is_err());
    }
    let mut foreign = b;
    foreign.build[0] ^= 1;
    assert!(matches!(
        Resolver::new(&banks, &images, Some(&snapshot), [Some((0, foreign)), None]),
        Err(Error::Snapshot)
    ));
    let other_images = sealed_packages(&[banks.bytes(Slot::B)]);
    assert!(Resolver::new(&banks, &other_images, Some(&snapshot), [Some((0, b)), None]).is_err());
    let missing = Resolver::new(&banks, &images, Some(&snapshot), [None, None]).unwrap();
    assert!(missing.resolve(b.package).is_none());
    assert!(missing.resolve(c.package).is_none());
    assert_eq!(
        missing.source(banks.digest(Slot::B)),
        Some(Source::Bank(Slot::B))
    );
}
