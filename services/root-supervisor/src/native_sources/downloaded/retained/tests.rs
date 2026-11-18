use super::*;
use crate::native_sources::{
    Resolver,
    tests::{fixture, sealed_images},
};
use ev_app_registry::Packages as _;

fn registered(c: bool) -> Images<crate::native_sources::tests::Model> {
    let mut images = sealed_images(c);
    images.register(0, 100).unwrap();
    if c {
        images.register(1, 100).unwrap();
    }
    images
}
#[test]
fn member_requires_actual_registration_current_snapshot_and_exact_package() {
    let mut images = sealed_images(true);
    let b_snapshot = crate::native_acquisition::tests::retained_snapshot(false);
    let c_snapshot = crate::native_acquisition::tests::retained_snapshot(true);
    let b = b_snapshot.candidate().unwrap();
    let c = c_snapshot.candidate().unwrap();
    assert!(Member::capture(&images, 0, &b_snapshot, b).is_err());
    images.register(0, 100).unwrap();
    assert!(Member::capture(&images, 0, &b_snapshot, b).is_ok());
    assert!(Member::capture(&images, 0, &b_snapshot, c).is_err());
    assert!(Member::capture(&images, 1, &c_snapshot, c).is_err());
    assert!(Member::capture(&images, 2, &b_snapshot, b).is_err());
    images.register(1, 100).unwrap();
    assert!(Member::capture(&images, 0, &c_snapshot, c).is_err());
    let mut changed = b;
    changed.build[0] ^= 1;
    assert!(Member::capture(&images, 0, &b_snapshot, changed).is_err());
}
#[test]
fn old_local_b_remains_resolvable_after_current_candidate_membership_is_replaced() {
    let images = registered(true);
    let b_snapshot = crate::native_acquisition::tests::retained_snapshot(false);
    let c_snapshot = crate::native_acquisition::tests::candidate_only_snapshot(true);
    // Explicit TEST lifecycle state: remove prior synthetic Active/KG so the
    // new authenticated candidate no longer contains B at all. This is NOT a
    // durable reconciliation or authorization constructor in production.
    let b = b_snapshot.candidate().unwrap();
    let c = c_snapshot.candidate().unwrap();
    let member_b = Member::capture(&images, 0, &b_snapshot, b).unwrap();
    let member_c = Member::capture(&images, 1, &c_snapshot, c).unwrap();
    assert!(Downloaded::from_images(&images, 0, &c_snapshot, b).is_err());
    let (cat, context, a, bank_b) = fixture();
    let banks = Packages::verify_network(&cat, context, &a, &bank_b).unwrap();
    let local = Resolver::from_members(&banks, &images, [Some(member_b), Some(member_c)]).unwrap();
    for (member, content) in [(member_b, b), (member_c, c)] {
        assert_eq!(
            local.source(content.package),
            Some(Source::Downloaded(member.slot()))
        );
        assert!(core::ptr::eq(
            local.resolve(content.package).unwrap(),
            images.bytes(member.kernel_slot()).unwrap()
        ));
        assert_eq!(
            local
                .checked_source(Source::Downloaded(member.slot()))
                .unwrap()
                .id()
                .bytes(),
            content.package
        );
    }
    assert!(
        View::new(
            &banks,
            &images,
            &c_snapshot,
            [
                Some(Downloaded::from_member(&images, member_b).unwrap()),
                None
            ]
        )
        .is_err()
    );
    assert!(core::mem::size_of::<Member>() <= 288);
    assert!(core::mem::size_of_val(&local) <= 1536);
}
#[test]
fn foreign_owner_slot_cap_header_or_binding_position_never_reuses_a_receipt() {
    let images = registered(true);
    let other = registered(true);
    let snapshot = crate::native_acquisition::tests::retained_snapshot(true);
    let b = snapshot.active().unwrap();
    let member = Member::capture(&images, 0, &snapshot, b).unwrap();
    assert!(member.check(&other).is_err());
    for bad in [
        Member {
            owner: member.owner + 1,
            ..member
        },
        Member {
            kernel_slot: 1,
            ..member
        },
        Member {
            capability: member.capability + 1,
            ..member
        },
        Member {
            header: [0; 32],
            ..member
        },
    ] {
        assert!(bad.check(&images).is_err());
    }
    let (cat, context, a, bank_b) = fixture();
    let banks = Packages::verify_network(&cat, context, &a, &bank_b).unwrap();
    assert!(Resolver::from_members(&banks, &images, [None, Some(member)]).is_err());
    assert!(Resolver::from_members(&banks, &images, [Some(member), Some(member)]).is_err());
    let mut loader = crate::native_cold::Loader::new();
    assert!(loader.adopt(&other, member).is_err());
    assert!(loader.members().is_none());
    loader.adopt(&images, member).unwrap();
    assert_eq!(loader.bindings().unwrap()[0], Some((0, b)));
    loader.adopt(&images, member).unwrap();
    assert_eq!(loader.members().unwrap()[0].unwrap().kernel_slot(), 0);
}
