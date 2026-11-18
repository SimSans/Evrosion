//! The larger physical build does not widen any legacy factory or process.
extern crate std;
use super::*;

#[test]
fn legacy_factory_cannot_select_workspace_domains_and_retains_all_original_limits() {
    let mut a = Authority::new();
    let before = a.staged_copy();
    assert_eq!(a.create_workspace_control_space(), Err(Error::Denied));
    tests::unchanged(&a, &before);
    assert_eq!(
        (a.space_limit(), a.object_limit(), a.node_limit()),
        (40, 64, 256)
    );
    for _ in 0..40 {
        a.create_space().unwrap();
    }
    assert_eq!(a.create_space(), Err(Error::Capacity));
    assert_eq!(a.metadata_usage(), (40, 0, 0, 0));
}

#[test]
fn workspace_spaces_stay_ordinary_sixteen_and_only_explicit_control_factory_is_wider() {
    let mut a = Authority::for_workspace_profile();
    let root = a.create_workspace_control_space().unwrap();
    let legacy = a.create_control_space().unwrap();
    let ordinary = a.create_space().unwrap();
    assert_eq!(a.slot_capacity(root), Ok(96));
    assert_eq!(a.slot_capacity(legacy), Ok(64));
    assert_eq!(a.slot_capacity(ordinary), Ok(16));
    for _ in 3..64 {
        let domain = a.create_space().unwrap();
        assert_eq!(a.slot_capacity(domain), Ok(16));
    }
    let before = a.staged_copy();
    assert_eq!(a.create_space(), Err(Error::Capacity));
    tests::unchanged(&a, &before);
    assert_eq!(a.metadata_usage().0, 64);
    std::println!(
        "M8_AUTHORITY bytes={} spaces={} objects={} lineage={} ordinary={} control={}",
        core::mem::size_of::<Authority>(),
        a.space_limit(),
        a.object_limit(),
        a.node_limit(),
        MAX_CAPS,
        a.capacity(root.0)
    );
}

#[test]
fn workspace_high_object_and_handle_slots_retain_generation_and_reclamation_rules() {
    let mut a = Authority::for_workspace_profile();
    let owner = a.create_workspace_control_space().unwrap();
    let handles: [Handle; 96] = core::array::from_fn(|_| {
        a.create_root(owner, Kind::Memory, Kind::Memory.allowed())
            .unwrap()
    });
    assert_eq!(handles[95].0 & 255, 95);
    assert_eq!(
        a.authorize(owner, handles[95], Kind::Memory, Rights::READ)
            .unwrap()
            .identity(),
        95
    );
    let before = a.staged_copy();
    assert_eq!(
        a.create_root(owner, Kind::Memory, Rights::READ),
        Err(Error::Capacity)
    );
    tests::unchanged(&a, &before);
    for handle in handles {
        a.destroy(owner, handle).unwrap();
        a.close(owner, handle).unwrap();
    }
    assert_eq!(a.collect_lineage(), Ok(96));
    assert_eq!(a.collect_dead_objects(), Ok(96));
    let next = a.create_root(owner, Kind::Memory, Rights::READ).unwrap();
    assert_eq!(
        a.authorize(owner, next, Kind::Memory, Rights::READ)
            .unwrap()
            .identity(),
        256
    );
    assert!(
        a.authorize(owner, handles[0], Kind::Memory, Rights::READ)
            .is_err()
    );
    a.close_space(owner).unwrap();
    a.collect_lineage().unwrap();
    let recycled = a.recycle_space(owner).unwrap();
    assert_eq!(a.slot_capacity(recycled), Ok(96));
    assert!(!a.is_live_space(owner));
    assert!(
        a.authorize(recycled, next, Kind::Memory, Rights::READ)
            .is_err()
    );
}

#[test]
fn selected_lineage_is_finite_and_closed_handles_keep_exact_ancestry_until_collection() {
    let mut a = Authority::for_workspace_profile();
    let owner = a.create_space().unwrap();
    let root = a
        .create_root(owner, Kind::Memory, Rights::READ | Rights::DERIVE)
        .unwrap();
    let mut last = Handle(0);
    for _ in 1..512 {
        last = a.derive(owner, root, owner, Rights::READ).unwrap();
        a.close(owner, last).unwrap();
    }
    assert_eq!(a.metadata_usage(), (1, 1, 512, 1));
    let before = a.staged_copy();
    assert_eq!(
        a.derive(owner, root, owner, Rights::READ),
        Err(Error::Capacity)
    );
    tests::unchanged(&a, &before);
    assert_eq!(a.collect_lineage(), Ok(511));
    let new = a.derive(owner, root, owner, Rights::READ).unwrap();
    assert_ne!(new, last);
    assert!(
        a.authorize(owner, last, Kind::Memory, Rights::READ)
            .is_err()
    );
    assert!(a.authorize(owner, new, Kind::Memory, Rights::READ).is_ok());
}

#[test]
fn widened_staging_batch_does_not_widen_legacy_or_ordinary_destination() {
    let mut a = Authority::for_workspace_profile();
    let owner = a.create_workspace_control_space().unwrap();
    let branches = a.create_workspace_control_space().unwrap();
    let destination = a.create_workspace_control_space().unwrap();
    let legacy = a.create_control_space().unwrap();
    let ordinary = a.create_space().unwrap();
    let root = a
        .create_root(owner, Kind::Memory, Kind::Memory.allowed())
        .unwrap();
    let requests: [Derivation; 96] = core::array::from_fn(|_| Derivation {
        source: root,
        kind: Kind::Memory,
        rights: Rights::READ,
    });
    let before = a.staged_copy();
    assert!(
        a.derive_scoped_into_empty(owner, branches, legacy, &requests)
            .is_err()
    );
    tests::unchanged(&a, &before);
    assert!(
        a.derive_scoped_into_empty(owner, branches, ordinary, &requests)
            .is_err()
    );
    tests::unchanged(&a, &before);
    let grants = a
        .derive_scoped_into_empty(owner, branches, destination, &requests)
        .unwrap();
    assert_eq!(grants.grants.handles().len(), 96);
    assert_eq!(grants.branches.handles().len(), 96);
    assert_eq!(grants.grants.handles()[95].0 & 255, 95);
    a.revoke_batch(branches, grants.branches.handles()).unwrap();
    for cap in grants.grants.handles() {
        assert!(
            a.authorize(destination, *cap, Kind::Memory, Rights::READ)
                .is_err()
        );
    }
}
