use super::*;

fn committed_payload(device: Disk, bytes: &[u8]) -> Disk {
    let mut store = Store::open(device, DEADLINE)
        .unwrap_or_else(|rejected| panic!("fixture open: {:?}", rejected.error));
    store
        .execute(
            store.next_operation().unwrap(),
            Request::WriteMutable {
                object: ObjectId::user_data(),
                bytes,
            },
            DEADLINE,
        )
        .unwrap();
    store.into_device().cold()
}

fn pending_payload(device: Disk, bytes: &[u8]) -> Disk {
    // Derive the actual journal flush boundary from a complete Store operation,
    // then cut the independent identical fixture immediately AFTER that flush.
    // The journal is valid and durable; the selected root/data remain old.
    let original = device.durable.clone();
    let complete_device = Disk::snapshot(original.clone());
    let probe = complete_device.probe.clone();
    let mut complete = Store::open(complete_device, DEADLINE)
        .unwrap_or_else(|rejected| panic!("fixture open: {:?}", rejected.error));
    probe.nth.set(0);
    probe.trace.borrow_mut().clear();
    complete
        .execute(
            complete.next_operation().unwrap(),
            Request::WriteMutable {
                object: ObjectId::user_data(),
                bytes,
            },
            DEADLINE,
        )
        .unwrap();
    let journal_flush = probe
        .trace
        .borrow()
        .iter()
        .position(|&(kind, _)| kind == 'f')
        .unwrap()
        + 1;
    let device = Disk::snapshot(original);
    let probe = device.probe.clone();
    let mut store = Store::open(device, DEADLINE)
        .unwrap_or_else(|rejected| panic!("fixture open: {:?}", rejected.error));
    probe.nth.set(0);
    probe.trace.borrow_mut().clear();
    probe.cut.set(Some((journal_flush, Cut::After)));
    assert_eq!(
        store.execute(
            store.next_operation().unwrap(),
            Request::WriteMutable {
                object: ObjectId::user_data(),
                bytes,
            },
            DEADLINE,
        ),
        Err(ev_store::Error::Io(Fault::Power))
    );
    assert_eq!(probe.trace.borrow().last().unwrap().0, 'f');
    assert_eq!(
        probe.trace.borrow().iter().filter(|x| x.0 == 'w').count(),
        1,
        "only the journal reached durable media"
    );
    store.into_device().cold()
}

fn no_write_refusal(
    device: Disk,
    owner: Policy,
    creation: &GenerationManifest,
    packages: &impl Packages,
    expected: Error<Fault>,
) {
    let before = device.durable.clone();
    let probe = device.probe.clone();
    probe.trace.borrow_mut().clear();
    let rejected = Registry::open_checked(device, owner, creation, packages, &Support, DEADLINE)
        .err()
        .expect("must refuse before recovery");
    assert_eq!(rejected.error, expected);
    assert_eq!(rejected.policy, owner);
    assert!(rejected.pending.is_none(), "cold open invents no intent");
    assert_eq!(rejected.device.durable, before);
    assert_eq!(rejected.device.cache, before);
    assert!(probe.trace.borrow().iter().all(|x| x.0 == 'r'));
    rejected.device.assert_guards();
}

fn reseal(bytes: &mut [u8; lifecycle::BYTES]) {
    let mut hash = Sha256::new();
    hash.update(b"evrosion.app-registry.v1\0");
    hash.update(&bytes[..224]);
    bytes[224..].copy_from_slice(&hash.finalize());
}

fn active_fixture(packages: &Catalog<'_>) -> (Disk, [u8; lifecycle::BYTES]) {
    let mut registry = fresh();
    apply(
        &mut registry,
        Change::Install {
            package: packages.packages[0].id().bytes(),
            data_epoch: 1,
        },
        packages,
    );
    apply(&mut registry, Change::Activate, packages);
    let record = registry.record().unwrap().unwrap().encode();
    (registry.into_parts().0.cold(), record)
}

#[test]
fn checked_open_requires_independent_creation_and_never_formats() {
    let bytes = [package(1, 1, 1, 7, 8)];
    let packages = catalog(&bytes);
    no_write_refusal(
        Disk::blank(),
        policy(),
        &format_manifest(),
        &packages,
        Error::Store(ev_store::Error::Unformatted),
    );
    let (device, _) = active_fixture(&packages);
    let original = device.durable.clone();
    for field in 0..4 {
        let mut foreign = format_manifest();
        match field {
            0 => foreign.cohort[0] ^= 1,
            1 => foreign.supervisor_image[0] ^= 1,
            2 => foreign.abi[0] ^= 1,
            _ => foreign.health_contract[0] ^= 1,
        }
        no_write_refusal(
            Disk::snapshot(original.clone()),
            policy(),
            &foreign,
            &packages,
            Error::Store(ev_store::Error::Conflict),
        );
    }
    let registry = Registry::open(
        Disk::snapshot(original),
        policy(),
        &packages,
        &Support,
        DEADLINE,
    )
    .unwrap_or_else(|rejected| panic!("fixture open: {:?}", rejected.error));
    let proposal = registry
        .prepare(
            registry.expected().unwrap(),
            Change::Remove,
            &packages,
            &Support,
        )
        .unwrap()
        .after()
        .encode();
    let mut foreign = format_manifest();
    foreign.cohort[0] ^= 1;
    no_write_refusal(
        pending_payload(registry.into_parts().0, &proposal),
        policy(),
        &foreign,
        &packages,
        Error::Store(ev_store::Error::Conflict),
    );
}

#[test]
fn checked_committed_metadata_requires_canonical_actual_owner_and_packages() {
    let bytes = [package(1, 1, 1, 7, 8)];
    let packages = catalog(&bytes);
    let (device, record) = active_fixture(&packages);
    let original = device.durable.clone();
    for case in 0..4 {
        let mut bad = record;
        let expected = match case {
            0 => {
                bad[16..32].fill(9);
                reseal(&mut bad);
                Error::Identity
            }
            1 => {
                bad[80..84].copy_from_slice(&2u32.to_le_bytes());
                reseal(&mut bad);
                Error::WrongPackage
            }
            2 => {
                bad[224] ^= 1;
                Error::Metadata(lifecycle::Error::Digest)
            }
            _ => Error::Readback,
        };
        let payload = if case == 3 { &bad[..255] } else { &bad[..] };
        no_write_refusal(
            committed_payload(Disk::snapshot(original.clone()), payload),
            policy(),
            &format_manifest(),
            &packages,
            expected,
        );
    }
    let missing = catalog(&[]);
    no_write_refusal(
        Disk::snapshot(original.clone()),
        policy(),
        &format_manifest(),
        &missing,
        Error::MissingPackage,
    );
    no_write_refusal(
        Disk::snapshot(original.clone()),
        Policy {
            abi: [9; 32],
            ..policy()
        },
        &format_manifest(),
        &packages,
        Error::Package(ev_zion::Error::Abi),
    );
    // A valid next journal must not hide a foreign committed owner. Generic
    // Store recovery would first replace these committed bytes with the journal.
    let mut foreign = record;
    foreign[16..32].fill(9);
    reseal(&mut foreign);
    let device = committed_payload(Disk::snapshot(original), &foreign);
    no_write_refusal(
        pending_payload(device, &record),
        policy(),
        &format_manifest(),
        &packages,
        Error::Identity,
    );
}

#[test]
fn checked_pending_rejects_foreign_corrupt_and_rewound_payload_before_any_write() {
    let bytes = [package(1, 1, 1, 7, 8), package(2, 2, 1, 7, 8)];
    let packages = catalog(&bytes);
    let (device, before) = active_fixture(&packages);
    let original = device.durable.clone();
    let registry = Registry::open(device, policy(), &packages, &Support, DEADLINE)
        .unwrap_or_else(|rejected| panic!("fixture open: {:?}", rejected.error));
    let proposal = registry
        .prepare(
            registry.expected().unwrap(),
            Change::Replace {
                package: packages.packages[1].id().bytes(),
            },
            &packages,
            &Support,
        )
        .unwrap()
        .after()
        .encode();
    for case in 0..6 {
        let mut bad = proposal;
        let expected = match case {
            0 => {
                bad[16..32].fill(9);
                reseal(&mut bad);
                Error::Identity
            }
            1 => {
                bad[80..84].copy_from_slice(&3u32.to_le_bytes());
                reseal(&mut bad);
                Error::WrongPackage
            }
            2 => {
                bad[224] ^= 1;
                Error::Metadata(lifecycle::Error::Digest)
            }
            3 => {
                bad = before;
                Error::RecoveryConflict
            }
            4 => {
                bad[32..40].copy_from_slice(&1u64.to_le_bytes());
                reseal(&mut bad);
                Error::RecoveryConflict
            }
            _ => Error::RecoveryConflict,
        };
        let payload = if case == 5 { &[][..] } else { &bad[..] };
        no_write_refusal(
            pending_payload(Disk::snapshot(original.clone()), payload),
            policy(),
            &format_manifest(),
            &packages,
            expected,
        );
    }
    // Committed bytes resolve, but the pending candidate's actual full package
    // is absent. An old open would publish it before its final load refuses.
    let only_old = catalog(&bytes[..1]);
    no_write_refusal(
        pending_payload(Disk::snapshot(original), &proposal),
        policy(),
        &format_manifest(),
        &only_old,
        Error::MissingPackage,
    );
}

#[test]
fn checked_pending_valid_lifecycle_replay_matches_historical_bytes_and_ids() {
    let bytes = [package(1, 1, 1, 7, 8), package(2, 2, 1, 7, 8)];
    let packages = catalog(&bytes);
    let a = packages.packages[0].id().bytes();
    let b = packages.packages[1].id().bytes();
    let mut registry = fresh();
    for change in [
        Change::Install {
            package: a,
            data_epoch: 1,
        },
        Change::Activate,
        Change::Stage { package: b },
        Change::Activate,
        Change::Rollback,
        Change::Replace { package: b },
        Change::DataMigrated { epoch: 2 },
        Change::Remove,
        Change::Reinstall { package: b },
    ] {
        let proposal = registry
            .prepare(registry.expected().unwrap(), change, &packages, &Support)
            .unwrap();
        let operation = proposal.operation();
        let exact = proposal.after().encode();
        let pending = pending_payload(registry.into_parts().0, &exact);
        let historical = Registry::open(
            Disk::snapshot(pending.durable.clone()),
            policy(),
            &packages,
            &Support,
            DEADLINE,
        )
        .unwrap_or_else(|rejected| panic!("historical replay: {:?}", rejected.error));
        let probe = pending.probe.clone();
        probe.trace.borrow_mut().clear();
        registry = Registry::open_checked(
            pending,
            policy(),
            &format_manifest(),
            &packages,
            &Support,
            DEADLINE,
        )
        .unwrap_or_else(|rejected| panic!("checked replay: {:?}", rejected.error));
        assert_eq!(registry.record().unwrap().unwrap().encode(), exact);
        assert_eq!(
            registry.store.next_operation().unwrap().get(),
            operation.get() + 1
        );
        assert!(registry.store.known_good().is_none());
        assert!(probe.trace.borrow().iter().any(|x| x.0 == 'w'));
        assert!(probe.trace.borrow().iter().any(|x| x.0 == 'f'));
        let (device, owner, pending) = registry.into_parts();
        assert!(pending.is_none());
        assert_eq!(
            device.durable,
            historical.into_parts().0.durable,
            "checked replay must preserve valid historical encoding"
        );
        device.assert_guards();
        registry = Registry::open_checked(
            device,
            owner,
            &format_manifest(),
            &packages,
            &Support,
            DEADLINE,
        )
        .unwrap_or_else(|rejected| panic!("checked clean reopen: {:?}", rejected.error));
    }
    registry.into_parts().0.assert_guards();
}

#[test]
fn checked_scoped_open_returns_exact_uncertain_intent_and_original_device() {
    let bytes = [package(1, 1, 1, 7, 8)];
    let packages = catalog(&bytes);
    let device = fresh().into_parts().0;
    let before = device.durable.clone();
    let probe = device.probe.clone();
    let mut operation = None;
    let rejected = Registry::with_open_checked(
        device,
        policy(),
        &format_manifest(),
        &packages,
        &Support,
        DEADLINE,
        |registry| {
            let proposal = registry
                .prepare(
                    registry.expected().unwrap(),
                    Change::Install {
                        package: packages.packages[0].id().bytes(),
                        data_epoch: 1,
                    },
                    &packages,
                    &Support,
                )
                .unwrap();
            operation = Some(proposal.operation());
            probe.nth.set(0);
            probe.cut.set(Some((1, Cut::Before)));
            assert_eq!(
                registry.publish(proposal, &packages, &Support, DEADLINE),
                Err(Error::Store(ev_store::Error::Io(Fault::Power)))
            );
            Ok(()) // A swallowed transport failure cannot turn into scoped success.
        },
    )
    .err()
    .unwrap();
    assert_eq!(rejected.error, Error::NeedsRecovery);
    assert_eq!(
        rejected.pending.as_ref().map(Prepared::operation),
        operation
    );
    assert_eq!(rejected.device.durable, before);
    assert!(Rc::ptr_eq(&rejected.device.probe, &probe));
    rejected.device.assert_guards();
}
