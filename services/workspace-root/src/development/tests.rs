extern crate std;
use super::*;
use ev_zion::{
    AppId, CapabilityRequest, Contract, DataSchema, Platform, Version,
    producer::{self, Spec},
};
use std::vec::Vec;
pub(super) fn package(app: u8, read: bool, edit: bool) -> Vec<u8> {
    package_ui(app, read, edit, true, true)
}
fn package_ui(app: u8, read: bool, edit: bool, surface: bool, input: bool) -> Vec<u8> {
    let mut caps = std::vec![];
    for (yes, capability) in [
        (read, Capability::SelectedFileRead),
        (true, Capability::AppPrivateData),
        (surface, Capability::OwnSurfacePresent),
        (input, Capability::FocusedInput),
        (edit, Capability::SelectedFileEdit),
    ] {
        if yes {
            caps.push(CapabilityRequest {
                capability,
                required: true,
            });
        }
    }
    producer::build(
        &Spec {
            app: AppId::new([app; 16]).unwrap(),
            name: "Independent development fixture",
            source: "model only",
            publisher: None,
            version: Version {
                major: 0,
                minor: 4,
                patch: 0,
            },
            build_id: [app; 32],
            platform: Platform {
                minimum: 1,
                target: 1,
            },
            abi: ev_userspace_contract::root_v5::child::abi(
                ev_userspace_contract::root_v5::graph::Child::EditorTwo,
            ),
            data_schema: DataSchema {
                current: 1,
                oldest_readable: 1,
            },
            entrypoint: "bin/main.elf",
            contracts: &[Contract {
                name: ev_userspace_contract::app_data::INTERFACE,
                major: 1,
                minimum_minor: 0,
                features: 0,
            }],
            capabilities: &caps,
        },
        include_bytes!("../../../../kernel/fixtures/bootstrap-static-v1.elf"),
        &[],
    )
    .unwrap()
}
fn root() -> Identity {
    Identity {
        process: 1,
        thread: 2,
        registered: 1,
    }
}
fn previous() -> Actor {
    Actor {
        control: 9,
        identity: Identity {
            process: 5,
            thread: 6,
            registered: 1,
        },
        ready: true,
        mapping_epoch: 1,
        failed: false,
    }
}
fn facts() -> Facts {
    facts_for(&package(9, true, true))
}
pub(super) fn facts_for(bytes: &[u8]) -> Facts {
    let loaded = crate::requirements::LoadedContracts {
        semantic_tree: true,
        file: None,
    };
    let contracts = crate::requirements::PrivateDataContracts::new(&loaded, true);
    let checked = crate::requirements::private_file_app(bytes, &contracts).unwrap();
    Facts::capture(&checked, previous(), root()).unwrap()
}
pub(super) fn effect(facts: Facts, intent: Intent) -> Effect {
    let shell = Identity {
        process: 3,
        thread: 4,
        registered: 1,
    };
    let mut policy = crate::policy::Policy::new(shell, root()).unwrap();
    policy.install(2, previous()).unwrap();
    let scope = facts.scope(intent);
    let attention = policy
        .trusted
        .attest_attention(&mut policy.desktop, 10)
        .unwrap();
    let challenge = policy
        .trusted
        .challenge(&mut policy.desktop, attention, scope)
        .unwrap();
    let witness = policy
        .trusted
        .attest_presented(&mut policy.desktop, challenge, scope, 20, 11)
        .unwrap();
    policy
        .trusted
        .attest_confirmation(
            &mut policy.desktop,
            witness,
            scope,
            12,
            ev_workspace_shell::ConfirmationSource::Physical,
        )
        .unwrap()
}
#[test]
fn install_and_run_require_distinct_exact_full_protected_effects() {
    let f = facts();
    assert_ne!(f.scope(Intent::Install), f.scope(Intent::Run));
    assert!(matches!(
        approve(f, Intent::Run, effect(f, Intent::Install), 100, 8000),
        Err(Error::Effect)
    ));
    for field in 0..8 {
        let mut changed = f;
        match field {
            0 => changed.source.app[0] ^= 1,
            1 => changed.source.package[0] ^= 1,
            2 => changed.source.image[0] ^= 1,
            3 => changed.source.build[0] ^= 1,
            4 => changed.previous.identity.process += 1,
            5 => changed.previous.identity.thread += 1,
            6 => changed.previous.mapping_epoch += 1,
            _ => changed.root.process += 1,
        }
        assert!(matches!(
            approve(
                changed,
                Intent::Install,
                effect(f, Intent::Install),
                100,
                8000
            ),
            Err(Error::Effect)
        ));
    }
    let approval = approve(f, Intent::Install, effect(f, Intent::Install), 100, 8000).unwrap();
    assert_eq!(approval.facts(), f);
    assert_eq!(approval.cut(), 8000);
    assert_eq!(approval.intent(), Intent::Install);
}
#[test]
fn original_cut_and_actual_target_never_renew_or_alias_after_approval() {
    let f = facts();
    let approval = approve(f, Intent::Run, effect(f, Intent::Run), 100, 8000).unwrap();
    assert!(approval.current(f, 7999));
    assert!(!approval.current(f, 99));
    assert!(!approval.current(f, 8000));
    let mut replacement = f;
    replacement.previous.control += 1;
    assert!(!approval.current(replacement, 101));
    replacement = f;
    replacement.previous.identity.registered += 1;
    assert!(!approval.current(replacement, 101));
    for cut in [0, 100, 8293, u64::MAX] {
        assert!(matches!(
            approve(f, Intent::Run, effect(f, Intent::Run), 100, cut),
            Err(Error::Deadline)
        ));
    }
}
#[test]
fn private_data_request_never_authorizes_selected_file_access() {
    for (read, edit) in [(false, false), (true, false), (true, true), (false, true)] {
        let bytes = package(9, read, edit);
        let package = Package::parse(&bytes).unwrap();
        assert_eq!(allows_file(&package, false), read);
        assert_eq!(allows_file(&package, true), read && edit);
        assert_eq!(private_profile(&package).is_ok(), !edit || read);
    }
}
#[test]
fn fixed_ui_roles_require_explicit_requests_before_external_delegation() {
    for (surface, input) in [(false, false), (true, false), (false, true)] {
        let bytes = package_ui(9, false, false, surface, input);
        assert_eq!(
            private_profile(&Package::parse(&bytes).unwrap()),
            Err(Error::Capability)
        );
    }
    let bytes = package(9, false, false);
    assert_eq!(private_profile(&Package::parse(&bytes).unwrap()), Ok(()));
}
#[test]
fn actual_source_identity_is_independent_of_current_actor_slot_or_display_name() {
    let a = package(9, true, true);
    let b = package(8, true, true);
    let a = Source::of(&Package::parse(&a).unwrap());
    let b = Source::of(&Package::parse(&b).unwrap());
    assert_ne!(a.app, b.app);
    assert_ne!(a.package, b.package);
    assert_ne!(a.build, b.build);
    assert_eq!(
        a.image, b.image,
        "fixture code is deliberately identical; software is not its instance slot"
    );
}
#[test]
fn boundary_clock_after_parsing_blocks_new_call_and_late_actual_reply_stays_owned() {
    use core::cell::Cell;
    let calls = Cell::new(0);
    let mut cut = Cut::new(1, 100).unwrap();
    let failure = cut
        .invoke(
            || 100,
            || {
                calls.set(calls.get() + 1);
                77u64
            },
        )
        .err()
        .unwrap();
    assert_eq!(failure.actual, None);
    assert_eq!(
        calls.get(),
        0,
        "stale entry time cannot admit Register after parsing"
    );
    let mut cut = Cut::new(1, 100).unwrap();
    let tick = Cell::new(1);
    let failure = cut
        .invoke(
            || tick.get(),
            || {
                calls.set(calls.get() + 1);
                tick.set(100);
                ev_userspace_runtime::CapReply {
                    status: 0,
                    value: 77,
                    capability: 88,
                    serial: 0,
                }
            },
        )
        .err()
        .unwrap();
    let actual = failure.actual.unwrap();
    assert_eq!(
        (actual.status, actual.value, actual.capability),
        (0, 77, 88)
    );
    assert!(
        cut.invoke(
            || 2,
            || {
                calls.set(calls.get() + 1);
                0u64
            }
        )
        .is_err()
    );
    assert_eq!(
        calls.get(),
        1,
        "late result cannot rearm or renew the original cut"
    );
}
