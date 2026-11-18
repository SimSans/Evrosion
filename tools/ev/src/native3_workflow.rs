//! One owned continuing disk per Native3 proof. All cold boots retain their own
//! exact source-built manifest; host observers only read complete snapshots.
use crate::native3_disk::{
    AppExpected, Expected, Generation, GrantExpected, Mutations, ProbeExpected, SystemExpected,
};
use crate::{
    boot::{self, Native3Boot},
    build::{self, Manifest, Result},
    cli::{BootOptions, BuildOptions},
    native3_io::Phase,
    storage,
};
use ev_diagnostics::owner::{Action, Phase as OwnerPhase};
use ev_root_supervisor::native_plan::{Slot, system};
use serde_json::{Value, json};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
struct Cohort {
    manifest: Manifest,
    path: PathBuf,
    components: crate::native_workflow::components::Components,
}
fn bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !m.is_file() || m.file_type().is_symlink() || m.len() > limit {
        return Err("Native3 nonregular/oversized evidence".into());
    }
    let mut out = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit + 1)
        .read_to_end(&mut out)
        .map_err(|e| e.to_string())?;
    if out.len() as u64 > limit {
        return Err("Native3 evidence grew beyond bound".into());
    }
    Ok(out)
}
fn link(path: &Path, base: &Path) -> Result<Value> {
    Ok(
        json!({"path":path.strip_prefix(base).map_err(|_|"Native3 evidence escaped directory")?,"sha256":build::hash_file(path)?,"bytes":fs::metadata(path).map_err(|e|e.to_string())?.len()}),
    )
}
fn cohort(root: &Path, parent: &Path, fixture: &str) -> Result<Cohort> {
    let directory = parent.join(fixture);
    fs::create_dir(&directory).map_err(|e| e.to_string())?;
    let (recipe, inputs) = build::source_inputs(root)?;
    storage::json_new(
        &directory.join("candidate-source-inputs.json"),
        &json!({"schema":1,"fixture":fixture,"source_sha256":recipe,"source_inputs":inputs,"scope":"candidate sources before build; no build, execution or acceptance claim"}),
    )?;
    build::build(&BuildOptions {
        root: Some(root.into()),
        fixture: Some(fixture.into()),
        ..BuildOptions::default()
    })?;
    let bytes = bounded(&root.join("build/m0/manifest.json"), 16 * 1024 * 1024)?;
    let path = directory.join("manifest.json");
    storage::immutable_new(&path, &bytes)?;
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    manifest.validate_policy_rows()?;
    if manifest.fixture.as_deref() != Some(fixture) {
        return Err("Native3 retained wrong mode manifest".into());
    }
    if manifest.source_sha256 != recipe {
        return Err("Native3 candidate source changed before retained build".into());
    }
    let components = crate::native_workflow::components::retain(root, &directory, &manifest)?;
    let kernel = build::verify_artifact(&root.join("build/m0"), &manifest.kernel)?;
    let status = Command::new("python3")
        .current_dir(root)
        .arg(root.join("tools/m5/stack_audit.py"))
        .arg(kernel)
        .arg(directory.join("kernel-stack.json"))
        .stdin(Stdio::null())
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!("Native3 linked Kernel stack preflight: {status}"));
    }
    Ok(Cohort {
        manifest,
        path,
        components,
    })
}
fn app() -> AppExpected {
    AppExpected {
        revision: 2,
        installed: true,
        active: Some(Slot::A),
        previous: None,
        staged: None,
        data_epoch: 1,
        registry_operation: 2,
        data_operation: 0,
        data_counter: 0,
        value: 1001,
    }
}
fn remembered_action(
    phase: Phase,
    previous: Option<[u8; 32]>,
    completed: Option<[u8; 32]>,
) -> Option<[u8; 32]> {
    if phase == Phase::GrantRemember {
        completed
    } else {
        // A tombstone retains the original remembered consent. Its separate
        // revoke action authorizes revocation, not replacement of that consent.
        previous
    }
}
pub(crate) fn run_system() -> Result<()> {
    run(true)
}
pub(crate) fn run_grants() -> Result<()> {
    run(false)
}
fn run(system_proof: bool) -> Result<()> {
    let root =
        crate::doctor::workspace(&std::env::current_dir().map_err(|e| e.to_string())?, None)?
            .canonicalize()
            .map_err(|e| e.to_string())?;
    let parent = storage::directory_beneath(&root, Path::new("build/m5/evidence"))?;
    let evidence = build::unique_directory(
        &parent,
        if system_proof {
            "native-system"
        } else {
            "native-owner-grants"
        },
    )?;
    println!("Evidence: {}", evidence.display());
    let mut stage = "build";
    let mut phases = Vec::<Value>::new();
    let mut builds = Vec::<Value>::new();
    let mut seed = None;
    let result: Result<()> = (|| {
        let fixtures: Vec<_> = if system_proof {
            vec!["m5-native-system", "m5-native-recovery"]
        } else {
            vec!["m5-native"]
        };
        let mut cohorts = Vec::new();
        for fixture in fixtures {
            let c = cohort(&root, &evidence, fixture)?;
            builds.push(json!({"manifest":link(&c.path,&evidence)?,"build_id":c.manifest.build_id,"source_sha256":c.manifest.source_sha256,"components":c.components.record}));
            cohorts.push(c);
        }
        let first = &cohorts[0];
        for c in &cohorts[1..] {
            if c.manifest.source_sha256 != first.manifest.source_sha256
                || c.components.packages != first.components.packages
            {
                return Err("Native3 boot modes do not share exact frozen sources/packages".into());
            }
        }
        stage = "import_exact_checkpoint";
        let (baseline, source) = crate::native_seed::checkpoint(&root, &evidence)?;
        seed = Some(source);
        let mut disk = storage::Disk::create(&root, &evidence)?;
        disk.restore_snapshot(&baseline)?;
        disk.capture(&evidence, "native3-before.raw")?;
        let selected: Vec<_> = if system_proof {
            vec![
                Phase::SystemFull,
                Phase::SystemBad,
                Phase::SystemGoodStage,
                Phase::SystemRecovery,
                Phase::SystemFinal,
            ]
        } else {
            vec![
                Phase::GrantRemember,
                Phase::GrantCold,
                Phase::GrantRevoke,
                Phase::GrantRefused,
            ]
        };
        let mut last_good_probe = None;
        let mut last_failure = None;
        let mut grant_action = None;
        let mut previous_verified_disk: Option<Value> = None;
        for phase in selected {
            stage = phase.name();
            let c = cohorts
                .iter()
                .find(|c| c.manifest.fixture.as_deref() == Some(phase.fixture()))
                .ok_or("Native3 missing mode cohort")?;
            let directory = evidence.join(phase.name());
            fs::create_dir(&directory).map_err(|e| e.to_string())?;
            let before = disk.bytes()?;
            let before_record = disk.capture(&directory, "data-before.raw")?;
            let boot = boot::boot_native3(
                &BootOptions {
                    root: Some(root.clone()),
                    timeout_seconds: 240,
                    ..BootOptions::default()
                },
                Native3Boot {
                    manifest: &c.path,
                    evidence: &directory,
                    disk: &disk,
                    phase,
                },
            );
            let after = disk.bytes()?;
            let after_record = disk.capture(&directory, "data-after.raw")?;
            let mut validation = None;
            let checked: Result<()> = (|| {
                boot?;
                let serial = bounded(&directory.join("boot/run-001/serial.log"), 1024 * 1024)?;
                let record = crate::native3_protocol::record(
                    &serial,
                    &c.manifest.build_id,
                    phase.recovery(),
                )?;
                let profile = crate::native_profile::finished(
                    &serial,
                    &c.manifest.build_id,
                    record.counts["faults"],
                    Some(
                        ev_userspace_contract::root_v2::native::catalogue::Catalogue::decode(
                            &c.components.catalogue,
                        )
                        .map_err(|e| format!("Native3 retained catalogue mode: {e:?}"))?
                        .boot_mode() as u64,
                    ),
                )?;
                let baseline =
                    crate::native_baselines::retain(&root, &c.manifest, &serial, &directory)?;
                let owner_expected = match phase {
                    Phase::SystemRecovery => vec![crate::native3_diagnostics::OwnerExpected {
                        action: Action::RecoverGood,
                        outcome: OwnerPhase::Completed,
                    }],
                    Phase::GrantRemember => vec![crate::native3_diagnostics::OwnerExpected {
                        action: Action::RememberRead,
                        outcome: OwnerPhase::Completed,
                    }],
                    Phase::GrantRevoke => vec![crate::native3_diagnostics::OwnerExpected {
                        action: Action::RevokeRead,
                        outcome: OwnerPhase::Completed,
                    }],
                    _ => vec![],
                };
                let admission = match phase {
                    Phase::SystemFull => Some((
                        system::Slot::Good,
                        1,
                        1,
                        ev_diagnostics::system::Phase::Healthy,
                    )),
                    Phase::SystemBad => Some((
                        system::Slot::Bad,
                        2,
                        2,
                        ev_diagnostics::system::Phase::Failed,
                    )),
                    Phase::SystemGoodStage => Some((
                        system::Slot::Good,
                        1,
                        3,
                        ev_diagnostics::system::Phase::Healthy,
                    )),
                    Phase::SystemFinal => Some((
                        system::Slot::Good,
                        1,
                        4,
                        ev_diagnostics::system::Phase::Healthy,
                    )),
                    _ => None,
                };
                let joined = crate::native3_diagnostics::retain(
                    &serial,
                    &c.manifest.build_id,
                    &c.manifest.source_sha256,
                    c.components.packages(),
                    &c.components.catalogue,
                    &c.components.root_manifest,
                    crate::native3_diagnostics::Expected {
                        recovery: phase.recovery(),
                        initial_selected: match phase {
                            Phase::SystemBad => Some(Generation {
                                slot: system::Slot::Bad,
                                id: 2,
                            }),
                            Phase::SystemGoodStage | Phase::SystemFinal => Some(Generation {
                                slot: system::Slot::Good,
                                id: 1,
                            }),
                            Phase::SystemRecovery => Some(Generation {
                                slot: system::Slot::Bad,
                                id: 3,
                            }),
                            _ => None,
                        },
                        current: admission.map(|(slot, id, boot_serial, phase)| {
                            crate::native3_diagnostics::CurrentExpected {
                                generation: Generation { slot, id },
                                boot_serial,
                                phase,
                            }
                        }),
                        selected: match phase {
                            Phase::SystemFull => Some(Generation {
                                slot: system::Slot::Bad,
                                id: 2,
                            }),
                            Phase::SystemGoodStage => Some(Generation {
                                slot: system::Slot::Bad,
                                id: 3,
                            }),
                            Phase::SystemBad | Phase::SystemRecovery | Phase::SystemFinal => {
                                Some(Generation {
                                    slot: system::Slot::Good,
                                    id: 1,
                                })
                            }
                            _ => None,
                        },
                        known_good: system_proof.then_some(1),
                        failure: if phase == Phase::SystemBad {
                            crate::native3_diagnostics::FailureExpected::CurrentMissingProgress {
                                operation: 9,
                                sequence: 10,
                            }
                        } else if let Some(failure) = last_failure {
                            crate::native3_diagnostics::FailureExpected::Exact(failure)
                        } else {
                            crate::native3_diagnostics::FailureExpected::None
                        },
                        shell_faults: usize::from(matches!(
                            phase,
                            Phase::SystemFull | Phase::SystemBad
                        )),
                        app_faults: usize::from(phase == Phase::SystemFull),
                        job_roles: if phase == Phase::SystemFinal {
                            &[
                                ev_diagnostics::live::Role::Boot,
                                ev_diagnostics::live::Role::Root,
                                ev_diagnostics::live::Role::Shell,
                                ev_diagnostics::live::Role::Input,
                                ev_diagnostics::live::Role::File,
                                ev_diagnostics::live::Role::Block,
                                ev_diagnostics::live::Role::Application,
                                ev_diagnostics::live::Role::Display,
                            ]
                        } else {
                            &[]
                        },
                        owners: &owner_expected,
                        managed_reads: usize::from(matches!(
                            phase,
                            Phase::GrantRemember | Phase::GrantCold | Phase::GrantRevoke
                        )),
                        inhibits: usize::from(phase == Phase::GrantRevoke),
                    },
                    &directory,
                )?;
                if matches!(
                    phase,
                    Phase::SystemFull | Phase::SystemGoodStage | Phase::SystemFinal
                ) {
                    last_good_probe = joined.admitted;
                }
                if phase == Phase::SystemBad {
                    last_failure = joined.failure;
                }
                let system =
                    if system_proof {
                        let (selected, high, serial, operation) = match phase {
                            Phase::SystemFull => (
                                Generation {
                                    slot: system::Slot::Bad,
                                    id: 2,
                                },
                                2,
                                1,
                                6,
                            ),
                            Phase::SystemBad => (
                                Generation {
                                    slot: system::Slot::Good,
                                    id: 1,
                                },
                                2,
                                2,
                                9,
                            ),
                            Phase::SystemGoodStage => (
                                Generation {
                                    slot: system::Slot::Bad,
                                    id: 3,
                                },
                                3,
                                3,
                                15,
                            ),
                            Phase::SystemRecovery => (
                                Generation {
                                    slot: system::Slot::Good,
                                    id: 1,
                                },
                                3,
                                3,
                                16,
                            ),
                            Phase::SystemFinal => (
                                Generation {
                                    slot: system::Slot::Good,
                                    id: 1,
                                },
                                3,
                                4,
                                20,
                            ),
                            _ => unreachable!(),
                        };
                        SystemExpected::Committed {
                            selected,
                            known_good: Some(1),
                            highest_generation: high,
                            boot_serial: serial,
                            operation,
                            failure: last_failure,
                            probe: ProbeExpected::Exact(last_good_probe.ok_or(
                                "Native3 missing independently verified Good storage probe",
                            )?),
                        }
                    } else {
                        SystemExpected::Unformatted
                    };
                let grant = if system_proof {
                    GrantExpected::Absent
                } else {
                    let events = crate::native3_diagnostics::owners(&serial, &c.manifest.build_id)?;
                    grant_action = remembered_action(
                        phase,
                        grant_action,
                        events
                            .iter()
                            .find(|e| e.prompt.phase == OwnerPhase::Completed)
                            .map(|e| e.prompt.action_digest),
                    );
                    GrantExpected::Record {
                        owner: *b"EVROSION-OWNER01",
                        serial: 1,
                        revision: if matches!(phase, Phase::GrantRevoke | Phase::GrantRefused) {
                            2
                        } else {
                            1
                        },
                        revoked: matches!(phase, Phase::GrantRevoke | Phase::GrantRefused),
                        package: Slot::A,
                        object: ev_file::desktop::Object::Notes,
                        action: grant_action.ok_or("Native3 exact grant action missing")?,
                    }
                };
                let first_phase = matches!(phase, Phase::SystemFull | Phase::GrantRemember);
                let initialized_policy = if phase == Phase::GrantRemember {
                    let middle = bounded(
                        &directory.join("boot/run-001/grant-initial-empty.raw"),
                        storage::DISK_BYTES as u64,
                    )?;
                    Some(crate::native3_disk::inspect(
                        &before,
                        &middle,
                        c.components.packages(),
                        Expected {
                            catalogue: &c.components.catalogue,
                            creation_catalogue: &first.components.catalogue,
                            app: app(),
                            system: SystemExpected::Unformatted,
                            grant: GrantExpected::Empty {
                                owner: *b"EVROSION-OWNER01",
                            },
                            mutations: Mutations {
                                system: false,
                                registry: true,
                                app_data: true,
                                grant_policy: true,
                            },
                        },
                    )?)
                } else {
                    None
                };
                let inspected = crate::native3_disk::inspect(
                    &before,
                    &after,
                    c.components.packages(),
                    Expected {
                        catalogue: &c.components.catalogue,
                        creation_catalogue: &first.components.catalogue,
                        app: app(),
                        system,
                        grant,
                        mutations: Mutations {
                            system: system_proof,
                            registry: first_phase,
                            app_data: first_phase,
                            grant_policy: matches!(
                                phase,
                                Phase::GrantRemember | Phase::GrantRevoke
                            ),
                        },
                    },
                )?;
                let expected_owner_head = match phase {
                    Phase::GrantRemember => initialized_policy
                        .as_ref()
                        .and_then(|d| d.get("grant_policy"))
                        .and_then(|d| d.get("head_sha256")),
                    Phase::GrantRevoke => previous_verified_disk
                        .as_ref()
                        .and_then(|d| d.get("grant_policy"))
                        .and_then(|d| d.get("head_sha256")),
                    Phase::SystemRecovery => previous_verified_disk
                        .as_ref()
                        .and_then(|d| d.get("system"))
                        .and_then(|d| d.get("owner_head_digest")),
                    _ => None,
                };
                if !owner_expected.is_empty() {
                    let head = expected_owner_head
                        .ok_or("Native3 owner prompt lacks independent pre-action disk head")?;
                    let events = crate::native3_diagnostics::owners(&serial, &c.manifest.build_id)?;
                    if events.is_empty()
                        || events.iter().any(|e| json!(e.prompt.head_digest) != *head)
                    {
                        return Err("Native3 prompt CAS head differs from independently observed pre-action durable state".into());
                    }
                }
                if matches!(phase, Phase::GrantCold | Phase::GrantRefused) && before != after {
                    return Err("Native3 cold policy read/refusal mutated continuing disk".into());
                }
                let performance = if phase == Phase::SystemFull {
                    Some(crate::desktop_io::validate_performance(
                        &directory.join("boot/run-001"),
                    )?)
                } else {
                    None
                };
                validation = Some(
                    json!({"record":record,"performance":performance,"scheduling_profile":profile,"memory_image_baseline":baseline,"joined_diagnostics":joined.record,"system_snapshot_state":format!("{:?}",joined.system.state),"initialized_empty_policy":initialized_policy,"disk":inspected}),
                );
                previous_verified_disk = Some(inspected);
                Ok(())
            })();
            let record = json!({"phase":phase.name(),"passed":checked.is_ok(),"error":checked.as_ref().err(),"build_id":c.manifest.build_id,"before":before_record,"after":after_record,"validation":validation});
            storage::json_new(&directory.join("phase-results.json"), &record)?;
            phases.push(record);
            checked?;
        }
        disk.capture(&evidence, "native3-after.raw")?;
        disk.seal()?;
        Ok(())
    })();
    fn visit(path: &Path, base: &Path, out: &mut Vec<Value>) -> Result<()> {
        for e in fs::read_dir(path).map_err(|e| e.to_string())? {
            let p = e.map_err(|e| e.to_string())?.path();
            let m = fs::symlink_metadata(&p).map_err(|e| e.to_string())?;
            if m.is_dir() {
                visit(&p, base, out)?;
            } else if m.is_file() && p.file_name().is_some_and(|n| n != "data.raw") {
                out.push(link(&p, base)?);
            }
        }
        Ok(())
    }
    let mut artifacts = Vec::new();
    let links = visit(&evidence, &evidence, &mut artifacts);
    storage::json_new(
        &evidence.join("results.json"),
        &json!({"schema":1,"kind":if system_proof{"actual-native-composed-system-recovery"}else{"actual-native-durable-owner-grants"},"passed":result.is_ok()&&links.is_ok(),"stage":stage,"error":result.as_ref().err(),"link_error":links.as_ref().err(),"builds":builds,"seed":seed,"expected_boots":if system_proof{5}else{4},"phases":phases,"artifacts":artifacts,"scope":"Actual source-built cold VM graph and owner input; independent readonly durable image, source/image/admission/live authority joins. Bounded Internal conformance, no whole0.1 or physical-machine claim."}),
    )?;
    links?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ev_picker::*;

    struct Remember(Option<intent::Record>);
    impl Handoff for Remember {
        type Delivered = ();
        type Error = ();
        fn revalidate_and_deliver_read(&mut self, request: ReadDelivery<'_>) -> Delivery<(), ()> {
            self.0 = Some(intent::Record::proposed(&request, 1, 1).unwrap());
            Delivery::Delivered(())
        }
    }

    #[test]
    fn revoke_proof_keeps_original_remembered_consent_across_cold_boots() {
        let user = UserId::new(*b"EVROSION-OWNER01").unwrap();
        let requester = Requester {
            user,
            session: SessionId::new([1; 16]).unwrap(),
            app: AppRef {
                app: ev_zion::AppId::new([2; 16]).unwrap(),
                package: ContentDigest::new([3; 32]).unwrap(),
            },
            incarnation: Incarnation::new(BootEpoch::new([4; 16]).unwrap(), 25).unwrap(),
            policy_revision: 1,
            alive: true,
        };
        let object = ObjectView {
            object: ObjectId::new(VolumeId::new(*b"EVRO-USERS-VOL01").unwrap(), 1).unwrap(),
            revision: Revision::new(0, ContentDigest::new([5; 32]).unwrap()).unwrap(),
            permission_revision: 1,
            readable: true,
        };
        let mut picker = Picker::new(PickerEpoch::new([6; 16]).unwrap(), 100).unwrap();
        let approval = picker
            .prepare(requester, object, Persistence::RememberPerUser, 10, 30)
            .unwrap();
        let consent = approval.selection().action_digest();
        let mut handoff = Remember(None);
        assert!(matches!(
            picker
                .commit(
                    approval,
                    Consent {
                        displayed_action: consent,
                        approver: user,
                        origin: Origin::ExplicitOwnerAction,
                    },
                    requester,
                    object,
                    11,
                    &mut handoff,
                )
                .unwrap(),
            Delivery::Delivered(())
        ));
        let active = intent::Record::decode(&handoff.0.unwrap().encode()).unwrap();
        let remembered = remembered_action(Phase::GrantRemember, None, Some(consent));
        assert_eq!(remembered, Some(active.action_digest()));
        let cold = remembered_action(Phase::GrantCold, remembered, None);
        assert_eq!(cold, remembered);

        let mut tombstone = active;
        tombstone.revoke().unwrap();
        let tombstone = intent::Record::decode(&tombstone.encode()).unwrap();
        assert!(tombstone.revoked());
        assert_eq!(tombstone.policy_revision(), 2);
        assert_eq!(tombstone.app(), active.app());
        assert_eq!(tombstone.object(), active.object());
        assert_eq!(tombstone.revision(), active.revision());
        let revoke_action = [0xa7; 32];
        assert_ne!(revoke_action, consent);
        let revoked = remembered_action(Phase::GrantRevoke, cold, Some(revoke_action));
        assert_eq!(revoked, Some(tombstone.action_digest()));
        assert_ne!(revoked, Some(revoke_action));
        assert_eq!(
            remembered_action(Phase::GrantRefused, revoked, None),
            Some(tombstone.action_digest())
        );
        // A later revoke completion cannot fabricate the missing original consent.
        assert_eq!(
            remembered_action(Phase::GrantRevoke, None, Some(revoke_action)),
            None
        );
        assert_eq!(remembered_action(Phase::GrantRemember, revoked, None), None);
    }
}
