//! Human-driven V4 owner session. Each VM retirement and captured selection
//! must validate before a requested restart can launch another retained mode.
use crate::{
    boot::{self, OwnerNetworkBoot},
    build::{self, Result},
    cli::BootOptions,
    network_session::BootSet,
    storage,
};
use serde_json::json;
use std::path::Path;

pub(crate) fn run() -> Result<()> {
    let root =
        crate::doctor::workspace(&std::env::current_dir().map_err(|e| e.to_string())?, None)?
            .canonicalize()
            .map_err(|e| e.to_string())?;
    let options = BootOptions {
        timeout_seconds: 240,
        ..BootOptions::default()
    };
    crate::native_workflow::preview_host(&options)?;
    let parent = storage::directory_beneath(&root, Path::new("build/m6/evidence"))?;
    let evidence = build::unique_directory(&parent, "network-session")?;
    println!("Evidence: {}", evidence.display());
    let (seed, provenance) = crate::native_seed::checkpoint(&root, &evidence)?;
    let retained = storage::SessionDisk::open_network(&root, &seed)?;
    let before = retained.disk.capture(&evidence, "data-before.raw")?;
    let mut rounds = Vec::new();
    let fixture = crate::download_fixture::Server::pending()?;
    let mut update_availability = None;
    let result: Result<()> = (|| {
        let set = BootSet::prepare(&root, &retained, &evidence)?;
        let bytes = retained.disk.bytes()?;
        let mut mode = set.initial_mode(&bytes)?;
        update_availability = Some(match set.publish_b(&root, &bytes, &evidence) {
            Ok(Some(phase)) => {
                fixture.replace_phase(phase)?;
                json!({"public_dev_b":true,"consumer_authorization_claim":false,"author_labels_are_not_acceptance_time":true})
            }
            Ok(None) => {
                println!(
                    "Updates unavailable: this disk already retains a later target floor than the manual DEV B fixture."
                );
                json!({"public_dev_b":false,"reason":"no newer compatible manual DEV fixture"})
            }
            Err(error) => {
                println!("Updates unavailable: {error}. Saved apps remain available.");
                json!({"public_dev_b":false,"reason":error})
            }
        });
        println!(
            "Evrosion network development session. Open Connection and updates to check for an update or select it for the next restart.\nSaved edits use the retained developer disk. Type 'finish' for checked shutdown; closing the window interrupts the VM."
        );
        loop {
            let round = build::unique_directory(&evidence, "vm")?;
            let prior = retained.disk.capture(&round, "data-before.raw")?;
            let boot = boot::boot_owner_network(
                &options,
                OwnerNetworkBoot {
                    manifest: set.path(mode),
                    evidence: &round,
                    disk: &retained.disk,
                    mode,
                },
            );
            let capture = retained.disk.capture(&round, "data-after.raw");
            rounds.push(json!({"mode":mode.owner_fixture(),"build_id":set.manifests[mode.index()].build_id,"before":prior,"after":capture.as_ref().ok(),"error":boot.as_ref().err(),"capture_error":capture.as_ref().err(),"restart_intent":boot.as_ref().ok().and_then(|i| i.as_ref())}));
            capture?;
            let Some(intent) = boot? else {
                return Ok(());
            };
            mode = set.restart_mode(&retained.disk.bytes()?, &intent)?;
            // The next VM uses only this already-retained set. No rebuild,
            // source reselection, automatic IO retry or synthesized intent.
        }
    })();
    let after = retained.disk.capture(&evidence, "data-after.raw");
    storage::json_new(
        &evidence.join("result.json"),
        &json!({"schema":2,"kind":"manual-v4-owner-network-session","checked_shutdown":result.is_ok(),"error":result.as_ref().err(),"disk_created":retained.created,"before":before,"after":after.as_ref().ok(),"capture_error":after.as_ref().err(),"seed":provenance,"rounds":rounds,"fixture_requests_served":fixture.served(),"update_availability":update_availability,"public_fixture":fixture.provenance()?,"fixture_exchanges":fixture.snapshot()?,"scripted_input":false,"human_review_claim":false,"m6_acceptance":false}),
    )?;
    result?;
    after?;
    Ok(())
}
