//! Separately scoped actual negative-network qualification. No ordinary
//! nominal checker or finite operation limit is relaxed by this module.
mod cases;
mod endurance_disk;
mod endurance_flow;
mod endurance_observer;
mod endurance_protocol;
mod endurance_runner;
mod fixture;
mod flow;
mod link_loss;
mod note;
pub(crate) mod records;
pub(crate) mod retirement;
mod runner;
pub(crate) fn endurance_diagnostic(line: &str, build: &str) -> Result<()> {
    if line.starts_with("EVROSION_M6_NEGATIVE_CPU") {
        endurance_protocol::cpu(line, build)?;
    } else if line.starts_with("EVROSION_M6_NEGATIVE_WORK") {
        endurance_protocol::work(line, build)?;
    } else {
        return Err("unknown endurance diagnostic".into());
    }
    Ok(())
}
use crate::{
    build::{Manifest, Result},
    network_negative_contract::Goal,
    storage, vm_clock,
};
use std::{
    path::Path,
    process::{Command, ExitStatus},
    time::Duration,
};

pub(crate) fn run(goal: Goal) -> Result<()> {
    if goal == Goal::Endurance {
        return endurance_runner::run(goal);
    }
    runner::run(goal)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn supervise(
    command: &mut Command,
    serial: &Path,
    errors: &Path,
    timeout: Duration,
    build: &str,
    directory: &Path,
    clock: &mut vm_clock::Prepared,
    root: &Path,
    manifest: &Manifest,
    goal: Goal,
    disk: &storage::Disk,
) -> Result<ExitStatus> {
    if goal == Goal::Endurance {
        return endurance_runner::supervise(
            command, serial, errors, timeout, build, directory, clock, root, manifest, goal, disk,
        );
    }
    runner::supervise(
        command, serial, errors, timeout, build, directory, clock, root, manifest, goal, disk,
    )
}

pub(crate) fn postflight(
    serial: &[u8],
    build: &str,
    status: Option<i32>,
    goal: Goal,
) -> Result<()> {
    final_check(serial, build, status, goal, None).map(|_| ())
}

fn final_check(
    serial: &[u8],
    build: &str,
    status: Option<i32>,
    goal: Goal,
    images: Option<&[String; 9]>,
) -> Result<Final> {
    let observed = records::records(serial, build, images)?;
    let telemetry = std::str::from_utf8(serial)
        .map_err(|_| "endurance finalUTF8")?
        .lines()
        .any(|r| {
            r.starts_with("EVROSION_M6_NEGATIVE_CPU") || r.starts_with("EVROSION_M6_NEGATIVE_WORK")
        });
    let endurance = goal == Goal::Endurance;
    let cancelled = if endurance {
        if crate::native_protocol::states_network(serial, build)?
            .iter()
            .any(|s| s.number("recovery") != Ok(0))
        {
            return Err("endurance entered unexpected Store recovery".into());
        }
        if !cases::app_denials(observed.rows())? {
            return Err("endurance lacks all actual source-bound App authority refusals".into());
        }
        let evidence = endurance_observer::prefix(serial, build, images)?
            .ok_or("endurance missing actual Root")?;
        evidence.complete()?;
        records::without_failure(&observed)?
    } else {
        if telemetry {
            return Err("endurance CPU/work outside its explicit goal".into());
        }
        cases::proof(&observed, goal)?
    };
    crate::boot_protocol::check_network_negative(serial, build, status, &cancelled)?;
    let native = crate::native_protocol::record_network_negative(serial, build, &cancelled)?;
    if native.counts["faults"] != 0
        || native.counts["restarts"] != 0
        || native.counts["grants"] != 0
        || native.counts["app_a_starts"] != if endurance { 2 } else { 1 }
        || native.counts["app_b_starts"] != 0
    {
        return Err("negative changed local App, fault or grant accounting".into());
    }
    let start = native
        .actions
        .iter()
        .find(|a| a.kind == "start")
        .ok_or("negative missing actual local App")?;
    if observed
        .rows()
        .iter()
        .any(|r| r.kind == 1 && (r.process != start.process || r.thread != start.thread))
    {
        return Err("negative App denials differ from actual started Note App".into());
    }
    let ui = crate::session_io::ProbeUi::parse(serial, build)?;
    let expected: &[(u64, u64)] = if endurance {
        &[(1, 1), (2, 2)]
    } else {
        &[(1, 1), (2, 2), (3, 2)]
    };
    for &(nonce, opcode) in expected {
        if ui.note_complete(start.process, nonce, opcode).is_none() {
            return Err("negative missing actual initial Read or before/after Write".into());
        }
    }
    ui.finish()?;
    if goal == Goal::LinkLoss
        && (cancelled.count() != 0 || native.counts["calls"] != native.counts["replies"])
    {
        return Err("linkloss requires ordinary strict call/reply balance".into());
    }
    let stages = crate::network_protocol::records(serial, build)?;
    let stopped = matches!(goal, Goal::DriverStop | Goal::ServiceStop);
    if stages.len() != if stopped { 8 } else { 7 }
        || stages
            .iter()
            .take(6)
            .enumerate()
            .any(|(n, p)| p.stage != n as u64 + 1 || p.result != 0)
        || stages
            .last()
            .is_none_or(|p| p.stage != 7 || p.result != 0 || p.argument != 2)
        || stopped && (stages[6].stage != 8 || stages[6].result != 4 || stages[6].argument != 7)
    {
        return Err("negative initial network/failure/physical retirement order differs".into());
    }
    Ok(Final {
        native,
        canonical_no_ack: cancelled.calls().to_vec(),
    })
}

#[derive(serde::Serialize)]
struct Final {
    native: crate::native_protocol::Record,
    canonical_no_ack: Vec<records::Call>,
}
