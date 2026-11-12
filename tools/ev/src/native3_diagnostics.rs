//! Native3 actual Root owner output and admission evidence. Reports are data;
//! independent runtime/disk joins remain mandatory before accepting a proof.
use crate::{boot_protocol::canonical_number, build::Result, storage};
use ev_diagnostics::owner::{Action, Phase, Prompt};
use serde_json::{Value, json};
use sha2::Digest as _;
use std::path::Path;
#[derive(Clone, Debug)]
pub(crate) struct OwnerEvent {
    pub report: u32,
    pub root_process: u64,
    pub root_thread: u64,
    pub prompt: Prompt,
    pub at: usize,
}
fn field<'a>(v: &'a str, key: &str) -> Result<&'a str> {
    v.strip_prefix(key)
        .and_then(|s| s.strip_prefix('='))
        .ok_or_else(|| format!("Native3 missing {key}"))
}
fn hash(v: &str) -> Result<Vec<u8>> {
    if !v.len().is_multiple_of(2)
        || !v
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Native3 requires canonical lowercase hex".into());
    }
    (0..v.len() / 2)
        .map(|i| u8::from_str_radix(&v[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
fn origin(v: &str, key: &str) -> Result<u64> {
    let n = canonical_number(v, key)?;
    if n == 0 || n == u64::MAX {
        return Err("Native3 zero/unbounded origin".into());
    }
    Ok(n)
}
pub(crate) fn owner_line(line: &str, build: &str) -> Result<OwnerEvent> {
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 2048
        || f.len() != 7
        || f[0] != "EVROSION_NATIVE_OWNER_PROMPT"
        || f[1] != "protocol=1"
        || field(f[2], "build")? != build
        || hash(build)?.len() != 32
    {
        return Err("Native3 owner report malformed/wrong-build".into());
    }
    let report =
        u32::try_from(origin(f[3], "report")?).map_err(|_| "Native3 owner report overflow")?;
    let prompt = Prompt::decode(&hash(field(f[6], "bytes")?)?)
        .map_err(|e| format!("Native3 owner codec: {e:?}"))?;
    Ok(OwnerEvent {
        report,
        root_process: origin(f[4], "root_process")?,
        root_thread: origin(f[5], "root_thread")?,
        prompt,
        at: 0,
    })
}
fn binding(mut a: Prompt, mut b: Prompt) -> bool {
    a.phase = Phase::Display;
    b.phase = Phase::Display;
    a == b
}
fn rendered(event: &OwnerEvent, build: &str) -> Result<Vec<String>> {
    let mut text = String::new();
    event
        .prompt
        .write(&mut text)
        .map_err(|_| "Native3 owner render failed")?;
    if !text.ends_with('\n') {
        return Err("Native3 owner text is not complete".into());
    }
    Ok(text
        .lines()
        .enumerate()
        .map(|(i, l)| {
            format!(
                "EVROSION_NATIVE_OWNER_TEXT protocol=1 build={build} report={} line={i} text={l}",
                event.report
            )
        })
        .collect())
}
struct Owners {
    events: Vec<OwnerEvent>,
    pending_text: bool,
}
fn owner_events(serial: &[u8], build: &str, complete: bool) -> Result<Owners> {
    if serial.len() > 1024 * 1024 {
        return Err("Native3 owner serial over1MiB".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "Native3 owner serial notUTF8")?;
    let mut events = Vec::new();
    let mut report = 0u32;
    let mut root = None;
    let mut expected_text: Vec<String> = Vec::new();
    let mut next_text = 0usize;
    let mut pending_event: Option<OwnerEvent> = None;
    let mut active: Option<Prompt> = None;
    let mut serial_number = 0u64;
    for (at, raw) in text.split_inclusive('\n').enumerate() {
        if !raw.ends_with('\n') {
            if complete {
                return Err("Native3 owner serial truncated".into());
            }
            break;
        }
        let line = raw.trim_end_matches(['\r', '\n']);
        if next_text < expected_text.len() {
            if line != expected_text[next_text] {
                return Err("Native3 owner visible text altered/interleaved/truncated".into());
            }
            next_text += 1;
            if next_text == expected_text.len() {
                events.push(
                    pending_event
                        .take()
                        .ok_or("Native3 owner text has no pending event")?,
                );
            }
            continue;
        }
        if line.starts_with("EVROSION_NATIVE_OWNER_TEXT") {
            return Err("Native3 unexpected/replayed owner visible text".into());
        }
        let diagnostic = [
            "EVROSION_NATIVE_CRASH ",
            "EVROSION_NATIVE_JOB ",
            "EVROSION_NATIVE_SYSTEM ",
            "EVROSION_NATIVE_OWNER_PROMPT ",
        ]
        .iter()
        .any(|p| line.starts_with(p));
        if !diagnostic {
            continue;
        }
        let f: Vec<_> = line.split(' ').collect();
        if f.len() != 7 || field(f[2], "build")? != build {
            return Err("Native3 mixed diagnostic build/fields".into());
        }
        let n = u32::try_from(origin(f[3], "report")?).map_err(|_| "Native3 report overflow")?;
        let actual = (origin(f[4], "root_process")?, origin(f[5], "root_thread")?);
        if n != report.checked_add(1).ok_or("Native3 report overflow")?
            || n > 64
            || root.is_some_and(|r| r != actual)
        {
            return Err("Native3 diagnostic replay/gap/origin change".into());
        }
        report = n;
        root = Some(actual);
        if !line.starts_with("EVROSION_NATIVE_OWNER_PROMPT ") {
            crate::native_diagnostics::line(line, build)?;
            continue;
        }
        let mut event = owner_line(line, build)?;
        event.at = at;
        let prompt = event.prompt;
        match prompt.phase {
            Phase::Display => {
                if active.is_some()
                    || prompt.prompt_serial
                        != serial_number
                            .checked_add(1)
                            .ok_or("Native3 prompt serial overflow")?
                {
                    return Err("Native3 owner prompt replay/overlap".into());
                }
                serial_number = prompt.prompt_serial;
                active = Some(prompt);
            }
            Phase::Armed => {
                if !active.is_some_and(|p| p.phase == Phase::Display && binding(p, prompt)) {
                    return Err("Native3 owner arm lacks exact complete displayed binding".into());
                }
                active = Some(prompt);
            }
            Phase::Confirmed => {
                if !active.is_some_and(|p| p.phase == Phase::Armed && binding(p, prompt)) {
                    return Err(
                        "Native3 owner confirmation preceded complete arm/changed binding".into(),
                    );
                }
                active = Some(prompt);
            }
            Phase::Completed => {
                if !active.is_some_and(|p| p.phase == Phase::Confirmed && binding(p, prompt)) {
                    return Err(
                        "Native3 owner action completed without confirmed exact binding".into(),
                    );
                }
                active = None;
            }
            Phase::Recovery => {
                if !active.is_some_and(|p| p.phase == Phase::Confirmed && binding(p, prompt)) {
                    return Err(
                        "Native3 uncertain owner publication lacks confirmed exact pending binding"
                            .into(),
                    );
                }
                active = None;
            }
            Phase::Cancelled | Phase::Expired => {
                if !active.is_some_and(|p| {
                    matches!(p.phase, Phase::Display | Phase::Armed) && binding(p, prompt)
                }) {
                    return Err(
                        "Native3 owner cancellation/expiry lacks exact pending binding".into(),
                    );
                }
                active = None;
            }
            Phase::Refused => {
                if let Some(p) = active {
                    if !matches!(p.phase, Phase::Display | Phase::Armed | Phase::Confirmed)
                        || !binding(p, prompt)
                    {
                        return Err("Native3 owner refused a different/unpending action".into());
                    }
                } else {
                    // Source may refuse a newly allocated action before any
                    // presentation. This proves neither display nor consent.
                    if prompt.prompt_serial
                        != serial_number
                            .checked_add(1)
                            .ok_or("Native3 prompt serial overflow")?
                    {
                        return Err("Native3 unpresented refusal replayed a prompt".into());
                    }
                    serial_number = prompt.prompt_serial;
                }
                active = None;
            }
        }
        // Raw metadata is not a completed visible status. In particular the
        // live runner cannot approve Armed or finish Completed until the entire
        // exact atomic callback output has arrived, including its last newline.
        expected_text = rendered(&event, build)?;
        next_text = 0;
        pending_event = Some(event);
    }
    if complete && (next_text < expected_text.len() || active.is_some()) {
        return Err("Native3 unfinished owner presentation/consent/action".into());
    }
    Ok(Owners {
        events,
        pending_text: next_text < expected_text.len(),
    })
}
/// Live runner view: incomplete final lines/presentation are retained as pending;
/// an Armed event is returned only after complete canonical visible output.
pub(crate) fn owners(serial: &[u8], build: &str) -> Result<Vec<OwnerEvent>> {
    Ok(owner_events(serial, build, false)?.events)
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct OwnerExpected {
    pub action: Action,
    pub outcome: Phase,
}
/// Retain complete, canonical owner records only after explicit phase matching.
/// Runtime and disk verifiers separately bind accepted effects and tombstones.
pub(crate) fn retain_owners(
    serial: &[u8],
    build: &str,
    expected: &[OwnerExpected],
    directory: &Path,
) -> Result<Value> {
    let checked = owner_events(serial, build, true)?;
    if checked.pending_text {
        return Err("Native3 incomplete owner visible output".into());
    }
    let terminal: Vec<_> = checked
        .events
        .iter()
        .filter(|e| {
            matches!(
                e.prompt.phase,
                Phase::Completed
                    | Phase::Cancelled
                    | Phase::Refused
                    | Phase::Expired
                    | Phase::Recovery
            )
        })
        .collect();
    if terminal.len() != expected.len()
        || terminal
            .iter()
            .zip(expected)
            .any(|(e, x)| e.prompt.action != x.action || e.prompt.phase != x.outcome)
    {
        return Err("Native3 owner action/outcome differs from explicit phase".into());
    }
    let output = directory.join("owner-diagnostics");
    std::fs::create_dir(&output).map_err(|e| e.to_string())?;
    let mut records = Vec::new();
    for event in &checked.events {
        let bytes = event
            .prompt
            .encode()
            .map_err(|e| format!("Native3 owner retention codec: {e:?}"))?;
        let name = format!("owner-{:03}.bin", event.report);
        storage::immutable_new(&output.join(&name), &bytes)?;
        records.push(json!({"report":event.report,"root_process":event.root_process,"root_thread":event.root_thread,"action":format!("{:?}",event.prompt.action),"phase":event.prompt.phase.name(),"prompt_serial":event.prompt.prompt_serial,"action_digest":event.prompt.action_digest,"head_digest":event.prompt.head_digest,"binary":name,"sha256":hex_digest(&sha2::Sha256::digest(bytes)),"bytes":bytes.len()}));
    }
    let record = json!({"schema":1,"events":records,"canonical_visible_output_checked":true,"scope":"actual authenticated Root prompt output/phase order; capability effects and durable state verified separately"});
    storage::json_new(&output.join("record.json"), &record)?;
    Ok(record)
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CurrentExpected {
    pub generation: crate::native3_disk::Generation,
    pub boot_serial: u64,
    pub phase: ev_diagnostics::system::Phase,
}
#[derive(Clone, Copy, Debug)]
pub(crate) enum FailureExpected {
    None,
    CurrentMissingProgress { operation: u64, sequence: u64 },
    Exact(ev_store::LastFailure),
}
pub(crate) struct Expected<'a> {
    pub recovery: bool,
    pub current: Option<CurrentExpected>,
    pub selected: Option<crate::native3_disk::Generation>,
    pub initial_selected: Option<crate::native3_disk::Generation>,
    pub known_good: Option<u64>,
    pub failure: FailureExpected,
    pub shell_faults: usize,
    pub app_faults: usize,
    pub job_roles: &'a [ev_diagnostics::live::Role],
    pub owners: &'a [OwnerExpected],
    pub managed_reads: usize,
    pub inhibits: usize,
}
pub(crate) struct Verified {
    pub record: Value,
    pub admitted: Option<ev_store::AdmissionReport>,
    pub system: ev_diagnostics::system::Snapshot,
    pub failure: Option<ev_store::LastFailure>,
}
fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn bytes32(v: &str) -> Result<[u8; 32]> {
    hash(v)?
        .try_into()
        .map_err(|_| "Native3 exact32byte digest missing".into())
}
fn manifest_json(m: ev_store::GenerationManifest) -> Value {
    json!({"generation":m.generation.get(),"cohort":m.cohort,"supervisor_image":m.supervisor_image,"abi":m.abi,"health_contract":m.health_contract,"health_version":m.health_version,"required_checks":m.required_checks})
}
fn failure_wire(f: ev_store::LastFailure) -> ev_diagnostics::system::Failure {
    ev_diagnostics::system::Failure {
        generation: f.generation.get(),
        boot_serial: f.boot_serial,
        attempts: f.attempts,
        reason: match f.reason {
            ev_store::LastFailureReason::ProcessFault => 1,
            ev_store::LastFailureReason::MissingProgress => 2,
            ev_store::LastFailureReason::StorageFailure => 3,
            ev_store::LastFailureReason::AttemptBudgetExhausted => 4,
        },
        supervisor_image: f.supervisor_image,
        process_stamp: f.process_stamp,
        operation: f.operation.get(),
        sequence: f.sequence,
    }
}
/// Verify actual mode-bound Root startup, current System admission, canonical
/// owner output, live mechanism effects and complete source-collected capsules.
/// Caller supplies expected phase facts; source markers never set expectations.
#[allow(clippy::too_many_arguments)]
pub(crate) fn retain(
    serial: &[u8],
    build: &str,
    recipe: &str,
    package_bytes: [&[u8]; 2],
    catalogue: &[u8],
    startup_manifest: &[u8],
    expected: Expected<'_>,
    directory: &Path,
) -> Result<Verified> {
    use crate::{native_diagnostics as d, native3_protocol as p};
    use ev_diagnostics::{
        Component, Crash,
        live::Role,
        system::{Phase as SystemPhase, Snapshot, State},
    };
    use ev_root_supervisor::native_plan::{self as n, system};
    use ev_userspace_contract::{
        Context,
        root_v2::{graph::Child, native},
    };
    use sha2::{Digest as _, Sha256};
    use std::collections::BTreeSet;
    if serial.len() > 1024 * 1024 || !serial.ends_with(b"\n") {
        return Err("Native3 diagnostic serial oversized/truncated".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "Native3 diagnostics notUTF8")?;
    let runtime = p::record(serial, build, expected.recovery)?;
    let observations = p::observations(serial, build)?;
    let commons: Vec<_> = observations
        .iter()
        .filter_map(|(at, e)| {
            if let p::Event::Common(c) = e {
                Some((*at, c))
            } else {
                None
            }
        })
        .collect();
    if commons.len() != 1 {
        return Err("Native3 requires one actual protected Root+Block prefix".into());
    }
    let (common_at, common) = commons[0];
    let cat = native::catalogue::Catalogue::decode(catalogue)
        .map_err(|e| format!("Native3 catalogue: {e:?}"))?;
    if common.mode != cat.boot_mode() as u64
        || expected.recovery != (common.mode == 2)
        || bytes32(&common.root_image)? != cat.base().root_image()
        || bytes32(&common.block_image)?
            != cat.base().images().nth(Child::Block.index()).unwrap().image
        || bytes32(recipe)? != cat.base().kernel_input()
        || startup_manifest.len() != native::MANIFEST_CURRENT_BYTES
        || bytes32(&common.root_manifest)? != <[u8; 32]>::from(Sha256::digest(startup_manifest))
    {
        return Err(
            "Native3 actual prefix differs from exact retained mode/source/Root/Block/manifest"
                .into(),
        );
    }
    let context = Context {
        epoch: common.root_epoch,
        incarnation: common.root_incarnation,
        process: common.root_process,
        limits: ev_root_supervisor::desktop_plan::ROOT_LIMITS,
        manifest: bytes32(&common.root_manifest)?,
        authority: startup_manifest[128..160].try_into().unwrap(),
    };
    let packages = n::Packages::verify(catalogue, context, package_bytes[0], package_bytes[1])
        .map_err(|e| format!("Native3 actual source package/manifest association: {e:?}"))?;
    let selected = expected
        .selected
        .map(|g| system::manifest(&packages, g.slot, g.id))
        .transpose()
        .map_err(|e| format!("Native3 expected System manifest: {e:?}"))?;
    let admitted = expected
        .current
        .map(|c| {
            let manifest = system::manifest(&packages, c.generation.slot, c.generation.id)
                .map_err(|e| format!("Native3 admitted manifest: {e:?}"))?;
            system::admission(
                &packages,
                context,
                common.root_process,
                common.root_thread,
                ev_store::BootPlan {
                    manifest,
                    serial: c.boot_serial,
                    candidate: c.generation.id != 1,
                    attempt: 1,
                },
            )
            .map_err(|e| format!("Native3 independent admission stamp: {e:?}"))
        })
        .transpose()?;
    let failure = match expected.failure {
        FailureExpected::None => None,
        FailureExpected::Exact(f) => Some(f),
        FailureExpected::CurrentMissingProgress {
            operation,
            sequence,
        } => {
            let a = admitted.ok_or("Native3 current failure lacks actual admission")?;
            if expected.current.unwrap().phase != SystemPhase::Failed {
                return Err("Native3 MissingProgress current phase differs".into());
            }
            Some(ev_store::LastFailure {
                generation: a.generation,
                boot_serial: a.boot_serial,
                attempts: 1,
                reason: ev_store::LastFailureReason::MissingProgress,
                supervisor_image: a.supervisor_image,
                process_stamp: Some(a.process_stamp),
                operation: ev_store::OperationId::new(operation)
                    .ok_or("Native3 invalid failure operation")?,
                sequence,
            })
        }
    };
    let mut reports = Vec::new();
    let mut faults = Vec::new();
    let mut queries = Vec::new();
    let mut report_number = 0u32;
    let mut finished = false;
    for (at, raw) in text.split_inclusive('\n').enumerate() {
        let line = raw.trim_end_matches(['\r', '\n']);
        if line.starts_with("EVROSION_M5_NATIVE ")
            || line.starts_with("EVROSION_M5_NATIVE_RECOVERY ")
        {
            finished = true;
            continue;
        }
        if line.starts_with("EVROSION_NATIVE_OWNER_PROMPT ") {
            let e = owner_line(line, build)?;
            if finished
                || e.report != report_number + 1
                || e.root_process != common.root_process
                || e.root_thread != common.root_thread
            {
                return Err(
                    "Native3 owner global sequence/actual origin/late frame mismatch".into(),
                );
            }
            report_number = e.report;
            continue;
        }
        if [
            "EVROSION_NATIVE_CRASH",
            "EVROSION_NATIVE_JOB",
            "EVROSION_NATIVE_SYSTEM",
            "EVROSION_NATIVE_FAULT",
        ]
        .iter()
        .any(|prefix| line.starts_with(prefix))
        {
            if finished {
                return Err("Native3 diagnostic after actual completion".into());
            }
            match d::parse(line, build, at)? {
                d::Event::Report(r) => {
                    if r.serial != report_number + 1
                        || r.serial > 64
                        || r.origin != (common.root_process, common.root_thread)
                    {
                        return Err("Native3 global report replay/origin differs".into());
                    }
                    report_number = r.serial;
                    reports.push(r);
                }
                d::Event::Fault(f) => faults.push(f),
                d::Event::Query(q) => {
                    if q.sequence as usize != queries.len() + 1
                        || q.origin != (common.root_process, common.root_thread)
                        || queries.last().is_some_and(|p: &d::Query| p.tick > q.tick)
                    {
                        return Err("Native3 actual Job query origin/sequence/clock differs".into());
                    }
                    queries.push(q);
                }
            }
        }
    }
    if !finished {
        return Err("Native3 completed runtime footer missing".into());
    }
    let systems: Vec<_> = reports
        .iter()
        .filter(|r| r.kind == d::Kind::System)
        .collect();
    if systems.is_empty() {
        return Err("Native3 complete System inspection missing".into());
    }
    let snapshots: Vec<_> = systems
        .iter()
        .map(|r| Snapshot::decode(&r.bytes).map_err(|e| format!("Native3 System snapshot: {e:?}")))
        .collect::<Result<_>>()?;
    let snapshot = *snapshots.last().unwrap();
    let admitted_manifest = expected
        .current
        .map(|c| system::manifest(&packages, c.generation.slot, c.generation.id))
        .transpose()
        .map_err(|e| format!("Native3 current manifest: {e:?}"))?;
    let wanted_current = admitted.map(|a| ev_diagnostics::system::Admission {
        manifest: system::manifest_digest(&admitted_manifest.unwrap()),
        generation: a.generation.get(),
        boot_serial: a.boot_serial,
        process_stamp: a.process_stamp,
        phase: expected.current.unwrap().phase,
    });
    let wire_manifest = |m: ev_store::GenerationManifest| ev_diagnostics::system::Manifest {
        generation: m.generation.get(),
        cohort: m.cohort,
        supervisor_image: m.supervisor_image,
        abi: m.abi,
        health_contract: m.health_contract,
        health_version: m.health_version,
        required_checks: m.required_checks,
    };
    let wanted_selected = selected.map(wire_manifest);
    let initial_selected = expected
        .initial_selected
        .map(|g| system::manifest(&packages, g.slot, g.id))
        .transpose()
        .map_err(|e| format!("Native3 initial manifest: {e:?}"))?
        .map(wire_manifest);
    let initial_kg = if expected.current.is_some_and(|c| c.boot_serial == 1) {
        None
    } else {
        expected.known_good
    };
    let initial_failure = if matches!(
        expected.failure,
        FailureExpected::CurrentMissingProgress { .. }
    ) {
        None
    } else {
        failure.map(failure_wire)
    };
    if snapshot.state
        != if selected.is_some() {
            State::Committed
        } else {
            State::Unformatted
        }
        || snapshot.selected != wanted_selected
        || snapshot.known_good != expected.known_good
        || snapshot.current != wanted_current
        || snapshot.last_failure != failure.map(failure_wire)
    {
        return Err(
            "Native3 final System selected/KnownGood/current admission/typed failure differs"
                .into(),
        );
    }
    let mut probation = None;
    let mut pending_metadata = false;
    let mut final_at = None;
    let mut selected_final_seen = false;
    let mut prior_tick = 0;
    for (i, (report, s)) in systems.iter().zip(&snapshots).enumerate() {
        if s.first_tick < prior_tick {
            return Err("Native3 System observation clock regressed".into());
        }
        prior_tick = s.last_tick;
        if i == 0 && s.current.is_none() {
            if s.selected != initial_selected
                || s.known_good != initial_kg
                || s.last_failure != initial_failure
                || s.state
                    != if initial_selected.is_some() {
                        State::Committed
                    } else {
                        State::Unformatted
                    }
            {
                return Err(
                    "Native3 initial System read differs from accepted prior cold phase".into(),
                );
            }
            continue;
        }
        if s.current.is_none()
            && expected.current.is_some()
            && probation.is_none()
            && final_at.is_none()
            && !pending_metadata
            && s.selected == admitted_manifest.map(wire_manifest)
            && s.known_good == initial_kg
            && s.last_failure == initial_failure
            && s.state == State::Committed
        {
            pending_metadata = true;
            continue;
        }
        if let Some(mut current) = wanted_current {
            if s.current.is_some_and(|c| c.phase == SystemPhase::Probation) {
                current.phase = SystemPhase::Probation;
                if probation.is_some()
                    || final_at.is_some()
                    || s.current != Some(current)
                    || s.selected != admitted_manifest.map(wire_manifest)
                    || s.known_good != initial_kg
                    || s.last_failure != initial_failure
                {
                    return Err(
                        "Native3 probation snapshot does not bind unique current admission".into(),
                    );
                }
                probation = Some(report.at);
            } else {
                if s.current != wanted_current {
                    return Err("Native3 current admission changed after probation".into());
                }
                let selected_current = admitted_manifest.map(wire_manifest);
                if s.selected != wanted_selected && s.selected != selected_current
                    || selected_final_seen && s.selected != wanted_selected
                    || s.known_good != expected.known_good
                    || s.last_failure != failure.map(failure_wire)
                {
                    return Err("Native3 current health/next-selection progression differs".into());
                }
                if expected
                    .current
                    .is_some_and(|c| c.phase == SystemPhase::Failed)
                    && s.selected != wanted_selected
                {
                    return Err(
                        "Native3 failed candidate did not durably select expected fallback".into(),
                    );
                }
                selected_final_seen |= s.selected == wanted_selected;
                final_at.get_or_insert(report.at);
            }
        } else if s.current.is_some() {
            return Err(
                "Native3 pre-admission/Recovery invented executed System generation".into(),
            );
        } else if s.selected != wanted_selected
            || s.known_good != expected.known_good
            || s.last_failure != failure.map(failure_wire)
        {
            return Err("Native3 final unadmitted System state differs".into());
        }
    }
    let self_queries: Vec<_> = observations
        .iter()
        .filter_map(|(at, e)| {
            if let p::Event::SelfIdentity(s) = e {
                Some((*at, s))
            } else {
                None
            }
        })
        .collect();
    for (i, (at, s)) in self_queries.iter().enumerate() {
        if s.sequence != i as u64 + 1
            || s.process != common.root_process
            || s.thread != common.root_thread
            || s.epoch != common.root_epoch
            || s.incarnation != common.root_incarnation
            || s.manifest != common.root_manifest
            || *at <= common_at
            || self_queries
                .get(i.wrapping_sub(1))
                .is_some_and(|(_, p)| p.tick > s.tick)
        {
            return Err(
                "Native3 actual Root live observation replay/identity/context/clock mismatch"
                    .into(),
            );
        }
    }
    if common.mode == 0 && !self_queries.is_empty() {
        return Err("Standalone invented System live admission query".into());
    }
    if expected.current.is_some() && self_queries.len() < 2 {
        return Err("Native3 System health lacks actual Root live observations".into());
    }
    if let Some(current) = expected.current {
        if self_queries.len() < 3 {
            return Err(
                "Native3 System health requires actual BeginBoot/anchor/fresh-live queries".into(),
            );
        }
        let (q1_at, q1) = self_queries[0];
        let (q2_at, q2) = self_queries[1];
        let (q3_at, q3) = self_queries[2];
        let final_at = final_at.ok_or("Native3 current System lacks final health snapshot")?;
        if q1_at >= q2_at
            || q2_at >= q3_at
            || q1.tick > q2.tick
            || q2.tick > q3.tick
            || probation.is_some_and(|at| at < q2_at || at > q3_at)
            || q3_at > final_at
        {
            return Err("Native3 actual health live observations do not fence admission/probation/final report".into());
        }
        if current.phase == SystemPhase::Failed
            && q3.tick
                < q2.tick
                    .checked_add(64)
                    .ok_or("Native3 health deadline overflow")?
        {
            return Err("Native3 MissingProgress preceded actual fixed64tick live deadline".into());
        }
        if current.phase == SystemPhase::Healthy
            && q3.tick
                >= q2
                    .tick
                    .checked_add(64)
                    .ok_or("Native3 health deadline overflow")?
        {
            return Err("Native3 healthy promotion arrived after fixed64tick deadline".into());
        }
        if current.phase == SystemPhase::Healthy {
            let (q4_at, q4) = *self_queries
                .get(3)
                .ok_or("Native3 healthy System lacks actual post-probe Root liveness")?;
            if q4_at <= q3_at || q4_at >= final_at || q4.tick < q3.tick {
                return Err(
                    "Native3 post-probe Root freshness does not precede actual health publication"
                        .into(),
                );
            }
        }
    }
    let critical: Vec<_> = observations
        .iter()
        .filter_map(|(at, e)| {
            if let p::Event::Critical(c) = e {
                Some((*at, c))
            } else {
                None
            }
        })
        .collect();
    let mut ready_ids = BTreeSet::new();
    for (_, c) in &critical {
        if !ready_ids.insert((c.process, c.thread)) {
            return Err("Native3 critical Ready replayed actual actor identity".into());
        }
    }
    if expected
        .current
        .is_some_and(|c| c.phase == SystemPhase::Healthy)
    {
        let (anchor_at, anchor) = self_queries[1];
        let (fresh_at, fresh) = self_queries[2];
        if !critical.iter().any(|(at, c)| {
            *at > anchor_at && *at < fresh_at && c.tick >= anchor.tick && c.tick <= fresh.tick
        }) {
            return Err(
                "Native3 healthy System lacks actual critical Ready within anchored live interval"
                    .into(),
            );
        }
    }
    let good_shell = cat.base().images().next().unwrap().image;
    let bad_shell = cat.bad_shell().image;
    for (at, c) in &critical {
        if *at <= common_at || bytes32(&c.image)? != good_shell {
            return Err("Native3 critical Ready is not actual selected Good Shell".into());
        }
    }
    if let Some(current) = expected.current {
        match current.phase {
            SystemPhase::Healthy if critical.is_empty() => {
                return Err("Native3 healthy System lacks actual critical Shell Ready".into());
            }
            SystemPhase::Failed if !critical.is_empty() => {
                return Err("Native3 failed Bad System invented critical Ready".into());
            }
            _ => {}
        }
    }
    let actions: Vec<_> = text
        .lines()
        .enumerate()
        .filter(|(_, l)| l.starts_with("EVROSION_M5_NATIVE_ACTION"))
        .map(|(at, l)| crate::native_protocol::action(l, build).map(|a| (at, a)))
        .collect::<Result<_>>()?;
    if queries
        .iter()
        .any(|q| q.status == 1 && (q.denial == 3 || q.capability == 0 || q.field != 0))
    {
        return Err(
            "Native3 actual Job negative proof has unclassified/wrong authority failure".into(),
        );
    }
    let wrong_kind = queries
        .iter()
        .filter(|q| q.status == 1 && q.denial == 1)
        .count();
    if wrong_kind != usize::from(expected.job_roles.contains(&Role::Boot)) {
        return Err("Native3 inspector wrong-kind denial count differs".into());
    }
    let grouped = d::groups(&queries)?;
    let mut used_groups = BTreeSet::new();
    let mut used_faults = BTreeSet::new();
    let mut crash_records = Vec::new();
    let app_packages = [
        packages
            .checked(n::Slot::A)
            .map_err(|e| format!("Native3 A: {e:?}"))?,
        packages
            .checked(n::Slot::B)
            .map_err(|e| format!("Native3 B: {e:?}"))?,
    ];
    let crashes: Vec<_> = reports
        .iter()
        .filter(|r| r.kind == d::Kind::Crash)
        .collect();
    if crashes.len() != expected.shell_faults + expected.app_faults || faults.len() != crashes.len()
    {
        return Err("Native3 actual fault/capsule count differs".into());
    }
    let mut observed_shell = 0;
    let mut observed_app = 0;
    for r in crashes {
        let c = Crash::decode(&r.bytes).map_err(|e| format!("Native3 crash codec: {e:?}"))?;
        let capture = c.capture();
        let provenance = c.provenance();
        let matching: Vec<_> = faults
            .iter()
            .enumerate()
            .filter(|(_, f)| f.at < r.at && f.words == d::capture_words(capture))
            .collect();
        if matching.len() != 1 {
            return Err("Native3 capsule lacks unique prior actual24word fault".into());
        }
        let (index, f) = matching[0];
        if !used_faults.insert(index)
            || f.image != provenance.image
            || (f.epoch, f.incarnation) != (common.root_epoch, common.root_incarnation)
            || (provenance.epoch, provenance.incarnation) != (f.epoch, f.incarnation)
        {
            return Err("Native3 crash actual source/context/capture replay differs".into());
        }
        let expected_generation = wanted_current.map(|c| c.manifest);
        if provenance.generation != expected_generation {
            return Err("Native3 crash running System generation provenance differs".into());
        }
        match f.actor {
            1 => {
                observed_shell += 1;
                let selected_image = if expected
                    .current
                    .is_some_and(|c| c.generation.slot == system::Slot::Bad)
                {
                    bad_shell
                } else {
                    good_shell
                };
                if provenance.component
                    != Component::Service(Child::Shell.image().selector() as u16)
                    || provenance.package.is_some()
                    || provenance.image != selected_image
                    || provenance.component_build != cat.base().kernel_input()
                {
                    return Err("Native3 Shell crash not retained selected cohort".into());
                }
            }
            5 => {
                observed_app += 1;
                let p = app_packages[0];
                if provenance.component != Component::Application(p.app().claimed_app)
                    || provenance.package != Some(p.id().bytes())
                    || provenance.component_build != p.app().build_id
                    || provenance.image != p.executable().digest
                {
                    return Err("Native3 App crash package/source differs".into());
                }
            }
            _ => return Err("Native3 unexpected actor fault".into()),
        }
        let gs: Vec<_> = grouped
            .iter()
            .enumerate()
            .filter(|(_, g)| g.first > f.at && g.last < r.at && g.values[0] == capture.job)
            .collect();
        if gs.len() != 1 {
            return Err("Native3 crash actual pre-Reap Job query absent/ambiguous".into());
        }
        let (gi, g) = gs[0];
        let retired_after = if f.actor == 5 {
            let start = actions.iter().find(|(at, a)| {
                *at < f.at
                    && a.kind == "start"
                    && (a.process, a.thread) == (capture.process, capture.thread)
                    && a.image_sha256 == hex_digest(&f.image)
            });
            let reap = actions.iter().find(|(at, a)| {
                *at > g.last
                    && a.kind == "reap"
                    && (a.process, a.thread) == (capture.process, capture.thread)
                    && a.image_sha256 == hex_digest(&f.image)
            });
            if start.is_none() || reap.is_none() {
                return Err("Native3 App fault/captureJob not tied to actual start and later authority retirement".into());
            }
            reap.unwrap().0
        } else {
            g.last
        };
        if !used_groups.insert(gi)
            || g.capability == 0
            || !queries.iter().any(|q| {
                q.status == 1
                    && q.denial == 2
                    && q.capability == g.capability
                    && q.at > retired_after
            })
        {
            return Err("Native3 fault Job authority/retirement denial incomplete".into());
        }
        crash_records.push(json!({"report":r.serial,"actor":f.actor,"image":provenance.image,"generation":provenance.generation,"capture":f.words,"job_capability":g.capability,"query_first":g.first_sequence,"query_last":g.last_sequence}));
    }
    if observed_shell != expected.shell_faults || observed_app != expected.app_faults {
        return Err("Native3 separate actual Shell/App fault counts differ".into());
    }
    let profiles = crate::native_profile::finished(
        serial,
        build,
        (expected.shell_faults + expected.app_faults) as u64,
        Some(cat.boot_mode() as u64),
    )?;
    if (
        profiles[0].counts["current_process"],
        profiles[0].counts["current_thread"],
    ) != (common.root_process, common.root_thread)
        || (
            profiles[4].counts["current_process"],
            profiles[4].counts["current_thread"],
        ) != (common.block_process, common.block_thread)
    {
        return Err("Native3 actual profile Root/Block differ from protected prefix".into());
    }
    for (_, c) in &critical {
        if (c.process, c.thread)
            != (
                profiles[1].counts["current_process"],
                profiles[1].counts["current_thread"],
            )
            && !faults.iter().any(|f| {
                f.actor == 1
                    && (f.words[1], f.words[2]) == (c.process, c.thread)
                    && hex_digest(&f.image) == c.image
            })
        {
            return Err(
                "Native3 critical Ready is not actual current or captured Shell incarnation".into(),
            );
        }
    }
    if expected.recovery
        && profiles.iter().enumerate().any(|(i, p)| {
            i != 0
                && i != 4
                && (p.counts["current_process"] != 0
                    || p.counts["incarnations"] != 0
                    || p.counts["captures"] != 0)
        })
    {
        return Err("Native3 independent Recovery executed an ordinary GUI/App actor".into());
    }
    let rows: Vec<_> = reports.iter().filter(|r| r.kind == d::Kind::Job).collect();
    if rows.len() != expected.job_roles.len() {
        return Err("Native3 actual Job row role count differs".into());
    }
    let mut ids = BTreeSet::new();
    let mut previous_at = 0;
    let mut previous_job_tick = 0;
    let mut row_caps = BTreeSet::new();
    let mut row_records = Vec::new();
    for (r, role) in rows.into_iter().zip(expected.job_roles) {
        let row = ev_diagnostics::live::Row::decode(&r.bytes)
            .map_err(|e| format!("Native3 Job row: {e:?}"))?;
        if row.role != *role || !ids.insert(row.job.diagnostic_id) || r.at <= previous_at {
            return Err("Native3 live Job roles/identity/order differ".into());
        }
        let previous_report_at = previous_at;
        previous_at = r.at;
        let matches: Vec<_> = grouped
            .iter()
            .enumerate()
            .filter(|(_, g)| {
                g.last < r.at
                    && g.first > previous_report_at
                    && g.values == d::job_values(row.job)
                    && row.job.first_tick <= g.first_tick
                    && row.job.last_tick >= g.last_tick
            })
            .collect();
        if matches.len() != 1 {
            return Err("Native3 Job row lacks exact actual query values/ticks".into());
        }
        let (i, g) = matches[0];
        if !used_groups.insert(i)
            || !row_caps.insert(g.capability)
            || row.job.first_tick < previous_job_tick
            || (*role == Role::Root) != (g.capability == 0)
        {
            return Err("Native3 Job authority mismatch/replay".into());
        }
        previous_job_tick = row.job.last_tick;
        let image = match role {
            Role::Boot => [0; 32],
            Role::Root => cat.base().root_image(),
            Role::Application => app_packages[0].executable().digest,
            Role::Shell => {
                if expected
                    .current
                    .is_some_and(|c| c.generation.slot == system::Slot::Bad)
                {
                    bad_shell
                } else {
                    good_shell
                }
            }
            Role::Input => cat.base().images().nth(1).unwrap().image,
            Role::File => cat.base().images().nth(2).unwrap().image,
            Role::Block => cat.base().images().nth(3).unwrap().image,
            Role::Display => cat.base().images().nth(5).unwrap().image,
        };
        if row.image != image
            || row.package
                != if *role == Role::Application {
                    Some(app_packages[0].id().bytes())
                } else {
                    None
                }
        {
            return Err("Native3 live Job row image/package differs".into());
        }
        if *role == Role::Root
            && (row.identity.process, row.identity.thread)
                != (common.root_process, common.root_thread)
        {
            return Err("Native3 Root Job not actual Root identity".into());
        }
        if *role == Role::Block
            && (row.identity.process, row.identity.thread)
                != (common.block_process, common.block_thread)
        {
            return Err("Native3 Block Job not actual protected Block identity".into());
        }
        if *role == Role::Boot {
            if row.started
                || row.identity.process != 0
                || row.identity.thread != 0
                || row.image != [0; 32]
                || row.package.is_some()
            {
                return Err("Native3 Boot Job row invented execution".into());
            }
        } else {
            let index = match role {
                Role::Root => 0,
                Role::Shell => 1,
                Role::Input => 2,
                Role::File => 3,
                Role::Block => 4,
                Role::Application => 5,
                Role::Display => 6,
                Role::Boot => unreachable!(),
            };
            let profile = &profiles[index].counts;
            if !row.started
                || (
                    row.identity.process,
                    row.identity.thread,
                    row.job.diagnostic_id,
                ) != (
                    profile["current_process"],
                    profile["current_thread"],
                    profile["current_job"],
                )
            {
                return Err(
                    "Native3 live Job row differs from actual current actor profile".into(),
                );
            }
        }
        row_records.push(json!({"report":r.serial,"role":format!("{role:?}"),"job":row.job.diagnostic_id,"process":row.identity.process,"thread":row.identity.thread,"image":row.image,"capability":g.capability,"query_first":g.first_sequence,"query_last":g.last_sequence}));
    }
    if queries
        .iter()
        .any(|q| q.status == 1 && q.denial == 1 && row_caps.contains(&q.capability))
    {
        return Err("Native3 wrong-kind negative reused a live actual Job capability".into());
    }
    if !expected.job_roles.is_empty()
        && (systems.last().unwrap().at <= previous_at || snapshot.first_tick < previous_job_tick)
    {
        return Err("Native3 final inspector System read preceded actual Job observations".into());
    }
    if used_groups.len() != grouped.len() {
        return Err("Native3 unused/replayed actual Job query group".into());
    }
    let managed: Vec<_> = observations
        .iter()
        .filter_map(|(at, e)| {
            if let p::Event::Managed(m) = e {
                Some((*at, m))
            } else {
                None
            }
        })
        .collect();
    let inhibits: Vec<_> = observations
        .iter()
        .filter_map(|(at, e)| {
            if let p::Event::Inhibit(m) = e {
                Some((*at, m))
            } else {
                None
            }
        })
        .collect();
    if managed.len() != expected.managed_reads || inhibits.len() != expected.inhibits {
        return Err("Native3 managed Read/inhibit actual effects differ".into());
    }
    let mut tickets = BTreeSet::new();
    for (at, m) in &managed {
        if (m.root_process, m.root_thread) != (common.root_process, common.root_thread)
            || !tickets.insert((m.process, m.thread, m.nonce, m.ticket))
            || m.image != format!("{:x}", Sha256::digest(app_packages[0].executable().bytes))
            || !actions.iter().any(|(pos, a)| {
                *pos < *at
                    && a.kind == "start"
                    && (a.process, a.thread) == (m.process, m.thread)
                    && a.image_sha256 == m.image
            })
            || actions.iter().any(|(pos, a)| {
                *pos < *at
                    && matches!(a.kind.as_str(), "stop" | "reap")
                    && (a.process, a.thread) == (m.process, m.thread)
            })
        {
            return Err(
                "Native3 managed fresh Read lacks actual live accepted App/Root provenance".into(),
            );
        }
    }
    for (at, i) in &inhibits {
        if (i.root_process, i.root_thread) != (common.root_process, common.root_thread)
            || !managed.iter().any(|(pos, m)| {
                *pos < *at
                    && (m.process, m.thread, m.image.as_str())
                        == (i.process, i.thread, i.image.as_str())
            })
            || !actions.iter().any(|(pos, a)| {
                *pos > *at && a.kind == "stop" && (a.process, a.thread) == (i.process, i.thread)
            })
            || !actions.iter().any(|(pos, a)| {
                *pos > *at && a.kind == "reap" && (a.process, a.thread) == (i.process, i.thread)
            })
            || managed
                .iter()
                .any(|(pos, m)| *pos > *at && (m.process, m.thread) == (i.process, i.thread))
        {
            return Err("Native3 revoke inhibit lacks actual ordered branch retirement".into());
        }
    }
    let owner_checked = owner_events(serial, build, true)?;
    let terminal: Vec<_> = owner_checked
        .events
        .iter()
        .filter(|e| {
            matches!(
                e.prompt.phase,
                Phase::Completed
                    | Phase::Cancelled
                    | Phase::Refused
                    | Phase::Expired
                    | Phase::Recovery
            )
        })
        .collect();
    if terminal.len() != expected.owners.len()
        || terminal
            .iter()
            .zip(expected.owners)
            .any(|(e, x)| e.prompt.action != x.action || e.prompt.phase != x.outcome)
    {
        return Err("Native3 owner explicit action outcomes differ".into());
    }
    for display in owner_checked
        .events
        .iter()
        .filter(|e| e.prompt.phase == Phase::Display)
    {
        let prompt = display.prompt;
        let same: Vec<_> = owner_checked
            .events
            .iter()
            .filter(|e| e.prompt.prompt_serial == prompt.prompt_serial)
            .collect();
        let confirmed = same.iter().find(|e| e.prompt.phase == Phase::Confirmed);
        let completed = same.iter().find(|e| e.prompt.phase == Phase::Completed);
        if prompt.owner != *b"EVROSION-OWNER01"
            || (display.root_process, display.root_thread)
                != (common.root_process, common.root_thread)
        {
            return Err(
                "Native3 owner prompt scope/origin differs from actual bounded owner".into(),
            );
        }
        match prompt.action {
            Action::RememberRead | Action::RevokeRead => {
                if prompt.app != cat.base().app_id()
                    || prompt.package != app_packages[0].id().bytes()
                    || prompt.volume != *b"EVRO-USERS-VOL01"
                    || prompt.object != 1
                    || prompt.object_counter != 0
                    || prompt.object_digest
                        != <[u8; 32]>::from(Sha256::digest(ev_file::desktop::SEED_NOTES))
                    || prompt.permission_revision != 1
                {
                    return Err(
                        "Native3 owner Read prompt differs from retained actual App/Notes revision"
                            .into(),
                    );
                }
                if prompt.process != 0 {
                    let starts: Vec<_> = actions
                        .iter()
                        .filter(|(at, a)| *at < display.at && a.kind == "start")
                        .collect();
                    let actual=starts.iter().find(|(_,a)|(a.process,a.thread)==(prompt.process,prompt.thread)).ok_or("Native3 owner current subject is not an actually started App incarnation")?;
                    let package = app_packages
                        .iter()
                        .find(|p| hex_digest(&p.executable().digest) == actual.1.image_sha256)
                        .ok_or("Native3 owner current image is not a retained package")?;
                    if prompt.current_package != package.id().bytes()
                        || prompt.app_epoch != starts.len() as u64
                    {
                        return Err(
                            "Native3 owner current package/epoch differs from actual start history"
                                .into(),
                        );
                    }
                }
                if prompt.current_admitted_gen != 0
                    || prompt.selected_next_gen != 0
                    || prompt.known_good != 0
                    || prompt.last_failed_gen != 0
                {
                    return Err(
                        "Native3 Standalone owner READ prompt invented System admission".into(),
                    );
                }
                if let (Some(confirmed), Some(completed)) = (confirmed, completed) {
                    if prompt.action == Action::RememberRead {
                        if !managed.iter().any(|(at, m)| {
                            *at > confirmed.at
                                && *at < completed.at
                                && (m.process, m.thread, m.nonce)
                                    == (prompt.process, prompt.thread, prompt.open_nonce)
                        }) {
                            return Err("Native3 remembered consent did not cause one actual accepted fresh READ before completion".into());
                        }
                    } else {
                        let effect=inhibits.iter().find(|(at,i)|*at>confirmed.at&&*at<completed.at&&(i.process,i.thread)==(prompt.process,prompt.thread)).ok_or("Native3 revoke consent lacks actual dispatch inhibition before completion")?;
                        for kind in ["stop", "reap"] {
                            if !actions.iter().any(|(at, a)| {
                                *at > effect.0
                                    && *at < completed.at
                                    && a.kind == kind
                                    && (a.process, a.thread) == (prompt.process, prompt.thread)
                            }) {
                                return Err("Native3 revoke completed before actual App authority retirement".into());
                            }
                        }
                    }
                } else if prompt.action == Action::RememberRead
                    && managed.iter().any(|(at, m)| {
                        *at > display.at
                            && (m.process, m.thread, m.nonce)
                                == (prompt.process, prompt.thread, prompt.open_nonce)
                    })
                {
                    return Err(
                        "Native3 refused/cancelled/expired owner prompt minted managed READ".into(),
                    );
                }
            }
            Action::RecoverGood => {
                if !expected.recovery
                    || prompt.current_admitted_gen != 0
                    || prompt.selected_next_gen != expected.initial_selected.map_or(0, |g| g.id)
                    || prompt.known_good != expected.known_good.unwrap_or(0)
                    || prompt.last_failed_gen != failure.map_or(0, |f| f.generation.get())
                {
                    return Err(
                        "Native3 recovery owner action confused current/next/KnownGood/lastFailure"
                            .into(),
                    );
                }
            }
        }
    }
    if expected.recovery
        && (!critical.is_empty()
            || !managed.is_empty()
            || !inhibits.is_empty()
            || !faults.is_empty()
            || !expected.job_roles.is_empty())
    {
        return Err("Native3 Recovery invented GUI/App/full graph evidence".into());
    }
    let meta = std::fs::symlink_metadata(directory).map_err(|e| e.to_string())?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err("Native3 evidence directory is not owned regular directory".into());
    }
    let output = directory.join("native3-diagnostics");
    std::fs::create_dir(&output).map_err(|e| e.to_string())?;
    let mut artifacts = Vec::new();
    let mut readable = String::new();
    for r in &reports {
        let name = format!("report-{:03}.bin", r.serial);
        storage::immutable_new(&output.join(&name), &r.bytes)?;
        artifacts.push(json!({"path":name,"bytes":r.bytes.len(),"sha256":hex_digest(&Sha256::digest(&r.bytes))}));
        match r.kind {
            d::Kind::Crash => {
                let crash = Crash::decode(&r.bytes)
                    .map_err(|e| format!("Native3 retained crash: {e:?}"))?;
                let mut text = String::new();
                ev_diagnostics::presentation::crash(&mut text, &crash)
                    .map_err(|e| e.to_string())?;
                let name = format!("crash-{:03}.txt", r.serial);
                storage::immutable_new(&output.join(&name), text.as_bytes())?;
                artifacts.push(json!({"path":name,"bytes":text.len(),"sha256":hex_digest(&Sha256::digest(text.as_bytes()))}));
            }
            d::Kind::Job => ev_diagnostics::live::Row::decode(&r.bytes)
                .map_err(|e| format!("Native3 retained row: {e:?}"))?
                .write(&mut readable)
                .map_err(|e| e.to_string())?,
            d::Kind::System => {
                use std::fmt::Write as _;
                let s = Snapshot::decode(&r.bytes)
                    .map_err(|e| format!("Native3 retained System: {e:?}"))?;
                writeln!(&mut readable,"System report {} ticks {}..{}: {:?}; selected generation {:?}; KnownGood {:?}; current admission {:?}; retained failure {:?}",r.serial,s.first_tick,s.last_tick,s.state,s.selected.map(|m|m.generation),s.known_good,s.current,s.last_failure).map_err(|e|e.to_string())?;
            }
        }
    }
    storage::immutable_new(&output.join("inspector.txt"), readable.as_bytes())?;
    artifacts.push(json!({"path":"inspector.txt","bytes":readable.len(),"sha256":hex_digest(&Sha256::digest(readable.as_bytes()))}));
    let owner_record = retain_owners(serial, build, expected.owners, directory)?;
    let managed_records:Vec<_>=managed.iter().map(|(at,m)|json!({"at":at,"process":m.process,"thread":m.thread,"image":m.image,"source_endpoint":m.source_endpoint,"inbox_endpoint":m.inbox_endpoint,"nonce":m.nonce,"ticket":m.ticket})).collect();
    let inhibit_records:Vec<_>=inhibits.iter().map(|(at,m)|json!({"at":at,"process":m.process,"thread":m.thread,"image":m.image,"outbound_pending":m.outbound_pending})).collect();
    let live_records: Vec<_> = self_queries
        .iter()
        .map(|(at, q)| json!({"at":at,"sequence":q.sequence,"tick":q.tick}))
        .collect();
    let record = json!({"schema":1,"profile":3,"mode":common.mode,"root_process":common.root_process,"root_thread":common.root_thread,"root_epoch":common.root_epoch,"root_incarnation":common.root_incarnation,"system_endpoint":common.system_endpoint,"startup_manifest":common.root_manifest,"selected":selected.map(manifest_json),"current_admission":admitted.map(|a|json!({"generation":a.generation.get(),"boot_serial":a.boot_serial,"process_stamp":a.process_stamp})),"crashes":crash_records,"jobs":row_records,"owner":owner_record,"managed_read_count":managed.len(),"inhibit_count":inhibits.len(),"runtime":runtime,"actual_self_queries":self_queries.len(),"live_observations":live_records,"managed_reads":managed_records,"inhibits":inhibit_records,"artifacts":artifacts,"scope":"independently joined exact startup/opaque source records/actual runtime identities; disk observer verifies durable effects separately"});
    storage::json_new(&output.join("record.json"), &record)?;
    Ok(Verified {
        record,
        admitted,
        system: snapshot,
        failure,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn build() -> String {
        "a".repeat(64)
    }
    fn prompt() -> Prompt {
        Prompt {
            action: Action::RememberRead,
            phase: Phase::Display,
            prompt_serial: 1,
            open_nonce: 3,
            owner: *b"EVROSION-OWNER01",
            app: [2; 16],
            package: [3; 32],
            process: 25,
            thread: 125,
            volume: *b"EVRO-USERS-VOL01",
            object: 1,
            object_counter: 0,
            object_digest: [4; 32],
            permission_revision: 1,
            grant_serial: 0,
            policy_revision: 0,
            head_digest: [5; 32],
            action_digest: [6; 32],
            token: [b'a'; 64],
            current_admitted_gen: 0,
            selected_next_gen: 0,
            known_good: 0,
            last_failed_gen: 0,
            response_budget_ticks: 200,
            current_package: [3; 32],
            app_epoch: 1,
        }
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|n| format!("{n:02x}")).collect()
    }
    fn envelope(report: u32, prompt: Prompt) -> String {
        format!(
            "EVROSION_NATIVE_OWNER_PROMPT protocol=1 build={} report={report} root_process=20 root_thread=120 bytes={}\n",
            build(),
            hex(&prompt.encode().unwrap())
        )
    }
    fn visible(report: u32, p: Prompt) -> String {
        let e = owner_line(envelope(report, p).trim_end(), &build()).unwrap();
        let mut out = envelope(report, p);
        for line in rendered(&e, &build()).unwrap() {
            out += &line;
            out.push('\n');
        }
        out
    }
    fn display() -> String {
        visible(1, prompt())
    }
    fn full() -> String {
        let mut out = display();
        for (i, phase) in [Phase::Armed, Phase::Confirmed, Phase::Completed]
            .into_iter()
            .enumerate()
        {
            let mut p = prompt();
            p.phase = phase;
            out += &visible(i as u32 + 2, p);
        }
        out
    }
    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build/test-tmp");
            std::fs::create_dir_all(&root).unwrap();
            let path = root.join(format!(
                "native3-diagnostics-model-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    struct Model {
        packages: [Vec<u8>; 2],
        catalogue: Vec<u8>,
        manifest: Vec<u8>,
        serial: String,
        failed: bool,
    }
    fn snapshot(report: u32, s: ev_diagnostics::system::Snapshot) -> String {
        format!(
            "EVROSION_NATIVE_SYSTEM protocol=1 build={} report={report} root_process=20 root_thread=120 bytes={}\n",
            build(),
            hex(&s.encode().unwrap())
        )
    }
    impl Model {
        fn new(failed: bool) -> Self {
            use ev_diagnostics::system::{Admission, Manifest, Phase as P, Snapshot, State};
            use ev_root_supervisor::native_plan::{self as n, system};
            use ev_userspace_contract::{
                Context,
                root_v2::{self, native},
            };
            use sha2::{Digest as _, Sha256};
            let (packages, mut catalogue) =
                crate::native_diagnostics::tests::package_catalogue_model();
            let at = native::catalogue::BOOT_MODE_OFFSET;
            catalogue[at..at + 2].copy_from_slice(&1u16.to_le_bytes());
            let measured =
                n::layout_measurement(&native::catalogue::Catalogue::decode(&catalogue).unwrap());
            let at = native::catalogue::MEASUREMENT_OFFSET;
            catalogue[at..at + 32].copy_from_slice(&measured);
            let cat = native::catalogue::Catalogue::decode(&catalogue).unwrap();
            let manifest = native::manifest_profile(root_v2::ManifestInputs {
                root_image: cat.base().root_image(),
                catalogue: Sha256::digest(&catalogue).into(),
                authority: [4; 32],
                limits: ev_root_supervisor::desktop_plan::ROOT_LIMITS,
                restart_attempts: cat.base().restart_attempts(),
                restart_window: cat.base().restart_window(),
            })
            .unwrap()
            .to_vec();
            let manifest_sha: [u8; 32] = Sha256::digest(&manifest).into();
            let context = Context {
                epoch: 4,
                incarnation: 2,
                process: 20,
                limits: ev_root_supervisor::desktop_plan::ROOT_LIMITS,
                manifest: manifest_sha,
                authority: [4; 32],
            };
            let banks =
                n::Packages::verify(&catalogue, context, &packages[0], &packages[1]).unwrap();
            let good = system::manifest(&banks, system::Slot::Good, 1).unwrap();
            let selected = if failed {
                system::manifest(&banks, system::Slot::Bad, 2).unwrap()
            } else {
                good
            };
            let boot_serial = if failed { 2 } else { 1 };
            let admitted = system::admission(
                &banks,
                context,
                20,
                120,
                ev_store::BootPlan {
                    manifest: selected,
                    serial: boot_serial,
                    candidate: failed,
                    attempt: 1,
                },
            )
            .unwrap();
            let wire = |m: ev_store::GenerationManifest| Manifest {
                generation: m.generation.get(),
                cohort: m.cohort,
                supervisor_image: m.supervisor_image,
                abi: m.abi,
                health_contract: m.health_contract,
                health_version: m.health_version,
                required_checks: m.required_checks,
            };
            let mut serial = format!(
                "EVROSION_M5_NATIVE_COMMON_PREFIX protocol=1 build={} mode=1 root_process=20 root_thread=120 root_image_sha256={} root_epoch=4 root_incarnation=2 root_manifest_sha256={} block_process=24 block_thread=124 block_image_sha256={} system_endpoint=77 root_frames=40 block_frames=20\n",
                build(),
                hex(&cat.base().root_image()),
                hex(&manifest_sha),
                hex(&cat.base().images().nth(3).unwrap().image)
            );
            let mut initial = Snapshot::new(
                if failed {
                    State::Committed
                } else {
                    State::Unformatted
                },
                1,
                2,
            );
            if failed {
                initial.selected = Some(wire(selected));
                initial.known_good = Some(1);
            }
            serial += &snapshot(1, initial);
            let query = |sequence, tick| {
                format!(
                    "EVROSION_M5_NATIVE_SELF_IDENTITY protocol=1 build={} sequence={sequence} process=20 thread=120 root_epoch=4 root_incarnation=2 root_manifest_sha256={} tick={tick}\n",
                    build(),
                    hex(&manifest_sha)
                )
            };
            serial += &query(1, 10);
            serial += &query(2, 11);
            let mut probation = Snapshot::new(State::Committed, 12, 13);
            probation.selected = Some(wire(selected));
            probation.known_good = if failed { Some(1) } else { None };
            probation.current = Some(Admission {
                manifest: system::manifest_digest(&selected),
                generation: selected.generation.get(),
                boot_serial,
                process_stamp: admitted.process_stamp,
                phase: P::Probation,
            });
            if !failed {
                let mut pending = Snapshot::new(State::Committed, 3, 4);
                pending.selected = Some(wire(good));
                serial += &snapshot(2, pending);
            }
            if !failed {
                serial += &format!(
                    "EVROSION_M5_NATIVE_CRITICAL_READY protocol=1 build={} process=21 thread=121 image_sha256={} tick=20\n",
                    build(),
                    hex(&cat.base().images().next().unwrap().image)
                );
            }
            serial += &query(3, if failed { 80 } else { 30 });
            if !failed {
                serial += &query(4, 31);
            }
            let mut final_snapshot = probation;
            final_snapshot.first_tick = if failed { 81 } else { 32 };
            final_snapshot.last_tick = if failed { 82 } else { 33 };
            final_snapshot.selected = Some(wire(good));
            final_snapshot.known_good = Some(1);
            final_snapshot.current.as_mut().unwrap().phase =
                if failed { P::Failed } else { P::Healthy };
            if failed {
                final_snapshot.last_failure = Some(ev_diagnostics::system::Failure {
                    generation: 2,
                    boot_serial: 2,
                    attempts: 1,
                    reason: 2,
                    supervisor_image: cat.base().root_image(),
                    process_stamp: Some(admitted.process_stamp),
                    operation: 9,
                    sequence: 10,
                });
            }
            serial += &snapshot(if failed { 2 } else { 3 }, final_snapshot);
            serial += &format!(
                "EVROSION_NATIVE_STATE protocol=1 build={} report=1 op=finish result=ok installed=0 active=none staged=none previous=none process=0 thread=0 revision=0 data_epoch=0 data_counter=0 value=0 mutations=0 recovery=0 actual_process=0 actual_thread=0 actual_image_sha256={} identity_matches=true\n",
                build(),
                "0".repeat(64)
            );
            for i in 0..7 {
                let absent = i == 5;
                serial += &format!(
                    "EVROSION_M5_NATIVE_PROFILE protocol=1 build={} phase=finished scope=actor_slot index={i} current_process={} current_thread={} current_job={} incarnations={} elapsed_ticks=10000 captures={} syscalls={} irqs={} faults=0 port_in={} port_out=0 yields=0 continuations={} charged_cpu_ticks={} current_job_cpu_ticks={} cpu_scope=subtree\n",
                    build(),
                    if absent { 0 } else { 20 + i },
                    if absent { 0 } else { 120 + i },
                    if absent { 0 } else { 100 + i },
                    u64::from(!absent),
                    if absent { 0 } else { 11 },
                    if absent { 0 } else { 10 },
                    u64::from(!absent),
                    u64::from(!absent),
                    if absent { 0 } else { 8 },
                    u64::from(!absent),
                    u64::from(!absent)
                );
            }
            let a = native::catalogue::package_pages(packages[0].len() as u64).unwrap();
            let b = native::catalogue::package_pages(packages[1].len() as u64).unwrap();
            serial += &format!(
                "EVROSION_M5_NATIVE protocol=1 build={} status=PASS processes=6 starts=6 calls=4 replies=4 faults=0 restarts=0 grants=0 app_a_starts=0 app_b_starts=0 app_a_stops=0 app_b_stops=0 app_a_reaps=0 app_b_reaps=0 app_a_process=0 app_b_process=0 app_a_thread=0 app_b_thread=0 package_a_pages={a} package_b_pages={b} bank_maps=2 bank_detaches=2 bank_reclaimed={} readonly_rejections=0 root_exit=0 frames=true metadata=true guards=true display_survived=true\n",
                build(),
                a + b
            );
            Self {
                packages,
                catalogue,
                manifest,
                serial,
                failed,
            }
        }
        fn expected(&self) -> Expected<'_> {
            use crate::native3_disk::Generation;
            use ev_root_supervisor::native_plan::system;
            Expected {
                recovery: false,
                current: Some(CurrentExpected {
                    generation: Generation {
                        slot: if self.failed {
                            system::Slot::Bad
                        } else {
                            system::Slot::Good
                        },
                        id: if self.failed { 2 } else { 1 },
                    },
                    boot_serial: if self.failed { 2 } else { 1 },
                    phase: if self.failed {
                        ev_diagnostics::system::Phase::Failed
                    } else {
                        ev_diagnostics::system::Phase::Healthy
                    },
                }),
                selected: Some(Generation {
                    slot: system::Slot::Good,
                    id: 1,
                }),
                initial_selected: if self.failed {
                    Some(Generation {
                        slot: system::Slot::Bad,
                        id: 2,
                    })
                } else {
                    None
                },
                known_good: Some(1),
                failure: if self.failed {
                    FailureExpected::CurrentMissingProgress {
                        operation: 9,
                        sequence: 10,
                    }
                } else {
                    FailureExpected::None
                },
                shell_faults: 0,
                app_faults: 0,
                job_roles: &[],
                owners: &[],
                managed_reads: 0,
                inhibits: 0,
            }
        }
        fn retain(&self, serial: &str, path: &Path) -> Result<Verified> {
            retain(
                serial.as_bytes(),
                &build(),
                &"ab".repeat(32),
                self.packages.each_ref().map(Vec::as_slice),
                &self.catalogue,
                &self.manifest,
                self.expected(),
                path,
            )
        }
    }
    #[test]
    fn contextual_admission_and_fixed_health_clock_are_independent_of_source_claims() {
        // All records here are structural adversarial fixtures, not executed actors.
        for failed in [false, true] {
            let m = Model::new(failed);
            let temp = Temp::new();
            let verified = m.retain(&m.serial, &temp.0).unwrap();
            assert_eq!(
                verified.admitted.unwrap().generation.get(),
                if failed { 2 } else { 1 }
            );
            assert_eq!(verified.failure.is_some(), failed);
        }
        let m = Model::new(false);
        for bad in [
            m.serial.replace("root_epoch=4", "root_epoch=5"),
            m.serial.replace("sequence=2", "sequence=3"),
            m.serial.replace("tick=30", "tick=80"),
            m.serial.replace(
                "process=21 thread=121",
                "process=21 thread=121 ignored=true",
            ),
            m.serial.replace("tick=20", "tick=90"),
            m.serial
                .replace("process=21 thread=121", "process=99 thread=199"),
        ] {
            let temp = Temp::new();
            assert!(m.retain(&bad, &temp.0).is_err());
            assert!(std::fs::read_dir(&temp.0).unwrap().next().is_none());
        }
        let m = Model::new(true);
        let bad = m.serial.replace("tick=80", "tick=74");
        let temp = Temp::new();
        assert!(
            m.retain(&bad, &temp.0).is_err(),
            "actual MissingProgress must wait fixed64 ticks from anchor11"
        );
    }
    #[test]
    fn resealed_system_claims_cannot_replace_actual_context_or_prior_cold_state() {
        let model = Model::new(false);
        for mutation in 0..3 {
            let mut system_index = 0;
            let mut bad = String::new();
            for line in model.serial.lines() {
                if line.starts_with("EVROSION_NATIVE_SYSTEM ") {
                    let fields: Vec<_> = line.split(' ').collect();
                    let mut row = ev_diagnostics::system::Snapshot::decode(
                        &hash(fields[6].strip_prefix("bytes=").unwrap()).unwrap(),
                    )
                    .unwrap();
                    if system_index == 2 {
                        match mutation {
                            0 => row.current.as_mut().unwrap().process_stamp[0] ^= 1,
                            1 => row.current.as_mut().unwrap().generation = 2,
                            _ => row.known_good = Some(2),
                        }
                    }
                    bad += &snapshot(system_index + 1, row);
                    system_index += 1;
                } else {
                    bad += line;
                    bad.push('\n');
                }
            }
            let temp = Temp::new();
            assert!(model.retain(&bad, &temp.0).is_err());
            assert!(std::fs::read_dir(&temp.0).unwrap().next().is_none());
        }
    }
    #[test]
    fn full_visible_prompt_is_exact_and_live_runner_waits_for_complete_arm() {
        let out = full();
        let events = owners(out.as_bytes(), &build()).unwrap();
        assert_eq!(events.len(), 4);
        assert_eq!(events[1].prompt.phase, Phase::Armed);
        assert!(owner_events(out.as_bytes(), &build(), true).is_ok());
        let shown = display();
        assert_eq!(owners(shown.as_bytes(), &build()).unwrap().len(), 1);
        let last = shown.rfind("EVROSION_NATIVE_OWNER_TEXT").unwrap();
        let partial = &shown[..last + 17];
        assert_eq!(owners(partial.as_bytes(), &build()).unwrap().len(), 0);
        assert!(owner_events(partial.as_bytes(), &build(), true).is_err());
        let mut p = prompt();
        p.phase = Phase::Armed;
        let half = format!("{shown}{}", envelope(2, p).trim_end_matches('\n'));
        assert_eq!(owners(half.as_bytes(), &build()).unwrap().len(), 1);
    }
    #[test]
    fn no_live_phase_escapes_before_its_complete_canonical_status_text() {
        let mut prefix = String::new();
        for (index, phase) in [
            Phase::Display,
            Phase::Armed,
            Phase::Confirmed,
            Phase::Completed,
        ]
        .into_iter()
        .enumerate()
        {
            let mut p = prompt();
            p.phase = phase;
            let text = visible(index as u32 + 1, p);
            for end in 0..text.len() {
                let partial = prefix.clone() + &text[..end];
                assert_eq!(
                    owners(partial.as_bytes(), &build()).unwrap().len(),
                    index,
                    "phase{phase:?} cut{end}"
                );
            }
            prefix += &text;
            assert_eq!(
                owners(prefix.as_bytes(), &build()).unwrap().len(),
                index + 1
            );
        }
        assert!(owner_events(prefix.as_bytes(), &build(), true).is_ok());
        for bad in [
            prefix.replace("is ARMED.", "is automatically approved."),
            prefix.replace(
                "confirmation accepted; applying",
                "operation already completed; applying",
            ),
            prefix.replace("fresh access enqueued.", "fresh access delivered."),
        ] {
            assert!(owners(bad.as_bytes(), &build()).is_err());
        }
    }
    #[test]
    fn all_failure_outcomes_require_their_exact_readable_terminal_status() {
        for phase in [
            Phase::Cancelled,
            Phase::Expired,
            Phase::Refused,
            Phase::Recovery,
        ] {
            let mut prefix = display();
            let mut p = prompt();
            p.phase = Phase::Armed;
            prefix += &visible(2, p);
            let report = if phase == Phase::Recovery {
                p.phase = Phase::Confirmed;
                prefix += &visible(3, p);
                4
            } else {
                3
            };
            p.phase = phase;
            let status = visible(report, p);
            let before = owners(prefix.as_bytes(), &build()).unwrap().len();
            assert_eq!(
                owners(
                    (prefix.clone() + status.trim_end_matches('\n')).as_bytes(),
                    &build()
                )
                .unwrap()
                .len(),
                before
            );
            let completed = prefix.clone() + &status;
            assert!(owner_events(completed.as_bytes(), &build(), true).is_ok());
            let first_text = status.find("EVROSION_NATIVE_OWNER_TEXT").unwrap();
            assert!(
                owner_events(
                    (prefix.clone() + &status[..first_text]).as_bytes(),
                    &build(),
                    true
                )
                .is_err()
            );
            let mut corrupt = status.clone();
            corrupt.insert_str(first_text, "unexpected status\n");
            assert!(owners((prefix + &corrupt).as_bytes(), &build()).is_err());
        }
    }
    #[test]
    fn altered_missing_interleaved_replayed_human_output_cannot_arm() {
        let good = full();
        let shown = display();
        let lines: Vec<_> = shown.lines().collect();
        for bad in [
            good.replace("explicit approval required.", "automatically approved."),
            good.replacen("line=0", "line=00", 1),
            good.replacen("root_process=20", "root_process=21", 1),
            good.replace("report=2", "report=3"),
            format!(
                "{}\n{}",
                lines[0],
                good.strip_prefix(&(lines[0].to_owned() + "\n"))
                    .unwrap()
                    .replace(lines[1], "EVROSION_NATIVE_OWNER_TEXT tampered")
            ),
            format!(
                "{shown}{}\n{}",
                lines[1],
                good.strip_prefix(&shown).unwrap()
            ),
        ] {
            assert!(
                owner_events(bad.as_bytes(), &build(), true).is_err(),
                "{bad}"
            );
        }
        let mut armed = prompt();
        armed.phase = Phase::Armed;
        assert!(owners(envelope(1, armed).as_bytes(), &build()).is_err());
    }
    #[test]
    fn binding_and_terminal_order_are_immutable_and_success_needs_completed() {
        let shown = display();
        let mut p = prompt();
        p.phase = Phase::Armed;
        let armed = shown.clone() + &visible(2, p);
        p.phase = Phase::Completed;
        assert!(owners((armed.clone() + &visible(3, p)).as_bytes(), &build()).is_err());
        p.phase = Phase::Confirmed;
        p.object = 2;
        assert!(owners((armed.clone() + &visible(3, p)).as_bytes(), &build()).is_err());
        p = prompt();
        p.phase = Phase::Confirmed;
        let confirmed = armed.clone() + &visible(3, p);
        assert!(owner_events(confirmed.as_bytes(), &build(), true).is_err());
        for phase in [Phase::Cancelled, Phase::Refused, Phase::Expired] {
            p = prompt();
            p.phase = phase;
            assert!(
                owner_events((armed.clone() + &visible(3, p)).as_bytes(), &build(), true).is_ok()
            );
        }
        p = prompt();
        p.phase = Phase::Refused;
        assert!(owner_events((confirmed + &visible(4, p)).as_bytes(), &build(), true).is_ok());
        let mut expired = prompt();
        expired.phase = Phase::Expired;
        assert!(
            owner_events(
                (display() + &visible(2, expired)).as_bytes(),
                &build(),
                true
            )
            .is_ok()
        );
        let mut next = prompt();
        next.phase = Phase::Display;
        assert!(owners((full() + &envelope(5, next)).as_bytes(), &build()).is_err());
    }
    #[test]
    fn owner_codec_rejects_extra_fields_uppercase_hex_and_wrong_build() {
        let line = envelope(1, prompt());
        for bad in [
            line.trim_end().to_owned() + " ignored=true",
            line.replace("protocol=1", "protocol=01"),
            line.replace("report=1", "report=01"),
            line.replace("root_thread=120", "root_thread=0"),
            line.replace("bytes=45564f574e523031", "bytes=45564F574E523031"),
        ] {
            assert!(owner_line(bad.trim_end(), &build()).is_err());
        }
        assert!(owner_line(line.trim_end(), &"b".repeat(64)).is_err());
    }
}
