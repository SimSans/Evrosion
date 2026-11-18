//! Explicit finite owned-VM network probe. Root labels are joined with actual
//! host bytes and complete Kernel retirement; failures never imply quiescence.
pub(crate) mod acquisition_disk;
pub(crate) mod components;
pub(crate) mod namespace_probe;
mod negative;
mod time_pause;
mod time_probe;
mod time_refresh;
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Goal {
    Hello,
    Time,
    TimePause,
    UpdateNamespace,
    TimeCorrupt,
    MissingEntropy,
    TimeRefresh,
}
use crate::{
    boot::ChildGuard,
    build::{Manifest, Result},
    desktop_protocol::{Producer, StepKind},
    native3_protocol::{CommonPrefix, Event},
    network_fixture::{Fixture, Snapshot},
    qmp::Qmp,
    storage,
};
use components::Context;
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Write},
    path::Path,
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};
const LIMIT: u64 = 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(240);
// Independent exact host fixture contract. Source changes cannot silently
// broaden the admitted request: the real socket bytes must still match this.
const REQUEST: &[u8] = b"GET /hello HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n";
fn bounded(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > LIMIT {
        return Err("network probe output bound exceeded".into());
    }
    Ok(bytes)
}
fn complete(bytes: &[u8]) -> &[u8] {
    bytes
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(&[], |n| &bytes[..=n])
}
fn fixture_complete(s: &Snapshot) -> Result<bool> {
    if s.omitted != 0 || s.observed > 1 || s.completed > 1 || s.exchanges.len() > 1 {
        return Err("network fixture omitted or received additional exchanges".into());
    }
    if s.observed == 0 {
        if s.completed != 0 || !s.exchanges.is_empty() {
            return Err("network fixture counter/ledger mismatch".into());
        }
        return Ok(false);
    }
    if s.observed != 1 || s.completed != 1 || s.exchanges.len() != 1 {
        return Err("network fixture exchange failed or incomplete".into());
    }
    hello_exchange(&s.exchanges[0])?;
    Ok(true)
}
pub(crate) fn hello_exchange(exchange: &crate::network_fixture::Exchange) -> Result<()> {
    let expected=[format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",crate::network_fixture::HELLO.len()).as_bytes(),crate::network_fixture::HELLO].concat();
    if exchange.error.is_some()
        || exchange.mutation.is_some()
        || exchange.request != REQUEST
        || exchange.response != expected
    {
        return Err("network fixture actual request/response differs".into());
    }
    Ok(())
}
pub(crate) fn acquisition_hello(s: &Snapshot) -> Result<bool> {
    fixture_complete(s)
}
struct Facts {
    common: Option<CommonPrefix>,
    shell: Option<(u64, u64)>,
    display: Option<u64>,
    stages: Vec<crate::network_protocol::Progress>,
    time: Vec<crate::time_protocol::Progress>,
    ready: bool,
    failure: Option<String>,
}
#[cfg(test)]
fn facts(context: &Context, serial: &[u8], build: &str, finish_sent: bool) -> Result<Facts> {
    facts_for_goal(context, serial, build, finish_sent, Goal::Hello)
}
fn facts_for_goal(
    context: &Context,
    serial: &[u8],
    build: &str,
    finish_sent: bool,
    goal: Goal,
) -> Result<Facts> {
    let serial = complete(serial);
    let text = std::str::from_utf8(serial).map_err(|_| "network probe serial UTF8")?;
    let mut common = None;
    let mut shell = None;
    for line in text.lines() {
        if line.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX ") {
            let Event::Common(c) = crate::native3_protocol::event_network(line, build)? else {
                unreachable!()
            };
            if common.is_some()
                || c.mode != 0
                || c.root_image != context.images[0]
                || c.root_manifest != context.root_manifest
                || c.block_image != context.images[4]
                || c.root_frames != context.root_frames
                || c.block_frames != context.block_frames
            {
                return Err(
                    "network actual Root/Block context differs from retained cohort".into(),
                );
            }
            common = Some(c);
        }
        if line.starts_with("EVROSION_M5_NATIVE_CRITICAL_READY ") {
            let Event::Critical(c) = crate::native3_protocol::event_network(line, build)? else {
                unreachable!()
            };
            if shell.is_some() || c.image != context.images[1] {
                return Err("network actual Shell readiness image/replay".into());
            }
            shell = Some((c.process, c.thread));
        }
    }
    let stages = crate::network_protocol::records(serial, build)?;
    if !crate::update_protocol::records(serial, build)?.is_empty() && goal != Goal::UpdateNamespace
    {
        return Err("network/time probe observed unrequested content preparation".into());
    }
    let time = crate::time_protocol::records(serial, build)?;
    let mut expected = 1;
    let mut entropy_refused = false;
    let mut failure = None;
    if let Some(error) = crate::network_error_protocol::records(serial, build)?.first() {
        failure = Some(format!(
            "actual {} operation{} class{} detail{} subdetail{} progress{}",
            error.actor,
            error.operation,
            error.class,
            error.detail,
            error.subdetail,
            error.progress
        ));
    }
    for p in &stages {
        if goal == Goal::MissingEntropy {
            if p.stage == 8 && p.result == 1 && p.argument == 1 && expected == 1 && !entropy_refused
            {
                entropy_refused = true;
                continue;
            }
            if p.stage == 7
                && p.result == 0
                && p.argument == 2
                && entropy_refused
                && expected == 1
                && finish_sent
            {
                expected = 8;
                continue;
            }
            return Err("missing entropy produced unexpected network progress".into());
        }
        if p.stage == 8 || p.result != 0 {
            failure.get_or_insert_with(|| {
                format!(
                    "actual Root network failure stage={} result={} argument={}",
                    p.stage, p.result, p.argument
                )
            });
            continue;
        }
        if p.stage != expected || p.stage == 7 && !finish_sent {
            return Err("network probe missing/replayed stage or unrequested shutdown".into());
        }
        if p.stage == 5 && p.argument != REQUEST.len() as u64 {
            return Err("network actual transmitted request length differs".into());
        }
        expected += 1;
    }
    if time.iter().any(|p| p.stage == 3 || p.result != 0) {
        failure = Some("actual Root elapsed-source failure".into());
    }
    let mut display = None;
    let mut home = false;
    for step in crate::desktop_protocol::steps(serial, build)? {
        if step.producer == Producer::App || step.app_process != 0 || step.grants != 0 {
            return Err("no-App network probe observed an App/grant".into());
        }
        if let Some((process, _)) = shell
            && step.shell_process != process
        {
            return Err("network Shell changed incarnation".into());
        }
        if display.is_some_and(|p| p != step.display_process) {
            return Err("network Display changed incarnation".into());
        }
        display = Some(step.display_process);
        if step.kind == StepKind::Frame && step.producer == Producer::Shell {
            let reference = crate::session_reference::Reference::new(
                ev_graphics::shell::Screen::Home,
                None,
                None,
            )?;
            if reference.surface_hash(Producer::Shell, step.frame)? != step.surface_sha256 {
                return Err("network protected Shell surface is not no-App Home".into());
            }
            home = true;
        }
    }
    if let (Some(common), Some((process, thread)), Some(display)) =
        (common.as_ref(), shell, display)
        && (BTreeSet::from([common.root_process, common.block_process, process, display]).len()
            != 4
            || [common.root_thread, common.block_thread].contains(&thread))
    {
        return Err("network protected actor identities alias".into());
    }
    let local_ready = failure.is_none() && common.is_some() && shell.is_some() && home;
    let ready = if goal == Goal::MissingEntropy {
        negative::no_time(serial, build)?;
        if !time.is_empty() {
            return Err("missing entropy unexpectedly initialized elapsed-source work".into());
        }
        local_ready && entropy_refused && time.is_empty()
    } else {
        local_ready
            && stages.len() >= 6
            && expected >= 7
            && time
                .first()
                .is_some_and(|p| p.stage == 1 && p.result == 0 && p.elapsed_seconds == 0)
            && time
                .iter()
                .any(|p| p.stage == 2 && p.result == 0 && p.elapsed_seconds > 0)
    };
    Ok(Facts {
        common,
        shell,
        display,
        stages,
        time,
        ready,
        failure,
    })
}
#[allow(clippy::too_many_arguments)] // Exact owned run, requested goal and terminal ownership facts.
fn finished(
    context: &Context,
    serial: &[u8],
    build: &str,
    status: ExitStatus,
    finish_sent: bool,
    fixture: &Snapshot,
    goal: Goal,
    time_sent: bool,
    pause: &time_pause::State,
    namespace: &namespace_probe::State,
    refresh: &time_refresh::State,
) -> Result<Value> {
    let checked = if goal == Goal::TimeRefresh {
        false
    } else {
        pause.complete(serial, build, goal == Goal::TimePause)?
    };
    if serial.last() != Some(&b'\n')
        || status.code() != Some(ev_test_protocol::QEMU_PASS_STATUS)
        || !finish_sent
        || !(match goal {
            Goal::Hello => fixture_complete(fixture)?,
            Goal::UpdateNamespace => {
                fixture_complete(fixture)? && namespace.complete(serial, build)?
            }
            Goal::Time => time_sent && time_probe::complete(serial, build, fixture, true)?,
            Goal::TimePause => {
                time_sent && time_probe::complete(serial, build, fixture, true)? && checked
            }
            Goal::TimeCorrupt => time_sent && negative::corrupt(serial, build, fixture, true)?,
            Goal::MissingEntropy => !time_sent && negative::empty_fixture(fixture)?,
            Goal::TimeRefresh => time_sent && refresh.complete(serial, build, fixture, true)?,
        })
    {
        return Err("network probe lacks actual complete exit/owner finish/fixture".into());
    }
    let facts = facts_for_goal(context, serial, build, finish_sent, goal)?;
    if !facts.ready
        || facts.failure.is_some()
        || facts.stages.len() != if goal == Goal::MissingEntropy { 2 } else { 7 }
        || facts
            .stages
            .last()
            .is_none_or(|p| p.stage != 7 || p.result != 0 || p.argument != 2)
    {
        return Err(
            "network probe lacks exact requested progress and successful NW7 retirement".into(),
        );
    }
    let log = crate::session_protocol::retention(serial, build)?;
    if log.omitted != 0 {
        return Err("network probe diagnostic history omitted".into());
    }
    let protocol = crate::session_protocol::without_network_diagnostics(serial, build)?;
    crate::boot_protocol::check_network(&protocol, build, status.code())?;
    let record = crate::native_protocol::record_session(serial, build)?;
    let c = &record.counts;
    if c["processes"] != 8
        || c["starts"] != 8
        || c["calls"] == 0
        || c["calls"] != c["replies"]
        || c["faults"] != 0
        || c["restarts"] != 0
        || c["grants"] != 0
        || c["readonly_rejections"] != 0
        || !record.actions.is_empty()
        || c["package_a_pages"] != context.package_pages[0]
        || c["package_b_pages"] != context.package_pages[1]
    {
        return Err("network probe graph/cleanup differs from actual no-App contract".into());
    }
    for slot in ["a", "b"] {
        for suffix in ["starts", "stops", "reaps", "process", "thread"] {
            if c[&format!("app_{slot}_{suffix}")] != 0 {
                return Err("network probe invented App execution".into());
            }
        }
    }
    let profiles = crate::native_profile::finished_network(serial, build, 0, Some(0))?;
    let common = facts.common.as_ref().unwrap();
    let mut processes = BTreeSet::new();
    let mut threads = BTreeSet::new();
    let mut jobs = BTreeSet::new();
    for (index, p) in profiles.iter().enumerate() {
        let p = &p.counts;
        if index == 5 {
            if p["current_process"] != 0 || p["incarnations"] != 0 || p["captures"] != 0 {
                return Err("network probe App profile is not absent".into());
            }
            continue;
        }
        if p["current_process"] == 0
            || p["current_thread"] == 0
            || p["current_job"] == 0
            || p["incarnations"] != 1
            || !processes.insert(p["current_process"])
            || !threads.insert(p["current_thread"])
            || !jobs.insert(p["current_job"])
        {
            return Err("network probe current eight-actor identities incomplete/aliased".into());
        }
    }
    if (
        profiles[0].counts["current_process"],
        profiles[0].counts["current_thread"],
    ) != (common.root_process, common.root_thread)
        || (
            profiles[4].counts["current_process"],
            profiles[4].counts["current_thread"],
        ) != (common.block_process, common.block_thread)
        || facts.shell
            != Some((
                profiles[1].counts["current_process"],
                profiles[1].counts["current_thread"],
            ))
        || facts.display != Some(profiles[6].counts["current_process"])
    {
        return Err("network actual graph identities disagree with protected receipts".into());
    }
    Ok(
        json!({"schema":1,"goal":goal,"scope":"Complete actual no-App V4 owned probe. Explicit negative goals require the specific source refusal plus actual normal retirement. Public relay mutation is untrusted transport evidence. No qualified UTC, calibrated rate, TLS/update trust or complete M6 claim.","network":facts.stages,"elapsed_source":facts.time,"time_proof":crate::time_proof_protocol::records(serial,build)?,"time_check":crate::tc_protocol::records(serial,build)?,"time_pause":if goal==Goal::TimePause {Some(pause.receipt())}else{None},"time_refresh":if goal==Goal::TimeRefresh{Some(refresh.receipt())}else{None},"current_actor_profiles":profiles,"native_retirement":record,"retention":log,"fixture":fixture,"complete_Kernel_retirement_receipt":true}),
    )
}
#[allow(clippy::too_many_arguments)] // One explicit owned-VM launch/receipt boundary.
pub(crate) fn supervise(
    command: &mut Command,
    serial: &Path,
    errors: &Path,
    timeout: Duration,
    build: &str,
    directory: &Path,
    clock: &mut crate::vm_clock::Prepared,
    root: &Path,
    manifest: &Manifest,
    goal: Goal,
) -> Result<ExitStatus> {
    if timeout != TIMEOUT {
        return Err("network probe requires original240s bound".into());
    }
    let context = Context::retain(root, manifest, directory)?;
    let fixture = if goal == Goal::TimeCorrupt {
        Fixture::corrupt_time()?
    } else {
        Fixture::hello()?
    };
    let origin = Instant::now();
    let deadline = origin
        .checked_add(timeout)
        .ok_or("network probe deadline overflow")?;
    let mut qmp = None;
    let mut failure = None;
    let mut finish_sent = false;
    let mut finish_input = None;
    let mut time_sent = false;
    let mut time_input = None;
    let mut pause = time_pause::State::default();
    let mut namespace = namespace_probe::State::default();
    let mut refresh = time_refresh::State::default();
    let mut usernet = None;
    let mut final_record = None;
    let result = (|| {
        let mut child = ChildGuard(
            command
                .stdin(Stdio::piped())
                .spawn()
                .map_err(|e| format!("owned network QEMU spawn: {e}"))?,
        );
        clock.verify_and_start(&mut child.0, directory)?;
        qmp = Some(Qmp::connect(directory, deadline)?);
        let mut input = child
            .0
            .stdin
            .take()
            .ok_or("network owner UART stdin absent")?;
        loop {
            let bytes = bounded(serial)?;
            let _ = bounded(errors)?;
            let snapshot = fixture.snapshot()?;
            match facts_for_goal(&context, &bytes, build, finish_sent, goal) {
                Ok(f) => {
                    if (goal == Goal::Hello || !time_sent)
                        && !crate::time_proof_protocol::records(complete(&bytes), build)?.is_empty()
                    {
                        failure = Some("time work preceded its explicit owned UART request".into());
                    }
                    if goal != Goal::TimeRefresh
                        && let Err(error) = pause.complete(complete(&bytes), build, false)
                    {
                        failure = Some(error);
                    }
                    if failure.is_none() {
                        failure = f.failure;
                    }
                    if failure.is_none() && !finish_sent && f.ready {
                        let progress = if goal == Goal::TimeRefresh && time_sent {
                            refresh.advance(
                                complete(&bytes),
                                build,
                                &snapshot,
                                qmp.as_mut().ok_or("owned network QMP absent")?,
                                &mut input,
                                origin,
                            )
                        } else if goal == Goal::MissingEntropy {
                            negative::empty_fixture(&snapshot)
                        } else if goal == Goal::TimeCorrupt && time_sent {
                            negative::corrupt(complete(&bytes), build, &snapshot, false)
                        } else if matches!(goal, Goal::Time | Goal::TimePause) && time_sent {
                            time_probe::complete(complete(&bytes), build, &snapshot, false)
                        } else {
                            fixture_complete(&snapshot)
                        };
                        match progress {
                            Ok(true) => {
                                let ready = if goal == Goal::TimePause && time_sent {
                                    match pause.advance(
                                        complete(&bytes),
                                        build,
                                        qmp.as_mut().ok_or("owned network QMP absent")?,
                                        &mut input,
                                        origin,
                                    ) {
                                        Ok(ready) => ready,
                                        Err(e) => {
                                            failure = Some(e);
                                            false
                                        }
                                    }
                                } else {
                                    true
                                };
                                if ready {
                                    let before =
                                        crate::perf_ledger::elapsed_ns(origin, Instant::now())
                                            .map_err(|e| format!("network host clock: {e:?}"))?;
                                    let request: Option<&[u8]> = if goal == Goal::UpdateNamespace {
                                        match namespace.next(complete(&bytes), build) {
                                            Ok(request) => request,
                                            Err(error) => {
                                                failure = Some(error);
                                                None
                                            }
                                        }
                                    } else if matches!(
                                        goal,
                                        Goal::Time
                                            | Goal::TimePause
                                            | Goal::TimeCorrupt
                                            | Goal::TimeRefresh
                                    ) && !time_sent
                                    {
                                        Some(b"time-probe\n")
                                    } else {
                                        Some(b"finish\n")
                                    };
                                    if let Some(request) = request {
                                        input
                                            .write_all(request)
                                            .and_then(|()| input.flush())
                                            .map_err(|e| e.to_string())?;
                                        let receipt = json!({"device":"owned QEMU owner UART","bytes":std::str::from_utf8(request).unwrap(),"host_bracket_ns":[before,crate::perf_ledger::elapsed_ns(origin,Instant::now()).map_err(|e|format!("network host clock: {e:?}"))?],"scripted_input":true,"human_consent_claim":false});
                                        if request == b"time-probe\n" {
                                            time_sent = true;
                                            time_input = Some(receipt);
                                        } else if request == b"finish\n" {
                                            finish_sent = true;
                                            finish_input = Some(receipt);
                                        } else {
                                            namespace.sent(request, receipt);
                                        }
                                    }
                                }
                            }
                            Ok(false) => (),
                            Err(e) => failure = Some(e),
                        }
                    }
                }
                Err(e) => {
                    if failure.is_none() {
                        failure = Some(e);
                    }
                }
            }
            // Diagnose once using the existing owned QMP connection. Failure
            // to read this optional table never changes the guest result or
            // acknowledges retained device/window debt.
            if usernet.is_none()
                && (!crate::network_error_protocol::records(complete(&bytes), build)?.is_empty()
                    || !crate::te_protocol::records(complete(&bytes), build)?.is_empty())
            {
                let before = crate::perf_ledger::elapsed_ns(origin, Instant::now())
                    .map_err(|e| format!("network host clock: {e:?}"))?;
                let result = qmp.as_mut().ok_or("owned network QMP absent")?.usernet();
                let mut receipt = json!({"command":"info usernet","host_bracket_ns":[before,
                    crate::perf_ledger::elapsed_ns(origin,Instant::now()).map_err(|e|format!("network host clock: {e:?}"))?],
                    "table":result.as_ref().ok(),"error":result.as_ref().err(),
                    "read_only":true,"guest_cleanup_claim":false});
                if let Err(error) =
                    storage::json_new(&directory.join("network-usernet-snapshot.json"), &receipt)
                {
                    receipt["retention_error"] = json!(error);
                }
                usernet = Some(receipt);
            }
            if let Some(status) = child.0.try_wait().map_err(|e| e.to_string())? {
                if let Some(error) = &failure {
                    return Err(error.clone());
                }
                let bytes = bounded(serial)?;
                final_record = Some(finished(
                    &context,
                    &bytes,
                    build,
                    status,
                    finish_sent,
                    &fixture.snapshot()?,
                    goal,
                    time_sent,
                    &pause,
                    &namespace,
                    &refresh,
                )?);
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "network probe original240s deadline; {}",
                    failure
                        .as_deref()
                        .unwrap_or("required actual progress/retirement incomplete")
                ));
            }
            thread::sleep(Duration::from_millis(20));
        }
    })();
    let snapshot = fixture.snapshot();
    let transcript = qmp.as_ref().map(Qmp::transcript).unwrap_or(&[]);
    storage::json_new(
        &directory.join("network-qmp-transcript.json"),
        &json!({"transcript":transcript,"scope":"Owned QMP capabilities only; prelaunch verified clock transcript retained separately. No host UI input/forced guest reply."}),
    )?;
    storage::json_new(
        &directory.join("network-observer.json"),
        &json!({"schema":1,"kind":"finite-headless-V4-network-probe","goal":goal,"passed":result.is_ok(),"error":result.as_ref().err(),"diagnostic_failure":failure,"finish_sent":finish_sent,"finish_input":finish_input,"time_sent":time_sent,"time_input":time_input,"time_pause":if goal==Goal::TimePause{Some(pause.receipt())}else{None},"time_refresh":if goal==Goal::TimeRefresh{Some(refresh.receipt())}else{None},"namespace":if goal==Goal::UpdateNamespace{Some(&namespace)}else{None},"usernet":usernet,"fixture":snapshot.as_ref().ok(),"fixture_error":snapshot.as_ref().err(),"actual":final_record,"original_timeout_seconds":240,"scripted_input":true,"human_consent_claim":false,"complete_Kernel_retirement_receipt":result.is_ok(),"whole_probe_acceptance_requires_caller_postflights":true,"scope":"Failure/host kill never proves actual NIC STOP/scrub or guest retirement. NW8 retains uncertainty through the original bounded observation period."}),
    )?;
    result
}
#[cfg(test)]
mod tests;
