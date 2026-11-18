//! Closed, bounded Kernel startup diagnostics. These observations establish no
//! health, successful operation, CPU elapsed time, or next-boot authority.
use crate::{boot_protocol::canonical_number as number, build::Result};
use ev_diagnostics::system::{Admission, Manifest, Phase, Snapshot};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const PREFIX: &str = "EVROSION_M6_STARTUP";
const PHASE: &str = "EVROSION_M6_STARTUP_PHASE";
const PHASE_COUNTS: &str = "EVROSION_M6_STARTUP_PHASE_COUNTS";
const CPU: &str = "EVROSION_M6_STARTUP_CPU";
const CPU_COUNTS: &str = "EVROSION_M6_STARTUP_CPU_COUNTS";

#[derive(Debug)]
pub(crate) struct Record {
    lines: BTreeSet<usize>,
}
impl Record {
    pub(crate) fn contains_line(&self, line: usize) -> bool {
        self.lines.contains(&line)
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Layout {
    Compact,
    #[cfg(test)]
    Legacy05,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Event {
    phase: u64,
    wire: u64,
    tick: u64,
    process: u64,
    thread: u64,
    peer_process: u64,
    peer_thread: u64,
    endpoint: u64,
    ticket: u64,
    epoch: u64,
    call: u64,
    value: u64,
}
fn fields<'a>(line: &'a str, build: &str, name: &str, count: usize) -> Result<Vec<&'a str>> {
    let fields: Vec<_> = line.split(' ').collect();
    if line.len() > 1024
        || fields.len() != count
        || fields[0] != name
        || fields[1] != "protocol=1"
        || fields[2] != format!("build={build}")
    {
        return Err("startup diagnostic shape/build".into());
    }
    Ok(fields)
}
fn finite(value: u64) -> Result<u64> {
    if matches!(value, 0 | u64::MAX) {
        return Err("startup diagnostic nonzero finite identity".into());
    }
    Ok(value)
}
fn word(field: &str) -> Result<u64> {
    let hex = field.strip_prefix("value=").ok_or("startup value key")?;
    if hex.len() != 16
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("startup value canonical16hex".into());
    }
    u64::from_str_radix(hex, 16).map_err(|_| "startup value overflow".into())
}
fn event(line: &str, build: &str, layout: Layout) -> Result<Event> {
    let f = fields(line, build, PHASE, 15)?;
    let n = f[3..14]
        .iter()
        .zip([
            "phase",
            "wire",
            "tick",
            "process",
            "thread",
            "peer_process",
            "peer_thread",
            "endpoint",
            "ticket",
            "call_epoch",
            "call",
        ])
        .map(|(f, k)| number(f, k))
        .collect::<Result<Vec<_>>>()?;
    let e = Event {
        phase: n[0],
        wire: n[1],
        tick: n[2],
        process: n[3],
        thread: n[4],
        peer_process: n[5],
        peer_thread: n[6],
        endpoint: n[7],
        ticket: n[8],
        epoch: n[9],
        call: n[10],
        value: word(f[14])?,
    };
    for value in [
        e.tick,
        e.process,
        e.thread,
        e.peer_process,
        e.peer_thread,
        e.endpoint,
        e.ticket,
    ] {
        finite(value)?;
    }
    match e.phase {
        1 | 2
            if e.wire == 15
                && e.epoch == 0
                && e.call == 0
                && [
                    u64::from_le_bytes(*b"EVGARDY1"),
                    u64::from_le_bytes(*b"EVGADON1"),
                    u64::from_le_bytes(*b"EVAPCRD1"),
                ]
                .contains(&e.value) => {}
        3..=8
            if e.wire == 0
                && finite(e.epoch).is_ok()
                && finite(e.call).is_ok()
                && e.value as u32 == u32::from_le_bytes(*b"EVP1")
                && (1..u64::from(u32::MAX)).contains(&(e.value >> 32)) => {}
        9 if layout == Layout::Compact
            && e.wire == 7
            && e.epoch == 0
            && e.call == 0
            && e.value == 0x000000010301544e => {}
        _ => return Err("startup diagnostic phase/wire/token/call".into()),
    }
    Ok(e)
}
fn digest(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("startup diagnostic digest".into());
    }
    let mut bytes = [0; 32];
    for (out, pair) in bytes
        .iter_mut()
        .zip(text.as_bytes().as_chunks::<2>().0.iter())
    {
        *out = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16)
            .map_err(|_| "startup digest byte")?;
    }
    Ok(bytes)
}
fn manifest(m: Manifest) -> Result<ev_store::GenerationManifest> {
    Ok(ev_store::GenerationManifest {
        generation: ev_store::GenerationId::new(m.generation).ok_or("startup generation")?,
        cohort: m.cohort,
        supervisor_image: m.supervisor_image,
        abi: m.abi,
        health_contract: m.health_contract,
        health_version: m.health_version,
        required_checks: m.required_checks,
    })
}
fn bind_admission(
    root: &crate::native3_protocol::CommonPrefix,
    app: &crate::downloaded_protocol::Action,
    admission: Admission,
    manifests: &[Manifest],
    layout: Layout,
) -> Result<()> {
    let m = manifests
        .iter()
        .find(|m| {
            manifest(**m).is_ok_and(|m| {
                ev_root_supervisor::native_plan::system::manifest_digest(&m) == admission.manifest
            })
        })
        .ok_or("startup current admission has no preceding exact manifest")?;
    if app.process == root.root_process
        || app.thread == root.root_thread
        || app.process == root.block_process
        || app.thread == root.block_thread
        || m.generation != admission.generation
        || !matches!(m.generation, 2 | 3)
        || m.supervisor_image != digest(&root.root_image)?
        || (layout == Layout::Compact
            && (m.health_version != 2
                || m.abi != ev_userspace_contract::root_v4::ABI
                || m.health_contract
                    != <[u8; 32]>::from(Sha256::digest(
                        ev_root_supervisor::downloaded_health::HEALTH_DESCRIPTION,
                    ))))
    {
        return Err("startup current admission/subject/cohort mismatch".into());
    }
    let mut h = Sha256::new();
    if m.health_version == 2 {
        h.update(b"evrosion.V4.downloaded-cohort.actual-admission.v2\0");
        h.update(m.health_version.to_le_bytes());
        h.update(m.health_contract);
    } else if layout != Layout::Compact && m.health_version == 1 {
        h.update(b"evrosion.V4.downloaded-cohort.actual-admission.v1\0");
    } else {
        return Err("startup diagnostic admission version".into());
    }
    for d in [
        m.cohort,
        digest(&root.root_manifest)?,
        digest(&root.root_image)?,
        digest(&app.elf_sha256)?,
    ] {
        h.update(d);
    }
    for n in [
        m.generation,
        admission.boot_serial,
        root.root_epoch,
        root.root_incarnation,
        root.root_process,
        root.root_thread,
        app.process,
        app.thread,
    ] {
        h.update(n.to_le_bytes());
    }
    if <[u8; 32]>::from(h.finalize()) != admission.process_stamp {
        return Err("startup diagnostic actual Root/subject admission stamp".into());
    }
    Ok(())
}

/// Production accepts only the current compact layout, including BOTH closing
/// footers even when no CPU sample was available. No inferred legacy fallback.
pub(crate) fn record(serial: &[u8], build: &str) -> Result<Option<Record>> {
    record_layout(serial, build, Layout::Compact)
}

/// A pre-frame downloaded App fault is distinct from the legacy initial Shell
/// fault. Return only its exact retained line after joining the complete actual
/// registration/lifetime, Kernel capture, capsule, failed admission and surviving
/// Display. This is a collector check, never authority or a health result.
pub(crate) fn downloaded_fault_line(serial: &[u8], build: &str) -> Result<Option<usize>> {
    let text = std::str::from_utf8(serial).map_err(|_| "downloaded fault UTF8")?;
    let rows: Vec<_> = text.lines().collect();
    let mut faults = Vec::new();
    for (at, line) in rows.iter().enumerate() {
        if line.starts_with("EVROSION_NATIVE_FAULT ") {
            let crate::native_diagnostics::Event::Fault(f) =
                crate::native_diagnostics::parse(line, build, at)?
            else {
                unreachable!()
            };
            faults.push(f);
        }
    }
    if !faults.iter().any(|f| f.words[3] == 6)
        && !rows.iter().any(|l| {
            l.starts_with("EVROSION_M4_DESKTOP_LIFECYCLE ") && l.split(' ').any(|f| f == "vector=6")
        })
    {
        return Ok(None);
    }
    if serial.len() > 1024 * 1024 || !serial.ends_with(b"\n") || faults.len() != 1 {
        return Err("downloaded fault bounded unique complete capture".into());
    }
    crate::native3_diagnostics::owners(serial, build)?;
    let actions = crate::downloaded_protocol::records(serial, build, true)?;
    if actions.len() != 3 || actions[0].kind != "start" {
        return Err("downloaded fault needs one closed registered lifetime".into());
    }
    let app = &actions[0];
    let fault = &faults[0];
    let mut roots = Vec::new();
    let mut systems = Vec::new();
    let mut crashes = Vec::new();
    let mut report_origins = Vec::new();
    let mut steps = Vec::new();
    let mut lifecycles = Vec::new();
    let mut action_lines = Vec::new();
    for (at, line) in rows.iter().enumerate() {
        if line.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX ") {
            let crate::native3_protocol::Event::Common(c) =
                crate::native3_protocol::event_network(line, build)?
            else {
                unreachable!()
            };
            roots.push(c);
        } else if line.starts_with("EVROSION_NATIVE_SYSTEM ")
            || line.starts_with("EVROSION_NATIVE_CRASH ")
        {
            let crate::native_diagnostics::Event::Report(r) =
                crate::native_diagnostics::parse(line, build, at)?
            else {
                unreachable!()
            };
            report_origins.push(r.origin);
            if r.kind == crate::native_diagnostics::Kind::System {
                systems.push((
                    at,
                    Snapshot::decode(&r.bytes).map_err(|_| "downloaded fault System codec")?,
                ));
            } else {
                crashes.push(r);
            }
        } else if line.starts_with("EVROSION_M4_DESKTOP_STEP ") {
            steps.push((at, crate::desktop_protocol::step_line(line, build)?));
        } else if line.starts_with("EVROSION_M4_DESKTOP_LIFECYCLE ") {
            lifecycles.push(at);
        } else if line.starts_with("EVROSION_M6_DOWNLOADED_ACTION ") {
            action_lines.push(at);
        }
    }
    if roots.len() != 1 || crashes.len() != 1 || lifecycles.len() != 1 || steps.is_empty() {
        return Err("downloaded fault unique Root/capsule/lifecycle/survivor".into());
    }
    let root = &roots[0];
    let (terminal_at, terminal) = systems
        .last()
        .ok_or("downloaded fault terminal System absent")?;
    let admission = terminal
        .current
        .ok_or("downloaded fault current admission absent")?;
    let failure = terminal
        .last_failure
        .ok_or("downloaded fault lastFailure absent")?;
    let manifests: Vec<_> = systems.iter().filter_map(|(_, s)| s.selected).collect();
    bind_admission(root, app, admission, &manifests, Layout::Compact)?;
    if root.mode != 1
        || report_origins
            .iter()
            .any(|o| *o != (root.root_process, root.root_thread))
        || admission.generation != 3
        || admission.phase != Phase::Failed
        || terminal.selected.is_none_or(|m| m.generation != 2)
        || terminal.known_good != Some(2)
        || failure.generation != admission.generation
        || failure.boot_serial != admission.boot_serial
        || failure.reason != 5
        || failure.supervisor_image != digest(&root.root_image)?
        || failure.process_stamp != Some(admission.process_stamp)
        || fault.actor != 5
        || fault.epoch != root.root_epoch
        || fault.incarnation != root.root_incarnation
        || fault.image != digest(&app.elf_sha256)?
        || fault.words[..6] != [app.job, app.process, app.thread, 6, 0, 0]
        || app.content_sha256 != app.declared_package_id
    {
        return Err("downloaded fault actual C/Kernel/current failed admission differs".into());
    }
    let crash = &crashes[0];
    let capsule =
        ev_diagnostics::Crash::decode(&crash.bytes).map_err(|_| "downloaded fault Crash codec")?;
    let provenance = capsule.provenance();
    if crate::native_diagnostics::capture_words(capsule.capture()) != fault.words
        || !matches!(
            provenance.component,
            ev_diagnostics::Component::Application(id)
                if id.bytes() == crate::native_package::HELLO_APP_ID
        )
        || provenance.image != fault.image
        || provenance.package != Some(digest(&app.declared_package_id)?)
        || provenance.generation != Some(admission.manifest)
        || (provenance.epoch, provenance.incarnation) != (root.root_epoch, root.root_incarnation)
    {
        return Err("downloaded fault capsule differs from actual complete Kernel capture".into());
    }
    let lifecycle = lifecycles[0];
    let (frame_at, frame) = &steps[0];
    let expected = format!(
        "EVROSION_M4_DESKTOP_LIFECYCLE protocol=1 build={build} event=fault actor=app process={} thread={} replacement=0 display_process={} grants=0 vector=6 error=0 address=0",
        app.process, app.thread, frame.display_process
    );
    if rows[lifecycle] != expected
        || action_lines.len() != 3
        || !(action_lines[0] < fault.at
            && fault.at < action_lines[1]
            && action_lines[1] < lifecycle
            && lifecycle < *frame_at
            && *frame_at < action_lines[2]
            && action_lines[2] < crash.at
            && crash.at < *terminal_at)
        || steps.iter().any(|(_, s)| {
            s.kind != crate::desktop_protocol::StepKind::Frame
                || s.producer != crate::desktop_protocol::Producer::Shell
                || s.app_process != app.process
                || s.grants != 0
                || s.display_process != frame.display_process
                || s.shell_process != frame.shell_process
        })
    {
        return Err(
            "downloaded fault exact pre-frame lifecycle/surviving Shell/Display order".into(),
        );
    }
    let native = crate::native_protocol::record_network(serial, build)?;
    let profiles = crate::native_profile::finished_network(serial, build, 1, Some(1))?;
    if native.counts["faults"] != 1
        || native.counts["restarts"] != 0
        || native.counts["grants"] != 0
        || !native.actions.is_empty()
        || profiles[1].counts["current_process"] != frame.shell_process
        || profiles[1].counts["incarnations"] != 1
        || profiles[1].counts["faults"] != 0
        || profiles[5].counts["incarnations"] != 1
        || profiles[5].counts["faults"] != 1
        || profiles[5].counts["current_process"] != 0
        || profiles[6].counts["current_process"] != frame.display_process
        || profiles[6].counts["incarnations"] != 1
        || profiles[6].counts["faults"] != 0
    {
        return Err(
            "downloaded fault closed native App and surviving Display profile differs".into(),
        );
    }
    Ok(Some(lifecycle))
}
fn record_layout(serial: &[u8], build: &str, layout: Layout) -> Result<Option<Record>> {
    let text = std::str::from_utf8(serial).map_err(|_| "startup diagnostic UTF8")?;
    if !text.lines().any(|l| l.starts_with(PREFIX)) {
        return Ok(None);
    }
    if serial.len() > 1024 * 1024 || !serial.ends_with(b"\n") {
        return Err("startup diagnostic bounded complete capture".into());
    }
    digest(build)?;
    crate::downloaded_protocol::records(serial, build, false)?;
    // Root shares one framed-report serial across System/Crash/Job/Owner.
    // Validate that complete typed sequence; System rows form a subsequence.
    crate::native3_diagnostics::owners(serial, build)?;
    let ui = crate::session_io::ProbeUi::parse(serial, build)?;
    let rows: Vec<_> = text.lines().collect();
    let mut root = None;
    let mut subject = None;
    let mut manifests = Vec::new();
    let mut terminal = None;
    let mut system_serial = 0;
    let mut events: Vec<Event> = Vec::new();
    let mut cpus = BTreeSet::new();
    let mut lines = BTreeSet::new();
    let mut stage = 0;
    let mut overflow = 0;
    let mut last_cpu_tick = None;
    let mut last_valid_cpu: Option<[u64; 10]> = None;
    let mut displays = BTreeSet::new();
    let mut display_threads = BTreeSet::new();
    for (at, line) in rows.iter().enumerate() {
        let line = line.trim_end_matches('\r');
        if !line.starts_with(PREFIX) {
            if matches!(stage, 1 | 2) {
                return Err("startup diagnostic block interrupted/truncated".into());
            }
            if line.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX") {
                let crate::native3_protocol::Event::Common(c) =
                    crate::native3_protocol::event_network(line, build)?
                else {
                    unreachable!()
                };
                if root.replace(c).is_some() {
                    return Err("startup duplicate actual Root prefix".into());
                }
            } else if line.starts_with("EVROSION_M6_DOWNLOADED_ACTION") {
                let a = crate::downloaded_protocol::line(line, build)?;
                if a.kind == "start" && stage == 0 && subject.replace(a).is_some() {
                    return Err("startup multiple downloaded subjects before block".into());
                }
            } else if line.starts_with("EVROSION_NATIVE_SYSTEM") {
                let crate::native_diagnostics::Event::Report(r) =
                    crate::native_diagnostics::parse(line, build, at)?
                else {
                    unreachable!()
                };
                let c = root.as_ref().ok_or("startup System before actual Root")?;
                if r.origin != (c.root_process, c.root_thread) || r.serial <= system_serial {
                    return Err("startup System origin/report replay".into());
                }
                system_serial = r.serial;
                let s = Snapshot::decode(&r.bytes).map_err(|_| "startup typed System snapshot")?;
                if let Some(m) = s.selected {
                    manifests.push(m);
                }
                if stage == 0 {
                    terminal = s
                        .current
                        .filter(|a| matches!(a.phase, Phase::Healthy | Phase::Failed))
                        .map(|a| (at, a));
                }
            } else if stage == 0 && line.starts_with("EVROSION_M4_DESKTOP_STEP ") {
                let s = crate::desktop_protocol::step_line(line, build)?;
                displays.insert(s.display_process);
            } else if stage == 0 && line.starts_with("EVROSION_M6_CURSOR ") {
                crate::session_io::line(line, build)?;
                let f: Vec<_> = line.split(' ').collect();
                display_threads.insert((
                    number(f[9], "callee_process")?,
                    number(f[10], "callee_thread")?,
                ));
            }
            continue;
        }
        if stage == 3 {
            return Err("startup diagnostic replay/row after close".into());
        }
        if stage == 0 {
            let c = root
                .as_ref()
                .ok_or("startup diagnostic actual Root absent")?;
            let (terminal_at, a) =
                terminal.ok_or("startup diagnostic lacks preceding terminal CURRENT admission")?;
            if c.mode != 1 || terminal_at + 1 != at {
                return Err("startup diagnostic needs Managed/current terminal adjacency".into());
            }
            let app = subject
                .as_ref()
                .ok_or("startup terminal admission lacks actual downloaded subject")?;
            bind_admission(c, app, a, &manifests, layout)?;
            stage = 1;
        }
        lines.insert(at);
        if line.starts_with(&format!("{PHASE} ")) && stage == 1 {
            let e = event(line, build, layout)?;
            let c = root.as_ref().unwrap();
            let app = subject
                .as_ref()
                .ok_or("startup event has no actual downloaded subject")?;
            if (e.process, e.thread) != (app.process, app.thread)
                || events.last().is_some_and(|p| p.tick > e.tick)
                || events.len() == 16
            {
                return Err("startup event subject/order/capacity".into());
            }
            if matches!(e.phase, 1 | 2 | 9)
                && (e.peer_process, e.peer_thread) != (c.root_process, c.root_thread)
            {
                return Err("startup event foreign Root".into());
            }
            if (3..=8).contains(&e.phase) {
                if e.epoch != c.root_epoch
                    || (!displays.is_empty() && !displays.contains(&e.peer_process))
                    || (!display_threads.is_empty()
                        && !display_threads.contains(&(e.peer_process, e.peer_thread)))
                {
                    return Err("startup Present foreign Display/epoch".into());
                }
                let previous = events.iter().rev().find(|p| (3..=8).contains(&p.phase));
                if previous.is_none() && e.phase != 3
                    || previous.is_some_and(|p| {
                        e.phase != p.phase + 1
                            || (
                                e.endpoint,
                                e.ticket,
                                e.epoch,
                                e.call,
                                e.value,
                                e.peer_process,
                                e.peer_thread,
                            ) != (
                                p.endpoint,
                                p.ticket,
                                p.epoch,
                                p.call,
                                p.value,
                                p.peer_process,
                                p.peer_thread,
                            )
                    })
                {
                    return Err("startup first Present call/phase changed/replayed".into());
                }
            } else if e.phase == 2 {
                if !events.iter().any(|p| {
                    p.phase == 1
                        && p.ticket == e.ticket
                        && p.endpoint == e.endpoint
                        && p.value == e.value
                }) || events.iter().any(|p| p.phase == 2 && p.ticket == e.ticket)
                {
                    return Err("startup receive lacks unique accepted token/ticket".into());
                }
            } else if e.phase == 1 && events.iter().any(|p| p.phase == 1 && p.ticket == e.ticket) {
                return Err("startup accepted ticket replay".into());
            }
            if e.phase == 9 {
                let scope = Scope {
                    root: c,
                    app,
                    serial,
                    build,
                    ui: &ui,
                    at,
                };
                if note_tuple(&scope)? != (e.endpoint, e.ticket, e.tick) {
                    return Err("startup Note differs from actual delivery".into());
                }
                if events.iter().any(|p| p.phase == 9) {
                    return Err("startup Note phase replay".into());
                }
            }
            events.push(e);
        } else if line.starts_with(&format!("{PHASE_COUNTS} ")) && stage == 1 {
            let f = fields(line, build, PHASE_COUNTS, 8)?;
            let n = f[3..7]
                .iter()
                .zip(["capacity", "observed", "retained", "overflow"])
                .map(|(f, k)| number(f, k))
                .collect::<Result<Vec<_>>>()?;
            if n[0] != 16
                || n[2] != events.len() as u64
                || n[1] != n[2].saturating_add(n[3])
                || f[7] != "closed=true"
                || n[3] != 0 && n[2] != 16
            {
                return Err("startup phase count/close mismatch".into());
            }
            overflow = n[3];
            stage = if layout == Layout::Compact { 2 } else { 3 };
        } else if line.starts_with(&format!("{CPU} ")) && stage == 2 {
            let scope = Scope {
                root: root.as_ref().unwrap(),
                app: subject.as_ref().ok_or("startup CPU subject")?,
                serial,
                build,
                ui: &ui,
                at,
            };
            let (tick, sample) = cpu(line, &events, overflow, &scope, &mut cpus)?;
            if let Some(current) = sample {
                if let Some(previous) = last_valid_cpu
                    && (current[1] < previous[1]
                        || current[2] < previous[2]
                        || current[3] != previous[3]
                        || current[4] != previous[4]
                        || current[5] < previous[5]
                        || (current[5] - previous[5]) % current[4] != 0
                        || (current[5] == previous[5] && current[7] < previous[7]))
                {
                    return Err("startup same-Job CPU snapshot moved backwards/reconfigured".into());
                }
                last_valid_cpu = Some(current);
            }
            if last_cpu_tick.is_some_and(|previous| previous > tick) {
                return Err("startup CPU point order".into());
            }
            last_cpu_tick = Some(tick);
        } else if line.starts_with(&format!("{CPU_COUNTS} ")) && stage == 2 {
            let f = fields(line, build, CPU_COUNTS, 9)?;
            let n = f[3..8]
                .iter()
                .zip(["capacity", "observed", "retained", "duplicates", "overflow"])
                .map(|(f, k)| number(f, k))
                .collect::<Result<Vec<_>>>()?;
            if n[0] != 2
                || n[2] != cpus.len() as u64
                || n[1] != n[2].saturating_add(n[3]).saturating_add(n[4])
                || f[8] != "closed=true"
                || n[4] != 0 && n[2] != 2
            {
                return Err("startup CPU count/close mismatch".into());
            }
            stage = 3;
        } else {
            return Err("startup diagnostic unknown/out-of-order row".into());
        }
    }
    if stage != 3 {
        return Err("startup diagnostic missing closed footers".into());
    }
    Ok(Some(Record { lines }))
}
struct Scope<'a> {
    root: &'a crate::native3_protocol::CommonPrefix,
    app: &'a crate::downloaded_protocol::Action,
    serial: &'a [u8],
    build: &'a str,
    ui: &'a crate::session_io::ProbeUi,
    at: usize,
}
fn note_tuple(scope: &Scope<'_>) -> Result<(u64, u64, u64)> {
    let at = scope
        .ui
        .note_complete(scope.app.process, 1, 1)
        .ok_or("startup Note lacks genuine request/accepted/delivered join")?;
    if at >= scope.at {
        return Err("startup Note delivery follows diagnostic output".into());
    }
    let line = std::str::from_utf8(scope.serial)
        .unwrap()
        .lines()
        .nth(at)
        .ok_or("startup Note line")?;
    crate::session_io::line(line, scope.build)?;
    let f: Vec<_> = line.split(' ').collect();
    if (
        number(f[7], "sender_process")?,
        number(f[8], "sender_thread")?,
    ) != (scope.root.root_process, scope.root.root_thread)
        || (
            number(f[9], "receiver_process")?,
            number(f[10], "receiver_thread")?,
        ) != (scope.app.process, scope.app.thread)
        || f[13] != "message=000000010301544e"
    {
        return Err("startup Note foreign actual Root/subject/message".into());
    }
    Ok((
        number(f[5], "endpoint")?,
        number(f[6], "ticket")?,
        number(f[14], "tick")?,
    ))
}
fn cpu(
    line: &str,
    events: &[Event],
    overflow: u64,
    scope: &Scope<'_>,
    seen: &mut BTreeSet<u64>,
) -> Result<(u64, Option<[u64; 10]>)> {
    let build = scope.build;
    let raw: Vec<_> = line.split(' ').collect();
    let valid = match raw.get(11) {
        Some(&"cpu_valid=true") => true,
        Some(&"cpu_valid=false") => false,
        _ => return Err("startup CPU availability schema".into()),
    };
    let f = fields(line, build, CPU, if valid { 22 } else { 12 })?;
    let n = f[3..11]
        .iter()
        .zip([
            "phase",
            "tick",
            "process",
            "thread",
            "app_job",
            "ticket",
            "call_epoch",
            "call",
        ])
        .map(|(f, k)| number(f, k))
        .collect::<Result<Vec<_>>>()?;
    let app = scope.app;
    if !matches!(n[0], 3 | 9)
        || !seen.insert(n[0])
        || seen.len() > 2
        || (n[2], n[3], n[4]) != (app.process, app.thread, app.job)
    {
        return Err("startup CPU phase/subject/job/replay".into());
    }
    for v in [n[1], n[2], n[3], n[4], n[5]] {
        finite(v)?;
    }
    if n[0] == 9 && (n[6] != 0 || n[7] != 0)
        || n[0] == 3 && (n[6] != scope.root.root_epoch || finite(n[7]).is_err())
    {
        return Err("startup CPU call identity".into());
    }
    match events.iter().find(|e| e.phase == n[0]) {
        Some(e)
            if (e.tick, e.process, e.thread, e.ticket, e.epoch, e.call)
                == (n[1], n[2], n[3], n[5], n[6], n[7]) => {}
        None if overflow != 0 => (),
        _ => return Err("startup CPU differs from retained actual event".into()),
    }
    if n[0] == 9 {
        let (_, ticket, tick) = note_tuple(scope)?;
        if (ticket, tick) != (n[5], n[1]) {
            return Err("startup CPU Note differs from actual delivered reply".into());
        }
    }
    let sample = if valid {
        let b = f[12..]
            .iter()
            .zip([
                "sampled_job",
                "app_charged_cpu",
                "scheduler_tick",
                "quota",
                "period",
                "window_start",
                "window_end",
                "consumed",
                "reserved",
                "remaining",
            ])
            .map(|(f, k)| number(f, k))
            .collect::<Result<Vec<_>>>()?;
        if b.contains(&u64::MAX)
            || b[0] != app.job
            || finite(b[2]).is_err()
            || finite(b[3]).is_err()
            || finite(b[4]).is_err()
            || b[3] > b[4]
            || b[5].checked_add(b[4]) != Some(b[6])
            || b[7].checked_add(b[8]).and_then(|v| v.checked_add(b[9])) != Some(b[3])
            || b[1] < b[7]
            || b[2] > n[1]
            || !(b[5]..b[6]).contains(&b[2])
        {
            return Err("startup CPU finite budget/window/accounting".into());
        }
        Some(b.try_into().map_err(|_| "startup CPU sample width")?)
    } else {
        None
    };
    Ok((n[1], sample))
}

#[cfg(test)]
#[path = "startup_protocol_tests.rs"]
mod tests;
