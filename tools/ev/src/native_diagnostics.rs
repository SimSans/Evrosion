//! Independent joins of source-collected records and actual Kernel observations.
//! Syntax, identities and diagnostic IDs never grant authority or prove health.
use crate::{
    boot_protocol::canonical_number, build::Result, native_io::Phase, native_profile,
    native_protocol, storage,
};
use ev_diagnostics::{
    Capture, Component, Crash,
    inspector::Job,
    live::{Role, Row},
    system::{Snapshot, State},
};
use ev_userspace_contract::root_v2::{graph::Child, native::catalogue::Catalogue};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt::Write as _, fs, path::Path};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Crash,
    Job,
    System,
}
impl Kind {
    fn bytes(self) -> usize {
        match self {
            Self::Crash => 416,
            Self::Job => 192,
            Self::System => 384,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Crash => "crash",
            Self::Job => "job",
            Self::System => "system",
        }
    }
}
#[derive(Debug)]
pub(crate) struct Report {
    pub(crate) kind: Kind,
    pub(crate) serial: u32,
    pub(crate) origin: (u64, u64),
    pub(crate) bytes: Vec<u8>,
    pub(crate) at: usize,
}
#[derive(Debug)]
pub(crate) struct Fault {
    pub(crate) actor: u64,
    pub(crate) image: [u8; 32],
    pub(crate) epoch: u64,
    pub(crate) incarnation: u64,
    pub(crate) words: [u64; 24],
    pub(crate) at: usize,
}
#[derive(Clone, Debug)]
pub(crate) struct Query {
    pub(crate) sequence: u64,
    pub(crate) origin: (u64, u64),
    pub(crate) capability: u64,
    pub(crate) field: u64,
    pub(crate) value: u64,
    pub(crate) tick: u64,
    pub(crate) status: u64,
    pub(crate) denial: u64,
    pub(crate) at: usize,
}
#[allow(clippy::large_enum_variant)] // Fixed bounded actual24-word raw capture.
pub(crate) enum Event {
    Report(Report),
    Fault(Fault),
    Query(Query),
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(text: &str, bytes: usize) -> Result<Vec<u8>> {
    if text.len() != bytes * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Native diagnostic requires exact lowercase hex".into());
    }
    (0..bytes)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
fn field<'a>(text: &'a str, key: &str) -> Result<&'a str> {
    text.strip_prefix(key)
        .and_then(|s| s.strip_prefix('='))
        .ok_or_else(|| format!("Native diagnostic missing {key}"))
}
fn identity(text: &str, key: &str) -> Result<u64> {
    let n = canonical_number(text, key)?;
    if n == 0 || n == u64::MAX {
        return Err(format!("Native diagnostic invalid {key}"));
    }
    Ok(n)
}
pub(crate) fn parse(line: &str, build: &str, at: usize) -> Result<Event> {
    unhex(build, 32)?;
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 2048 || f.len() < 3 || f[1] != "protocol=1" || field(f[2], "build")? != build {
        return Err("malformed/wrong-build Native diagnostic".into());
    }
    let kind = match f[0] {
        "EVROSION_NATIVE_CRASH" => Some(Kind::Crash),
        "EVROSION_NATIVE_JOB" => Some(Kind::Job),
        "EVROSION_NATIVE_SYSTEM" => Some(Kind::System),
        _ => None,
    };
    if let Some(kind) = kind {
        if f.len() != 7 {
            return Err("Native diagnostic report fields differ".into());
        }
        let serial = u32::try_from(identity(f[3], "report")?)
            .map_err(|_| "Native report serial overflows")?;
        let origin = (
            identity(f[4], "root_process")?,
            identity(f[5], "root_thread")?,
        );
        let bytes = unhex(field(f[6], "bytes")?, kind.bytes())?;
        match kind {
            Kind::Crash => {
                Crash::decode(&bytes).map_err(|e| format!("Native crash codec: {e:?}"))?;
            }
            Kind::Job => {
                Row::decode(&bytes).map_err(|e| format!("Native Job codec: {e:?}"))?;
            }
            Kind::System => {
                Snapshot::decode(&bytes).map_err(|e| format!("Native System codec: {e:?}"))?;
            }
        }
        return Ok(Event::Report(Report {
            kind,
            serial,
            origin,
            bytes,
            at,
        }));
    }
    if f[0] == "EVROSION_NATIVE_FAULT" {
        if f.len() != 8 {
            return Err("Native raw fault fields differ".into());
        }
        let actor = canonical_number(f[3], "actor")?;
        if !matches!(actor, 1 | 5) {
            return Err("unexpected Native raw fault actor".into());
        }
        let image = unhex(field(f[4], "image_sha256")?, 32)?.try_into().unwrap();
        let epoch = identity(f[5], "root_epoch")?;
        let incarnation = identity(f[6], "root_incarnation")?;
        let values: Vec<_> = field(f[7], "words")?.split(',').collect();
        if values.len() != 24 {
            return Err("Native raw fault needs24 exact words".into());
        }
        let mut words = [0; 24];
        for (out, input) in words.iter_mut().zip(values) {
            *out = canonical_number(&format!("word={input}"), "word")?;
        }
        if words[..3].iter().any(|n| *n == 0 || *n == u64::MAX) {
            return Err("Native raw fault identity absent".into());
        }
        return Ok(Event::Fault(Fault {
            actor,
            image,
            epoch,
            incarnation,
            words,
            at,
        }));
    }
    if f[0] == "EVROSION_NATIVE_JOB_FIELD" {
        if f.len() != 12 {
            return Err("Native Job observation fields differ".into());
        }
        let q = Query {
            sequence: identity(f[3], "sequence")?,
            origin: (
                identity(f[4], "root_process")?,
                identity(f[5], "root_thread")?,
            ),
            capability: canonical_number(f[6], "capability")?,
            field: canonical_number(f[7], "field")?,
            value: canonical_number(f[8], "value")?,
            tick: canonical_number(f[9], "tick")?,
            status: canonical_number(f[10], "status")?,
            denial: canonical_number(f[11], "denial")?,
            at,
        };
        if q.sequence > 512
            || q.field > 8
            || !matches!((q.status, q.denial), (0, 0) | (1, 1..=3))
            || (q.status != 0 && q.value != 0)
        {
            return Err("invalid Native Job result/denial".into());
        }
        return Ok(Event::Query(q));
    }
    Err("unknown Native diagnostic envelope".into())
}
/// Generic parser gate only. Actual source/phase/capture provenance is joined
/// separately by retain; old generic parser fixtures need not invent live facts.
pub(crate) fn line(line: &str, build: &str) -> Result<()> {
    if line.starts_with("EVROSION_NATIVE_OWNER_PROMPT") {
        crate::native3_diagnostics::owner_line(line, build).map(drop)
    } else {
        parse(line, build, 0).map(drop)
    }
}
fn targeted(line: &str) -> bool {
    [
        "EVROSION_NATIVE_CRASH",
        "EVROSION_NATIVE_JOB",
        "EVROSION_NATIVE_SYSTEM",
        "EVROSION_NATIVE_FAULT",
    ]
    .iter()
    .any(|prefix| line.starts_with(prefix))
}
#[derive(Debug)]
pub(crate) struct Group {
    pub(crate) capability: u64,
    pub(crate) values: [u64; 9],
    pub(crate) first: usize,
    pub(crate) last: usize,
    pub(crate) first_tick: u64,
    pub(crate) last_tick: u64,
    pub(crate) first_sequence: u64,
    pub(crate) last_sequence: u64,
}
pub(crate) fn groups(queries: &[Query]) -> Result<Vec<Group>> {
    let mut result = Vec::new();
    let mut pending: Vec<&Query> = Vec::new();
    for q in queries {
        if q.status != 0 {
            if !pending.is_empty() {
                return Err("Job denial interleaved a synchronous collector group".into());
            }
            continue;
        }
        let index = pending.len();
        if q.field != if index == 9 { 0 } else { index as u64 }
            || pending
                .first()
                .is_some_and(|p| p.capability != q.capability || p.origin != q.origin)
        {
            return Err("Native Job collector field/capability order changed".into());
        }
        pending.push(q);
        if pending.len() == 10 {
            if pending[0].value == 0 || pending[0].value != pending[9].value {
                return Err("Native Job collector lost its actual Job identity".into());
            }
            result.push(Group {
                capability: pending[0].capability,
                values: core::array::from_fn(|i| pending[i].value),
                first: pending[0].at,
                last: q.at,
                first_tick: pending[0].tick,
                last_tick: q.tick,
                first_sequence: pending[0].sequence,
                last_sequence: q.sequence,
            });
            pending.clear();
        }
    }
    if !pending.is_empty() {
        return Err("truncated Native Job collector group".into());
    }
    Ok(result)
}
pub(crate) fn capture_words(c: Capture) -> [u64; 24] {
    let mut out = [0; 24];
    out[..9].copy_from_slice(&[
        c.job,
        c.process,
        c.thread,
        c.vector,
        c.error,
        c.address,
        c.instruction,
        c.stack,
        c.flags,
    ]);
    out[9..].copy_from_slice(&c.registers);
    out
}
pub(crate) fn job_values(j: Job) -> [u64; 9] {
    [
        j.diagnostic_id,
        j.subtree.cpu_ticks,
        j.subtree.frames,
        j.subtree.processes,
        j.subtree.threads,
        j.limits.cpu_ticks,
        j.limits.frames,
        j.limits.processes,
        j.limits.threads,
    ]
}
struct Sources {
    root: [u8; 32],
    input: [u8; 32],
    images: [[u8; 32]; 6],
    app: [u8; 16],
    packages: [[u8; 32]; 2],
    builds: [[u8; 32]; 2],
    app_images: [[u8; 32]; 2],
}
fn sources(packages: [&[u8]; 2], catalogue: &[u8], recipe: &str) -> Result<Sources> {
    let cat =
        Catalogue::decode(catalogue).map_err(|e| format!("Native diagnostics catalogue: {e:?}"))?;
    if cat.boot_mode() != ev_userspace_contract::root_v2::native::catalogue::BootMode::Standalone
        || ev_root_supervisor::native_plan::layout_measurement(&cat) != cat.layout_measurement()
        || ev_root_supervisor::desktop_plan::graph_measurement(cat.base())
            != cat.base().graph_measurement()
    {
        return Err("Native diagnostic catalogue measurement differs".into());
    }
    let parsed = packages.map(|p| {
        ev_zion::Package::parse(p).map_err(|e| format!("Native diagnostic package: {e:?}"))
    });
    let [a, b] = parsed;
    let [a, b] = [a?, b?];
    let base = cat.base();
    let ids = [a.id().bytes(), b.id().bytes()];
    let builds = [a.app().build_id, b.app().build_id];
    let images = core::array::from_fn(|i| base.images().nth(i).unwrap().image);
    let app_images = [a.executable().digest, b.executable().digest];
    if base.kernel_input().as_slice() != unhex(recipe, 32)?.as_slice()
        || ids != [cat.package_a(), cat.package_b()]
        || builds != [base.app_build(), cat.package_b_build()]
        || a.app().claimed_app != b.app().claimed_app
        || a.app().claimed_app.bytes() != base.app_id()
        || app_images != [images[Child::App.index()], cat.app_b().image]
        || ids[0] == ids[1]
        || app_images[0] == app_images[1]
        || packages[0].len() as u64 != cat.package_a_bytes()
        || packages[1].len() as u64 != cat.package_b_bytes()
    {
        return Err(
            "Native diagnostic package/AppId/build/image/cohort association differs".into(),
        );
    }
    Ok(Sources {
        root: base.root_image(),
        input: base.kernel_input(),
        images,
        app: base.app_id(),
        packages: ids,
        builds,
        app_images,
    })
}
struct Action {
    value: native_protocol::Action,
    at: usize,
}
struct Checked {
    reports: Vec<Report>,
    queries: Vec<Query>,
    faults: Vec<Fault>,
    root: (u64, u64),
    groups: Vec<Group>,
}
fn verify(serial: &[u8], build: &str, phase: Phase, source: &Sources) -> Result<Checked> {
    if serial.len() > 1024 * 1024 {
        return Err("Native diagnostics log exceeds1MiB".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "Native diagnostics log notUTF8")?;
    let mut reports = Vec::new();
    let mut queries = Vec::new();
    let mut faults = Vec::new();
    let mut actions = Vec::new();
    let mut inspect = Vec::new();
    let mut finish = Vec::new();
    let mut ended = false;
    for (at, raw) in text.split_inclusive('\n').enumerate() {
        let complete = raw.ends_with('\n');
        let line = raw
            .strip_suffix('\n')
            .unwrap_or(raw)
            .strip_suffix('\r')
            .unwrap_or(raw.strip_suffix('\n').unwrap_or(raw));
        if targeted(line) {
            if !complete || ended {
                return Err("truncated/late Native diagnostic".into());
            }
            match parse(line, build, at)? {
                Event::Report(r) => {
                    if r.serial as usize != reports.len() + 1 || reports.len() >= 16 {
                        return Err("Native report replay/gap/overflow".into());
                    }
                    reports.push(r);
                }
                Event::Fault(f) => {
                    if faults.len() >= 2 {
                        return Err("unexpected extra Native raw fault".into());
                    }
                    faults.push(f);
                }
                Event::Query(q) => {
                    if q.sequence as usize != queries.len() + 1
                        || queries.last().is_some_and(|p: &Query| p.tick > q.tick)
                    {
                        return Err("Native Job query replay/gap/clock reversal".into());
                    }
                    queries.push(q);
                }
            }
        } else if line.starts_with("EVROSION_M5_NATIVE_ACTION") {
            if !complete {
                return Err("truncated Native action for diagnostics".into());
            }
            actions.push(Action {
                value: native_protocol::action(line, build)?,
                at,
            });
        } else if line.starts_with("EVROSION_NATIVE_STATE") {
            if !complete {
                return Err("truncated Native state for diagnostics".into());
            }
            let state = native_protocol::state_line(line, build)?;
            if state.is("inspect") {
                inspect.push(at);
            }
            if state.is("finish") {
                finish.push(at);
            }
        } else if line.starts_with("EVROSION_M5_NATIVE_PROFILE")
            || line.starts_with("EVROSION_M5_NATIVE ")
        {
            ended = true;
        }
    }
    let full = phase == Phase::InstallFull;
    let inspecting = phase == Phase::VerifyCancel;
    let expected_faults = if full { 2 } else { 0 };
    let profiles = native_profile::finished(serial, build, expected_faults, Some(0))?;
    let root = (
        profiles[0].counts["current_process"],
        profiles[0].counts["current_thread"],
    );
    if root.0 == 0
        || root.1 == 0
        || reports.iter().any(|r| r.origin != root)
        || queries.iter().any(|q| q.origin != root)
    {
        return Err("diagnostics did not originate from actual admitted Root".into());
    }
    let counts = [Kind::Crash, Kind::Job, Kind::System]
        .map(|kind| reports.iter().filter(|r| r.kind == kind).count());
    if faults.len() != expected_faults as usize
        || counts
            != [
                if full { 2 } else { 0 },
                if inspecting { 8 } else { 0 },
                1 + usize::from(inspecting),
            ]
        || inspect.len() != usize::from(inspecting)
        || finish.len() != 1
        || reports.last().is_some_and(|r| r.at >= finish[0])
    {
        return Err("Native phase lacks exact crash/inspector/completion records".into());
    }
    let common: Vec<_> = crate::native3_protocol::observations(serial, build)?
        .into_iter()
        .filter_map(|(at, e)| {
            if let crate::native3_protocol::Event::Common(c) = e {
                Some((at, c))
            } else {
                None
            }
        })
        .collect();
    if common.len() != 1 {
        return Err("Standalone requires one actual protected Root/Block prefix".into());
    }
    let (common_at, common) = &common[0];
    if common.mode != 0
        || (common.root_process, common.root_thread) != root
        || common.root_image != hex(&source.root)
        || common.block_image != hex(&source.images[3])
    {
        return Err("Standalone prefix differs from actual measured Root/Block source".into());
    }
    let initial = &reports[0];
    let state = Snapshot::decode(&initial.bytes)
        .map_err(|e| format!("Standalone initial System read: {e:?}"))?;
    if initial.kind != Kind::System
        || initial.serial != 1
        || initial.at <= *common_at
        || state.state != State::Unformatted
        || state.current.is_some()
        || state.selected.is_some()
        || state.known_good.is_some()
        || state.last_failure.is_some()
        || faults.iter().any(|f| f.at < initial.at)
        || actions.iter().any(|a| a.at < initial.at)
    {
        return Err(
            "Standalone initial read invented System admission or preceded protected prefix".into(),
        );
    }
    let groups = groups(&queries)?;
    let mut used = BTreeSet::new();
    let mut used_faults = BTreeSet::new();
    let mut captured_caps = BTreeSet::new();
    let mut crash_context = None;
    for report in reports.iter().filter(|r| r.kind == Kind::Crash) {
        let crash = Crash::decode(&report.bytes).map_err(|e| format!("Native crash: {e:?}"))?;
        let provenance = crash.provenance();
        let capture = crash.capture();
        let matching: Vec<_> = faults
            .iter()
            .enumerate()
            .filter(|(_, f)| f.at < report.at && f.words == capture_words(capture))
            .collect();
        if matching.len() != 1 {
            return Err("crash does not match one prior actual24-word fault".into());
        }
        let (fault_index, fault) = matching[0];
        if !used_faults.insert(fault_index)
            || provenance.image != fault.image
            || provenance.generation.is_some()
            || (provenance.epoch, provenance.incarnation) != (fault.epoch, fault.incarnation)
            || crash_context.is_some_and(|c| c != (fault.epoch, fault.incarnation))
            || (fault.epoch, fault.incarnation) != (common.root_epoch, common.root_incarnation)
        {
            return Err(
                "crash replay/image/actual Root epoch/generation provenance mismatch".into(),
            );
        }
        crash_context = Some((fault.epoch, fault.incarnation));
        let app = fault.actor == 5;
        if app {
            if provenance.component
                != Component::Application(ev_zion::AppId::new(source.app).unwrap())
                || provenance.package != Some(source.packages[0])
                || provenance.component_build != source.builds[0]
                || provenance.image != source.app_images[0]
            {
                return Err("App crash is not exact retained package A provenance".into());
            }
        } else if provenance.component != Component::Service(Child::Shell.image().selector() as u16)
            || provenance.package.is_some()
            || provenance.component_build != source.input
            || provenance.image != source.images[0]
        {
            return Err("Shell crash is not retained service/image/source provenance".into());
        }
        let candidates: Vec<_> = groups
            .iter()
            .enumerate()
            .filter(|(_, g)| g.first > fault.at && g.last < report.at && g.values[0] == capture.job)
            .collect();
        if candidates.len() != 1 {
            return Err("crash missing unique actual pre-reap Job query group".into());
        }
        let (group_index, group) = candidates[0];
        if !used.insert(group_index) || group.capability == 0 {
            return Err("crash used wrong/replayed Job authority".into());
        }
        let reap = if app {
            let start = actions.iter().find(|a| {
                a.value.kind == "start"
                    && a.value.process == capture.process
                    && a.value.thread == capture.thread
                    && a.value.image_sha256 == hex(&fault.image)
            });
            let reap = actions.iter().find(|a| {
                a.value.kind == "reap"
                    && a.value.process == capture.process
                    && a.value.thread == capture.thread
                    && a.value.image_sha256 == hex(&fault.image)
            });
            if !start.is_some_and(|a| a.at < fault.at) || !reap.is_some_and(|a| a.at > group.last) {
                return Err("App fault/query did not precede actual image retirement".into());
            }
            reap.unwrap().at
        } else {
            group.last
        };
        if !queries.iter().any(|q| {
            q.status == 1
                && q.denial == 2
                && q.field == 0
                && q.capability == group.capability
                && q.at > reap
        }) {
            return Err("captured Job lacks actual post-retirement stale-cap denial".into());
        }
        captured_caps.insert(group.capability);
    }
    if full && faults.iter().map(|f| f.actor).collect::<BTreeSet<_>>() != BTreeSet::from([1, 5]) {
        return Err("full Native phase needs one actual App and one Shell crash".into());
    }
    let roles = [
        Role::Boot,
        Role::Root,
        Role::Shell,
        Role::Input,
        Role::File,
        Role::Block,
        Role::Application,
        Role::Display,
    ];
    let mut jobs = BTreeSet::new();
    let mut caps = BTreeSet::new();
    let mut previous_report = 0;
    let mut previous_tick = 0;
    for (index, report) in reports.iter().filter(|r| r.kind == Kind::Job).enumerate() {
        let row = Row::decode(&report.bytes).map_err(|e| format!("Native Job row: {e:?}"))?;
        if row.role != roles[index] || !jobs.insert(row.job.diagnostic_id) {
            return Err("inspector Job role/order/identity replay".into());
        }
        let candidates: Vec<_> = groups
            .iter()
            .enumerate()
            .filter(|(_, g)| {
                g.values == job_values(row.job) && g.last < report.at && g.first > previous_report
            })
            .collect();
        if candidates.len() != 1 {
            return Err("inspector row not matched to unique actual Job query group".into());
        }
        let (group_index, group) = candidates[0];
        if !used.insert(group_index)
            || !caps.insert(group.capability)
            || row.job.first_tick > group.first_tick
            || row.job.last_tick < group.last_tick
            || row.job.first_tick < previous_tick
            || (row.role == Role::Root) != (group.capability == 0)
        {
            return Err("inspector interval/capability/current-Job binding differs".into());
        }
        if index == 0 {
            if row.started
                || row.identity.process != 0
                || row.identity.thread != 0
                || row.image != [0; 32]
                || row.package.is_some()
            {
                return Err("Boot container row invented a running process".into());
            }
        } else {
            let p = &profiles[index - 1].counts;
            if !row.started
                || row.identity.process != p["current_process"]
                || row.identity.thread != p["current_thread"]
                || row.job.diagnostic_id != p["current_job"]
            {
                return Err("inspector row not actual currently admitted actor/Job".into());
            }
            let image = if index == 1 {
                source.root
            } else {
                source.images[index - 2]
            };
            let package = if index == 6 {
                Some(source.packages[0])
            } else {
                None
            };
            if row.image != image || row.package != package {
                return Err("inspector measured image/package differs".into());
            }
            if index == 6
                && !actions.iter().any(|a| {
                    a.at < report.at
                        && a.value.kind == "start"
                        && a.value.process == row.identity.process
                        && a.value.thread == row.identity.thread
                        && a.value.image_sha256 == hex(&image)
                })
            {
                return Err("inspector App was not actually started from retained package".into());
            }
        }
        previous_report = report.at;
        previous_tick = row.job.last_tick;
    }
    if used.len() != groups.len() {
        return Err("unclaimed extra actual Job query group".into());
    }
    let wrong_kind = queries
        .iter()
        .filter(|q| q.status == 1 && q.denial == 1)
        .count();
    let stale = queries
        .iter()
        .filter(|q| q.status == 1 && q.denial == 2)
        .count();
    if queries
        .iter()
        .any(|q| q.status == 1 && (q.denial == 3 || q.field != 0 || q.capability == 0))
        || (full && (stale < 2 || captured_caps.len() != 2))
        || (inspecting && wrong_kind == 0)
    {
        return Err("Native actual Job denial proof incomplete or unexpected".into());
    }
    if inspecting {
        if !queries
            .iter()
            .any(|q| q.denial == 1 && q.at < groups[0].first && !caps.contains(&q.capability))
        {
            return Err(
                "inspector lacks actual wrong-kind capability denial before collection".into(),
            );
        }
        let report = reports.last().unwrap();
        let system =
            Snapshot::decode(&report.bytes).map_err(|e| format!("Native System row: {e:?}"))?;
        if report.kind != Kind::System
            || report.at <= previous_report
            || report.at >= inspect[0]
            || system.state != State::Unformatted
            || system.first_tick < previous_tick
            || system.selected.is_some()
            || system.known_good.is_some()
            || system.last_failure.is_some()
            || system.current.is_some()
        {
            return Err(
                "Native System inspection invented admitted/committed generation state".into(),
            );
        }
    }
    Ok(Checked {
        reports,
        queries,
        faults,
        root,
        groups,
    })
}
fn artifact(directory: &Path, name: &str, bytes: &[u8]) -> Result<Value> {
    let path = directory.join(name);
    storage::immutable_new(&path, bytes)?;
    Ok(
        json!({"path":format!("diagnostics/{name}"),"sha256":hex(&Sha256::digest(bytes)),"bytes":bytes.len()}),
    )
}
pub(crate) fn retain(
    serial: &[u8],
    build: &str,
    recipe: &str,
    phase: Phase,
    packages: [&[u8]; 2],
    catalogue: &[u8],
    directory: &Path,
) -> Result<Value> {
    let source = sources(packages, catalogue, recipe)?;
    let checked = verify(serial, build, phase, &source)?;
    let meta = fs::symlink_metadata(directory).map_err(|e| e.to_string())?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err("Native diagnostic directory is not an owned regular directory".into());
    }
    let output = directory.join("diagnostics");
    fs::create_dir(&output).map_err(|e| e.to_string())?;
    let mut crashes = Vec::new();
    let mut rows = Vec::new();
    let mut system = Value::Null;
    let mut readable = String::new();
    for report in &checked.reports {
        let binary = artifact(
            &output,
            &format!("{}-{:03}.bin", report.kind.name(), report.serial),
            &report.bytes,
        )?;
        match report.kind {
            Kind::Crash => {
                let crash = Crash::decode(&report.bytes)
                    .map_err(|e| format!("Native crash retention: {e:?}"))?;
                let mut text = String::new();
                ev_diagnostics::presentation::crash(&mut text, &crash)
                    .map_err(|e| e.to_string())?;
                let prose = artifact(
                    &output,
                    &format!("crash-{:03}.txt", report.serial),
                    text.as_bytes(),
                )?;
                let p = crash.provenance();
                let component = match p.component {
                    Component::Application(id) => {
                        json!({"kind":"Application","app_id":hex(&id.bytes())})
                    }
                    Component::Service(role) => json!({"kind":"Service","role":role}),
                };
                let group = checked
                    .groups
                    .iter()
                    .find(|g| g.values[0] == crash.capture().job && g.last < report.at)
                    .ok_or("verified crash Job query binding disappeared")?;
                crashes.push(json!({"report":report.serial,"binary":binary,"readable":prose,"component":component,"capture_words":capture_words(crash.capture()),"actual_job_control":group.capability,"actual_job_query_sequence":[group.first_sequence,group.last_sequence],"executable_sha256":hex(&p.image),"package_sha256":p.package.map(|p|hex(&p)),"component_build":hex(&p.component_build),"generation":null,"epoch":p.epoch,"root_incarnation":p.incarnation}));
            }
            Kind::Job => {
                let row = Row::decode(&report.bytes)
                    .map_err(|e| format!("Native Job retention: {e:?}"))?;
                row.write(&mut readable).map_err(|e| e.to_string())?;
                let group = checked
                    .groups
                    .iter()
                    .find(|g| g.values == job_values(row.job) && g.last < report.at)
                    .ok_or("verified inspector Job query binding disappeared")?;
                rows.push(json!({"report":report.serial,"binary":binary,"role":row.role.name(),"process":row.identity.process,"thread":row.identity.thread,"job_values":job_values(row.job),"actual_capability":group.capability,"actual_query_sequence":[group.first_sequence,group.last_sequence],"actual_query_ticks":[group.first_tick,group.last_tick],"first_tick":row.job.first_tick,"last_tick":row.job.last_tick,"image_sha256":hex(&row.image),"package_sha256":row.package.map(|p|hex(&p))}));
            }
            Kind::System => {
                let row = Snapshot::decode(&report.bytes)
                    .map_err(|e| format!("Native System retention: {e:?}"))?;
                writeln!(&mut readable,"System region: {:?}; selected=None KnownGood=None; actual current System admission: unavailable (Native development boot); observed ticks {}..{}",row.state,row.first_tick,row.last_tick).map_err(|e|e.to_string())?;
                system = json!({"report":report.serial,"binary":binary,"state":"Unformatted","selected":null,"known_good":null,"current_admission":null,"first_tick":row.first_tick,"last_tick":row.last_tick});
            }
        }
    }
    let inspector = if readable.is_empty() {
        Value::Null
    } else {
        artifact(&output, "inspector.txt", readable.as_bytes())?
    };
    let queries:Vec<_>=checked.queries.iter().map(|q|json!({"sequence":q.sequence,"root_process":q.origin.0,"root_thread":q.origin.1,"capability":q.capability,"field":q.field,"value":q.value,"tick":q.tick,"status":q.status,"denial":q.denial})).collect();
    let raw:Vec<_>=checked.faults.iter().map(|f|json!({"actor":f.actor,"image_sha256":hex(&f.image),"root_epoch":f.epoch,"root_incarnation":f.incarnation,"words":f.words})).collect();
    let record = json!({"schema":1,"passed":true,"phase":phase.name(),"actual_root":{"process":checked.root.0,"thread":checked.root.1},"crashes":crashes,"jobs":rows,"system":system,"inspector":inspector,"actual_faults":raw,"actual_job_queries":queries,"successful_query_groups":checked.groups.len(),"scope":"actual raw fault/register/image and capability-authorized query joins to retained source packages/catalogue; SourceRoot records are diagnostics, not authority or System health; no disk repair or KnownGood inference"});
    storage::json_new(&output.join("record.json"), &record)?;
    Ok(record)
}

#[cfg(test)]
pub(crate) mod tests {
    // Structural package/catalogue and modeled serial fixtures only. No ELF is
    // executed; actual Kernel authority/capture requires the separate VM proof.
    use super::*;
    use ev_diagnostics::{Provenance, inspector::Usage, live::Identity};
    use ev_userspace_contract::root_v2::{catalogue as base, graph, native::catalogue as nc};
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    const INPUT: [u8; 32] = [0xab; 32];
    fn build() -> String {
        hex(&INPUT)
    }
    struct Fixture {
        packages: [Vec<u8>; 2],
        catalogue: Vec<u8>,
    }
    impl Fixture {
        fn new() -> Self {
            let packages = core::array::from_fn(|i| {
                let mut elf = vec![0; 120];
                elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
                elf[16..18].copy_from_slice(&2u16.to_le_bytes());
                elf[18..20].copy_from_slice(&62u16.to_le_bytes());
                elf[20..24].copy_from_slice(&1u32.to_le_bytes());
                elf[24] = i as u8 + 1;
                elf[32..40].copy_from_slice(&64u64.to_le_bytes());
                elf[52..54].copy_from_slice(&64u16.to_le_bytes());
                elf[54..56].copy_from_slice(&56u16.to_le_bytes());
                elf[56..58].copy_from_slice(&1u16.to_le_bytes());
                ev_zion::producer::build(
                    &ev_zion::producer::Spec {
                        app: ev_zion::AppId::new(crate::native_package::HELLO_APP_ID).unwrap(),
                        name: "model Hello",
                        source: "structural component fixture",
                        publisher: None,
                        version: ev_zion::Version {
                            major: 0,
                            minor: 1,
                            patch: i as u32,
                        },
                        build_id: [0x70 + i as u8; 32],
                        platform: ev_zion::Platform {
                            minimum: 1,
                            target: 1,
                        },
                        abi: ev_userspace_contract::ABI,
                        data_schema: ev_zion::DataSchema {
                            current: 1,
                            oldest_readable: 1,
                        },
                        entrypoint: "bin/main.elf",
                        contracts: &[ev_zion::Contract {
                            name: "ev.app.private-data",
                            major: 1,
                            minimum_minor: 0,
                            features: 0,
                        }],
                        capabilities: &[ev_zion::CapabilityRequest {
                            capability: ev_zion::Capability::AppPrivateData,
                            required: true,
                        }],
                    },
                    &elf,
                    &[],
                )
                .unwrap()
            });
            let parsed = packages
                .each_ref()
                .map(|b| ev_zion::Package::parse(b).unwrap());
            let images = core::array::from_fn(|i| base::Image {
                role: graph::CHILDREN[i].image(),
                image: if i == 4 {
                    parsed[0].executable().digest
                } else {
                    [0x10 + i as u8; 32]
                },
                descriptor: [0x30 + i as u8; 32],
                abi: ev_userspace_contract::ABI,
                limits: base::CHILD_LIMITS,
                display_layout: i == 5,
                grants: base::CHILD_ROLE_COUNTS[i],
                roles: ev_root_supervisor::desktop_plan::roles_measurement(graph::CHILDREN[i]),
            });
            let description = |graph| base::Description {
                root_image: [0x55; 32],
                kernel_input: INPUT,
                graph,
                app_id: parsed[0].app().claimed_app.bytes(),
                package: parsed[0].id().bytes(),
                app_build: parsed[0].app().build_id,
                provenance: base::Provenance::Zion,
                restart_attempts: ev_root_supervisor::desktop_plan::RESTART_ATTEMPTS,
                restart_window: ev_root_supervisor::desktop_plan::RESTART_WINDOW,
                images,
            };
            let provisional = base::encode(description([0; 32])).unwrap();
            let measured = ev_root_supervisor::desktop_plan::graph_measurement(
                &base::Catalogue::decode(&provisional).unwrap(),
            );
            let base = base::encode(description(measured)).unwrap();
            let description = |layout_measurement| nc::Description {
                base: &base,
                app_b: nc::AppImage {
                    image: parsed[1].executable().digest,
                    descriptor: [0x61; 32],
                    abi: ev_userspace_contract::ABI,
                    limits: base::CHILD_LIMITS,
                    roles: images[4].roles,
                },
                bad_shell: nc::AppImage {
                    image: [0x71; 32],
                    descriptor: [0x72; 32],
                    abi: ev_userspace_contract::ABI,
                    limits: base::CHILD_LIMITS,
                    roles: images[0].roles,
                },
                boot_mode: nc::BootMode::Standalone,
                package_b: parsed[1].id().bytes(),
                package_b_build: parsed[1].app().build_id,
                package_a_bytes: packages[0].len() as u64,
                package_b_bytes: packages[1].len() as u64,
                layout_measurement,
            };
            let provisional = nc::encode(description([1; 32])).unwrap();
            let measured = ev_root_supervisor::native_plan::layout_measurement(
                &nc::Catalogue::decode(&provisional).unwrap(),
            );
            let catalogue = nc::encode(description(measured)).unwrap().to_vec();
            Self {
                packages,
                catalogue,
            }
        }
        fn packages(&self) -> [&[u8]; 2] {
            self.packages.each_ref().map(Vec::as_slice)
        }
        fn source(&self) -> Sources {
            sources(self.packages(), &self.catalogue, &build()).unwrap()
        }
    }
    /// Structural bytes only, shared by the Native3 adversarial host model.
    pub(crate) fn package_catalogue_model() -> ([Vec<u8>; 2], Vec<u8>) {
        let f = Fixture::new();
        (f.packages, f.catalogue)
    }
    fn envelope(kind: &str, report: u32, bytes: &[u8]) -> String {
        format!(
            "EVROSION_NATIVE_{kind} protocol=1 build={} report={report} root_process=20 root_thread=120 bytes={}\n",
            build(),
            hex(bytes)
        )
    }
    fn query(
        sequence: u64,
        capability: u64,
        field: u64,
        value: u64,
        tick: u64,
        status: u64,
        denial: u64,
    ) -> String {
        format!(
            "EVROSION_NATIVE_JOB_FIELD protocol=1 build={} sequence={sequence} root_process=20 root_thread=120 capability={capability} field={field} value={value} tick={tick} status={status} denial={denial}\n",
            build()
        )
    }
    fn values(id: u64) -> [u64; 9] {
        [id, 7, 10, 1, 1, 16384, 32, 1, 1]
    }
    fn group(serial: &mut String, sequence: &mut u64, cap: u64, id: u64, tick: u64) {
        let values = values(id);
        for index in 0..10 {
            let field = if index == 9 { 0 } else { index };
            *sequence += 1;
            serial.push_str(&query(
                *sequence,
                cap,
                field as u64,
                values[field],
                tick + index as u64,
                0,
                0,
            ));
        }
    }
    fn job(id: u64, tick: u64) -> Job {
        let v = values(id);
        Job {
            diagnostic_id: id,
            first_tick: tick - 1,
            last_tick: tick + 10,
            subtree: Usage {
                cpu_ticks: v[1],
                frames: v[2],
                processes: v[3],
                threads: v[4],
            },
            limits: Usage {
                cpu_ticks: v[5],
                frames: v[6],
                processes: v[7],
                threads: v[8],
            },
        }
    }
    fn action(kind: &str, pid: u64, image: [u8; 32]) -> String {
        format!(
            "EVROSION_M5_NATIVE_ACTION protocol=1 build={} action={kind} process={pid} thread={} image_sha256={}\n",
            build(),
            pid + 100,
            hex(&image)
        )
    }
    fn state(op: &str, report: u32, image: [u8; 32]) -> String {
        format!(
            "EVROSION_NATIVE_STATE protocol=1 build={} report={report} op={op} result=ok installed=1 active=a staged=none previous=a process=25 thread=125 revision=8 data_epoch=1 data_counter=1 value=2026 mutations=0 recovery=0 actual_process=25 actual_thread=125 actual_image_sha256={} identity_matches=true\n",
            build(),
            hex(&image)
        )
    }
    fn profiles(full: bool) -> String {
        (0..7).map(|i| {
            let faults=u64::from(full&&matches!(i,1|5));let incarnations=1+faults;
            format!("EVROSION_M5_NATIVE_PROFILE protocol=1 build={} phase=finished scope=actor_slot index={i} current_process={} current_thread={} current_job={} incarnations={incarnations} elapsed_ticks=10000 captures={} syscalls=10 irqs=1 faults={faults} port_in=3 port_out=2 yields=1 continuations=8 charged_cpu_ticks=1 current_job_cpu_ticks=100 cpu_scope=subtree\n",build(),20+i,120+i,100+i,11+faults)
        }).collect()
    }
    fn initial(source: &Sources) -> String {
        let prefix = format!(
            "EVROSION_M5_NATIVE_COMMON_PREFIX protocol=1 build={} mode=0 root_process=20 root_thread=120 root_image_sha256={} root_epoch=4 root_incarnation=2 root_manifest_sha256={} block_process=24 block_thread=124 block_image_sha256={} system_endpoint=77 root_frames=40 block_frames=20\n",
            build(),
            hex(&source.root),
            "c".repeat(64),
            hex(&source.images[3])
        );
        prefix
            + &envelope(
                "SYSTEM",
                1,
                &Snapshot::new(State::Unformatted, 1, 2).encode().unwrap(),
            )
    }
    fn inspection(source: &Sources) -> String {
        let mut serial = initial(source) + &action("start", 25, source.app_images[0]);
        let mut seq = 1;
        serial.push_str(&query(seq, 999, 0, 0, 90, 1, 1));
        let roles = [
            Role::Boot,
            Role::Root,
            Role::Shell,
            Role::Input,
            Role::File,
            Role::Block,
            Role::Application,
            Role::Display,
        ];
        for (index, role) in roles.into_iter().enumerate() {
            let tick = 100 + 20 * index as u64;
            let id = 99 + index as u64;
            let cap = match index {
                0 => 501,
                1 => 0,
                _ => 500 + index as u64,
            };
            group(&mut serial, &mut seq, cap, id, tick);
            let row = Row::new(
                role,
                Identity {
                    process: if index == 0 { 0 } else { 19 + index as u64 },
                    thread: if index == 0 { 0 } else { 119 + index as u64 },
                },
                index != 0,
                if index == 0 {
                    [0; 32]
                } else if index == 1 {
                    source.root
                } else {
                    source.images[index - 2]
                },
                if role == Role::Application {
                    Some(source.packages[0])
                } else {
                    None
                },
                job(id, tick),
            )
            .unwrap();
            serial.push_str(&envelope("JOB", index as u32 + 2, &row.encode()));
        }
        serial.push_str(&envelope(
            "SYSTEM",
            10,
            &Snapshot::new(State::Unformatted, 260, 270)
                .encode()
                .unwrap(),
        ));
        serial.push_str(&state("inspect", 1, source.app_images[0]));
        serial.push_str(&state("finish", 2, source.app_images[0]));
        serial.push_str(&action("stop", 25, source.app_images[0]));
        serial.push_str(&action("reap", 25, source.app_images[0]));
        serial.push_str(&profiles(false));
        serial
    }
    fn crash(source: &Sources, app: bool) -> Crash {
        Crash::new(
            Provenance {
                component: if app {
                    Component::Application(ev_zion::AppId::new(source.app).unwrap())
                } else {
                    Component::Service(Child::Shell.image().selector() as u16)
                },
                image: if app {
                    source.app_images[0]
                } else {
                    source.images[0]
                },
                package: app.then_some(source.packages[0]),
                component_build: if app { source.builds[0] } else { source.input },
                generation: None,
                epoch: 4,
                incarnation: 2,
            },
            Capture {
                job: if app { 901 } else { 902 },
                process: if app { 30 } else { 31 },
                thread: if app { 130 } else { 131 },
                vector: 14,
                error: 4,
                address: 0x1a000000,
                instruction: 0x1000,
                stack: 0x2000,
                flags: 0x202,
                registers: core::array::from_fn(|i| 0xabcdef + i as u64),
            },
        )
        .unwrap()
    }
    fn full(source: &Sources) -> String {
        let mut serial = initial(source) + &action("start", 30, source.app_images[0]);
        let mut seq = 0;
        for (index, app) in [true, false].into_iter().enumerate() {
            let crash = crash(source, app);
            let c = crash.capture();
            let p = crash.provenance();
            let actor = if app { 5 } else { 1 };
            serial.push_str(&format!("EVROSION_NATIVE_FAULT protocol=1 build={} actor={actor} image_sha256={} root_epoch=4 root_incarnation=2 words={}\n",build(),hex(&p.image),capture_words(c).iter().map(u64::to_string).collect::<Vec<_>>().join(",")));
            group(
                &mut serial,
                &mut seq,
                701 + index as u64,
                c.job,
                1000 + 100 * index as u64,
            );
            if app {
                serial.push_str(&action("stop", 30, p.image));
                serial.push_str(&action("reap", 30, p.image));
            }
            seq += 1;
            serial.push_str(&query(
                seq,
                701 + index as u64,
                0,
                0,
                1012 + 100 * index as u64,
                1,
                2,
            ));
            serial.push_str(&envelope("CRASH", index as u32 + 2, &crash.encode()));
            if app {
                serial.push_str(&action("start", 25, source.app_images[0]));
            }
        }
        serial.push_str(&state("finish", 1, source.app_images[0]));
        serial.push_str(&action("stop", 25, source.app_images[0]));
        serial.push_str(&action("reap", 25, source.app_images[0]));
        serial.push_str(&profiles(true));
        serial
    }
    fn modify_report(
        serial: &str,
        kind: &str,
        index: usize,
        change: impl FnOnce(&mut Vec<u8>),
    ) -> String {
        let mut lines: Vec<String> = serial.lines().map(str::to_owned).collect();
        let row = lines
            .iter_mut()
            .filter(|s| s.starts_with(&format!("EVROSION_NATIVE_{kind} ")))
            .nth(index)
            .unwrap();
        let (prefix, payload) = row.rsplit_once("bytes=").unwrap();
        let mut bytes = unhex(payload, payload.len() / 2).unwrap();
        change(&mut bytes);
        *row = format!("{prefix}bytes={}", hex(&bytes));
        lines.join("\n") + "\n"
    }
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../build/test-tmp")
                .join(format!(
                    "native-diag-test-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
            fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn actual_joins_keep_raw_capture_and_query_values_and_retain_immutable_artifacts() {
        let f = Fixture::new();
        let s = f.source();
        for (phase, serial, count) in [
            (Phase::InstallFull, full(&s), 2),
            (Phase::VerifyCancel, inspection(&s), 0),
        ] {
            let temp = Temp::new();
            let result = retain(
                serial.as_bytes(),
                &build(),
                &build(),
                phase,
                f.packages(),
                &f.catalogue,
                &temp.0,
            )
            .unwrap();
            assert_eq!(result["crashes"].as_array().unwrap().len(), count);
            assert!(temp.0.join("diagnostics/record.json").is_file());
            assert!(
                retain(
                    serial.as_bytes(),
                    &build(),
                    &build(),
                    phase,
                    f.packages(),
                    &f.catalogue,
                    &temp.0
                )
                .is_err()
            );
            if count == 2 {
                assert_eq!(
                    fs::read(temp.0.join("diagnostics/crash-002.bin")).unwrap(),
                    crash(&s, true).encode()
                );
            } else {
                assert!(
                    fs::read_to_string(temp.0.join("diagnostics/inspector.txt"))
                        .unwrap()
                        .contains("KnownGood=None")
                );
            }
        }
    }
    #[test]
    fn generic_syntax_decodes_only_and_rejects_extra_fields_noncanonical_words_and_denials() {
        let f = Fixture::new();
        let good = envelope("CRASH", 1, &crash(&f.source(), true).encode());
        assert!(line(good.trim_end(), &build()).is_ok());
        for bad in [
            good.replace("report=1", "report=01"),
            good.replace("root_thread=120", "root_thread=0"),
            good.trim_end().to_owned() + " extra=1",
            good.replace("protocol=1", "protocol=2"),
            good.replace(&build(), &"f".repeat(64)),
            good.replace("bytes=4556", "bytes=455G"),
        ] {
            assert!(line(bad.trim_end(), &build()).is_err());
        }
        assert!(line(query(1, 9, 0, 1, 5, 1, 2).trim_end(), &build()).is_err());
        assert!(line(query(513, 9, 0, 0, 5, 1, 2).trim_end(), &build()).is_err());
    }
    #[test]
    fn crash_provenance_and_every_register_must_match_actual_fault() {
        let f = Fixture::new();
        let s = f.source();
        let serial = full(&s);
        for field in 0..24 {
            let changed = modify_report(&serial, "CRASH", 0, |b| {
                let mut c = Crash::decode(b).unwrap().capture();
                let mut words = capture_words(c);
                words[field] ^= 1;
                c = Capture {
                    job: words[0],
                    process: words[1],
                    thread: words[2],
                    vector: words[3],
                    error: words[4],
                    address: words[5],
                    instruction: words[6],
                    stack: words[7],
                    flags: words[8],
                    registers: words[9..].try_into().unwrap(),
                };
                if let Ok(c) = Crash::new(crash(&s, true).provenance(), c) {
                    *b = c.encode().to_vec();
                } else {
                    b[0] ^= 1;
                }
            });
            assert!(
                verify(changed.as_bytes(), &build(), Phase::InstallFull, &s).is_err(),
                "capture field{field}"
            );
        }
        for field in 0..7 {
            let changed = modify_report(&serial, "CRASH", 0, |b| {
                let c = Crash::decode(b).unwrap();
                let mut p = c.provenance();
                match field {
                    0 => {
                        p.component = Component::Application(ev_zion::AppId::new([9; 16]).unwrap())
                    }
                    1 => p.image = [9; 32],
                    2 => p.package = Some(s.packages[1]),
                    3 => p.component_build = s.builds[1],
                    4 => p.generation = Some([9; 32]),
                    5 => p.epoch += 1,
                    _ => p.incarnation += 1,
                };
                *b = Crash::new(p, c.capture()).unwrap().encode().to_vec();
            });
            assert!(
                verify(changed.as_bytes(), &build(), Phase::InstallFull, &s).is_err(),
                "provenance field{field}"
            );
        }
    }
    #[test]
    fn inspect_rejects_resealed_job_values_roles_pid_images_intervals_and_generation_claims() {
        let f = Fixture::new();
        let s = f.source();
        let serial = inspection(&s);
        for field in 0..7 {
            let changed = modify_report(&serial, "JOB", 2, |b| {
                let mut r = Row::decode(b).unwrap();
                match field {
                    0 => r.job.subtree.frames += 1,
                    1 => r.role = Role::File,
                    2 => r.identity.process += 1,
                    3 => r.image = [9; 32],
                    4 => r.job.first_tick += 5,
                    5 => r.job.last_tick -= 5,
                    _ => r.job.diagnostic_id += 1,
                };
                *b = r.encode().to_vec();
            });
            assert!(
                verify(changed.as_bytes(), &build(), Phase::VerifyCancel, &s).is_err(),
                "Job field{field}"
            );
        }
        let changed = modify_report(&serial, "SYSTEM", 0, |b| {
            *b = Snapshot::new(State::Unavailable, 260, 270)
                .encode()
                .unwrap()
                .to_vec()
        });
        assert!(verify(changed.as_bytes(), &build(), Phase::VerifyCancel, &s).is_err());
        let reversed = modify_report(&serial, "SYSTEM", 1, |b| {
            *b = Snapshot::new(State::Unformatted, 1, 2)
                .encode()
                .unwrap()
                .to_vec()
        });
        assert!(verify(reversed.as_bytes(), &build(), Phase::VerifyCancel, &s).is_err());
    }
    #[test]
    fn replay_gap_truncation_origin_group_interleave_and_missing_negatives_are_refused() {
        let f = Fixture::new();
        let s = f.source();
        let serial = inspection(&s);
        let first = serial
            .lines()
            .find(|l| l.starts_with("EVROSION_NATIVE_JOB "))
            .unwrap();
        let query = serial.lines().find(|l| l.contains("sequence=2 ")).unwrap();
        for changed in [
            serial.replacen("report=2 ", "report=1 ", 1),
            serial.replacen("sequence=3 ", "sequence=4 ", 1),
            serial.replacen("root_process=20", "root_process=21", 1),
            serial.replacen("field=1 ", "field=2 ", 1),
            serial.replacen(first, "", 1),
            serial.replacen("denial=1", "denial=3", 1),
            serial.replacen(query, &format!("{query}\n{first}"), 1),
            serial.replacen("capability=501 field=1", "capability=502 field=1", 1),
        ] {
            assert!(verify(changed.as_bytes(), &build(), Phase::VerifyCancel, &s).is_err());
        }
        let truncated = serial
            .split("EVROSION_NATIVE_SYSTEM")
            .next()
            .unwrap()
            .to_owned()
            + "EVROSION_NATIVE_SYSTEM";
        assert!(verify(truncated.as_bytes(), &build(), Phase::VerifyCancel, &s).is_err());
        let no_stale = full(&s)
            .lines()
            .filter(|l| !l.contains("denial=2"))
            .map(|l| format!("{l}\n"))
            .collect::<String>();
        assert!(verify(no_stale.as_bytes(), &build(), Phase::InstallFull, &s).is_err());
    }
    #[test]
    fn source_mismatch_and_fake_stop_capsules_fail_before_creating_any_artifact() {
        let f = Fixture::new();
        let s = f.source();
        let temp = Temp::new();
        let serial = full(&s);
        let wrong = serial.replace("EVROSION_NATIVE_FAULT", "IGNORED_NATIVE_STOP");
        assert!(
            retain(
                wrong.as_bytes(),
                &build(),
                &build(),
                Phase::InstallFull,
                f.packages(),
                &f.catalogue,
                &temp.0
            )
            .is_err()
        );
        assert!(fs::read_dir(&temp.0).unwrap().next().is_none());
        assert!(sources([&f.packages[1], &f.packages[0]], &f.catalogue, &build()).is_err());
        for phase in [
            Phase::ActivateB,
            Phase::RollbackA,
            Phase::Remove,
            Phase::ReinstallA,
        ] {
            assert!(verify(serial.as_bytes(), &build(), phase, &s).is_err());
        }
    }
}
