//! Strict diagnostics for the explicit Native fixture. Parsed receipts do not
//! grant authority or replace source/disk/pixel validation.
use crate::{boot_protocol::canonical_number, build::Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Action {
    pub kind: String,
    pub process: u64,
    pub thread: u64,
    pub image_sha256: String,
}
fn digest(field: &str, key: &str) -> Result<String> {
    let value = field
        .strip_prefix(key)
        .and_then(|v| v.strip_prefix('='))
        .ok_or("missing Native digest")?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Native digest must be canonical lowercase64hex".into());
    }
    Ok(value.into())
}
pub(crate) fn action(line: &str, build: &str) -> Result<Action> {
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 512
        || f.len() != 7
        || f[0] != "EVROSION_M5_NATIVE_ACTION"
        || f[1] != "protocol=1"
        || digest(f[2], "build")? != build
    {
        return Err("malformed/wrong-build Native action".into());
    }
    let kind = f[3]
        .strip_prefix("action=")
        .filter(|v| matches!(*v, "start" | "stop" | "reap"))
        .ok_or("unknown Native action")?;
    let process = canonical_number(f[4], "process")?;
    let thread = canonical_number(f[5], "thread")?;
    if process == 0 || thread == 0 || process == u64::MAX || thread == u64::MAX {
        return Err("invalid Native identity".into());
    }
    Ok(Action {
        kind: kind.into(),
        process,
        thread,
        image_sha256: digest(f[6], "image_sha256")?,
    })
}
const NUMBERS: &[&str] = &[
    "processes",
    "starts",
    "calls",
    "replies",
    "faults",
    "restarts",
    "grants",
    "app_a_starts",
    "app_b_starts",
    "app_a_stops",
    "app_b_stops",
    "app_a_reaps",
    "app_b_reaps",
    "app_a_process",
    "app_b_process",
    "app_a_thread",
    "app_b_thread",
    "package_a_pages",
    "package_b_pages",
    "bank_maps",
    "bank_detaches",
    "bank_reclaimed",
    "readonly_rejections",
];
#[derive(Debug, Serialize)]
pub(crate) struct Record {
    pub counts: BTreeMap<String, u64>,
    pub actions: Vec<Action>,
    pub history_complete: bool,
    pub downloaded_actions: Vec<crate::downloaded_protocol::Action>,
}
pub(crate) fn summary(line: &str, build: &str) -> Result<BTreeMap<String, u64>> {
    summary_profile(line, build, false, 0)
}
fn summary_profile(
    line: &str,
    build: &str,
    session: bool,
    cancelled: u64,
) -> Result<BTreeMap<String, u64>> {
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 2048
        || f.len() != 4 + NUMBERS.len() + 5
        || f[0] != "EVROSION_M5_NATIVE"
        || f[1] != "protocol=1"
        || digest(f[2], "build")? != build
        || f[3] != "status=PASS"
    {
        return Err("malformed/wrong-build Native completion".into());
    }
    let mut counts = BTreeMap::new();
    for (field, name) in f[4..4 + NUMBERS.len()].iter().zip(NUMBERS) {
        counts.insert((*name).into(), canonical_number(field, name)?);
    }
    if f[4 + NUMBERS.len()..]
        != [
            "root_exit=0",
            "frames=true",
            "metadata=true",
            "guards=true",
            "display_survived=true",
        ]
    {
        return Err("Native ownership/exit facts missing".into());
    }
    if counts["starts"] == 0
        || Some(counts["calls"]) != counts["replies"].checked_add(cancelled)
        || counts["bank_maps"] != 2
        || counts["bank_detaches"] != 2
        || Some(counts["bank_reclaimed"])
            != counts["package_a_pages"].checked_add(counts["package_b_pages"])
    {
        return Err("inconsistent Native process/call/bank accounting".into());
    }
    for slot in ["a", "b"] {
        let starts = counts[&format!("app_{slot}_starts")];
        if (!session && starts > 64)
            || starts != counts[&format!("app_{slot}_stops")]
            || starts != counts[&format!("app_{slot}_reaps")]
            || !(1..=63).contains(&counts[&format!("package_{slot}_pages")])
        {
            return Err("Native App incarnation/bank accounting differs".into());
        }
        for field in ["process", "thread"] {
            if (starts == 0) != (counts[&format!("app_{slot}_{field}")] == 0) {
                return Err("Native absent/live last identity mismatch".into());
            }
        }
    }
    Ok(counts)
}
pub(crate) fn record(serial: &[u8], build: &str) -> Result<Record> {
    record_profile(serial, build, false, false, None)
}
pub(crate) fn record_session(serial: &[u8], build: &str) -> Result<Record> {
    record_profile(serial, build, true, false, None)
}
/// Dedicated document-crash history only; ordinary state parsers stay strict.
pub(crate) fn record_document_crash(
    serial: &[u8],
    build: &str,
    proof: &crate::document_crash::Proof,
) -> Result<Record> {
    if !proof.matches(serial, build) {
        return Err("document crash proof belongs to different raw serial/build".into());
    }
    record_checked_profile(serial, build, true, false, None, Some(proof))
}
pub(crate) fn record_network(serial: &[u8], build: &str) -> Result<Record> {
    record_profile(serial, build, true, true, None)
}
pub(crate) fn record_network_negative(
    serial: &[u8],
    build: &str,
    cancelled: &crate::network_negative::records::Cancelled,
) -> Result<Record> {
    record_profile(serial, build, true, true, Some(cancelled))
}
fn record_profile(
    serial: &[u8],
    build: &str,
    session: bool,
    network: bool,
    cancelled: Option<&crate::network_negative::records::Cancelled>,
) -> Result<Record> {
    record_checked_profile(serial, build, session, network, cancelled, None)
}
fn record_checked_profile(
    serial: &[u8],
    build: &str,
    session: bool,
    network: bool,
    cancelled: Option<&crate::network_negative::records::Cancelled>,
    document_crash: Option<&crate::document_crash::Proof>,
) -> Result<Record> {
    if document_crash.is_some_and(|p| !p.matches(serial, build))
        || document_crash.is_some() && (!session || network || cancelled.is_some())
    {
        return Err("document crash proof outside its exact offline session".into());
    }
    if serial.len() > 1024 * 1024 {
        return Err("Native serial exceeds1MiB".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "Native serial notUTF8")?;
    if cancelled.is_some_and(|proof| !proof.matches(serial))
        || (cancelled.is_none() && text.lines().any(|r| r.starts_with("EVROSION_M6_NEGATIVE")))
    {
        return Err("negative network history outside its exact typed qualification".into());
    }
    let omitted = session && crate::session_protocol::retention(serial, build)?.omitted != 0;
    let downloaded_actions = if network {
        crate::downloaded_protocol::records(serial, build, !omitted)?
    } else {
        if text
            .lines()
            .any(|row| row.starts_with("EVROSION_M6_DOWNLOADED_ACTION"))
        {
            return Err("downloaded action outside selected Network profile".into());
        }
        Vec::new()
    };
    let mut actions = Vec::new();
    let mut counts = None;
    let mut live = None;
    let mut stopped = None;
    let mut old = BTreeSet::new();
    let mut prefix_closed = false;
    for line in text
        .split_inclusive('\n')
        .filter(|s| s.ends_with('\n'))
        .map(|s| s.trim_end_matches(['\r', '\n']))
    {
        if session && line.starts_with("EVROSION_M6_LOG_BOUND ") {
            prefix_closed = true;
        }
        if line.starts_with("EVROSION_M5_NATIVE_ACTION") {
            if counts.is_some() || prefix_closed || (!session && actions.len() >= 192) {
                return Err("Native action after completion/over budget".into());
            }
            let event = action(line, build)?;
            let id = (event.process, event.thread, event.image_sha256.clone());
            match event.kind.as_str() {
                "start"
                    if live.is_none()
                        && stopped.is_none()
                        && old.insert((event.process, event.thread)) =>
                {
                    live = Some(id)
                }
                "stop" if live.as_ref() == Some(&id) => {
                    live = None;
                    stopped = Some(id);
                }
                "reap" if stopped.as_ref() == Some(&id) => stopped = None,
                _ => {
                    return Err("Native action has stale/duplicate/out-of-order incarnation".into());
                }
            }
            actions.push(event);
        } else if line.starts_with("EVROSION_M5_NATIVE ") {
            if counts.is_some() || (!omitted && (live.is_some() || stopped.is_some())) {
                return Err("duplicate Native completion or retained App owner".into());
            }
            counts = Some(if session {
                summary_profile(
                    line,
                    build,
                    true,
                    cancelled.map_or(0, |proof| proof.count()),
                )?
            } else {
                summary(line, build)?
            });
        } else if line.starts_with("EVROSION_M4_DESKTOP ") {
            return Err("Native fixture mixed Desktop completion".into());
        }
    }
    let states = if let Some(proof) = document_crash {
        proof.states().to_vec()
    } else if network {
        states_network(serial, build)?
    } else {
        states_profile(serial, build, session, false)?
    };
    if !states.last().is_some_and(|state| state.is("finish")) {
        return Err("Native completion lacks final complete requested finish report".into());
    }
    let counts = counts.ok_or("Native completion missing")?;
    let actual = actions.iter().filter(|a| a.kind == "start").count() as u64;
    let total = counts["app_a_starts"]
        .checked_add(counts["app_b_starts"])
        .ok_or("Native start total overflow")?;
    if (!omitted && actual != total) || (omitted && actual > total) {
        return Err("Native action count differs from completion".into());
    }
    Ok(Record {
        counts,
        actions,
        history_complete: !omitted,
        downloaded_actions,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn state(build: &str) -> String {
        format!(
            "EVROSION_NATIVE_STATE protocol=1 build={build} report=1 op=open result=ok installed=0 active=none staged=none previous=none process=0 thread=0 revision=0 data_epoch=0 data_counter=0 value=0 mutations=0 recovery=0 actual_process=0 actual_thread=0 actual_image_sha256={} identity_matches=true",
            "0".repeat(64)
        )
    }
    #[test]
    fn downloaded_tags_require_selected_network_profile_and_never_alias_banks() {
        let build = "a".repeat(64);
        let base = state(&build).replace("installed=0", "installed=1");
        let fetch = state(&build).replace("op=open", "op=update-fetch");
        assert!(state_line(&fetch, &build).is_err());
        assert!(
            state_line_network(&fetch, &build)
                .unwrap()
                .is("update-fetch")
        );
        for field in ["active", "staged", "previous"] {
            for tag in ["downloaded-b", "downloaded-c"] {
                let row = base.replace(&format!("{field}=none"), &format!("{field}={tag}"));
                assert!(state_line(&row, &build).is_err());
                assert_eq!(state_line_network(&row, &build).unwrap().fields[field], tag);
                assert!(states(format!("{row}\n").as_bytes(), &build).is_err());
                let parsed = states_network(format!("{row}\n").as_bytes(), &build).unwrap();
                assert_eq!(parsed[0].fields[field], tag);
                for bad in ["downloaded-a", "downloaded-d", "Downloaded-b", "b-download"] {
                    assert!(state_line_network(&row.replace(tag, bad), &build).is_err());
                }
            }
        }
        for tag in ["none", "a", "b"] {
            let row = base.replace("active=none", &format!("active={tag}"));
            assert_eq!(
                state_line(&row, &build).unwrap().fields,
                state_line_network(&row, &build).unwrap().fields
            );
        }
    }
    #[test]
    fn complete_state_binds_actual_identity_build_sequence_and_closed_tags() {
        let build = "a".repeat(64);
        let line = state(&build);
        assert!(state_line(&line, &build).unwrap().is("open"));
        assert!(states(line.as_bytes(), &build).unwrap().is_empty());
        assert_eq!(
            states(format!("{line}\n").as_bytes(), &build)
                .unwrap()
                .len(),
            1
        );
        for bad in [
            line.replace("process=0 thread=0", "process=7 thread=8"),
            line.replace("identity_matches=true", "identity_matches=false"),
            line.replace("active=none", "active=administrator"),
            line.replace("installed=0", "installed=2"),
            line.replace("report=1", "report=01"),
            format!("{line} ignored=true"),
        ] {
            assert!(state_line(&bad, &build).is_err());
        }
        assert!(state_line(&line, &"b".repeat(64)).is_err());
        assert!(states(format!("{line}\n{line}\n").as_bytes(), &build).is_err());
        assert!(
            states(
                format!("{}\n", line.replace("report=1", "report=2")).as_bytes(),
                &build
            )
            .is_err()
        );
        assert!(record(format!("{line}\n").as_bytes(), &build).is_err());
    }
    #[test]
    fn action_cannot_accept_unknown_fields_wrong_build_or_unbounded_identity() {
        let build = "a".repeat(64);
        let image = "b".repeat(64);
        let line = format!(
            "EVROSION_M5_NATIVE_ACTION protocol=1 build={build} action=start process=7 thread=8 image_sha256={image}"
        );
        assert_eq!(action(&line, &build).unwrap().process, 7);
        for bad in [
            line.replace("process=7", "process=07"),
            line.replace("action=start", "action=choose"),
            line.replace("thread=8", "thread=0"),
            format!("{line} extra=true"),
        ] {
            assert!(action(&bad, &build).is_err());
        }
        assert!(action(&line, &"c".repeat(64)).is_err());
    }

    #[test]
    fn sustained_parser_retains_accounting_beyond_the_finite_incarnation_cap() {
        // Parser fixture only: replace actual14 actions with200 complete
        // distinct incarnations. This does not claim these ran in a VM.
        let historical = include_str!("../../../tests/fixtures/m6-session-exercise-parser.serial");
        let first = historical
            .lines()
            .find(|l| l.starts_with("EVROSION_M5_NATIVE_ACTION "))
            .unwrap();
        let build = first
            .split(' ')
            .nth(2)
            .unwrap()
            .strip_prefix("build=")
            .unwrap();
        let image = action(first, build).unwrap().image_sha256;
        let baseline = crate::session_protocol::retention(historical.as_bytes(), build).unwrap();
        let original_actions: Vec<_> = historical
            .lines()
            .filter(|line| line.starts_with("EVROSION_M5_NATIVE_ACTION "))
            .collect();
        let original_bytes: usize = original_actions.iter().map(|line| line.len() + 1).sum();
        let mut synthetic_actions = String::new();
        for i in 0..200 {
            for kind in ["start", "stop", "reap"] {
                synthetic_actions.push_str(&format!("EVROSION_M5_NATIVE_ACTION protocol=1 build={build} action={kind} process={} thread={} image_sha256={image}\n",2000+i,3000+i));
            }
        }
        let retained = baseline.retained - original_actions.len() as u64 + 600;
        let detail_bytes =
            baseline.detail_bytes - original_bytes as u64 + synthetic_actions.len() as u64;
        let mut output = String::new();
        let mut inserted = false;
        for line in historical.lines() {
            if line.starts_with("EVROSION_M5_NATIVE_ACTION ") {
                if !inserted {
                    output.push_str(&synthetic_actions);
                    inserted = true;
                }
            } else if line.starts_with("EVROSION_M6_LOG ") {
                output.push_str(&format!("EVROSION_M6_LOG protocol=1 build={build} observed={retained} retained={retained} omitted=0 detail_bytes={detail_bytes} final_bytes={} omitted_bytes=0 prefix_closed=false\n",baseline.final_bytes));
            } else if line.starts_with("EVROSION_M5_NATIVE ") {
                let changed = line
                    .split(' ')
                    .map(|field| {
                        let (key, _) = field.split_once('=').unwrap_or((field, ""));
                        let value = match key {
                            "processes" | "starts" => Some(207),
                            "app_a_starts" | "app_a_stops" | "app_a_reaps" => Some(200),
                            "app_b_starts" | "app_b_stops" | "app_b_reaps" | "app_b_process"
                            | "app_b_thread" => Some(0),
                            "app_a_process" => Some(2199),
                            "app_a_thread" => Some(3199),
                            _ => None,
                        };
                        value.map_or_else(|| field.to_owned(), |v| format!("{key}={v}"))
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                output.push_str(&changed);
                output.push('\n');
            } else {
                output.push_str(line);
                output.push('\n');
            }
        }
        let result = record_session(output.as_bytes(), build).unwrap();
        assert!(result.history_complete);
        assert_eq!(result.actions.len(), 600);
        assert_eq!(result.counts["app_a_starts"], 200);
        assert!(record(output.as_bytes(), build).is_err());
        let bad = output.replacen("action=stop process=2000", "action=reap process=2000", 1);
        assert!(record_session(bad.as_bytes(), build).is_err());
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct StateRecord {
    pub fields: BTreeMap<String, String>,
}
impl StateRecord {
    pub fn number(&self, name: &str) -> Result<u64> {
        canonical_number(
            &format!(
                "{name}={}",
                self.fields.get(name).ok_or("missing Native state number")?
            ),
            name,
        )
    }
    pub fn is(&self, op: &str) -> bool {
        self.fields.get("op").is_some_and(|s| s == op)
            && self.fields.get("result").is_some_and(|s| s == "ok")
    }
}
/// Complete state diagnostics only. These snapshots are not atomic machine
/// state or persistence receipts; the host independently checks actual facts.
pub(crate) fn state_line(line: &str, build: &str) -> Result<StateRecord> {
    state_line_profile(line, build, false)
}
/// Selected V4 state claims only. Labels never establish actual downloaded
/// execution, publication, Kernel admission or health.
pub(crate) fn state_line_network(line: &str, build: &str) -> Result<StateRecord> {
    state_line_profile(line, build, true)
}
fn state_line_profile(line: &str, build: &str, network: bool) -> Result<StateRecord> {
    const FIELDS: &[&str] = &[
        "report",
        "op",
        "result",
        "installed",
        "active",
        "staged",
        "previous",
        "process",
        "thread",
        "revision",
        "data_epoch",
        "data_counter",
        "value",
        "mutations",
        "recovery",
        "actual_process",
        "actual_thread",
        "actual_image_sha256",
        "identity_matches",
    ];
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 1024
        || f.len() != 3 + FIELDS.len()
        || f[0] != "EVROSION_NATIVE_STATE"
        || f[1] != "protocol=1"
        || digest(f[2], "build")? != build
    {
        return Err("malformed Native state record".into());
    }
    let mut fields = BTreeMap::new();
    for (field, key) in f[3..].iter().zip(FIELDS) {
        let value = field
            .strip_prefix(key)
            .and_then(|v| v.strip_prefix('='))
            .ok_or("Native state field out of order")?;
        match *key {
            "op" if matches!(
                value,
                "open"
                    | "install"
                    | "stage"
                    | "activate"
                    | "rollback"
                    | "remove"
                    | "reinstall"
                    | "inspect"
                    | "cancel"
                    | "finish"
                    | "boot"
                    | "crash-shell"
                    | "crash-app"
                    | "invalid"
                    | "initialize-grants"
                    | "remember"
                    | "revoke"
                    | "system-init"
                    | "system-stage"
                    | "system-activate"
                    | "recover-good"
                    | "time-probe"
                    | "time-check"
                    | "update-init"
                    | "update-inspect"
            ) => {}
            "op" if network && value == "update-fetch" => {}
            "result" if matches!(value, "ok" | "busy" | "refused" | "recovery") => (),
            "active" | "staged" | "previous" if matches!(value, "none" | "a" | "b") => (),
            "active" | "staged" | "previous"
                if network && matches!(value, "downloaded-b" | "downloaded-c") => {}
            "actual_image_sha256" => {
                digest(field, key)?;
            }
            "identity_matches" if value == "true" => (),
            "identity_matches" => return Err("Native reported identity mismatch".into()),
            "op" | "result" | "active" | "staged" | "previous" => {
                return Err("unknown Native state tag".into());
            }
            _ => {
                canonical_number(field, key)?;
            }
        }
        fields.insert((*key).into(), value.into());
    }
    let state = StateRecord { fields };
    if state.number("report")? == 0
        || state.number("installed")? > 1
        || state.number("recovery")? > 1
        || state.number("process")? != state.number("actual_process")?
        || state.number("thread")? != state.number("actual_thread")?
    {
        return Err("Native source snapshot differs from actual live incarnation".into());
    }
    Ok(state)
}
pub(crate) fn states(serial: &[u8], build: &str) -> Result<Vec<StateRecord>> {
    states_profile(serial, build, false, false)
}
pub(crate) fn states_network(serial: &[u8], build: &str) -> Result<Vec<StateRecord>> {
    states_profile(serial, build, true, true)
}
fn states_profile(
    serial: &[u8],
    build: &str,
    session: bool,
    network: bool,
) -> Result<Vec<StateRecord>> {
    if serial.len() > 1024 * 1024 {
        return Err("Native state log exceeds1MiB".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "Native states notUTF8")?;
    let mut states = Vec::new();
    let mut closed = false;
    for line in text.split_inclusive('\n').filter(|l| l.ends_with('\n')) {
        if session && line.starts_with("EVROSION_M6_LOG_BOUND ") {
            closed = true;
        }
        if line.starts_with("EVROSION_NATIVE_STATE") {
            let state = state_line_profile(line.trim_end_matches(['\r', '\n']), build, network)?;
            let report = state.number("report")?;
            let previous = states
                .last()
                .map(|s: &StateRecord| s.number("report"))
                .transpose()?
                .unwrap_or(0);
            if (!closed && report != previous + 1)
                || (closed && (report <= previous || !state.is("finish")))
                || (!session && states.len() >= 64)
            {
                return Err("Native state sequence replay/gap/overflow".into());
            }
            states.push(state);
        }
    }
    Ok(states)
}
