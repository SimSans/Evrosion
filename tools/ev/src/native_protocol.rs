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
}
pub(crate) fn summary(line: &str, build: &str) -> Result<BTreeMap<String, u64>> {
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
        || counts["calls"] != counts["replies"]
        || counts["bank_maps"] != 2
        || counts["bank_detaches"] != 2
        || counts["bank_reclaimed"] != counts["package_a_pages"] + counts["package_b_pages"]
    {
        return Err("inconsistent Native process/call/bank accounting".into());
    }
    for slot in ["a", "b"] {
        let starts = counts[&format!("app_{slot}_starts")];
        if starts > 64
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
    if serial.len() > 1024 * 1024 {
        return Err("Native serial exceeds1MiB".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "Native serial notUTF8")?;
    let mut actions = Vec::new();
    let mut counts = None;
    let mut live = None;
    let mut stopped = None;
    let mut old = BTreeSet::new();
    for line in text
        .split_inclusive('\n')
        .filter(|s| s.ends_with('\n'))
        .map(|s| s.trim_end_matches(['\r', '\n']))
    {
        if line.starts_with("EVROSION_M5_NATIVE_ACTION") {
            if counts.is_some() || actions.len() >= 192 {
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
            if counts.is_some() || live.is_some() || stopped.is_some() {
                return Err("duplicate Native completion or retained App owner".into());
            }
            counts = Some(summary(line, build)?);
        } else if line.starts_with("EVROSION_M4_DESKTOP ") {
            return Err("Native fixture mixed Desktop completion".into());
        }
    }
    let states = states(serial, build)?;
    if !states.last().is_some_and(|state| state.is("finish")) {
        return Err("Native completion lacks final complete requested finish report".into());
    }
    let counts = counts.ok_or("Native completion missing")?;
    let actual = actions.iter().filter(|a| a.kind == "start").count() as u64;
    if actual != counts["app_a_starts"] + counts["app_b_starts"] {
        return Err("Native action count differs from completion".into());
    }
    Ok(Record { counts, actions })
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
                    | "invalid"
                    | "initialize-grants"
                    | "remember"
                    | "revoke"
                    | "system-init"
                    | "system-stage"
                    | "system-activate"
                    | "recover-good"
            ) => {}
            "result" if matches!(value, "ok" | "busy" | "refused" | "recovery") => (),
            "active" | "staged" | "previous" if matches!(value, "none" | "a" | "b") => (),
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
    if serial.len() > 1024 * 1024 {
        return Err("Native state log exceeds1MiB".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "Native states notUTF8")?;
    let mut states = Vec::new();
    for line in text.split_inclusive('\n').filter(|l| l.ends_with('\n')) {
        if line.starts_with("EVROSION_NATIVE_STATE") {
            let state = state_line(line.trim_end_matches(['\r', '\n']), build)?;
            if state.number("report")? != states.len() as u64 + 1 || states.len() >= 64 {
                return Err("Native state sequence replay/gap/overflow".into());
            }
            states.push(state);
        }
    }
    Ok(states)
}
