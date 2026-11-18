//! Only the scripted Document(Crash) experiment may retain one stale crash
//! snapshot after genuine old-owner retirement. Every raw field is preserved;
//! a missing live App never becomes a successful live identity observation.
use crate::{
    boot_protocol::canonical_number,
    build::Result,
    desktop_protocol::{self, Actor, Event},
    native_protocol::{self, StateRecord},
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

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
const UNCHANGED: &[&str] = &[
    "installed",
    "active",
    "staged",
    "previous",
    "revision",
    "data_epoch",
    "data_counter",
    "value",
    "mutations",
    "recovery",
];

/// Opaque complete-history proof for one exact serial/build. Ordinary protocol
/// entrypoints never accept this diagnostic variant. Constructors check the
/// actual fault, ownership actions and replacement before exposing any row.
pub(crate) struct Proof {
    raw_sha256: [u8; 32],
    build: String,
    states: Vec<StateRecord>,
    retired_row: Option<String>,
}
impl Proof {
    pub(crate) fn complete(serial: &[u8], build: &str) -> Result<Self> {
        let proof = parse(serial, build, true)?;
        if crate::session_protocol::retention(serial, build)?.omitted != 0 {
            return Err("document crash requires complete retained history".into());
        }
        Ok(proof)
    }
    pub(crate) fn matches(&self, serial: &[u8], build: &str) -> bool {
        self.build == build && self.raw_sha256 == <[u8; 32]>::from(Sha256::digest(serial))
    }
    pub(crate) fn states(&self) -> &[StateRecord] {
        &self.states
    }
    pub(crate) fn state_line(&self, line: &str, build: &str) -> Result<StateRecord> {
        if self.build != build {
            return Err("document crash proof build differs".into());
        }
        if self.retired_row.as_deref() == Some(line) {
            // This still contains actual_process=0, zero ELF and false. It is
            // typed old-owner history, not a normalized live state.
            return retired_state(line, build);
        }
        native_protocol::state_line(line, build)
    }
}

/// Poll only the dedicated crash driver's completed history. A finish may not
/// yet be present; the old fault and replacement boot must already be proven.
pub(crate) fn prefix_states(serial: &[u8], build: &str) -> Result<Vec<StateRecord>> {
    Ok(parse(serial, build, false)?.states)
}

fn retired_state(line: &str, build: &str) -> Result<StateRecord> {
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 1024
        || f.len() != 3 + FIELDS.len()
        || f[0] != "EVROSION_NATIVE_STATE"
        || f[1] != "protocol=1"
        || f[2] != format!("build={build}")
    {
        return Err("document retired-owner state extent/build".into());
    }
    let mut fields = BTreeMap::new();
    for (field, key) in f[3..].iter().zip(FIELDS) {
        let value = field
            .strip_prefix(key)
            .and_then(|v| v.strip_prefix('='))
            .ok_or("document retired-owner state field order")?;
        match *key {
            "op" if value == "crash-app" => {}
            "result" if value == "ok" => {}
            "active" if value == "a" => {}
            "staged" | "previous" if value == "none" => {}
            "identity_matches" if value == "false" => {}
            "actual_image_sha256" if value == "0".repeat(64) => {}
            "op"
            | "result"
            | "active"
            | "staged"
            | "previous"
            | "identity_matches"
            | "actual_image_sha256" => {
                return Err(
                    "document retired-owner state is not the exact dead crash tuple".into(),
                );
            }
            _ => {
                canonical_number(field, key)?;
            }
        }
        fields.insert((*key).into(), value.into());
    }
    let state = StateRecord { fields };
    if state.number("installed")? != 1
        || state.number("recovery")? != 0
        || state.number("process")? == 0
        || state.number("thread")? == 0
        || state.number("actual_process")? != 0
        || state.number("actual_thread")? != 0
    {
        return Err("document retired-owner state invents live/partial identity".into());
    }
    Ok(state)
}

fn parse(serial: &[u8], build: &str, complete: bool) -> Result<Proof> {
    if serial.len() > 1024 * 1024 {
        return Err("document crash history exceeds1MiB".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "document crash history UTF8")?;
    let mut states = Vec::new();
    let mut state_lines = Vec::new();
    let mut actions = Vec::new();
    let mut lifecycle = Vec::new();
    let mut retired_row = None;
    let mut summary = None;
    for (at, raw) in text
        .split_inclusive('\n')
        .enumerate()
        .filter(|(_, l)| l.ends_with('\n'))
    {
        let line = raw.trim_end_matches(['\r', '\n']);
        if line.starts_with("EVROSION_NATIVE_STATE") {
            if states.len() >= 12 || summary.is_some() {
                return Err("document crash state budget/order".into());
            }
            let state = match native_protocol::state_line(line, build) {
                Ok(state) => state,
                Err(_) if retired_row.is_none() => {
                    let state = retired_state(line, build)?;
                    retired_row = Some(line.to_owned());
                    state
                }
                Err(e) => return Err(e),
            };
            if state.number("report")? != states.len() as u64 + 1 {
                return Err("document crash state report replay/gap".into());
            }
            states.push(state);
            state_lines.push(at);
        } else if line.starts_with("EVROSION_M5_NATIVE_ACTION") {
            if actions.len() == 6 || summary.is_some() {
                return Err("document crash unexpected/late action".into());
            }
            actions.push((at, native_protocol::action(line, build)?));
        } else if line.starts_with("EVROSION_M4_DESKTOP_LIFECYCLE") {
            if lifecycle.len() == 2 || summary.is_some() {
                return Err("document crash duplicate/unrelated lifecycle".into());
            }
            lifecycle.push((at, desktop_protocol::lifecycle_syntax(line, build)?));
        } else if line.starts_with("EVROSION_M5_NATIVE ") {
            if summary.is_some() {
                return Err("document crash duplicate completion".into());
            }
            summary = Some(native_protocol::summary(line, build)?);
        } else if line.starts_with("EVROSION_M6_DOWNLOADED_ACTION")
            || line.starts_with("EVROSION_M6_NEGATIVE")
            || line.starts_with("EVROSION_M4_DESKTOP_EXIT")
            || line.starts_with("EVROSION_M5_NATIVE_RECOVERY")
        {
            return Err("document crash mixed profile/voluntary exit".into());
        }
    }
    if states.len() < 4 || actions.len() < 4 || lifecycle.len() != 2 {
        return Err(
            "document crash requires old boot/fault/retirement and replacement boot".into(),
        );
    }
    let old = &actions[0].1;
    let new = &actions[3].1;
    if old.process == new.process
        || old.thread == new.thread
        || old.image_sha256 != new.image_sha256
        || old.image_sha256 == "0".repeat(64)
    {
        return Err(
            "document crash replacement must be fresh and use the same actual image".into(),
        );
    }
    for (i, (_, action)) in actions.iter().enumerate() {
        let owner = if i < 3 { old } else { new };
        if action.kind != ["start", "stop", "reap"][i % 3]
            || (action.process, action.thread) != (owner.process, owner.thread)
            || action.image_sha256 != old.image_sha256
        {
            return Err("document crash actions have stale/wrong/out-of-order owners".into());
        }
    }
    let (fault_at, fault) = &lifecycle[0];
    let (restart_at, restart) = &lifecycle[1];
    if fault.event != Event::Fault
        || fault.actor != Actor::App
        || (fault.process, fault.thread) != (old.process, old.thread)
        || fault.replacement != 0
        || fault.grants != 1
        || (fault.vector, fault.error, fault.address) != (14, 4, 0x80_0040_0000)
        || restart.event != Event::Restart
        || restart.actor != Actor::App
        || (restart.process, restart.thread) != (old.process, old.thread)
        || restart.replacement != new.process
        || restart.grants != 1
        || restart.display_process != fault.display_process
        || !(actions[0].0 < state_lines[1]
            && state_lines[1] < actions[1].0
            && actions[1].0 < *fault_at
            && *fault_at < actions[2].0
            && actions[2].0 < actions[3].0
            && actions[3].0 < *restart_at
            && *restart_at < state_lines[3])
        || retired_row.is_some() && *fault_at >= state_lines[2]
    {
        return Err("document crash lacks exact real PF14/retirement/replacement ordering".into());
    }
    for state in &states {
        if UNCHANGED
            .iter()
            .any(|key| state.fields[*key] != states[0].fields[*key])
        {
            return Err("document crash changed native registry/data metadata".into());
        }
    }
    if !states[0].is("open")
        || states[0].number("process")? != 0
        || states[0].number("thread")? != 0
        || states[0].fields["actual_image_sha256"] != "0".repeat(64)
        || states[0].fields["installed"] != "1"
        || states[0].fields["active"] != "a"
        || states[0].fields["staged"] != "none"
        || states[0].fields["previous"] != "none"
        || states[0].fields["recovery"] != "0"
        || !states[1].is("boot")
        || !states[2].is("crash-app")
        || !states[3].is("boot")
    {
        return Err("document crash unexpected native state sequence".into());
    }
    for (i, state) in states.iter().enumerate().skip(1) {
        let owner = if i < 3 { old } else { new };
        if (state.number("process")?, state.number("thread")?) != (owner.process, owner.thread) {
            return Err("document crash source snapshot names wrong owner".into());
        }
        if (i != 2 || state.fields["identity_matches"] == "true")
            && (state.fields["actual_image_sha256"] != old.image_sha256
                || state.fields["identity_matches"] != "true"
                || (
                    state.number("actual_process")?,
                    state.number("actual_thread")?,
                ) != (owner.process, owner.thread))
        {
            return Err("document crash live boot/finish identity differs".into());
        }
        if i >= 4
            && (state.fields["op"] != "finish"
                || !matches!(state.fields["result"].as_str(), "busy" | "ok")
                || (i + 1 < states.len() && state.is("finish")))
        {
            return Err("document crash invalid/duplicate finish state".into());
        }
    }
    if complete {
        if actions.len() != 6 || !states.last().is_some_and(|s| s.is("finish")) {
            return Err("document crash completion lacks complete owner teardown/finish".into());
        }
        let counts = summary.ok_or("document crash completion missing")?;
        for (key, value) in [
            ("processes", 8),
            ("starts", 8),
            ("faults", 1),
            ("restarts", 1),
            ("grants", 2),
            ("app_a_starts", 2),
            ("app_a_stops", 2),
            ("app_a_reaps", 2),
            ("app_b_starts", 0),
            ("app_b_stops", 0),
            ("app_b_reaps", 0),
            ("app_b_process", 0),
            ("app_b_thread", 0),
            ("readonly_rejections", 0),
            ("app_a_process", new.process),
            ("app_a_thread", new.thread),
        ] {
            if counts[key] != value {
                return Err(format!(
                    "document crash exact completion count differs: {key}"
                ));
            }
        }
    }
    Ok(Proof {
        raw_sha256: Sha256::digest(serial).into(),
        build: build.into(),
        states,
        retired_row,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const BUILD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const IMAGE: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    // Synthetic protocol mechanism tests only. No marker below is VM evidence.
    fn state(report: u64, op: &str, owner: u64, dead: bool) -> String {
        let actual = if dead { 0 } else { owner };
        let image = if actual == 0 { ZERO } else { IMAGE };
        format!(
            "EVROSION_NATIVE_STATE protocol=1 build={BUILD} report={report} op={op} result=ok installed=1 active=a staged=none previous=none process={owner} thread={owner} revision=2 data_epoch=1 data_counter=0 value=1001 mutations=0 recovery=0 actual_process={actual} actual_thread={actual} actual_image_sha256={image} identity_matches={}\n",
            !dead
        )
    }
    fn action(kind: &str, owner: u64) -> String {
        format!(
            "EVROSION_M5_NATIVE_ACTION protocol=1 build={BUILD} action={kind} process={owner} thread={owner} image_sha256={IMAGE}\n"
        )
    }
    fn history(dead: bool, finish: bool) -> String {
        let mut s = state(1, "open", 0, false);
        s += &action("start", 7);
        s += &state(2, "boot", 7, false);
        s += &action("stop", 7);
        s += &format!(
            "EVROSION_M4_DESKTOP_LIFECYCLE protocol=1 build={BUILD} event=fault actor=app process=7 thread=7 replacement=0 display_process=3 grants=1 vector=14 error=4 address=549760008192\n"
        );
        s += &action("reap", 7);
        s += &state(3, "crash-app", 7, dead);
        s += &action("start", 263);
        s += &format!(
            "EVROSION_M4_DESKTOP_LIFECYCLE protocol=1 build={BUILD} event=restart actor=app process=7 thread=7 replacement=263 display_process=3 grants=1 vector=0 error=0 address=0\n"
        );
        s += &state(4, "boot", 263, false);
        if finish {
            s += &state(5, "finish", 263, false);
            s += &action("stop", 263);
            s += &action("reap", 263);
            s += &format!(
                "EVROSION_M5_NATIVE protocol=1 build={BUILD} status=PASS processes=8 starts=8 calls=200 replies=200 faults=1 restarts=1 grants=2 app_a_starts=2 app_b_starts=0 app_a_stops=2 app_b_stops=0 app_a_reaps=2 app_b_reaps=0 app_a_process=263 app_b_process=0 app_a_thread=263 app_b_thread=0 package_a_pages=27 package_b_pages=27 bank_maps=2 bank_detaches=2 bank_reclaimed=54 readonly_rejections=0 root_exit=0 frames=true metadata=true guards=true display_survived=true\n"
            );
        }
        s
    }
    #[test]
    fn both_crash_snapshot_timings_preserve_raw_identity_semantics() {
        for dead in [false, true] {
            let serial = history(dead, false);
            let states = prefix_states(serial.as_bytes(), BUILD).unwrap();
            assert_eq!(states.len(), 4);
            assert_eq!(states[2].number("process").unwrap(), 7);
            assert_eq!(
                states[2].number("actual_process").unwrap(),
                if dead { 0 } else { 7 }
            );
            assert_eq!(states[2].fields["identity_matches"], (!dead).to_string());
            assert_eq!(states[3].number("actual_process").unwrap(), 263);
        }
    }
    #[test]
    fn ordinary_parsers_still_reject_the_unmodified_false_row() {
        let line = state(3, "crash-app", 7, true);
        assert!(native_protocol::state_line(line.trim_end(), BUILD).is_err());
        assert!(native_protocol::states(history(true, false).as_bytes(), BUILD).is_err());
        assert!(
            native_protocol::state_line(state(3, "crash-app", 7, false).trim_end(), BUILD).is_ok()
        );
    }
    #[test]
    fn dead_snapshot_cannot_become_a_live_vacancy_or_unrelated_operation() {
        let serial = history(true, false);
        let dead = state(3, "crash-app", 7, true);
        for bad in [
            dead.replace("op=crash-app", "op=boot"),
            dead.replace("actual_process=0", "actual_process=7"),
            dead.replace("actual_thread=0", "actual_thread=7"),
            dead.replace(
                &format!("actual_image_sha256={ZERO}"),
                &format!("actual_image_sha256={IMAGE}"),
            ),
            dead.replace("process=7 thread=7", "process=263 thread=263"),
            dead.replace("report=3", "report=4"),
            format!("{dead}{dead}"),
        ] {
            assert!(prefix_states(serial.replace(&dead, &bad).as_bytes(), BUILD).is_err());
        }
        let vacancy = serial.replace(&state(4, "boot", 263, false), &state(4, "boot", 0, false));
        assert!(prefix_states(vacancy.as_bytes(), BUILD).is_err());
    }
    #[test]
    fn exact_genuine_fault_retirement_and_fresh_replacement_are_required() {
        let serial = history(true, false);
        for bad in [
            serial.replace("vector=14", "vector=6"),
            serial.replace("error=4", "error=0"),
            serial.replace("address=549760008192", "address=549760008193"),
            serial.replace(&action("stop", 7), ""),
            serial.replace(&action("reap", 7), ""),
            serial.replace("replacement=263", "replacement=264"),
            serial.replace("event=restart actor=app", "event=restart actor=shell"),
            serial.replace(&action("start", 263), &action("start", 7)),
            serial.replace(&state(4, "boot", 263, false), &state(4, "boot", 264, false)),
        ] {
            assert!(prefix_states(bad.as_bytes(), BUILD).is_err());
        }
        let dead = state(3, "crash-app", 7, true);
        let moved = serial
            .replace(&dead, "")
            .replace(&action("stop", 7), &(dead + &action("stop", 7)));
        assert!(prefix_states(moved.as_bytes(), BUILD).is_err());
    }
    #[test]
    fn complete_proof_requires_finish_teardown_and_real_retention_footer() {
        assert!(parse(history(true, false).as_bytes(), BUILD, true).is_err());
        let complete_core = history(true, true);
        parse(complete_core.as_bytes(), BUILD, true).unwrap();
        // A well-formed core trace alone is insufficient for the public proof.
        assert!(Proof::complete(complete_core.as_bytes(), BUILD).is_err());
        assert!(
            parse(
                complete_core.replace("faults=1", "faults=0").as_bytes(),
                BUILD,
                true
            )
            .is_err()
        );
    }
    #[test]
    fn proof_is_bound_to_every_raw_byte_and_exact_build() {
        let serial = history(true, true);
        let proof = parse(serial.as_bytes(), BUILD, true).unwrap();
        assert!(proof.matches(serial.as_bytes(), BUILD));
        assert!(!proof.matches(format!("{serial}\n").as_bytes(), BUILD));
        assert!(!proof.matches(serial.as_bytes(), IMAGE));
        assert!(
            native_protocol::record_document_crash(format!("{serial}\n").as_bytes(), BUILD, &proof)
                .is_err()
        );
        assert!(
            crate::boot_protocol::check_document_crash(
                serial.as_bytes(),
                IMAGE,
                Some(ev_test_protocol::QEMU_PASS_STATUS),
                &proof
            )
            .is_err()
        );
    }
}
