//! Bounded actual trap/scheduling observations, never health or completion.
use crate::{boot_protocol::canonical_number, build::Result};
use serde::Serialize;
use std::collections::BTreeMap;

const FIELDS: &[&str] = &[
    "index",
    "current_process",
    "current_thread",
    "current_job",
    "incarnations",
    "elapsed_ticks",
    "captures",
    "syscalls",
    "irqs",
    "faults",
    "port_in",
    "port_out",
    "yields",
    "continuations",
    "charged_cpu_ticks",
    "current_job_cpu_ticks",
];
#[derive(Debug, Serialize)]
pub(crate) struct Profile {
    pub counts: BTreeMap<String, u64>,
}
pub(crate) fn line(line: &str, build: &str) -> Result<Profile> {
    let fields: Vec<_> = line.split(' ').collect();
    if line.len() > 1024
        || fields.len() != 6 + FIELDS.len()
        || fields[..5]
            != [
                "EVROSION_M5_NATIVE_PROFILE",
                "protocol=1",
                &format!("build={build}"),
                "phase=finished",
                "scope=actor_slot",
            ]
        || fields.last() != Some(&"cpu_scope=subtree")
    {
        return Err("malformed, wrong-build or unfinished Native scheduling profile".into());
    }
    let counts = fields[5..5 + FIELDS.len()]
        .iter()
        .zip(FIELDS)
        .map(|(field, name)| Ok(((*name).into(), canonical_number(field, name)?)))
        .collect::<Result<BTreeMap<String, u64>>>()?;
    let c = &counts;
    let sum = |names: &[&str]| -> Result<u64> {
        names
            .iter()
            .try_fold(0u64, |total, name| total.checked_add(c[*name]))
            .ok_or_else(|| "Native scheduling counter overflow".into())
    };
    if c["index"] >= 7
        || c["captures"] != sum(&["syscalls", "irqs", "faults"])?
        || c["charged_cpu_ticks"] != c["irqs"]
        || sum(&["port_in", "port_out", "yields"])? > c["syscalls"]
        || sum(&["continuations", "yields"])? > c["syscalls"]
        || c["elapsed_ticks"] == 0
        || c["incarnations"] > c["captures"]
        || (c["current_process"] == 0) != (c["current_thread"] == 0)
        || (c["current_process"] == 0) != (c["current_job"] == 0)
        || (c["current_job"] == 0 && c["current_job_cpu_ticks"] != 0)
    {
        return Err("inconsistent Native scheduling counters or identity".into());
    }
    Ok(Profile { counts })
}
pub(crate) fn finished(
    serial: &[u8],
    build: &str,
    faults: u64,
    mode: Option<u64>,
) -> Result<Vec<Profile>> {
    use ev_userspace_contract::root_v2::native::{catalogue::BootMode, world_ticks};
    // Old Native2 receipts have no mode. New dedicated callers additionally
    // join the declared mode to the actual retained verified catalogue.
    let mode = match mode {
        None | Some(0) => BootMode::Standalone,
        Some(1) => BootMode::SystemManaged,
        Some(2) => BootMode::Recovery,
        _ => return Err("unknown Native scheduling world mode".into()),
    };
    if serial.len() > 1024 * 1024 {
        return Err("Native scheduling log exceeds1MiB".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "Native profile notUTF8")?;
    let mut profiles = Vec::new();
    for row in text.split_inclusive('\n') {
        if !row.starts_with("EVROSION_M5_NATIVE_PROFILE") {
            continue;
        }
        if !row.ends_with('\n') {
            return Err("truncated Native scheduling profile".into());
        }
        let profile = line(row.trim_end_matches(['\r', '\n']), build)?;
        if profile.counts["index"] != profiles.len() as u64 {
            return Err("Native scheduling profile replay, gap or ordering error".into());
        }
        profiles.push(profile);
    }
    let sum = |name: &str| -> Result<u64> {
        profiles
            .iter()
            .try_fold(0u64, |total, p| total.checked_add(p.counts[name]))
            .ok_or_else(|| "Native scheduling aggregate overflow".into())
    };
    if profiles.len() == 7 && profiles[0].counts["elapsed_ticks"] >= world_ticks(mode) {
        return Err("Native scheduling elapsed reached the selected finite world bound".into());
    }
    if profiles.len() != 7
        || profiles
            .iter()
            .any(|p| p.counts["elapsed_ticks"] != profiles[0].counts["elapsed_ticks"])
        || sum("faults")? != faults
        || sum("irqs")? == 0
        || sum("continuations")? == 0
        || sum("port_in")? == 0
    {
        return Err("Native scheduling batch missing actual timers, I/O or continuation".into());
    }
    Ok(profiles)
}

#[cfg(test)]
mod tests {
    use super::*;
    // Synthetic parser fixture only; it is not an executed runtime result.
    fn fixture() -> String {
        (0..7)
            .map(|i| format!("EVROSION_M5_NATIVE_PROFILE protocol=1 build={} phase=finished scope=actor_slot index={i} current_process={} current_thread={} current_job={} incarnations=1 elapsed_ticks=100 captures=11 syscalls=10 irqs=1 faults=0 port_in=3 port_out=2 yields=1 continuations=8 charged_cpu_ticks=1 current_job_cpu_ticks=1 cpu_scope=subtree\n", "a".repeat(64), i+1, i+1, i+1))
            .collect()
    }
    #[test]
    fn parser_keeps_measured_slot_totals_separate_from_current_job() {
        let text = fixture().replace("current_job_cpu_ticks=1", "current_job_cpu_ticks=0");
        let p = finished(text.as_bytes(), &"a".repeat(64), 0, None).unwrap();
        assert_eq!(p.len(), 7);
        assert_eq!(p[0].counts["charged_cpu_ticks"], 1);
        assert_eq!(p[0].counts["current_job_cpu_ticks"], 0);
    }
    #[test]
    fn profile_rejects_replay_incomplete_wrong_build_phase_and_inconsistent_counters() {
        let good = fixture();
        for text in [
            good.clone() + good.lines().next().unwrap() + "\n",
            good.lines().take(6).map(|l| format!("{l}\n")).collect(),
            good.replace("phase=finished", "phase=bound"),
            good.replace(&"a".repeat(64), &"b".repeat(64)),
            good.replace("captures=11", "captures=12"),
            good.replace("charged_cpu_ticks=1", "charged_cpu_ticks=2"),
            good.replace("continuations=8", "continuations=10"),
            good.trim_end().into(),
        ] {
            assert!(finished(text.as_bytes(), &"a".repeat(64), 0, None).is_err());
        }
        assert!(finished(good.as_bytes(), &"a".repeat(64), 1, None).is_err());
    }
    #[test]
    fn finished_world_bound_is_exclusive_and_mode_specific() {
        let build = "a".repeat(64);
        for (mode, limit) in [
            (None, 16_384),
            (Some(0), 16_384),
            (Some(1), 32_768),
            (Some(2), 16_384),
        ] {
            let fixture = fixture();
            for (elapsed, accepted) in [(limit - 1, true), (limit, false), (limit + 1, false)] {
                let changed =
                    fixture.replace("elapsed_ticks=100", &format!("elapsed_ticks={elapsed}"));
                assert_eq!(
                    finished(changed.as_bytes(), &build, 0, mode).is_ok(),
                    accepted,
                    "mode={mode:?} elapsed={elapsed}"
                );
            }
        }
        let legacy_overbound = fixture().replace("elapsed_ticks=100", "elapsed_ticks=16384");
        assert!(finished(legacy_overbound.as_bytes(), &build, 0, Some(1)).is_ok());
        assert!(finished(fixture().as_bytes(), &build, 0, Some(3)).is_err());
    }
}
