//! Exact Native3 mechanism records. IDs are observed provenance, never authority.
use crate::{boot_protocol::canonical_number, build::Result, native_protocol};
use std::collections::BTreeMap;
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
fn digest(field: &str, key: &str) -> Result<String> {
    let v = field
        .strip_prefix(key)
        .and_then(|s| s.strip_prefix('='))
        .ok_or("Native3 digest field missing")?;
    if v.len() != 64
        || !v
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Native3 digest is not canonical64hex".into());
    }
    Ok(v.into())
}
pub(crate) fn summary(line: &str, build: &str) -> Result<BTreeMap<String, u64>> {
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 2048
        || f.len() != 4 + NUMBERS.len() + 5
        || f[0] != "EVROSION_M5_NATIVE_RECOVERY"
        || f[1] != "protocol=1"
        || digest(f[2], "build")? != build
        || f[3] != "status=PASS"
    {
        return Err("malformed/wrong-build Native3 Recovery completion".into());
    }
    let mut counts = BTreeMap::new();
    for (v, k) in f[4..4 + NUMBERS.len()].iter().zip(NUMBERS) {
        counts.insert((*k).into(), canonical_number(v, k)?);
    }
    if f[4 + NUMBERS.len()..]
        != [
            "root_exit=0",
            "frames=true",
            "metadata=true",
            "guards=true",
            "graphical=false",
        ]
    {
        return Err("Native3 independent recovery ownership/exit proof incomplete".into());
    }
    if counts["processes"] != 2
        || counts["starts"] != 2
        || counts["calls"] == 0
        || counts["calls"] != counts["replies"]
        || counts["faults"] != 0
        || counts["restarts"] != 0
        || counts["grants"] != 0
        || counts["bank_maps"] != 2
        || counts["bank_detaches"] != 2
        || counts["bank_reclaimed"] != counts["package_a_pages"] + counts["package_b_pages"]
        || counts["readonly_rejections"] != 0
    {
        return Err("Native3 Recovery is not the exact Root+Block independent graph".into());
    }
    for slot in ["a", "b"] {
        if !(1..=63).contains(&counts[&format!("package_{slot}_pages")]) {
            return Err("Native3 Recovery package bank exceeds real bounds".into());
        }
        for suffix in ["starts", "stops", "reaps", "process", "thread"] {
            if counts[&format!("app_{slot}_{suffix}")] != 0 {
                return Err("Native3 Recovery invented Application execution".into());
            }
        }
    }
    Ok(counts)
}
/// Syntactic validation for generic line parsers. Complete ordering is checked
/// by record(); trusted Root/Block image and namespace joins are separate.
pub(crate) fn line(line: &str, build: &str) -> Result<()> {
    if line.starts_with("EVROSION_M5_NATIVE_RECOVERY") {
        summary(line, build).map(|_| ())
    } else {
        event(line, build).map(drop)
    }
}
pub(crate) fn line_session(line: &str, build: &str) -> Result<()> {
    event_profile(line, build, true, false).map(drop)
}
pub(crate) fn line_network(line: &str, build: &str) -> Result<()> {
    event_network(line, build).map(drop)
}
pub(crate) fn record(
    serial: &[u8],
    build: &str,
    recovery: bool,
) -> Result<native_protocol::Record> {
    if !recovery {
        if std::str::from_utf8(serial)
            .map_err(|_| "Native3 serial notUTF8")?
            .lines()
            .any(|line| line.starts_with("EVROSION_M5_NATIVE_RECOVERY"))
        {
            return Err("Native3 ordinary graph mixed Recovery completion".into());
        }
        return native_protocol::record(serial, build);
    }
    if serial.len() > 1024 * 1024 || !serial.ends_with(b"\n") {
        return Err("Native3 Recovery serial oversized/truncated".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "Native3 Recovery serial notUTF8")?;
    let mut counts = None;
    for raw in text.split_inclusive('\n') {
        let line = raw.trim_end_matches(['\r', '\n']);
        if line.starts_with("EVROSION_M5_NATIVE_RECOVERY") {
            if counts.is_some() {
                return Err("Native3 duplicate Recovery completion".into());
            }
            counts = Some(summary(line, build)?);
        } else if line.starts_with("EVROSION_M5_NATIVE ")
            || line.starts_with("EVROSION_M5_NATIVE_ACTION")
            || line.starts_with("EVROSION_M6_DOWNLOADED_ACTION")
            || line.starts_with("EVROSION_M4_DESKTOP ")
        {
            return Err("Native3 Recovery mixed ordinary/App/Desktop execution".into());
        }
    }
    Ok(native_protocol::Record {
        history_complete: true,
        downloaded_actions: Vec::new(),
        counts: counts.ok_or("Native3 Recovery footer absent")?,
        actions: Vec::new(),
    })
}
/// Explicit V4 Recovery: the Root+Block graph retains the nine-slot session
/// recorder while emitting its true independent Recovery completion marker.
/// Legacy Recovery remains on record(..., true) and its seven-slot boot gate.
pub(crate) fn record_network_recovery(
    serial: &[u8],
    build: &str,
) -> Result<native_protocol::Record> {
    let retention = crate::session_protocol::retention_network_recovery(serial, build)?;
    if retention.omitted != 0 {
        return Err("V4 Recovery history incomplete".into());
    }
    let mut record = record(serial, build, true)?;
    let actions = crate::downloaded_protocol::records(serial, build, true)?;
    if !actions.is_empty() {
        return Err("V4 Recovery started downloaded code".into());
    }
    let states = native_protocol::states_network(serial, build)?;
    if !states.last().is_some_and(|r| r.is("finish")) {
        return Err("V4 Recovery lacks complete requested finish report".into());
    }
    let mut common = None;
    for line in std::str::from_utf8(serial)
        .map_err(|_| "V4 Recovery UTF8")?
        .lines()
    {
        if line.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX ") {
            let Event::Common(c) = event_network(line, build)? else {
                unreachable!()
            };
            if c.mode != 2 || common.replace(c).is_some() {
                return Err("V4 Recovery actual mode/Root prefix differs".into());
            }
        }
        if line.starts_with("EVROSION_M5_NATIVE_CRITICAL_READY ")
            || line.starts_with("EVROSION_M5_NATIVE_MANAGED_READ ")
            || line.starts_with("EVROSION_M5_NATIVE_INHIBIT ")
        {
            return Err("V4 Recovery invented normal Shell/App graph".into());
        }
    }
    let common = common.ok_or("V4 Recovery actual Root+Block prefix absent")?;
    let profiles = crate::native_profile::finished_network(serial, build, 0, Some(2))?;
    for (index, profile) in profiles.iter().enumerate() {
        let c = &profile.counts;
        let identity = match index {
            0 => Some((common.root_process, common.root_thread)),
            4 => Some((common.block_process, common.block_thread)),
            _ => None,
        };
        if let Some((process, thread)) = identity {
            if c["incarnations"] != 1
                || c["current_process"] != process
                || c["current_thread"] != thread
            {
                return Err("V4 Recovery profiles differ from actual Root/Block identities".into());
            }
        } else if c
            .iter()
            .any(|(name, value)| !matches!(name.as_str(), "index" | "elapsed_ticks") && *value != 0)
        {
            return Err("V4 Recovery started App/Display/NIC or another normal actor".into());
        }
    }
    if !crate::network_protocol::records(serial, build)?.is_empty()
        || !crate::time_proof_protocol::records(serial, build)?.is_empty()
    {
        return Err("V4 Recovery unexpectedly ran network/time work".into());
    }
    record.downloaded_actions = actions;
    Ok(record)
}
#[cfg(test)]
mod tests {
    use super::*;
    // Synthetic Root+Block V4 parser input. Generic mechanism rows below are
    // borrowed from a retained parser fixture; this is no new VM evidence.
    fn network_recovery_fixture() -> (String, String) {
        let raw = include_str!("../../../tests/fixtures/m6-session-exercise-parser.serial");
        let rows: Vec<_> = raw.lines().collect();
        let build = rows
            .iter()
            .find(|l| l.starts_with("EVROSION_BOOT "))
            .unwrap()
            .split(' ')
            .find_map(|f| f.strip_prefix("build="))
            .unwrap()
            .to_owned();
        let before = rows
            .iter()
            .position(|l| l.starts_with("EVROSION_M5_NATIVE_MEMORY "))
            .unwrap();
        let after = rows
            .iter()
            .position(|l| l.starts_with("EVROSION_M5_NATIVE "))
            .unwrap()
            + 1;
        let mut out = rows[..before].join("\n") + "\n";
        out += rows
            .iter()
            .find(|l| l.starts_with("EVROSION_M5_NATIVE_MEMORY ") && l.contains(" phase=before "))
            .unwrap();
        out += "\n";
        let padding = *rows
            .iter()
            .find(|l| l.starts_with("EVROSION_M6_WINDOW_PADDING "))
            .unwrap();
        out += padding;
        out += "\n";
        out += &format!(
            "EVROSION_M5_NATIVE_COMMON_PREFIX protocol=1 build={build} mode=2 root_process=20 root_thread=120 root_image_sha256={} root_epoch=4 root_incarnation=2 root_manifest_sha256={} block_process=24 block_thread=124 block_image_sha256={} system_endpoint=77 root_frames=40 block_frames=20\n",
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64)
        );
        out += &format!(
            "EVROSION_NATIVE_STATE protocol=1 build={build} report=1 op=finish result=ok installed=0 active=none staged=none previous=none process=0 thread=0 revision=0 data_epoch=0 data_counter=0 value=0 mutations=0 recovery=0 actual_process=0 actual_thread=0 actual_image_sha256={} identity_matches=true\n",
            "0".repeat(64)
        );
        for i in 0..9 {
            let running = matches!(i, 0 | 4);
            let n = u64::from(running);
            out += &format!(
                "EVROSION_M5_NATIVE_PROFILE protocol=1 build={build} phase=finished scope=actor_slot index={i} current_process={} current_thread={} current_job={} incarnations={n} elapsed_ticks=100 captures={} syscalls={} irqs={n} faults=0 port_in={} port_out={} yields={n} continuations={} charged_cpu_ticks={n} current_job_cpu_ticks={n} cpu_scope=subtree\n",
                if running { 20 + i } else { 0 },
                if running { 120 + i } else { 0 },
                if running { 100 + i } else { 0 },
                n * 11,
                n * 10,
                n * 3,
                n * 2,
                n * 8
            );
        }
        out += &format!(
            "EVROSION_M6_UI_COUNTS protocol=1 build={build} phase=finished barriers=0 cursors=0 note_requests=0 note_accepted=0 note_delivered=0\n"
        );
        out += padding;
        out += "\n";
        for phase in ["held", "after"] {
            out += rows
                .iter()
                .find(|l| {
                    l.starts_with("EVROSION_M5_NATIVE_MEMORY ")
                        && l.contains(&format!(" phase={phase} "))
                })
                .unwrap();
            out += "\n";
        }
        out += &format!(
            "EVROSION_M6_LOG protocol=1 build={build} observed=0 retained=0 omitted=0 detail_bytes=0 final_bytes=0 omitted_bytes=0 prefix_closed=false\n"
        );
        out += &footer().replace(&"a".repeat(64), &build);
        out += "\n";
        out += &rows[after..].join("\n");
        out += "\n";
        (out, build)
    }
    #[test]
    fn network_recovery_requires_true_marker_complete_retention_and_exact_nine_slot_empty_graph() {
        let (serial, build) = network_recovery_fixture();
        let record = record_network_recovery(serial.as_bytes(), &build).unwrap();
        assert_eq!(record.counts["starts"], 2);
        assert!(record.actions.is_empty() && record.downloaded_actions.is_empty());
        assert!(crate::session_protocol::retention(serial.as_bytes(), &build).is_err());
        let body = crate::session_protocol::without_network_diagnostics(serial.as_bytes(), &build)
            .unwrap();
        crate::boot_protocol::check_network_recovery(&body, &build, Some(33)).unwrap();
        assert!(crate::boot_protocol::check_network(&body, &build, Some(33)).is_err());
        assert!(crate::boot_protocol::check(&body, &build, Some(33)).is_err());
        assert!(crate::native_profile::finished(serial.as_bytes(), &build, 0, Some(2)).is_err());
        for bad in [
            serial.replace("mode=2", "mode=1"),
            serial.replace("EVROSION_M5_NATIVE_RECOVERY ", "EVROSION_M5_NATIVE "),
            serial.replace("graphical=false", "display_survived=true"),
            serial.replace("index=4 current_process=24", "index=4 current_process=25"),
            serial
                .lines()
                .filter(|l| !l.contains(" index=8 "))
                .map(|l| format!("{l}\n"))
                .collect(),
            serial.clone() + &footer().replace(&"a".repeat(64), &build) + "\n",
        ] {
            assert!(record_network_recovery(bad.as_bytes(), &build).is_err());
        }
    }
    #[test]
    fn both_boot_postchecks_select_recovery_only_for_exact_proof_and_owner_fixtures() {
        let (serial, build) = network_recovery_fixture();
        let body = crate::session_protocol::without_network_diagnostics(serial.as_bytes(), &build)
            .unwrap();
        for fixture in ["m6-network-recovery", "m6-network-recovery-owner"] {
            crate::boot::check_network_fixture(Some(fixture), &body, &build, Some(33)).unwrap();
            let record =
                crate::boot::record_network_fixture(Some(fixture), serial.as_bytes(), &build)
                    .unwrap();
            assert_eq!(record.counts["starts"], 2);
            assert!(record.actions.is_empty() && record.downloaded_actions.is_empty());
            assert!(
                crate::boot::check_network_fixture(Some(fixture), &body, &build, Some(35)).is_err()
            );
            let incomplete = serial
                .lines()
                .filter(|l| !l.contains(" index=8 "))
                .map(|l| format!("{l}\n"))
                .collect::<String>();
            assert!(
                crate::boot::record_network_fixture(Some(fixture), incomplete.as_bytes(), &build)
                    .is_err()
            );
        }
        for fixture in [
            None,
            Some("m6-network"),
            Some("m6-network-system"),
            Some("m6-session"),
            Some("m5-native-recovery"),
            Some("m6-network-recovery-extra"),
            Some("m6-network-recovery-owner-extra"),
        ] {
            assert!(!crate::boot::network_recovery_fixture(fixture));
            assert!(crate::boot::check_network_fixture(fixture, &body, &build, Some(33)).is_err());
            assert!(
                crate::boot::record_network_fixture(fixture, serial.as_bytes(), &build).is_err()
            );
        }
    }
    #[test]
    fn network_recovery_rejects_activity_in_every_unstarted_actor_and_keeps_legacy_seven_strict() {
        let (serial, build) = network_recovery_fixture();
        for index in [1, 2, 3, 5, 6, 7, 8] {
            let old = serial
                .lines()
                .find(|l| {
                    l.starts_with("EVROSION_M5_NATIVE_PROFILE ")
                        && l.contains(&format!(" index={index} "))
                })
                .unwrap();
            let bad = serial.replace(old, &old.replace("port_in=0", "port_in=1"));
            assert!(record_network_recovery(bad.as_bytes(), &build).is_err());
        }
        let seven = serial
            .lines()
            .filter(|l| !l.contains(" index=7 ") && !l.contains(" index=8 "))
            .map(|l| format!("{l}\n"))
            .collect::<String>();
        assert!(crate::native_profile::finished(seven.as_bytes(), &build, 0, Some(2)).is_ok());
        assert!(record_network_recovery(seven.as_bytes(), &build).is_err());
    }
    fn footer() -> String {
        let mut out = format!(
            "EVROSION_M5_NATIVE_RECOVERY protocol=1 build={} status=PASS",
            "a".repeat(64)
        );
        for key in NUMBERS {
            let n = match *key {
                "processes" | "starts" | "bank_maps" | "bank_detaches" => 2,
                "calls" | "replies" => 4,
                "package_a_pages" | "package_b_pages" => 1,
                "bank_reclaimed" => 2,
                _ => 0,
            };
            out += &format!(" {key}={n}");
        }
        out + " root_exit=0 frames=true metadata=true guards=true graphical=false"
    }
    #[test]
    fn independent_recovery_never_infers_gui_or_application() {
        let build = "a".repeat(64);
        let good = footer();
        assert!(line(&good, &build).is_ok());
        assert!(record(format!("{good}\n").as_bytes(), &build, true).is_ok());
        for bad in [
            good.replace("processes=2", "processes=7"),
            good.replace("starts=2", "starts=02"),
            good.replace("faults=0", "faults=1"),
            good.replace("app_a_starts=0", "app_a_starts=1"),
            good.replace("graphical=false", "display_survived=true"),
            good.replace("calls=4", "calls=0"),
            good.replace("bank_reclaimed=2", "bank_reclaimed=0"),
            format!("{good} ignored=true"),
        ] {
            assert!(summary(&bad, &build).is_err(), "{bad}");
        }
        assert!(record(good.as_bytes(), &build, true).is_err());
        assert!(record(format!("{good}\n{good}\n").as_bytes(), &build, true).is_err());
        assert!(
            record(
                format!("{good}\nEVROSION_M5_NATIVE_ACTION x\n").as_bytes(),
                &build,
                true
            )
            .is_err()
        );
        assert!(summary(&good, &"b".repeat(64)).is_err());
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CommonPrefix {
    pub mode: u64,
    pub root_process: u64,
    pub root_thread: u64,
    pub root_image: String,
    pub root_epoch: u64,
    pub root_incarnation: u64,
    pub root_manifest: String,
    pub block_process: u64,
    pub block_thread: u64,
    pub block_image: String,
    pub system_endpoint: u64,
    pub root_frames: u64,
    pub block_frames: u64,
}
#[derive(Clone, Debug)]
pub(crate) struct CriticalReady {
    pub process: u64,
    pub thread: u64,
    pub image: String,
    pub tick: u64,
}
#[derive(Clone, Debug)]
pub(crate) struct ManagedRead {
    pub root_process: u64,
    pub root_thread: u64,
    pub process: u64,
    pub thread: u64,
    pub image: String,
    pub source_endpoint: u64,
    pub inbox_endpoint: u64,
    pub nonce: u64,
    pub ticket: u64,
}
#[derive(Clone, Debug)]
pub(crate) struct Inhibit {
    pub root_process: u64,
    pub root_thread: u64,
    pub process: u64,
    pub thread: u64,
    pub image: String,
    pub outbound_pending: u64,
}
#[derive(Clone, Debug)]
pub(crate) enum Event {
    Common(CommonPrefix),
    Critical(CriticalReady),
    Managed(ManagedRead),
    Inhibit(Inhibit),
    SelfIdentity(SelfIdentity),
}
fn id(v: &str, key: &str) -> Result<u64> {
    let n = canonical_number(v, key)?;
    if n == 0 || n == u64::MAX {
        return Err(format!("Native3 invalid {key}"));
    }
    Ok(n)
}
pub(crate) fn event(line: &str, build: &str) -> Result<Event> {
    event_profile(line, build, false, false)
}
pub(crate) fn event_network(line: &str, build: &str) -> Result<Event> {
    event_profile(line, build, true, true)
}
fn event_profile(line: &str, build: &str, session: bool, network: bool) -> Result<Event> {
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 1536 || f.len() < 3 || f[1] != "protocol=1" || digest(f[2], "build")? != build {
        return Err("Native3 malformed/wrong-build observation".into());
    }
    match f[0] {
        "EVROSION_M5_NATIVE_COMMON_PREFIX" if f.len() == 16 => {
            let r = CommonPrefix {
                mode: canonical_number(f[3], "mode")?,
                root_process: id(f[4], "root_process")?,
                root_thread: id(f[5], "root_thread")?,
                root_image: digest(f[6], "root_image_sha256")?,
                root_epoch: id(f[7], "root_epoch")?,
                root_incarnation: id(f[8], "root_incarnation")?,
                root_manifest: digest(f[9], "root_manifest_sha256")?,
                block_process: id(f[10], "block_process")?,
                block_thread: id(f[11], "block_thread")?,
                block_image: digest(f[12], "block_image_sha256")?,
                system_endpoint: id(f[13], "system_endpoint")?,
                root_frames: id(f[14], "root_frames")?,
                block_frames: id(f[15], "block_frames")?,
            };
            if r.mode > 2
                || r.root_process == r.block_process
                || r.root_thread == r.block_thread
                || r.root_frames
                    > if network {
                        ev_kernel::executable::ROOT_V4_MAX_PRIVATE_FRAMES
                    } else {
                        ev_kernel::executable::NATIVE_ROOT_MAX_PRIVATE_FRAMES
                    }
                || r.block_frames > 32
                || r.root_image == r.block_image
            {
                return Err("Native3 invalid actual protected prefix graph".into());
            }
            Ok(Event::Common(r))
        }
        "EVROSION_M5_NATIVE_CRITICAL_READY" if f.len() == 7 => Ok(Event::Critical(CriticalReady {
            process: id(f[3], "process")?,
            thread: id(f[4], "thread")?,
            image: digest(f[5], "image_sha256")?,
            tick: canonical_number(f[6], "tick")?,
        })),
        "EVROSION_M5_NATIVE_MANAGED_READ" if f.len() == 12 => {
            let r = ManagedRead {
                root_process: id(f[3], "root_process")?,
                root_thread: id(f[4], "root_thread")?,
                process: id(f[5], "process")?,
                thread: id(f[6], "thread")?,
                image: digest(f[7], "image_sha256")?,
                source_endpoint: id(f[8], "source_endpoint")?,
                inbox_endpoint: id(f[9], "inbox_endpoint")?,
                nonce: id(f[10], "nonce")?,
                ticket: id(f[11], "ticket")?,
            };
            if r.root_process == r.process
                || r.root_thread == r.thread
                || r.source_endpoint == r.inbox_endpoint
            {
                return Err("Native3 managed Read aliases live subject/source/inbox".into());
            }
            Ok(Event::Managed(r))
        }
        "EVROSION_M5_NATIVE_INHIBIT" if f.len() == 9 => {
            let r = Inhibit {
                root_process: id(f[3], "root_process")?,
                root_thread: id(f[4], "root_thread")?,
                process: id(f[5], "process")?,
                thread: id(f[6], "thread")?,
                image: digest(f[7], "image_sha256")?,
                outbound_pending: canonical_number(f[8], "outbound_pending")?,
            };
            if r.root_process == r.process || r.root_thread == r.thread || r.outbound_pending > 64 {
                return Err("Native3 inhibit invalid identity/pending count".into());
            }
            Ok(Event::Inhibit(r))
        }
        "EVROSION_M5_NATIVE_SELF_IDENTITY" if f.len() == 10 => {
            let r = SelfIdentity {
                sequence: id(f[3], "sequence")?,
                process: id(f[4], "process")?,
                thread: id(f[5], "thread")?,
                epoch: id(f[6], "root_epoch")?,
                incarnation: id(f[7], "root_incarnation")?,
                manifest: digest(f[8], "root_manifest_sha256")?,
                tick: canonical_number(f[9], "tick")?,
            };
            if !session && r.sequence > 32 {
                return Err("Native3 actual self identity query bound exceeded".into());
            }
            Ok(Event::SelfIdentity(r))
        }
        _ => Err("Native3 unknown/malformed actual observation".into()),
    }
}
pub(crate) fn observations(serial: &[u8], build: &str) -> Result<Vec<(usize, Event)>> {
    if serial.len() > 1024 * 1024 {
        return Err("Native3 observation serial oversized".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "Native3 observation serial notUTF8")?;
    let mut events = Vec::new();
    for (at, raw) in text.split_inclusive('\n').enumerate() {
        let line = raw.trim_end_matches(['\r', '\n']);
        if [
            "EVROSION_M5_NATIVE_COMMON_PREFIX",
            "EVROSION_M5_NATIVE_CRITICAL_READY",
            "EVROSION_M5_NATIVE_MANAGED_READ",
            "EVROSION_M5_NATIVE_INHIBIT",
            "EVROSION_M5_NATIVE_SELF_IDENTITY",
        ]
        .iter()
        .any(|p| line.starts_with(p))
        {
            if !raw.ends_with('\n') || events.len() >= 128 {
                return Err("Native3 truncated/overbudget actual observations".into());
            }
            events.push((at, event(line, build)?));
        }
    }
    Ok(events)
}

#[derive(Clone, Debug)]
pub(crate) struct SelfIdentity {
    pub sequence: u64,
    pub process: u64,
    pub thread: u64,
    pub epoch: u64,
    pub incarnation: u64,
    pub manifest: String,
    pub tick: u64,
}

#[cfg(test)]
mod observation_tests {
    use super::*;
    fn build() -> String {
        "a".repeat(64)
    }
    fn common() -> String {
        format!(
            "EVROSION_M5_NATIVE_COMMON_PREFIX protocol=1 build={} mode=1 root_process=20 root_thread=120 root_image_sha256={} root_epoch=4 root_incarnation=2 root_manifest_sha256={} block_process=24 block_thread=124 block_image_sha256={} system_endpoint=77 root_frames=40 block_frames=20",
            build(),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64)
        )
    }
    #[test]
    fn actual_prefix_and_scalar_identity_require_exact_fields_context_and_bounds() {
        let line = common();
        assert!(matches!(event(&line, &build()).unwrap(), Event::Common(_)));
        assert!(event(&line.replace("root_frames=40", "root_frames=85"), &build()).is_ok());
        for bad in [
            line.replace("mode=1", "mode=3"),
            line.replace("root_epoch=4", "root_epoch=0"),
            line.replace("block_process=24", "block_process=20"),
            line.replace("system_endpoint=77", "system_endpoint=077"),
            line.replace("root_frames=40", "root_frames=103"),
            format!("{line} ignored=true"),
        ] {
            assert!(event(&bad, &build()).is_err());
        }
        let line = format!(
            "EVROSION_M5_NATIVE_SELF_IDENTITY protocol=1 build={} sequence=1 process=20 thread=120 root_epoch=4 root_incarnation=2 root_manifest_sha256={} tick=20",
            build(),
            "c".repeat(64)
        );
        assert!(event(&line, &build()).is_ok());
        assert!(line_session(&line.replace("sequence=1", "sequence=33"), &build()).is_ok());
        for bad in [
            line.replace("sequence=1", "sequence=33"),
            line.replace("thread=120", "thread=0"),
            line.replace("tick=20", "tick=020"),
        ] {
            assert!(event(&bad, &build()).is_err());
        }
        assert!(observations(line.as_bytes(), &build()).is_err());
        assert_eq!(
            observations(format!("{line}\n").as_bytes(), &build())
                .unwrap()
                .len(),
            1
        );
    }
    #[test]
    fn network_prefix_uses_its_selected_capacity_without_loosening_native3() {
        let limit = ev_kernel::executable::ROOT_V4_MAX_PRIVATE_FRAMES;
        let field = format!("root_frames={limit}");
        let line = common().replace("root_frames=40", &field);
        assert!(event_network(&line, &build()).is_ok());
        assert!(event(&line, &build()).is_err());
        assert!(
            event_network(
                &line.replace(&field, &format!("root_frames={}", limit + 1)),
                &build()
            )
            .is_err()
        );
    }
    #[test]
    fn managed_delivery_and_inhibition_are_closed_records_without_aliases() {
        let managed = format!(
            "EVROSION_M5_NATIVE_MANAGED_READ protocol=1 build={} root_process=20 root_thread=120 process=25 thread=125 image_sha256={} source_endpoint=9 inbox_endpoint=10 nonce=3 ticket=4",
            build(),
            "b".repeat(64)
        );
        assert!(event(&managed, &build()).is_ok());
        for bad in [
            managed.replace("inbox_endpoint=10", "inbox_endpoint=9"),
            managed.replace("nonce=3", "nonce=0"),
            managed.replace("process=25", "process=20"),
            managed.replace("ticket=4", "ticket=04"),
        ] {
            assert!(event(&bad, &build()).is_err());
        }
        let inhibit = format!(
            "EVROSION_M5_NATIVE_INHIBIT protocol=1 build={} root_process=20 root_thread=120 process=25 thread=125 image_sha256={} outbound_pending=1",
            build(),
            "b".repeat(64)
        );
        assert!(event(&inhibit, &build()).is_ok());
        assert!(
            event(
                &inhibit.replace("outbound_pending=1", "outbound_pending=65"),
                &build()
            )
            .is_err()
        );
    }
}
