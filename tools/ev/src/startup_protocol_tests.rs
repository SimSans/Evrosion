use super::*;
const OLD: &[u8] = include_bytes!("../../../tests/fixtures/m6-startup05-failed-prefix.serial");
// Historical captured data only: the original Source06 workflow FAILED its
// Host checker after FaultC. Parser replay cannot qualify its missing boots.
const FAULT06: &[u8] = include_bytes!("../../../tests/fixtures/m6-startup06-fault-c.serial");
fn build() -> String {
    std::str::from_utf8(OLD)
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("EVROSION_BOOT protocol=1 build="))
        .unwrap()
        .trim_end_matches('\r')
        .to_owned()
}
fn replace_system(line: &str, build: &str, s: Snapshot) -> String {
    let f: Vec<_> = line.split(' ').collect();
    format!(
        "EVROSION_NATIVE_SYSTEM protocol=1 build={build} {} {} {} bytes={}",
        f[3],
        f[4],
        f[5],
        s.encode()
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}
/// Synthetic current-layout parser input derived from preserved FAILED05. This
/// rewrites protocol fields for wire tests; it is never actual VM evidence.
fn compact_with_health(health: [u8; 32]) -> (String, String) {
    let build = build();
    let mut rows: Vec<String> = std::str::from_utf8(OLD)
        .unwrap()
        .lines()
        .map(|l| l.trim_end_matches('\r').to_owned())
        .collect();
    let first = rows
        .iter()
        .position(|l| l.starts_with("EVROSION_NATIVE_SYSTEM "))
        .unwrap();
    let crate::native_diagnostics::Event::Report(r) =
        crate::native_diagnostics::parse(&rows[first], &build, first).unwrap()
    else {
        unreachable!()
    };
    let mut s = Snapshot::decode(&r.bytes).unwrap();
    let mut m = s.selected.unwrap();
    m.health_version = 2;
    m.health_contract = health;
    m.abi = ev_userspace_contract::root_v4::ABI;
    s.selected = Some(m);
    rows[first] = replace_system(&rows[first], &build, s);
    let last = rows
        .iter()
        .rposition(|l| l.starts_with("EVROSION_NATIVE_SYSTEM "))
        .unwrap();
    let crate::native_diagnostics::Event::Report(r) =
        crate::native_diagnostics::parse(&rows[last], &build, last).unwrap()
    else {
        unreachable!()
    };
    let mut s = Snapshot::decode(&r.bytes).unwrap();
    let mut a = s.current.unwrap();
    a.manifest = ev_root_supervisor::native_plan::system::manifest_digest(&manifest(m).unwrap());
    let crate::native3_protocol::Event::Common(c) = crate::native3_protocol::event_network(
        rows.iter()
            .find(|l| l.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX"))
            .unwrap(),
        &build,
    )
    .unwrap() else {
        unreachable!()
    };
    let app = crate::downloaded_protocol::line(
        rows.iter().find(|l| l.contains(" action=start ")).unwrap(),
        &build,
    )
    .unwrap();
    let mut h = Sha256::new();
    h.update(b"evrosion.V4.downloaded-cohort.actual-admission.v2\0");
    h.update(2u16.to_le_bytes());
    h.update(m.health_contract);
    for d in [
        m.cohort,
        digest(&c.root_manifest).unwrap(),
        digest(&c.root_image).unwrap(),
        digest(&app.elf_sha256).unwrap(),
    ] {
        h.update(d);
    }
    for n in [
        m.generation,
        a.boot_serial,
        c.root_epoch,
        c.root_incarnation,
        c.root_process,
        c.root_thread,
        app.process,
        app.thread,
    ] {
        h.update(n.to_le_bytes());
    }
    a.process_stamp = h.finalize().into();
    s.current = Some(a);
    rows[last] = replace_system(&rows[last], &build, s);
    let p = rows
        .iter()
        .position(|l| l.starts_with(PHASE) && l.contains(" phase=3 "))
        .unwrap();
    rows.insert(p,format!("{PHASE} protocol=1 build={build} phase=9 wire=7 tick=25489 process=8 thread=8 peer_process=1 peer_thread=1 endpoint=36 ticket=2 call_epoch=0 call=0 value=000000010301544e"));
    let end = rows
        .iter()
        .position(|l| l.starts_with(PHASE_COUNTS))
        .unwrap();
    rows[end] = format!(
        "{PHASE_COUNTS} protocol=1 build={build} capacity=16 observed=13 retained=13 overflow=0 closed=true"
    );
    rows.splice(end+1..end+1,[
        format!("{CPU} protocol=1 build={build} phase=9 tick=25489 process=8 thread=8 app_job=9 ticket=2 call_epoch=0 call=0 cpu_valid=true sampled_job=9 app_charged_cpu=17 scheduler_tick=25489 quota=64 period=256 window_start=25480 window_end=25736 consumed=17 reserved=1 remaining=46"),
        format!("{CPU} protocol=1 build={build} phase=3 tick=25521 process=8 thread=8 app_job=9 ticket=2 call_epoch=501 call=5381 cpu_valid=false"),
        format!("{CPU_COUNTS} protocol=1 build={build} capacity=2 observed=2 retained=2 duplicates=0 overflow=0 closed=true"),
    ]);
    (rows.join("\n") + "\n", build)
}
fn compact() -> (String, String) {
    compact_with_health(
        Sha256::digest(ev_root_supervisor::downloaded_health::HEALTH_DESCRIPTION).into(),
    )
}
#[test]
fn actual_closed_fault06_uses_global_reports_and_c_generation3_in_physical_slot1() {
    assert_eq!(FAULT06.len(), 91066);
    assert_eq!(
        format!("{:x}", Sha256::digest(FAULT06)),
        "f6c2833eb65027f50f2ffe3e0359b4dbb4dad0122e220e0e0ada071f02ca08e0"
    );
    let text = std::str::from_utf8(FAULT06).unwrap();
    let b = text
        .lines()
        .find_map(|l| l.strip_prefix("EVROSION_BOOT protocol=1 build="))
        .unwrap();
    let frames: Vec<_> = text
        .lines()
        .filter(|l| {
            l.starts_with("EVROSION_NATIVE_SYSTEM ") || l.starts_with("EVROSION_NATIVE_CRASH ")
        })
        .map(|l| {
            let crate::native_diagnostics::Event::Report(r) =
                crate::native_diagnostics::parse(l, b, 0).unwrap()
            else {
                unreachable!()
            };
            (r.kind, r.serial, r.origin)
        })
        .collect();
    assert_eq!(frames.iter().map(|r| r.1).collect::<Vec<_>>(), [1, 2, 3]);
    assert!(frames.iter().all(|r| r.2 == (1, 1)));
    assert_eq!(frames[1].0, crate::native_diagnostics::Kind::Crash);
    let actions = crate::downloaded_protocol::records(FAULT06, b, true).unwrap();
    assert_eq!(actions[0].slot, 1);
    let r = record(FAULT06, b).unwrap().unwrap();
    assert_eq!(r.lines.len(), 2); // Honest zero event/CPU samples with both footers.
    let body = crate::session_protocol::without_network_diagnostics(FAULT06, b).unwrap();
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("EVROSION_NATIVE_CRASH ")
    );
    let native = crate::native_protocol::record_network(FAULT06, b).unwrap();
    assert_eq!(
        (
            native.counts["faults"],
            native.counts["calls"],
            native.counts["replies"]
        ),
        (1, 18588, 18588)
    );
    // This exercises the corrected whole-parser wiring using a supplied exit
    // status for replay. It never rewrites the failed original run or disk.
    crate::boot_protocol::check_network(&body, b, Some(33)).unwrap();
}
#[test]
fn managed_downloaded_fault_needs_every_actual_binding_and_preserves_legacy_grammar() {
    let text = std::str::from_utf8(FAULT06).unwrap();
    let b = text
        .lines()
        .find_map(|l| l.strip_prefix("EVROSION_BOOT protocol=1 build="))
        .unwrap();
    let row = |prefix: &str| text.lines().find(|l| l.starts_with(prefix)).unwrap();
    let life = row("EVROSION_M4_DESKTOP_LIFECYCLE ");
    assert!(crate::desktop_protocol::lifecycle_syntax(life, b).is_err());
    assert!(crate::desktop_protocol::initial_native_shell_fault_line(life, b).is_err());
    assert_eq!(downloaded_fault_line(FAULT06, b).unwrap(), Some(203));
    let registration = text
        .lines()
        .find(|l| l.starts_with("EVROSION_M6_IMAGE ") && l.contains("op=6 slot=1 phase=4 "))
        .unwrap();
    let fault = row("EVROSION_NATIVE_FAULT ");
    let crash = row("EVROSION_NATIVE_CRASH ");
    let frame = row("EVROSION_M4_DESKTOP_STEP ");
    let mut bad = vec![
        (
            "actor",
            text.replace(life, &life.replace("actor=app", "actor=shell")),
        ),
        (
            "process",
            text.replace(life, &life.replace("process=8 ", "process=7 ")),
        ),
        (
            "thread",
            text.replace(life, &life.replace("thread=8 ", "thread=7 ")),
        ),
        (
            "grants",
            text.replace(life, &life.replace("grants=0", "grants=2")),
        ),
        (
            "replacement",
            text.replace(life, &life.replace("replacement=0", "replacement=10")),
        ),
        (
            "vector",
            text.replace(life, &life.replace("vector=6", "vector=14")),
        ),
        ("missing lifecycle", text.replace(life, "")),
        (
            "replayed lifecycle",
            text.replace(life, &format!("{life}\n{life}")),
        ),
        (
            "mode",
            text.replace(" mode=1 root_process=", " mode=0 root_process="),
        ),
        (
            "consistent foreign report origin",
            text.replace(
                "root_process=1 root_thread=1 bytes=",
                "root_process=2 root_thread=2 bytes=",
            ),
        ),
        ("missing registration", text.replace(registration, "")),
        (
            "replayed registration",
            text.replace(registration, &format!("{registration}\n{registration}")),
        ),
        (
            "wrong slot",
            text.replacen("action=start slot=1", "action=start slot=2", 1),
        ),
        ("missing fault", text.replace(fault, "")),
        (
            "fault actor",
            text.replace(fault, &fault.replace("actor=5", "actor=1")),
        ),
        (
            "fault image",
            text.replace(
                fault,
                &fault.replace("image_sha256=adb3", "image_sha256=adb4"),
            ),
        ),
        ("missing capsule", text.replace(crash, "")),
        ("missing frame", text.replace(frame, "")),
        (
            "foreign Display",
            text.replace(
                frame,
                &frame.replace("display_process=3", "display_process=4"),
            ),
        ),
        (
            "foreign Shell",
            text.replace(frame, &frame.replace("shell_process=9", "shell_process=10")),
        ),
    ];
    let terminal = text
        .lines()
        .rfind(|l| l.starts_with("EVROSION_NATIVE_SYSTEM "))
        .unwrap();
    let crate::native_diagnostics::Event::Report(r) =
        crate::native_diagnostics::parse(terminal, b, 0).unwrap()
    else {
        unreachable!()
    };
    let s = Snapshot::decode(&r.bytes).unwrap();
    for (label, mutate) in [
        ("phase", 0),
        ("generation", 1),
        ("stamp", 2),
        ("failure", 3),
        ("serial", 4),
    ] {
        let mut changed = s;
        match mutate {
            0 => changed.current.as_mut().unwrap().phase = Phase::Healthy,
            1 => changed.current.as_mut().unwrap().generation = 2,
            2 => changed.current.as_mut().unwrap().process_stamp[0] ^= 1,
            3 => changed.last_failure.as_mut().unwrap().reason = 2,
            4 => changed.last_failure.as_mut().unwrap().boot_serial += 1,
            _ => unreachable!(),
        }
        bad.push((
            label,
            text.replace(terminal, &replace_system(terminal, b, changed)),
        ));
    }
    let crate::native_diagnostics::Event::Report(r) =
        crate::native_diagnostics::parse(crash, b, 0).unwrap()
    else {
        unreachable!()
    };
    let c = ev_diagnostics::Crash::decode(&r.bytes).unwrap();
    for (label, part) in [
        ("hash-valid foreign package", 0),
        ("hash-valid foreign AppId", 1),
        ("hash-valid foreign generation", 2),
        ("hash-valid foreign capture", 3),
    ] {
        let mut provenance = c.provenance();
        let mut capture = c.capture();
        match part {
            0 => provenance.package.as_mut().unwrap()[0] ^= 1,
            1 => {
                provenance.component =
                    ev_diagnostics::Component::Application(ev_zion::AppId::new([1; 16]).unwrap())
            }
            2 => provenance.generation.as_mut().unwrap()[0] ^= 1,
            3 => capture.registers[0] ^= 1,
            _ => unreachable!(),
        }
        let changed = ev_diagnostics::Crash::new(provenance, capture)
            .unwrap()
            .encode();
        let forged = crash.replace(
            crash.split("bytes=").nth(1).unwrap(),
            &changed
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        );
        bad.push((label, text.replace(crash, &forged)));
    }
    for (label, bad) in bad {
        assert_ne!(bad, text, "mutant must change {label}");
        assert!(downloaded_fault_line(bad.as_bytes(), b).is_err(), "{label}");
        assert!(
            crate::session_protocol::without_network_diagnostics(bad.as_bytes(), b)
                .and_then(|body| crate::boot_protocol::check_network(&body, b, Some(33)))
                .is_err(),
            "whole parser {label}"
        );
    }
}
#[test]
fn mixed_report_gaps_replays_foreign_origins_and_invalid_capsules_still_refuse() {
    let text = std::str::from_utf8(FAULT06).unwrap();
    let b = text
        .lines()
        .find_map(|l| l.strip_prefix("EVROSION_BOOT protocol=1 build="))
        .unwrap();
    let crash = text
        .lines()
        .find(|l| l.starts_with("EVROSION_NATIVE_CRASH "))
        .unwrap();
    for bad in [
        text.replace(crash, ""),
        text.replace(crash, &format!("{crash}\n{crash}")),
        text.replace(crash, &crash.replace("report=2", "report=4")),
        text.replace(crash, &crash.replace("root_process=1", "root_process=2")),
        text.replace(crash, &crash.replace("root_thread=1", "root_thread=2")),
        text.replace(crash, &crash.replace("bytes=4556", "bytes=4557")),
        text.replace(crash, &crash[..crash.len() - 2]),
        text.replace("EVROSION_NATIVE_CRASH ", "EVROSION_NATIVE_UNVALIDATED "),
        text.replace("report=3 root_process=1", "report=2 root_process=1"),
    ] {
        assert!(record(bad.as_bytes(), b).is_err());
        assert!(crate::session_protocol::without_network_diagnostics(bad.as_bytes(), b).is_err());
        assert!(
            crate::session_protocol::without_network_diagnostics(bad.as_bytes(), b)
                .and_then(|body| crate::boot_protocol::check_network(&body, b, Some(33)))
                .is_err()
        );
    }
}
#[test]
fn registered_physical_slot2_does_not_relabel_current_b_generation() {
    let (s, b) = compact();
    let moved = s
        .lines()
        .map(|l| {
            if l.starts_with("EVROSION_M6_IMAGE ")
                || l.starts_with("EVROSION_M6_DOWNLOADED_ACTION ")
            {
                l.replace(" slot=1 ", " slot=2 ")
            } else {
                l.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    record(moved.as_bytes(), &b).unwrap().unwrap();
    let stale_slot = moved.replacen("action=start slot=2", "action=start slot=1", 1);
    assert!(record(stale_slot.as_bytes(), &b).is_err());
    // Stamp/manifest joins remain exact even when both physical slots are legal.
    let mut rows: Vec<_> = moved.lines().map(str::to_owned).collect();
    let at = rows
        .iter()
        .rposition(|l| l.starts_with("EVROSION_NATIVE_SYSTEM "))
        .unwrap();
    let crate::native_diagnostics::Event::Report(r) =
        crate::native_diagnostics::parse(&rows[at], &b, at).unwrap()
    else {
        unreachable!()
    };
    let mut snapshot = Snapshot::decode(&r.bytes).unwrap();
    snapshot.current.as_mut().unwrap().process_stamp[0] ^= 1;
    rows[at] = replace_system(&rows[at], &b, snapshot);
    assert!(record((rows.join("\n") + "\n").as_bytes(), &b).is_err());
}
#[test]
fn actual_failed05_is_explicit_audit_only_and_keeps_failed_admission() {
    assert_eq!(OLD.len(), 79862);
    assert_eq!(
        format!("{:x}", Sha256::digest(OLD)),
        "ca610ecb021df147662735928dc5668480e4f0026ae134e2dc9be2de948fec59"
    );
    let b = build();
    let record = record_layout(OLD, &b, Layout::Legacy05).unwrap().unwrap();
    assert_eq!(record.lines.len(), 13);
    assert!(super::record(OLD, &b).is_err());
    assert!(crate::session_protocol::without_network_diagnostics(OLD, &b).is_err());
    let mut failed = false;
    for (at, l) in std::str::from_utf8(OLD).unwrap().lines().enumerate() {
        if l.starts_with("EVROSION_NATIVE_SYSTEM") {
            let crate::native_diagnostics::Event::Report(r) =
                crate::native_diagnostics::parse(l, &b, at).unwrap()
            else {
                unreachable!()
            };
            let s = Snapshot::decode(&r.bytes).unwrap();
            if let Some(a) = s.current {
                assert_eq!(a.phase, Phase::Failed);
                assert_eq!(s.known_good, None);
                failed = true;
            }
        }
    }
    assert!(failed);
    assert!(crate::boot_protocol::check_network(OLD, &b, Some(35)).is_err());
}
#[test]
fn compact_positive_consumers_project_only_exact_validated_rows() {
    let (s, b) = compact();
    let r = record(s.as_bytes(), &b).unwrap().unwrap();
    assert_eq!(r.lines.len(), 17);
    let body = crate::session_protocol::without_network_diagnostics(s.as_bytes(), &b).unwrap();
    assert!(!std::str::from_utf8(&body).unwrap().contains(PREFIX));
    // It remains the original failed/incomplete boot, with no final retirement.
    assert!(crate::native_protocol::record_network(s.as_bytes(), &b).is_err());
    assert!(crate::boot_protocol::check_network(s.as_bytes(), &b, Some(33)).is_err());
    assert!(crate::boot_protocol::check_network(&body, &b, Some(33)).is_err());
    for (at, line) in s.lines().enumerate() {
        if !r.contains_line(at) && !line.starts_with("EVROSION_M6_") {
            assert!(
                std::str::from_utf8(&body)
                    .unwrap()
                    .lines()
                    .any(|l| l == line)
            );
        }
    }
}
#[test]
fn rejects_scope_subject_root_build_and_closed_replays() {
    let (s, b) = compact();
    let phase = s
        .lines()
        .find(|l| l.starts_with(&format!("{PHASE} ")))
        .unwrap();
    let common = s
        .lines()
        .find(|l| l.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX"))
        .unwrap();
    let terminal = s
        .lines()
        .find(|l| l.starts_with("EVROSION_NATIVE_SYSTEM") && l.contains("report=2"))
        .unwrap();
    for bad in [
        s.replace(" mode=1 ", " mode=0 "),
        s.replace(" mode=1 ", " mode=2 "),
        s.replace(
            "phase=9 wire=7 tick=25489 process=8",
            "phase=9 wire=7 tick=25489 process=9",
        ),
        s.replace(
            "peer_process=1 peer_thread=1 endpoint=36",
            "peer_process=2 peer_thread=2 endpoint=36",
        ),
        s.replace("app_job=9 ticket=2", "app_job=10 ticket=2"),
        s.replace(phase, &phase.replace(&b, &"b".repeat(64))),
        s.clone() + phase + "\n",
        s.replace(common, &format!("{common}\n{common}")),
        s.replace(terminal, &format!("{terminal}\n{terminal}")),
    ] {
        assert!(record(bad.as_bytes(), &b).is_err(), "accepted mutation");
        assert!(crate::session_protocol::without_network_diagnostics(bad.as_bytes(), &b).is_err());
    }
}
#[test]
fn rejects_bad_shape_token_call_tick_and_cpu_accounting() {
    let (s, b) = compact();
    for (from, to) in [
        ("phase=9 wire=7", "phase=9 wire=15"),
        ("value=000000010301544e", "value=000000010302544e"),
        ("phase=4 wire=0 tick=25522", "phase=4 wire=0 tick=25520"),
        (
            "call_epoch=501 call=5381 value",
            "call_epoch=501 call=5382 value",
        ),
        ("phase=5 wire=0", "phase=6 wire=0"),
        (
            "wire=0 tick=25522 process=8 thread=8 peer_process=3 peer_thread=3",
            "wire=0 tick=25522 process=8 thread=8 peer_process=3 peer_thread=4",
        ),
        ("sampled_job=9", "sampled_job=10"),
        ("remaining=46", "remaining=47"),
        ("window_end=25736", "window_end=25735"),
        ("quota=64 period=256", "quota=257 period=256"),
        ("cpu_valid=false", "cpu_valid=false sampled_job=0"),
        (
            "app_job=9 ticket=2 call_epoch=501",
            "app_job=0 ticket=2 call_epoch=501",
        ),
        (
            "phase=3 tick=25521 process=8 thread=8 app_job=9 ticket=2",
            "phase=3 tick=25521 process=8 thread=8 app_job=9 ticket=3",
        ),
        ("capacity=2 observed=2", "capacity=2 observed=3"),
        ("retained=13 overflow=0", "retained=12 overflow=0"),
        (
            "cpu_valid=true sampled_job",
            "cpu_valid=unknown sampled_job",
        ),
    ] {
        let bad = s.replace(from, to);
        assert_ne!(bad, s, "missing test needle");
        assert!(
            record(bad.as_bytes(), &b).is_err(),
            "accepted {from} -> {to}"
        );
    }
}
#[test]
fn requires_both_footers_and_rejects_interruption_extra_keys_and_postclose_cpu() {
    let (s, b) = compact();
    let footer = s.lines().find(|l| l.starts_with(CPU_COUNTS)).unwrap();
    let phase_footer = s.lines().find(|l| l.starts_with(PHASE_COUNTS)).unwrap();
    let cpu = s
        .lines()
        .find(|l| l.starts_with(&format!("{CPU} ")))
        .unwrap();
    for bad in [
        s.replace(&(footer.to_owned() + "\n"), ""),
        s.replace(&(phase_footer.to_owned() + "\n"), ""),
        s.replace(phase_footer, &format!("{phase_footer}\n{phase_footer}")),
        s.replace(cpu, &format!("unrelated\n{cpu}")),
        s.replace(cpu, &format!("{cpu} unknown=0")),
        s.clone() + cpu + "\n",
        s.clone() + footer + "\n",
        s[..s.find(footer).unwrap()].to_owned(),
        s.trim_end_matches('\n').to_owned(),
    ] {
        assert!(record(bad.as_bytes(), &b).is_err());
    }
}
#[test]
fn zero_samples_are_explicit_unknown_and_later_selection_does_not_rebind_current() {
    let (s, b) = compact();
    let mut empty = String::new();
    for line in s.lines() {
        if line.starts_with(&format!("{CPU} ")) || line.starts_with(&format!("{PHASE} ")) {
            continue;
        }
        let line = line
            .replace(
                "capacity=16 observed=13 retained=13",
                "capacity=16 observed=0 retained=0",
            )
            .replace(
                "capacity=2 observed=2 retained=2",
                "capacity=2 observed=0 retained=0",
            );
        empty += &line;
        empty.push('\n');
    }
    assert_eq!(
        record(empty.as_bytes(), &b).unwrap().unwrap().lines.len(),
        2
    );
    let first = s
        .lines()
        .find(|l| l.starts_with("EVROSION_NATIVE_SYSTEM"))
        .unwrap();
    let crate::native_diagnostics::Event::Report(r) =
        crate::native_diagnostics::parse(first, &b, 0).unwrap()
    else {
        unreachable!()
    };
    let mut later = Snapshot::decode(&r.bytes).unwrap();
    later.selected.as_mut().unwrap().generation = 3;
    let later = replace_system(&first.replace("report=1", "report=3"), &b, later);
    assert!(record((s + &later + "\n").as_bytes(), &b).is_ok());
}

/// Fully synthetic CLOSED current Network grammar, including real parser
/// mechanism fixture scaffolding. It proves consumer wiring, never VM health.
fn closed_compact() -> (String, String) {
    let (mut out, b) = compact();
    // Preserve context through genuine downloaded reap; discard later live
    // observation-only details from the failed-prefix fixture.
    let end = out.find("EVROSION_M6_DOWNLOADED_ACTION").unwrap();
    let end = out[end..].find("action=reap").unwrap() + end;
    let end = out[end..].find('\n').unwrap() + end + 1;
    out.truncate(end);
    let state = out
        .lines()
        .find(|l| l.starts_with("EVROSION_NATIVE_STATE "))
        .unwrap()
        .to_owned();
    out += &state.replace("report=1 op=open", "report=2 op=finish");
    out.push('\n');
    for (i, p, t, j) in [
        (0, 1, 1, 2),
        (1, 9, 9, 10),
        (2, 5, 5, 6),
        (3, 4, 4, 5),
        (4, 2, 2, 3),
        (5, 8, 8, 9),
        (6, 3, 3, 4),
        (7, 6, 6, 7),
        (8, 7, 7, 8),
    ] {
        out += &format!(
            "EVROSION_M5_NATIVE_PROFILE protocol=1 build={b} phase=finished scope=actor_slot index={i} current_process={p} current_thread={t} current_job={j} incarnations=1 elapsed_ticks=30000 captures=11 syscalls=10 irqs=1 faults=0 port_in=1 port_out=1 yields=1 continuations=1 charged_cpu_ticks=1 current_job_cpu_ticks=1 cpu_scope=subtree\n"
        );
    }
    out += &format!(
        "EVROSION_M6_UI_COUNTS protocol=1 build={b} phase=finished barriers=1 cursors=1 note_requests=1 note_accepted=1 note_delivered=1\n"
    );
    let padding = out
        .lines()
        .find(|l| l.starts_with("EVROSION_M6_WINDOW_PADDING "))
        .unwrap()
        .to_owned();
    out += &padding;
    out.push('\n');
    let before = out
        .lines()
        .find(|l| l.starts_with("EVROSION_M5_NATIVE_MEMORY "))
        .unwrap()
        .to_owned();
    let total = before
        .split(' ')
        .find_map(|f| f.strip_prefix("total_frames="))
        .unwrap();
    let remaining: u64 = before
        .split(' ')
        .find_map(|f| f.strip_prefix("remaining_frames="))
        .unwrap()
        .parse()
        .unwrap();
    out += &format!(
        "EVROSION_M5_NATIVE_MEMORY protocol=1 build={b} phase=held total_frames={total} remaining_frames={}\n",
        remaining - 1
    );
    out += &before.replace("phase=before", "phase=after");
    out.push('\n');
    out += &format!(
        "EVROSION_M6_LOG protocol=1 build={b} observed=0 retained=0 omitted=0 detail_bytes=0 final_bytes=0 omitted_bytes=0 prefix_closed=false\n"
    );
    let generic = include_str!("../../../tests/fixtures/m6-session-exercise-parser.serial");
    let rows: Vec<_> = generic.lines().collect();
    let i = rows
        .iter()
        .position(|l| l.starts_with("EVROSION_M5_NATIVE "))
        .unwrap();
    let old_build = rows[i]
        .split(' ')
        .find_map(|f| f.strip_prefix("build="))
        .unwrap();
    let summary = rows[i]
        .replace(old_build, &b)
        .replace(
            "faults=2 restarts=2 grants=1",
            "faults=0 restarts=0 grants=0",
        )
        .replace("app_a_starts=2", "app_a_starts=0")
        .replace("app_a_stops=2", "app_a_stops=0")
        .replace("app_a_reaps=2", "app_a_reaps=0")
        .replace("app_a_process=263", "app_a_process=0")
        .replace("app_a_thread=263", "app_a_thread=0");
    out += &summary;
    out.push('\n');
    for row in &rows[i + 1..] {
        out += &row.replace(old_build, &b);
        out.push('\n');
    }
    (out, b)
}
#[test]
fn closed_current_compact_runs_strict_network_normalizer_native_and_boot_consumers() {
    let (s, b) = closed_compact();
    record(s.as_bytes(), &b).unwrap().unwrap();
    crate::native_protocol::record_network(s.as_bytes(), &b).unwrap();
    let body = crate::session_protocol::without_network_diagnostics(s.as_bytes(), &b).unwrap();
    crate::boot_protocol::check_network(&body, &b, Some(33)).unwrap();
    // The boot consumer independently checks raw diagnostic indices before its
    // existing stricter non-startup UI/RPC grammar is projected by its caller.
    for bad in [
        s.replace(
            "closed=true\nEVROSION_M6_STARTUP_CPU ",
            "closed=false\nEVROSION_M6_STARTUP_CPU ",
        ),
        s.replace(" mode=1 ", " mode=0 "),
        s.replace(
            "capacity=2 observed=2 retained=2",
            "capacity=2 observed=2 retained=1",
        ),
    ] {
        assert!(crate::boot_protocol::check_network(bad.as_bytes(), &b, Some(33)).is_err());
        assert!(crate::session_protocol::without_network_diagnostics(bad.as_bytes(), &b).is_err());
    }
}

#[test]
fn capped_prefix_keeps_cpu_samples_independent_and_requires_actual_note_and_epoch() {
    let (s, b) = compact();
    let mut rows = Vec::new();
    for line in s.lines() {
        if line.starts_with(&format!("{PHASE} ")) {
            continue;
        }
        if line.starts_with(PHASE_COUNTS) {
            for i in 0..16 {
                rows.push(format!("{PHASE} protocol=1 build={b} phase=1 wire=15 tick={} process=8 thread=8 peer_process=1 peer_thread=1 endpoint=7 ticket={} call_epoch=0 call=0 value=3159445241475645",25472+i,300+i));
            }
            rows.push(format!("{PHASE_COUNTS} protocol=1 build={b} capacity=16 observed=29 retained=16 overflow=13 closed=true"));
        } else {
            rows.push(line.to_owned());
        }
    }
    let capped = rows.join("\n") + "\n";
    assert!(record(capped.as_bytes(), &b).is_ok());
    // Saturation is the producer's declared count operation, not wrapping math.
    assert!(
        record(
            capped
                .replace(
                    "observed=29 retained=16 overflow=13",
                    "observed=18446744073709551615 retained=16 overflow=18446744073709551615"
                )
                .as_bytes(),
            &b
        )
        .is_ok()
    );
    for bad in [
        capped.replace(
            "phase=9 tick=25489 process=8 thread=8 app_job=9 ticket=2",
            "phase=9 tick=25489 process=8 thread=8 app_job=9 ticket=3",
        ),
        capped.replace(
            "app_job=9 ticket=2 call_epoch=501",
            "app_job=9 ticket=2 call_epoch=502",
        ),
        capped.replace(
            "observed=29 retained=16 overflow=13",
            "observed=16 retained=16 overflow=0",
        ),
    ] {
        assert!(record(bad.as_bytes(), &b).is_err());
    }
}

#[test]
fn preceding_current_healthy_b_is_bound_even_when_next_selection_is_c() {
    let (s, b) = compact();
    let mut rows: Vec<String> = s.lines().map(str::to_owned).collect();
    let at = rows
        .iter()
        .position(|l| l.starts_with("EVROSION_NATIVE_SYSTEM") && l.contains("report=2"))
        .unwrap();
    let crate::native_diagnostics::Event::Report(r) =
        crate::native_diagnostics::parse(&rows[at], &b, at).unwrap()
    else {
        unreachable!()
    };
    let mut terminal = Snapshot::decode(&r.bytes).unwrap();
    let first = rows
        .iter()
        .find(|l| l.starts_with("EVROSION_NATIVE_SYSTEM") && l.contains("report=1"))
        .unwrap();
    let crate::native_diagnostics::Event::Report(r) =
        crate::native_diagnostics::parse(first, &b, 0).unwrap()
    else {
        unreachable!()
    };
    let mut next = Snapshot::decode(&r.bytes).unwrap().selected.unwrap();
    next.generation = 3;
    next.cohort = [0x42; 32];
    terminal.state = ev_diagnostics::system::State::Committed;
    terminal.current.as_mut().unwrap().phase = Phase::Healthy;
    terminal.selected = Some(next);
    terminal.known_good = Some(2);
    rows[at] = replace_system(&rows[at], &b, terminal);
    let changed = rows.join("\n") + "\n";
    record(changed.as_bytes(), &b).unwrap().unwrap();
    let mut foreign = terminal;
    foreign.current.as_mut().unwrap().process_stamp[0] ^= 1;
    rows[at] = replace_system(&rows[at], &b, foreign);
    assert!(record((rows.join("\n") + "\n").as_bytes(), &b).is_err());
}
#[test]
fn ordinary_session_standalone_and_recovery_cannot_accept_current_startup_rows() {
    let (s, b) = closed_compact();
    assert!(crate::session_protocol::without_diagnostics(s.as_bytes(), &b).is_err());
    assert!(crate::boot_protocol::check_session(s.as_bytes(), &b, Some(33)).is_err());
    assert!(crate::boot_protocol::check_network_recovery(s.as_bytes(), &b, Some(33)).is_err());
    let body = crate::session_protocol::without_network_diagnostics(s.as_bytes(), &b).unwrap();
    assert!(crate::boot_protocol::check(&body, &b, Some(33)).is_err());
}

#[test]
fn current_health_description_refuses_even_coherent_foreign_manifest_and_stamp() {
    let (s, b) = compact_with_health([0x42; 32]);
    assert!(record(s.as_bytes(), &b).is_err());
    assert!(crate::session_protocol::without_network_diagnostics(s.as_bytes(), &b).is_err());
}
#[test]
fn two_available_cpu_snapshots_preserve_one_job_window_and_lifetime_accounting() {
    let (s, b) = compact();
    let available = "cpu_valid=true sampled_job=9 app_charged_cpu=18 scheduler_tick=25520 quota=64 period=256 window_start=25480 window_end=25736 consumed=18 reserved=0 remaining=46";
    let s = s.replace("cpu_valid=false", available);
    record(s.as_bytes(), &b).unwrap().unwrap();
    for changed in [
        available.replace("scheduler_tick=25520", "scheduler_tick=25522"),
        available.replace("scheduler_tick=25520", "scheduler_tick=25479"),
        available.replace("scheduler_tick=25520", "scheduler_tick=25488"),
        available
            .replace("app_charged_cpu=18", "app_charged_cpu=16")
            .replace("consumed=18", "consumed=16")
            .replace("remaining=46", "remaining=48"),
        available
            .replace("consumed=18", "consumed=16")
            .replace("remaining=46", "remaining=48"),
        available
            .replace("quota=64", "quota=32")
            .replace("remaining=46", "remaining=14"),
        available
            .replace("period=256", "period=128")
            .replace("window_end=25736", "window_end=25608"),
        available.replace(
            "window_start=25480 window_end=25736",
            "window_start=25400 window_end=25656",
        ),
        available.replace(
            "window_start=25480 window_end=25736",
            "window_start=25500 window_end=25756",
        ),
    ] {
        assert!(
            record(s.replace(available, &changed).as_bytes(), &b).is_err(),
            "accepted {changed}"
        );
    }
    // A None endpoint gives no earlier usage/window facts to compare with the
    // later available sample. Zero usage is valid only when actually sampled.
    let first = s
        .lines()
        .find(|l| l.starts_with(&format!("{CPU} ")) && l.contains(" phase=9 "))
        .unwrap();
    let first_none = first.split(" cpu_valid=").next().unwrap().to_owned() + " cpu_valid=false";
    let zero = available
        .replace("app_charged_cpu=18", "app_charged_cpu=0")
        .replace("consumed=18", "consumed=0")
        .replace("remaining=46", "remaining=64");
    let unknown = s.replace(first, &first_none).replace(available, &zero);
    record(unknown.as_bytes(), &b).unwrap().unwrap();
}
