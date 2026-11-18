//! Parser/observer models only; none of these rows claim network execution.
use super::*;
use crate::network_fixture::Exchange;
pub(super) fn build() -> String {
    "a".repeat(64)
}
pub(super) fn context() -> Context {
    Context {
        images: core::array::from_fn(|i| format!("{:064x}", i + 1)),
        root_manifest: "b".repeat(64),
        root_frames: 40,
        block_frames: 20,
        package_pages: [24, 24],
        banks: None,
    }
}
fn common(c: &Context) -> String {
    format!(
        "EVROSION_M5_NATIVE_COMMON_PREFIX protocol=1 build={} mode=0 root_process=1 root_thread=11 root_image_sha256={} root_epoch=501 root_incarnation=1 root_manifest_sha256={} block_process=2 block_thread=12 block_image_sha256={} system_endpoint=31 root_frames=40 block_frames=20\r\n",
        build(),
        c.images[0],
        c.root_manifest,
        c.images[4]
    )
}
fn row(stage: u64, result: u64, argument: u64) -> String {
    format!(
        "EVROSION_M6_NETWORK_PROGRESS protocol=1 build={} root_process=1 root_thread=11 endpoint=7 ticket={} tick={} stage={stage} result={result} argument={argument}\r\n",
        build(),
        100 + stage,
        1000 + stage
    )
}
fn time_row(ticket: u64, stage: u64, result: u64, elapsed: u64) -> String {
    format!(
        "EVROSION_M6_TIME_PROGRESS protocol=1 build={} root_process=1 root_thread=11 endpoint=7 ticket={ticket} tick={} stage={stage} result={result} elapsed_seconds={elapsed}\r\n",
        build(),
        ticket + 1000
    )
}
pub(super) fn ready(c: &Context) -> String {
    let mut text = common(c);
    text.push_str(&format!("EVROSION_M5_NATIVE_CRITICAL_READY protocol=1 build={} process=6 thread=16 image_sha256={} tick=900\r\n",build(),c.images[1]));
    let reference =
        crate::session_reference::Reference::new(ev_graphics::shell::Screen::Home, None, None)
            .unwrap();
    let surface = reference.surface_hash(Producer::Shell, 1).unwrap();
    text.push_str(&format!("EVROSION_M4_DESKTOP_STEP protocol=1 build={} step=frame frame=1 width=1280 height=800 app_process=0 shell_process=6 display_process=3 grants=0 producer=shell surface_sha256={surface} held_ticks=0\r\n",build()));
    text.push_str(&time_row(200, 1, 0, 0));
    text.push_str(&time_row(201, 2, 0, 1));
    for (i, argument) in [1, 0x0f02000a, 0x01020304, 8080, REQUEST.len() as u64, 28]
        .into_iter()
        .enumerate()
    {
        text.push_str(&row(i as u64 + 1, 0, argument));
    }
    text
}
pub(super) fn exchange() -> Snapshot {
    let response=[format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",crate::network_fixture::HELLO.len()).as_bytes(),crate::network_fixture::HELLO].concat();
    Snapshot {
        observed: 1,
        completed: 1,
        omitted: 0,
        exchanges: vec![Exchange {
            request: REQUEST.to_vec(),
            response,
            error: None,
            mutation: None,
        }],
    }
}
#[test]
fn nw6_is_readiness_only_and_needs_the_exact_actual_host_exchange() {
    let c = context();
    let text = ready(&c);
    assert!(facts(&c, text.as_bytes(), &build(), false).unwrap().ready);
    assert!(!fixture_complete(&Snapshot::default()).unwrap());
    assert!(fixture_complete(&exchange()).unwrap());
}
#[test]
fn partial_serial_cannot_publish_nw6_or_request_finish() {
    let c = context();
    let text = ready(&c);
    let partial = &text[..text.len() - 1];
    let f = facts(&c, partial.as_bytes(), &build(), false).unwrap();
    assert_eq!(f.stages.len(), 5);
    assert!(!f.ready);
}
#[test]
fn wrong_source_missing_stages_replay_and_false_request_lengths_refuse() {
    let c = context();
    let text = ready(&c);
    let cases = [
        text.replace(&row(2, 0, 0x0f02000a), ""),
        text.replace(&row(4, 0, 8080), &row(4, 0, 8080).repeat(2)),
        text.replace(
            "root_process=1 root_thread=11 endpoint=7",
            "root_process=2 root_thread=12 endpoint=7",
        ),
        text.replace(&row(5, 0, REQUEST.len() as u64), &row(5, 0, 1)),
        text.replace(&c.root_manifest, &"c".repeat(64)),
        text.replace("root_frames=40", "root_frames=41"),
        text.replace(&c.images[1], &"d".repeat(64)),
        text.replace(&build(), &"e".repeat(64)),
        text.replace("app_process=0", "app_process=7"),
        text.replace("grants=0", "grants=1"),
    ];
    for (i, bad) in cases.iter().enumerate() {
        assert!(
            facts(&c, bad.as_bytes(), &build(), false).is_err(),
            "case{i}"
        );
    }
}
#[test]
fn failure_keeps_uncertainty_and_shutdown_cannot_precede_owner_finish() {
    let c = context();
    let mut text = ready(&c);
    text.push_str(&row(8, 3, 6));
    let f = facts(&c, text.as_bytes(), &build(), false).unwrap();
    assert!(!f.ready);
    assert!(f.failure.is_some());
    let text = ready(&c) + &row(7, 0, 2);
    assert!(facts(&c, text.as_bytes(), &build(), false).is_err());
    let f = facts(&c, text.as_bytes(), &build(), true).unwrap();
    assert!(f.ready);
    assert_eq!(f.stages.len(), 7);
}
#[test]
fn exact_socket_bytes_and_complete_ledger_are_required() {
    let good = exchange();
    assert!(fixture_complete(&good).unwrap());
    let mut cases = Vec::new();
    let mut bad = good.clone();
    bad.exchanges[0].request.push(b'x');
    cases.push(bad);
    let mut bad = good.clone();
    bad.exchanges[0].response.pop();
    cases.push(bad);
    let mut bad = good.clone();
    bad.exchanges[0].error = Some("lost write".into());
    cases.push(bad);
    let mut bad = good.clone();
    bad.omitted = 1;
    cases.push(bad);
    let mut bad = good.clone();
    bad.completed = 0;
    cases.push(bad);
    let mut bad = good.clone();
    bad.observed = 2;
    cases.push(bad);
    let bad = Snapshot {
        exchanges: good.exchanges,
        ..Snapshot::default()
    };
    cases.push(bad);
    for bad in cases {
        assert!(fixture_complete(&bad).is_err());
    }
}
#[test]
fn root_labels_and_successful_host_socket_alone_never_establish_retirement() {
    use std::os::unix::process::ExitStatusExt;
    let c = context();
    let text = ready(&c) + &row(7, 0, 2);
    assert!(
        finished(
            &c,
            text.as_bytes(),
            &build(),
            ExitStatus::from_raw(33 << 8),
            true,
            &exchange(),
            Goal::Hello,
            false,
            &time_pause::State::default(),
            &namespace_probe::State::default(),
            &time_refresh::State::default(),
        )
        .is_err()
    );
    assert!(
        finished(
            &c,
            text.as_bytes(),
            &build(),
            ExitStatus::from_raw(35 << 8),
            true,
            &exchange(),
            Goal::Hello,
            false,
            &time_pause::State::default(),
            &namespace_probe::State::default(),
            &time_refresh::State::default(),
        )
        .is_err()
    );
}
#[test]
fn public_probe_and_manual_workflows_remain_separate() {
    use crate::cli::{self, Cli};
    use std::ffi::OsString;
    for (words, expected) in [
        (vec!["network"], "network-session"),
        (vec!["test", "network-probe"], "network-probe"),
        (vec!["test", "time-probe"], "time-probe"),
        (vec!["test", "time-pause-probe"], "time-pause-probe"),
        (vec!["test", "time-refresh-probe"], "time-refresh-probe"),
        (vec!["test", "time-corrupt-probe"], "time-corrupt-probe"),
        (
            vec!["test", "entropy-missing-probe"],
            "entropy-missing-probe",
        ),
        (
            vec!["test", "update-namespace-probe"],
            "update-namespace-probe",
        ),
    ] {
        let parsed = cli::parse(words.into_iter().map(OsString::from)).unwrap();
        assert!(matches!(parsed,Cli::Workflow(name) if name==expected));
    }
}

#[test]
fn absent_entropy_is_an_explicit_refusal_goal_and_requires_actual_shutdown() {
    let c = context();
    let positive = ready(&c);
    let initial = positive
        .lines()
        .filter(|l| {
            !l.starts_with("EVROSION_M6_TIME_PROGRESS")
                && !l.starts_with("EVROSION_M6_NETWORK_PROGRESS")
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    assert!(
        !facts_for_goal(
            &c,
            initial.as_bytes(),
            &build(),
            false,
            Goal::MissingEntropy
        )
        .unwrap()
        .ready
    );
    let refused = initial.clone() + &row(8, 1, 1);
    assert!(
        facts_for_goal(
            &c,
            refused.as_bytes(),
            &build(),
            false,
            Goal::MissingEntropy
        )
        .unwrap()
        .ready
    );
    assert!(
        !facts(&c, refused.as_bytes(), &build(), false)
            .unwrap()
            .ready
    );
    for bad in [
        initial.clone() + &row(8, 2, 1),
        initial.clone() + &row(8, 1, 2),
        positive,
        refused.clone() + &time_row(201, 1, 0, 0),
        refused.clone() + &row(8, 1, 1),
        refused.clone() + &row(7, 0, 2),
    ] {
        assert!(facts_for_goal(&c, bad.as_bytes(), &build(), false, Goal::MissingEntropy).is_err());
    }
    // Independent protected ticket/tick ordering must still hold; NW7 is not
    // allowed before the actual owned UART finish publication.
    let shutdown = row(7, 0, 2)
        .replace("ticket=107", "ticket=109")
        .replace("tick=1007", "tick=1009");
    let finished = refused + &shutdown;
    let f = facts_for_goal(
        &c,
        finished.as_bytes(),
        &build(),
        true,
        Goal::MissingEntropy,
    )
    .unwrap();
    assert!(f.ready);
    assert_eq!(f.stages.len(), 2);
}

#[test]
fn network_success_cannot_substitute_for_actual_elapsed_source_progress() {
    let c = context();
    let text = ready(&c);
    let no_sample = text.replace(&time_row(201, 2, 0, 1), "");
    assert!(
        !facts(&c, no_sample.as_bytes(), &build(), false)
            .unwrap()
            .ready
    );
    let zero = text.replace(&time_row(201, 2, 0, 1), &time_row(201, 2, 0, 0));
    assert!(!facts(&c, zero.as_bytes(), &build(), false).unwrap().ready);
    let failed = text + &time_row(202, 3, 2, 1);
    let f = facts(&c, failed.as_bytes(), &build(), false).unwrap();
    assert!(!f.ready);
    assert!(f.failure.is_some());
}
