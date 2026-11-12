//! Independent fixtures for the owner wire protocol. These are parser tests;
//! hardware ownership, durable state and actual UART provenance remain checked
//! by the retained VM/disk evidence.
use super::*;

const BUILD: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const CATALOGUE: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn prompt_fixture() -> String {
    format!(
        "EVROSION_M3_OWNER_PROMPT protocol=1 build={BUILD} catalogue={CATALOGUE} operation=16 selected=3 known_good=1 failure_generation=2 failure_serial=2 deadline=62000 actions=r,q"
    )
}

fn completion(decision: OwnerDecision) -> Completion {
    let continued = decision == OwnerDecision::Continue;
    Completion {
        mode: Mode::OwnerRecover,
        owner_decision: decision,
        booted: u64::from(continued),
        selected: if continued { 1 } else { 3 },
        known_good: 1,
        boot_serial: if continued { 4 } else { 0 },
        process: if continued { 9 } else { 0 },
        thread: if continued { 10 } else { 0 },
        failure_generation: 2,
        failure_serial: 2,
        failure_reason: 1,
        negatives: if continued { 4 } else { 0 },
        mutations: if continued { 22 } else { 0 },
        operation: if continued { 21 } else { 16 },
        sequence: if continued { 22 } else { 17 },
        failure_operation: 10,
        failure_sequence: 11,
        catalogue: [2; 32],
        process_stamp: if continued { [3; 32] } else { [0; 32] },
        storage_probe: [4; 32],
        booted_cohort: if continued { [5; 32] } else { [0; 32] },
    }
}

fn hex_fixture(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn record_fixture(report: Completion, received: &[u8]) -> String {
    let active = u64::from(report.process != 0);
    let calls = if active == 1 { 100 } else { 5 };
    format!(
        "EVROSION_M3_OWNER status=PASS scope=recovery phase=owner-recover decision={} calls={calls} blocks={calls} wakes={calls} replies={calls} mutations={} starts={active} ready={active} critical_ready={active} faults=0 stops={active} reaps={active} forged={} uart_inputs=1000 uart_outputs=900 catalogue=true frames=true metadata=true guards=true report={} uart_rx_before_tx=0 uart_rx={}",
        decision_name(report.owner_decision),
        report.mutations,
        report.negatives,
        hex_fixture(&report.encode()[..256]),
        hex_fixture(received),
    )
}

fn budget_fixture() -> &'static str {
    "EVROSION_M3_OWNER_BUDGET status=PASS elapsed_ticks=600 limit_ticks=65536 driver_cpu=100 controller_cpu=400 critical_cpu=100 parent_cpu=600 parent_limit=131072 transitions=4000 transition_limit=8000000 max_pending=1 accounted=true bounded=true"
}

#[test]
fn prompt_binds_exact_build_catalogue_order_and_finite_deadline() {
    let fixture = prompt_fixture();
    let parsed = prompt_line(&fixture, BUILD, Some(CATALOGUE)).unwrap();
    assert_eq!(parsed.build, BUILD);
    assert_eq!(parsed.catalogue, CATALOGUE);
    assert_eq!(parsed.operation, 16);
    assert_eq!(parsed.deadline, 62000);
    assert!(prompt_line(&fixture, CATALOGUE, Some(CATALOGUE)).is_err());
    assert!(prompt_line(&fixture, BUILD, Some(BUILD)).is_err());
    let mut reordered: Vec<_> = fixture.split(' ').collect();
    reordered.swap(5, 6);
    assert!(prompt_line(&reordered.join(" "), BUILD, Some(CATALOGUE)).is_err());
    for replacement in [
        "deadline=0",
        "deadline=062000",
        "deadline=18446744073709551615",
    ] {
        assert!(
            prompt_line(
                &fixture.replace("deadline=62000", replacement),
                BUILD,
                Some(CATALOGUE)
            )
            .is_err()
        );
    }
    for suffix in [" ", " extra=1", "\n"] {
        assert!(prompt_line(&format!("{fixture}{suffix}"), BUILD, Some(CATALOGUE)).is_err());
    }
}

#[test]
fn prompt_is_not_armed_from_a_partial_or_duplicate_marker() {
    let fixture = prompt_fixture();
    assert!(
        prompt(fixture.as_bytes(), BUILD, CATALOGUE)
            .unwrap()
            .is_none()
    );
    let serial = format!("boot diagnostics\n{fixture}\r\n");
    assert!(
        prompt(serial.as_bytes(), BUILD, CATALOGUE)
            .unwrap()
            .is_some()
    );
    assert!(
        prompt(
            format!("{fixture}\n{fixture}\n").as_bytes(),
            BUILD,
            CATALOGUE
        )
        .is_err()
    );
    assert!(prompt(format!("{fixture}\n{fixture}").as_bytes(), BUILD, CATALOGUE).is_err());
    assert!(prompt(b"\xff\n", BUILD, CATALOGUE).is_err());
    assert!(prompt(&vec![b'x'; 1024 * 1024 + 1], BUILD, CATALOGUE).is_err());
}

#[test]
fn human_explanation_is_ordered_and_cannot_silently_claim_other_failure() {
    let lines = [
        "Evrosion generation 2 could not start: a process fault.".to_owned(),
        format!("Failed image: {}", "ab".repeat(32)),
        "Current selection: generation 3 (pending validation).".to_owned(),
        "Known-good generation 1 is available. Returning keeps your files.".to_owned(),
        "Type r then Enter to continue with known-good, or q then Enter to cancel.".to_owned(),
    ];
    let mut stage = 0;
    for line in &lines {
        stage = ui_line(stage, line, false).unwrap();
    }
    assert_eq!(stage, 5);
    assert_eq!(
        ui_line(stage, "Please type r or q, then Enter.", true).unwrap(),
        5
    );
    assert!(ui_line(5, "Please type r or q, then Enter.", false).is_err());
    assert!(ui_line(0, &lines[1], false).is_err());
    assert!(
        ui_line(
            0,
            "Evrosion generation 2 could not start: missing progress.",
            false
        )
        .is_err()
    );
    assert!(ui_line(1, "Failed image: AB", false).is_err());
}

#[test]
fn uart_requires_a_complete_isolated_command_line() {
    for bytes in [b"r\n".as_slice(), b"R\r", b" \tr\r\n"] {
        assert_eq!(received_choice(bytes), Some(OwnerDecision::Continue));
    }
    for bytes in [b"q\n".as_slice(), b"Q\r", b"\t q\r\n"] {
        assert_eq!(received_choice(bytes), Some(OwnerDecision::Cancel));
    }
    for bytes in [
        b"r".as_slice(),
        b"q",
        b"\tr",
        b"r \n",
        b"r\t\n",
        b"run\n",
        b"\x1br\n",
        b"\x1b[31mr\n",
        b"\0r\n",
        b"qr\n",
        b"\xffr\n",
    ] {
        assert_eq!(received_choice(bytes), None, "{bytes:?}");
    }
    assert_eq!(
        received_choice(b"rubbish\n\x1bq\n q\n"),
        Some(OwnerDecision::Cancel)
    );
    assert_eq!(received_choice(b"q\nr\n"), Some(OwnerDecision::Cancel));
    assert_eq!(received_choice(b"r\nq\n"), Some(OwnerDecision::Continue));
}

#[test]
fn actual_uart_command_must_match_reported_decision() {
    let continued = completion(OwnerDecision::Continue);
    let cancelled = completion(OwnerDecision::Cancel);
    assert_eq!(
        line(&record_fixture(continued, b"r\n")).unwrap().report,
        continued
    );
    assert_eq!(
        line(&record_fixture(cancelled, b"q\n")).unwrap().report,
        cancelled
    );
    for received in [b"r".as_slice(), b"\x1br\n", b"q\n", b""] {
        assert!(line(&record_fixture(continued, received)).is_err());
    }
    for received in [b"q".as_slice(), b"r\n", b"rq\n"] {
        assert!(line(&record_fixture(cancelled, received)).is_err());
    }
    // First valid whole line wins. A later line cannot change the consent.
    assert!(line(&record_fixture(cancelled, b"r\nq\n")).is_err());
}

#[test]
fn stale_uart_drain_is_retained_but_cannot_choose_for_the_fresh_prompt() {
    let cancelled = completion(OwnerDecision::Cancel);
    let fixture =
        record_fixture(cancelled, b"r\nq\n").replace("uart_rx_before_tx=0", "uart_rx_before_tx=2");
    let parsed = line(&fixture).unwrap();
    assert_eq!(parsed.report.owner_decision, OwnerDecision::Cancel);
    assert_eq!(parsed.received, b"r\nq\n");
    // The genuinely submitted suffix must also be complete and valid.
    for received in [b"r\nq".as_slice(), b"r\n\x1bq\n"] {
        let wrong = record_fixture(cancelled, received)
            .replace("uart_rx_before_tx=0", "uart_rx_before_tx=2");
        assert!(line(&wrong).is_err());
    }
    for offset in ["5", "129", "18446744073709551615", "02"] {
        assert!(
            line(&fixture.replace(
                "uart_rx_before_tx=2",
                &format!("uart_rx_before_tx={offset}")
            ))
            .is_err()
        );
    }
    let no_prompt_input = record_fixture(completion(OwnerDecision::Timeout), b"r\n")
        .replace("uart_rx_before_tx=0", "uart_rx_before_tx=2");
    assert!(line(&no_prompt_input).is_ok());
}

#[test]
fn no_action_outcomes_preserve_pending_selection_without_mutations_or_launch() {
    for decision in [
        OwnerDecision::Cancel,
        OwnerDecision::Timeout,
        OwnerDecision::InputFault,
        OwnerDecision::InputBudget,
    ] {
        let report = completion(decision);
        let received = if decision == OwnerDecision::Cancel {
            b"q\n".as_slice()
        } else {
            b"noise\n"
        };
        let parsed = line(&record_fixture(report, received)).unwrap();
        assert_eq!((parsed.report.selected, parsed.report.known_good), (3, 1));
        assert_eq!(
            (
                parsed.report.mutations,
                parsed.report.process,
                parsed.report.thread
            ),
            (0, 0, 0)
        );
        assert_eq!((parsed.report.operation, parsed.report.sequence), (16, 17));
        let mut mutated = report;
        mutated.mutations = 1;
        assert!(line(&record_fixture(mutated, received)).is_err());
        let mut launched = report;
        launched.process = 9;
        assert!(line(&record_fixture(launched, received)).is_err());
    }
    let report = completion(OwnerDecision::Timeout);
    assert!(line(&record_fixture(report, b"r\n")).is_err());
    assert!(line(&record_fixture(report, b"q\n")).is_err());
}

#[test]
fn record_rejects_counter_imbalance_unbounded_uart_and_missing_prompt_output() {
    let fixture = record_fixture(completion(OwnerDecision::Cancel), b"q\n");
    let parsed = line(&fixture).unwrap();
    assert_eq!((parsed.uart_inputs, parsed.uart_outputs), (1000, 900));
    assert_eq!(parsed.received, b"q\n");
    for (old, new) in [
        ("calls=5", "calls=0"),
        ("calls=5", "calls=100001"),
        ("blocks=5", "blocks=4"),
        ("wakes=5", "wakes=6"),
        ("replies=5", "replies=05"),
        ("mutations=0", "mutations=1"),
        ("uart_inputs=1000", "uart_inputs=1"),
        ("uart_inputs=1000", "uart_inputs=8000001"),
        ("uart_outputs=900", "uart_outputs=8000001"),
        ("uart_outputs=900", "uart_outputs=0"),
        ("frames=true", "frames=false"),
        ("guards=true", "guards=false"),
    ] {
        assert!(line(&fixture.replace(old, new)).is_err(), "{old} -> {new}");
    }
    assert!(
        line(&record_fixture(
            completion(OwnerDecision::InputBudget),
            &[b'x'; 129]
        ))
        .is_err()
    );
}

#[test]
fn report_is_canonical_and_original_failure_survives_recovery() {
    let report = completion(OwnerDecision::Continue);
    let fixture = record_fixture(report, b"r\n");
    for change in 0..5 {
        let mut wrong = report;
        match change {
            0 => wrong.failure_generation = 3,
            1 => wrong.failure_serial = 4,
            2 => wrong.failure_reason = 2,
            3 => wrong.failure_operation = 17,
            _ => wrong.failure_sequence = 18,
        }
        assert!(line(&record_fixture(wrong, b"r\n")).is_err());
    }
    let encoded = hex_fixture(&report.encode()[..256]);
    assert!(line(&fixture.replace(&encoded, &encoded.to_ascii_uppercase())).is_err());
    assert!(line(&fixture.replace(&encoded, &encoded[..510])).is_err());
    let mut wrong_flags = report.encode();
    wrong_flags[6] ^= 8;
    assert!(line(&fixture.replace(&encoded, &hex_fixture(&wrong_flags[..256]))).is_err());
    let mut wrong_reserved = report.encode();
    wrong_reserved[255] = 1; // A digest component, not reserved: must remain valid.
    assert!(Completion::decode(&wrong_reserved).is_ok());
    wrong_reserved[256] = 1;
    assert!(Completion::decode(&wrong_reserved).is_err());
    assert!(record(format!("{fixture}\n{fixture}\n").as_bytes()).is_err());
}

#[test]
fn bounded_cpu_uses_checked_ancestor_accounting_and_no_reset() {
    let fixture = budget_fixture();
    let parsed = budget_line(fixture).unwrap();
    assert_eq!(
        (
            parsed.elapsed,
            parsed.driver,
            parsed.controller,
            parsed.critical,
            parsed.parent,
            parsed.transitions
        ),
        (600, 100, 400, 100, 600, 4000)
    );
    for (old, new) in [
        ("elapsed_ticks=600", "elapsed_ticks=65536"),
        ("elapsed_ticks=600", "elapsed_ticks=0600"),
        ("driver_cpu=100", "driver_cpu=101"),
        ("driver_cpu=100", "driver_cpu=18446744073709551615"),
        ("controller_cpu=400", "controller_cpu=65537"),
        ("parent_cpu=600", "parent_cpu=0"),
        ("parent_limit=131072", "parent_limit=262144"),
        ("transitions=4000", "transitions=0"),
        ("transitions=4000", "transitions=8000001"),
        ("transition_limit=8000000", "transition_limit=16000000"),
        ("max_pending=1", "max_pending=2"),
        ("accounted=true", "accounted=false"),
    ] {
        assert!(
            budget_line(&fixture.replace(old, new)).is_err(),
            "{old} -> {new}"
        );
    }
    assert!(budget(format!("{fixture}\n{fixture}\n").as_bytes()).is_err());
}
