mod support;

use ev::{
    boot::supervised,
    boot_protocol::check,
    build::{Artifact, hash_file, verify_artifact},
    cli::{self, Cli},
};
use std::{
    fs::{self, File},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use support::TempDirectory;

const GOOD: &str = "firmware chatter\r\nEVROSION_BOOT protocol=1 build=abc\r\nEVROSION_FRAMEBUFFER present=true width=1280 height=800 stride=1280 format=bgr\r\nEvrosion kernel entered.\r\nEVROSION_M0_RESULT status=PASS code=0\r\n";

#[test]
fn paging_proof_requires_distinct_roots_complete_checks_and_order() {
    const RECORD: &str = "EVROSION_M1_PAGING status=PASS roots=2 map_unmap=true remap=true zeroed=true permissions=true restored=true root_a=0x3000 root_b=0x7000 virtual=0xffff800000000000";
    let prefix = GOOD.replace("Evrosion kernel entered.", "EVROSION_MEMORY regions=2 usable_bytes=16384\r\nEvrosion kernel entered.\r\nEVROSION_M1_BOOTSTRAP status=PASS page_size=4096 allocated=2 total=4 remaining=2 first=0x1000 second=0x2000");
    let good = prefix.replace(
        "EVROSION_M0_RESULT",
        &format!("{RECORD}\r\nEVROSION_M0_RESULT"),
    );
    check(good.as_bytes(), "abc", Some(33)).unwrap();
    const FAULTS: &str =
        "EVROSION_M1_FAULTS status=PASS readonly=true noexecute=true unmapped=true recovered=3";
    let faults = good.replace(
        "EVROSION_M0_RESULT",
        &format!("{FAULTS}\r\nEVROSION_M0_RESULT"),
    );
    check(faults.as_bytes(), "abc", Some(33)).unwrap();
    const USER: &str = "EVROSION_M1_USER status=PASS roots=2 cpl=3 private=true kernel_denied=true wx=true stack=true io_denied=true traps=15 root_a=0xe000 root_b=0x12000";
    let user = faults.replace(
        "EVROSION_M0_RESULT",
        &format!("{USER}\r\nEVROSION_M0_RESULT"),
    );
    check(user.as_bytes(), "abc", Some(33)).unwrap();
    const TIMER: &str =
        "EVROSION_M1_TIMER status=PASS ticks=8 deadline=8 masked_bound=true interrupts_off=true";
    let timer = user.replace(
        "EVROSION_M0_RESULT",
        &format!("{TIMER}\r\nEVROSION_M0_RESULT"),
    );
    check(timer.as_bytes(), "abc", Some(33)).unwrap();
    const TOPOLOGY: &str = "EVROSION_M1_TOPOLOGY status=PASS enabled=2 bsp=0 lapic=0xfee00000";
    let topology = timer.replace(
        "EVROSION_M0_RESULT",
        &format!("{TOPOLOGY}\r\nEVROSION_M0_RESULT"),
    );
    check(topology.as_bytes(), "abc", Some(33)).unwrap();
    const SMP: &str =
        "EVROSION_M1_SMP status=PASS online=2 ap=1 root=0x22000 shared=20000 parked=true";
    let smp = topology.replace(
        "EVROSION_M0_RESULT",
        &format!("{SMP}\r\nEVROSION_M0_RESULT"),
    );
    check(smp.as_bytes(), "abc", Some(33)).unwrap();
    const SCHEDULER: &str = "EVROSION_M1_SCHEDULER status=PASS scope=policy threads=2 jobs=2 dispatches=36 signal=true deadline=true stale_rejected=true";
    let scheduler = smp.replace(
        "EVROSION_M0_RESULT",
        &format!("{SCHEDULER}\r\nEVROSION_M0_RESULT"),
    );
    check(scheduler.as_bytes(), "abc", Some(33)).unwrap();
    const THREADS: &str = "EVROSION_M1_THREADS status=PASS threads=2 dispatches=36 switches=72 guards=4 registers=true stacks=true signal=true deadline=true exited=true";
    let threads = scheduler.replace(
        "EVROSION_M0_RESULT",
        &format!("{THREADS}\r\nEVROSION_M0_RESULT"),
    );
    check(threads.as_bytes(), "abc", Some(33)).unwrap();
    const PREEMPT: &str = "EVROSION_M1_PREEMPT status=PASS threads=2 quanta=8 dispatches=10 progress=true restored=true";
    let preempt = threads.replace(
        "EVROSION_M0_RESULT",
        &format!("{PREEMPT}\r\nEVROSION_M0_RESULT"),
    );
    check(preempt.as_bytes(), "abc", Some(33)).unwrap();
    const CAPS: &str = "EVROSION_M1_CAPS status=PASS scope=tables attenuation=true transfer=true revocation=true stale=true denial=true lifetime=true";
    let caps = preempt.replace(
        "EVROSION_M0_RESULT",
        &format!("{CAPS}\r\nEVROSION_M0_RESULT"),
    );
    check(caps.as_bytes(), "abc", Some(33)).unwrap();
    const IPC: &str = "EVROSION_M1_IPC status=PASS scope=mailbox bounded=true escrow=true delivery=true deadline=true death_return=true";
    let ipc = caps.replace(
        "EVROSION_M0_RESULT",
        &format!("{IPC}\r\nEVROSION_M0_RESULT"),
    );
    check(ipc.as_bytes(), "abc", Some(33)).unwrap();
    const BINDING: &str = "EVROSION_M2_BINDING status=PASS scope=fixture grants=2 measured=true resolved=true atomic=true attenuated=true revoked=true";
    let binding = ipc.replace(
        "EVROSION_M0_RESULT",
        &format!("{BINDING}\r\nEVROSION_M0_RESULT"),
    );
    check(binding.as_bytes(), "abc", Some(33)).unwrap();
    for invalid in [
        binding.replace(BINDING, &format!("{BINDING}\r\n{BINDING}")),
        binding.replace("grants=2", "grants=1"),
        binding.replace("scope=fixture", "scope=supervisor"),
        caps.replace(
            "EVROSION_M0_RESULT",
            &format!("{BINDING}\r\nEVROSION_M0_RESULT"),
        ),
    ] {
        assert!(check(invalid.as_bytes(), "abc", Some(33)).is_err());
    }
    const RUNTIME: &str = "EVROSION_M1_RUNTIME status=PASS processes=6 faults=3 survivors=3 messages=3 quanta=12 isolated=true authority=true restored=true";
    const LIFETIME: &str = "EVROSION_M2_LIFETIME status=PASS scope=authority cycles=64 reclaimed=128 old_space_denied=true stale_handles_denied=true";
    let lifetime = binding.replace(
        "EVROSION_M0_RESULT",
        &format!("{LIFETIME}\r\nEVROSION_M0_RESULT"),
    );
    check(lifetime.as_bytes(), "abc", Some(33)).unwrap();
    for invalid in [
        lifetime.replace("cycles=64", "cycles=1"),
        lifetime.replace("reclaimed=128", "reclaimed=0"),
        lifetime.replace(LIFETIME, &format!("{LIFETIME}\r\n{LIFETIME}")),
        ipc.replace(
            "EVROSION_M0_RESULT",
            &format!("{LIFETIME}\r\nEVROSION_M0_RESULT"),
        ),
    ] {
        assert!(check(invalid.as_bytes(), "abc", Some(33)).is_err());
    }
    const SCOPES: &str = "EVROSION_M2_SCOPES status=PASS scope=authority cycles=64 revoked=128 roots_preserved=true peers_preserved=true stale_revoke_denied=true";
    let scopes = lifetime.replace(
        "EVROSION_M0_RESULT",
        &format!("{SCOPES}\r\nEVROSION_M0_RESULT"),
    );
    check(scopes.as_bytes(), "abc", Some(33)).unwrap();
    for invalid in [
        scopes.replace("revoked=128", "revoked=0"),
        scopes.replace("roots_preserved=true", "roots_preserved=false"),
        scopes.replace("stale_revoke_denied=true", "stale_revoke_denied=false"),
        scopes.replace(SCOPES, &format!("{SCOPES}\r\n{SCOPES}")),
        binding.replace(
            "EVROSION_M0_RESULT",
            &format!("{SCOPES}\r\nEVROSION_M0_RESULT"),
        ),
    ] {
        assert!(check(invalid.as_bytes(), "abc", Some(33)).is_err());
    }
    const INCARNATION: &str = "EVROSION_M2_INCARNATION status=PASS scope=prepared bindings=2 held=true stale_events_denied=true limits=true revoked=true";
    let incarnation = scopes.replace(
        "EVROSION_M0_RESULT",
        &format!("{INCARNATION}\r\nEVROSION_M0_RESULT"),
    );
    check(incarnation.as_bytes(), "abc", Some(33)).unwrap();
    for invalid in [
        incarnation.replace("scope=prepared", "scope=active"),
        incarnation.replace("held=true", "held=false"),
        incarnation.replace("stale_events_denied=true", "stale_events_denied=false"),
        incarnation.replace(INCARNATION, &format!("{INCARNATION}\r\n{INCARNATION}")),
        lifetime.replace(
            "EVROSION_M0_RESULT",
            &format!("{INCARNATION}\r\nEVROSION_M0_RESULT"),
        ),
    ] {
        assert!(check(invalid.as_bytes(), "abc", Some(33)).is_err());
    }
    const EXECUTABLE: &str = "EVROSION_M2_EXECUTABLE status=PASS scope=loader segments=2 pages=5 frames=9 cpl3=5 measured=true zeroed=true wx=true guarded=true reclaimed=true";
    let executable = incarnation.replace(
        "EVROSION_M0_RESULT",
        &format!("{EXECUTABLE}\r\nEVROSION_M0_RESULT"),
    );
    check(executable.as_bytes(), "abc", Some(33)).unwrap();
    for invalid in [
        executable.replace("scope=loader", "scope=supervisor"),
        executable.replace("cpl3=5", "cpl3=0"),
        executable.replace("wx=true", "wx=false"),
        executable.replace("reclaimed=true", "reclaimed=false"),
        executable.replace(EXECUTABLE, &format!("{EXECUTABLE}\r\n{EXECUTABLE}")),
        scopes.replace(
            "EVROSION_M0_RESULT",
            &format!("{EXECUTABLE}\r\nEVROSION_M0_RESULT"),
        ),
    ] {
        assert!(check(invalid.as_bytes(), "abc", Some(33)).is_err());
    }
    const ACTIVATION: &str = "EVROSION_M2_ACTIVATION status=PASS scope=fixture attempts=2 admitted=1 rejected=1 cpl3=1 rechecked=true stale_denied=true inhibited=true peers_preserved=true frames=18 reclaimed=true";
    let activation = executable.replace(
        "EVROSION_M0_RESULT",
        &format!("{ACTIVATION}\r\nEVROSION_M0_RESULT"),
    );
    check(activation.as_bytes(), "abc", Some(33)).unwrap();
    for invalid in [
        activation.replace("scope=fixture", "scope=system"),
        activation.replace("admitted=1", "admitted=2"),
        activation.replace("rechecked=true", "rechecked=false"),
        activation.replace("inhibited=true", "inhibited=false"),
        activation.replace(ACTIVATION, &format!("{ACTIVATION}\r\n{ACTIVATION}")),
        incarnation.replace(
            "EVROSION_M0_RESULT",
            &format!("{ACTIVATION}\r\nEVROSION_M0_RESULT"),
        ),
    ] {
        assert!(check(invalid.as_bytes(), "abc", Some(33)).is_err());
    }
    const SUPERVISOR: &str = "EVROSION_M2_SUPERVISOR status=PASS scope=bootstrap images=2 ready=2 faults=1 denied=4 readonly=true measured=true authority=true stopped=true reclaimed=true";
    let supervisor = activation.replace(
        "EVROSION_M0_RESULT",
        &format!("{SUPERVISOR}\r\nEVROSION_M0_RESULT"),
    );
    check(supervisor.as_bytes(), "abc", Some(33)).unwrap();
    for invalid in [
        supervisor.replace("scope=bootstrap", "scope=system"),
        supervisor.replace("ready=2", "ready=0"),
        supervisor.replace("faults=1", "faults=0"),
        supervisor.replace("readonly=true", "readonly=false"),
        supervisor.replace(SUPERVISOR, &format!("{SUPERVISOR}\r\n{SUPERVISOR}")),
        executable.replace(
            "EVROSION_M0_RESULT",
            &format!("{SUPERVISOR}\r\nEVROSION_M0_RESULT"),
        ),
    ] {
        assert!(check(invalid.as_bytes(), "abc", Some(33)).is_err());
    }
    const SERVICES: &str = "EVROSION_M2_SERVICES status=PASS scope=launch graphs=2 children=2 requests=5 replies=4 cancelled=1 faults=1 control_denied=8 service_denied=8 event_denied=6 delegated=4 observed=true held=true isolated=true measured=true reclaimed=true";
    let services = supervisor.replace(
        "EVROSION_M0_RESULT",
        &format!("{SERVICES}\r\nEVROSION_M0_RESULT"),
    );
    check(services.as_bytes(), "abc", Some(33)).unwrap();
    for invalid in [
        services.replace("children=2", "children=0"),
        services.replace("requests=5", "requests=0"),
        services.replace("service_denied=8", "service_denied=0"),
        services.replace("delegated=4", "delegated=0"),
        services.replace(SERVICES, &format!("{SERVICES}\r\n{SERVICES}")),
        activation.replace(
            "EVROSION_M0_RESULT",
            &format!("{SERVICES}\r\nEVROSION_M0_RESULT"),
        ),
    ] {
        assert!(check(invalid.as_bytes(), "abc", Some(33)).is_err());
    }
    const RPC: &str = "EVROSION_M2_RPC status=PASS scope=transport successes=7 accepted=8 blocks=8 wakes=8 denied=2 expired=2 timeouts=1 busy=true late=1 stale=true reclaimed=true";
    let rpc = services.replace(
        "EVROSION_M0_RESULT",
        &format!("{RPC}\r\nEVROSION_M0_RESULT"),
    );
    check(rpc.as_bytes(), "abc", Some(33)).unwrap();
    for invalid in [
        rpc.replace("scope=transport", "scope=metadata"),
        rpc.replace("blocks=8", "blocks=0"),
        rpc.replace("late=1", "late=0"),
        rpc.replace("stale=true", "stale=false"),
        rpc.replace(RPC, &format!("{RPC}\r\n{RPC}")),
        supervisor.replace(
            "EVROSION_M0_RESULT",
            &format!("{RPC}\r\nEVROSION_M0_RESULT"),
        ),
    ] {
        assert!(check(invalid.as_bytes(), "abc", Some(33)).is_err());
    }
    const RESTART: &str = "EVROSION_M2_RESTART status=PASS scope=service cycles=64 faults=64 peer_replies=128 victim_replies=64 starts=66 stale=true root_preserved=true frames=true metadata=true reclaimed=true";
    let restart = rpc.replace(
        "EVROSION_M0_RESULT",
        &format!("{RESTART}\r\nEVROSION_M0_RESULT"),
    );
    check(restart.as_bytes(), "abc", Some(33)).unwrap();
    for invalid in [
        restart.replace("cycles=64", "cycles=1"),
        restart.replace("peer_replies=128", "peer_replies=0"),
        restart.replace("metadata=true", "metadata=false"),
        restart.replace("root_preserved=true", "root_preserved=false"),
        restart.replace(RESTART, &format!("{RESTART}\r\n{RESTART}")),
        services.replace(
            "EVROSION_M0_RESULT",
            &format!("{RESTART}\r\nEVROSION_M0_RESULT"),
        ),
    ] {
        assert!(check(invalid.as_bytes(), "abc", Some(33)).is_err());
    }
    const CUSTODY: &str = "EVROSION_M2_CUSTODY status=PASS scope=graph incarnations=4 replacements=3 root_faults=4 graphs=4 service_starts=8 service_replies=8 accepted_transfers=4 rejected_transfers=4 invalidated_transfers=4 recovery=1 unique=true authority=true graph=true budget=true stale=true frames=true metadata=true independent=true";
    let custody = restart.replace(
        "EVROSION_M0_RESULT",
        &format!("{CUSTODY}\r\nEVROSION_M0_RESULT"),
    );
    check(custody.as_bytes(), "abc", Some(33)).unwrap();
    for invalid in [
        custody.replace("incarnations=4", "incarnations=5"),
        custody.replace("invalidated_transfers=4", "invalidated_transfers=0"),
        custody.replace("recovery=1", "recovery=0"),
        custody.replace("independent=true", "independent=false"),
        custody.replace(CUSTODY, &format!("{CUSTODY}\r\n{CUSTODY}")),
        rpc.replace(
            "EVROSION_M0_RESULT",
            &format!("{CUSTODY}\r\nEVROSION_M0_RESULT"),
        ),
    ] {
        assert!(check(invalid.as_bytes(), "abc", Some(33)).is_err());
    }
    const RECOVERY_CASES: &str = "EVROSION_M2_RECOVERY_CASES status=PASS scope=failure cases=11 faults=6 exits=4 watchdogs=4 interruptions=6 integrity=3 attempts=33 charged=24 held=20 admitted=16 active=15 graphs=14 starts=28 replies=28 transfers=14 rejected=14 invalidated=14 recovery=11 retired=true frames=true unique=true budget=true selection=true grants=true";
    let recovery_cases = custody.replace(
        "EVROSION_M0_RESULT",
        &format!("{RECOVERY_CASES}\r\nEVROSION_M0_RESULT"),
    );
    check(recovery_cases.as_bytes(), "abc", Some(33)).unwrap();
    for invalid in [
        recovery_cases.replace("cases=11", "cases=1"),
        recovery_cases.replace("integrity=3", "integrity=0"),
        recovery_cases.replace("charged=24", "charged=0"),
        recovery_cases.replace("selection=true", "selection=false"),
        recovery_cases.replace(
            RECOVERY_CASES,
            &format!("{RECOVERY_CASES}\r\n{RECOVERY_CASES}"),
        ),
        restart.replace(
            "EVROSION_M0_RESULT",
            &format!("{RECOVERY_CASES}\r\nEVROSION_M0_RESULT"),
        ),
    ] {
        assert!(check(invalid.as_bytes(), "abc", Some(33)).is_err());
    }
    const CAPRPC: &str = "EVROSION_M2_CAPRPC status=PASS scope=transport worlds=5 accepted=8 blocks=8 wakes=8 delivered=6 returned=4 refunded=2 no_refund=2 timeouts=2 faults=2 late=1 stale=1 wrong_object=1 rejected=3 busy=true exits=5 frames=true metadata=true";
    let caprpc = recovery_cases.replace(
        "EVROSION_M0_RESULT",
        &format!("{CAPRPC}\r\nEVROSION_M0_RESULT"),
    );
    check(caprpc.as_bytes(), "abc", Some(33)).unwrap();
    for invalid in [
        caprpc.replace("refunded=2", "refunded=0"),
        caprpc.replace("no_refund=2", "no_refund=0"),
        caprpc.replace("wrong_object=1", "wrong_object=0"),
        caprpc.replace(CAPRPC, &format!("{CAPRPC}\r\n{CAPRPC}")),
        custody.replace(
            "EVROSION_M0_RESULT",
            &format!("{CAPRPC}\r\nEVROSION_M0_RESULT"),
        ),
    ] {
        assert!(check(invalid.as_bytes(), "abc", Some(33)).is_err());
    }
    const DISCIPLINE: &str = "EVROSION_M2_IPC_DISCIPLINE status=PASS scope=threads worlds=2 calls=10 blocks=10 wakes=10 delivered=10 replies=10 contexts=10 spawned=6 exits=2 mutex_acquired=1 mutex_released=1 no_wait=1 cycles=1 extended=1 depth=1 wrong_thread=1 max_depth=8 stacks=true frames=true metadata=true";
    let discipline = caprpc.replace(
        "EVROSION_M0_RESULT",
        &format!("{DISCIPLINE}\r\nEVROSION_M0_RESULT"),
    );
    check(discipline.as_bytes(), "abc", Some(33)).unwrap();
    let generation_report = ev_userspace_contract::generation::Completion {
        mode: ev_userspace_contract::generation::Mode::Verify,
        owner_decision: ev_userspace_contract::generation::OwnerDecision::None,
        booted: 0,
        selected: 1,
        known_good: 1,
        boot_serial: 0,
        process: 0,
        thread: 0,
        failure_generation: 2,
        failure_serial: 2,
        failure_reason: 1,
        negatives: 0,
        mutations: 0,
        operation: 21,
        sequence: 22,
        failure_operation: 10,
        failure_sequence: 11,
        catalogue: [1; 32],
        process_stamp: [0; 32],
        storage_probe: [2; 32],
        booted_cohort: [0; 32],
    };
    let generation_hex: String = generation_report.encode()[..256]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let generation_record = format!(
        "EVROSION_M3_GENERATION status=PASS scope=cohort phase=verify calls=50 blocks=50 wakes=50 replies=50 mutations=0 starts=0 ready=0 critical_ready=0 faults=0 stops=0 reaps=0 forged=0 catalogue=true frames=true metadata=true guards=true report={generation_hex}"
    );
    let generation = discipline.replace(
        "EVROSION_M0_RESULT",
        &format!("{generation_record}\r\nEVROSION_M0_RESULT"),
    );
    check(generation.as_bytes(), "abc", Some(33)).unwrap();
    const GENERATION_BUDGET: &str = "EVROSION_M3_GENERATION_BUDGET status=PASS elapsed_ticks=100 limit_ticks=2048 driver_cpu=75 controller_cpu=25 critical_cpu=0 parent_cpu=100 transitions=2000 max_pending=1 accounted=true bounded=true";
    let timed_generation = generation.replace(
        "EVROSION_M0_RESULT",
        &format!("{GENERATION_BUDGET}\r\nEVROSION_M0_RESULT"),
    );
    check(timed_generation.as_bytes(), "abc", Some(33)).unwrap();
    let file_report = {
        use sha2::Digest;
        ev_userspace_contract::file_test::Completion {
            mode: ev_userspace_contract::file_test::Mode::Verify,
            object: 1,
            counter: 1,
            requests: 7,
            ro_denied: 1,
            malformed: 2,
            invalid_counter: 2,
            skipped: 0,
            conflicting: 0,
            duplicates: 0,
            port_denied: 1,
            block_denied: 1,
            private_snapshot: 0,
            payload: sha2::Sha256::digest(ev_userspace_contract::file_test::DATA_B).into(),
        }
    };
    let file_hex: String = file_report
        .encode()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let file_record = format!(
        "EVROSION_M3_FILE status=PASS scope=object phase=verify calls=27 blocks=27 wakes=27 replies=27 outer=7 backend=20 nested=10 startup=10 pre_delivery=0 delivered_nested=10 max_pending=2 mutations=0 snapshots=0 authority_denied=1 block_denied=1 unbound_denied=1 bindings=2 mapped=4 frames=true metadata=true guards=true report={file_hex}"
    );
    const FILE_BUDGET: &str = "EVROSION_M3_FILE_BUDGET status=PASS elapsed_ticks=100 limit_ticks=2048 driver_cpu=50 server_cpu=40 app_cpu=10 parent_cpu=100 transitions=2000 max_pending=2 accounted=true bounded=true";
    let file = discipline.replace(
        "EVROSION_M0_RESULT",
        &format!("{file_record}\r\n{FILE_BUDGET}\r\nEVROSION_M0_RESULT"),
    );
    check(file.as_bytes(), "abc", Some(33)).unwrap();
    for invalid in [
        file.replace(FILE_BUDGET, ""),
        file.replace(&file_record, &format!("{file_record}\r\n{file_record}")),
        file.replace(&file_record, &format!("{FILE_BUDGET}\r\n{file_record}")),
        caprpc.replace(
            "EVROSION_M0_RESULT",
            &format!("{file_record}\r\n{FILE_BUDGET}\r\nEVROSION_M0_RESULT"),
        ),
        file.replace(
            "EVROSION_M0_RESULT",
            &format!("{generation_record}\r\nEVROSION_M0_RESULT"),
        ),
        generation.replace(
            "EVROSION_M0_RESULT",
            &format!("{file_record}\r\n{FILE_BUDGET}\r\nEVROSION_M0_RESULT"),
        ),
    ] {
        assert!(check(invalid.as_bytes(), "abc", Some(33)).is_err());
    }
    for invalid in [
        discipline.replace(
            "EVROSION_M0_RESULT",
            &format!("{GENERATION_BUDGET}\r\nEVROSION_M0_RESULT"),
        ),
        timed_generation.replace(
            GENERATION_BUDGET,
            &format!("{GENERATION_BUDGET}\r\n{GENERATION_BUDGET}"),
        ),
        timed_generation.replace("driver_cpu=75", "driver_cpu=76"),
        timed_generation.replace("elapsed_ticks=100", "elapsed_ticks=2048"),
    ] {
        assert!(check(invalid.as_bytes(), "abc", Some(33)).is_err());
    }
    for invalid in [
        generation.replace(
            &generation_record,
            &format!("{generation_record}\r\n{generation_record}"),
        ),
        caprpc.replace(
            "EVROSION_M0_RESULT",
            &format!("{generation_record}\r\nEVROSION_M0_RESULT"),
        ),
        discipline.replace(
            "EVROSION_M0_RESULT status=PASS code=0",
            &format!("EVROSION_M0_RESULT status=PASS code=0\r\n{generation_record}"),
        ),
        generation.replace("critical_ready=0", "critical_ready=1"),
        generation.replace(
            "frames=true metadata=true guards=true report=",
            "frames=true metadata=false guards=true report=",
        ),
    ] {
        assert!(check(invalid.as_bytes(), "abc", Some(33)).is_err());
    }
    const JOURNAL: &str = "EVROSION_M3_STORE status=PASS scope=journal phase=init calls=25 blocks=25 wakes=25 replies=25 mutations=5 operation=0 sequence=1 pending=true replay_verified=false payload=initial frames=true metadata=true guards=true";
    let journal = discipline.replace(
        "EVROSION_M0_RESULT",
        &format!("{JOURNAL}\r\nEVROSION_M0_RESULT"),
    );
    check(journal.as_bytes(), "abc", Some(33)).unwrap();
    assert!(
        check(
            journal
                .replace(
                    "EVROSION_M0_RESULT",
                    &format!("{generation_record}\r\nEVROSION_M0_RESULT")
                )
                .as_bytes(),
            "abc",
            Some(33)
        )
        .is_err()
    );
    for invalid in [
        journal.replace("pending=true", "pending=false"),
        journal.replace("mutations=5", "mutations=4"),
        journal.replace("sequence=1", "sequence=2"),
        journal.replace("calls=25", "calls=025"),
        journal.replace("guards=true", "guards=false"),
        journal.replace(JOURNAL, &format!("{JOURNAL}\r\n{JOURNAL}")),
    ] {
        assert!(check(invalid.as_bytes(), "abc", Some(33)).is_err());
    }
    const JOURNAL_CUT: &str = "EVROSION_M3_STORE_CUT protocol=1 build=abc status=PASS scope=journal cut=3 calls=20 blocks=20 wakes=20 replies=20 mutations=3 fault_vector=6 fault_error=0 process=2 thread=2 frames=true metadata=true guards=true";
    let cut = discipline.replace("EVROSION_M0_RESULT status=PASS code=0", JOURNAL_CUT);
    ev::boot_protocol::check_store_cut_prefix(cut.as_bytes(), "abc", 3).unwrap();
    assert!(check(cut.as_bytes(), "abc", Some(33)).is_err());
    for invalid in [
        cut.replace("build=abc status", "build=wrong status"),
        cut.replace("mutations=3", "mutations=2"),
        cut.replace("cut=3", "cut=03"),
        cut.replace("replies=20", "replies=19"),
        cut.replace("fault_vector=6", "fault_vector=14"),
        cut.replace("process=2", "process=0"),
        cut.replace(
            "frames=true metadata=true guards=true",
            "frames=false metadata=true guards=true",
        ),
        cut.replace(JOURNAL_CUT, &format!("{JOURNAL_CUT}\r\n{JOURNAL_CUT}")),
        format!("{cut}EVROSION_M0_RESULT status=PASS code=0\r\n"),
        GOOD.replace("EVROSION_M0_RESULT status=PASS code=0", JOURNAL_CUT),
        cut.trim_end().to_owned(),
    ] {
        assert!(ev::boot_protocol::check_store_cut_prefix(invalid.as_bytes(), "abc", 3).is_err());
    }
    const BLOCK: &str = "EVROSION_M3_BLOCK status=PASS scope=pio phase=write inputs=1024 outputs=300 denied=4 malformed=4 direct_denied=1 exits=1 flushes=1 frames=true metadata=true";
    let block = discipline.replace(
        "EVROSION_M0_RESULT",
        &format!("{BLOCK}\r\nEVROSION_M0_RESULT"),
    );
    check(block.as_bytes(), "abc", Some(33)).unwrap();
    let verify = block
        .replace("phase=write", "phase=verify")
        .replace("flushes=1", "flushes=0");
    check(verify.as_bytes(), "abc", Some(33)).unwrap();
    const M3_SHARED: &str = "EVROSION_M3_TRANSPORT status=PASS scope=shared phase=write calls=4 blocks=4 wakes=4 replies=4 short_deadline_denied=1 authority_denied=1 malformed=2 mapped=2 private_copy=true guards=true frames=true metadata=true";
    let shared = block.replace(
        "EVROSION_M0_RESULT",
        &format!("{M3_SHARED}\r\nEVROSION_M0_RESULT"),
    );
    check(shared.as_bytes(), "abc", Some(33)).unwrap();
    for invalid in [
        shared.replace(M3_SHARED, &format!("{M3_SHARED}\r\n{M3_SHARED}")),
        shared.replace("blocks=4", "blocks=3"),
        shared.replace("private_copy=true", "private_copy=false"),
        shared.replace("mapped=2", "mapped=1"),
        shared.replace(
            M3_SHARED,
            &M3_SHARED
                .replace("phase=write", "phase=verify")
                .replace("calls=4", "calls=2")
                .replace("blocks=4", "blocks=2")
                .replace("wakes=4", "wakes=2")
                .replace("replies=4", "replies=2"),
        ),
        discipline.replace(
            "EVROSION_M0_RESULT",
            &format!("{M3_SHARED}\r\nEVROSION_M0_RESULT"),
        ),
        block.replace(BLOCK, &format!("{M3_SHARED}\r\n{BLOCK}")),
    ] {
        assert!(check(invalid.as_bytes(), "abc", Some(33)).is_err());
    }
    for invalid in [
        block.replace(BLOCK, &format!("{BLOCK}\r\n{BLOCK}")),
        block.replace("inputs=1024", "inputs=0"),
        block.replace("flushes=1", "flushes=0"),
        block.replace("denied=4", "denied=0"),
        block.replace("malformed=4", "malformed=0"),
        block.replace("direct_denied=1", "direct_denied=0"),
        block.replace("frames=true", "frames=false"),
        block.replace("metadata=true", "metadata=false"),
        caprpc.replace(
            "EVROSION_M0_RESULT",
            &format!("{BLOCK}\r\nEVROSION_M0_RESULT"),
        ),
    ] {
        assert!(check(invalid.as_bytes(), "abc", Some(33)).is_err());
    }

    for invalid in [
        discipline.replace("no_wait=1", "no_wait=0"),
        discipline.replace("max_depth=8", "max_depth=9"),
        discipline.replace("wrong_thread=1", "wrong_thread=0"),
        discipline.replace("stacks=true", "stacks=false"),
        discipline.replace(DISCIPLINE, &format!("{DISCIPLINE}\r\n{DISCIPLINE}")),
        recovery_cases.replace(
            "EVROSION_M0_RESULT",
            &format!("{DISCIPLINE}\r\nEVROSION_M0_RESULT"),
        ),
    ] {
        assert!(check(invalid.as_bytes(), "abc", Some(33)).is_err());
    }
    let runtime = discipline.replace(
        "EVROSION_M0_RESULT",
        &format!("{RUNTIME}\r\nEVROSION_M0_RESULT"),
    );
    check(runtime.as_bytes(), "abc", Some(33)).unwrap();
    let late_block = runtime.replace(
        "EVROSION_M0_RESULT",
        &format!("{BLOCK}\r\nEVROSION_M0_RESULT"),
    );
    assert!(check(late_block.as_bytes(), "abc", Some(33)).is_err());
    let with_block = runtime.replace(
        "EVROSION_M1_RUNTIME",
        &format!("{BLOCK}\r\nEVROSION_M1_RUNTIME"),
    );
    check(with_block.as_bytes(), "abc", Some(33)).unwrap();

    const WAITS: &str =
        "EVROSION_M1_WAITS status=PASS blocks=6 signals=3 deadlines=3 idle_ticks=6 retired=true";
    let waits = runtime.replace(
        "EVROSION_M0_RESULT",
        &format!("{WAITS}\r\nEVROSION_M0_RESULT"),
    );
    check(waits.as_bytes(), "abc", Some(33)).unwrap();
    const RETIRE: &str = "EVROSION_M1_RETIRE status=PASS processes=6 reclaimed=3 discarded=3 closed=true quiescent=true";
    let retired = waits.replace(
        "EVROSION_M0_RESULT",
        &format!("{RETIRE}\r\nEVROSION_M0_RESULT"),
    );
    check(retired.as_bytes(), "abc", Some(33)).unwrap();
    const RECLAIM: &str =
        "EVROSION_M1_RECLAIM status=PASS frames=42 reused=28 zeroed=true restored=true";
    let reclaim = retired.replace(
        "EVROSION_M0_RESULT",
        &format!("{RECLAIM}\r\nEVROSION_M0_RESULT"),
    );
    check(reclaim.as_bytes(), "abc", Some(33)).unwrap();
    const SHARED: &str =
        "EVROSION_M1_SHARED status=PASS objects=3 maps=6 denied=6 busy=3 destroyed=3 zeroed=true";
    let shared = reclaim.replace(
        "EVROSION_M0_RESULT",
        &format!("{SHARED}\r\nEVROSION_M0_RESULT"),
    );
    check(shared.as_bytes(), "abc", Some(33)).unwrap();
    const JOBS: &str = "EVROSION_M1_JOBS status=PASS jobs=9 frames=45 cpu_ticks=12 hierarchy=true admission=true live_zero=true";
    let jobs = shared.replace(
        "EVROSION_M0_RESULT",
        &format!("{JOBS}\r\nEVROSION_M0_RESULT"),
    );
    check(jobs.as_bytes(), "abc", Some(33)).unwrap();
    const REVOKE: &str =
        "EVROSION_M1_REVOKE status=PASS invalidated=3 denied=3 faults=3 sibling_live=true";
    let revoke = jobs.replace(
        "EVROSION_M0_RESULT",
        &format!("{REVOKE}\r\nEVROSION_M0_RESULT"),
    );
    check(revoke.as_bytes(), "abc", Some(33)).unwrap();
    const FX: &str =
        "EVROSION_M1_FX status=PASS processes=6 x87=true xmm=true mxcsr=true clean=true eager=true";
    let fx = revoke.replace("EVROSION_M0_RESULT", &format!("{FX}\r\nEVROSION_M0_RESULT"));
    check(fx.as_bytes(), "abc", Some(33)).unwrap();
    const FD: &str = "EVROSION_M1_FAULT_DELIVERY status=PASS records=3 denied=3 consumed_once=true kernel_sender=true";
    let fd = fx.replace("EVROSION_M0_RESULT", &format!("{FD}\r\nEVROSION_M0_RESULT"));
    check(fd.as_bytes(), "abc", Some(33)).unwrap();
    const ALLOC: &str = "EVROSION_M1_ALLOC status=PASS allocated=6 freed=6 denied=3 zeroed=true unmapped=true rollback=true";
    let alloc = fd.replace("frames=45", "frames=51").replace(
        "EVROSION_M0_RESULT",
        &format!("{ALLOC}\r\nEVROSION_M0_RESULT"),
    );
    check(alloc.as_bytes(), "abc", Some(33)).unwrap();
    for bad in [
        alloc.replace("allocated=6", "allocated=0"),
        alloc.replace("frames=51", "frames=45"),
        alloc.replace(ALLOC, &format!("{ALLOC}\r\n{ALLOC}")),
        alloc.replace(&format!("{FD}\r\n"), ""),
    ] {
        assert!(check(bad.as_bytes(), "abc", Some(33)).is_err());
    }
    for bad in [
        fd.replace("records=3", "records=0"),
        fd.replace(FD, &format!("{FD}\r\n{FD}")),
        fd.replace(&format!("{FX}\r\n"), ""),
    ] {
        assert!(check(bad.as_bytes(), "abc", Some(33)).is_err());
    }
    for bad in [
        fx.replace("x87=true", "x87=false"),
        fx.replace(FX, &format!("{FX}\r\n{FX}")),
        fx.replace(&format!("{REVOKE}\r\n"), ""),
    ] {
        assert!(check(bad.as_bytes(), "abc", Some(33)).is_err());
    }
    for bad in [
        revoke.replace("invalidated=3", "invalidated=0"),
        revoke.replace("sibling_live=true", "sibling_live=false"),
        revoke.replace(REVOKE, &format!("{REVOKE}\r\n{REVOKE}")),
        revoke.replace(&format!("{JOBS}\r\n"), ""),
    ] {
        assert!(check(bad.as_bytes(), "abc", Some(33)).is_err());
    }
    for bad in [
        jobs.replace("cpu_ticks=12", "cpu_ticks=13"),
        jobs.replace("live_zero=true", "live_zero=false"),
        jobs.replace(JOBS, &format!("{JOBS}\r\n{JOBS}")),
        jobs.replace(&format!("{SHARED}\r\n"), ""),
    ] {
        assert!(check(bad.as_bytes(), "abc", Some(33)).is_err());
    }
    for bad in [
        shared.replace("denied=6", "denied=0"),
        shared.replace("busy=3", "busy=0"),
        shared.replace(SHARED, &format!("{SHARED}\r\n{SHARED}")),
        shared.replace(&format!("{RECLAIM}\r\n"), ""),
    ] {
        assert!(check(bad.as_bytes(), "abc", Some(33)).is_err());
    }
    for bad in [
        reclaim.replace("reused=28", "reused=27"),
        reclaim.replace("reused=28", "reused=43"),
        reclaim.replace("zeroed=true", "zeroed=false"),
        reclaim.replace(RECLAIM, &format!("{RECLAIM}\r\n{RECLAIM}")),
        reclaim.replace(&format!("{RETIRE}\r\n"), ""),
    ] {
        assert!(check(bad.as_bytes(), "abc", Some(33)).is_err());
    }
    for bad in [
        retired.replace("reclaimed=3", "reclaimed=2"),
        retired.replace("quiescent=true", "quiescent=false"),
        retired.replace(RETIRE, &format!("{RETIRE}\r\n{RETIRE}")),
        retired.replace(&format!("{WAITS}\r\n"), ""),
    ] {
        assert!(check(bad.as_bytes(), "abc", Some(33)).is_err());
    }
    for bad in [
        waits.replace("signals=3", "signals=2"),
        waits.replace("idle_ticks=6", "idle_ticks=0"),
        waits.replace("idle_ticks=6", "idle_ticks=3073"),
        waits.replace("retired=true", "retired=false"),
        waits.replace(WAITS, &format!("{WAITS}\r\n{WAITS}")),
        waits.replace(&format!("{RUNTIME}\r\n"), ""),
    ] {
        assert!(check(bad.as_bytes(), "abc", Some(33)).is_err());
    }
    for bad in [
        runtime.replace("survivors=3", "survivors=2"),
        runtime.replace("quanta=12", "quanta=11"),
        runtime.replace("quanta=12", "quanta=3073"),
        runtime.replace("authority=true", "authority=false"),
        runtime.replace(RUNTIME, &format!("{RUNTIME}\r\n{RUNTIME}")),
        runtime.replace(&format!("{IPC}\r\n"), ""),
    ] {
        assert!(check(bad.as_bytes(), "abc", Some(33)).is_err());
    }
    for bad in [
        ipc.replace("escrow=true", "escrow=false"),
        ipc.replace("death_return=true", "death_return=false"),
        ipc.replace(IPC, &format!("{IPC}\r\n{IPC}")),
        ipc.replace(&format!("{CAPS}\r\n"), ""),
    ] {
        assert!(check(bad.as_bytes(), "abc", Some(33)).is_err());
    }

    for bad in [
        caps.replace("attenuation=true", "attenuation=false"),
        caps.replace("scope=tables", "scope=userspace"),
        caps.replace(CAPS, &format!("{CAPS}\r\n{CAPS}")),
        caps.replace(&format!("{PREEMPT}\r\n"), ""),
    ] {
        assert!(check(bad.as_bytes(), "abc", Some(33)).is_err());
    }

    for bad in [
        preempt.replace("quanta=8", "quanta=7"),
        preempt.replace("dispatches=10", "dispatches=11"),
        preempt.replace("restored=true", "restored=false"),
        preempt.replace(PREEMPT, &format!("{PREEMPT}\r\n{PREEMPT}")),
        preempt.replace(&format!("{THREADS}\r\n"), ""),
    ] {
        assert!(check(bad.as_bytes(), "abc", Some(33)).is_err());
    }

    for bad in [
        threads.replace("switches=72", "switches=71"),
        threads.replace("guards=4", "guards=0"),
        threads.replace("registers=true", "registers=false"),
        threads.replace("exited=true", "exited=false"),
        threads.replace(THREADS, &format!("{THREADS}\r\n{THREADS}")),
        threads.replace(&format!("{SCHEDULER}\r\n"), ""),
    ] {
        assert!(check(bad.as_bytes(), "abc", Some(33)).is_err());
    }

    for invalid in [
        scheduler.replace("dispatches=36", "dispatches=35"),
        scheduler.replace("scope=policy", "scope=threads"),
        scheduler.replace("stale_rejected=true", "stale_rejected=false"),
        scheduler.replace(SCHEDULER, &format!("{SCHEDULER}\r\n{SCHEDULER}")),
        scheduler.replace(&format!("{SMP}\r\n"), ""),
    ] {
        assert!(check(invalid.as_bytes(), "abc", Some(33)).is_err());
    }

    let skip = smp.replace(SMP, "EVROSION_M1_SMP status=SKIP reason=single_cpu");
    assert!(check(skip.as_bytes(), "abc", Some(33)).is_err());
    check(
        skip.replace("enabled=2", "enabled=1").as_bytes(),
        "abc",
        Some(33),
    )
    .unwrap();
    for bad in [
        smp.replace("ap=1", "ap=0"),
        smp.replace("shared=20000", "shared=19999"),
        smp.replace("parked=true", "parked=false"),
        smp.replace("enabled=2", "enabled=1"),
        smp.replace("root=0x22000", "root=0x22001"),
        smp.replace("root=0x22000", "root=0x100000000"),
        smp.replace(SMP, &format!("{SMP}\r\n{SMP}")),
        smp.replace(&format!("{TOPOLOGY}\r\n"), ""),
    ] {
        assert!(check(bad.as_bytes(), "abc", Some(33)).is_err());
    }

    for bad in [
        topology.replace("enabled=2", "enabled=0"),
        topology.replace("enabled=2", "enabled=65"),
        topology.replace("bsp=0", "bsp=4294967296"),
        topology.replace("lapic=0xfee00000", "lapic=0xfee00001"),
        topology.replace("lapic=0xfee00000", "lapic=0x0"),
        topology.replace(TOPOLOGY, &format!("{TOPOLOGY}\r\n{TOPOLOGY}")),
        topology.replace(&format!("{TIMER}\r\n"), ""),
    ] {
        assert!(check(bad.as_bytes(), "abc", Some(33)).is_err());
    }

    for bad in [
        timer.replace("ticks=8", "ticks=7"),
        timer.replace("ticks=8", "ticks=65"),
        timer.replace("deadline=8", "deadline=9"),
        timer.replace("masked_bound=true", "masked_bound=false"),
        timer.replace("interrupts_off=true", "interrupts_off=false"),
        timer.replace(TIMER, &format!("{TIMER}\r\n{TIMER}")),
        timer.replace(&format!("{USER}\r\n"), ""),
    ] {
        assert!(check(bad.as_bytes(), "abc", Some(33)).is_err());
    }
    for bad in [
        user.replace("traps=15", "traps=14"),
        user.replace("cpl=3", "cpl=0"),
        user.replace("private=true", "private=false"),
        user.replace("kernel_denied=true", "kernel_denied=false"),
        user.replace("wx=true", "wx=false"),
        user.replace("root_b=0x12000", "root_b=0xe000"),
        user.replace("root_b=0x12000", "root_b=0x12001"),
        user.replace(USER, &format!("{USER}\r\n{USER}")),
        user.replace(&format!("{FAULTS}\r\n"), ""),
    ] {
        assert!(check(bad.as_bytes(), "abc", Some(33)).is_err());
    }
    for bad in [
        faults.replace("recovered=3", "recovered=2"),
        faults.replace("readonly=true", "readonly=false"),
        faults.replace("noexecute=true", "noexecute=false"),
        faults.replace("unmapped=true", "unmapped=false"),
        faults.replace(FAULTS, &format!("{FAULTS}\r\n{FAULTS}")),
        prefix.replace(
            "EVROSION_M0_RESULT",
            &format!("{FAULTS}\r\nEVROSION_M0_RESULT"),
        ),
    ] {
        assert!(check(bad.as_bytes(), "abc", Some(33)).is_err());
    }
    for bad in [
        good.replace("root_b=0x7000", "root_b=0x3000"),
        good.replace("root_b=0x7000", "root_b=0x7001"),
        good.replace("root_a=0x3000", "root_a=0x0"),
        good.replace("roots=2", "roots=1"),
        good.replace("restored=true", "restored=false"),
        good.replace("permissions=true", "permissions=false"),
        good.replace("virtual=0xffff800000000000", "virtual=0x800000000000"),
        good.replace("virtual=0xffff800000000000", "virtual=0xffffff8000000000"),
        good.replace("virtual=0xffff800000000000", "virtual=0xffff800000000001"),
        good.replace(RECORD, &format!("{RECORD}\r\n{RECORD}")),
        GOOD.replace(
            "EVROSION_M0_RESULT",
            &format!("{RECORD}\r\nEVROSION_M0_RESULT"),
        ),
        prefix.replace(
            "Evrosion kernel entered.",
            &format!("{RECORD}\r\nEvrosion kernel entered."),
        ),
    ] {
        assert!(
            check(bad.as_bytes(), "abc", Some(33)).is_err(),
            "accepted: {bad}"
        );
    }
}

#[test]
fn bootstrap_record_requires_valid_frames_counts_order_and_memory() {
    const RECORD: &str = "EVROSION_M1_BOOTSTRAP status=PASS page_size=4096 allocated=2 total=4 remaining=2 first=0x1000 second=0x2000";
    let prefix = GOOD.replace(
        "Evrosion kernel entered.",
        "EVROSION_MEMORY regions=2 usable_bytes=16384\r\nEvrosion kernel entered.",
    );
    let good = prefix.replace(
        "EVROSION_M0_RESULT",
        &format!("{RECORD}\r\nEVROSION_M0_RESULT"),
    );
    check(good.as_bytes(), "abc", Some(33)).unwrap();
    for bad in [
        good.replace("page_size=4096", "page_size=0"),
        good.replace("allocated=2", "allocated=0"),
        good.replace("remaining=2", "remaining=5"),
        good.replace("total=4 remaining=2", "total=5 remaining=3"),
        good.replace("first=0x1000", "first=0x0"),
        good.replace("first=0x1000", "first=0x1001"),
        good.replace("first=0x1000", "first=0x2000"),
        good.replace("second=0x2000", "second=0x10000000000000"),
        good.replace("second=0x2000", "second=0xffffffffffffffffffff"),
        good.replace("second=0x2000", "second=0x+2000"),
        good.replace(RECORD, &format!("{RECORD}\r\n{RECORD}")),
        good.replace(RECORD, &format!("{RECORD} extra=1")),
        GOOD.replace(
            "EVROSION_M0_RESULT",
            &format!("{RECORD}\r\nEVROSION_M0_RESULT"),
        ),
        prefix.replace(
            "Evrosion kernel entered.",
            &format!("{RECORD}\r\nEvrosion kernel entered."),
        ),
        format!("{prefix}{RECORD}\r\n"),
    ] {
        assert!(
            check(bad.as_bytes(), "abc", Some(33)).is_err(),
            "accepted: {bad}"
        );
    }
}

#[test]
fn deliberate_panic_requires_failure_status_identity_source_and_bounded_message() {
    use ev::boot_protocol::check_panic;
    let panic = GOOD.replace("EVROSION_M0_RESULT status=PASS code=0", "EVROSION_PANIC protocol=1 build=abc cpu=0 location=kernel/src/main.rs:75 message=M0 deliberate panic: observable and symbolizable\r\nEVROSION_M0_RESULT status=FAIL code=1");
    check_panic(panic.as_bytes(), "abc", Some(35)).unwrap();
    assert!(check_panic(panic.as_bytes(), "abc", Some(33)).is_err());
    assert!(check_panic(panic.as_bytes(), "other", Some(35)).is_err());
    assert!(check_panic(GOOD.as_bytes(), "abc", Some(35)).is_err());
    assert!(
        check_panic(
            panic
                .replace("location=kernel/src/main.rs:75", "location=unknown")
                .as_bytes(),
            "abc",
            Some(35)
        )
        .is_err()
    );
    assert!(
        check_panic(
            panic.replace("symbolizable", &"x".repeat(2048)).as_bytes(),
            "abc",
            Some(35)
        )
        .is_err()
    );
    assert!(
        check_panic(
            format!("{panic}EVROSION_PANIC bogus\n").as_bytes(),
            "abc",
            Some(35)
        )
        .is_err()
    );
}

#[test]
fn accepts_complete_matching_boot_with_and_without_framebuffer() {
    check(GOOD.as_bytes(), "abc", Some(33)).unwrap();
    check(
        GOOD.replace(
            "present=true width=1280 height=800 stride=1280 format=bgr",
            "present=false width=0 height=0 stride=0 format=none",
        )
        .as_bytes(),
        "abc",
        Some(33),
    )
    .unwrap();
}

#[test]
fn markers_alone_or_status_alone_cannot_pass() {
    for status in [None, Some(0), Some(1), Some(35)] {
        assert!(check(GOOD.as_bytes(), "abc", status).is_err());
    }
    assert!(check(b"", "abc", Some(33)).is_err());
    assert!(check(b"Evrosion kernel entered.\n", "abc", Some(33)).is_err());
    assert!(check(GOOD.as_bytes(), "different", Some(33)).is_err());
    assert!(
        check(
            GOOD.replace("protocol=1", "protocol=2").as_bytes(),
            "abc",
            Some(33)
        )
        .is_err()
    );
}

#[test]
fn rejects_duplicates_truncation_panics_and_trailing_failure() {
    for line in GOOD.lines().skip(1) {
        assert!(
            check(
                GOOD.replace(line, &format!("{line}\n{line}")).as_bytes(),
                "abc",
                Some(33)
            )
            .is_err()
        );
        assert!(check(GOOD.replace(line, "").as_bytes(), "abc", Some(33)).is_err());
    }
    for extra in [
        "EVROSION_PANIC protocol=1 message=oops",
        "EVROSION_M0_RESULT status=FAIL code=1",
        "junk",
    ] {
        assert!(check(format!("{GOOD}{extra}\n").as_bytes(), "abc", Some(33)).is_err());
    }
    assert!(
        check(
            GOOD.replace("firmware chatter", "EVROSION_PANIC early")
                .as_bytes(),
            "abc",
            Some(33)
        )
        .is_err()
    );
}

#[test]
fn rejects_invalid_or_inconsistent_framebuffer_fields() {
    for (old, new) in [
        ("width=1280", "width=0"),
        ("stride=1280", "stride=1"),
        ("height=800", "height=99999999999999999999999999999"),
        ("format=bgr", "format=unknown"),
        ("present=true", "present=false"),
        ("width=1280", "width=+1280"),
    ] {
        assert!(check(GOOD.replace(old, new).as_bytes(), "abc", Some(33)).is_err());
    }
}

#[test]
fn build_and_boot_cli_validate_limits_duplicates_and_paths() {
    let parse = |args: &[&str]| cli::parse(args.iter().map(Into::into));
    assert!(
        matches!(parse(&["build", "--profile", "release"]), Ok(Cli::Build(options)) if options.release)
    );
    assert!(matches!(parse(&["test", "boot"]), Ok(Cli::Boot(options)) if options.runs == 3));
    assert!(
        matches!(parse(&["run", "--root", "path with spaces"]), Ok(Cli::Preview(options)) if options.root.as_ref().unwrap().to_str() == Some("path with spaces") && options.timeout_seconds==240)
    );
    for args in [
        &["test", "boot", "--runs", "0"][..],
        &["run", "--timeout", "601"],
        &["run", "--timeout", "0"],
        &["run", "--timeout", "1", "--timeout", "2"],
        &["build", "--profile", "other"],
        &["run", "--runs", "2"],
        &["build", "--root"],
    ] {
        assert!(parse(args).is_err(), "accepted {args:?}");
    }
}

#[test]
fn artifact_tampering_and_directory_escape_are_rejected() {
    let temporary = TempDirectory::new();
    let root = &temporary.0;
    fs::write(root.join("image"), b"image").unwrap();
    let artifact = Artifact {
        path: "image".into(),
        sha256: hash_file(&root.join("image")).unwrap(),
    };
    assert!(verify_artifact(root, &artifact).is_ok());
    fs::write(root.join("image"), b"tampered").unwrap();
    assert!(verify_artifact(root, &artifact).is_err());
    for path in ["../image", "/etc/passwd"] {
        assert!(
            verify_artifact(
                root,
                &Artifact {
                    path: path.into(),
                    sha256: String::new()
                }
            )
            .is_err()
        );
    }
}

#[test]
fn timeout_kills_and_reaps_the_vm_process() {
    let temporary = TempDirectory::new();
    let pid = temporary.0.join("pid");
    let log = temporary.0.join("log");
    let file = File::create(&log).unwrap();
    let mut command = Command::new("python3");
    command
        .args([
            "-c",
            "import os,sys,time; open(sys.argv[1], 'w').write(str(os.getpid())); time.sleep(30)",
        ])
        .arg(&pid)
        .stdout(Stdio::null())
        .stderr(file);
    let start = Instant::now();
    let result = supervised(&mut command, &[&log], Duration::from_secs(1));
    assert!(result.unwrap_err().contains("timed out"));
    assert!(start.elapsed() < Duration::from_secs(5));
    let pid = fs::read_to_string(pid).unwrap();
    assert!(
        !std::path::Path::new("/proc").join(pid).exists(),
        "child is alive or a zombie"
    );
}

#[test]
fn output_overflow_cannot_pass_or_leave_a_child_running() {
    let temporary = TempDirectory::new();
    let pid = temporary.0.join("pid");
    let log = temporary.0.join("log");
    let mut command = Command::new("python3");
    command.args(["-c", "import os,sys,time; open(sys.argv[1], 'w').write(str(os.getpid())); sys.stderr.write('x' * 1100000); sys.stderr.flush(); time.sleep(30)"])
        .arg(&pid).stdout(Stdio::null()).stderr(File::create(&log).unwrap());
    assert!(
        supervised(&mut command, &[&log], Duration::from_secs(5))
            .unwrap_err()
            .contains("output limit")
    );
    let pid = fs::read_to_string(pid).unwrap();
    assert!(!std::path::Path::new("/proc").join(pid).exists());
}

#[test]
fn boot_cpu_count_is_explicit_bounded_and_defaults_to_one() {
    let Cli::Preview(preview) = cli::parse(["run"].map(Into::into)).unwrap() else {
        panic!("preview options")
    };
    assert_eq!(
        (preview.cpus, preview.runs, preview.timeout_seconds),
        (1, 1, 240)
    );
    let Cli::Boot(boot) = cli::parse(["test", "boot"].map(Into::into)).unwrap() else {
        panic!("boot options")
    };
    assert_eq!((boot.cpus, boot.runs, boot.timeout_seconds), (1, 3, 60));
    assert!(cli::parse(["run", "--cpus", "2"].map(Into::into)).is_err());
    let Cli::Boot(options) =
        cli::parse(["test", "boot", "--cpus", "2"].into_iter().map(Into::into)).unwrap()
    else {
        panic!("boot options")
    };
    assert_eq!(options.cpus, 2);
    for count in ["0", "65", "-1", "two"] {
        assert!(cli::parse(["run", "--cpus", count].into_iter().map(Into::into)).is_err());
    }
}

#[test]
fn storage_fixture_selection_is_explicit_without_external_disk_paths() {
    use std::ffi::OsString;
    assert_eq!(
        cli::parse(["test", "storage-pio"].map(OsString::from)).unwrap(),
        Cli::Workflow("storage-pio".into())
    );
    for fixture in ["m3-pio-write", "m3-pio-verify"] {
        let Cli::Build(options) =
            cli::parse(["build", "--fixture", fixture].map(OsString::from)).unwrap()
        else {
            panic!("expected build")
        };
        assert_eq!(options.fixture.as_deref(), Some(fixture));
    }
    for arguments in [
        vec!["run", "--data-disk", "/dev/sda"],
        vec!["test", "storage-pio", "--data-disk", "disk.raw"],
    ] {
        assert!(cli::parse(arguments.into_iter().map(OsString::from)).is_err());
    }
}
