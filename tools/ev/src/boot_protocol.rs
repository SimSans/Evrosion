use ev_test_protocol as protocol;

/// Negative acceptance: an intentional panic must fail the guest, but pass this check.
pub fn check_panic(serial: &[u8], build: &str, status: Option<i32>) -> Result<(), String> {
    if serial.len() > 1024 * 1024 || status != Some(protocol::QEMU_FAIL_STATUS) {
        return Err("panic test requires bounded output and QEMU failure status 35".into());
    }
    let text = String::from_utf8_lossy(serial);
    let prefix =
        format!("EVROSION_PANIC protocol=1 build={build} cpu=0 location=kernel/src/main.rs:");
    let lines: Vec<_> = text
        .lines()
        .filter(|l| l.starts_with("EVROSION_PANIC"))
        .collect();
    if lines.len() != 1
        || !lines[0].starts_with(&prefix)
        || lines[0].len() > 1024
        || !lines[0].contains("message=M0 deliberate panic: observable and symbolizable")
        || !text.ends_with(&format!("{}\r\n", protocol::FAIL))
        || text.contains(protocol::PASS)
    {
        return Err("missing, malformed or wrong-build deliberate panic record".into());
    }
    let before = text
        .split("EVROSION_PANIC")
        .next()
        .ok_or("missing panic prefix")?;
    check(
        format!("{before}{}\r\n", protocol::PASS).as_bytes(),
        build,
        Some(protocol::QEMU_PASS_STATUS),
    )
}

/// PASS requires the complete ordered protocol AND the QEMU exit device status.
pub fn check(serial: &[u8], expected_build: &str, exit_status: Option<i32>) -> Result<(), String> {
    check_profile(
        serial,
        expected_build,
        exit_status,
        false,
        false,
        false,
        None,
    )
}
pub(crate) fn check_session(
    serial: &[u8],
    expected_build: &str,
    exit_status: Option<i32>,
) -> Result<(), String> {
    check_profile(
        serial,
        expected_build,
        exit_status,
        true,
        false,
        false,
        None,
    )
}
/// Exact typed Document(Crash) proof, with the same machine/footer grammar.
/// All ordinary check/state entrypoints keep their strict identity behavior.
pub(crate) fn check_document_crash(
    serial: &[u8],
    expected_build: &str,
    exit_status: Option<i32>,
    proof: &crate::document_crash::Proof,
) -> Result<(), String> {
    if !proof.matches(serial, expected_build) {
        return Err("document crash boot proof belongs to different raw serial/build".into());
    }
    check_checked_profile(
        serial,
        expected_build,
        exit_status,
        true,
        false,
        false,
        None,
        Some(proof),
    )
}
pub(crate) fn check_network(
    serial: &[u8],
    expected_build: &str,
    exit_status: Option<i32>,
) -> Result<(), String> {
    check_profile(serial, expected_build, exit_status, true, true, false, None)
}
pub(crate) fn check_network_recovery(
    serial: &[u8],
    expected_build: &str,
    exit_status: Option<i32>,
) -> Result<(), String> {
    check_profile(serial, expected_build, exit_status, true, true, true, None)
}
pub(crate) fn check_network_negative(
    serial: &[u8],
    expected_build: &str,
    exit_status: Option<i32>,
    cancelled: &crate::network_negative::records::Cancelled,
) -> Result<(), String> {
    if !cancelled.matches(serial) {
        return Err("negative boot proof belongs to another raw serial".into());
    }
    let observed = crate::network_negative::records::records(serial, expected_build, None)?;
    crate::network_negative::retirement::complete(
        serial,
        expected_build,
        observed.rows(),
        cancelled.count() != 0,
    )?;
    check_profile(
        serial,
        expected_build,
        exit_status,
        true,
        true,
        false,
        Some(cancelled),
    )
}
fn check_profile(
    serial: &[u8],
    expected_build: &str,
    exit_status: Option<i32>,
    session: bool,
    network: bool,
    network_recovery: bool,
    negative: Option<&crate::network_negative::records::Cancelled>,
) -> Result<(), String> {
    check_checked_profile(
        serial,
        expected_build,
        exit_status,
        session,
        network,
        network_recovery,
        negative,
        None,
    )
}
#[allow(clippy::too_many_arguments)] // Explicit separate typed document experiment.
fn check_checked_profile(
    serial: &[u8],
    expected_build: &str,
    exit_status: Option<i32>,
    session: bool,
    network: bool,
    network_recovery: bool,
    negative: Option<&crate::network_negative::records::Cancelled>,
    document_crash: Option<&crate::document_crash::Proof>,
) -> Result<(), String> {
    if document_crash.is_some_and(|p| !p.matches(serial, expected_build))
        || document_crash.is_some()
            && (!session || network || network_recovery || negative.is_some())
    {
        return Err("document crash proof outside its exact offline boot profile".into());
    }
    if serial.len() > 1024 * 1024 {
        return Err("serial output exceeded 1 MiB".into());
    }
    if negative.is_some_and(|proof| !proof.matches(serial)) {
        return Err("negative network proof belongs to different actual serial".into());
    }
    let startup = if network {
        crate::startup_protocol::record(serial, expected_build)?
    } else {
        None
    };
    if startup.is_some() && (negative.is_some() || network_recovery) {
        return Err("startup diagnostic outside ordinary Managed Network profile".into());
    }
    if network {
        crate::network_protocol::records(serial, expected_build)?;
        crate::network_error_protocol::records(serial, expected_build)?;
        crate::time_protocol::records(serial, expected_build)?;
        crate::time_proof_protocol::records(serial, expected_build)?;
        crate::tc_protocol::records(serial, expected_build)?;
        crate::te_protocol::records(serial, expected_build)?;
        crate::image_protocol::records(serial, expected_build)?;
        crate::downloaded_protocol::records(serial, expected_build, false)?;
        crate::update_protocol::records(serial, expected_build)?;
        crate::rpc_rejection_protocol::records(serial, expected_build)?;
    }
    let omitted = if session {
        let retention = if network_recovery {
            crate::session_protocol::retention_network_recovery(serial, expected_build)?
        } else {
            crate::session_protocol::retention(serial, expected_build)?
        };
        retention.omitted != 0
    } else {
        false
    };
    if exit_status != Some(protocol::QEMU_PASS_STATUS) {
        return Err(format!(
            "QEMU status {exit_status:?}; expected {}",
            protocol::QEMU_PASS_STATUS
        ));
    }
    let negative_protocol = negative
        .map(|proof| {
            crate::session_protocol::without_network_negative_diagnostics(
                serial,
                expected_build,
                proof,
            )
        })
        .transpose()?;
    let text = String::from_utf8_lossy(negative_protocol.as_deref().unwrap_or(serial));
    // This independent, complete-capture join admits only the current Managed
    // downloaded C UD2 fault. Legacy lifecycle syntax remains unchanged.
    let downloaded_fault = if network && !network_recovery && negative.is_none() {
        crate::startup_protocol::downloaded_fault_line(serial, expected_build)?
    } else {
        None
    };
    if text.contains("EVROSION_PANIC")
        || text.contains("EVROSION_BOOT_ERROR")
        || text.contains("status=FAIL")
    {
        return Err("guest reported a panic or boot failure".into());
    }
    let header = format!(
        "EVROSION_BOOT protocol={} build={expected_build}",
        protocol::VERSION
    );
    let mut stage = 0;
    let mut memory_seen = false;
    let mut bootstrap_seen = false;
    let mut paging_seen = false;
    let mut faults_seen = false;
    let mut user_seen = false;
    let mut timer_seen = false;
    let mut topology_seen = false;
    let mut smp_seen = false;
    let mut scheduler_seen = false;
    let mut threads_seen = false;
    let mut preempt_seen = false;
    let mut caps_seen = false;
    let mut ipc_seen = false;
    let mut binding_seen = false;
    let mut authority_lifetime_seen = false;
    let mut authority_scopes_seen = false;
    let mut incarnation_seen = false;
    let mut executable_seen = false;
    let mut activation_seen = false;
    let mut supervisor_seen = false;
    let mut services_seen = false;
    let mut rpc_seen = false;
    let mut service_restart_seen = false;
    let mut custody_seen = false;
    let mut recovery_cases_seen = false;
    let mut caprpc_seen = false;
    let mut discipline_seen = false;
    let mut block_seen = false;
    let mut block_phase = None;
    let mut shared_storage_seen = false;
    let mut store_seen = false;
    let mut generation_seen = false;
    let mut generation_budget_seen = false;
    let mut progress_expected = false;
    let mut progress_seen = false;
    let mut owner_ui = 0u8;
    let mut owner_prompt_seen = false;
    let mut owner_seen = false;
    let mut owner_budget_seen = false;
    let mut file_seen = false;
    let mut file_budget_seen = false;
    let mut native_started = false;
    let mut native_memory_started = false;
    let mut native_common_mode = None;
    let mut native_done = false;
    let mut native_diagnostic_report = 0u64;
    let mut native_job_query = 0u64;
    let mut native_diagnostic_origin = None;
    let mut native_raw_faults = 0u64;
    let mut native_crashes = 0u64;
    let mut ipc_started = false;
    let mut ipc_done = false;
    let mut provider_started = false;
    let mut provider_done = false;
    let mut desktop_started = false;
    let mut native_pre_gui_shell_fault = false;
    let mut desktop_done = false;
    let mut desktop_timeline = crate::desktop_protocol::Timeline::default();
    let mut desktop_lifecycles = 0usize;
    let mut display_present_seen = false;
    let mut display_seen = false;
    let mut runtime_seen = false;
    let mut waits_seen = false;
    let mut retire_seen = false;
    let mut reclaim_seen = false;
    let mut shared_seen = false;
    let mut jobs_seen = false;
    let mut job_frames = 0;
    let mut revoke_seen = false;
    let mut fx_seen = false;
    let mut fault_delivery_seen = false;
    let mut allocation_seen = false;
    let mut user_quanta = 0;
    let mut topology_cpus = 0;
    let mut topology_bsp = 0;
    let mut usable_bytes = 0;
    let mut session_restart_seen = false;
    let mut session_prefix_closed = false;
    let mut session_log_seen = false;
    let mut session_padding_count = 0;
    let mut session_memory_before = false;
    let mut session_memory_held = false;
    let mut session_profile_count = 0;
    let mut session_image_cleanup = false;
    for (at, line) in text
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.is_empty())
    {
        if stage == 4 {
            return Err("output follows the final PASS record".into());
        }
        if session_prefix_closed
            && (line.starts_with("EVROSION_M4_DESKTOP_STEP")
                || line.starts_with("EVROSION_M4_DESKTOP_LIFECYCLE")
                || line.starts_with("EVROSION_M5_NATIVE_ACTION")
                || line.starts_with("EVROSION_M5_NATIVE_CRITICAL_READY")
                || line.starts_with("EVROSION_M5_NATIVE_SELF_IDENTITY")
                || line.starts_with("EVROSION_M5_NATIVE_MANAGED_READ")
                || line.starts_with("EVROSION_M5_NATIVE_INHIBIT")
                || (line.starts_with("EVROSION_NATIVE_")
                    && !line.starts_with("EVROSION_NATIVE_STATE ")))
        {
            return Err("ordinary session detail follows its retention boundary".into());
        }
        if ipc_started
            && !line.starts_with("EVROSION_M5_IPC")
            && !line.starts_with("EVROSION_M1_")
            && line != protocol::PASS
        {
            return Err("IPC benchmark mixed another graph".into());
        }
        if provider_started
            && !line.starts_with("EVROSION_M5_PROVIDER")
            && !line.starts_with("EVROSION_M1_")
            && line != protocol::PASS
        {
            return Err("provider experiment mixed another boot profile".into());
        }
        if (desktop_started || native_pre_gui_shell_fault)
            && (line.starts_with("EVROSION_M3_")
                || line.starts_with("EVROSION_M4_PRESENT ")
                || line.starts_with("EVROSION_M4_DISPLAY "))
        {
            return Err("desktop graph cannot mix another storage/display experiment".into());
        }
        if line.starts_with("EVROSION_BOOT ") {
            if stage != 0 || line != header {
                return Err("duplicate, unsupported or wrong-build boot header".into());
            }
            stage = 1;
        } else if line.starts_with("EVROSION_FRAMEBUFFER ") {
            if stage != 1 {
                return Err("duplicate or out-of-order framebuffer record".into());
            }
            framebuffer(line)?;
            stage = 2;
        } else if line.starts_with("EVROSION_MEMORY ") {
            if stage != 2 || memory_seen {
                return Err("duplicate or out-of-order memory record".into());
            }
            let fields: Vec<_> = line.split(' ').collect();
            if fields.len() != 3 || number(fields[1], "regions=")? == 0 {
                return Err("malformed memory record".into());
            }
            usable_bytes = number(fields[2], "usable_bytes=")?;
            memory_seen = true;
        } else if line == protocol::ENTERED {
            if stage != 2 {
                return Err("duplicate or out-of-order kernel entry marker".into());
            }
            stage = 3;
        } else if line.starts_with("EVROSION_M1_BOOTSTRAP ") {
            if stage != 3 || !memory_seen || bootstrap_seen {
                return Err("duplicate or out-of-order M1 bootstrap record".into());
            }
            bootstrap(line, usable_bytes)?;
            bootstrap_seen = true;
        } else if line.starts_with("EVROSION_M1_PAGING ") {
            if stage != 3 || !bootstrap_seen || paging_seen {
                return Err("duplicate or out-of-order M1 paging record".into());
            }
            paging(line)?;
            paging_seen = true;
        } else if line.starts_with("EVROSION_M1_FAULTS ") {
            if stage != 3
                || !paging_seen
                || faults_seen
                || line
                    != "EVROSION_M1_FAULTS status=PASS readonly=true noexecute=true unmapped=true recovered=3"
            {
                return Err("missing, malformed or out-of-order protection fault proof".into());
            }
            faults_seen = true;
        } else if line.starts_with("EVROSION_M1_USER ") {
            if stage != 3 || !faults_seen || user_seen {
                return Err("duplicate or out-of-order user isolation proof".into());
            }
            user(line)?;
            user_seen = true;
        } else if line.starts_with("EVROSION_M1_TIMER ") {
            if stage != 3 || !user_seen || timer_seen {
                return Err("duplicate or out-of-order timer proof".into());
            }
            let fields: Vec<_> = line.split(' ').collect();
            if fields.len() != 6
                || fields[1] != "status=PASS"
                || fields[4] != "masked_bound=true"
                || fields[5] != "interrupts_off=true"
                || number(fields[3], "deadline=")? != 8
                || !(8..=64).contains(&number(fields[2], "ticks=")?)
            {
                return Err("malformed timer/deadline proof".into());
            }
            timer_seen = true;
        } else if line.starts_with("EVROSION_M1_TOPOLOGY ") {
            if stage != 3 || !timer_seen || topology_seen {
                return Err("duplicate or out-of-order topology proof".into());
            }
            let fields: Vec<_> = line.split(' ').collect();
            if fields.len() != 5
                || fields[1] != "status=PASS"
                || !(1..=64).contains(&number(fields[2], "enabled=")?)
                || number(fields[3], "bsp=")? > u32::MAX as u64
            {
                return Err("malformed topology proof".into());
            }
            let lapic = fields[4].strip_prefix("lapic=0x").ok_or("missing LAPIC")?;
            if lapic.is_empty()
                || !lapic
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            {
                return Err("malformed LAPIC".into());
            }
            let lapic = u64::from_str_radix(lapic, 16).map_err(|_| "invalid LAPIC")?;
            if lapic == 0 || lapic >= 1 << 52 || lapic % 4096 != 0 {
                return Err("invalid LAPIC bounds".into());
            }
            topology_seen = true;
            topology_cpus = number(fields[2], "enabled=")?;
            topology_bsp = number(fields[3], "bsp=")?;
        } else if line.starts_with("EVROSION_M1_SMP ") {
            if stage != 3 || !topology_seen || smp_seen {
                return Err("duplicate or out-of-order SMP proof".into());
            }
            if line == "EVROSION_M1_SMP status=SKIP reason=single_cpu" {
                if topology_cpus != 1 {
                    return Err("SMP skip requires exactly one CPU".into());
                }
            } else {
                let fields: Vec<_> = line.split(' ').collect();
                if fields.len() != 7
                    || fields[1] != "status=PASS"
                    || fields[2] != "online=2"
                    || number(fields[3], "ap=")? >= 255
                    || number(fields[3], "ap=")? == topology_bsp
                    || topology_cpus < 2
                    || fields[5] != "shared=20000"
                    || fields[6] != "parked=true"
                {
                    return Err("malformed SMP handshake proof".into());
                }
                let root = fields[4].strip_prefix("root=0x").ok_or("missing AP root")?;
                if root.is_empty()
                    || !root
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                {
                    return Err("malformed AP root".into());
                }
                let root = u64::from_str_radix(root, 16).map_err(|_| "invalid AP root")?;
                if root == 0 || root >= 1 << 32 || root % 4096 != 0 {
                    return Err("invalid AP root bounds".into());
                }
            }
            smp_seen = true;
        } else if line.starts_with("EVROSION_M1_SCHEDULER ") {
            if stage != 3
                || !smp_seen
                || scheduler_seen
                || line
                    != "EVROSION_M1_SCHEDULER status=PASS scope=policy threads=2 jobs=2 dispatches=36 signal=true deadline=true stale_rejected=true"
            {
                return Err("missing, malformed or out-of-order scheduler policy proof".into());
            }
            scheduler_seen = true;
        } else if line.starts_with("EVROSION_M1_THREADS ") {
            if stage != 3
                || !scheduler_seen
                || threads_seen
                || line
                    != "EVROSION_M1_THREADS status=PASS threads=2 dispatches=36 switches=72 guards=4 registers=true stacks=true signal=true deadline=true exited=true"
            {
                return Err("missing, malformed or out-of-order thread context proof".into());
            }
            threads_seen = true;
        } else if line.starts_with("EVROSION_M1_PREEMPT ") {
            if stage != 3 || !threads_seen || preempt_seen {
                return Err("duplicate or out-of-order preemption proof".into());
            }
            let fields: Vec<_> = line.split(' ').collect();
            if fields.len() != 7
                || fields[1] != "status=PASS"
                || fields[2] != "threads=2"
                || fields[5] != "progress=true"
                || fields[6] != "restored=true"
            {
                return Err("malformed preemption proof".into());
            }
            let quanta = number(fields[3], "quanta=")?;
            if !(8..=64).contains(&quanta) || number(fields[4], "dispatches=")? != quanta + 2 {
                return Err("invalid preemption counts".into());
            }
            preempt_seen = true;
        } else if line.starts_with("EVROSION_M1_CAPS ") {
            if stage != 3
                || !preempt_seen
                || caps_seen
                || line
                    != "EVROSION_M1_CAPS status=PASS scope=tables attenuation=true transfer=true revocation=true stale=true denial=true lifetime=true"
            {
                return Err("missing, malformed or out-of-order capability table proof".into());
            }
            caps_seen = true;
        } else if line.starts_with("EVROSION_M1_IPC ") {
            if stage != 3
                || !caps_seen
                || ipc_seen
                || line
                    != "EVROSION_M1_IPC status=PASS scope=mailbox bounded=true escrow=true delivery=true deadline=true death_return=true"
            {
                return Err("missing, malformed or out-of-order mailbox proof".into());
            }
            ipc_seen = true;
        } else if line.starts_with("EVROSION_M2_BINDING ") {
            if stage != 3
                || !ipc_seen
                || binding_seen
                || runtime_seen
                || line
                    != "EVROSION_M2_BINDING status=PASS scope=fixture grants=2 measured=true resolved=true atomic=true attenuated=true revoked=true"
            {
                return Err("duplicate, malformed or out-of-order M2 binding proof".into());
            }
            binding_seen = true;
        } else if line.starts_with("EVROSION_M2_LIFETIME ") {
            if stage != 3
                || !binding_seen
                || authority_lifetime_seen
                || runtime_seen
                || line
                    != "EVROSION_M2_LIFETIME status=PASS scope=authority cycles=64 reclaimed=128 old_space_denied=true stale_handles_denied=true"
            {
                return Err(
                    "duplicate, malformed or out-of-order M2 authority lifetime proof".into(),
                );
            }
            authority_lifetime_seen = true;
        } else if line.starts_with("EVROSION_M2_SCOPES ") {
            if stage != 3
                || !authority_lifetime_seen
                || authority_scopes_seen
                || runtime_seen
                || line
                    != "EVROSION_M2_SCOPES status=PASS scope=authority cycles=64 revoked=128 roots_preserved=true peers_preserved=true stale_revoke_denied=true"
            {
                return Err("duplicate, malformed or out-of-order M2 authority scope proof".into());
            }
            authority_scopes_seen = true;
        } else if line.starts_with("EVROSION_M2_INCARNATION ") {
            if stage != 3
                || !authority_scopes_seen
                || incarnation_seen
                || runtime_seen
                || line
                    != "EVROSION_M2_INCARNATION status=PASS scope=prepared bindings=2 held=true stale_events_denied=true limits=true revoked=true"
            {
                return Err("duplicate, malformed or out-of-order M2 incarnation proof".into());
            }
            incarnation_seen = true;
        } else if line.starts_with("EVROSION_M2_EXECUTABLE ") {
            if stage != 3
                || !incarnation_seen
                || executable_seen
                || runtime_seen
                || line
                    != "EVROSION_M2_EXECUTABLE status=PASS scope=loader segments=2 pages=5 frames=9 cpl3=5 measured=true zeroed=true wx=true guarded=true reclaimed=true"
            {
                return Err("duplicate, malformed or out-of-order M2 executable proof".into());
            }
            executable_seen = true;
        } else if line.starts_with("EVROSION_M2_ACTIVATION ") {
            if stage != 3
                || !executable_seen
                || activation_seen
                || runtime_seen
                || line
                    != "EVROSION_M2_ACTIVATION status=PASS scope=fixture attempts=2 admitted=1 rejected=1 cpl3=1 rechecked=true stale_denied=true inhibited=true peers_preserved=true frames=18 reclaimed=true"
            {
                return Err("duplicate, malformed or out-of-order M2 activation proof".into());
            }
            activation_seen = true;
        } else if line.starts_with("EVROSION_M2_SUPERVISOR ") {
            if stage != 3
                || !activation_seen
                || supervisor_seen
                || runtime_seen
                || line
                    != "EVROSION_M2_SUPERVISOR status=PASS scope=bootstrap images=2 ready=2 faults=1 denied=4 readonly=true measured=true authority=true stopped=true reclaimed=true"
            {
                return Err(
                    "duplicate, malformed or out-of-order supervisor bootstrap proof".into(),
                );
            }
            supervisor_seen = true;
        } else if line.starts_with("EVROSION_M2_SERVICES ") {
            if stage != 3
                || !supervisor_seen
                || services_seen
                || runtime_seen
                || line
                    != "EVROSION_M2_SERVICES status=PASS scope=launch graphs=2 children=2 requests=5 replies=4 cancelled=1 faults=1 control_denied=8 service_denied=8 event_denied=6 delegated=4 observed=true held=true isolated=true measured=true reclaimed=true"
            {
                return Err("duplicate, malformed or out-of-order service launch proof".into());
            }
            services_seen = true;
        } else if line.starts_with("EVROSION_M2_RPC ") {
            if stage != 3
                || !services_seen
                || rpc_seen
                || runtime_seen
                || line
                    != "EVROSION_M2_RPC status=PASS scope=transport successes=7 accepted=8 blocks=8 wakes=8 denied=2 expired=2 timeouts=1 busy=true late=1 stale=true reclaimed=true"
            {
                return Err("duplicate, malformed or out-of-order synchronous RPC proof".into());
            }
            rpc_seen = true;
        } else if line.starts_with("EVROSION_M2_RESTART ") {
            if stage != 3
                || !rpc_seen
                || service_restart_seen
                || runtime_seen
                || line
                    != "EVROSION_M2_RESTART status=PASS scope=service cycles=64 faults=64 peer_replies=128 victim_replies=64 starts=66 stale=true root_preserved=true frames=true metadata=true reclaimed=true"
            {
                return Err("duplicate, malformed or out-of-order service restart proof".into());
            }
            service_restart_seen = true;
        } else if line.starts_with("EVROSION_M2_CUSTODY ") {
            if stage != 3
                || !service_restart_seen
                || custody_seen
                || runtime_seen
                || line
                    != "EVROSION_M2_CUSTODY status=PASS scope=graph incarnations=4 replacements=3 root_faults=4 graphs=4 service_starts=8 service_replies=8 accepted_transfers=4 rejected_transfers=4 invalidated_transfers=4 recovery=1 unique=true authority=true graph=true budget=true stale=true frames=true metadata=true independent=true"
            {
                return Err("duplicate, malformed or out-of-order custodian graph proof".into());
            }
            custody_seen = true;
        } else if line.starts_with("EVROSION_M2_RECOVERY_CASES ") {
            if stage != 3
                || !custody_seen
                || recovery_cases_seen
                || runtime_seen
                || line
                    != "EVROSION_M2_RECOVERY_CASES status=PASS scope=failure cases=11 faults=6 exits=4 watchdogs=4 interruptions=6 integrity=3 attempts=33 charged=24 held=20 admitted=16 active=15 graphs=14 starts=28 replies=28 transfers=14 rejected=14 invalidated=14 recovery=11 retired=true frames=true unique=true budget=true selection=true grants=true"
            {
                return Err("duplicate, malformed or out-of-order recovery failure proof".into());
            }
            recovery_cases_seen = true;
        } else if line.starts_with("EVROSION_M2_CAPRPC ") {
            if stage != 3
                || !recovery_cases_seen
                || caprpc_seen
                || runtime_seen
                || line
                    != "EVROSION_M2_CAPRPC status=PASS scope=transport worlds=5 accepted=8 blocks=8 wakes=8 delivered=6 returned=4 refunded=2 no_refund=2 timeouts=2 faults=2 late=1 stale=1 wrong_object=1 rejected=3 busy=true exits=5 frames=true metadata=true"
            {
                return Err("duplicate, malformed or out-of-order capability RPC proof".into());
            }
            caprpc_seen = true;
        } else if line.starts_with("EVROSION_M2_IPC_DISCIPLINE ") {
            if stage != 3
                || !caprpc_seen
                || discipline_seen
                || runtime_seen
                || line
                    != "EVROSION_M2_IPC_DISCIPLINE status=PASS scope=threads worlds=2 calls=10 blocks=10 wakes=10 delivered=10 replies=10 contexts=10 spawned=6 exits=2 mutex_acquired=1 mutex_released=1 no_wait=1 cycles=1 extended=1 depth=1 wrong_thread=1 max_depth=8 stacks=true frames=true metadata=true"
            {
                return Err("duplicate, malformed or out-of-order IPC discipline proof".into());
            }
            discipline_seen = true;
        } else if line.starts_with("EVROSION_M5_IPC") {
            if stage != 3
                || !discipline_seen
                || ipc_done
                || runtime_seen
                || provider_started
                || native_started
                || desktop_started
                || block_seen
                || store_seen
                || generation_seen
                || owner_seen
                || file_seen
                || display_present_seen
            {
                return Err("mixed/out-of-order IPC benchmark receipt".into());
            }
            crate::ipc_bench_protocol::line(line, expected_build)?;
            if line.starts_with("EVROSION_M5_IPC ") {
                crate::ipc_bench_protocol::check_unbound(serial, expected_build)?;
                ipc_done = true;
            }
            ipc_started = true;
        } else if line.starts_with("EVROSION_M5_PROVIDER") {
            if stage != 3
                || !discipline_seen
                || provider_done
                || runtime_seen
                || native_started
                || desktop_started
                || block_seen
                || store_seen
                || generation_seen
                || owner_seen
                || file_seen
                || display_present_seen
            {
                return Err("mixed/out-of-order provider receipt".into());
            }
            if line.starts_with("EVROSION_M5_PROVIDER_LIFECYCLE ") {
                crate::provider_protocol::lifecycle_line(line, expected_build)?;
            } else if line.starts_with("EVROSION_M5_PROVIDER_BIND ") {
                crate::provider_protocol::binding_line(line, expected_build)?;
            } else if line.starts_with("EVROSION_M5_PROVIDER_CALL ") {
                crate::provider_protocol::call_line(line, expected_build)?;
            } else if line.starts_with("EVROSION_M5_PROVIDER ") {
                if !provider_started {
                    return Err("provider completion lacks actual history".into());
                }
                crate::provider_protocol::check_unbound(serial, expected_build)?;
                provider_done = true;
            } else {
                return Err("unknown provider diagnostic".into());
            }
            provider_started = true;
        } else if line.starts_with("EVROSION_M5_NATIVE_MEMORY ")
            || line.starts_with("EVROSION_M5_NATIVE_KERNEL_MEMORY ")
        {
            if stage != 3
                || !discipline_seen
                || native_done
                || desktop_done
                || runtime_seen
                || provider_started
                || block_seen
                || store_seen
                || generation_seen
                || owner_seen
                || file_seen
                || display_present_seen
            {
                return Err("mixed/out-of-order actual Native memory snapshot".into());
            }
            crate::native_baselines::line(line, expected_build)?;
            if session && line.starts_with("EVROSION_M5_NATIVE_MEMORY ") {
                match line.split(' ').nth(3) {
                    Some("phase=before")
                        if !session_memory_before
                            && session_padding_count == 0
                            && !native_started =>
                    {
                        session_memory_before = true;
                    }
                    Some("phase=held") if session_padding_count == 2 && !session_memory_held => {
                        session_memory_held = true;
                    }
                    Some("phase=after") if session_memory_held => {}
                    _ => return Err("session padding/memory boundary order differs".into()),
                }
            }
            native_memory_started = true;
        } else if startup.as_ref().is_some_and(|r| r.contains_line(at)) {
            if !network
                || negative.is_some()
                || network_recovery
                || stage != 3
                || !native_started
                || native_done
                || session_prefix_closed
                || session_log_seen
            {
                return Err(
                    "startup diagnostic outside selected live Managed Network profile".into(),
                );
            }
        } else if line.starts_with("EVROSION_M6_NEGATIVE") {
            if negative.is_none()
                || !network
                || stage != 3
                || !native_started
                || native_done
                || session_log_seen
            {
                return Err("negative observation outside selected live qualification".into());
            }
            crate::network_negative::records::line(line, expected_build)?;
        } else if line.starts_with("EVROSION_M6_DOWNLOADED_ACTION") {
            crate::downloaded_protocol::line(line, expected_build)?;
            if !network
                || stage != 3
                || !native_started
                || native_done
                || session_prefix_closed
                || session_image_cleanup
                || session_log_seen
            {
                return Err("downloaded action outside selected live Network profile".into());
            }
        } else if line.starts_with("EVROSION_M6_RESTART") {
            crate::restart_protocol::line(line, expected_build)?;
            if !network
                || stage != 3
                || !native_started
                || native_done
                || session_prefix_closed
                || session_image_cleanup
                || session_log_seen
                || session_restart_seen
            {
                return Err("restart intent outside selected live Network profile/replayed".into());
            }
            session_restart_seen = true;
        } else if line.starts_with("EVROSION_M6_IMAGE ") {
            let image = crate::image_protocol::line(line, expected_build)?;
            if !network
                || stage != 3
                || !native_started
                || native_done
                || session_log_seen
                || session_image_cleanup
                || ((image.op == 0) != session_memory_held)
                || (session_prefix_closed && image.op != 0)
            {
                return Err("dynamic image outside selected live/final profile".into());
            }
            session_image_cleanup = image.op == 0;
        } else if line.starts_with("EVROSION_M6_NETWORK_PROGRESS ")
            || line.starts_with("EVROSION_M6_TIME_PROGRESS ")
            || line.starts_with("EVROSION_M6_TIME_PROOF ")
            || line.starts_with("EVROSION_M6_TIME_CHECK ")
            || line.starts_with("EVROSION_M6_TIME_EXCHANGE ")
            || line.starts_with("EVROSION_M6_NETWORK_ERROR ")
            || line.starts_with("EVROSION_M6_UPDATE_PROGRESS ")
            || line.starts_with("EVROSION_M6_RPC_REJECTION ")
        {
            if !network
                || stage != 3
                || !native_started
                || native_done
                || session_prefix_closed
                || session_log_seen
            {
                return Err("network diagnostic outside selected live profile".into());
            }
            if line.starts_with("EVROSION_M6_NETWORK_PROGRESS ") {
                crate::network_protocol::line(line, expected_build)?;
            } else if line.starts_with("EVROSION_M6_TIME_PROGRESS ") {
                crate::time_protocol::line(line, expected_build)?;
            } else if line.starts_with("EVROSION_M6_TIME_PROOF ") {
                crate::time_proof_protocol::line(line, expected_build)?;
            } else if line.starts_with("EVROSION_M6_TIME_CHECK ") {
                crate::tc_protocol::line(line, expected_build)?;
            } else if line.starts_with("EVROSION_M6_TIME_EXCHANGE ") {
                crate::te_protocol::line(line, expected_build)?;
            } else if line.starts_with("EVROSION_M6_UPDATE_PROGRESS ") {
                crate::update_protocol::line(line, expected_build)?;
            } else if line.starts_with("EVROSION_M6_RPC_REJECTION ") {
                crate::rpc_rejection_protocol::line(line, expected_build)?;
            } else {
                crate::network_error_protocol::line(line, expected_build)?;
            }
        } else if line.starts_with("EVROSION_M6_WINDOW_PADDING ") {
            if !session || stage != 3 || !discipline_seen || native_done || session_log_seen {
                return Err("out-of-order App window padding observation".into());
            }
            crate::session_protocol::window_padding(line, expected_build)?;
            match session_padding_count {
                0 if session_memory_before && !native_started && native_common_mode.is_none() => {}
                1 if native_started
                    && native_common_mode.is_some()
                    && !session_memory_held
                    && session_profile_count == if network { 9 } else { 7 } => {}
                _ => return Err("App padding lacks exact startup/final profile boundary".into()),
            }
            session_padding_count += 1;
        } else if line.starts_with("EVROSION_M6_LOG_BOUND ") {
            if !session
                || stage != 3
                || !native_started
                || session_prefix_closed
                || session_log_seen
            {
                return Err("out-of-order session retention boundary".into());
            }
            session_prefix_closed = true;
        } else if line.starts_with("EVROSION_M6_LOG ") {
            if !session || stage != 3 || !native_started || session_log_seen || native_done {
                return Err("out-of-order session retention summary".into());
            }
            session_log_seen = true;
        } else if line.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX ") {
            if stage != 3
                || !discipline_seen
                || native_common_mode.is_some()
                || native_started
                || native_done
                || desktop_done
                || runtime_seen
                || block_seen
                || store_seen
                || generation_seen
                || provider_started
            {
                return Err("mixed/duplicate/out-of-order Native common prefix".into());
            }
            if session && session_padding_count != 1 {
                return Err("session CommonPrefix lacks startup padding observation".into());
            }
            if network {
                crate::native3_protocol::line_network(line, expected_build)?;
            } else {
                crate::native3_protocol::line(line, expected_build)?;
            }
            let fields: Vec<_> = line.split(' ').collect();
            native_common_mode = Some(canonical_number(fields[3], "mode")?);
            native_started = true;
        } else if [
            "EVROSION_M5_NATIVE_MANAGED_READ ",
            "EVROSION_M5_NATIVE_INHIBIT ",
            "EVROSION_M5_NATIVE_CRITICAL_READY ",
            "EVROSION_M5_NATIVE_SELF_IDENTITY ",
        ]
        .iter()
        .any(|prefix| line.starts_with(prefix))
        {
            if stage != 3
                || !discipline_seen
                || native_common_mode.is_none()
                || native_done
                || desktop_done
                || runtime_seen
            {
                return Err("mixed/out-of-order Native mechanism receipt".into());
            }
            if session {
                crate::native3_protocol::line_session(line, expected_build)?;
            } else {
                crate::native3_protocol::line(line, expected_build)?;
            }
        } else if line.starts_with("EVROSION_NATIVE_OWNER_TEXT ") {
            if stage != 3
                || native_common_mode.is_none()
                || native_done
                || desktop_done
                || runtime_seen
            {
                return Err("out-of-order Native owner human prompt".into());
            }
            crate::native3_diagnostics::owners(serial, expected_build)?;
        } else if [
            "EVROSION_NATIVE_CRASH",
            "EVROSION_NATIVE_JOB",
            "EVROSION_NATIVE_SYSTEM",
            "EVROSION_NATIVE_FAULT",
            "EVROSION_NATIVE_OWNER_PROMPT",
        ]
        .iter()
        .any(|prefix| line.starts_with(prefix))
        {
            if stage != 3
                || !discipline_seen
                || !native_started
                || (!desktop_started && native_common_mode.is_none())
                || native_done
                || desktop_done
                || runtime_seen
                || block_seen
                || store_seen
                || generation_seen
                || owner_seen
                || file_seen
                || display_present_seen
            {
                return Err("mixed/out-of-order Native structured diagnostic".into());
            }
            crate::native_diagnostics::line(line, expected_build)?;
            let fields: Vec<_> = line.split(' ').collect();
            if line.starts_with("EVROSION_NATIVE_FAULT ") {
                native_raw_faults += 1;
                if !session && native_raw_faults > 2 {
                    return Err("Native raw fault archive bound exceeded".into());
                }
            } else {
                let origin = (
                    canonical_number(fields[4], "root_process")?,
                    canonical_number(fields[5], "root_thread")?,
                );
                if native_diagnostic_origin.is_some_and(|old| old != origin) {
                    return Err("Native diagnostic origin changed".into());
                }
                native_diagnostic_origin = Some(origin);
                if line.starts_with("EVROSION_NATIVE_JOB_FIELD ") {
                    native_job_query += 1;
                    if (!session && native_job_query > 512)
                        || canonical_number(fields[3], "sequence")? != native_job_query
                    {
                        return Err("Native query sequence replay/gap/overflow".into());
                    }
                } else {
                    native_diagnostic_report += 1;
                    if (!session && native_diagnostic_report > 64)
                        || canonical_number(fields[3], "report")? != native_diagnostic_report
                    {
                        return Err("Native diagnostic sequence replay/gap/overflow".into());
                    }
                    if line.starts_with("EVROSION_NATIVE_CRASH ") {
                        native_crashes += 1;
                        if native_crashes > native_raw_faults {
                            return Err("Native capsule precedes its actual trap".into());
                        }
                    }
                }
            }
        } else if line.starts_with("EVROSION_NATIVE_STATE") {
            if stage != 3 || !discipline_seen || native_done || desktop_done || runtime_seen {
                return Err("out-of-order Native state diagnostic".into());
            }
            let state = if let Some(proof) = document_crash {
                proof.state_line(line, expected_build)?
            } else if network {
                crate::native_protocol::state_line_network(line, expected_build)?
            } else {
                crate::native_protocol::state_line(line, expected_build)?
            };
            if session_prefix_closed && !state.is("finish") {
                return Err("ordinary state follows session retention boundary".into());
            }
            native_started = true;
        } else if line.starts_with("EVROSION_M5_NATIVE_ACTION") {
            if stage != 3
                || !discipline_seen
                || native_done
                || desktop_done
                || runtime_seen
                || block_seen
                || store_seen
                || generation_seen
                || owner_seen
                || file_seen
                || display_present_seen
            {
                return Err("mixed/out-of-order Native action".into());
            }
            crate::native_protocol::action(line, expected_build)?;
            native_started = true;
        } else if line.starts_with("EVROSION_M5_NATIVE_PROFILE") {
            if stage != 3
                || !discipline_seen
                || !native_started
                || (!desktop_started && native_common_mode.is_none())
                || native_done
                || desktop_done
                || runtime_seen
                || block_seen
                || store_seen
                || generation_seen
                || owner_seen
                || file_seen
                || display_present_seen
            {
                return Err("mixed/out-of-order Native scheduling profile".into());
            }
            let profile = if network {
                crate::native_profile::line_network(line, expected_build)?
            } else {
                crate::native_profile::line(line, expected_build)?
            };
            if session {
                if session_padding_count != 1 || profile.counts["index"] != session_profile_count {
                    return Err(
                        "session profile batch replayed or outside padding boundaries".into(),
                    );
                }
                session_profile_count += 1;
            }
        } else if line.starts_with("EVROSION_M5_NATIVE_RECOVERY ") {
            if stage != 3
                || network && !network_recovery
                || !discipline_seen
                || native_common_mode != Some(2)
                || desktop_started
                || native_done
                || desktop_done
                || runtime_seen
            {
                return Err(
                    "mixed/duplicate/out-of-order independent Native recovery completion".into(),
                );
            }
            let record = if network {
                crate::native3_protocol::record_network_recovery(serial, expected_build)?
            } else {
                crate::native3_protocol::record(serial, expected_build, true)?
            };
            if native_memory_started {
                crate::native_baselines::memory(serial, expected_build)?;
            }
            let profile = if network {
                crate::native_profile::finished_network(
                    serial,
                    expected_build,
                    record.counts["faults"],
                    native_common_mode,
                )?
            } else {
                crate::native_profile::finished(
                    serial,
                    expected_build,
                    record.counts["faults"],
                    native_common_mode,
                )?
            };
            if native_raw_faults != 0
                || native_crashes != 0
                || native_diagnostic_origin.is_some_and(|origin| {
                    origin
                        != (
                            profile[0].counts["current_process"],
                            profile[0].counts["current_thread"],
                        )
                })
            {
                return Err("Native recovery lacks actualRoot origin or invented fault".into());
            }
            native_done = true;
            desktop_done = true;
        } else if line.starts_with("EVROSION_M5_NATIVE ") {
            if stage != 3
                || network_recovery
                || !discipline_seen
                || (!desktop_started && native_common_mode != Some(1))
                || native_done
                || desktop_done
                || runtime_seen
            {
                return Err("duplicate/out-of-order Native completion".into());
            }
            let record = if session {
                if !session_log_seen || session_padding_count != 2 {
                    return Err("session completion lacks final retention accounting".into());
                }
                if network {
                    if let Some(proof) = negative {
                        crate::native_protocol::record_network_negative(
                            serial,
                            expected_build,
                            proof,
                        )?
                    } else {
                        crate::native_protocol::record_network(serial, expected_build)?
                    }
                } else if let Some(proof) = document_crash {
                    crate::native_protocol::record_document_crash(serial, expected_build, proof)?
                } else {
                    crate::native_protocol::record_session(serial, expected_build)?
                }
            } else {
                crate::native_protocol::record(serial, expected_build)?
            };
            if native_pre_gui_shell_fault {
                if desktop_started
                    || desktop_lifecycles != 1
                    || native_raw_faults != 1
                    || native_crashes != 1
                    || record.counts["processes"] != 6
                    || record.counts["starts"] != 6
                    || record.counts["faults"] != 1
                    || record.counts["restarts"] != 0
                    || record.counts["grants"] != 0
                    || record.counts["app_a_starts"] != 0
                    || record.counts["app_b_starts"] != 0
                    || !record.actions.is_empty()
                {
                    return Err(
                        "Native pre-GUI Shell fault mixed App, restart or desktop execution".into(),
                    );
                }
            } else if !desktop_started && record.counts["faults"] != 0 {
                return Err("Native pre-GUI fault lacks its one initial Shell lifecycle".into());
            }
            if native_memory_started {
                crate::native_baselines::memory(serial, expected_build)?;
            }
            let profile = if network {
                crate::native_profile::finished_network(
                    serial,
                    expected_build,
                    record.counts["faults"],
                    native_common_mode,
                )?
            } else if session {
                crate::native_profile::finished_session(
                    serial,
                    expected_build,
                    record.counts["faults"],
                    native_common_mode,
                )?
            } else {
                crate::native_profile::finished(
                    serial,
                    expected_build,
                    record.counts["faults"],
                    native_common_mode,
                )?
            };
            if native_pre_gui_shell_fault
                && (profile[1].counts["incarnations"] != 1
                    || profile[1].counts["faults"] != 1
                    || profile[5].counts["incarnations"] != 0
                    || profile[5].counts["captures"] != 0)
            {
                return Err("Native pre-GUI profile mixed another Shell or App incarnation".into());
            }
            if (!omitted && native_raw_faults != native_crashes)
                || native_diagnostic_origin.is_some_and(|origin| {
                    origin
                        != (
                            profile[0].counts["current_process"],
                            profile[0].counts["current_thread"],
                        )
                })
            {
                return Err("Native diagnostics lack matched traps or actual Root origin".into());
            }
            native_done = true;
            desktop_done = true;
        } else if line.starts_with("EVROSION_M4_DESKTOP_STEP ") {
            if stage != 3
                || !discipline_seen
                || native_pre_gui_shell_fault
                || desktop_done
                || block_seen
                || store_seen
                || generation_seen
                || owner_seen
                || owner_prompt_seen
                || file_seen
                || display_present_seen
                || runtime_seen
            {
                return Err("mixed/out-of-order desktop step".into());
            }
            let step = crate::desktop_protocol::step_line(line, expected_build)?;
            if session {
                desktop_timeline.observe_session(&step)?;
            } else {
                desktop_timeline.observe(&step)?;
            }
            desktop_started = true;
        } else if line.starts_with("EVROSION_M4_DESKTOP_LIFECYCLE ") {
            if stage != 3
                || desktop_done
                || runtime_seen
                || native_pre_gui_shell_fault
                || (!session && desktop_lifecycles >= 4)
            {
                return Err("out-of-order desktop lifecycle".into());
            }
            if downloaded_fault == Some(at) {
                if !discipline_seen
                    || native_common_mode != Some(1)
                    || desktop_started
                    || desktop_lifecycles != 0
                    || native_raw_faults != 1
                {
                    return Err("out-of-order Managed downloaded fault".into());
                }
            } else if desktop_started {
                if session {
                    crate::desktop_protocol::lifecycle_syntax(line, expected_build)?;
                } else {
                    crate::desktop_protocol::lifecycle_line(line, expected_build)?;
                }
            } else {
                if !discipline_seen
                    || native_common_mode != Some(1)
                    || desktop_lifecycles != 0
                    || native_raw_faults != 1
                {
                    return Err("out-of-order or non-Managed initial Shell fault".into());
                }
                crate::desktop_protocol::initial_native_shell_fault_line(line, expected_build)?;
                native_pre_gui_shell_fault = true;
            }
            desktop_lifecycles += 1;
        } else if line.starts_with("EVROSION_M4_DESKTOP ") {
            if stage != 3
                || !desktop_started
                || desktop_done
                || runtime_seen
                || desktop_lifecycles != 4
                || native_started
            {
                return Err("out-of-order desktop final proof".into());
            }
            crate::desktop_protocol::line(line)?;
            crate::desktop_protocol::record(serial, expected_build)?;
            desktop_done = true;
        } else if line.starts_with("EVROSION_M4_PRESENT ") {
            if stage != 3
                || !discipline_seen
                || display_present_seen
                || block_seen
                || store_seen
                || generation_seen
                || owner_seen
                || owner_prompt_seen
                || file_seen
                || runtime_seen
            {
                return Err("duplicate, mixed or out-of-order display Present record".into());
            }
            crate::graphics_protocol::present_line(line, expected_build)?;
            display_present_seen = true;
        } else if line.starts_with("EVROSION_M4_DISPLAY ") {
            if stage != 3 || !display_present_seen || display_seen || runtime_seen {
                return Err("duplicate or out-of-order display lifecycle proof".into());
            }
            crate::graphics_protocol::line(line)?;
            display_seen = true;
        } else if line.starts_with("EVROSION_M3_BLOCK ") {
            if stage != 3
                || !discipline_seen
                || display_present_seen
                || block_seen
                || store_seen
                || generation_seen
                || owner_seen
                || owner_prompt_seen
                || file_seen
                || runtime_seen
            {
                return Err("duplicate or out-of-order storage PIO proof".into());
            }
            block_phase = Some(block_record(line)?.phase);
            block_seen = true;
        } else if line.starts_with("EVROSION_M3_TRANSPORT ") {
            if stage != 3
                || !block_seen
                || shared_storage_seen
                || store_seen
                || generation_seen
                || owner_seen
                || owner_prompt_seen
                || file_seen
                || runtime_seen
            {
                return Err("duplicate or out-of-order shared storage proof".into());
            }
            if Some(shared_record(line)?.phase) != block_phase {
                return Err("shared storage phase differs from block proof".into());
            }
            shared_storage_seen = true;
        } else if line.starts_with("EVROSION_M3_STORE ") {
            if stage != 3
                || !discipline_seen
                || display_present_seen
                || block_seen
                || store_seen
                || generation_seen
                || owner_seen
                || owner_prompt_seen
                || file_seen
                || runtime_seen
            {
                return Err("duplicate or out-of-order durable store proof".into());
            }
            store_record(line)?;
            store_seen = true;
        } else if line.starts_with("EVROSION_M3_FILE_BUDGET ") {
            if stage != 3 || !file_seen || file_budget_seen || runtime_seen {
                return Err("duplicate or out-of-order File/Object budget".into());
            }
            crate::file_protocol::budget_line(line)?;
            file_budget_seen = true;
        } else if line.starts_with("EVROSION_M3_FILE ") {
            if stage != 3
                || !discipline_seen
                || display_present_seen
                || block_seen
                || store_seen
                || generation_seen
                || owner_seen
                || owner_prompt_seen
                || file_seen
                || runtime_seen
            {
                return Err("duplicate or out-of-order File/Object proof".into());
            }
            crate::file_protocol::line(line)?;
            file_seen = true;
        } else if line.starts_with("Evrosion generation ")
            || owner_ui != 0
                && (line.starts_with("Failed image: ")
                    || line.starts_with("Current selection: ")
                    || line.starts_with("Known-good generation ")
                    || line.starts_with("Type r then ")
                    || line == "Please type r or q, then Enter.")
        {
            if stage != 3
                || !discipline_seen
                || display_present_seen
                || block_seen
                || store_seen
                || generation_seen
                || owner_seen
                || file_seen
                || runtime_seen
            {
                return Err("out-of-order owner recovery explanation".into());
            }
            owner_ui = crate::owner_protocol::ui_line(owner_ui, line, owner_prompt_seen)?;
        } else if line.starts_with("EVROSION_M3_OWNER_PROMPT ") {
            if stage != 3
                || !discipline_seen
                || owner_ui != 5
                || owner_prompt_seen
                || owner_seen
                || runtime_seen
            {
                return Err("duplicate or out-of-order owner prompt".into());
            }
            crate::owner_protocol::prompt_line(line, expected_build, None)?;
            owner_prompt_seen = true;
        } else if line.starts_with("EVROSION_M3_OWNER_BUDGET ") {
            if stage != 3 || !owner_seen || owner_budget_seen || runtime_seen {
                return Err("out-of-order owner budget".into());
            }
            crate::owner_protocol::budget_line(line)?;
            owner_budget_seen = true;
        } else if line.starts_with("EVROSION_M3_OWNER ") {
            if stage != 3
                || !discipline_seen
                || display_present_seen
                || block_seen
                || store_seen
                || generation_seen
                || owner_seen
                || file_seen
                || runtime_seen
            {
                return Err("duplicate or out-of-order owner proof".into());
            }
            let owner = crate::owner_protocol::line(line)?;
            if (owner.report.mode == ev_userspace_contract::generation::Mode::OwnerRecover)
                != owner_prompt_seen
            {
                return Err("owner action and actual prompt disagree".into());
            }
            owner_seen = true;
        } else if line.starts_with("EVROSION_M3_PROGRESS ") {
            if stage != 3
                || !generation_seen
                || !generation_budget_seen
                || !progress_expected
                || progress_seen
                || runtime_seen
            {
                return Err("duplicate or out-of-order service progress proof".into());
            }
            progress_line(line)?;
            progress_seen = true;
        } else if line.starts_with("EVROSION_M3_GENERATION_BUDGET ") {
            if stage != 3 || !generation_seen || generation_budget_seen || runtime_seen {
                return Err("duplicate or out-of-order generation budget proof".into());
            }
            generation_budget_line(line)?;
            generation_budget_seen = true;
        } else if line.starts_with("EVROSION_M3_GENERATION ") {
            if stage != 3
                || !discipline_seen
                || display_present_seen
                || block_seen
                || store_seen
                || generation_seen
                || owner_seen
                || owner_prompt_seen
                || file_seen
                || runtime_seen
            {
                return Err("duplicate or out-of-order generation proof".into());
            }
            let report = generation_line(line)?;
            progress_expected = report.mode == ev_userspace_contract::generation::Mode::FailB
                && report.failure_reason == 2;
            generation_seen = true;
        } else if line.starts_with("EVROSION_M3_STORE_CUT ") {
            return Err("an interrupted VM requires the dedicated cut-prefix checker".into());
        } else if line.starts_with("EVROSION_M1_RUNTIME ") {
            if stage != 3 || !ipc_seen || runtime_seen || display_present_seen && !display_seen {
                return Err("duplicate or out-of-order user runtime proof".into());
            }
            let fields: Vec<_> = line.split(' ').collect();
            if fields.len() != 10
                || fields[1] != "status=PASS"
                || fields[2] != "processes=6"
                || fields[3] != "faults=3"
                || fields[4] != "survivors=3"
                || fields[5] != "messages=3"
                || fields[7] != "isolated=true"
                || fields[8] != "authority=true"
                || fields[9] != "restored=true"
            {
                return Err("malformed user runtime proof".into());
            }
            if !(12..=3072).contains(&number(fields[6], "quanta=")?) {
                return Err("invalid user runtime timer counts".into());
            }
            user_quanta = number(fields[6], "quanta=")?;
            runtime_seen = true;
        } else if line.starts_with("EVROSION_M1_WAITS ") {
            if stage != 3 || !runtime_seen || waits_seen {
                return Err("duplicate or out-of-order user wait proof".into());
            }
            let fields: Vec<_> = line.split(' ').collect();
            if fields.len() != 7
                || fields[1] != "status=PASS"
                || fields[2] != "blocks=6"
                || fields[3] != "signals=3"
                || fields[4] != "deadlines=3"
                || fields[6] != "retired=true"
            {
                return Err("malformed user wait proof".into());
            }
            if !(3..=3072).contains(&number(fields[5], "idle_ticks=")?) {
                return Err("invalid user wait idle counts".into());
            }
            waits_seen = true;
        } else if line.starts_with("EVROSION_M1_RETIRE ") {
            if stage != 3
                || !waits_seen
                || retire_seen
                || line
                    != "EVROSION_M1_RETIRE status=PASS processes=6 reclaimed=3 discarded=3 closed=true quiescent=true"
            {
                return Err("missing, malformed or out-of-order process retirement proof".into());
            }
            retire_seen = true;
        } else if line.starts_with("EVROSION_M1_RECLAIM ") {
            if stage != 3 || !retire_seen || reclaim_seen {
                return Err("duplicate or out-of-order frame reclamation proof".into());
            }
            let fields: Vec<_> = line.split(' ').collect();
            if fields.len() != 6
                || fields[1] != "status=PASS"
                || fields[2] != "frames=42"
                || fields[4] != "zeroed=true"
                || fields[5] != "restored=true"
            {
                return Err("malformed frame reclamation proof".into());
            }
            if !(28..=42).contains(&number(fields[3], "reused=")?) {
                return Err("invalid reuse count".into());
            }
            reclaim_seen = true;
        } else if line.starts_with("EVROSION_M1_SHARED ") {
            if stage != 3
                || !reclaim_seen
                || shared_seen
                || line
                    != "EVROSION_M1_SHARED status=PASS objects=3 maps=6 denied=6 busy=3 destroyed=3 zeroed=true"
            {
                return Err("missing, malformed or out-of-order shared memory proof".into());
            }
            shared_seen = true;
        } else if line.starts_with("EVROSION_M1_JOBS ") {
            if stage != 3 || !shared_seen || jobs_seen {
                return Err("duplicate or out-of-order Job proof".into());
            }
            let fields: Vec<_> = line.split(' ').collect();
            if fields.len() != 8
                || fields[1] != "status=PASS"
                || fields[2] != "jobs=9"
                || !["frames=45", "frames=51"].contains(&fields[3])
                || fields[5] != "hierarchy=true"
                || fields[6] != "admission=true"
                || fields[7] != "live_zero=true"
            {
                return Err("malformed Job resource proof".into());
            }
            if number(fields[4], "cpu_ticks=")? != user_quanta {
                return Err("Job ticks do not match scheduled userspace".into());
            }
            job_frames = number(fields[3], "frames=")?;
            jobs_seen = true;
        } else if line.starts_with("EVROSION_M1_REVOKE ") {
            if stage != 3
                || !jobs_seen
                || revoke_seen
                || line
                    != "EVROSION_M1_REVOKE status=PASS invalidated=3 denied=3 faults=3 sibling_live=true"
            {
                return Err("missing, malformed or out-of-order mapping revocation proof".into());
            }
            revoke_seen = true;
        } else if line.starts_with("EVROSION_M1_FX ") {
            if stage != 3
                || !revoke_seen
                || fx_seen
                || line
                    != "EVROSION_M1_FX status=PASS processes=6 x87=true xmm=true mxcsr=true clean=true eager=true"
            {
                return Err("missing, malformed or out-of-order extended context proof".into());
            }
            fx_seen = true;
        } else if line.starts_with("EVROSION_M1_FAULT_DELIVERY ") {
            if stage != 3
                || !fx_seen
                || fault_delivery_seen
                || line
                    != "EVROSION_M1_FAULT_DELIVERY status=PASS records=3 denied=3 consumed_once=true kernel_sender=true"
            {
                return Err("missing, malformed or out-of-order fault delivery proof".into());
            }
            fault_delivery_seen = true;
        } else if line.starts_with("EVROSION_M1_ALLOC ") {
            if stage != 3
                || !fault_delivery_seen
                || job_frames != 51
                || allocation_seen
                || line
                    != "EVROSION_M1_ALLOC status=PASS allocated=6 freed=6 denied=3 zeroed=true unmapped=true rollback=true"
            {
                return Err("missing, malformed or out-of-order allocation proof".into());
            }
            allocation_seen = true;
        } else if line == protocol::PASS {
            if stage != 3
                || owner_seen && !owner_budget_seen
                || file_seen && !file_budget_seen
                || progress_expected && !progress_seen
                || display_present_seen && !display_seen
                || desktop_started && !desktop_done
                || native_started && !native_done
                || native_memory_started && !native_done
                || provider_started && !provider_done
                || ipc_started && !ipc_done
            {
                return Err("duplicate or out-of-order PASS record".into());
            }
            stage = 4;
        } else if stage != 0 || line.contains("EVROSION_") || line.contains(protocol::ENTERED) {
            return Err(format!("unexpected kernel output: {line}"));
        }
        // Firmware/loader chatter before the first header is preserved but not a pass signal.
    }
    if stage != 4 {
        return Err("missing or truncated boot protocol".into());
    }
    Ok(())
}

fn user(line: &str) -> Result<(), String> {
    let tail = line.strip_prefix("EVROSION_M1_USER status=PASS roots=2 cpl=3 private=true kernel_denied=true wx=true stack=true io_denied=true traps=15 ")
        .ok_or("malformed user isolation proof")?;
    let (a, b) = tail.split_once(' ').ok_or("missing user roots")?;
    let hex = |field: &str, prefix: &str| -> Result<u64, String> {
        let text = field
            .strip_prefix(prefix)
            .ok_or("missing user root field")?;
        if text.is_empty()
            || !text
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err("malformed user root".into());
        }
        let value = u64::from_str_radix(text, 16).map_err(|_| "invalid user root")?;
        if value == 0 || value >= 1 << 52 || value % 4096 != 0 {
            return Err("invalid user root bounds".into());
        }
        Ok(value)
    };
    if hex(a, "root_a=0x")? == hex(b, "root_b=0x")? {
        return Err("user roots must differ".into());
    }
    Ok(())
}

fn bootstrap(line: &str, usable_bytes: u64) -> Result<(), String> {
    let fields: Vec<_> = line.split(' ').collect();
    if fields.len() != 8 || fields[1] != "status=PASS" {
        return Err("malformed M1 bootstrap record".into());
    }
    let page = number(fields[2], "page_size=")?;
    let allocated = number(fields[3], "allocated=")?;
    let total = number(fields[4], "total=")?;
    let remaining = number(fields[5], "remaining=")?;
    let hex = |field: &str, prefix: &str| -> Result<u64, String> {
        field
            .strip_prefix(prefix)
            .filter(|s| {
                !s.is_empty()
                    && s.bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            })
            .and_then(|s| u64::from_str_radix(s, 16).ok())
            .ok_or_else(|| format!("invalid physical frame field: {field}"))
    };
    let first = hex(fields[6], "first=0x")?;
    let second = hex(fields[7], "second=0x")?;
    if page != 4096
        || allocated != 2
        || total.checked_sub(remaining) != Some(allocated)
        || total > usable_bytes / 4096
        || total >= (1 << 52) / 4096
        || first == 0
        || first >= second
        || second >= 1 << 52
        || first % 4096 != 0
        || second % 4096 != 0
    {
        return Err("inconsistent M1 bootstrap frame/count record".into());
    }
    Ok(())
}

fn paging(line: &str) -> Result<(), String> {
    let fields: Vec<_> = line.split(' ').collect();
    if fields.len() != 11
        || fields[1..8]
            != [
                "status=PASS",
                "roots=2",
                "map_unmap=true",
                "remap=true",
                "zeroed=true",
                "permissions=true",
                "restored=true",
            ]
    {
        return Err("malformed M1 paging record".into());
    }
    let hex = |field: &str, prefix: &str| -> Result<u64, String> {
        field
            .strip_prefix(prefix)
            .filter(|s| {
                !s.is_empty()
                    && s.bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            })
            .and_then(|s| u64::from_str_radix(s, 16).ok())
            .ok_or_else(|| format!("invalid paging address: {field}"))
    };
    let a = hex(fields[8], "root_a=0x")?;
    let b = hex(fields[9], "root_b=0x")?;
    let address = hex(fields[10], "virtual=0x")?;
    if a == b
        || [a, b]
            .iter()
            .any(|r| *r == 0 || *r >= 1 << 52 || r % 4096 != 0)
        || !(0xffff_8000_0000_0000..0xffff_ff80_0000_0000).contains(&address)
        || address & ((1 << 39) - 1) != 0
    {
        return Err("inconsistent M1 paging addresses".into());
    }
    Ok(())
}

fn number(field: &str, prefix: &str) -> Result<u64, String> {
    field
        .strip_prefix(prefix)
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| format!("invalid protocol field: {field}"))
}

fn framebuffer(line: &str) -> Result<(), String> {
    let fields: Vec<_> = line.split(' ').collect();
    if fields.len() != 6 {
        return Err("malformed framebuffer record".into());
    }
    let width = number(fields[2], "width=")?;
    let height = number(fields[3], "height=")?;
    let stride = number(fields[4], "stride=")?;
    match fields[1] {
        "present=false"
            if width == 0 && height == 0 && stride == 0 && fields[5] == "format=none" =>
        {
            Ok(())
        }
        "present=true"
            if (1..=16384).contains(&width)
                && (1..=16384).contains(&height)
                && stride >= width
                && stride <= 128 * 1024 * 1024
                && matches!(fields[5], "format=rgb" | "format=bgr" | "format=gray") =>
        {
            Ok(())
        }
        _ => Err("inconsistent framebuffer metadata".into()),
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct BlockRecord {
    pub phase: crate::storage::Phase,
    pub inputs: u64,
    pub outputs: u64,
}

fn block_record(line: &str) -> Result<BlockRecord, String> {
    use crate::storage::Phase;
    let fields: Vec<_> = line.split(' ').collect();
    if fields.len() != 13
        || fields[0] != "EVROSION_M3_BLOCK"
        || fields[1] != "status=PASS"
        || fields[2] != "scope=pio"
        || fields[6] != "denied=4"
        || fields[7] != "malformed=4"
        || fields[8] != "direct_denied=1"
        || fields[9] != "exits=1"
        || fields[11] != "frames=true"
        || fields[12] != "metadata=true"
    {
        return Err("malformed storage PIO record".into());
    }
    let phase = match fields[3] {
        "phase=write" => Phase::Write,
        "phase=verify" => Phase::Verify,
        _ => return Err("unknown storage phase".into()),
    };
    let inputs = number(fields[4], "inputs=")?;
    let outputs = number(fields[5], "outputs=")?;
    if !(1..=1_000_000).contains(&inputs)
        || !(1..=1_000_000).contains(&outputs)
        || fields[4] != format!("inputs={inputs}")
        || fields[5] != format!("outputs={outputs}")
        || fields[10] != format!("flushes={}", phase.flushes())
    {
        return Err("invalid storage operation counts".into());
    }
    Ok(BlockRecord {
        phase,
        inputs,
        outputs,
    })
}

/// The ordinary boot protocol accepts an optional exact storage record. Only the
/// explicit storage runner requires one, in addition to full protocol/status.
pub(crate) fn storage_record(serial: &[u8]) -> Result<BlockRecord, String> {
    if serial.len() > 1024 * 1024 {
        return Err("serial output exceeded 1 MiB".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "storage serial is not UTF-8")?;
    let mut records = text
        .lines()
        .filter(|line| line.starts_with("EVROSION_M3_BLOCK"));
    let record = records
        .next()
        .ok_or("required storage PIO proof is missing")?;
    if records.next().is_some() {
        return Err("duplicate storage PIO proof".into());
    }
    block_record(record)
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct SharedStorageRecord {
    pub phase: crate::storage::Phase,
    pub calls: u64,
}

fn shared_record(line: &str) -> Result<SharedStorageRecord, String> {
    use crate::storage::Phase;
    let fields: Vec<_> = line.split(' ').collect();
    if fields.len() != 16
        || fields[0] != "EVROSION_M3_TRANSPORT"
        || fields[1] != "status=PASS"
        || fields[2] != "scope=shared"
        || fields[8] != "short_deadline_denied=1"
        || fields[9] != "authority_denied=1"
        || fields[10] != "malformed=2"
        || fields[11] != "mapped=2"
        || fields[12] != "private_copy=true"
        || fields[13] != "guards=true"
        || fields[14] != "frames=true"
        || fields[15] != "metadata=true"
    {
        return Err("malformed shared storage record".into());
    }
    let (phase, calls) = match fields[3] {
        "phase=write" => (Phase::Write, 4),
        "phase=verify" => (Phase::Verify, 2),
        _ => return Err("unknown shared storage phase".into()),
    };
    for (field, name) in fields[4..8]
        .iter()
        .zip(["calls", "blocks", "wakes", "replies"])
    {
        if *field != format!("{name}={calls}") {
            return Err("shared storage call/wait totals differ from phase contract".into());
        }
    }
    Ok(SharedStorageRecord { phase, calls })
}

/// Required by the current cumulative disk workflow in addition to the earlier
/// standalone proof. Old immutable boot evidence retains its original frontend.
pub(crate) fn shared_storage_record(serial: &[u8]) -> Result<SharedStorageRecord, String> {
    if serial.len() > 1024 * 1024 {
        return Err("serial output exceeded 1 MiB".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "storage serial is not UTF-8")?;
    let mut records = text
        .lines()
        .filter(|line| line.starts_with("EVROSION_M3_TRANSPORT"));
    let record = records
        .next()
        .ok_or("required shared storage proof is missing")?;
    if records.next().is_some() {
        return Err("duplicate shared storage proof".into());
    }
    shared_record(record)
}

pub(crate) fn canonical_number(field: &str, name: &str) -> Result<u64, String> {
    let value = number(field, &format!("{name}="))?;
    if field != format!("{name}={value}") {
        return Err(format!("noncanonical {name}"));
    }
    Ok(value)
}

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct GenerationBudget {
    pub(crate) elapsed_ticks: u64,
    pub(crate) cpu_driver: u64,
    pub(crate) cpu_client: u64,
    pub(crate) cpu_critical: u64,
    pub(crate) cpu_parent: u64,
    pub(crate) transitions: u64,
    pub(crate) max_pending: u64,
}
fn generation_budget_line(line: &str) -> Result<GenerationBudget, String> {
    let f: Vec<_> = line.split(' ').collect();
    if f.len() != 12
        || f[0] != "EVROSION_M3_GENERATION_BUDGET"
        || f[1] != "status=PASS"
        || f[3] != "limit_ticks=2048"
        || f[10] != "accounted=true"
        || f[11] != "bounded=true"
    {
        return Err("malformed generation budget record".into());
    }
    let result = GenerationBudget {
        elapsed_ticks: canonical_number(f[2], "elapsed_ticks")?,
        cpu_driver: canonical_number(f[4], "driver_cpu")?,
        cpu_client: canonical_number(f[5], "controller_cpu")?,
        cpu_critical: canonical_number(f[6], "critical_cpu")?,
        cpu_parent: canonical_number(f[7], "parent_cpu")?,
        transitions: canonical_number(f[8], "transitions")?,
        max_pending: canonical_number(f[9], "max_pending")?,
    };
    if result.elapsed_ticks >= 2048
        || result.cpu_driver > 2048
        || result.cpu_client > 2048
        || result.cpu_critical > 2048
        || result.cpu_parent != result.elapsed_ticks
        || result
            .cpu_driver
            .checked_add(result.cpu_client)
            .and_then(|n| n.checked_add(result.cpu_critical))
            != Some(result.cpu_parent)
        || !(1..=100_000).contains(&result.transitions)
        || result.max_pending != 1
    {
        return Err("generation budget is exhausted or CPU accounting is unbalanced".into());
    }
    Ok(result)
}
pub(crate) fn generation_budget_record(serial: &[u8]) -> Result<GenerationBudget, String> {
    if serial.len() > 1024 * 1024 {
        return Err("generation serial exceeded 1 MiB".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "generation serial is not UTF-8")?;
    let mut lines = text
        .lines()
        .filter(|line| line.starts_with("EVROSION_M3_GENERATION_BUDGET "));
    let line = lines.next().ok_or("missing generation budget proof")?;
    if lines.next().is_some() {
        return Err("duplicate generation budget proof".into());
    }
    generation_budget_line(line)
}

fn generation_line(line: &str) -> Result<ev_userspace_contract::generation::Completion, String> {
    use ev_userspace_contract::generation::Mode;
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 1024
        || f.len() != 21
        || f[0] != "EVROSION_M3_GENERATION"
        || f[1] != "status=PASS"
        || f[2] != "scope=cohort"
        || f[16] != "catalogue=true"
        || f[17] != "frames=true"
        || f[18] != "metadata=true"
        || f[19] != "guards=true"
    {
        return Err("malformed generation record".into());
    }
    let hex = f[20]
        .strip_prefix("report=")
        .ok_or("missing generation report")?;
    let report = generation_report_hex(hex)?;
    let (phase, operation, mutations, serial) = match report.mode {
        Mode::ProvisionA => ("provision-a", 4, 23, 1),
        Mode::FailB => ("fail-b", 10, 28, 2),
        Mode::AutoA => ("auto-a", 14, 18, 3),
        Mode::ManualA => ("manual-a", 21, 32, 4),
        Mode::Verify => ("verify", 21, 0, 0),
        Mode::OwnerPrepare3 | Mode::OwnerRecover => {
            return Err("owner mode requires owner proof".into());
        }
    };
    if f[3] != format!("phase={phase}")
        || report.operation != operation
        || report.mutations != mutations
        || report.boot_serial != serial
        || canonical_number(f[8], "mutations")? != mutations
    {
        return Err("generation result differs from phase operation contract".into());
    }
    let calls = canonical_number(f[4], "calls")?;
    if !(1..=100_000).contains(&calls) {
        return Err("unbounded generation calls".into());
    }
    for (field, name) in f[5..8].iter().zip(["blocks", "wakes", "replies"]) {
        if canonical_number(field, name)? != calls {
            return Err("generation wait/reply imbalance".into());
        }
    }
    let active = u64::from(report.mode != Mode::Verify);
    let failed = u64::from(report.mode == Mode::FailB);
    let faulted = u64::from(report.mode == Mode::FailB && report.failure_reason == 1);
    let ready = canonical_number(f[10], "ready")?;
    if canonical_number(f[9], "starts")? != active
        || ready > active
        || (active == 1 && failed == 0 && ready != 1)
        || canonical_number(f[11], "critical_ready")? != active - failed
        || canonical_number(f[12], "faults")? != faulted
        || canonical_number(f[13], "stops")? != active
        || canonical_number(f[14], "reaps")? != active
        || canonical_number(f[15], "forged")? != report.negatives
    {
        return Err("generation admission/health/provenance proof mismatch".into());
    }
    if report.mode == Mode::ProvisionA {
        if [
            report.failure_generation,
            report.failure_serial,
            report.failure_reason,
            report.failure_operation,
            report.failure_sequence,
        ]
        .iter()
        .any(|&n| n != 0)
        {
            return Err("initial generation invented a failure".into());
        }
    } else if !matches!(report.failure_reason, 1 | 2)
        || (
            report.failure_generation,
            report.failure_serial,
            report.failure_operation,
            report.failure_sequence,
        ) != (2, 2, 10, 11)
    {
        return Err("generation lost original failed B identity".into());
    }
    Ok(report)
}

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct ProgressRecord {
    pub(crate) start_tick: u64,
    pub(crate) observed_tick: u64,
    pub(crate) stop_tick: u64,
}
fn progress_line(line: &str) -> Result<ProgressRecord, String> {
    let f: Vec<_> = line.split(' ').collect();
    if f.len() != 8
        || f[0] != "EVROSION_M3_PROGRESS"
        || f[1] != "status=PASS"
        || f[5] != "wait_ticks=64"
        || f[6] != "stopped_live=true"
        || f[7] != "fault=false"
    {
        return Err("malformed service progress proof".into());
    }
    let result = ProgressRecord {
        start_tick: canonical_number(f[2], "start_tick")?,
        observed_tick: canonical_number(f[3], "observed_tick")?,
        stop_tick: canonical_number(f[4], "stop_tick")?,
    };
    if result
        .start_tick
        .checked_add(64)
        .is_none_or(|deadline| result.observed_tick < deadline)
        || result.stop_tick < result.observed_tick
    {
        return Err(
            "service progress failure did not observe a live process through its declared deadline"
                .into(),
        );
    }
    Ok(result)
}
pub(crate) fn progress_record(serial: &[u8]) -> Result<ProgressRecord, String> {
    if serial.len() > 1024 * 1024 {
        return Err("progress serial exceeded1MiB".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "progress serial is notUTF8")?;
    let mut lines = text
        .lines()
        .filter(|line| line.starts_with("EVROSION_M3_PROGRESS "));
    let line = lines.next().ok_or("missing progress failure proof")?;
    if lines.next().is_some() {
        return Err("duplicate progress failure proof".into());
    }
    progress_line(line)
}

pub(crate) fn generation_report_hex(
    hex: &str,
) -> Result<ev_userspace_contract::generation::Completion, String> {
    use ev_userspace_contract::generation::Completion;
    if hex.len() != 512
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("noncanonical generation report encoding".into());
    }
    let mut bytes = [0u8; 512];
    for (index, pair) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        bytes[index] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Completion::decode(&bytes).map_err(|e| format!("invalid generation report: {e:?}"))
}

pub(crate) fn generation_record(
    serial: &[u8],
) -> Result<ev_userspace_contract::generation::Completion, String> {
    if serial.len() > 1024 * 1024 {
        return Err("serial output exceeded 1MiB".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "generation serial is not UTF-8")?;
    let lines: Vec<_> = text
        .lines()
        .filter(|l| l.starts_with("EVROSION_M3_GENERATION "))
        .collect();
    if lines.len() != 1 {
        return Err("missing or duplicate generation proof".into());
    }
    generation_line(lines[0])
}

fn store_record(line: &str) -> Result<ev_userspace_contract::store_test::Mode, String> {
    use ev_userspace_contract::store_test::Mode;
    let f: Vec<_> = line.split(' ').collect();
    if f.len() != 17
        || f[0] != "EVROSION_M3_STORE"
        || f[1] != "status=PASS"
        || f[2] != "scope=journal"
        || f[11] != "pending=true"
        || f[14] != "frames=true"
        || f[15] != "metadata=true"
        || f[16] != "guards=true"
    {
        return Err("malformed durable store record".into());
    }
    let mode = match f[3] {
        "phase=init" => Mode::Init,
        "phase=recover" => Mode::Recover,
        "phase=commit" => Mode::Commit,
        "phase=verify" => Mode::Verify,
        _ => return Err("invalid durable store phase".into()),
    };
    let calls = canonical_number(f[4], "calls")?;
    if !(1..=100_000).contains(&calls) {
        return Err("unbounded store calls".into());
    }
    for (field, name) in f[5..8].iter().zip(["blocks", "wakes", "replies"]) {
        if canonical_number(field, name)? != calls {
            return Err("store wait/reply imbalance".into());
        }
    }
    let mutations = canonical_number(f[8], "mutations")?;
    let initial = mode == Mode::Init;
    if mutations > 6
        || (initial && mutations != 5)
        || (mode == Mode::Commit && mutations != 6)
        || (mode == Mode::Verify && mutations != 0)
        || f[9]
            != if initial {
                "operation=0"
            } else {
                "operation=1"
            }
        || f[10] != if initial { "sequence=1" } else { "sequence=2" }
        || f[12]
            != if initial {
                "replay_verified=false"
            } else {
                "replay_verified=true"
            }
        || f[13]
            != if initial {
                "payload=initial"
            } else {
                "payload=committed"
            }
    {
        return Err("store completion differs from phase contract".into());
    }
    Ok(mode)
}

pub(crate) fn check_store_record(
    serial: &[u8],
    expected: ev_userspace_contract::store_test::Control,
) -> Result<(), String> {
    if serial.len() > 1024 * 1024 {
        return Err("serial output exceeded 1 MiB".into());
    }
    let text = String::from_utf8_lossy(serial);
    let records: Vec<_> = text
        .lines()
        .filter(|l| l.starts_with("EVROSION_M3_STORE "))
        .collect();
    if records.len() != 1 || store_record(records[0])? != expected.mode {
        return Err("missing, duplicate or wrong-phase store completion".into());
    }
    Ok(())
}

/// Check a prefix from an intentionally interrupted guest. This does not claim
/// a normal guest PASS; the runner separately requires its own abrupt kill/reap.
pub fn check_store_cut_prefix(serial: &[u8], build: &str, expected_cut: u64) -> Result<(), String> {
    if serial.len() > 1024 * 1024
        || !(1..=6).contains(&expected_cut)
        || serial.last() != Some(&b'\n')
    {
        return Err("invalid interrupted serial bound/cut".into());
    }
    let text = String::from_utf8_lossy(serial);
    if text.contains("EVROSION_M0_RESULT")
        || text.contains("EVROSION_M3_STORE ")
        || !text
            .lines()
            .any(|l| l.starts_with("EVROSION_M2_IPC_DISCIPLINE "))
    {
        return Err("interruption lacks prerequisites or follows a completion".into());
    }
    let records: Vec<_> = text
        .lines()
        .filter(|l| l.starts_with("EVROSION_M3_STORE_CUT "))
        .collect();
    let Some(line) = records.first().copied() else {
        return Err("missing interruption record".into());
    };
    if records.len() != 1 || text.lines().rfind(|l| !l.is_empty()) != Some(line) {
        return Err("duplicate or nonfinal interruption record".into());
    }
    let f: Vec<_> = line.split(' ').collect();
    if f.len() != 18
        || f[0] != "EVROSION_M3_STORE_CUT"
        || f[1] != "protocol=1"
        || f[2] != format!("build={build}")
        || f[3] != "status=PASS"
        || f[4] != "scope=journal"
        || canonical_number(f[5], "cut")? != expected_cut
        || canonical_number(f[10], "mutations")? != expected_cut
        || f[11] != "fault_vector=6"
        || f[12] != "fault_error=0"
        || canonical_number(f[13], "process")? == 0
        || canonical_number(f[14], "thread")? == 0
        || f[15] != "frames=true"
        || f[16] != "metadata=true"
        || f[17] != "guards=true"
    {
        return Err("malformed or wrong-build interruption record".into());
    }
    let calls = canonical_number(f[6], "calls")?;
    if !(1..=100_000).contains(&calls) {
        return Err("unbounded interrupted calls".into());
    }
    for (field, name) in f[7..10].iter().zip(["blocks", "wakes", "replies"]) {
        if canonical_number(field, name)? != calls {
            return Err("interrupted wait/reply imbalance".into());
        }
    }
    let offset = text
        .rfind(line)
        .ok_or("missing final interruption offset")?;
    // Reuse strict ordered parsing solely for the already completed prefix.
    // Neither this synthetic parser terminator nor QEMU status is guest evidence.
    check(
        format!("{}{}\r\n", &text[..offset], protocol::PASS).as_bytes(),
        build,
        Some(protocol::QEMU_PASS_STATUS),
    )
}

#[cfg(test)]
mod native_pre_gui_fault_tests {
    use super::*;
    use sha2::{Digest, Sha256};
    // Exact unchanged serial from the second System candidate's Bad cold boot,
    // retained by m5-native3-pre-gui-shell-fault-parser-failure-2026-11-11.json.
    // Parser acceptance does not change that historical suite's failed result
    // or replace dedicated verified-catalogue/Source/disk/health joins.
    const SERIAL: &[u8] =
        include_bytes!("../../../tests/fixtures/native3-pre-gui-shell-fault.serial");
    const BUILD: &str = "02f06f6d8278e525052b4ae3db7f2fef04ee18451978b9c0546b729fce851d1c";
    fn row(prefix: &str) -> &'static str {
        core::str::from_utf8(SERIAL)
            .unwrap()
            .split_inclusive('\n')
            .find(|line| line.starts_with(prefix))
            .unwrap()
    }
    fn frame() -> String {
        format!(
            "EVROSION_M4_DESKTOP_STEP protocol=1 build={BUILD} step=frame frame=1 width=1280 height=800 app_process=0 shell_process=6 display_process=3 grants=0 producer=shell surface_sha256={} held_ticks=0\r\n",
            "a".repeat(64)
        )
    }
    fn rejected(changed: &str) {
        assert!(check(changed.as_bytes(), BUILD, Some(protocol::QEMU_PASS_STATUS)).is_err());
    }
    #[test]
    fn unchanged_actual_bad_trace_passes_complete_closed_boot_parser() {
        assert_eq!(SERIAL.len(), 19_087);
        assert_eq!(
            format!("{:x}", Sha256::digest(SERIAL)),
            "bb926c5cec64de54a99a58dfafaeb32c77e1dfb2895071bb907da89120a7b8a6"
        );
        check(SERIAL, BUILD, Some(protocol::QEMU_PASS_STATUS)).unwrap();
        assert!(check(SERIAL, BUILD, None).is_err());
    }
    #[test]
    fn initial_fault_requires_managed_mode_one_lifecycle_and_original_fault_shape() {
        let serial = core::str::from_utf8(SERIAL).unwrap();
        let life = row("EVROSION_M4_DESKTOP_LIFECYCLE ");
        for changed in [
            serial.replace("mode=1 ", "mode=0 "),
            serial.replace("mode=1 ", "mode=2 "),
            serial.replace(row("EVROSION_M5_NATIVE_COMMON_PREFIX "), ""),
            serial.replace(life, ""),
            serial.replace(life, &(life.to_owned() + life)),
            serial.replace(life, &life.replace("actor=shell", "actor=app")),
            serial.replace(life, &life.replace("grants=0", "grants=3")),
            serial.replace(life, &life.replace("vector=14", "vector=13")),
            serial.replace(life, &life.replace("error=4", "error=6")),
            serial.replace(life, &life.replace(BUILD, &"a".repeat(64))),
        ] {
            rejected(&changed);
        }
        let raw = row("EVROSION_NATIVE_FAULT ");
        rejected(
            &serial
                .replace(life, "")
                .replace(raw, &(life.to_owned() + raw)),
        );
        // Keep diagnostic sequence and complete raw/capsule codecs valid: the
        // special branch must reject a second pair independently of the
        // unchanged one-fault footer and scheduling counters.
        let crash = row("EVROSION_NATIVE_CRASH ");
        let system = serial
            .split_inclusive('\n')
            .find(|line| line.starts_with("EVROSION_NATIVE_SYSTEM ") && line.contains(" report=3 "))
            .unwrap();
        let second_pair = serial
            .replace(system, &system.replace(" report=3 ", " report=4 "))
            .replace(
                crash,
                &(crash.to_owned() + raw + &crash.replace(" report=2 ", " report=3 ")),
            );
        assert!(
            check(
                second_pair.as_bytes(),
                BUILD,
                Some(protocol::QEMU_PASS_STATUS)
            )
            .unwrap_err()
            .contains("pre-GUI Shell fault")
        );
    }
    #[test]
    fn initial_fault_cannot_mix_frames_restarts_apps_or_changed_completion() {
        let serial = core::str::from_utf8(SERIAL).unwrap();
        let life = row("EVROSION_M4_DESKTOP_LIFECYCLE ");
        let footer = row("EVROSION_M5_NATIVE ");
        let restart = life
            .replace("event=fault", "event=restart")
            .replace("replacement=0", "replacement=262")
            .replace("vector=14", "vector=0")
            .replace("error=4", "error=0")
            .replace("address=549760008192", "address=0");
        for changed in [
            serial.replace(life, &(frame() + life)),
            serial.replace(life, &(life.to_owned() + &frame())),
            serial.replace(life, &restart),
            serial.replace(life, &(life.to_owned() + &restart)),
            serial.replace(footer, &footer.replace("faults=1", "faults=0")),
            serial.replace(footer, &footer.replace("restarts=0", "restarts=1")),
            serial.replace(footer, &footer.replace("grants=0", "grants=1")),
            serial.replace(footer, &footer.replace("processes=6", "processes=7")),
            serial
                .replace(life, "")
                .replace(footer, &(footer.to_owned() + life)),
        ] {
            rejected(&changed);
        }
        // Coherent ordinary Native App lifecycle/footer syntax still cannot
        // enter the special pre-GUI no-App profile.
        let actions: String = ["start", "stop", "reap"].into_iter().map(|action| format!(
            "EVROSION_M5_NATIVE_ACTION protocol=1 build={BUILD} action={action} process=7 thread=7 image_sha256={}\r\n", "a".repeat(64)
        )).collect();
        let app_footer = footer
            .replace("processes=6", "processes=7")
            .replace("starts=6", "starts=7")
            .replace("app_a_starts=0", "app_a_starts=1")
            .replace("app_a_stops=0", "app_a_stops=1")
            .replace("app_a_reaps=0", "app_a_reaps=1")
            .replace("app_a_process=0", "app_a_process=7")
            .replace("app_a_thread=0", "app_a_thread=7");
        let mixed = serial.replace(footer, &(actions + &app_footer));
        crate::native_protocol::record(mixed.as_bytes(), BUILD).unwrap();
        rejected(&mixed);
    }
}

#[cfg(test)]
mod native_profile_order_tests {
    use super::*;
    // Exact actual full-graph serial from the retained Run5 host-parser failure.
    // Its reuse here tests parsing; it does not turn that failed suite into a
    // six-boot lifecycle result or new execution evidence.
    const SERIAL: &[u8] =
        include_bytes!("../../../tests/fixtures/native-scheduling-profile-parser.log");
    const BUILD: &str = "a59fb92763796b6e4faed3289cceb1e6270d73b8ef85e9536f03d060aa8a6957";
    #[test]
    fn actual_native_profiles_fit_the_complete_ordered_boot_protocol() {
        check(SERIAL, BUILD, Some(protocol::QEMU_PASS_STATUS)).unwrap();
    }
    #[test]
    fn closed_boot_parser_enforces_declared_managed_and_legacy_world_bounds() {
        // Synthetic edits of the actual parser fixture test mode/bound routing
        // only. They are not runtime or authenticated-catalogue evidence.
        let serial = core::str::from_utf8(SERIAL).unwrap();
        for (mode, limit) in [(None, 16_384), (Some(0), 16_384), (Some(1), 32_768)] {
            let mut fixture = serial.to_owned();
            if let Some(mode) = mode {
                let prefix = format!(
                    "EVROSION_M5_NATIVE_COMMON_PREFIX protocol=1 build={BUILD} mode={mode} root_process=1 root_thread=1 root_image_sha256={} root_epoch=501 root_incarnation=1 root_manifest_sha256={} block_process=2 block_thread=2 block_image_sha256={} system_endpoint=31 root_frames=40 block_frames=20\r\n",
                    "a".repeat(64),
                    "b".repeat(64),
                    "c".repeat(64)
                );
                let offset = fixture.find("EVROSION_NATIVE_STATE ").unwrap();
                fixture.insert_str(offset, &prefix);
            }
            for (elapsed, accepted) in [(limit - 1, true), (limit, false), (limit + 1, false)] {
                let changed =
                    fixture.replace("elapsed_ticks=7217", &format!("elapsed_ticks={elapsed}"));
                assert_eq!(
                    check(changed.as_bytes(), BUILD, Some(protocol::QEMU_PASS_STATUS)).is_ok(),
                    accepted,
                    "mode={mode:?} elapsed={elapsed}"
                );
            }
        }
    }
    #[test]
    fn native_profile_cannot_replace_completion_or_cross_boot_ordering() {
        let serial = core::str::from_utf8(SERIAL).unwrap();
        let profile = serial
            .split_inclusive('\n')
            .find(|line| line.starts_with("EVROSION_M5_NATIVE_PROFILE"))
            .unwrap();
        for changed in [
            serial.replace(profile, ""),
            serial.replacen(profile, &(profile.to_owned() + profile), 1),
            serial.replace("phase=finished", "phase=bound"),
            profile.to_owned() + &serial.replace(profile, ""),
            serial
                .split_inclusive('\n')
                .filter(|line| !line.starts_with("EVROSION_M5_NATIVE "))
                .collect(),
        ] {
            assert!(check(changed.as_bytes(), BUILD, Some(protocol::QEMU_PASS_STATUS)).is_err());
        }
    }
}

#[cfg(test)]
mod display_order_tests {
    use super::*;
    /// Exact historical serial bytes are only a parser fixture here. Inserting
    /// synthetic M4 lines never becomes a physical-display evidence claim.
    fn fixture() -> (String, String, String, String) {
        let original = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/m2-complete-boot-parser.serial"
        ))
        .to_owned();
        let build = "87d2c58af93152104b603526775aac0b4849269b5ec999cde55de73b5ddbf486".to_owned();
        check(original.as_bytes(), &build, Some(33)).unwrap();
        let present = format!(
            "EVROSION_M4_PRESENT protocol=1 build={build} frame=1 width=1280 height=800 app_process=1 display_process=2 surface_sha256={}",
            crate::graphics_protocol::Reference::hello()
                .unwrap()
                .surface_sha256
        );
        let record="EVROSION_M4_DISPLAY status=PASS scope=surface worlds=3 calls=2 blocks=2 wakes=2 replies=1 faults=2 authority_denied=9 mapped=6 surface_pages=63 display_tables=6 peak_frames=110 max_pending=1 frames=true metadata=true guards=true".to_owned();
        (original, build, present, record)
    }
    #[test]
    fn display_follows_full_m2_precedes_runtime_and_cannot_mix_or_skip_completion() {
        let (original, build, present, record) = fixture();
        let runtime = "EVROSION_M1_RUNTIME ";
        let offset = original.find(runtime).unwrap();
        let prefix = &original[..offset];
        let suffix = &original[offset..];
        let good = format!("{prefix}{present}\r\n{record}\r\n{suffix}");
        check(good.as_bytes(), &build, Some(33)).unwrap();
        assert!(check(good.as_bytes(), &build, Some(35)).is_err());
        for invalid in [
            format!("{prefix}{present}\r\n{suffix}"),
            format!("{prefix}{record}\r\n{suffix}"),
            format!("{prefix}{present}\r\n{present}\r\n{record}\r\n{suffix}"),
            format!("{prefix}{present}\r\n{record}\r\n{record}\r\n{suffix}"),
            format!("{prefix}{record}\r\n{present}\r\n{suffix}"),
            good.replace("EVROSION_M2_IPC_DISCIPLINE ", "unsupported "),
            format!("{prefix}{present}\r\nEVROSION_M3_STORE status=PASS\r\n{record}\r\n{suffix}"),
            original.replace(
                protocol::PASS,
                &format!("{present}\r\n{record}\r\n{}", protocol::PASS),
            ),
        ] {
            assert!(check(invalid.as_bytes(), &build, Some(33)).is_err());
        }
    }
    #[test]
    fn desktop_requires_real_lifecycle_shapes_order_and_full_boot_completion() {
        let (original, build, _, _) = fixture();
        let offset = original.find("EVROSION_M1_RUNTIME ").unwrap();
        let prefix = &original[..offset];
        let suffix = &original[offset..];
        let frame = format!(
            "EVROSION_M4_DESKTOP_STEP protocol=1 build={build} step=frame frame=1 width=1280 height=800 app_process=0 shell_process=2 display_process=3 grants=0 producer=shell surface_sha256={} held_ticks=0",
            "ab".repeat(32)
        );
        let mut lives = Vec::new();
        for (actor, id, thread, replacement, grants) in [("app", 4, 5, 8, 2), ("shell", 2, 6, 9, 3)]
        {
            for event in ["fault", "restart"] {
                let (repl, vector, error, address) = if event == "fault" {
                    (0, 14, 4, (1u64 << 39) + 4 * 1024 * 1024)
                } else {
                    (replacement, 0, 0, 0)
                };
                lives.push(format!("EVROSION_M4_DESKTOP_LIFECYCLE protocol=1 build={build} event={event} actor={actor} process={id} thread={thread} replacement={repl} display_process=3 grants={grants} vector={vector} error={error} address={address}"));
            }
        }
        let final_line = "EVROSION_M4_DESKTOP status=PASS scope=graph processes=9 starts=9 faults=2 restarts=2 calls=432 replies=432 grants=3 frames=true metadata=true guards=true display_survived=true";
        let life = lives.join("\r\n");
        let good = format!("{prefix}{frame}\r\n{life}\r\n{final_line}\r\n{suffix}");
        check(good.as_bytes(), &build, Some(33)).unwrap();
        assert!(
            crate::boot::check_desktop_prefix(format!("{prefix}{frame}\r\n").as_bytes(), &build)
                .is_ok()
        );
        assert!(check(format!("{prefix}{frame}\r\n").as_bytes(), &build, Some(33)).is_err());
        for bad in [
            good.replace("faults=2", "faults=1"),
            good.replace("error=4", "error=7"),
            good.replace(
                "actor=app process=4 thread=5 replacement=8",
                "actor=app process=4 thread=7 replacement=8",
            ),
            good.replace("event=restart actor=app", "event=fault actor=app"),
            good.replace("display_process=3 grants=3", "display_process=7 grants=3"),
            good.replace(&format!("{}\r\n", lives[0]), ""),
            format!("{prefix}{frame}\r\n{final_line}\r\n{life}\r\n{suffix}"),
            good.replace("EVROSION_M2_IPC_DISCIPLINE ", "unsupported "),
            good.replace(final_line, &format!("{final_line}\r\n{final_line}")),
            good.replace(
                final_line,
                &format!("EVROSION_M4_DISPLAY status=PASS\r\n{final_line}"),
            ),
        ] {
            assert!(check(bad.as_bytes(), &build, Some(33)).is_err());
        }
        assert!(check(good.as_bytes(), &build, Some(35)).is_err());
    }
    #[test]
    fn present_prefix_validation_never_treats_capture_as_guest_completion() {
        let (original, build, present, record) = fixture();
        let offset = original.find("EVROSION_M1_RUNTIME ").unwrap();
        let prefix = format!("{}{present}\r\n", &original[..offset]);
        assert!(
            crate::boot::check_display_present_prefix(prefix.as_bytes(), &build)
                .unwrap()
                .is_some()
        );
        assert!(check(prefix.as_bytes(), &build, Some(33)).is_err());
        assert!(
            crate::boot::check_display_present_prefix(format!("{present}\r\n").as_bytes(), &build)
                .is_err()
        );
        assert!(
            crate::boot::check_display_present_prefix(
                format!("{prefix}{record}\r\n").as_bytes(),
                &build
            )
            .is_err()
        );
        assert!(
            crate::boot::check_display_present_prefix(
                format!("{prefix}{}\r\n", protocol::PASS).as_bytes(),
                &build
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod storage_tests {
    use super::*;
    const WRITE: &str = "EVROSION_M3_BLOCK status=PASS scope=pio phase=write inputs=1024 outputs=300 denied=4 malformed=4 direct_denied=1 exits=1 flushes=1 frames=true metadata=true";
    const SHARED: &str = "EVROSION_M3_TRANSPORT status=PASS scope=shared phase=write calls=4 blocks=4 wakes=4 replies=4 short_deadline_denied=1 authority_denied=1 malformed=2 mapped=2 private_copy=true guards=true frames=true metadata=true";
    #[test]
    fn missing_progress_requires_real_live_observations_through_the_window() {
        const LINE: &str = "EVROSION_M3_PROGRESS status=PASS start_tick=10 observed_tick=74 stop_tick=75 wait_ticks=64 stopped_live=true fault=false";
        assert_eq!(progress_record(LINE.as_bytes()).unwrap().stop_tick, 75);
        for (a, b) in [
            ("start_tick=10", "start_tick=18446744073709551615"),
            ("observed_tick=74", "observed_tick=73"),
            ("stop_tick=75", "stop_tick=73"),
            ("wait_ticks=64", "wait_ticks=63"),
            ("stopped_live=true", "stopped_live=false"),
            ("fault=false", "fault=true"),
            ("start_tick=10", "start_tick=010"),
        ] {
            assert!(progress_record(LINE.replace(a, b).as_bytes()).is_err());
        }
        assert!(progress_record(format!("{LINE}\n{LINE}").as_bytes()).is_err());
        assert!(progress_record(b"").is_err());
    }
    #[test]
    fn generation_budget_requires_finite_actual_cpu_and_one_balanced_parent() {
        const BUDGET: &str = "EVROSION_M3_GENERATION_BUDGET status=PASS elapsed_ticks=1025 limit_ticks=2048 driver_cpu=800 controller_cpu=56 critical_cpu=169 parent_cpu=1025 transitions=57000 max_pending=1 accounted=true bounded=true";
        let observed = generation_budget_record(BUDGET.as_bytes()).unwrap();
        assert_eq!((observed.elapsed_ticks, observed.cpu_parent), (1025, 1025));
        for (before, after) in [
            ("elapsed_ticks=1025", "elapsed_ticks=2048"),
            ("elapsed_ticks=1025", "elapsed_ticks=01025"),
            ("limit_ticks=2048", "limit_ticks=4096"),
            ("driver_cpu=800", "driver_cpu=801"),
            ("controller_cpu=56", "controller_cpu=18446744073709551615"),
            ("critical_cpu=169", "critical_cpu=0"),
            ("parent_cpu=1025", "parent_cpu=1024"),
            ("transitions=57000", "transitions=0"),
            ("transitions=57000", "transitions=100001"),
            ("max_pending=1", "max_pending=0"),
            ("max_pending=1", "max_pending=2"),
            ("accounted=true", "accounted=false"),
            ("bounded=true", "bounded=false"),
        ] {
            assert!(generation_budget_record(BUDGET.replace(before, after).as_bytes()).is_err());
        }
        assert!(generation_budget_record(b"").is_err());
        assert!(generation_budget_record(format!("{BUDGET}\n{BUDGET}").as_bytes()).is_err());
    }
    fn generation_fixture(mode: ev_userspace_contract::generation::Mode) -> String {
        use ev_userspace_contract::generation::{Completion, Mode};
        let (phase, operation, mutations, serial) = match mode {
            Mode::ProvisionA => ("provision-a", 4, 23, 1),
            Mode::FailB => ("fail-b", 10, 28, 2),
            Mode::AutoA => ("auto-a", 14, 18, 3),
            Mode::ManualA => ("manual-a", 21, 32, 4),
            Mode::Verify => ("verify", 21, 0, 0),
            Mode::OwnerPrepare3 | Mode::OwnerRecover => unreachable!(),
        };
        let active = u64::from(mode != Mode::Verify);
        let failed = u64::from(mode == Mode::FailB);
        let previous_failure = u64::from(mode != Mode::ProvisionA);
        let report = Completion {
            mode,
            owner_decision: ev_userspace_contract::generation::OwnerDecision::None,
            booted: if failed == 1 { 2 } else { active },
            selected: 1,
            known_good: 1,
            boot_serial: serial,
            process: active * 101,
            thread: active * 102,
            failure_generation: previous_failure * 2,
            failure_serial: previous_failure * 2,
            failure_reason: previous_failure,
            negatives: active * 4,
            mutations,
            operation,
            sequence: operation + 1,
            failure_operation: previous_failure * 10,
            failure_sequence: previous_failure * 11,
            catalogue: [0xab; 32],
            process_stamp: [active as u8; 32],
            storage_probe: [0xcd; 32],
            booted_cohort: [active as u8; 32],
        };
        let hex: String = report.encode()[..256]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!(
            "EVROSION_M3_GENERATION status=PASS scope=cohort phase={phase} calls=100 blocks=100 wakes=100 replies=100 mutations={mutations} starts={active} ready={active} critical_ready={} faults={failed} stops={active} reaps={active} forged={} catalogue=true frames=true metadata=true guards=true report={hex}",
            active - failed,
            active * 4
        )
    }
    #[test]
    fn generation_records_require_real_lifecycle_health_and_canonical_bound_report() {
        use ev_userspace_contract::generation::Mode;
        for mode in [
            Mode::ProvisionA,
            Mode::FailB,
            Mode::AutoA,
            Mode::ManualA,
            Mode::Verify,
        ] {
            let line = generation_fixture(mode);
            assert_eq!(generation_record(line.as_bytes()).unwrap().mode, mode);
            let active = u64::from(mode != Mode::Verify);
            let failed = u64::from(mode == Mode::FailB);
            for (before, after) in [
                ("blocks=100".into(), "blocks=99".into()),
                ("calls=100".into(), "calls=0100".into()),
                ("wakes=100".into(), "wakes=101".into()),
                (format!("starts={active}"), format!("starts={}", 1 - active)),
                (
                    format!("critical_ready={}", active - failed),
                    format!("critical_ready={}", 1 - active + failed),
                ),
                (format!("faults={failed}"), format!("faults={}", 1 - failed)),
                (format!("reaps={active}"), format!("reaps={}", 1 - active)),
                (format!("forged={}", active * 4), "forged=3".into()),
                ("catalogue=true".into(), "catalogue=false".into()),
                ("guards=true".into(), "guards=false".into()),
                ("abababab".into(), "ABABABAB".into()),
            ] {
                let bad = line.replacen(&before, &after, 1);
                assert_ne!(bad, line);
                assert!(generation_record(bad.as_bytes()).is_err(), "accepted {bad}");
            }
            assert!(generation_record(format!("{line}\n{line}").as_bytes()).is_err());
            assert!(generation_record(format!("{line} extra=true").as_bytes()).is_err());
            let mut invalid = line.into_bytes();
            invalid.push(0xff);
            assert!(generation_record(&invalid).is_err());
        }
    }
    #[test]
    fn shared_proof_requires_exact_phase_waits_and_lifetime_guards() {
        assert_eq!(shared_storage_record(SHARED.as_bytes()).unwrap().calls, 4);
        let verify = SHARED
            .replace("phase=write", "phase=verify")
            .replace("calls=4", "calls=2")
            .replace("blocks=4", "blocks=2")
            .replace("wakes=4", "wakes=2")
            .replace("replies=4", "replies=2");
        assert_eq!(shared_storage_record(verify.as_bytes()).unwrap().calls, 2);
        let mut invalid = vec![
            String::new(),
            format!("{SHARED}\n{SHARED}"),
            format!("{SHARED} extra=true"),
        ];
        for (before, after) in [
            ("phase=write", "phase=verify"),
            ("calls=4", "calls=04"),
            ("blocks=4", "blocks=0"),
            ("wakes=4", "wakes=3"),
            ("replies=4", "replies=5"),
            ("short_deadline_denied=1", "short_deadline_denied=0"),
            ("authority_denied=1", "authority_denied=0"),
            ("malformed=2", "malformed=1"),
            ("mapped=2", "mapped=1"),
            ("private_copy=true", "private_copy=false"),
            ("guards=true", "guards=false"),
            ("frames=true", "frames=false"),
            ("metadata=true", "metadata=false"),
            ("scope=shared", "scope=kernel"),
        ] {
            invalid.push(SHARED.replace(before, after));
        }
        for serial in invalid {
            assert!(
                shared_storage_record(serial.as_bytes()).is_err(),
                "accepted {serial}"
            );
        }
    }
    #[test]
    fn explicit_runner_requires_exact_phase_flush_and_bounded_counts() {
        assert_eq!(
            storage_record(WRITE.as_bytes()).unwrap(),
            BlockRecord {
                phase: crate::storage::Phase::Write,
                inputs: 1024,
                outputs: 300
            }
        );
        let verify = WRITE
            .replace("phase=write", "phase=verify")
            .replace("flushes=1", "flushes=0");
        assert_eq!(
            storage_record(verify.as_bytes()).unwrap().phase,
            crate::storage::Phase::Verify
        );
        for bad in [
            String::new(),
            format!("{WRITE}\r\n{WRITE}"),
            WRITE.replace("scope=pio", "scope=kernel"),
            WRITE.replace("phase=write", "phase=unknown"),
            WRITE.replace("phase=write", "phase=verify"),
            WRITE.replace("inputs=1024", "inputs=0"),
            WRITE.replace("inputs=1024", "inputs=01024"),
            WRITE.replace("outputs=300", "outputs=1000001"),
            WRITE.replace("denied=4", "denied=0"),
            WRITE.replace("malformed=4", "malformed=0"),
            WRITE.replace("direct_denied=1", "direct_denied=0"),
            WRITE.replace("exits=1", "exits=0"),
            WRITE.replace("frames=true", "frames=false"),
            WRITE.replace("metadata=true", "metadata=false"),
            format!("{WRITE} extra=true"),
            WRITE.replacen(' ', "  ", 1),
        ] {
            assert!(storage_record(bad.as_bytes()).is_err(), "accepted {bad:?}");
        }
    }
    #[test]
    fn optional_storage_record_cannot_skip_existing_proofs_or_follow_pass() {
        let prefix = "EVROSION_BOOT protocol=1 build=abc\r\nEVROSION_FRAMEBUFFER present=false width=0 height=0 stride=0 format=none\r\nEvrosion kernel entered.\r\n";
        let plain = format!("{prefix}{}\r\n", protocol::PASS);
        check(plain.as_bytes(), "abc", Some(33)).unwrap();
        assert!(
            check(
                format!("{prefix}{WRITE}\r\n{}\r\n", protocol::PASS).as_bytes(),
                "abc",
                Some(33)
            )
            .is_err()
        );
        assert!(check(format!("{plain}{WRITE}\r\n").as_bytes(), "abc", Some(33)).is_err());
    }
}
