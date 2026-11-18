// SPDX-License-Identifier: GPL-3.0-only
//! Bounded diagnostic observations for the explicit M6 session profile.
//! These rows explain real RPC timing; they establish no successful operation.
use crate::build::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Log {
    pub observed: u64,
    pub retained: u64,
    pub omitted: u64,
    pub detail_bytes: u64,
    pub final_bytes: u64,
    pub omitted_bytes: u64,
    pub prefix_closed: bool,
}
pub(crate) fn window_padding(line: &str, build: &str) -> Result<u64> {
    let line = line
        .strip_suffix(" status=observed")
        .ok_or("session padding status")?;
    let n = numbers(
        line,
        build,
        "EVROSION_M6_WINDOW_PADDING",
        &["start", "end", "nonzero", "first"],
    )?;
    if n[0] != 256
        || n[1] != 4096
        || n[2] > n[1] - n[0]
        || (n[2] == 0 && n[3] != n[1])
        || (n[2] != 0 && !(n[0]..n[1]).contains(&n[3]))
        || (n[2] != 0 && n[2] > n[1] - n[3])
    {
        return Err("session padding extent/count/first byte".into());
    }
    Ok(n[2])
}

fn numbers(line: &str, build: &str, prefix: &str, keys: &[&str]) -> Result<Vec<u64>> {
    let fields: Vec<_> = line.split(' ').collect();
    if fields.len() != 3 + keys.len()
        || fields[0] != prefix
        || fields[1] != "protocol=1"
        || fields[2] != format!("build={build}")
    {
        return Err("session retention record shape/build".into());
    }
    fields[3..]
        .iter()
        .zip(keys)
        .map(|(field, key)| crate::boot_protocol::canonical_number(field, key))
        .collect()
}

fn bound(line: &str, build: &str) -> Result<Vec<u64>> {
    let n = numbers(
        line,
        build,
        "EVROSION_M6_LOG_BOUND",
        &["observation", "retained", "detail_bytes"],
    )?;
    if n[1].checked_add(1) != Some(n[0]) || n[2] > 384 * 1024 {
        return Err("session retention boundary accounting".into());
    }
    Ok(n)
}

fn log(line: &str, build: &str) -> Result<Log> {
    let (line, closed) = line
        .rsplit_once(" prefix_closed=")
        .ok_or("session retention missing state")?;
    let prefix_closed = match closed {
        "true" => true,
        "false" => false,
        _ => return Err("session retention state".into()),
    };
    let n = numbers(
        line,
        build,
        "EVROSION_M6_LOG",
        &[
            "observed",
            "retained",
            "omitted",
            "detail_bytes",
            "final_bytes",
            "omitted_bytes",
        ],
    )?;
    if n[1].checked_add(n[2]) != Some(n[0])
        || n[3] > 384 * 1024
        || n[4] > 64 * 1024
        || prefix_closed != (n[2] != 0)
        || (n[2] == 0) != (n[5] == 0)
        || n[5] < n[2]
    {
        return Err("session retention inconsistent totals".into());
    }
    Ok(Log {
        observed: n[0],
        retained: n[1],
        omitted: n[2],
        detail_bytes: n[3],
        final_bytes: n[4],
        omitted_bytes: n[5],
        prefix_closed,
    })
}

/// Validate an explicit finite prefix and its final omission totals. This does
/// not reconstruct unrecorded lifecycle events or claim a complete history.
pub(crate) fn retention(serial: &[u8], build: &str) -> Result<Log> {
    retention_profile(serial, build, false)
}
pub(crate) fn retention_network_recovery(serial: &[u8], build: &str) -> Result<Log> {
    retention_profile(serial, build, true)
}
fn retention_profile(serial: &[u8], build: &str, recovery: bool) -> Result<Log> {
    if serial.len() > 1024 * 1024 || serial.last() != Some(&b'\n') {
        return Err("session retention capture bound/completeness".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "session retention UTF8")?;
    let mut boundary = None;
    let mut summary = None;
    let mut finished = false;
    let mut padding_count = 0;
    let mut common_seen = false;
    let mut memory_before = false;
    let mut memory_held = false;
    let mut memory_after = false;
    let mut profile_next = 0;
    let mut profiles_closed = false;
    let completion = if recovery {
        "EVROSION_M5_NATIVE_RECOVERY "
    } else {
        "EVROSION_M5_NATIVE "
    };
    for line in text.lines().map(|l| l.trim_end_matches('\r')) {
        if summary.is_some() && !finished && !line.starts_with(completion) {
            return Err("session detail follows final retention summary".into());
        }
        if profile_next != 0 && !line.starts_with("EVROSION_M5_NATIVE_PROFILE ") {
            profiles_closed = true;
            if padding_count != 2
                && !line.starts_with("EVROSION_M6_UI_COUNTS ")
                && !line.starts_with("EVROSION_M6_WINDOW_PADDING ")
            {
                return Err("detail interrupts final session profile batch".into());
            }
        }
        if line.starts_with("EVROSION_M6_WINDOW_PADDING") {
            if summary.is_some() || finished {
                return Err("duplicate/out-of-order App padding observation".into());
            }
            window_padding(line.trim_end_matches('\r'), build)?;
            match padding_count {
                0 if memory_before && !common_seen && profile_next == 0 => {}
                1 if common_seen && profile_next != 0 && !memory_held => {}
                _ => return Err("App padding lacks exact startup/final boundary".into()),
            }
            padding_count += 1;
        } else if line.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX ") {
            if padding_count != 1 || common_seen {
                return Err("session CommonPrefix lacks its unique startup padding".into());
            }
            common_seen = true;
        } else if line.starts_with("EVROSION_M5_NATIVE_PROFILE ") {
            // Retention validates ordering, not the selected graph's size.
            // The explicit boot profile separately requires exactly 7 or 9
            // fully decoded actor rows and validates their aggregate facts.
            let fields: Vec<_> = line.split(' ').collect();
            if !common_seen
                || padding_count != 1
                || profiles_closed
                || fields.len() < 6
                || fields[1] != "protocol=1"
                || fields[2] != format!("build={build}")
                || fields[3] != "phase=finished"
                || fields[4] != "scope=actor_slot"
                || crate::boot_protocol::canonical_number(fields[5], "index")? != profile_next
            {
                return Err(
                    "session final profiles are replayed, interrupted or out of order".into(),
                );
            }
            profile_next += 1;
        } else if line.starts_with("EVROSION_M5_NATIVE_MEMORY ") {
            crate::native_baselines::line(line, build)?;
            match line.split(' ').nth(3) {
                Some("phase=before") if !memory_before && padding_count == 0 && !common_seen => {
                    memory_before = true;
                }
                Some("phase=held") if padding_count == 2 && !memory_held && !memory_after => {
                    memory_held = true;
                }
                Some("phase=after") if memory_held && !memory_after => memory_after = true,
                _ => return Err("session padding/memory boundary order differs".into()),
            }
        } else if line.starts_with("EVROSION_M6_LOG_BOUND") {
            if boundary.is_some() || summary.is_some() || finished {
                return Err("duplicate/out-of-order session retention boundary".into());
            }
            boundary = Some(bound(line, build)?);
        } else if line.starts_with("EVROSION_M6_LOG") {
            if summary.is_some() || finished || padding_count != 2 || !memory_after {
                return Err("duplicate/out-of-order session retention summary".into());
            }
            summary = Some(log(line, build)?);
        } else if line.starts_with(completion) {
            if summary.is_none() || finished {
                return Err("session completion precedes retention summary".into());
            }
            finished = true;
        } else if line.starts_with("EVROSION_M5_NATIVE ")
            || line.starts_with("EVROSION_M5_NATIVE_RECOVERY ")
        {
            return Err("session completion differs from the explicitly selected mode".into());
        }
    }
    let summary = summary.ok_or("session retention summary absent")?;
    if !finished
        || padding_count != 2
        || !common_seen
        || profile_next == 0
        || summary.prefix_closed != boundary.is_some()
        || boundary.as_ref().is_some_and(|b| {
            b[0] > summary.observed || b[1] > summary.retained || b[2] != summary.detail_bytes
        })
    {
        return Err("session retention boundary/completion differs from totals".into());
    }
    Ok(summary)
}

pub(crate) fn without_diagnostics(serial: &[u8], build: &str) -> Result<Vec<u8>> {
    without_profile_diagnostics(serial, build, false, None)
}
pub(crate) fn without_network_diagnostics(serial: &[u8], build: &str) -> Result<Vec<u8>> {
    without_selected_network_diagnostics(serial, build, None)
}
pub(crate) fn without_network_negative_diagnostics(
    serial: &[u8],
    build: &str,
    proof: &crate::network_negative::records::Cancelled,
) -> Result<Vec<u8>> {
    if !proof.matches(serial) {
        return Err("negative diagnostics proof belongs to another raw serial".into());
    }
    without_selected_network_diagnostics(serial, build, Some(proof))
}
fn without_selected_network_diagnostics(
    serial: &[u8],
    build: &str,
    negative: Option<&crate::network_negative::records::Cancelled>,
) -> Result<Vec<u8>> {
    crate::restart_protocol::records(serial, build)?;
    crate::network_protocol::records(serial, build)?;
    crate::network_error_protocol::records(serial, build)?;
    crate::time_protocol::records(serial, build)?;
    crate::time_proof_protocol::records(serial, build)?;
    crate::tc_protocol::records(serial, build)?;
    crate::te_protocol::records(serial, build)?;
    crate::image_protocol::records(serial, build)?;
    crate::downloaded_protocol::records(serial, build, false)?;
    crate::update_protocol::records(serial, build)?;
    crate::rpc_rejection_protocol::records(serial, build)?;
    without_profile_diagnostics(serial, build, true, negative)
}
fn without_profile_diagnostics(
    serial: &[u8],
    build: &str,
    network: bool,
    negative: Option<&crate::network_negative::records::Cancelled>,
) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(serial).map_err(|_| "session serial is not UTF-8")?;
    let startup = if network {
        crate::startup_protocol::record(serial, build)?
    } else {
        None
    };
    let mut output = Vec::new();
    let mut count = 0;
    let mut async_count = 0;
    let mut ui_count = 0;
    for (at, line) in text.lines().enumerate() {
        if startup.as_ref().is_some_and(|r| r.contains_line(at)) {
            // Original serial was validated as one exact closed current block.
        } else if line.starts_with("EVROSION_M6_WINDOW_PADDING") {
            window_padding(line.trim_end_matches('\r'), build)?;
            output.extend_from_slice(line.as_bytes());
            output.push(b'\n');
        } else if line.starts_with("EVROSION_M6_LOG_BOUND") {
            bound(line.trim_end_matches('\r'), build)?;
            output.extend_from_slice(line.as_bytes());
            output.push(b'\n');
        } else if line.starts_with("EVROSION_M6_LOG") {
            log(line.trim_end_matches('\r'), build)?;
            output.extend_from_slice(line.as_bytes());
            output.push(b'\n');
        } else if network && line.starts_with("EVROSION_M6_NETWORK_PROGRESS") {
            crate::network_protocol::line(line.trim_end_matches('\r'), build)?;
            output.extend_from_slice(line.as_bytes());
            output.push(b'\n');
        } else if network && line.starts_with("EVROSION_M6_TIME_PROGRESS") {
            crate::time_protocol::line(line.trim_end_matches('\r'), build)?;
            output.extend_from_slice(line.as_bytes());
            output.push(b'\n');
        } else if network && line.starts_with("EVROSION_M6_TIME_PROOF") {
            crate::time_proof_protocol::line(line.trim_end_matches('\r'), build)?;
            output.extend_from_slice(line.as_bytes());
            output.push(b'\n');
        } else if network && line.starts_with("EVROSION_M6_TIME_CHECK") {
            crate::tc_protocol::line(line.trim_end_matches('\r'), build)?;
            output.extend_from_slice(line.as_bytes());
            output.push(b'\n');
        } else if network && line.starts_with("EVROSION_M6_TIME_EXCHANGE") {
            crate::te_protocol::line(line.trim_end_matches('\r'), build)?;
            output.extend_from_slice(line.as_bytes());
            output.push(b'\n');
        } else if network && line.starts_with("EVROSION_M6_NETWORK_ERROR") {
            crate::network_error_protocol::line(line.trim_end_matches('\r'), build)?;
            output.extend_from_slice(line.as_bytes());
            output.push(b'\n');
        } else if network && line.starts_with("EVROSION_M6_RESTART") {
            crate::restart_protocol::line(line.trim_end_matches('\r'), build)?;
            output.extend_from_slice(line.as_bytes());
            output.push(b'\n');
        } else if network && line.starts_with("EVROSION_M6_DOWNLOADED_ACTION") {
            crate::downloaded_protocol::line(line.trim_end_matches('\r'), build)?;
            output.extend_from_slice(line.as_bytes());
            output.push(b'\n');
        } else if network && line.starts_with("EVROSION_M6_IMAGE") {
            crate::image_protocol::line(line.trim_end_matches('\r'), build)?;
            output.extend_from_slice(line.as_bytes());
            output.push(b'\n');
        } else if network && line.starts_with("EVROSION_M6_UPDATE_PROGRESS") {
            crate::update_protocol::line(line.trim_end_matches('\r'), build)?;
            output.extend_from_slice(line.as_bytes());
            output.push(b'\n');
        } else if network && line.starts_with("EVROSION_M6_RPC_REJECTION") {
            crate::rpc_rejection_protocol::line(line.trim_end_matches('\r'), build)?;
            output.extend_from_slice(line.as_bytes());
            output.push(b'\n');
        } else if negative.is_some()
            && (line.starts_with("EVROSION_M6_NEGATIVE_CPU")
                || line.starts_with("EVROSION_M6_NEGATIVE_WORK"))
        {
            crate::network_negative::endurance_diagnostic(line.trim_end_matches('\r'), build)?;
        } else if negative.is_some() && line.starts_with("EVROSION_M6_NEGATIVE") {
            crate::network_negative::records::line(line.trim_end_matches('\r'), build)?;
        } else if negative.is_some() && line.starts_with("EVROSION_M6_NETWORK_RETIREMENT") {
            crate::network_negative::retirement::line(line.trim_end_matches('\r'), build)?;
        } else if line.starts_with("EVROSION_M6_RPC") {
            count += 1;
            if count > 96 {
                return Err("session RPC diagnostic bound exceeded".into());
            }
            diagnostic(line, build)?;
        } else if line.starts_with("EVROSION_M6_ASYNC_EXPIRED") {
            async_count += 1;
            async_expiry(line, build, async_count)?;
        } else if line.starts_with("EVROSION_M6_") {
            ui_count += 1;
            if ui_count > 161 {
                return Err("session UI diagnostic retention bound".into());
            }
            crate::session_io::line(line, build)?;
        } else {
            output.extend_from_slice(line.as_bytes());
            output.push(b'\n');
        }
    }
    Ok(output)
}
fn async_expiry(line: &str, build: &str, sequence: u64) -> Result<()> {
    const KEYS: [&str; 10] = [
        "sequence",
        "endpoint",
        "ticket",
        "sender_process",
        "sender_thread",
        "receiver_process",
        "receiver_thread",
        "deadline",
        "tick",
        "value",
    ];
    let fields: Vec<_> = line.split(' ').collect();
    if fields.len() != 13
        || fields[0] != "EVROSION_M6_ASYNC_EXPIRED"
        || fields[1] != "protocol=1"
        || fields[2] != format!("build={build}")
        || sequence > 32
    {
        return Err("malformed/capped session queued-expiry observation".into());
    }
    let mut numbers = [0; 10];
    for (i, key) in KEYS.iter().enumerate() {
        let value = fields[i + 3]
            .strip_prefix(&format!("{key}="))
            .ok_or("queued-expiry field/order")?;
        numbers[i] = if i == 9 {
            if value.len() != 16
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("queued-expiry scalar word".into());
            }
            u64::from_str_radix(value, 16).map_err(|_| "queued-expiry scalar overflow")?
        } else {
            if value.is_empty()
                || (value.len() > 1 && value.starts_with('0'))
                || !value.bytes().all(|b| b.is_ascii_digit())
            {
                return Err("queued-expiry number".into());
            }
            value
                .parse::<u64>()
                .map_err(|_| "queued-expiry number overflow")?
        };
    }
    if numbers[0] != sequence
        || numbers[2] == 0
        || numbers[7] == u64::MAX
        || numbers[8] < numbers[7]
    {
        return Err("inconsistent queued-expiry observation".into());
    }
    Ok(())
}

fn diagnostic(line: &str, build: &str) -> Result<()> {
    let fields: Vec<_> = line.split(' ').collect();
    const KEYS: [&str; 21] = [
        "call_epoch",
        "call",
        "caller_process",
        "caller_thread",
        "callee_process",
        "callee_thread",
        "endpoint",
        "request",
        "started",
        "tick",
        "deadline",
        "status",
        "callee_cpu",
        "scheduler_tick",
        "quota",
        "period",
        "window_start",
        "window_end",
        "used",
        "reserved",
        "remaining",
    ];
    if fields.len() != 25
        || fields[0] != "EVROSION_M6_RPC"
        || fields[1] != "protocol=1"
        || fields[2] != format!("build={build}")
        || !matches!(
            fields[3],
            "phase=accepted" | "phase=completed" | "phase=terminal" | "phase=quiescent"
        )
    {
        return Err("malformed session RPC diagnostic".into());
    }
    let mut n = [0u64; 21];
    for (index, key) in KEYS.iter().enumerate() {
        let value = fields[index + 4]
            .strip_prefix(&format!("{key}="))
            .ok_or("session RPC diagnostic field/order")?;
        n[index] = if *key == "request" {
            if value.len() != 16
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("session RPC request word".into());
            }
            u64::from_str_radix(value, 16).map_err(|_| "session RPC request overflow")?
        } else {
            if value.is_empty()
                || (value.len() > 1 && value.starts_with('0'))
                || !value.bytes().all(|b| b.is_ascii_digit())
            {
                return Err("session RPC number encoding".into());
            }
            value.parse().map_err(|_| "session RPC number overflow")?
        };
    }
    if n[..6].iter().any(|v| matches!(*v, 0 | u64::MAX))
        || n[8] > n[9]
        || n[8] >= n[10]
        || n[10] == u64::MAX
        || n[14] == 0
        || n[14] > n[15]
        || n[15] == u64::MAX
        || n[16].checked_add(n[15]) != Some(n[17])
        || n[18].checked_add(n[19]).and_then(|v| v.checked_add(n[20])) != Some(n[14])
    {
        return Err("inconsistent session RPC observation".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exact actual14 bytes remain in the fixture. Normalization and the edits
    // in individual tests are parser inputs, never new execution evidence.
    fn fixture() -> (String, String) {
        let serial = include_str!("../../../tests/fixtures/m6-session-exercise-parser.serial");
        let build = serial
            .lines()
            .find(|l| l.starts_with("EVROSION_BOOT "))
            .unwrap()
            .split(' ')
            .find_map(|f| f.strip_prefix("build="))
            .unwrap()
            .to_owned();
        (serial.lines().collect::<Vec<_>>().join("\n") + "\n", build)
    }

    fn complete_log(build: &str) -> String {
        format!(
            "EVROSION_M6_LOG protocol=1 build={build} observed=210 retained=210 omitted=0 detail_bytes=67533 final_bytes=1955 omitted_bytes=0 prefix_closed=false\n"
        )
    }

    #[test]
    fn actual14_raw_trace_has_exact_startup_and_final_padding_boundaries() {
        use sha2::{Digest, Sha256};
        let raw = include_bytes!("../../../tests/fixtures/m6-session-exercise-parser.serial");
        assert_eq!(raw.len(), 80_485);
        assert_eq!(
            format!("{:x}", Sha256::digest(raw)),
            "10c49bb5ec3c16bcdd4b47049231213e1ea687f8836dec4931e6620e3e361939"
        );
        let (_, build) = fixture();
        let log = retention(raw, &build).unwrap();
        assert_eq!((log.observed, log.retained, log.omitted), (210, 210, 0));
        let body = without_diagnostics(raw, &build).unwrap();
        crate::boot_protocol::check_session(&body, &build, Some(33)).unwrap();
        assert!(
            crate::native_protocol::record_session(raw, &build)
                .unwrap()
                .history_complete
        );
        // Replaying historical bytes only verifies this parser. The original
        // actual14 whole command stays failed and has no cold-reopen evidence.
        assert!(crate::boot_protocol::check(&body, &build, Some(33)).is_err());
    }

    #[test]
    fn padding_boundaries_reject_missing_extra_reordered_truncated_and_wrong_build() {
        let (serial, build) = fixture();
        let row = |prefix: &str| {
            serial
                .lines()
                .find(|l| l.starts_with(prefix))
                .unwrap()
                .to_owned()
                + "\n"
        };
        let padding = row("EVROSION_M6_WINDOW_PADDING ");
        let common = row("EVROSION_M5_NATIVE_COMMON_PREFIX ");
        let profile = row("EVROSION_M5_NATIVE_PROFILE ");
        let held = serial
            .lines()
            .find(|l| l.contains(" phase=held "))
            .unwrap()
            .to_owned()
            + "\n";
        let mut no_final = serial.clone();
        let at = no_final.rfind(&padding).unwrap();
        no_final.replace_range(at..at + padding.len(), "");
        let no_startup = serial.replacen(&padding, "", 1);
        let cases = [
            no_final.clone(),
            no_startup.clone(),
            serial.replacen(&padding, &padding.repeat(2), 1),
            no_startup.replacen(&common, &(common.clone() + &padding), 1),
            no_final.replacen(&profile, &(padding.clone() + &profile), 1),
            no_final.replacen(&held, &(held.clone() + &padding), 1),
            serial.replace(&padding, &padding.replace(&build, &"b".repeat(64))),
            serial[..serial.len() - 1].to_owned(),
            serial.replace("nonzero=0 first=4096", "nonzero=0 first=4095"),
        ];
        for (case, changed) in cases.iter().enumerate() {
            assert!(
                retention(changed.as_bytes(), &build).is_err(),
                "case {case}"
            );
            if case != 7 {
                assert!(
                    without_diagnostics(changed.as_bytes(), &build)
                        .and_then(|body| crate::boot_protocol::check_session(
                            &body,
                            &build,
                            Some(33)
                        ))
                        .is_err(),
                    "boot case {case}"
                );
            }
        }
        // The real driver checks raw completeness before line filtering,
        // which normalizes terminators. The boot parser also rejects its own
        // truncated input rather than using that normalization as evidence.
        let mut body = without_diagnostics(serial.as_bytes(), &build).unwrap();
        body.pop();
        assert!(crate::boot_protocol::check_session(&body, &build, Some(33)).is_err());
    }

    #[test]
    fn final_padding_cannot_substitute_for_the_selected_seven_actor_profile_batch() {
        let (serial, build) = fixture();
        let last = serial
            .lines()
            .find(|l| l.starts_with("EVROSION_M5_NATIVE_PROFILE ") && l.contains(" index=6 "))
            .unwrap()
            .to_owned()
            + "\n";
        for changed in [
            serial.replace(&last, ""),
            serial.replace(&last, &(last.clone() + &last.replace("index=6", "index=7"))),
        ] {
            // Generic history parsing does not infer a graph from row counts.
            retention(changed.as_bytes(), &build).unwrap();
            let body = without_diagnostics(changed.as_bytes(), &build).unwrap();
            assert!(crate::boot_protocol::check_session(&body, &build, Some(33)).is_err());
        }
        let first = serial
            .lines()
            .find(|l| l.starts_with("EVROSION_M5_NATIVE_PROFILE "))
            .unwrap();
        let interrupted = serial.replacen(first, &format!("{first}\nunexpected"), 1);
        assert!(retention(interrupted.as_bytes(), &build).is_err());
    }

    #[test]
    fn complete_session_retention_is_explicit_and_legacy_parser_stays_strict() {
        let (serial, build) = fixture();
        let with_log = serial;
        assert_eq!(retention(with_log.as_bytes(), &build).unwrap().omitted, 0);
        let body = without_diagnostics(with_log.as_bytes(), &build).unwrap();
        crate::boot_protocol::check_session(&body, &build, Some(33)).unwrap();
        assert!(crate::boot_protocol::check(with_log.as_bytes(), &build, Some(33)).is_err());
        assert!(
            crate::native_protocol::record_session(with_log.as_bytes(), &build)
                .unwrap()
                .history_complete
        );
        for bad in [
            with_log.replace("retained=210", "retained=209"),
            with_log.replace("omitted=0", "omitted=1"),
            with_log.replace("detail_bytes=67533", "detail_bytes=393217"),
            with_log.replace("final_bytes=1955", "final_bytes=65537"),
            with_log.replace("prefix_closed=false", "prefix_closed=true"),
            with_log.replace("observed=210", "observed=0210"),
            with_log.replace(&complete_log(&build), ""),
            with_log.replace(&complete_log(&build), &complete_log(&build).repeat(2)),
            with_log.replace(
                &complete_log(&build),
                &(complete_log(&build) + "unexpected\n"),
            ),
        ] {
            assert!(retention(bad.as_bytes(), &build).is_err());
        }
    }

    #[test]
    fn truncated_history_cannot_claim_complete_action_evidence() {
        let (serial, build) = fixture();
        let first_state = serial
            .lines()
            .find(|l| l.starts_with("EVROSION_NATIVE_STATE "))
            .unwrap();
        let start = serial
            .lines()
            .find(|l| l.starts_with("EVROSION_M5_NATIVE_ACTION "))
            .unwrap();
        let finish = serial
            .lines()
            .rev()
            .find(|l| l.starts_with("EVROSION_NATIVE_STATE "))
            .unwrap();
        let summary = serial
            .lines()
            .find(|l| l.starts_with("EVROSION_M5_NATIVE "))
            .unwrap();
        let boundary = format!(
            "EVROSION_M6_LOG_BOUND protocol=1 build={build} observation=3 retained=2 detail_bytes=393210"
        );
        let totals = format!(
            "EVROSION_M6_LOG protocol=1 build={build} observed=13 retained=3 omitted=10 detail_bytes=393210 final_bytes=1000 omitted_bytes=4000 prefix_closed=true"
        );
        let row = |prefix: &str| serial.lines().find(|l| l.starts_with(prefix)).unwrap();
        let profiles = serial
            .lines()
            .filter(|l| l.starts_with("EVROSION_M5_NATIVE_PROFILE "))
            .collect::<Vec<_>>()
            .join("\n");
        let padding = row("EVROSION_M6_WINDOW_PADDING ");
        let before = serial
            .lines()
            .find(|l| l.contains(" phase=before "))
            .unwrap();
        let held = serial.lines().find(|l| l.contains(" phase=held ")).unwrap();
        let after = serial
            .lines()
            .find(|l| l.contains(" phase=after "))
            .unwrap();
        let common = row("EVROSION_M5_NATIVE_COMMON_PREFIX ");
        let partial = format!(
            "{before}\n{padding}\n{common}\n{first_state}\n{start}\n{boundary}\n{finish}\n{profiles}\n{padding}\n{held}\n{after}\n{totals}\n{summary}\n"
        );
        let record = crate::native_protocol::record_session(partial.as_bytes(), &build).unwrap();
        assert!(!record.history_complete);
        assert_eq!(record.actions.len(), 1);
        assert!(crate::native_protocol::record(partial.as_bytes(), &build).is_err());
        for bad in [
            partial.replace(&boundary, ""),
            partial.replace("retained=2", "retained=1"),
            partial.replace("detail_bytes=393210 final", "detail_bytes=393209 final"),
            partial.replace(&boundary, &format!("{boundary}\n{start}")),
            partial.replace(&boundary, &format!("{boundary}\n{first_state}")),
        ] {
            assert!(crate::native_protocol::record_session(bad.as_bytes(), &build).is_err());
        }
    }
    #[test]
    fn client_padding_is_observed_without_becoming_a_hardware_guard_claim() {
        let row = "EVROSION_M6_WINDOW_PADDING protocol=1 build=test start=256 end=4096 nonzero=1 first=512 status=observed";
        assert_eq!(window_padding(row, "test").unwrap(), 1);
        assert_eq!(
            without_diagnostics(row.as_bytes(), "test").unwrap(),
            format!("{row}\n").as_bytes()
        );
        for bad in [
            row.replace("start=256", "start=512"),
            row.replace("nonzero=1", "nonzero=0"),
            row.replace("first=512", "first=4096"),
            row.replace("nonzero=1", "nonzero=4096"),
            row.replace("status=observed", "status=PASS"),
            format!("{row} repaired=true"),
        ] {
            assert!(window_padding(&bad, "test").is_err());
        }
    }
    #[test]
    fn queued_expiry_is_bounded_diagnostic_data_and_never_a_delivery_ack() {
        let row = "EVROSION_M6_ASYNC_EXPIRED protocol=1 build=test sequence=1 endpoint=15 ticket=9 sender_process=2 sender_thread=2 receiver_process=1 receiver_thread=1 deadline=512 tick=513 value=0102030405060708";
        assert!(
            without_diagnostics(row.as_bytes(), "test")
                .unwrap()
                .is_empty()
        );
        assert!(
            without_diagnostics(row.replace("sequence=1", "sequence=2").as_bytes(), "test")
                .is_err()
        );
        assert!(
            without_diagnostics(row.replace("tick=513", "tick=511").as_bytes(), "test").is_err()
        );
        assert!(
            without_diagnostics(row.replace("build=test", "build=other").as_bytes(), "test")
                .is_err()
        );
    }
    #[test]
    fn observations_cannot_hide_wrong_build_malformed_budget_or_failure() {
        let row = "EVROSION_M6_RPC protocol=1 build=test phase=accepted call_epoch=1 call=2 caller_process=1 caller_thread=1 callee_process=2 callee_thread=2 endpoint=9 request=ffffffffffffffff started=10 tick=10 deadline=522 status=0 callee_cpu=3 scheduler_tick=10 quota=64 period=256 window_start=0 window_end=256 used=3 reserved=0 remaining=61";
        let serial = format!("before\n{row}\nEVROSION_PANIC retained\n");
        assert_eq!(
            without_diagnostics(serial.as_bytes(), "test").unwrap(),
            b"before\nEVROSION_PANIC retained\n"
        );
        for bad in [
            row.replace("build=test", "build=other"),
            row.replace("remaining=61", "remaining=62"),
            row.replace("deadline=522", "deadline=10"),
            format!("{row} extra=1"),
            row.replace("call=2", "call=02"),
            row.replace("phase=accepted", "phase=success"),
        ] {
            assert!(without_diagnostics(bad.as_bytes(), "test").is_err());
        }
        assert!(without_diagnostics(format!("{row}\n").repeat(96).as_bytes(), "test").is_ok());
        assert!(without_diagnostics(format!("{row}\n").repeat(97).as_bytes(), "test").is_err());
    }
}
