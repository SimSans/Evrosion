//! Strict diagnostics for the bounded owner recovery fixture. These records are
//! checked against immutable catalogue and read-only disk evidence by its runner.
use crate::boot_protocol::{canonical_number as number, generation_report_hex};
use ev_userspace_contract::generation::{Completion, Mode, OwnerDecision};

type Result<T> = std::result::Result<T, String>;

pub(crate) fn ui_line(stage: u8, line: &str, prompted: bool) -> Result<u8> {
    if prompted && stage == 5 && line == "Please type r or q, then Enter." {
        return Ok(stage);
    }
    match (stage, line) {
        (0, "Evrosion generation 2 could not start: a process fault.") => Ok(1),
        (1, _)
            if line.starts_with("Failed image: ")
                && hex(line.strip_prefix("Failed image: ").unwrap(), 32)?.len() == 32 =>
        {
            Ok(2)
        }
        (2, "Current selection: generation 3 (pending validation).") => Ok(3),
        (3, "Known-good generation 1 is available. Returning keeps your files.") => Ok(4),
        (4, "Type r then Enter to continue with known-good, or q then Enter to cancel.") => Ok(5),
        _ => Err("malformed owner recovery explanation".into()),
    }
}

pub(crate) fn text(serial: &[u8]) -> Result<&str> {
    if serial.len() > 1024 * 1024 {
        return Err("owner serial exceeded 1 MiB".into());
    }
    std::str::from_utf8(serial).map_err(|_| "owner serial is not UTF-8".into())
}

pub(crate) fn one<'a>(serial: &'a [u8], prefix: &str) -> Result<&'a str> {
    let mut lines = text(serial)?
        .lines()
        .filter(|line| line.starts_with(prefix));
    let line = lines.next().ok_or_else(|| format!("missing {prefix}"))?;
    if lines.next().is_some() {
        return Err(format!("duplicate {prefix}"));
    }
    Ok(line)
}

pub(crate) fn hex(hex: &str, maximum: usize) -> Result<Vec<u8>> {
    if hex.len() > maximum * 2
        || !hex.len().is_multiple_of(2)
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("noncanonical owner hex".into());
    }
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |b| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            Ok(digit(pair[0]) * 16 + digit(pair[1]))
        })
        .collect()
}

pub(crate) fn decision_name(decision: OwnerDecision) -> &'static str {
    match decision {
        OwnerDecision::None => "none",
        OwnerDecision::Continue => "continue",
        OwnerDecision::Cancel => "cancel",
        OwnerDecision::Timeout => "timeout",
        OwnerDecision::InputFault => "input-fault",
        OwnerDecision::InputBudget => "input-budget",
    }
}

/// The first complete valid ASCII command line, independently reconstructed from
/// actual UART DATA reads. Status-port polls never enter this byte stream.
pub(crate) fn received_choice(bytes: &[u8]) -> Option<OwnerDecision> {
    for line in bytes.split_inclusive(|byte| matches!(byte, b'\r' | b'\n')) {
        if !line
            .last()
            .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
        {
            continue;
        }
        let line = &line[..line.len() - 1];
        let leading = line
            .iter()
            .take_while(|byte| matches!(byte, b' ' | b'\t'))
            .count();
        let decision = match &line[leading..] {
            b"r" | b"R" => Some(OwnerDecision::Continue),
            b"q" | b"Q" => Some(OwnerDecision::Cancel),
            _ => None,
        };
        if let Some(decision) = decision {
            return Some(decision);
        }
    }
    None
}

#[derive(serde::Serialize)]
pub(crate) struct Prompt {
    pub(crate) build: String,
    pub(crate) catalogue: String,
    pub(crate) operation: u64,
    pub(crate) deadline: u64,
}
pub(crate) fn prompt_line(line: &str, build: &str, catalogue: Option<&str>) -> Result<Prompt> {
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 512
        || f.len() != 11
        || f[0] != "EVROSION_M3_OWNER_PROMPT"
        || f[1] != "protocol=1"
        || f[2] != format!("build={build}")
        || f[4] != "operation=16"
        || f[5] != "selected=3"
        || f[6] != "known_good=1"
        || f[7] != "failure_generation=2"
        || f[8] != "failure_serial=2"
        || f[10] != "actions=r,q"
    {
        return Err("malformed or wrong-build owner prompt".into());
    }
    if hex(build, 32)?.len() != 32 {
        return Err("owner prompt build ID must be32 bytes".into());
    }
    let found = f[3]
        .strip_prefix("catalogue=")
        .ok_or("owner prompt has no catalogue")?;
    if hex(found, 32)?.len() != 32 || catalogue.is_some_and(|expected| expected != found) {
        return Err("owner prompt has the wrong catalogue".into());
    }
    let deadline = number(f[9], "deadline")?;
    if deadline == 0 || deadline == u64::MAX {
        return Err("owner prompt has no finite deadline".into());
    }
    Ok(Prompt {
        build: build.into(),
        catalogue: found.into(),
        operation: 16,
        deadline,
    })
}
pub(crate) fn prompt(serial: &[u8], build: &str, catalogue: &str) -> Result<Option<Prompt>> {
    let mut prompts = text(serial)?
        .split_inclusive('\n')
        .filter(|line| line.starts_with("EVROSION_M3_OWNER_PROMPT "));
    let Some(line) = prompts.next() else {
        return Ok(None);
    };
    if prompts.next().is_some() {
        return Err("duplicate owner prompt".into());
    }
    if !line.ends_with('\n') {
        return Ok(None);
    }
    prompt_line(line.trim_end_matches(['\r', '\n']), build, Some(catalogue)).map(Some)
}

pub(crate) struct Record {
    pub(crate) report: Completion,
    pub(crate) uart_inputs: u64,
    pub(crate) uart_outputs: u64,
    pub(crate) received: Vec<u8>,
    pub(crate) before_tx: usize,
}

pub(crate) fn line(line: &str) -> Result<Record> {
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 1536
        || f.len() != 26
        || f[0] != "EVROSION_M3_OWNER"
        || f[1] != "status=PASS"
        || f[2] != "scope=recovery"
        || f[19] != "catalogue=true"
        || f[20] != "frames=true"
        || f[21] != "metadata=true"
        || f[22] != "guards=true"
    {
        return Err("malformed owner recovery record".into());
    }
    let report = generation_report_hex(
        f[23]
            .strip_prefix("report=")
            .ok_or("missing owner report")?,
    )?;
    let (phase, operation, mutations, serial) = match report.mode {
        Mode::ProvisionA => ("provision-a", 4, 23, 1),
        Mode::FailB => ("fail-b", 10, 28, 2),
        Mode::AutoA => ("auto-a", 14, 18, 3),
        Mode::Verify => ("verify", 21, 0, 0),
        Mode::OwnerPrepare3 => ("owner-prepare3", 16, 10, 0),
        Mode::OwnerRecover if report.owner_decision == OwnerDecision::Continue => {
            ("owner-recover", 21, 22, 4)
        }
        Mode::OwnerRecover => ("owner-recover", 16, 0, 0),
        Mode::ManualA => return Err("owner recovery cannot bypass console consent".into()),
    };
    if f[3] != format!("phase={phase}")
        || f[4] != format!("decision={}", decision_name(report.owner_decision))
        || (report.operation, report.mutations, report.boot_serial)
            != (operation, mutations, serial)
        || number(f[9], "mutations")? != mutations
    {
        return Err("owner report differs from its durable phase contract".into());
    }
    let calls = number(f[5], "calls")?;
    if !(1..=100_000).contains(&calls) {
        return Err("unbounded owner storage calls".into());
    }
    for (field, name) in f[6..9].iter().zip(["blocks", "wakes", "replies"]) {
        if number(field, name)? != calls {
            return Err("owner call/wait/reply imbalance".into());
        }
    }
    let active = u64::from(report.process != 0);
    let failed = u64::from(report.mode == Mode::FailB);
    let ready = number(f[11], "ready")?;
    if number(f[10], "starts")? != active
        || ready > active
        || (active == 1 && failed == 0 && ready != 1)
        || number(f[12], "critical_ready")? != active - failed
        || number(f[13], "faults")? != failed
        || number(f[14], "stops")? != active
        || number(f[15], "reaps")? != active
        || number(f[16], "forged")? != report.negatives
    {
        return Err("owner lifecycle/provenance mismatch".into());
    }
    let uart_inputs = number(f[17], "uart_inputs")?;
    let uart_outputs = number(f[18], "uart_outputs")?;
    let before_tx = usize::try_from(number(f[24], "uart_rx_before_tx")?)
        .map_err(|_| "owner RX offset overflow")?;
    let received = hex(
        f[25]
            .strip_prefix("uart_rx=")
            .ok_or("missing actual UART input")?,
        128,
    )?;
    if before_tx > received.len() {
        return Err("owner RX offset exceeds actual DATA bytes".into());
    }
    if uart_inputs > 8_000_000 || uart_outputs > 8_000_000 || uart_inputs < received.len() as u64 {
        return Err("unbounded owner UART facts".into());
    }
    if report.mode == Mode::OwnerRecover {
        if uart_outputs == 0 {
            return Err("owner recovery never displayed its prompt".into());
        }
        match report.owner_decision {
            OwnerDecision::Continue | OwnerDecision::Cancel => {
                if received_choice(&received[before_tx..]) != Some(report.owner_decision) {
                    return Err("owner decision lacks a matching actual UART command line".into());
                }
            }
            _ if received_choice(&received[before_tx..]).is_some() => {
                return Err("owner discarded a valid submitted decision".into());
            }
            _ => (),
        }
    } else if uart_inputs != 0 || uart_outputs != 0 || !received.is_empty() {
        return Err("noninteractive phase performed owner UART activity".into());
    }
    let failure = if report.mode == Mode::ProvisionA {
        (0, 0, 0, 0, 0)
    } else {
        (2, 2, 1, 10, 11)
    };
    if (
        report.failure_generation,
        report.failure_serial,
        report.failure_reason,
        report.failure_operation,
        report.failure_sequence,
    ) != failure
    {
        return Err("owner recovery lost original failed generation identity".into());
    }
    Ok(Record {
        report,
        uart_inputs,
        uart_outputs,
        received,
        before_tx,
    })
}

pub(crate) fn record(serial: &[u8]) -> Result<Record> {
    line(one(serial, "EVROSION_M3_OWNER ")?)
}

#[derive(serde::Serialize)]
pub(crate) struct Budget {
    pub(crate) elapsed: u64,
    pub(crate) driver: u64,
    pub(crate) controller: u64,
    pub(crate) critical: u64,
    pub(crate) parent: u64,
    pub(crate) transitions: u64,
}
pub(crate) fn budget_line(line: &str) -> Result<Budget> {
    let f: Vec<_> = line.split(' ').collect();
    if f.len() != 14
        || f[0] != "EVROSION_M3_OWNER_BUDGET"
        || f[1] != "status=PASS"
        || f[3] != "limit_ticks=65536"
        || f[8] != "parent_limit=131072"
        || f[10] != "transition_limit=8000000"
        || f[11] != "max_pending=1"
        || f[12] != "accounted=true"
        || f[13] != "bounded=true"
    {
        return Err("malformed owner budget record".into());
    }
    let result = Budget {
        elapsed: number(f[2], "elapsed_ticks")?,
        driver: number(f[4], "driver_cpu")?,
        controller: number(f[5], "controller_cpu")?,
        critical: number(f[6], "critical_cpu")?,
        parent: number(f[7], "parent_cpu")?,
        transitions: number(f[9], "transitions")?,
    };
    if result.elapsed >= 65536
        || result.parent != result.elapsed
        || result
            .driver
            .checked_add(result.controller)
            .and_then(|n| n.checked_add(result.critical))
            != Some(result.parent)
        || !(1..=8_000_000).contains(&result.transitions)
    {
        return Err("owner budget exhausted or ancestor accounting unbalanced".into());
    }
    Ok(result)
}
pub(crate) fn budget(serial: &[u8]) -> Result<Budget> {
    budget_line(one(serial, "EVROSION_M3_OWNER_BUDGET ")?)
}

#[cfg(test)]
#[path = "owner_protocol_tests.rs"]
mod tests;
