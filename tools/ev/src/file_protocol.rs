//! Strict diagnostics for the closed, capability-bound File/Object experiment.
use crate::boot_protocol::canonical_number as number;
use ev_userspace_contract::file_test::{Completion, DATA_B, Mode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, String>;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Record {
    pub(crate) report: Completion,
    pub(crate) calls: u64,
    pub(crate) backend: u64,
    pub(crate) nested: u64,
    pub(crate) startup: u64,
    pub(crate) pre_delivery: u64,
    pub(crate) delivered_nested: u64,
    pub(crate) mutations: u64,
}
impl Record {
    pub(crate) fn evidence(&self) -> Value {
        let r = self.report;
        json!({"phase":if r.mode==Mode::Write {"write"}else{"verify"},
            "calls":self.calls,"blocks":self.calls,"wakes":self.calls,"replies":self.calls,
            "outer":r.requests,"backend":self.backend,"nested":self.nested,"startup":self.startup,
            "pre_delivery":self.pre_delivery,"delivered_nested":self.delivered_nested,
            "max_pending":2,"mutations":self.mutations,"snapshots":r.private_snapshot,
            "authority_denied":1,"block_denied":1,"unbound_denied":1,"bindings":2,"mapped":4,
            "frames":true,"metadata":true,"guards":true,"object":r.object,"counter":r.counter,
            "ro_denied":r.ro_denied,"malformed":r.malformed,"invalid_counter":r.invalid_counter,
            "skipped":r.skipped,"conflicting":r.conflicting,"duplicates":r.duplicates,
            "payload_sha256":format!("{:x}",Sha256::digest(DATA_B)),
            "completion_hex":r.encode().iter().map(|b|format!("{b:02x}")).collect::<String>()})
    }
}

fn completion(text: &str) -> Result<Completion> {
    let hex = text
        .strip_prefix("report=")
        .ok_or("missing File completion")?;
    if hex.len() != 512
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("File completion must be exactly256 lowercase hexadecimal bytes".into());
    }
    let mut bytes = [0; 256];
    for (out, pair) in bytes.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        *out = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Completion::decode(&bytes).map_err(|e| format!("invalid File completion: {e:?}"))
}

pub(crate) fn line(line: &str) -> Result<Record> {
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 2048
        || f.len() != 26
        || f[0] != "EVROSION_M3_FILE"
        || f[1] != "status=PASS"
        || f[2] != "scope=object"
        || f[14] != "max_pending=2"
        || f[17] != "authority_denied=1"
        || f[18] != "block_denied=1"
        || f[19] != "unbound_denied=1"
        || f[20] != "bindings=2"
        || f[21] != "mapped=4"
        || f[22] != "frames=true"
        || f[23] != "metadata=true"
        || f[24] != "guards=true"
    {
        return Err("malformed File/Object proof record".into());
    }
    let report = completion(f[25])?;
    let phase = if report.mode == Mode::Write {
        "phase=write"
    } else {
        "phase=verify"
    };
    let calls = number(f[4], "calls")?;
    let outer = number(f[8], "outer")?;
    let record = Record {
        report,
        calls,
        backend: number(f[9], "backend")?,
        nested: number(f[10], "nested")?,
        startup: number(f[11], "startup")?,
        pre_delivery: number(f[12], "pre_delivery")?,
        delivered_nested: number(f[13], "delivered_nested")?,
        mutations: number(f[15], "mutations")?,
    };
    if f[3] != phase
        || calls == 0
        || calls > 100_000
        || outer != report.requests
        || number(f[5], "blocks")? != calls
        || number(f[6], "wakes")? != calls
        || number(f[7], "replies")? != calls
        || outer.checked_add(record.backend) != Some(calls)
        || record.startup.checked_add(record.nested) != Some(record.backend)
        || record.pre_delivery.checked_add(record.delivered_nested) != Some(record.nested)
        || record.pre_delivery != 0
        || record.delivered_nested == 0
        || record.startup == 0
        || number(f[16], "snapshots")? != report.private_snapshot
        || record.mutations != if report.mode == Mode::Write { 11 } else { 0 }
        || report.payload != <[u8; 32]>::from(Sha256::digest(DATA_B))
    {
        return Err("File/Object metrics disagree with actual request, nesting, ownership or payload diagnostics".into());
    }
    Ok(record)
}

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Budget {
    pub(crate) elapsed_ticks: u64,
    pub(crate) cpu_driver: u64,
    pub(crate) cpu_server: u64,
    pub(crate) cpu_app: u64,
    pub(crate) cpu_parent: u64,
    pub(crate) transitions: u64,
    pub(crate) max_pending: u64,
}
pub(crate) fn budget_line(line: &str) -> Result<Budget> {
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 512
        || f.len() != 12
        || f[0] != "EVROSION_M3_FILE_BUDGET"
        || f[1] != "status=PASS"
        || f[3] != "limit_ticks=2048"
        || f[10] != "accounted=true"
        || f[11] != "bounded=true"
    {
        return Err("malformed File budget record".into());
    }
    let b = Budget {
        elapsed_ticks: number(f[2], "elapsed_ticks")?,
        cpu_driver: number(f[4], "driver_cpu")?,
        cpu_server: number(f[5], "server_cpu")?,
        cpu_app: number(f[6], "app_cpu")?,
        cpu_parent: number(f[7], "parent_cpu")?,
        transitions: number(f[8], "transitions")?,
        max_pending: number(f[9], "max_pending")?,
    };
    if b.elapsed_ticks == 0
        || b.elapsed_ticks >= 2048
        || b.cpu_parent != b.elapsed_ticks
        || b.cpu_driver
            .checked_add(b.cpu_server)
            .and_then(|n| n.checked_add(b.cpu_app))
            != Some(b.cpu_parent)
        || !(1..=100_000).contains(&b.transitions)
        || b.max_pending != 2
    {
        return Err("File budget is exhausted or actual CPU accounting is unbalanced".into());
    }
    Ok(b)
}
fn unique(serial: &[u8], tag: &str) -> Result<String> {
    if serial.len() > 1024 * 1024 {
        return Err("File serial exceeds1MiB".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "File serial is not UTF-8")?;
    let mut found = text
        .split_inclusive('\n')
        .filter(|line| line.starts_with(tag));
    let line = found.next().ok_or("required File record is missing")?;
    if found.next().is_some() || !line.ends_with('\n') {
        return Err("duplicate or truncated File record".into());
    }
    Ok(line
        .strip_suffix('\n')
        .unwrap()
        .strip_suffix('\r')
        .unwrap_or(line.strip_suffix('\n').unwrap())
        .to_owned())
}
pub(crate) fn record(serial: &[u8]) -> Result<Record> {
    line(&unique(serial, "EVROSION_M3_FILE ")?)
}
pub(crate) fn budget(serial: &[u8]) -> Result<Budget> {
    budget_line(&unique(serial, "EVROSION_M3_FILE_BUDGET ")?)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn completion(mode: Mode) -> Completion {
        let write = u64::from(mode == Mode::Write);
        Completion {
            mode,
            object: 1,
            counter: 1,
            requests: if write == 1 { 11 } else { 7 },
            ro_denied: 1,
            malformed: 2,
            invalid_counter: 2,
            skipped: write,
            conflicting: write,
            duplicates: write,
            port_denied: 1,
            block_denied: 1,
            private_snapshot: write,
            payload: Sha256::digest(DATA_B).into(),
        }
    }
    fn sample(mode: Mode) -> String {
        let c = completion(mode);
        let hex = c
            .encode()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        format!(
            "EVROSION_M3_FILE status=PASS scope=object phase={} calls={} blocks={} wakes={} replies={} outer={} backend=39 nested=20 startup=19 pre_delivery=0 delivered_nested=20 max_pending=2 mutations={} snapshots={} authority_denied=1 block_denied=1 unbound_denied=1 bindings=2 mapped=4 frames=true metadata=true guards=true report={hex}",
            if mode == Mode::Write {
                "write"
            } else {
                "verify"
            },
            c.requests + 39,
            c.requests + 39,
            c.requests + 39,
            c.requests + 39,
            c.requests,
            if mode == Mode::Write { 11 } else { 0 },
            c.private_snapshot
        )
    }
    #[test]
    fn exact_phase_completion_matches_real_nesting_and_request_counts() {
        for mode in [Mode::Write, Mode::Verify] {
            let text = sample(mode);
            assert_eq!(line(&text).unwrap().report, completion(mode));
            for (old, new) in [
                ("blocks=50", "blocks=49"),
                ("outer=11", "outer=12"),
                ("backend=39", "backend=40"),
                ("nested=20", "nested=21"),
                ("startup=19", "startup=18"),
                (
                    "pre_delivery=0 delivered_nested=20",
                    "pre_delivery=1 delivered_nested=19",
                ),
                ("unbound_denied=1", "unbound_denied=0"),
                ("bindings=2", "bindings=0"),
                ("mutations=11", "mutations=10"),
                ("phase=write", "phase=verify"),
                ("mapped=4", "mapped=3"),
                ("guards=true", "guards=false"),
                ("calls=50", "calls=050"),
            ] {
                if text.contains(old) {
                    assert!(line(&text.replacen(old, new, 1)).is_err(), "{old}");
                }
            }
        }
        let text = sample(Mode::Write);
        for byte in 0..256 {
            let mut c = completion(Mode::Write).encode();
            c[byte] ^= 0x80;
            let altered = c.iter().map(|b| format!("{b:02x}")).collect::<String>();
            let prefix = text.rsplit_once("report=").unwrap().0;
            assert!(
                line(&format!("{prefix}report={altered}")).is_err(),
                "byte{byte}"
            );
        }
    }
    #[test]
    fn canonical_wire_and_serial_cannot_hide_duplicates_truncation_or_overflow() {
        let text = sample(Mode::Write);
        assert!(record(format!("{text}\r\n").as_bytes()).is_ok());
        assert!(record(text.as_bytes()).is_err());
        assert!(record(format!("{text}\n{text}\n").as_bytes()).is_err());
        assert!(record(b"\xff\n").is_err());
        assert!(record(&vec![b'x'; 1024 * 1024 + 1]).is_err());
        assert!(line(&format!("{text} trailing=true")).is_err());
        assert!(line(&text.replace("report=4556", "report=455A")).is_err());
        assert!(line(&text.replace("backend=39", "backend=18446744073709551615")).is_err());
        assert!(
            line(&text.replace(
                "delivered_nested=20",
                "delivered_nested=18446744073709551615"
            ))
            .is_err()
        );
    }
    const BUDGET: &str = "EVROSION_M3_FILE_BUDGET status=PASS elapsed_ticks=1000 limit_ticks=2048 driver_cpu=400 server_cpu=500 app_cpu=100 parent_cpu=1000 transitions=12345 max_pending=2 accounted=true bounded=true";
    #[test]
    fn actual_cpu_budget_requires_checked_full_accounting_and_finite_limits() {
        assert_eq!(budget_line(BUDGET).unwrap().cpu_server, 500);
        assert!(budget(format!("{BUDGET}\n").as_bytes()).is_ok());
        assert!(budget(format!("{BUDGET}\n{BUDGET}\n").as_bytes()).is_err());
        for (old, new) in [
            ("elapsed_ticks=1000", "elapsed_ticks=2048"),
            ("parent_cpu=1000", "parent_cpu=999"),
            ("app_cpu=100", "app_cpu=101"),
            ("driver_cpu=400", "driver_cpu=18446744073709551615"),
            ("transitions=12345", "transitions=0"),
            ("transitions=12345", "transitions=100001"),
            ("max_pending=2", "max_pending=1"),
            ("accounted=true", "accounted=false"),
            ("server_cpu=500", "server_cpu=0500"),
        ] {
            assert!(budget_line(&BUDGET.replace(old, new)).is_err(), "{old}");
        }
    }
}
