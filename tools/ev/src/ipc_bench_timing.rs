//! Host serial-availability bounds. These are not Source-client latency.
//! A newline absent from the preceding snapshot and present in this one became
//! observable between the preceding read start and the current read end. Using
//! this read's start as the lower endpoint would be unsound for buffered bytes.
use crate::{
    build::Result,
    perf_ledger::{self, Bracket, Ledger},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Instant;

pub(crate) const OUTPUT_LIMIT: u64 = 1024 * 1024;
const MAX_READS: u64 = 200_000;
const KIND: &str = "host-serial-batch-availability-bounds";
const SCOPE: &str = "host-observed complete Before-to-After serial availability; Root barriers, scheduling, 4,096 checked SDK RPCs, sample framing and serial delivery uncertainty; no QMP pauses; not exact client-only, raw trap or physical hardware latency";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Range {
    earliest_ns: u64,
    latest_ns: u64,
}
impl Range {
    fn bracket(self) -> Result<Bracket> {
        Bracket::new(self.earliest_ns, self.latest_ns)
            .map_err(|e| format!("IPC host bracket: {e:?}"))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Read {
    ordinal: u64,
    start_ns: u64,
    end_ns: u64,
    bytes: usize,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Boundary {
    phase: String,
    line_start: usize,
    line_end: usize, // Exclusive, including the actual complete newline.
    line: String,
    availability: Range,
    previous_read: Option<Read>,
    current_read: Read,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bounds {
    lower_ns: u64,
    upper_ns: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    schema: u8,
    kind: String,
    scope: String,
    spawn: Option<Range>,
    read_count: u64,
    final_read: Option<Read>,
    serial_bytes: usize,
    scanned_bytes: usize,
    before: Option<Boundary>,
    after: Option<Boundary>,
    qemu_exit_status: Option<i32>,
    execution_error: Option<String>,
    bounds: Option<Bounds>,
    quantitative_accepted: bool,
    timing_error: Option<String>,
}
// Match str::lines() for the actual LF/CRLF serial transport. Retain the
// original CR in Boundary.line; only the protocol view removes one terminal CR.
// Repeated or interior CR bytes still reach the closed protocol and fail.
fn protocol_view(raw: &str) -> &str {
    raw.strip_suffix('\r').unwrap_or(raw)
}
fn measure(before: &Boundary, after: &Boundary) -> Result<Bounds> {
    let timing = Ledger::new()
        .measure(
            before.availability.bracket()?,
            after.availability.bracket()?,
        )
        .map_err(|e| format!("IPC host interval: {e:?}"))?;
    Ok(Bounds {
        lower_ns: timing.wall_min_ns,
        upper_ns: timing.wall_max_ns,
    })
}
pub(crate) struct Observer {
    origin: Instant,
    spawn: Option<Range>,
    previous: Vec<u8>,
    scanned: usize,
    last_read: Option<Read>,
    reads: u64,
    before: Option<Boundary>,
    after: Option<Boundary>,
}
impl Observer {
    pub(crate) fn new(origin: Instant) -> Self {
        Self {
            origin,
            spawn: None,
            previous: Vec::new(),
            scanned: 0,
            last_read: None,
            reads: 0,
            before: None,
            after: None,
        }
    }
    pub(crate) fn elapsed(&self, at: Instant) -> Result<u64> {
        perf_ledger::elapsed_ns(self.origin, at).map_err(|e| format!("IPC host clock: {e:?}"))
    }
    pub(crate) fn spawned(&mut self, before: Instant, after: Instant) -> Result<()> {
        self.spawn_ns(self.elapsed(before)?, self.elapsed(after)?)
    }
    fn spawn_ns(&mut self, earliest_ns: u64, latest_ns: u64) -> Result<()> {
        let range = Range {
            earliest_ns,
            latest_ns,
        };
        range.bracket()?;
        if self.spawn.is_some() {
            return Err("IPC repeated spawn bracket".into());
        }
        self.spawn = Some(range);
        Ok(())
    }
    pub(crate) fn observe(
        &mut self,
        bytes: &[u8],
        build: &str,
        start: u64,
        end: u64,
    ) -> Result<()> {
        let spawn = self.spawn.ok_or("IPC read before actual owned spawn")?;
        if bytes.len() as u64 > OUTPUT_LIMIT
            || self.reads == MAX_READS
            || !bytes.starts_with(&self.previous)
            || start > end
            || start < spawn.latest_ns
            || self.last_read.is_some_and(|old| start < old.end_ns)
        {
            return Err("IPC host read limit/truncation/mutation/time order".into());
        }
        self.reads += 1;
        let read = Read {
            ordinal: self.reads,
            start_ns: start,
            end_ns: end,
            bytes: bytes.len(),
        };
        while let Some(relative) = bytes[self.scanned..].iter().position(|b| *b == b'\n') {
            let finish = self.scanned + relative + 1;
            let raw = &bytes[self.scanned..finish - 1];
            if raw.starts_with(b"EVROSION_M5_IPC_BATCH") {
                let line = std::str::from_utf8(raw).map_err(|_| "IPC batch serial not UTF8")?;
                let protocol = protocol_view(line);
                crate::ipc_bench_protocol::line(protocol, build)?;
                let phase = protocol.split(' ').nth(3).ok_or("IPC phase missing")?;
                let phase = phase.strip_prefix("phase=").ok_or("IPC phase missing")?;
                let boundary = Boundary {
                    phase: phase.into(),
                    line_start: self.scanned,
                    line_end: finish,
                    line: line.into(),
                    availability: Range {
                        earliest_ns: self.last_read.map_or(spawn.earliest_ns, |r| r.start_ns),
                        latest_ns: end,
                    },
                    previous_read: self.last_read,
                    current_read: read,
                };
                match phase {
                    "before" if self.before.is_none() && self.after.is_none() => {
                        self.before = Some(boundary)
                    }
                    "after" if self.before.is_some() && self.after.is_none() => {
                        self.after = Some(boundary)
                    }
                    _ => return Err("IPC host duplicate/reordered batch marker".into()),
                }
            }
            self.scanned = finish;
        }
        self.previous.clear();
        self.previous.extend_from_slice(bytes);
        self.last_read = Some(read);
        Ok(())
    }
    pub(crate) fn record(&self, status: Option<i32>, error: Option<String>) -> Value {
        let measured = self
            .before
            .as_ref()
            .zip(self.after.as_ref())
            .ok_or_else(|| "IPC host complete batch boundaries missing".to_owned())
            .and_then(|(before, after)| measure(before, after));
        let timing_error = match &measured {
            Ok(b) if b.lower_ns == 0 => Some("IPC host batch unresolved: overlapping/coalesced read brackets have zero guaranteed lower bound".into()),
            Ok(_) => None,
            Err(e) => Some(e.clone()),
        };
        json!(Evidence {
            schema: 1,
            kind: KIND.into(),
            scope: SCOPE.into(),
            spawn: self.spawn,
            read_count: self.reads,
            final_read: self.last_read,
            serial_bytes: self.previous.len(),
            scanned_bytes: self.scanned,
            before: self.before.clone(),
            after: self.after.clone(),
            qemu_exit_status: status,
            execution_error: error.clone(),
            bounds: measured.ok(),
            quantitative_accepted: timing_error.is_none()
                && error.is_none()
                && status == Some(ev_test_protocol::QEMU_PASS_STATUS),
            timing_error
        })
    }
}
fn validate_read(r: Read, spawn: Range, count: u64, size: usize) -> Result<()> {
    if r.ordinal == 0
        || r.ordinal > count
        || r.start_ns < spawn.latest_ns
        || r.start_ns > r.end_ns
        || r.bytes > size
    {
        return Err("IPC retained read bracket invalid".into());
    }
    Ok(())
}
fn validate_boundary(
    b: &Boundary,
    phase: &str,
    e: &Evidence,
    serial: &[u8],
    build: &str,
) -> Result<()> {
    let spawn = e.spawn.ok_or("IPC retained spawn missing")?;
    let final_read = e.final_read.ok_or("IPC retained final read missing")?;
    validate_read(b.current_read, spawn, e.read_count, serial.len())?;
    if b.phase != phase
        || b.line_start >= b.line_end
        || b.line_end > b.current_read.bytes
        || b.current_read.end_ns > final_read.end_ns
        || serial
            .get(b.line_start..b.line_end)
            .is_none_or(|s| s != format!("{}\n", b.line).as_bytes())
        || b.line_start > 0 && serial[b.line_start - 1] != b'\n'
    {
        return Err("IPC retained boundary is not exact complete raw serial line".into());
    }
    let protocol = protocol_view(&b.line);
    crate::ipc_bench_protocol::line(protocol, build)?;
    if protocol.split(' ').nth(3) != Some(&format!("phase={phase}")) {
        return Err("IPC retained boundary phase differs".into());
    }
    let lower = if let Some(prior) = b.previous_read {
        validate_read(prior, spawn, e.read_count, serial.len())?;
        if prior.ordinal.checked_add(1) != Some(b.current_read.ordinal)
            || prior.end_ns > b.current_read.start_ns
            || prior.bytes >= b.line_end
            || prior.bytes > b.current_read.bytes
        {
            return Err("IPC prior snapshot did not lack the complete boundary".into());
        }
        prior.start_ns
    } else {
        if b.current_read.ordinal != 1 {
            return Err("IPC missing prior read".into());
        }
        spawn.earliest_ns
    };
    if b.availability
        != (Range {
            earliest_ns: lower,
            latest_ns: b.current_read.end_ns,
        })
    {
        return Err("IPC retained availability endpoints were narrowed".into());
    }
    Ok(())
}
/// Called only after the independently retained Source/Kernel functional proof.
/// Recomputes every duration; a supplied passed flag cannot mint a measurement.
pub(crate) fn check(record: &Value, serial: &[u8], build: &str) -> Result<Value> {
    let e: Evidence = serde_json::from_value(record.clone()).map_err(|e| e.to_string())?;
    if e.schema != 1
        || e.kind != KIND
        || e.scope != SCOPE
        || e.execution_error.is_some()
        || e.qemu_exit_status != Some(ev_test_protocol::QEMU_PASS_STATUS)
        || e.read_count == 0
        || e.read_count > MAX_READS
        || e.serial_bytes != serial.len()
        || e.scanned_bytes != serial.len()
        || serial.len() as u64 > OUTPUT_LIMIT
        || !serial.ends_with(b"\n")
    {
        return Err("IPC host evidence incomplete/failed/invalid scope".into());
    }
    let spawn = e.spawn.ok_or("IPC actual spawn bracket missing")?;
    spawn.bracket()?;
    let last = e.final_read.ok_or("IPC final read missing")?;
    validate_read(last, spawn, e.read_count, serial.len())?;
    if last.ordinal != e.read_count || last.bytes != serial.len() {
        return Err("IPC final read does not cover raw serial".into());
    }
    let before = e
        .before
        .as_ref()
        .ok_or("IPC Before host observation missing")?;
    let after = e
        .after
        .as_ref()
        .ok_or("IPC After host observation missing")?;
    validate_boundary(before, "before", &e, serial, build)?;
    validate_boundary(after, "after", &e, serial, build)?;
    if before.line_end > after.line_start
        || before.current_read.ordinal > after.current_read.ordinal
        || before.current_read.end_ns > after.current_read.end_ns
    {
        return Err("IPC host batch boundaries reversed".into());
    }
    // References to one actual read must have identical endpoints and length.
    // Otherwise same-poll lines could be forged into separate reads.
    let mut reads = std::collections::BTreeMap::new();
    for read in [
        Some(last),
        Some(before.current_read),
        before.previous_read,
        Some(after.current_read),
        after.previous_read,
    ]
    .into_iter()
    .flatten()
    {
        if reads
            .insert(read.ordinal, read)
            .is_some_and(|old| old != read)
        {
            return Err("IPC contradictory references to one retained read".into());
        }
    }
    let mut prior: Option<Read> = None;
    for read in reads.values() {
        if prior.is_some_and(|p| p.end_ns > read.start_ns || p.bytes > read.bytes) {
            return Err("IPC retained reads are not append-only and time ordered".into());
        }
        prior = Some(*read);
    }
    let bounds = measure(before, after)?;
    if e.bounds != Some(bounds) {
        return Err("IPC host supplied interval differs from actual read brackets".into());
    }
    if bounds.lower_ns == 0 || !e.quantitative_accepted || e.timing_error.is_some() {
        return Err("IPC host batch unresolved: positive guaranteed lower bound required".into());
    }
    Ok(
        json!({"schema":1,"clock":"host std::time::Instant monotonic nanoseconds","scope":SCOPE,
        "batch_duration_lower_ns":bounds.lower_ns,"batch_duration_upper_ns":bounds.upper_ns,
        "amortized_batch_duration_ns_per_checked_rpc_bounds":{"lower_numerator":bounds.lower_ns,"upper_numerator":bounds.upper_ns,"denominator":4096},
        "positive_lower_bound":true,"read_brackets":record,"guest_irq_sample_separate":true}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn marker(phase: &str) -> String {
        let n = if phase == "before" { 64 } else { 4160 };
        format!(
            "EVROSION_M5_IPC_BATCH protocol=1 build={} phase={phase} tick=10 calls={n} replies={n} rejected=0 completed={n} first_nonce=1 last_nonce={n} endpoint=7 send_handle=513 root_process=11 root_thread=12 root_image_sha256={} client_process=13 client_thread=14 client_image_sha256={} server_process=15 server_thread=16 server_image_sha256={}\n",
            "d".repeat(64),
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64)
        )
    }
    fn observe(o: &mut Observer, s: &str, lo: u64, hi: u64) {
        o.observe(s.as_bytes(), &"d".repeat(64), lo, hi).unwrap();
    }
    fn observer() -> Observer {
        let mut o = Observer::new(Instant::now());
        o.spawn_ns(1, 2).unwrap();
        o
    }
    fn fixture() -> (Observer, String) {
        let mut o = observer();
        observe(&mut o, "", 3, 4);
        let before = marker("before");
        observe(&mut o, &before, 10, 12);
        observe(&mut o, &before, 90, 92);
        let full = format!("{before}{}", marker("after"));
        observe(&mut o, &full, 100, 105);
        (o, full)
    }
    #[test]
    fn delayed_buffered_bytes_use_prior_read_start_not_current_start() {
        let (o, s) = fixture();
        let r = o.record(Some(33), None);
        let checked = check(&r, s.as_bytes(), &"d".repeat(64)).unwrap();
        assert_eq!(r["before"]["availability"]["earliest_ns"], 3);
        assert_eq!(r["after"]["availability"]["earliest_ns"], 90);
        assert_eq!(checked["batch_duration_lower_ns"], 78);
        assert_eq!(checked["batch_duration_upper_ns"], 102);
    }
    #[test]
    fn same_read_is_unresolved_and_never_promoted_to_positive_latency() {
        let mut o = observer();
        let s = format!("{}{}", marker("before"), marker("after"));
        observe(&mut o, &s, 10, 12);
        let r = o.record(Some(33), None);
        assert_eq!(r["bounds"]["lower_ns"], 0);
        assert_eq!(r["quantitative_accepted"], false);
        assert!(check(&r, s.as_bytes(), &"d".repeat(64)).is_err());
    }
    #[test]
    fn partial_newline_and_empty_reads_keep_sound_lower_endpoint() {
        let mut o = observer();
        let before = marker("before");
        let partial = &before[..before.len() - 1];
        observe(&mut o, partial, 10, 11);
        assert!(o.before.is_none());
        observe(&mut o, partial, 20, 21);
        observe(&mut o, &before, 30, 31);
        assert_eq!(
            o.before.unwrap().availability,
            Range {
                earliest_ns: 20,
                latest_ns: 31
            }
        );
    }
    #[test]
    fn altered_raw_line_narrowed_bounds_and_forged_pass_fail() {
        let (o, s) = fixture();
        let r = o.record(Some(33), None);
        for (pointer, value) in [
            ("/before/availability/earliest_ns", json!(10)),
            ("/bounds/lower_ns", json!(88)),
            ("/after/previous_read/bytes", json!(s.len())),
            ("/final_read/ordinal", json!(1)),
            ("/serial_bytes", json!(1)),
        ] {
            let mut bad = r.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(check(&bad, s.as_bytes(), &"d".repeat(64)).is_err());
        }
        assert!(
            check(
                &r,
                s.replace("endpoint=7", "endpoint=8").as_bytes(),
                &"d".repeat(64)
            )
            .is_err()
        );
        assert!(
            check(
                &o.record(Some(33), Some("timeout".into())),
                s.as_bytes(),
                &"d".repeat(64)
            )
            .is_err()
        );
    }
    #[test]
    fn truncation_mutation_replay_reversal_and_read_budget_fail() {
        let (mut o, s) = fixture();
        assert!(o.observe(b"", &"d".repeat(64), 110, 111).is_err());
        assert!(o.observe(s.as_bytes(), &"d".repeat(64), 1, 2).is_err());
        let mut o = observer();
        assert!(
            o.observe(marker("after").as_bytes(), &"d".repeat(64), 3, 4)
                .is_err()
        );
        let mut o = observer();
        let b = marker("before");
        observe(&mut o, &b, 3, 4);
        assert!(
            o.observe(format!("{b}{b}").as_bytes(), &"d".repeat(64), 5, 6)
                .is_err()
        );
        let mut o = observer();
        o.reads = MAX_READS;
        assert!(o.observe(b"", &"d".repeat(64), 3, 4).is_err());
    }
    #[test]
    fn incomplete_and_foreign_build_records_never_accept() {
        let o = observer();
        assert!(check(&o.record(None, None), b"\n", &"d".repeat(64)).is_err());
        let mut o = observer();
        assert!(
            o.observe(marker("before").as_bytes(), &"e".repeat(64), 3, 4)
                .is_err()
        );
        assert!(o.spawn_ns(3, 4).is_err());
    }
    #[test]
    fn forged_zero_pass_and_failed_exit_cannot_mint_timing() {
        let mut o = observer();
        let s = format!("{}{}", marker("before"), marker("after"));
        observe(&mut o, &s, 10, 12);
        let mut r = o.record(Some(33), None);
        r["quantitative_accepted"] = json!(true);
        r["timing_error"] = Value::Null;
        assert!(check(&r, s.as_bytes(), &"d".repeat(64)).is_err());
        let (o, s) = fixture();
        assert!(check(&o.record(Some(0), None), s.as_bytes(), &"d".repeat(64)).is_err());
    }
    fn ending_fixture(before_crlf: bool, after_crlf: bool) -> (Observer, String) {
        let ending = |phase, crlf| {
            let line = marker(phase);
            if crlf {
                line.replace('\n', "\r\n")
            } else {
                line
            }
        };
        let mut o = observer();
        observe(&mut o, "", 3, 4);
        let before = ending("before", before_crlf);
        // Include a read ending between the CR and LF of a CRLF line.
        let incomplete = &before[..before.len() - 1];
        observe(&mut o, incomplete, 10, 11);
        assert!(o.before.is_none());
        observe(&mut o, &before, 20, 22);
        observe(&mut o, &before, 90, 92);
        let full = format!("{before}{}", ending("after", after_crlf));
        observe(&mut o, &full, 100, 105);
        (o, full)
    }
    #[test]
    fn complete_crlf_batch_preserves_raw_offsets_and_json_history() {
        let (o, s) = ending_fixture(true, true);
        let record = o.record(Some(33), None);
        let encoded = serde_json::to_vec(&record).unwrap();
        let decoded: Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, record);
        assert!(decoded["before"]["line"].as_str().unwrap().ends_with('\r'));
        assert!(decoded["after"]["line"].as_str().unwrap().ends_with('\r'));
        assert_eq!(decoded["before"]["line_end"], marker("before").len() + 1);
        assert_eq!(decoded["after"]["line_end"], s.len());
        assert!(check(&decoded, s.as_bytes(), &"d".repeat(64)).is_ok());
        assert!(
            check(
                &decoded,
                s.replace("\r\n", "\n").as_bytes(),
                &"d".repeat(64)
            )
            .is_err()
        );
        let mut normalized = decoded.clone();
        normalized["before"]["line"] =
            json!(protocol_view(decoded["before"]["line"].as_str().unwrap()));
        assert!(check(&normalized, s.as_bytes(), &"d".repeat(64)).is_err());
    }
    #[test]
    fn mixed_crlf_lf_batches_keep_each_raw_line_unchanged() {
        for (before_crlf, after_crlf) in [(true, false), (false, true)] {
            let (o, s) = ending_fixture(before_crlf, after_crlf);
            let record = o.record(Some(33), None);
            let decoded: Value =
                serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
            assert_eq!(
                decoded["before"]["line"].as_str().unwrap().ends_with('\r'),
                before_crlf
            );
            assert_eq!(
                decoded["after"]["line"].as_str().unwrap().ends_with('\r'),
                after_crlf
            );
            assert!(check(&decoded, s.as_bytes(), &"d".repeat(64)).is_ok());
        }
        let mut o = observer();
        let repeated = marker("before").replace('\n', "\r\r\n");
        assert!(
            o.observe(repeated.as_bytes(), &"d".repeat(64), 3, 4)
                .is_err()
        );
    }
}
