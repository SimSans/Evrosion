//! Core exclusion receipts. Physical STOP/scrub remains conditional on the
//! exact sealed trusted Root source and the complete final guest retirement.
use super::records::Row;
use crate::{boot_protocol::canonical_number, build::Result};
#[derive(Clone, Debug)]
pub(crate) struct Retirement {
    root: (u64, u64),
    operation: u64,
    driver: (u64, u64),
    service: (u64, u64),
    extra: u64,
    tick: u64,
    value: u64,
}
pub(crate) fn line(text: &str, build: &str) -> Result<Retirement> {
    let fields: Vec<_> = text.split(' ').collect();
    if text.len() > 768
        || fields.len() != 14
        || fields[..3]
            != [
                "EVROSION_M6_NETWORK_RETIREMENT",
                "protocol=1",
                &format!("build={build}"),
            ]
        || fields[13] != "physical_proof=trusted-root-source"
    {
        return Err("negative Core retirement shape/build/physical scope".into());
    }
    let keys = [
        "root_process",
        "root_thread",
        "operation",
        "driver_process",
        "driver_thread",
        "service_process",
        "service_thread",
        "extra",
        "tick",
        "value",
    ];
    let n: Vec<_> = fields[3..13]
        .iter()
        .zip(keys)
        .map(|(f, k)| canonical_number(f, k))
        .collect::<Result<_>>()?;
    if [n[0], n[1], n[3], n[4], n[5], n[6]]
        .into_iter()
        .any(|v| matches!(v, 0 | u64::MAX))
        || n[0] == n[3]
        || n[0] == n[5]
        || n[3] == n[5]
        || n[1] == n[4]
        || n[1] == n[6]
        || n[4] == n[6]
        || n[8] == u64::MAX
    {
        return Err("negative Core retirement actual pair".into());
    }
    if match n[2] {
        0 => n[9] != 1 || n[7] <= n[8] || n[7] == u64::MAX || n[7] - n[8] > 8192,
        1 => n[7] != 1 || n[9] != 0,
        _ => true,
    } {
        return Err("negative Core retirement operation/token/cut".into());
    }
    Ok(Retirement {
        root: (n[0], n[1]),
        operation: n[2],
        driver: (n[3], n[4]),
        service: (n[5], n[6]),
        extra: n[7],
        tick: n[8],
        value: n[9],
    })
}
pub(crate) fn complete(serial: &[u8], build: &str, observed: &[Row], expected: bool) -> Result<()> {
    let mut rows = Vec::new();
    let mut summary = None;
    let mut last_cancel = 0;
    for (position, text) in std::str::from_utf8(serial)
        .map_err(|_| "negative retirement UTF8")?
        .lines()
        .enumerate()
    {
        let text = text.trim_end_matches('\r');
        if text.starts_with("EVROSION_M6_NETWORK_RETIREMENT") {
            rows.push((position, line(text, build)?));
            if rows.len() > 2 {
                return Err("negative Core retirement extra operation".into());
            }
        }
        if text.starts_with("EVROSION_M6_NEGATIVE ") {
            let row = super::records::line(text, build)?;
            if row.kind == 8 {
                summary = Some(position);
            }
            if row.kind == 7 {
                last_cancel = position;
            }
        }
    }
    if !expected {
        return if rows.is_empty() {
            Ok(())
        } else {
            Err("unexpected Core recovery in no-failure goal".into())
        };
    }
    if rows.len() != 2 {
        return Err("negative missing both actual Core retirement joins".into());
    }
    let (begin, end) = (&rows[0].1, &rows[1].1);
    let leaf = observed
        .iter()
        .find(|r| r.kind == 4)
        .ok_or("negative retirement lacks actual nested capture")?;
    let inner = leaf.call.ok_or("negative nested call absent")?;
    let root = observed
        .iter()
        .find(|r| r.kind == 0)
        .ok_or("negative Root scope absent")?;
    if begin.operation != 0
        || end.operation != 1
        || begin.root != (root.process, root.thread)
        || end.root != begin.root
        || begin.driver != inner.callee
        || begin.service != inner.caller
        || end.driver != begin.driver
        || end.service != begin.service
        || begin.value != 1
        || end.tick < begin.tick
        || end.tick >= begin.extra
        || rows[0].0 <= last_cancel
        || rows[1].0 <= rows[0].0
        || summary.is_none_or(|at| rows[1].0 >= at)
    {
        return Err(
            "negative Core recovery did not preserve actual Root/pair/token/original cut/order"
                .into(),
        );
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn core_scope_remains_closed_and_never_claims_hardware_direct_proof() {
        let build = "a".repeat(64);
        let row = format!(
            "EVROSION_M6_NETWORK_RETIREMENT protocol=1 build={build} root_process=20 root_thread=120 operation=0 driver_process=27 driver_thread=127 service_process=28 service_thread=128 extra=8000 tick=100 value=1 physical_proof=trusted-root-source"
        );
        assert!(line(&row, &build).is_ok());
        for bad in [
            row.replace("operation=0", "operation=2"),
            row.replace("extra=8000", "extra=9000"),
            row.replace("value=1", "value=0"),
            row.replace("driver_process=27", "driver_process=20"),
            row.replace("trusted-root-source", "kernel-pio-measured"),
            row.clone() + " extra=1",
        ] {
            assert!(line(&bad, &build).is_err());
        }
    }
}
