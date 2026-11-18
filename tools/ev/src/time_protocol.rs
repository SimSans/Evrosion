//! Authenticated-origin elapsed-source diagnostics, never UTC qualification.
use crate::{boot_protocol::canonical_number, build::Result};
#[derive(Debug, serde::Serialize)]
pub(crate) struct Progress {
    pub root_process: u64,
    pub root_thread: u64,
    pub endpoint: u64,
    pub ticket: u64,
    pub tick: u64,
    pub stage: u64,
    pub result: u64,
    pub elapsed_seconds: u64,
}
pub(crate) fn line(line: &str, build: &str) -> Result<Progress> {
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 512
        || f.len() != 11
        || f[0] != "EVROSION_M6_TIME_PROGRESS"
        || f[1] != "protocol=1"
        || f[2] != format!("build={build}")
    {
        return Err("elapsed diagnostic shape/build".into());
    }
    let keys = [
        "root_process",
        "root_thread",
        "endpoint",
        "ticket",
        "tick",
        "stage",
        "result",
        "elapsed_seconds",
    ];
    let n = f[3..]
        .iter()
        .zip(keys)
        .map(|(v, k)| canonical_number(v, k))
        .collect::<Result<Vec<_>>>()?;
    if n[..4].iter().any(|v| matches!(*v, 0 | u64::MAX))
        || !(1..=3).contains(&n[5])
        || n[6] > 3
        || n[7] > u32::MAX as u64
        || (n[5] == 3) != (n[6] != 0)
        || n[5] == 1 && n[7] != 0
    {
        return Err("elapsed diagnostic identity/range/meaning".into());
    }
    Ok(Progress {
        root_process: n[0],
        root_thread: n[1],
        endpoint: n[2],
        ticket: n[3],
        tick: n[4],
        stage: n[5],
        result: n[6],
        elapsed_seconds: n[7],
    })
}
pub(crate) fn records(serial: &[u8], build: &str) -> Result<Vec<Progress>> {
    if serial.len() > 1024 * 1024 {
        return Err("elapsed capture bound".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "elapsed serial UTF8")?;
    let mut root = None;
    let mut closed = false;
    let mut out: Vec<Progress> = Vec::new();
    for raw in text.split_inclusive('\n') {
        let row = raw.trim_end_matches(['\r', '\n']);
        if row.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX ") {
            if root.is_some() {
                return Err("duplicate elapsed Root prefix".into());
            }
            let crate::native3_protocol::Event::Common(c) =
                crate::native3_protocol::event_network(row, build)?
            else {
                unreachable!()
            };
            root = Some((c.root_process, c.root_thread));
        } else if row.starts_with("EVROSION_M6_LOG_BOUND ") || row.starts_with("EVROSION_M6_LOG ") {
            closed = true;
        } else if row.starts_with("EVROSION_M6_TIME_PROGRESS") {
            if !raw.ends_with('\n') || closed || out.len() >= 16 {
                return Err("elapsed capture incomplete/closed/bounded".into());
            }
            let p = line(row, build)?;
            if root != Some((p.root_process, p.root_thread))
                || out.last().map_or(!matches!(p.stage, 1 | 3), |old| {
                    old.stage == 3
                        || p.stage == 1
                        || p.ticket <= old.ticket
                        || p.tick < old.tick
                        || p.endpoint != old.endpoint
                        || p.stage != 3 && p.elapsed_seconds < old.elapsed_seconds
                })
            {
                return Err("elapsed source/replay/order".into());
            }
            out.push(p);
        }
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn row(ticket: u64, stage: u64, result: u64, elapsed: u64) -> String {
        format!(
            "EVROSION_M6_TIME_PROGRESS protocol=1 build={} root_process=20 root_thread=120 endpoint=33 ticket={ticket} tick={ticket} stage={stage} result={result} elapsed_seconds={elapsed}\n",
            "a".repeat(64)
        )
    }
    fn prefix() -> String {
        format!(
            "EVROSION_M5_NATIVE_COMMON_PREFIX protocol=1 build={} mode=0 root_process=20 root_thread=120 root_image_sha256={} root_epoch=501 root_incarnation=1 root_manifest_sha256={} block_process=24 block_thread=124 block_image_sha256={} system_endpoint=12 root_frames=111 block_frames=20\n",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64)
        )
    }
    #[test]
    fn relative_samples_require_actual_selected_root_and_order_not_utc() {
        let build = "a".repeat(64);
        let good = format!(
            "{}{}{}{}",
            prefix(),
            row(1, 1, 0, 0),
            row(2, 2, 0, 3),
            row(3, 3, 2, 2)
        );
        assert_eq!(records(good.as_bytes(), &build).unwrap().len(), 3);
        for bad in [
            row(1, 1, 0, 0),
            good.replace(
                "root_process=20 root_thread=120 endpoint",
                "root_process=21 root_thread=120 endpoint",
            ),
            good.replace("ticket=2", "ticket=1"),
            good.replace("stage=2 result=0", "stage=1 result=0"),
            format!("{good}{}", row(4, 2, 0, 4)),
            format!(
                "{}{}{}{}",
                prefix(),
                row(1, 1, 0, 0),
                row(2, 2, 0, 3),
                row(3, 2, 0, 2)
            ),
            format!("{}EVROSION_M6_LOG_BOUND x\n{}", prefix(), row(1, 1, 0, 0)),
        ] {
            assert!(records(bad.as_bytes(), &build).is_err(), "{bad}");
        }
        assert!(records(good.trim_end().as_bytes(), &build).is_err());
    }
    #[test]
    fn syntax_bounds_and_failure_meaning_are_closed() {
        let build = "a".repeat(64);
        let valid = row(1, 1, 0, 0);
        for bad in [
            valid.replace("elapsed_seconds=0", "elapsed_seconds=1"),
            valid.replace("result=0", "result=1"),
            valid.replace("ticket=1", "ticket=01"),
            valid.replace("stage=1", "stage=3"),
            valid.replace("endpoint=33", "endpoint=0"),
        ] {
            assert!(line(bad.trim_end(), &build).is_err());
        }
        let mut many = prefix() + &row(1, 1, 0, 0);
        for n in 2..=16 {
            many.push_str(&row(n, 2, 0, n));
        }
        assert_eq!(records(many.as_bytes(), &build).unwrap().len(), 16);
        many.push_str(&row(17, 2, 0, 17));
        assert!(records(many.as_bytes(), &build).is_err());
    }
}
