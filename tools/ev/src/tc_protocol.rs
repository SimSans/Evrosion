//! Bounded authenticated actual-Root checks of private unqualified time proofs.
use crate::{boot_protocol::canonical_number, build::Result, time_protocol::Progress};

pub(crate) fn line(line: &str, build: &str) -> Result<Progress> {
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 512
        || f.len() != 12
        || f[0] != "EVROSION_M6_TIME_CHECK"
        || f[1] != "protocol=1"
        || f[2] != format!("build={build}")
        || f[11] != "utc=unqualified"
    {
        return Err("retained time check shape/build/qualification".into());
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
    let n = f[3..11]
        .iter()
        .zip(keys)
        .map(|(v, k)| canonical_number(v, k))
        .collect::<Result<Vec<_>>>()?;
    if n[..4].iter().any(|v| matches!(*v, 0 | u64::MAX))
        || n[5] != 1
        || n[6] > 3
        || n[7] > u32::MAX as u64
        || n[6] == 1 && n[7] != 0
    {
        return Err("retained time check identity/range".into());
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
        return Err("retained time check capture bound".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "retained time check serial UTF8")?;
    let mut root = None;
    let mut closed = false;
    let mut out: Vec<Progress> = Vec::new();
    for raw in text.split_inclusive('\n') {
        let row = raw.strip_suffix('\n').unwrap_or(raw);
        let row = row.strip_suffix('\r').unwrap_or(row);
        if row.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX ") {
            if root.is_some() {
                return Err("duplicate retained time check Root prefix".into());
            }
            let crate::native3_protocol::Event::Common(c) =
                crate::native3_protocol::event_network(row, build)?
            else {
                unreachable!()
            };
            root = Some((c.root_process, c.root_thread));
        } else if row.starts_with("EVROSION_M6_LOG_BOUND ") || row.starts_with("EVROSION_M6_LOG ") {
            closed = true;
        } else if row.starts_with("EVROSION_M6_TIME_CHECK") {
            if !raw.ends_with('\n') || closed || out.len() >= 4 {
                return Err("retained time check incomplete/closed/replayed".into());
            }
            let p = line(row, build)?;
            if root != Some((p.root_process, p.root_thread))
                || out.last().is_some_and(|old| {
                    p.ticket <= old.ticket
                        || p.tick < old.tick
                        || p.endpoint != old.endpoint
                        || p.result != 1 && p.elapsed_seconds < old.elapsed_seconds
                })
            {
                return Err("retained time check actual Root differs".into());
            }
            out.push(p);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(result: u64) -> String {
        format!(
            "EVROSION_M6_TIME_CHECK protocol=1 build={} root_process=1 root_thread=11 endpoint=7 ticket=400 tick=5000 stage=1 result={result} elapsed_seconds=38 utc=unqualified\r\n",
            "a".repeat(64)
        )
    }
    fn prefix() -> String {
        format!(
            "EVROSION_M5_NATIVE_COMMON_PREFIX protocol=1 build={} mode=0 root_process=1 root_thread=11 root_image_sha256={} root_epoch=501 root_incarnation=1 root_manifest_sha256={} block_process=2 block_thread=12 block_image_sha256={} system_endpoint=31 root_frames=40 block_frames=20\n",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64)
        )
    }
    #[test]
    fn checks_are_complete_actual_root_observations_and_never_qualified() {
        let build = "a".repeat(64);
        for result in 0..=3 {
            let text = prefix()
                + &if result == 1 {
                    row(result).replace("elapsed_seconds=38", "elapsed_seconds=0")
                } else {
                    row(result)
                };
            let p = records(text.as_bytes(), &build).unwrap();
            assert_eq!(p.len(), 1);
            assert_eq!(p[0].result, result);
        }
        let good = prefix() + &row(2);
        for bad in [
            row(2),
            good.trim_end().into(),
            good.clone() + &row(2),
            prefix() + "EVROSION_M6_LOG_BOUND x\n" + &row(2),
            prefix() + "EVROSION_M6_LOG x\n" + &row(2),
            good.replace("root_thread=11 endpoint", "root_thread=12 endpoint"),
            good.replace("utc=unqualified", "utc=qualified"),
            good.replace("stage=1", "stage=2"),
            good.replace("result=2", "result=4"),
            good.replace("ticket=400", "ticket=0400"),
            good.replace("endpoint=7", "endpoint=0"),
            good.replace("elapsed_seconds=38", "elapsed_seconds=4294967296"),
            good.replace("EVROSION_M6_TIME_CHECK ", "EVROSION_M6_TIME_CHECK_EXTRA "),
            good.replace("\r\n", "\r\r\n"),
        ] {
            assert!(records(bad.as_bytes(), &build).is_err(), "{bad}");
        }
        assert!(records(good.as_bytes(), &"f".repeat(64)).is_err());
    }
    #[test]
    fn four_ordered_checks_do_not_reopen_an_old_check_or_prove_refresh() {
        let build = "a".repeat(64);
        let mut text = prefix();
        for n in 0..4 {
            text.push_str(
                &row(2)
                    .replace("ticket=400", &format!("ticket={}", 400 + n))
                    .replace("tick=5000", &format!("tick={}", 5000 + n))
                    .replace("elapsed_seconds=38", &format!("elapsed_seconds={}", 38 + n)),
            );
        }
        assert_eq!(records(text.as_bytes(), &build).unwrap().len(), 4);
        let fifth = row(0)
            .replace("ticket=400", "ticket=404")
            .replace("tick=5000", "tick=5004")
            .replace("elapsed_seconds=38", "elapsed_seconds=42");
        assert!(records((text + &fifth).as_bytes(), &build).is_err());
        let pair = prefix()
            + &row(2)
            + &row(0)
                .replace("ticket=400", "ticket=401")
                .replace("tick=5000", "tick=5001")
                .replace("elapsed_seconds=38", "elapsed_seconds=39");
        assert_eq!(records(pair.as_bytes(), &build).unwrap().len(), 2);
        assert!(records(pair.replace("ticket=401", "ticket=400").as_bytes(), &build).is_err());
        assert!(
            records(
                pair.replace("elapsed_seconds=39", "elapsed_seconds=37")
                    .as_bytes(),
                &build
            )
            .is_err()
        );
    }
}
