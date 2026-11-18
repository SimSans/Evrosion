//! Existing transport state captured on failure, never a verified time result.
use crate::{boot_protocol::canonical_number, build::Result};
pub(crate) fn line(row: &str, build: &str) -> Result<Vec<u64>> {
    let f: Vec<_> = row.split(' ').collect();
    if row.len() > 512
        || f.len() != 13
        || f[0] != "EVROSION_M6_TIME_EXCHANGE"
        || f[1] != "protocol=1"
        || f[2] != format!("build={build}")
    {
        return Err("time exchange diagnostic shape/build".into());
    }
    let n = f[3..]
        .iter()
        .zip([
            "root_process",
            "root_thread",
            "endpoint",
            "ticket",
            "tick",
            "phase",
            "tcp",
            "calls",
            "error",
            "detail",
        ])
        .map(|(v, k)| canonical_number(v, k))
        .collect::<Result<Vec<_>>>()?;
    if n[..4].iter().any(|v| matches!(*v, 0 | u64::MAX))
        || n[4] == u64::MAX
        || !(1..=10).contains(&n[5])
        || !(n[6] <= 10 || n[6] == 255)
        || n[7] > 128
        || !(1..=6).contains(&n[8])
        || if n[8] == 6 {
            !(1..=8).contains(&n[9])
        } else {
            n[9] != 0
        }
    {
        return Err("time exchange diagnostic state/error range".into());
    }
    Ok(n)
}
pub(crate) fn records(serial: &[u8], build: &str) -> Result<Vec<Vec<u64>>> {
    if serial.len() > 1024 * 1024 {
        return Err("time exchange capture bound".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "time exchange UTF8")?;
    let mut root = None;
    let mut closed = false;
    let mut out = Vec::new();
    for raw in text.split_inclusive('\n') {
        let row = raw.trim_end_matches(['\r', '\n']);
        if row.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX ") {
            if root.is_some() {
                return Err("time exchange duplicate Root".into());
            }
            let crate::native3_protocol::Event::Common(c) =
                crate::native3_protocol::event_network(row, build)?
            else {
                unreachable!()
            };
            root = Some((c.root_process, c.root_thread));
        } else if row.starts_with("EVROSION_M6_LOG_BOUND ") || row.starts_with("EVROSION_M6_LOG ") {
            closed = true;
        } else if row.starts_with("EVROSION_M6_TIME_EXCHANGE") {
            let n = line(row, build)?;
            if closed || !raw.ends_with('\n') || !out.is_empty() || root != Some((n[0], n[1])) {
                return Err("time exchange Root/order/bound".into());
            }
            out.push(n);
        }
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_unknown_or_unjoined_state_never_becomes_a_time_success() {
        let b = "a".repeat(64);
        let r = format!(
            "EVROSION_M6_TIME_EXCHANGE protocol=1 build={b} root_process=1 root_thread=1 endpoint=7 ticket=150 tick=19000 phase=6 tcp=2 calls=120 error=6 detail=7"
        );
        line(&r, &b).unwrap();
        for bad in [
            r.replace("tcp=2", "tcp=11"),
            r.replace("calls=120", "calls=129"),
            r.replace("error=6", "error=5"),
            r.replace("detail=7", "detail=0"),
            r.replace("ticket=150", "ticket=0150"),
        ] {
            assert!(line(&bad, &b).is_err());
        }
        assert!(records(format!("{r}\n").as_bytes(), &b).is_err());
    }
}
