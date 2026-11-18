//! Accepted Root policy diagnostics; no device/health authority is inferred.
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
    pub argument: u64,
}
pub(crate) fn line(line: &str, build: &str) -> Result<Progress> {
    const KEYS: [&str; 8] = [
        "root_process",
        "root_thread",
        "endpoint",
        "ticket",
        "tick",
        "stage",
        "result",
        "argument",
    ];
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 512
        || f.len() != 11
        || f[0] != "EVROSION_M6_NETWORK_PROGRESS"
        || f[1] != "protocol=1"
        || f[2] != format!("build={build}")
    {
        return Err("network diagnostic shape/build".into());
    }
    let n = f[3..]
        .iter()
        .zip(KEYS)
        .map(|(v, k)| canonical_number(v, k))
        .collect::<Result<Vec<_>>>()?;
    if n[..4].iter().any(|v| matches!(*v, 0 | u64::MAX))
        || !(1..=8).contains(&n[5])
        || n[6] > 4
        || n[7] > u32::MAX as u64
    {
        return Err("network diagnostic identity/range".into());
    }
    if n[6] == 0
        && match n[5] {
            1 => n[7] != 1,
            2 | 3 => n[7] == 0,
            4 => n[7] != 8080,
            5 => !(1..=1024).contains(&n[7]),
            6 => n[7] != crate::network_fixture::HELLO.len() as u64,
            7 => n[7] != 2,
            _ => true,
        }
    {
        return Err("network positive argument".into());
    }
    if n[5] == 8 && !(1..=7).contains(&n[7]) {
        return Err("network failed stage".into());
    }
    Ok(Progress {
        root_process: n[0],
        root_thread: n[1],
        endpoint: n[2],
        ticket: n[3],
        tick: n[4],
        stage: n[5],
        result: n[6],
        argument: n[7],
    })
}
/// Validate the retained prefix's source and ordering. Missing later records
/// are not reconstructed as successful operations after retention closes.
pub(crate) fn records(serial: &[u8], build: &str) -> Result<Vec<Progress>> {
    if serial.len() > 1024 * 1024 {
        return Err("network capture bound".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "network serial UTF8")?;
    let mut root = None;
    let mut out: Vec<Progress> = Vec::new();
    let mut closed = false;
    for row in text.split_inclusive('\n') {
        let complete = row.ends_with('\n');
        let row = row.trim_end_matches(['\r', '\n']);
        if row.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX ") {
            if root.is_some() {
                return Err("duplicate network Root prefix".into());
            }
            let crate::native3_protocol::Event::Common(c) =
                crate::native3_protocol::event_network(row, build)?
            else {
                unreachable!()
            };
            root = Some((c.root_process, c.root_thread));
        } else if row.starts_with("EVROSION_M6_LOG_BOUND ") || row.starts_with("EVROSION_M6_LOG ") {
            closed = true;
        } else if row.starts_with("EVROSION_M6_NETWORK_PROGRESS") {
            if !complete || closed || out.len() >= 16 {
                return Err("network capture incomplete/closed/bounded".into());
            }
            let p = line(row, build)?;
            if root != Some((p.root_process, p.root_thread))
                || out.last().is_some_and(|old| {
                    p.ticket <= old.ticket
                        || p.tick < old.tick
                        || p.endpoint != old.endpoint
                        || old.stage == 7
                        || (p.stage != 7 && p.stage != 8 && p.stage <= old.stage)
                })
            {
                return Err("network source/replay/order".into());
            }
            out.push(p);
        }
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn progress_refuses_wrong_build_ranges_or_false_body_and_requires_root_origin() {
        let good = format!(
            "EVROSION_M6_NETWORK_PROGRESS protocol=1 build={} root_process=1 root_thread=1 endpoint=33 ticket=4 tick=10 stage=6 result=0 argument=28",
            "a".repeat(64)
        );
        line(&good, &"a".repeat(64)).unwrap();
        for bad in [
            good.replace("argument=28", "argument=27"),
            good.replace("ticket=4", "ticket=0"),
            good.replace("result=0", "result=5"),
            good.replace("stage=6", "stage=9"),
            good.replace("tick=10", "tick=010"),
        ] {
            assert!(line(&bad, &"a".repeat(64)).is_err());
        }
        assert!(line(&good, &"b".repeat(64)).is_err());
        assert!(records(format!("{good}\n").as_bytes(), &"a".repeat(64)).is_err());
    }
}
