//! Authenticated Root local-namespace progress, never release/UTC/Known Good.
use crate::{boot_protocol::canonical_number, build::Result};
#[derive(Debug, serde::Serialize)]
pub(crate) struct Progress {
    root: (u64, u64),
    endpoint: u64,
    ticket: u64,
    tick: u64,
    pub(crate) stage: u64,
    pub(crate) result: u64,
    pub(crate) progress: u64,
}
pub(crate) fn line(row: &str, build: &str) -> Result<Progress> {
    let f: Vec<_> = row.split(' ').collect();
    if row.len() > 512
        || f.len() != 11
        || f[0] != "EVROSION_M6_UPDATE_PROGRESS"
        || f[1] != "protocol=1"
        || f[2] != format!("build={build}")
    {
        return Err("update progress shape/build".into());
    }
    let n = f[3..]
        .iter()
        .zip([
            "root_process",
            "root_thread",
            "endpoint",
            "ticket",
            "tick",
            "stage",
            "result",
            "progress",
        ])
        .map(|(v, k)| canonical_number(v, k))
        .collect::<Result<Vec<_>>>()?;
    if n[..4].iter().any(|v| matches!(*v, 0 | u64::MAX))
        || n[4] == u64::MAX
        || n[7] > u32::MAX as u64
        || match n[5] {
            1 => n[6] != 0 || n[7] != 0,
            2 => n[6] != 0 || n[7] == 0 || n[7] > 7950 || !n[7].is_multiple_of(512),
            3 => n[6] != 0 || n[7] != 7950,
            4 => n[6] != 0 || n[7] == 0,
            5 => !(1..=6).contains(&n[6]) || n[7] > 7950,
            _ => true,
        }
    {
        return Err("update progress stage/result/counter".into());
    }
    Ok(Progress {
        root: (n[0], n[1]),
        endpoint: n[2],
        ticket: n[3],
        tick: n[4],
        stage: n[5],
        result: n[6],
        progress: n[7],
    })
}
pub(crate) fn records(serial: &[u8], build: &str) -> Result<Vec<Progress>> {
    if serial.len() > 1024 * 1024 {
        return Err("update progress capture bound".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "update progress UTF8")?;
    let mut root = None;
    let mut closed = false;
    let mut out: Vec<Progress> = Vec::new();
    for raw in text.split_inclusive('\n') {
        let row = raw.trim_end_matches(['\r', '\n']);
        if row.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX ") {
            if root.is_some() {
                return Err("update progress duplicate Root".into());
            }
            let crate::native3_protocol::Event::Common(c) =
                crate::native3_protocol::event_network(row, build)?
            else {
                unreachable!()
            };
            root = Some((c.root_process, c.root_thread));
        } else if row.starts_with("EVROSION_M6_LOG_BOUND ") || row.starts_with("EVROSION_M6_LOG ") {
            closed = true;
        } else if row.starts_with("EVROSION_M6_UPDATE_PROGRESS") {
            let p = line(row, build)?;
            if closed
                || !raw.ends_with('\n')
                || out.len() >= 20
                || root != Some(p.root)
                || out.last().is_some_and(|old| {
                    p.endpoint != old.endpoint
                        || p.ticket <= old.ticket
                        || p.tick < old.tick
                        || (p.stage == 2
                            && matches!(old.stage, 1 | 2)
                            && p.progress <= old.progress)
                })
            {
                return Err("update progress Root/order/bound".into());
            }
            out.push(p);
        }
    }
    // Diagnostic drops cannot reconstruct a complete operation. A successful
    // command still needs its actual Store/checkpoint/whole-disk evidence.
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_schema_rejects_false_progress_and_never_supplies_trust_authority() {
        let build = "a".repeat(64);
        let row = format!(
            "EVROSION_M6_UPDATE_PROGRESS protocol=1 build={build} root_process=20 root_thread=120 endpoint=7 ticket=9 tick=10 stage=2 result=0 progress=512"
        );
        line(&row, &build).unwrap();
        for bad in [
            row.replace("progress=512", "progress=511"),
            row.replace("progress=512", "progress=8192"),
            row.replace("result=0", "result=1"),
            row.replace("stage=2", "stage=3"),
            row.replace("ticket=9", "ticket=09"),
        ] {
            assert!(line(&bad, &build).is_err());
        }
        assert!(records(format!("{row}\n").as_bytes(), &build).is_err());
        let prefix = format!(
            "EVROSION_M5_NATIVE_COMMON_PREFIX protocol=1 build={build} mode=0 root_process=20 root_thread=120 root_image_sha256={} root_epoch=501 root_incarnation=1 root_manifest_sha256={} block_process=24 block_thread=124 block_image_sha256={} system_endpoint=12 root_frames=122 block_frames=20\n",
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64)
        );
        assert_eq!(
            records(format!("{prefix}{row}\n").as_bytes(), &build)
                .unwrap()
                .len(),
            1
        );
        for bad in [
            format!("{prefix}{row}"),
            format!("{prefix}{row}\n{row}\n"),
            format!("{prefix}EVROSION_M6_LOG_BOUND closed\n{row}\n"),
        ] {
            assert!(records(bad.as_bytes(), &build).is_err());
        }
    }
}
