//! Canonical error classes from actual authenticated network actor senders.
//! These records establish neither device quiescence nor repair permission.
use crate::{boot_protocol::canonical_number, build::Result};
#[derive(Debug, serde::Serialize)]
pub(crate) struct Failure {
    pub actor: String,
    pub process: u64,
    pub thread: u64,
    pub endpoint: u64,
    pub ticket: u64,
    pub tick: u64,
    pub layer: u8,
    pub operation: u8,
    pub class: u8,
    pub detail: u8,
    pub subdetail: u8,
    pub progress: u8,
}
pub(crate) fn line(line: &str, build: &str) -> Result<Failure> {
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 512
        || f.len() != 15
        || f[0] != "EVROSION_M6_NETWORK_ERROR"
        || f[1] != "protocol=1"
        || f[2] != format!("build={build}")
    {
        return Err("network error diagnostic shape/build".into());
    }
    let actor = f[3]
        .strip_prefix("actor=")
        .ok_or("network error actor key")?;
    let layer = match actor {
        "root" => 3,
        "net_driver" => 1,
        "net_service" => 2,
        _ => return Err("network error actor".into()),
    };
    let keys = [
        "process",
        "thread",
        "endpoint",
        "ticket",
        "tick",
        "layer",
        "operation",
        "class",
        "detail",
        "subdetail",
        "progress",
    ];
    let n = f[4..]
        .iter()
        .zip(keys)
        .map(|(v, k)| canonical_number(v, k))
        .collect::<Result<Vec<_>>>()?;
    if n[..4].iter().any(|v| matches!(*v, 0 | u64::MAX))
        || n[5..].iter().any(|v| *v > 255)
        || n[5] != layer
    {
        return Err("network error actualidentity/layer/range".into());
    }
    let d = ev_net_driver::diagnostic::Diagnostic::checked(
        n[5] as u8,
        n[6] as u8,
        n[7] as u8,
        n[8] as u8,
        n[9] as u8,
        n[10] as u8,
    )
    .ok_or("network error undefinedclass/detail")?;
    Ok(Failure {
        actor: actor.into(),
        process: n[0],
        thread: n[1],
        endpoint: n[2],
        ticket: n[3],
        tick: n[4],
        layer: d.layer(),
        operation: d.operation(),
        class: d.class(),
        detail: d.detail(),
        subdetail: d.subdetail(),
        progress: d.progress(),
    })
}
pub(crate) fn records(serial: &[u8], build: &str) -> Result<Vec<Failure>> {
    if serial.len() > 1024 * 1024 {
        return Err("network error capture bound".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "network error serialUTF8")?;
    let mut root = None;
    let mut out: Vec<Failure> = Vec::new();
    let mut closed = false;
    for raw in text.split_inclusive('\n') {
        let row = raw.trim_end_matches(['\r', '\n']);
        if row.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX ") {
            if root.is_some() {
                return Err("duplicate network error Root prefix".into());
            }
            let crate::native3_protocol::Event::Common(c) =
                crate::native3_protocol::event_network(row, build)?
            else {
                unreachable!()
            };
            root = Some((c.root_process, c.root_thread));
        } else if row.starts_with("EVROSION_M6_LOG_BOUND ") || row.starts_with("EVROSION_M6_LOG ") {
            closed = true;
        } else if row.starts_with("EVROSION_M6_NETWORK_ERROR") {
            if closed || !raw.ends_with('\n') || out.len() >= 3 {
                return Err("network error incomplete/closed/bounded".into());
            }
            let p = line(row, build)?;
            let Some(actual_root) = root else {
                return Err("network error lacks Root origin".into());
            };
            if (p.actor == "root" && (p.process, p.thread) != actual_root)
                || (p.actor != "root" && (p.process == actual_root.0 || p.thread == actual_root.1))
                || out.iter().any(|old| {
                    old.actor == p.actor || old.process == p.process || old.thread == p.thread
                })
                || out.last().is_some_and(|old| {
                    p.ticket <= old.ticket || p.tick < old.tick || p.endpoint != old.endpoint
                })
            {
                return Err("network error source/replay/order".into());
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
    fn source_and_defined_error_detail_are_closed_without_authority_inference() {
        let build = "a".repeat(64);
        let row = format!(
            "EVROSION_M6_NETWORK_ERROR protocol=1 build={build} actor=root process=20 thread=120 endpoint=7 ticket=9 tick=10 layer=3 operation=5 class=7 detail=5 subdetail=0 progress=0"
        );
        line(&row, &build).unwrap();
        for bad in [
            row.replace("layer=3", "layer=1"),
            row.replace("detail=5", "detail=6"),
            row.replace("ticket=9", "ticket=09"),
            row.replace("progress=0", "progress=1"),
            row.replace("subdetail=0", "subdetail=1"),
        ] {
            assert!(line(&bad, &build).is_err());
        }
        assert!(records(format!("{row}\n").as_bytes(), &build).is_err());
        let prefix = format!(
            "EVROSION_M5_NATIVE_COMMON_PREFIX protocol=1 build={build} mode=0 root_process=20 root_thread=120 root_image_sha256={} root_epoch=501 root_incarnation=1 root_manifest_sha256={} block_process=24 block_thread=124 block_image_sha256={} system_endpoint=12 root_frames=111 block_frames=20\n",
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
            format!("{prefix}{row}\n{row}\n"),
            format!("{prefix}{row}"),
            format!("{prefix}EVROSION_M6_LOG_BOUND x\n{row}\n"),
        ] {
            assert!(records(bad.as_bytes(), &build).is_err());
        }
    }
}
