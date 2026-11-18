//! First Kernel rejection per actual actor. No accepted-work/retry authority.
use crate::{boot_protocol::canonical_number, build::Result};
#[derive(Debug)]
pub(crate) struct Rejection {
    actor: u64,
    process: u64,
    thread: u64,
    tick: u64,
}
pub(crate) fn line(row: &str, build: &str) -> Result<Rejection> {
    let f: Vec<_> = row.split(' ').collect();
    if row.len() > 1024
        || f.len() != 17
        || f[0] != "EVROSION_M6_RPC_REJECTION"
        || f[1] != "protocol=1"
        || f[2] != format!("build={build}")
    {
        return Err("RPC rejection shape/build".into());
    }
    let n = f[3..]
        .iter()
        .zip([
            "actor",
            "process",
            "thread",
            "capability",
            "wire",
            "endpoint",
            "deadline",
            "tick",
            "branch",
            "reason",
            "detail",
            "parent_call",
            "parent_deadline",
            "parent_delivered",
        ])
        .map(|(v, k)| canonical_number(v, k))
        .collect::<Result<Vec<_>>>()?;
    if n[0] > 8
        || n[1..3].iter().any(|v| matches!(*v, 0 | u64::MAX))
        || n[6] == u64::MAX
        || n[7] == u64::MAX
        || n[13] > 2
        || ((n[11] == 0) != (n[12] == 0))
        || (n[11] == 0 && n[13] != 0)
        || n[11] == u64::MAX
        || n[12] == u64::MAX
        || match n[8] {
            1 => n[4] != 255 || n[5] != 0 || n[9] != 0 || n[10] != 0,
            2 => n[4] > 17 || n[5] == 0 || n[9] != 0 || n[10] != 0,
            3 => {
                n[4] > 17
                    || n[5] == 0
                    || !(1..=14).contains(&n[9])
                    || if n[9] == 1 {
                        !(1..=11).contains(&n[10])
                    } else {
                        n[10] != 0
                    }
            }
            4 => n[4] > 17 || n[5] == 0 || !(1..=25).contains(&n[9]) || n[10] != 0,
            _ => true,
        }
    {
        return Err("RPC rejection source/branch/reason/parent".into());
    }
    Ok(Rejection {
        actor: n[0],
        process: n[1],
        thread: n[2],
        tick: n[7],
    })
}
pub(crate) fn records(serial: &[u8], build: &str) -> Result<Vec<Rejection>> {
    if serial.len() > 1024 * 1024 {
        return Err("RPC rejection capture bound".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "RPC rejection UTF8")?;
    let mut root = None;
    let mut closed = false;
    let mut out: Vec<Rejection> = Vec::new();
    for raw in text.split_inclusive('\n') {
        let row = raw.trim_end_matches(['\r', '\n']);
        if row.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX ") {
            if root.is_some() {
                return Err("RPC rejection duplicate Root".into());
            }
            let crate::native3_protocol::Event::Common(c) =
                crate::native3_protocol::event_network(row, build)?
            else {
                unreachable!()
            };
            root = Some((c.root_process, c.root_thread));
        } else if row.starts_with("EVROSION_M6_LOG_BOUND ") || row.starts_with("EVROSION_M6_LOG ") {
            closed = true;
        } else if row.starts_with("EVROSION_M6_RPC_REJECTION") {
            let p = line(row, build)?;
            let Some(actual) = root else {
                return Err("RPC rejection lacks Root context".into());
            };
            if closed
                || !raw.ends_with('\n')
                || out.len() >= 9
                || (p.actor == 0 && (p.process, p.thread) != actual)
                || (p.actor != 0 && (p.process == actual.0 || p.thread == actual.1))
                || out.iter().any(|old| old.actor == p.actor)
                || out.last().is_some_and(|old| p.tick < old.tick)
            {
                return Err("RPC rejection actor/origin/order/bound".into());
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
    fn rejects_ambiguous_branch_codes_parent_shapes_and_duplicate_actor() {
        let b = "a".repeat(64);
        let row = format!(
            "EVROSION_M6_RPC_REJECTION protocol=1 build={b} actor=8 process=7 thread=7 capability=512 wire=16 endpoint=30 deadline=19000 tick=18700 branch=4 reason=15 detail=0 parent_call=90 parent_deadline=18800 parent_delivered=0"
        );
        line(&row, &b).unwrap();
        for bad in [
            row.replace("reason=15", "reason=26"),
            row.replace("detail=0", "detail=1"),
            row.replace("parent_call=90", "parent_call=0"),
            row.replace("wire=16", "wire=255"),
            row.replace("actor=8", "actor=08"),
        ] {
            assert!(line(&bad, &b).is_err());
        }
        assert!(records(format!("{row}\n").as_bytes(), &b).is_err());
        let prefix = format!(
            "EVROSION_M5_NATIVE_COMMON_PREFIX protocol=1 build={b} mode=0 root_process=1 root_thread=1 root_image_sha256={} root_epoch=501 root_incarnation=1 root_manifest_sha256={} block_process=4 block_thread=4 block_image_sha256={} system_endpoint=12 root_frames=128 block_frames=20\n",
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64)
        );
        assert_eq!(
            records(format!("{prefix}{row}\n").as_bytes(), &b)
                .unwrap()
                .len(),
            1
        );
        for bad in [
            format!("{prefix}{row}"),
            format!("{prefix}{row}\n{row}\n"),
            format!("{prefix}EVROSION_M6_LOG_BOUND closed\n{row}\n"),
        ] {
            assert!(records(bad.as_bytes(), &b).is_err());
        }
    }
}
