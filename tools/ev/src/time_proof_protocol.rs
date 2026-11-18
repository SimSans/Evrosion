//! Actual Root proof progress, including success that explicitly leaves UTC
//! unqualified. Packets and this diagnostic never grant update authority.
pub(crate) use crate::network_protocol::Progress;
use crate::{boot_protocol::canonical_number, build::Result};
pub(crate) fn line(line: &str, build: &str) -> Result<Progress> {
    let f: Vec<_> = line.split(' ').collect();
    if line.len() > 512
        || f.len() != 12
        || f[0] != "EVROSION_M6_TIME_PROOF"
        || f[1] != "protocol=1"
        || f[2] != format!("build={build}")
        || f[11] != "utc=unqualified"
    {
        return Err("private time proof diagnostic shape/build/authority".into());
    }
    let keys = [
        "root_process",
        "root_thread",
        "endpoint",
        "ticket",
        "tick",
        "stage",
        "result",
        "argument",
    ];
    let n = f[3..11]
        .iter()
        .zip(keys)
        .map(|(v, k)| canonical_number(v, k))
        .collect::<Result<Vec<_>>>()?;
    if n[..4].iter().any(|v| matches!(*v, 0 | u64::MAX))
        || !(1..=4).contains(&n[5])
        || n[6] > 5
        || n[7] > u32::MAX as u64
        || (n[5] == 4) != (n[6] != 0)
        || match n[5] {
            1 => matches!(n[7], 0 | 0xffff_ffff),
            2 => !(1..=ev_time_proof::MAX_REPLY_BYTES as u64).contains(&n[7]),
            3 => n[7] != 11,
            4 => !(1..=3).contains(&n[7]),
            _ => true,
        }
    {
        return Err("private time proof diagnostic identity/range/meaning".into());
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
pub(crate) fn records(serial: &[u8], build: &str) -> Result<Vec<Progress>> {
    if serial.len() > 1024 * 1024 {
        return Err("private time capture bound".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "private time serial UTF8")?;
    let mut root = None;
    let mut closed = false;
    let mut out: Vec<Progress> = Vec::new();
    let mut sequence = None;
    for raw in text.split_inclusive('\n') {
        let row = raw.trim_end_matches(['\r', '\n']);
        if row.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX ") {
            if root.is_some() {
                return Err("duplicate private time Root prefix".into());
            }
            let crate::native3_protocol::Event::Common(c) =
                crate::native3_protocol::event_network(row, build)?
            else {
                unreachable!()
            };
            root = Some((c.root_process, c.root_thread));
        } else if row.starts_with("EVROSION_M6_LOG_BOUND ") || row.starts_with("EVROSION_M6_LOG ") {
            closed = true;
        } else if row.starts_with("EVROSION_M6_TIME_PROOF") {
            if !raw.ends_with('\n') || closed || out.len() >= 4 {
                return Err("private time incomplete/closed/bounded".into());
            }
            let p = line(row, build)?;
            let next_sequence = if p.stage == 1 {
                let expected = sequence.map_or(Some(1), |old: u64| old.checked_add(1));
                if Some(p.argument) != expected {
                    return Err("private time challenge sequence skipped/replayed".into());
                }
                Some(p.argument)
            } else {
                sequence
            };
            if root != Some((p.root_process, p.root_thread))
                || out.last().map_or(!matches!(p.stage, 1 | 4), |old| {
                    p.ticket <= old.ticket
                        || p.tick < old.tick
                        || p.endpoint != old.endpoint
                        || if matches!(old.stage, 3 | 4) {
                            p.stage != 1 || sequence.is_none()
                        } else {
                            p.stage != 4 && p.stage != old.stage + 1
                        }
                })
            {
                return Err("private time source/replay/order".into());
            }
            sequence = next_sequence;
            out.push(p);
        }
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn row(ticket: u64, stage: u64, result: u64, arg: u64) -> String {
        format!(
            "EVROSION_M6_TIME_PROOF protocol=1 build={} root_process=20 root_thread=120 endpoint=33 ticket={ticket} tick={ticket} stage={stage} result={result} argument={arg} utc=unqualified\n",
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
    fn complete_proof_is_root_ordered_and_still_explicitly_unqualified() {
        let build = "a".repeat(64);
        let good = format!(
            "{}{}{}{}",
            prefix(),
            row(1, 1, 0, 1),
            row(2, 2, 0, 352),
            row(3, 3, 0, 11)
        );
        assert_eq!(records(good.as_bytes(), &build).unwrap().len(), 3);
        for bad in [
            row(1, 1, 0, 1),
            good.replace("utc=unqualified", "utc=qualified"),
            good.replace("ticket=2", "ticket=1"),
            good.replace("argument=352", "argument=865"),
            good.replace("argument=11", "argument=1"),
            good.replace(
                "root_process=20 root_thread=120 endpoint",
                "root_process=21 root_thread=120 endpoint",
            ),
            format!("{good}{}", row(4, 4, 4, 3)),
            format!("{}{}{}", prefix(), row(1, 1, 0, 1), row(3, 3, 0, 11)),
            format!("{}EVROSION_M6_LOG_BOUND x\n{}", prefix(), row(1, 1, 0, 1)),
        ] {
            assert!(records(bad.as_bytes(), &build).is_err(), "{bad}");
        }
        assert!(records(good.trim_end().as_bytes(), &build).is_err());
        assert!(
            records(
                format!("{}{}", prefix(), row(1, 4, 1, 1)).as_bytes(),
                &build
            )
            .is_ok()
        );
    }
    #[test]
    fn lifetime_four_can_retain_the_next_sequence_without_inventing_its_completion() {
        let build = "a".repeat(64);
        let first = prefix() + &row(1, 1, 0, 1) + &row(2, 2, 0, 352) + &row(3, 3, 0, 11);
        let new = row(4, 1, 0, 2);
        assert_eq!(
            records((first.clone() + &new).as_bytes(), &build)
                .unwrap()
                .len(),
            4
        );
        for bad in [
            first.clone() + &row(4, 1, 0, 1),
            first.clone() + &row(4, 1, 0, 3),
            first.clone() + &row(4, 2, 0, 352),
            first.clone() + &new + &row(5, 2, 0, 352),
            prefix() + &row(1, 1, 0, 2),
            prefix() + &row(1, 4, 1, 1) + &row(2, 1, 0, 1),
        ] {
            assert!(records(bad.as_bytes(), &build).is_err());
        }
        let failed = prefix() + &row(1, 1, 0, 1) + &row(2, 2, 0, 352) + &row(3, 4, 4, 3) + &new;
        assert_eq!(records(failed.as_bytes(), &build).unwrap().len(), 4);
    }
}
