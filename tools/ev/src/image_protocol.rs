//! Actual bounded Kernel dynamic-image observations. A declared package ID is
//! not a verified Zion identity, release selection, health, or Known Good.
use crate::{boot_protocol::canonical_number, build::Result};

#[derive(Debug)]
pub(crate) struct Image {
    pub op: u64,
    pub process: u64,
    pub thread: u64,
    pub slot: u64,
    pub phase: u64,
    pub status: u64,
    pub elf_sha256: String,
    pub content_sha256: String,
    pub declared_package_id: String,
    job: u64,
    tick: u64,
    root_cr3: u64,
}
pub(crate) fn line(row: &str, build: &str) -> Result<Image> {
    let f: Vec<_> = row.split(' ').collect();
    if row.len() > 1536
        || f.len() != 24
        || f[0] != "EVROSION_M6_IMAGE"
        || f[1] != "protocol=1"
        || f[2] != format!("build={build}")
    {
        return Err("dynamic image observation shape/build".into());
    }
    let keys = [
        "op",
        "slot",
        "phase",
        "status",
        "reason",
        "process",
        "thread",
        "job",
        "tick",
        "original_cut",
        "external_frames",
        "root_cr3",
        "table",
        "control",
        "declared_bytes",
        "pages",
        "verified_bytes",
    ];
    let n = f[3..20]
        .iter()
        .zip(keys)
        .map(|(v, k)| canonical_number(v, k))
        .collect::<Result<Vec<_>>>()?;
    let cap = canonical_number(f[23], "returned_memory_capability")?;
    let mut hashes = Vec::new();
    let mut digests = Vec::new();
    for (field, key) in
        f[20..23]
            .iter()
            .zip(["elf_sha256", "content_sha256", "declared_package_id"])
    {
        let value = field
            .strip_prefix(key)
            .and_then(|s| s.strip_prefix('='))
            .ok_or("dynamic image digest key")?;
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("dynamic image digest canonical64hex".into());
        }
        hashes.push(value.bytes().all(|b| b == b'0'));
        digests.push(value.to_owned());
    }
    let [
        op,
        slot,
        phase,
        status,
        reason,
        process,
        thread,
        job,
        _tick,
        cut,
        external,
        cr3,
        table,
        control,
        bytes,
        pages,
        verified,
    ] = n[..]
    else {
        unreachable!()
    };
    let aligned = |v: u64| v & 4095 == 0 && v < 1u64 << 52;
    if op > 9
        || slot > 2
        || phase > 5
        || status > 1
        || (status == 0 && reason != 0)
        || (status == 1 && (!(1..=9).contains(&reason) || cap != 0))
        || [process, thread, job]
            .iter()
            .any(|v| matches!(*v, 0 | u64::MAX))
        || cut == u64::MAX
        || cr3 == 0
        || !aligned(cr3)
        || !aligned(table)
        || !aligned(control)
        || external != u64::from(table != 0) + u64::from(control != 0)
        || (table != 0 && (table == control || table == cr3))
        || (control != 0 && control == cr3)
        || bytes > 64 * 4096
        || pages > 64
        || (verified != 0 && verified != bytes)
        || ((verified == 0) != (hashes[0] && hashes[1]))
        || (verified != 0 && (hashes[0] || hashes[1]))
        || ((bytes == 0) != hashes[2])
        || (bytes != 0 && (pages == 0 || bytes.div_ceil(4096) != pages || cut == 0))
        || ((phase == 3 || phase == 4) && verified == 0)
        || (cap != 0 && (status != 0 || !matches!(op, 2 | 5) || matches!(cap, u64::MAX)))
        || (op == 0
            && status == 0
            && (slot != 0
                || phase != 0
                || external != 0
                || bytes != 0
                || pages != 0
                || verified != 0
                || cap != 0))
    {
        return Err("dynamic image source/state/count/hash/cap invariant".into());
    }
    Ok(Image {
        op,
        process,
        thread,
        slot,
        phase,
        status,
        elf_sha256: digests[0].clone(),
        content_sha256: digests[1].clone(),
        declared_package_id: digests[2].clone(),
        job,
        tick: n[8],
        root_cr3: cr3,
    })
}

/// Accept a retained ordinary prefix and at most one final cleanup snapshot.
/// Omitted observations never become a reconstructed successful lifecycle.
pub(crate) fn records(serial: &[u8], build: &str) -> Result<Vec<Image>> {
    if serial.len() > 1024 * 1024 {
        return Err("dynamic image capture bound".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "dynamic image serial UTF8")?;
    let mut root = None;
    let mut out: Vec<Image> = Vec::new();
    let mut closed = false;
    let mut complete = false;
    let mut cleanup = false;
    for raw in text.split_inclusive('\n') {
        let row = raw.trim_end_matches(['\r', '\n']);
        if row.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX ") {
            if root.is_some() {
                return Err("duplicate dynamic image Root prefix".into());
            }
            let crate::native3_protocol::Event::Common(c) =
                crate::native3_protocol::event_network(row, build)?
            else {
                unreachable!()
            };
            root = Some((c.root_process, c.root_thread));
        } else if row.starts_with("EVROSION_M6_LOG_BOUND ") {
            closed = true;
        } else if row.starts_with("EVROSION_M6_LOG ") {
            complete = true;
        } else if row.starts_with("EVROSION_M6_IMAGE") {
            let image = line(row, build)?;
            if !raw.ends_with('\n')
                || complete
                || cleanup
                || (closed && image.op != 0)
                || root != Some((image.process, image.thread))
                || out.last().is_some_and(|old| {
                    image.tick < old.tick || image.job != old.job || image.root_cr3 != old.root_cr3
                })
            {
                return Err("dynamic image actualRoot/order/retention".into());
            }
            cleanup = image.op == 0;
            out.push(image);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(op: u64) -> String {
        format!(
            "EVROSION_M6_IMAGE protocol=1 build={} op={op} slot=0 phase=0 status=0 reason=0 process=20 thread=120 job=3 tick=900 original_cut=0 external_frames=0 root_cr3=4096 table=0 control=0 declared_bytes=0 pages=0 verified_bytes=0 elf_sha256={} content_sha256={} declared_package_id={} returned_memory_capability=0",
            "a".repeat(64),
            "0".repeat(64),
            "0".repeat(64),
            "0".repeat(64)
        )
    }
    #[test]
    fn reject_false_verified_data_and_capabilities_and_ambiguous_wire_fields() {
        let good = row(0);
        let build = "a".repeat(64);
        line(&good, &build).unwrap();
        for bad in [
            good.replace("op=0", "op=10"),
            good.replace("status=0", "status=1"),
            good.replace("verified_bytes=0", "verified_bytes=1"),
            good.replace("pages=0", "pages=01"),
            good.replace(
                "returned_memory_capability=0",
                "returned_memory_capability=7",
            ),
            good.replace("root_cr3=4096", "root_cr3=4097"),
            good.replace("table=0", "table=4096"),
        ] {
            assert!(line(&bad, &build).is_err(), "{bad}");
        }
    }
    #[test]
    fn final_cleanup_is_unique_and_cannot_hide_work_after_omission_or_change_root() {
        let build = "a".repeat(64);
        let prefix = format!(
            "EVROSION_M5_NATIVE_COMMON_PREFIX protocol=1 build={build} mode=0 root_process=20 root_thread=120 root_image_sha256={} root_epoch=501 root_incarnation=1 root_manifest_sha256={} block_process=24 block_thread=124 block_image_sha256={} system_endpoint=12 root_frames=121 block_frames=20\n",
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64)
        );
        let work = row(1);
        let cleanup = row(0);
        let good = format!("{prefix}{work}\nEVROSION_M6_LOG_BOUND omitted\n{cleanup}\n");
        assert_eq!(records(good.as_bytes(), &build).unwrap().len(), 2);
        for bad in [
            format!("{work}\n"),
            format!("{good}{cleanup}\n"),
            format!("{good}{work}\n"),
            good.replace("process=20 thread=120 job=3", "process=21 thread=120 job=3"),
            format!("{prefix}{cleanup}"),
            format!("{prefix}EVROSION_M6_LOG done\n{cleanup}\n"),
        ] {
            assert!(records(bad.as_bytes(), &build).is_err(), "{bad}");
        }
    }
}
