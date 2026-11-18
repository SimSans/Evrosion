//! Actual Kernel downloaded-code lifecycle, separate from compiled-bank counts.
//! Sealed bytes/registration prove neither publisher trust, health nor Known Good.
use crate::{boot_protocol::canonical_number, build::Result};
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Action {
    pub kind: String,
    pub slot: u64,
    pub process: u64,
    pub thread: u64,
    pub job: u64,
    pub elf_sha256: String,
    pub content_sha256: String,
    pub declared_package_id: String,
}
pub(crate) fn line(row: &str, build: &str) -> Result<Action> {
    let fields: Vec<_> = row.split(' ').collect();
    if row.len() > 768
        || fields.len() != 11
        || fields[0] != "EVROSION_M6_DOWNLOADED_ACTION"
        || fields[1] != "protocol=1"
        || fields[2] != format!("build={build}")
    {
        return Err("downloaded action shape/build".into());
    }
    let kind = fields[3]
        .strip_prefix("action=")
        .filter(|v| matches!(*v, "start" | "stop" | "reap"))
        .ok_or("downloaded action kind")?;
    let numbers = fields[4..8]
        .iter()
        .zip(["slot", "process", "thread", "job"])
        .map(|(f, k)| canonical_number(f, k))
        .collect::<Result<Vec<_>>>()?;
    if !(1..=2).contains(&numbers[0]) || numbers[1..].iter().any(|n| matches!(*n, 0 | u64::MAX)) {
        return Err("downloaded action identity/slot".into());
    }
    let hashes = fields[8..]
        .iter()
        .zip(["elf_sha256", "content_sha256", "declared_package_id"])
        .map(|(f, k)| {
            let hash = f
                .strip_prefix(k)
                .and_then(|v| v.strip_prefix('='))
                .ok_or("downloaded digest key")?;
            if hash.len() != 64
                || hash.bytes().all(|b| b == b'0')
                || !hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("downloaded digest canonical nonzero64hex".into());
            }
            Ok(hash.to_owned())
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Action {
        kind: kind.to_owned(),
        slot: numbers[0],
        process: numbers[1],
        thread: numbers[2],
        job: numbers[3],
        elf_sha256: hashes[0].clone(),
        content_sha256: hashes[1].clone(),
        declared_package_id: hashes[2].clone(),
    })
}
pub(crate) fn records(serial: &[u8], build: &str, final_check: bool) -> Result<Vec<Action>> {
    if serial.len() > 1024 * 1024 {
        return Err("downloaded action capture bound".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "downloaded action UTF8")?;
    let mut root = None;
    let mut identities: [Option<(String, String, String)>; 2] = [None, None];
    let mut registered = [false; 2];
    let mut live: Option<Action> = None;
    let mut stopped: Option<Action> = None;
    let mut bank: Option<crate::native_protocol::Action> = None;
    let mut bank_stopped = false;
    let mut processes = std::collections::BTreeSet::new();
    let mut threads = std::collections::BTreeSet::new();
    let mut closed = false;
    let mut cleanup = false;
    let mut out = Vec::new();
    for raw in text.split_inclusive('\n') {
        let row = raw.trim_end_matches(['\r', '\n']);
        if row.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX ") {
            if root.is_some() {
                return Err("downloaded action duplicate Root prefix".into());
            }
            let crate::native3_protocol::Event::Common(c) =
                crate::native3_protocol::event_network(row, build)?
            else {
                unreachable!()
            };
            root = Some((c.root_process, c.root_thread));
        } else if row.starts_with("EVROSION_M6_LOG_BOUND ") || row.starts_with("EVROSION_M6_LOG ") {
            closed = true;
        } else if row.starts_with("EVROSION_M6_IMAGE ") {
            let image = crate::image_protocol::line(row, build)?;
            if !raw.ends_with('\n') || root != Some((image.process, image.thread)) {
                return Err("downloaded registration actual Root".into());
            }
            if cleanup {
                return Err("image work after final physical cleanup".into());
            }
            if image.op == 0 && image.status == 0 {
                if !closed && (live.is_some() || stopped.is_some() || bank.is_some()) {
                    return Err("physical cleanup precedes actual App reap".into());
                }
                cleanup = true;
            }
            if image.status == 0 && image.op == 6 {
                if closed || image.phase != 4 || !(1..=2).contains(&image.slot) {
                    return Err("downloaded registration state".into());
                }
                let index = image.slot as usize - 1;
                let identity = (
                    image.elf_sha256,
                    image.content_sha256,
                    image.declared_package_id,
                );
                if registered[index]
                    || live.as_ref().is_some_and(|a| a.slot == image.slot)
                    || stopped.as_ref().is_some_and(|a| a.slot == image.slot)
                    || identities[index]
                        .as_ref()
                        .is_some_and(|old| old != &identity)
                {
                    return Err("downloaded immutable registration replaced/duplicated/live".into());
                }
                identities[index] = Some(identity);
                registered[index] = true;
            } else if image.status == 0 && image.op == 8 && (1..=2).contains(&image.slot) {
                let index = image.slot as usize - 1;
                if closed
                    || image.phase != 3
                    || !registered[index]
                    || live.as_ref().is_some_and(|a| a.slot == image.slot)
                    || stopped.as_ref().is_some_and(|a| a.slot == image.slot)
                    || identities[index]
                        .as_ref()
                        .is_none_or(|(elf, content, package)| {
                            *elf != image.elf_sha256
                                || *content != image.content_sha256
                                || *package != image.declared_package_id
                        })
                {
                    return Err(
                        "downloaded unregister before reap/without exact registration".into(),
                    );
                }
                registered[index] = false;
            }
        } else if row.starts_with("EVROSION_M5_NATIVE_ACTION") {
            let action = crate::native_protocol::action(row, build)?;
            let same = bank.as_ref().is_some_and(|old| {
                old.process == action.process
                    && old.thread == action.thread
                    && old.image_sha256 == action.image_sha256
            });
            if closed || cleanup || root.is_none() || !raw.ends_with('\n') {
                return Err("bank action origin/retention".into());
            }
            match action.kind.as_str() {
                "start"
                    if bank.is_none()
                        && live.is_none()
                        && stopped.is_none()
                        && processes.insert(action.process)
                        && threads.insert(action.thread) =>
                {
                    bank = Some(action)
                }
                "stop" if same && !bank_stopped => bank_stopped = true,
                "reap" if same && bank_stopped => {
                    bank = None;
                    bank_stopped = false;
                }
                _ => return Err("bank/downloaded App ownership overlap/order".into()),
            }
        } else if row.starts_with("EVROSION_M6_DOWNLOADED_ACTION") {
            let action = line(row, build)?;
            if closed
                || cleanup
                || root.is_none()
                || !raw.ends_with('\n')
                || root.is_some_and(|(process, thread)| {
                    process == action.process || thread == action.thread
                })
            {
                return Err("downloaded action origin/retention".into());
            }
            let same = |a: &Action| {
                a.slot == action.slot
                    && a.process == action.process
                    && a.thread == action.thread
                    && a.job == action.job
                    && a.elf_sha256 == action.elf_sha256
                    && a.content_sha256 == action.content_sha256
                    && a.declared_package_id == action.declared_package_id
            };
            match action.kind.as_str() {
                "start"
                    if live.is_none()
                        && stopped.is_none()
                        && bank.is_none()
                        && processes.insert(action.process)
                        && threads.insert(action.thread)
                        && registered[action.slot as usize - 1]
                        && identities[action.slot as usize - 1].as_ref().is_some_and(
                            |(elf, content, package)| {
                                *elf == action.elf_sha256
                                    && *content == action.content_sha256
                                    && *package == action.declared_package_id
                            },
                        ) =>
                {
                    live = Some(action.clone())
                }
                "stop" if live.as_ref().is_some_and(same) => {
                    live = None;
                    stopped = Some(action.clone());
                }
                "reap" if stopped.as_ref().is_some_and(same) => stopped = None,
                _ => return Err("downloaded action missing registration/stale/out of order".into()),
            }
            out.push(action);
        }
    }
    if final_check && (live.is_some() || stopped.is_some() || bank.is_some()) {
        return Err("downloaded lifecycle incomplete".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn build() -> String {
        "a".repeat(64)
    }
    fn prefix() -> String {
        format!(
            "EVROSION_M5_NATIVE_COMMON_PREFIX protocol=1 build={} mode=0 root_process=20 root_thread=120 root_image_sha256={} root_epoch=501 root_incarnation=1 root_manifest_sha256={} block_process=24 block_thread=124 block_image_sha256={} system_endpoint=12 root_frames=176 block_frames=20\n",
            build(),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64)
        )
    }
    fn registered() -> String {
        format!(
            "EVROSION_M6_IMAGE protocol=1 build={} op=6 slot=1 phase=4 status=0 reason=0 process=20 thread=120 job=3 tick=900 original_cut=10000 external_frames=2 root_cr3=4096 table=8192 control=12288 declared_bytes=4096 pages=1 verified_bytes=4096 elf_sha256={} content_sha256={} declared_package_id={} returned_memory_capability=0\n",
            build(),
            "e".repeat(64),
            "f".repeat(64),
            "1".repeat(64)
        )
    }
    fn action(kind: &str) -> String {
        format!(
            "EVROSION_M6_DOWNLOADED_ACTION protocol=1 build={} action={kind} slot=1 process=30 thread=130 job=7 elf_sha256={} content_sha256={} declared_package_id={}\n",
            build(),
            "e".repeat(64),
            "f".repeat(64),
            "1".repeat(64)
        )
    }
    fn cleanup() -> String {
        format!(
            "EVROSION_M6_IMAGE protocol=1 build={} op=0 slot=0 phase=0 status=0 reason=0 process=20 thread=120 job=3 tick=901 original_cut=0 external_frames=0 root_cr3=4096 table=0 control=0 declared_bytes=0 pages=0 verified_bytes=0 elf_sha256={} content_sha256={} declared_package_id={} returned_memory_capability=0\n",
            build(),
            "0".repeat(64),
            "0".repeat(64),
            "0".repeat(64)
        )
    }
    #[test]
    fn identities_cannot_change_and_cleanup_or_pid_tid_reuse_cannot_hide_another_app() {
        let end = action("start") + &action("stop") + &action("reap");
        let done = prefix() + &registered() + &end;
        let unregister = registered().replace("op=6 slot=1 phase=4", "op=8 slot=1 phase=3");
        let next = end.replace("process=30 thread=130", "process=31 thread=131");
        assert!(
            records(
                (done.clone() + &unregister + &registered() + &next + &cleanup()).as_bytes(),
                &build(),
                true
            )
            .is_ok()
        );
        let cases = [
            done.clone() + &end.replace("process=30 thread=130", "process=30 thread=131"),
            done.clone() + &end.replace("process=30 thread=130", "process=31 thread=130"),
            prefix() + &registered() + &registered() + &end,
            prefix()
                + &registered()
                + &action("start")
                + &unregister
                + &action("stop")
                + &action("reap"),
            prefix()
                + &registered()
                + &action("start")
                + &action("stop")
                + &unregister
                + &action("reap"),
            done.clone()
                + &unregister
                + &registered().replace(&"e".repeat(64), &"2".repeat(64))
                + &next,
            done.clone() + &cleanup() + &next,
            prefix() + &registered() + &action("start") + &cleanup(),
        ];
        for bad in cases {
            assert!(records(bad.as_bytes(), &build(), true).is_err(), "{bad}");
        }
        let bank = |kind| {
            format!(
                "EVROSION_M5_NATIVE_ACTION protocol=1 build={} action={kind} process=40 thread=140 image_sha256={}\n",
                build(),
                "e".repeat(64)
            )
        };
        let base = prefix() + &registered() + &bank("start") + &bank("stop") + &bank("reap");
        for reused in [
            end.replace("process=30 thread=130", "process=40 thread=130"),
            end.replace("process=30 thread=130", "process=30 thread=140"),
        ] {
            assert!(records((base.clone() + &reused).as_bytes(), &build(), true).is_err());
        }
    }
    #[test]
    fn only_actual_registered_slot_and_complete_incarnation_accept_downloaded_lifecycle() {
        let good = prefix() + &registered() + &action("start") + &action("stop") + &action("reap");
        assert_eq!(records(good.as_bytes(), &build(), true).unwrap().len(), 3);
        let partial = prefix() + &registered() + &action("start");
        assert_eq!(
            records(partial.as_bytes(), &build(), false).unwrap().len(),
            1
        );
        assert!(records(partial.as_bytes(), &build(), true).is_err());
        for bad in [
            prefix() + &action("start") + &action("stop") + &action("reap"),
            good.replace("op=6 slot=1 phase=4", "op=5 slot=1 phase=3"),
            good.replace("action=stop slot=1", "action=stop slot=2"),
            good.replace(
                "action=reap slot=1 process=30",
                "action=reap slot=1 process=31",
            ),
            good.replace(
                "action=start slot=1 process=30 thread=130",
                "action=start slot=1 process=20 thread=120",
            ),
            prefix() + &registered() + &action("stop") + &action("reap"),
            good.clone() + &action("start"),
            prefix() + &registered() + "EVROSION_M6_LOG_BOUND closed\n" + &action("start"),
            prefix() + &registered() + action("start").trim_end(),
        ] {
            assert!(records(bad.as_bytes(), &build(), true).is_err(), "{bad}");
        }
    }
    #[test]
    fn equal_elf_bytes_do_not_alias_bank_provenance_or_allow_parallel_app_owners() {
        let start = action("start");
        assert!(crate::native_protocol::action(start.trim_end(), &build()).is_err());
        let bank = |kind| {
            format!(
                "EVROSION_M5_NATIVE_ACTION protocol=1 build={} action={kind} process=40 thread=140 image_sha256={}\n",
                build(),
                "e".repeat(64)
            )
        };
        let sequence = prefix()
            + &registered()
            + &bank("start")
            + &bank("stop")
            + &bank("reap")
            + &start
            + &action("stop")
            + &action("reap");
        assert_eq!(
            records(sequence.as_bytes(), &build(), true).unwrap().len(),
            3
        );
        for overlap in [
            prefix() + &registered() + &bank("start") + &start,
            prefix() + &registered() + &start + &bank("start"),
        ] {
            assert!(records(overlap.as_bytes(), &build(), false).is_err());
        }
        for bad in [
            start.replace("slot=1", "slot=3"),
            start.replace("job=7", "job=0"),
            start.replace("process=30", "process=030"),
            start.replace(&"e".repeat(64), &"0".repeat(64)),
            start.replace("action=start", "action=healthy"),
        ] {
            assert!(line(bad.trim_end(), &build()).is_err());
        }
    }
}
