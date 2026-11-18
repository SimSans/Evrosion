//! Closed Kernel-direct negative-fixture observations. These records do not
//! establish whole-guest success or permit replay of accepted work.
use crate::{boot_protocol::canonical_number, build::Result};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
#[cfg(test)]
#[path = "records_tests.rs"]
mod independent_tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct Call {
    pub epoch: u64,
    pub id: u64,
    pub endpoint: u64,
    pub ticket: u64,
    pub deadline: u64,
    pub caller: (u64, u64),
    pub callee: (u64, u64),
}
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Row {
    pub sequence: u64,
    pub kind: u8,
    pub actor: usize,
    pub process: u64,
    pub thread: u64,
    pub tick: u64,
    pub call: Option<Call>,
    pub opcode: u64,
    pub status: u64,
    pub length: u64,
    pub value: u64,
    pub request: u64,
    pub payload: [u8; 32],
    pub image: [u8; 32],
}
fn hex(value: &str, key: &str) -> Result<[u8; 32]> {
    let value = value
        .strip_prefix(key)
        .and_then(|v| v.strip_prefix('='))
        .ok_or_else(|| format!("negative missing {key}"))?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("negative digest must be64 lowercase hex characters".into());
    }
    let mut out = [0; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}
pub(crate) fn line(text: &str, build: &str) -> Result<Row> {
    let f: Vec<_> = text.split(' ').collect();
    if text.len() > 1536
        || f.len() != 25
        || f[0] != "EVROSION_M6_NEGATIVE"
        || f[1] != "protocol=1"
        || f[2] != format!("build={build}")
        || build.len() != 64
        || !build
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("negative observation shape/protocol/build".into());
    }
    let keys = [
        "sequence",
        "kind",
        "actor",
        "process",
        "thread",
        "tick",
        "call_epoch",
        "call",
        "endpoint",
        "ticket",
        "deadline",
        "caller_process",
        "caller_thread",
        "callee_process",
        "callee_thread",
        "opcode",
        "status",
        "length",
        "value",
        "request",
    ];
    let n: Vec<_> = f[3..23]
        .iter()
        .zip(keys)
        .map(|(v, k)| canonical_number(v, k))
        .collect::<Result<_>>()?;
    let nonzero = |v| v != 0 && v != u64::MAX;
    if !(1..=97).contains(&n[0])
        || n[1] > 8
        || n[2] > 8
        || !nonzero(n[3])
        || !nonzero(n[4])
        || n[5] == u64::MAX
    {
        return Err("negative identity/sequence/kind/tick".into());
    }
    let call = if n[1] <= 1 || n[1] == 8 {
        if n[6..15].iter().any(|v| *v != 0) {
            return Err("negative fabricated call on noncall row".into());
        }
        None
    } else {
        if !n[6..15].iter().all(|v| nonzero(*v)) || n[11] == n[13] || n[12] == n[14] {
            return Err("negative actual call identity/cut missing".into());
        }
        Some(Call {
            epoch: n[6],
            id: n[7],
            endpoint: n[8],
            ticket: n[9],
            deadline: n[10],
            caller: (n[11], n[12]),
            callee: (n[13], n[14]),
        })
    };
    let payload = hex(f[23], "payload_sha256")?;
    let image = hex(f[24], "image_sha256")?;
    if image == [0; 32] {
        return Err("negative actual image absent".into());
    }
    let actor = n[2] as usize;
    let me = (n[3], n[4]);
    let op = n[15];
    let status = n[16];
    let len = n[17];
    let value = n[18];
    let valid = match n[1] {
        0 => {
            actor == 0
                && matches!(op, 1..=3)
                && status == 0
                && len == 0
                && value > n[5]
                && value != u64::MAX
                && value - n[5] <= 8192
                && n[19] == 0
                && payload == [0; 32]
        }
        1 => {
            actor == 5
                && matches!(
                    op,
                    ev_userspace_contract::syscall::RPC_CALL | 35 | 36 | 50 | 51 | 53
                )
                && status == 1
                && len == 0
                && payload == [0; 32]
                && match op {
                    35 | 36 => value == 0x300 && n[19] == 0,
                    ev_userspace_contract::syscall::RPC_CALL => {
                        value == 0 && n[19] == u64::from_le_bytes(*b"S\x01\x05\0\x01\0\0\0")
                    }
                    50 => value == 0x310 && n[19] == 0,
                    51 => value == 0x310 && n[19] == 0x12345678,
                    53 => value == 0 && n[19] == 0,
                    _ => false,
                }
        }
        2 => {
            actor == 0
                && me == call.unwrap().caller
                && status == 0
                && (1..=11).contains(&op)
                && len <= 1024
                && payload != [0; 32]
        }
        3 => {
            actor == 8
                && me == call.unwrap().callee
                && (1..=11).contains(&op)
                && status <= 5
                && len <= 1024
                && payload != [0; 32]
        }
        4 => {
            actor == 7
                && me == call.unwrap().callee
                && op == 6
                && status == 0
                && len == 4096
                && nonzero(value)
                && payload != [0; 32]
        }
        5 => {
            actor == 8
                && me == call.unwrap().callee
                && op == 10
                && status == 0
                && len == 4096
                && nonzero(value)
                && payload != [0; 32]
        }
        6 => {
            matches!(actor, 7 | 8)
                && (me == call.unwrap().caller || me == call.unwrap().callee)
                && op == 0
                && status == 1
                && len == 0
                && nonzero(value)
                && payload == [0; 32]
        }
        7 => {
            matches!(actor, 0 | 8)
                && me == call.unwrap().caller
                && op == 0
                && matches!(status, 4..=6)
                && len == 0
                && value == 0
                && payload == [0; 32]
        }
        8 => actor == 0 && op == 0 && status == 0 && len == 0 && n[19] == 0 && payload == [0; 32],
        _ => false,
    };
    if !valid {
        return Err("negative row has impossible kind/source/payload facts".into());
    }
    Ok(Row {
        sequence: n[0],
        kind: n[1] as u8,
        actor,
        process: n[3],
        thread: n[4],
        tick: n[5],
        call,
        opcode: op,
        status,
        length: len,
        value,
        request: n[19],
        payload,
        image,
    })
}

pub(crate) struct Verified {
    rows: Vec<Row>,
    serial: [u8; 32],
}
impl Verified {
    pub(crate) fn rows(&self) -> &[Row] {
        &self.rows
    }
}
pub(crate) fn records(
    serial: &[u8],
    build: &str,
    images: Option<&[String; 9]>,
) -> Result<Verified> {
    let rows = prefix(serial, build, images)?;
    if serial.last() != Some(&b'\n') || rows.last().is_none_or(|r| r.kind != 8 || r.value != 0) {
        return Err("negative observation history lacks complete zero-omission summary".into());
    }
    Ok(Verified {
        rows,
        serial: Sha256::digest(serial).into(),
    })
}
pub(crate) fn prefix(serial: &[u8], build: &str, images: Option<&[String; 9]>) -> Result<Vec<Row>> {
    if serial.len() > 1024 * 1024 {
        return Err("negative complete serial bound".into());
    }
    let text = std::str::from_utf8(serial).map_err(|_| "negative UTF8")?;
    let mut root = None;
    let mut closed = false;
    let mut identities: [Option<(u64, u64)>; 9] = [None; 9];
    let mut out: Vec<Row> = Vec::new();
    for line_text in text.lines().map(|s| s.trim_end_matches('\r')) {
        if line_text.starts_with("EVROSION_M5_NATIVE_COMMON_PREFIX ") {
            let crate::native3_protocol::Event::Common(c) =
                crate::native3_protocol::event_network(line_text, build)?
            else {
                unreachable!()
            };
            if root
                .replace((
                    (c.root_process, c.root_thread),
                    hex(&format!("image={}", c.root_image), "image")?,
                ))
                .is_some()
            {
                return Err("negative duplicate actual Root".into());
            }
        }
        if line_text.starts_with("EVROSION_M6_LOG ")
            || line_text.starts_with("EVROSION_M5_NATIVE ")
            || line_text.starts_with("EVROSION_M6_LOG_BOUND ")
            || line_text.starts_with("EVROSION_M5_NATIVE_PROFILE ")
        {
            closed = true;
        }
        if line_text.starts_with("EVROSION_M6_NEGATIVE_CPU") {
            super::endurance_protocol::cpu(line_text, build)?;
            continue;
        }
        if line_text.starts_with("EVROSION_M6_NEGATIVE_WORK") {
            super::endurance_protocol::work(line_text, build)?;
            continue;
        }
        if line_text.starts_with("EVROSION_M6_NEGATIVE") {
            let row = line(line_text, build)?;
            let (actual_root, root_image) = root.ok_or("negative record precedes actual Root")?;
            if closed
                || out.last().is_some_and(|old| old.kind == 8)
                || row.sequence != out.len() as u64 + 1
                || out.last().is_some_and(|old| row.tick < old.tick)
                || images.is_some_and(|i| {
                    hex(&format!("image={}", i[row.actor]), "image") != Ok(row.image)
                })
                || (row.actor == 0 && row.image != root_image)
                || ((row.actor == 0) != ((row.process, row.thread) == actual_root))
            {
                return Err("negative actual image/Root/ordering mismatch".into());
            }
            if let Some(call) = row.call
                && matches!(row.kind, 2 | 5)
                && call.caller != actual_root
            {
                return Err("negative outer call has foreign actual Root".into());
            }
            let who = (row.process, row.thread);
            if identities[row.actor].is_some_and(|old| old != who)
                || identities.iter().enumerate().any(|(actor, old)| {
                    actor != row.actor && old.is_some_and(|id| id.0 == who.0 || id.1 == who.1)
                })
            {
                return Err("negative actor changed incarnation or shared another identity".into());
            }
            identities[row.actor] = Some(who);
            out.push(row);
        }
    }
    Ok(out)
}

/// Constructed only from joined Kernel capture/cancellation records. Ordinary
/// completion parsers keep requiring calls==replies.
pub(crate) struct Cancelled {
    calls: Vec<Call>,
    serial: [u8; 32],
}
impl Cancelled {
    pub(crate) fn count(&self) -> u64 {
        self.calls.len() as u64
    }
    pub(crate) fn calls(&self) -> &[Call] {
        &self.calls
    }
    pub(crate) fn matches(&self, serial: &[u8]) -> bool {
        <[u8; 32]>::from(Sha256::digest(serial)) == self.serial
    }
}
pub(crate) fn without_failure(verified: &Verified) -> Result<Cancelled> {
    if verified.rows.iter().any(|r| matches!(r.kind, 4..=7)) {
        return Err("negative no-failure case contains captured stop or cancellation".into());
    }
    Ok(Cancelled {
        calls: Vec::new(),
        serial: verified.serial,
    })
}
pub(crate) fn captured_failure(verified: &Verified, victim: usize) -> Result<Cancelled> {
    let rows = verified.rows();
    if !matches!(victim, 7 | 8) {
        return Err("negative wrong failure victim".into());
    }
    let select = |kind| rows.iter().filter(|r| r.kind == kind).collect::<Vec<_>>();
    let arms = select(0);
    let leaf = select(4);
    let parent = select(5);
    let stops = select(6);
    if arms.len() != 2
        || arms[0].opcode != 3
        || arms[1].opcode != if victim == 7 { 1 } else { 2 }
        || arms[0].value != arms[1].value
        || leaf.len() != 1
        || parent.len() != 1
        || stops.len() != 1
    {
        return Err("negative missing unique watch/arm/nested call/actual stop".into());
    }
    let (leaf, parent, stop) = (leaf[0], parent[0], stops[0]);
    let inner = leaf.call.unwrap();
    let outer = parent.call.unwrap();
    let expected_window =
        |notice: u64, prefix: u8, opcode: u8, magic: &[u8; 8]| -> Result<[u8; 32]> {
            let n = notice.to_le_bytes();
            if n[..4] != [prefix, 2, opcode, 0]
                || matches!(u32::from_le_bytes(n[4..].try_into().unwrap()), 0 | u32::MAX)
            {
                return Err("negative captured shutdown notice differs".into());
            }
            let mut window = [0; 4096];
            window[..8].copy_from_slice(magic);
            window[8] = 2;
            window[11] = opcode;
            window[14] = 8;
            window[16..20].copy_from_slice(&n[4..]);
            window[64..72].copy_from_slice(&arms[0].value.to_le_bytes());
            Ok(Sha256::digest(window).into())
        };
    if leaf.payload != expected_window(leaf.request, b'N', 6, b"EVNIO001")?
        || parent.payload != expected_window(parent.request, b'S', 10, b"EVNET001")?
    {
        return Err(
            "negative captured windows differ from exact canonical original aggregate".into(),
        );
    }
    let accepted_outer: Vec<_> = rows
        .iter()
        .filter(|r| {
            r.kind == 2
                && r.call == Some(outer)
                && r.opcode == 10
                && r.request == parent.request
                && r.length == 8
                && r.value == arms[0].value
                && r.payload == parent.payload
                && r.sequence < leaf.sequence
        })
        .collect();
    if accepted_outer.len() != 1 {
        return Err(
            "negative captured outer window does not join its actual accepted request".into(),
        );
    }
    if leaf.sequence <= arms[1].sequence
        || parent.sequence != leaf.sequence + 1
        || stop.sequence != parent.sequence + 1
        || inner.epoch != outer.epoch
        || leaf.value != outer.id
        || parent.value != inner.id
        || stop.actor != victim
        || stop.call != Some(inner)
        || stop.request != leaf.request
        || stop.value != outer.id
        || inner.caller != outer.callee
        || inner.deadline > outer.deadline
        || outer.deadline > arms[0].value
        || stop.tick >= inner.deadline
    {
        return Err("negative captured nested relation/cut/stop identity differs".into());
    }
    let mut unique = BTreeSet::new();
    let mut cancelled = Vec::new();
    for row in select(7) {
        let call = row.call.unwrap();
        if row.sequence <= stop.sequence
            || row.request
                != if call == inner {
                    leaf.request
                } else {
                    parent.request
                }
            || ![inner, outer].contains(&call)
            || !unique.insert((call.epoch, call.id))
        {
            return Err("negative unjoined/duplicate no-ACK cancellation".into());
        }
        cancelled.push(call);
    }
    if cancelled.is_empty() {
        return Err("negative actual peer death returned no canonical guard owner".into());
    }
    let dead_call = if victim == 7 { inner } else { outer };
    if !rows
        .iter()
        .any(|r| r.kind == 7 && r.call == Some(dead_call) && r.status == 5)
    {
        return Err("negative stopped callee lacks its actual mandatory PeerDied terminal".into());
    }
    Ok(Cancelled {
        calls: cancelled,
        serial: verified.serial,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn arm() -> String {
        format!(
            "EVROSION_M6_NEGATIVE protocol=1 build={} sequence=1 kind=0 actor=0 process=1 thread=1 tick=100 call_epoch=0 call=0 endpoint=0 ticket=0 deadline=0 caller_process=0 caller_thread=0 callee_process=0 callee_thread=0 opcode=3 status=0 length=0 value=1000 request=0 payload_sha256={} image_sha256={}",
            "a".repeat(64),
            "0".repeat(64),
            "b".repeat(64)
        )
    }
    #[test]
    fn closed_shapes_refuse_false_calls_unknown_kinds_and_bad_cuts() {
        let a = arm();
        assert!(line(&a, &"a".repeat(64)).is_ok());
        for bad in [
            a.replace("sequence=1", "sequence=01"),
            a.replace("kind=0", "kind=9"),
            a.replace("call=0", "call=1"),
            a.replace("value=1000", "value=100"),
            a.replace("value=1000", "value=9000"),
            a.replace("actor=0", "actor=7"),
            a.clone() + " extra=1",
        ] {
            assert!(line(&bad, &"a".repeat(64)).is_err(), "{bad}");
        }
    }
    #[test]
    fn parser_input_alone_cannot_claim_captured_failure_or_replies() {
        let v = Verified {
            rows: Vec::new(),
            serial: [0; 32],
        };
        assert!(captured_failure(&v, 7).is_err());
        assert!(captured_failure(&v, 8).is_err());
        let v = Verified {
            rows: vec![line(&arm(), &"a".repeat(64)).unwrap()],
            serial: [0; 32],
        };
        assert!(captured_failure(&v, 7).is_err());
    }
}
