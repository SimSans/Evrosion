//! Source-independent exact fixture bytes joined to Kernel-observed windows.
use super::{
    fixture,
    records::{self, Cancelled, Row, Verified},
};
use crate::{build::Result, network_negative_contract::Goal};
use ev_userspace_contract::syscall;
use sha2::{Digest as _, Sha256};
#[cfg(test)]
#[path = "cases_tests.rs"]
mod tests;

fn body_matches(row: &Row, body: &[u8]) -> bool {
    if !matches!(row.kind, 2 | 3) || row.length != body.len() as u64 {
        return false;
    }
    let notice = row.request.to_le_bytes();
    let version = if row.opcode >= 10 { 2 } else { 1 };
    if notice[..4] != [b'S', version, row.opcode as u8, 0]
        || matches!(
            u32::from_le_bytes(notice[4..].try_into().unwrap()),
            0 | u32::MAX
        )
    {
        return false;
    }
    let mut window = [0; 4096];
    window[..8].copy_from_slice(b"EVNET001");
    window[8] = version;
    window[10] = u8::from(row.kind == 3);
    window[11] = row.opcode as u8;
    window[12] = row.status as u8;
    window[14..16].copy_from_slice(&(body.len() as u16).to_le_bytes());
    window[16..20].copy_from_slice(&notice[4..]);
    window[64..64 + body.len()].copy_from_slice(body);
    <[u8; 32]>::from(Sha256::digest(window)) == row.payload
}
fn exchanges(rows: &[Row], opcode: u64, body: &[u8], status: u64) -> Result<bool> {
    let requests: Vec<_> = rows
        .iter()
        .filter(|r| r.kind == 2 && r.opcode == opcode && body_matches(r, body))
        .collect();
    if requests.len() > 1 {
        return Err("negative duplicate semantic request".into());
    }
    let Some(request) = requests.first() else {
        return Ok(false);
    };
    let replies: Vec<_> = rows
        .iter()
        .filter(|r| r.kind == 3 && r.call == request.call && r.request == request.request)
        .collect();
    if replies.is_empty() {
        return Ok(false);
    }
    if replies.len() != 1
        || replies[0].status != status
        || replies[0].sequence <= request.sequence
        || !body_matches(replies[0], &[])
    {
        return Err("negative real request/reply window differs".into());
    }
    Ok(true)
}
pub(super) fn app_denials(rows: &[Row]) -> Result<bool> {
    let rows: Vec<_> = rows.iter().filter(|r| r.kind == 1).collect();
    if rows.len() > 6 {
        return Err("negative extra App denial".into());
    }
    let mut id = None;
    let mut seen = std::collections::BTreeSet::new();
    for row in &rows {
        if id.is_some_and(|who| who != (row.process, row.thread))
            || !seen.insert(row.opcode)
            || row.opcode == syscall::RPC_CALL
                && row.request != u64::from_le_bytes(*b"S\x01\x05\0\x01\0\0\0")
        {
            return Err("negative App probe incarnation or operation differs".into());
        }
        id = Some((row.process, row.thread));
    }
    Ok(seen
        == [syscall::RPC_CALL, 35, 36, 50, 51, 53]
            .into_iter()
            .collect())
}
pub(super) fn destination(rows: &[Row]) -> Result<bool> {
    let arms: Vec<_> = rows.iter().filter(|r| r.kind == 0).collect();
    if arms.len() > 1 || arms.first().is_some_and(|r| r.opcode != 3) {
        return Err("destination unexpected arm".into());
    }
    let Some(arm) = arms.first() else {
        return Ok(false);
    };
    if rows.iter().any(|r| {
        r.kind == 2
            && r.call
                .is_none_or(|call| call.deadline > arm.value || r.tick >= call.deadline)
    }) {
        return Err("destination semantic call escaped original cut".into());
    }
    let denied = exchanges(rows, 5, &[10, 0, 2, 3, 0x90, 0x1f], 2)?
        && exchanges(rows, 5, &[10, 0, 2, 2, 0x91, 0x1f], 2)?
        && exchanges(rows, 3, b"forbidden.invalid", 2)?;
    let allowed = exchanges(rows, 5, &[10, 0, 2, 2, 0x90, 0x1f], 1)?;
    let written = rows
        .iter()
        .any(|r| r.kind == 2 && r.opcode == 6 && body_matches(r, fixture::HELLO));
    let eof = rows
        .iter()
        .any(|r| r.kind == 3 && r.opcode == 7 && r.status == 0 && body_matches(r, &[]));
    Ok(denied && allowed && written && eof)
}
pub(super) fn pending(rows: &[Row]) -> Result<bool> {
    if !exchanges(rows, 5, &[10, 0, 2, 2, 0x90, 0x1f], 1)? {
        return Ok(false);
    }
    let Some(write) = rows
        .iter()
        .find(|r| r.kind == 2 && r.opcode == 6 && body_matches(r, fixture::PENDING))
    else {
        return Ok(false);
    };
    let established = rows.iter().any(|r| {
        r.kind == 3
            && r.opcode == 2
            && r.status == 0
            && r.length == 32
            && r.value.to_le_bytes()[..3] == [1, 1, 4]
            && r.sequence < write.sequence
    });
    let read = rows.iter().any(|r| {
        r.kind == 3
            && r.opcode == 7
            && r.status == 1
            && r.sequence > write.sequence
            && body_matches(r, &[])
    });
    Ok(established && read)
}
pub(super) fn link_loss_scope(rows: &[Row]) -> Result<bool> {
    let arms: Vec<_> = rows.iter().filter(|r| r.kind == 0).collect();
    if arms.len() > 1
        || arms.first().is_some_and(|r| r.opcode != 3)
        || rows.iter().any(|r| matches!(r.kind, 4..=7))
    {
        return Err("linkloss attempted actor stop/cancel or changed original watch".into());
    }
    Ok(arms.len() == 1 && pending(rows)?)
}
pub(super) fn proof(verified: &Verified, goal: Goal) -> Result<Cancelled> {
    if !app_denials(verified.rows())? {
        return Err("negative case lacks all six genuine App denials".into());
    }
    match goal {
        Goal::AppDenial => {
            if verified.rows().iter().any(|r| r.kind == 0) {
                return Err("App-only case performed network watch".into());
            }
            records::without_failure(verified)
        }
        Goal::Destination => {
            if !destination(verified.rows())? {
                return Err("destination case incomplete".into());
            }
            records::without_failure(verified)
        }
        Goal::DriverStop | Goal::ServiceStop => {
            if !pending(verified.rows())? {
                return Err("actual pending window absent before peer stop".into());
            }
            records::captured_failure(verified, if goal == Goal::DriverStop { 7 } else { 8 })
        }
        Goal::LinkLoss => {
            if !link_loss_scope(verified.rows())? {
                return Err("linkloss actual pending scope incomplete".into());
            }
            records::without_failure(verified)
        }
        Goal::Endurance => Err("negative goal is not yet qualified".into()),
    }
}
