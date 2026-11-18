//! Host-only join from actual held-response acceptance and Kernel ReadPending
//! to an owned QMP disconnect, later same-App Note completion and full Finish.
use super::{cases, fixture::Snapshot, records::Row};
use crate::{
    build::Result,
    qmp::{self, Qmp, ReferenceLinkDown},
    session_io::ProbeUi,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
#[derive(Serialize)]
pub(super) struct Capture {
    qmp: ReferenceLinkDown,
    guest_prefix_bytes: usize,
    guest_prefix_lines: usize,
    guest_prefix_sha256: [u8; 32],
    pending_sequence: u64,
    pending_tick: u64,
    app: u64,
    fixture_before: Snapshot,
}
impl Capture {
    pub(super) fn begin(
        serial: &[u8],
        rows: &[Row],
        fixture: &Snapshot,
        app: u64,
        qmp: &mut Qmp,
    ) -> Result<Self> {
        fixture.pending_withheld()?;
        if !cases::link_loss_scope(rows)? {
            return Err("linkloss lacks genuine original-scope TCP/ReadPending".into());
        }
        let pending = rows
            .iter()
            .find(|r| r.kind == 3 && r.opcode == 7 && r.status == 1)
            .ok_or("linkloss actual ReadPending absent")?;
        let prefix = Sha256::digest(serial).into();
        let bytes = serial.len();
        let lines = serial.iter().filter(|b| **b == b'\n').count();
        let proof = qmp.disconnect_reference_nic()?;
        Ok(Self {
            qmp: proof,
            guest_prefix_bytes: bytes,
            guest_prefix_lines: lines,
            guest_prefix_sha256: prefix,
            pending_sequence: pending.sequence,
            pending_tick: pending.tick,
            app,
            fixture_before: fixture.clone(),
        })
    }
    pub(super) fn complete(
        &self,
        serial: &[u8],
        build: &str,
        trace: &[serde_json::Value],
        fixture: &Snapshot,
    ) -> Result<()> {
        fixture.pending_withheld()?;
        let prefix = serial
            .get(..self.guest_prefix_bytes)
            .ok_or("linkloss final serial lost actual pending prefix")?;
        if <[u8; 32]>::from(Sha256::digest(prefix)) != self.guest_prefix_sha256
            || qmp::verify_reference_link_down(trace)? != self.qmp
        {
            return Err("linkloss raw prefix or actual QMP disconnect changed".into());
        }
        let ui = ProbeUi::parse(serial, build)?;
        if ui
            .note_complete(self.app, 3, 2)
            .is_none_or(|line| line < self.guest_prefix_lines)
        {
            return Err(
                "linkloss same-App Note write did not complete after actual disconnect".into(),
            );
        }
        if !crate::network_error_protocol::records(serial, build)?.is_empty()
            || std::str::from_utf8(serial)
                .map_err(|_| "linkloss serial UTF8")?
                .lines()
                .any(|l| l.starts_with("EVROSION_M6_NETWORK_EXIT "))
        {
            return Err("linkloss unexpectedly lost a NIC actor or reported device failure".into());
        }
        Ok(())
    }
}
