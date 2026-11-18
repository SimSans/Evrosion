//! Bounded document engine with caller-owned resident bytes and streamed saves.
//! This model never owns a File capability or claims an actual RPC completion.
//! Native clients must obtain these events from the exact bound endpoint and
//! actual loan/transport state. Model success alone proves no guest durability.
#![no_std]
#![forbid(unsafe_code)]
use sha2::{Digest, Sha256};

pub const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;
pub const CHUNK_BYTES: usize = 4096;
pub type Hash = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bounds,
    Text,
    ReadOnly,
    Busy,
    Uncertain,
    Conflict,
    Exhausted,
    NoChanges,
    WrongPhase,
    Mismatch,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Saved,
    Dirty,
    Saving,
    Readback,
    Uncertain,
    Conflict,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Close {
    Ready,
    ConfirmDiscard,
    RecoveryRequired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Begin,
    Chunks,
    CommitReady,
    CommitSent,
    Verify,
    AbortReady,
    AbortSent,
    Uncertain,
}
/// Describes the immutable proposed bytes, not storage authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub operation: u64,
    pub base_revision: u64,
    pub revision: u64,
    pub length: u64,
    pub digest: Hash,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeginRefusal {
    NoSpace,
    Conflict,
}
/// Historical exact attempt metadata; its bytes remain the local dirty
/// document until the user edits again. This is not a transport receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefusedBegin {
    pub proposal: Proposal,
    pub reason: BeginRefusal,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chunk {
    pub offset: u64,
    pub length: u32,
    pub digest: Hash,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub transfer: u64,
    pub revision: u64,
    pub length: u64,
    pub digest: Hash,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbortRequest {
    pub operation: u64,
    pub transfer: u64,
    pub base_revision: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbortReceipt {
    pub operation: u64,
    pub transfer: u64,
    pub revision: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingInfo {
    pub proposal: Proposal,
    pub phase: Phase,
    pub transfer: u64,
    pub staged: u64,
    pub read_back: u64,
    pub in_flight: Option<Chunk>,
    pub abort_operation: Option<u64>,
}
struct Pending {
    info: PendingInfo,
    verification: Sha256,
    observed_readback: bool,
}
/// The backing is owned by the client for the entire open session. No document
/// sized value or stack array is returned, allocated, or copied by construction.
pub struct Editor<'a> {
    bytes: &'a mut [u8],
    length: usize,
    cursor: usize,
    anchor: usize,
    revision: u64,
    editable: bool,
    dirty: bool,
    edit_sequence: u64,
    last_operation: u64,
    conflict: Option<u64>,
    refused_begin: Option<RefusedBegin>,
    cancelled_save: Option<Proposal>,
    pending: Option<Pending>,
}
fn hash(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}
fn supported(bytes: &[u8]) -> bool {
    core::str::from_utf8(bytes).is_ok_and(|text| {
        text.chars()
            .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
    })
}
impl<'a> Editor<'a> {
    /// Caller must have read and verified this bound File revision first.
    /// Refusal leaves the supplied original bytes unchanged.
    pub fn open(
        bytes: &'a mut [u8],
        length: usize,
        revision: u64,
        editable: bool,
    ) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > MAX_DOCUMENT_BYTES || length > bytes.len() {
            return Err(Error::Bounds);
        }
        if revision == u64::MAX {
            return Err(Error::Exhausted);
        }
        if !supported(&bytes[..length]) {
            return Err(Error::Text);
        }
        Ok(Self {
            bytes,
            length,
            cursor: length,
            anchor: length,
            revision,
            editable,
            dirty: false,
            edit_sequence: 0,
            last_operation: 0,
            conflict: None,
            refused_begin: None,
            cancelled_save: None,
            pending: None,
        })
    }
    pub fn text(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.length]).expect("validated text")
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub const fn cursor(&self) -> usize {
        self.cursor
    }
    pub const fn anchor(&self) -> usize {
        self.anchor
    }
    pub const fn edit_sequence(&self) -> u64 {
        self.edit_sequence
    }
    pub fn status(&self) -> Status {
        match self.pending.as_ref().map(|p| p.info.phase) {
            Some(Phase::Uncertain) => Status::Uncertain,
            Some(Phase::Verify) => Status::Readback,
            Some(_) => Status::Saving,
            None if self.conflicted() => Status::Conflict,
            None if self.dirty => Status::Dirty,
            None => Status::Saved,
        }
    }
    pub fn pending(&self) -> Option<PendingInfo> {
        self.pending.as_ref().map(|p| p.info)
    }
    pub const fn refused_begin(&self) -> Option<RefusedBegin> {
        self.refused_begin
    }
    pub const fn cancelled_save(&self) -> Option<Proposal> {
        self.cancelled_save
    }
    /// Describes only a prepublication point between settled requests. The
    /// native caller must separately check its real FileClient/whole cut.
    pub fn can_cancel_save(&self) -> bool {
        self.pending().is_some_and(|p| {
            matches!(p.phase, Phase::Chunks | Phase::CommitReady)
                && p.transfer != 0
                && p.transfer != u64::MAX
                && p.in_flight.is_none()
                && p.abort_operation.is_none()
        })
    }
    fn conflicted(&self) -> bool {
        self.conflict.is_some()
            || self
                .refused_begin
                .is_some_and(|r| r.reason == BeginRefusal::Conflict)
    }
    pub fn close(&self) -> Close {
        if self.pending.is_some() {
            Close::RecoveryRequired
        } else if self.dirty {
            Close::ConfirmDiscard
        } else {
            Close::Ready
        }
    }
    pub fn selection(&self) -> core::ops::Range<usize> {
        self.cursor.min(self.anchor)..self.cursor.max(self.anchor)
    }
    pub const fn caret(&self) -> usize {
        self.cursor
    }
    pub fn select(&mut self, cursor: usize, anchor: usize) -> Result<(), Error> {
        if cursor > self.length
            || anchor > self.length
            || !self.text().is_char_boundary(cursor)
            || !self.text().is_char_boundary(anchor)
        {
            return Err(Error::Bounds);
        }
        self.cursor = cursor;
        self.anchor = anchor;
        Ok(())
    }
    pub fn select_all(&mut self) {
        self.anchor = 0;
        self.cursor = self.length;
    }
    pub fn left(&mut self, extend: bool) {
        let end = if !extend && self.cursor != self.anchor {
            self.selection().start
        } else {
            self.text()[..self.cursor]
                .char_indices()
                .next_back()
                .map_or(0, |(at, _)| at)
        };
        self.cursor = end;
        if !extend {
            self.anchor = end;
        }
    }
    pub fn right(&mut self, extend: bool) {
        let end = if !extend && self.cursor != self.anchor {
            self.selection().end
        } else {
            self.text()[self.cursor..]
                .chars()
                .next()
                .map_or(self.length, |c| self.cursor + c.len_utf8())
        };
        self.cursor = end;
        if !extend {
            self.anchor = end;
        }
    }
    pub fn line_home(&mut self, extend: bool) {
        self.cursor = self.bytes[..self.cursor]
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(0, |at| at + 1);
        if !extend {
            self.anchor = self.cursor;
        }
    }
    pub fn line_end(&mut self, extend: bool) {
        self.cursor = self.bytes[self.cursor..self.length]
            .iter()
            .position(|b| *b == b'\n')
            .map_or(self.length, |at| self.cursor + at);
        if !extend {
            self.anchor = self.cursor;
        }
    }
    pub fn vertical(&mut self, down: bool, extend: bool) {
        let start = self.bytes[..self.cursor]
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(0, |at| at + 1);
        let column = self.text()[start..self.cursor].chars().count();
        let target = if down {
            self.bytes[self.cursor..self.length]
                .iter()
                .position(|b| *b == b'\n')
                .map(|at| self.cursor + at + 1)
        } else if start == 0 {
            None
        } else {
            Some(
                self.bytes[..start - 1]
                    .iter()
                    .rposition(|b| *b == b'\n')
                    .map_or(0, |at| at + 1),
            )
        };
        if let Some(target) = target {
            let end = self.bytes[target..self.length]
                .iter()
                .position(|b| *b == b'\n')
                .map_or(self.length, |at| target + at);
            self.cursor = self.text()[target..end]
                .char_indices()
                .nth(column)
                .map_or(end, |(at, _)| target + at);
            if !extend {
                self.anchor = self.cursor;
            }
        }
    }
    fn mutable(&self) -> Result<(), Error> {
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.info.phase == Phase::Uncertain)
        {
            return Err(Error::Uncertain);
        }
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        if !self.editable {
            return Err(Error::ReadOnly);
        }
        Ok(())
    }
    /// Atomic bounded replacement; data and selection survive failed input.
    pub fn replace(&mut self, inserted: &[u8]) -> Result<bool, Error> {
        self.mutable()?;
        if !supported(inserted) {
            return Err(Error::Text);
        }
        let selected = self.selection();
        let length = self.length - selected.len();
        let length = length.checked_add(inserted.len()).ok_or(Error::Bounds)?;
        if length > self.bytes.len() {
            return Err(Error::Bounds);
        }
        if self.bytes[selected.clone()] == *inserted {
            self.cursor = selected.start + inserted.len();
            self.anchor = self.cursor;
            return Ok(false);
        }
        if self.edit_sequence == u64::MAX {
            return Err(Error::Exhausted);
        }
        self.bytes
            .copy_within(selected.end..self.length, selected.start + inserted.len());
        self.bytes[selected.start..selected.start + inserted.len()].copy_from_slice(inserted);
        if length < self.length {
            self.bytes[length..self.length].fill(0);
        }
        self.length = length;
        self.cursor = selected.start + inserted.len();
        self.anchor = self.cursor;
        self.edit_sequence += 1;
        self.dirty = true;
        Ok(true)
    }
    pub fn backspace(&mut self) -> Result<bool, Error> {
        self.mutable()?;
        if self.edit_sequence == u64::MAX {
            return Err(Error::Exhausted);
        }
        if self.selection().is_empty() {
            if self.cursor == 0 {
                return Ok(false);
            }
            self.anchor = self.text()[..self.cursor]
                .char_indices()
                .next_back()
                .map_or(0, |(at, _)| at);
        }
        self.replace(&[])
    }
    /// Bounded UTF8 range for rendering or semantic consumers. Ranges start at a
    /// scalar boundary and never truncate a scalar to fit the caller buffer.
    pub fn range(&self, start: usize, out: &mut [u8]) -> Result<usize, Error> {
        if start > self.length || !self.text().is_char_boundary(start) {
            return Err(Error::Bounds);
        }
        let mut end = self.length.min(start.saturating_add(out.len()));
        while !self.text().is_char_boundary(end) {
            end -= 1;
        }
        out[..end - start].copy_from_slice(&self.bytes[start..end]);
        Ok(end - start)
    }
    pub fn notify_revision(&mut self, revision: u64) -> Result<(), Error> {
        if revision < self.revision || revision == u64::MAX {
            return Err(Error::Mismatch);
        }
        if revision != self.revision && self.pending.is_none() {
            self.conflict = Some(revision);
        }
        Ok(())
    }
    pub fn revoke_edit(&mut self) {
        self.editable = false;
        if self.pending.is_some() {
            self.mark_uncertain();
        }
    }
    /// Keep the resident document for Save As on an independently authorized,
    /// newly bound destination route. The native owner must first release and
    /// retire the old route and verify the new destination's revision and edit
    /// grant. This method neither grants access nor clears accepted work.
    pub fn retarget_for_save(
        &mut self,
        destination_revision: u64,
        destination_writable: bool,
    ) -> Result<(), Error> {
        if let Some(pending) = self.pending.as_ref() {
            return Err(if pending.info.phase == Phase::Uncertain {
                Error::Uncertain
            } else {
                Error::Busy
            });
        }
        if !destination_writable {
            return Err(Error::ReadOnly);
        }
        if destination_revision >= u64::MAX - 1 {
            return Err(Error::Exhausted);
        }
        self.revision = destination_revision;
        self.editable = true;
        self.dirty = true;
        self.conflict = None;
        self.refused_begin = None;
        self.cancelled_save = None;
        // Operation IDs belong to the new actual route, whose client starts a
        // new counter. Reconstructing a client on the old route is forbidden.
        self.last_operation = 0;
        Ok(())
    }
    pub fn begin_save(&mut self, operation: u64) -> Result<Proposal, Error> {
        self.mutable()?;
        if self.conflicted() {
            return Err(Error::Conflict);
        }
        if !self.dirty {
            return Err(Error::NoChanges);
        }
        if operation == 0 || operation <= self.last_operation || operation == u64::MAX {
            return Err(Error::Exhausted);
        }
        let revision = self
            .revision
            .checked_add(1)
            .filter(|n| *n != u64::MAX)
            .ok_or(Error::Exhausted)?;
        let proposal = Proposal {
            operation,
            base_revision: self.revision,
            revision,
            length: self.length as u64,
            digest: hash(self.bytes()),
        };
        self.last_operation = operation;
        self.refused_begin = None;
        self.cancelled_save = None;
        self.pending = Some(Pending {
            info: PendingInfo {
                proposal,
                phase: Phase::Begin,
                transfer: 0,
                staged: 0,
                read_back: 0,
                in_flight: None,
                abort_operation: None,
            },
            verification: Sha256::new(),
            observed_readback: false,
        });
        Ok(proposal)
    }
    fn uncertain<T>(&mut self, error: Error) -> Result<T, Error> {
        self.mark_uncertain();
        Err(error)
    }
    pub fn begin_confirmed(
        &mut self,
        transfer: u64,
        length: u64,
        digest: Hash,
    ) -> Result<(), Error> {
        let info = self.pending().ok_or(Error::WrongPhase)?;
        if info.phase != Phase::Begin {
            return Err(Error::WrongPhase);
        }
        if transfer == 0
            || transfer == u64::MAX
            || length != info.proposal.length
            || digest != info.proposal.digest
        {
            return self.uncertain(Error::Mismatch);
        }
        let p = self.pending.as_mut().unwrap();
        p.info.transfer = transfer;
        p.info.phase = if length == 0 {
            Phase::CommitReady
        } else {
            Phase::Chunks
        };
        Ok(())
    }
    pub fn next_chunk(&mut self, out: &mut [u8]) -> Result<Chunk, Error> {
        let info = self.pending().ok_or(Error::WrongPhase)?;
        if info.phase != Phase::Chunks {
            return Err(Error::WrongPhase);
        }
        if info.in_flight.is_some() {
            return Err(Error::Busy);
        }
        // A wire chunk may contain partial UTF8; only the complete file is text.
        let start = usize::try_from(info.staged).map_err(|_| Error::Bounds)?;
        let length = (self.length - start).min(CHUNK_BYTES);
        if length == 0 || out.len() < length {
            return Err(Error::Bounds);
        }
        out[..length].copy_from_slice(&self.bytes[start..start + length]);
        let chunk = Chunk {
            offset: start as u64,
            length: length as u32,
            digest: hash(&out[..length]),
        };
        self.pending.as_mut().unwrap().info.in_flight = Some(chunk);
        Ok(chunk)
    }
    pub fn chunk_confirmed(&mut self, transfer: u64, chunk: Chunk) -> Result<(), Error> {
        let info = self.pending().ok_or(Error::WrongPhase)?;
        if info.phase != Phase::Chunks {
            return Err(Error::WrongPhase);
        }
        if info.transfer != transfer || info.in_flight != Some(chunk) {
            return self.uncertain(Error::Mismatch);
        }
        let p = self.pending.as_mut().unwrap();
        p.info.staged += u64::from(chunk.length);
        p.info.in_flight = None;
        if p.info.staged == p.info.proposal.length {
            p.info.phase = Phase::CommitReady;
        }
        Ok(())
    }
    pub fn commit_request(&mut self) -> Result<Proposal, Error> {
        let p = self.pending.as_mut().ok_or(Error::WrongPhase)?;
        if p.info.phase != Phase::CommitReady {
            return Err(Error::WrongPhase);
        }
        p.info.phase = Phase::CommitSent;
        Ok(p.info.proposal)
    }
    /// Explicit owner action, never automatic cleanup after a failed request.
    /// The exact proposal remains frozen until a successful actual Abort.
    pub fn cancel_save(&mut self, proposal: Proposal) -> Result<(), Error> {
        let info = self.pending().ok_or(Error::WrongPhase)?;
        if !self.can_cancel_save() {
            return Err(Error::WrongPhase);
        }
        if info.proposal != proposal {
            return Err(Error::Mismatch);
        }
        self.pending.as_mut().unwrap().info.phase = Phase::AbortReady;
        Ok(())
    }
    /// The native owner obtains this distinct nonce from the same live client
    /// and uses the unchanged whole-transfer cut for the one actual Abort.
    pub fn abort_request(&mut self, operation: u64) -> Result<AbortRequest, Error> {
        let info = self.pending().ok_or(Error::WrongPhase)?;
        if info.phase != Phase::AbortReady || info.abort_operation.is_some() {
            return Err(Error::WrongPhase);
        }
        if operation == 0 || operation <= self.last_operation || operation == u64::MAX {
            return Err(Error::Exhausted);
        }
        let request = AbortRequest {
            operation,
            transfer: info.transfer,
            base_revision: info.proposal.base_revision,
        };
        self.last_operation = operation;
        let pending = self.pending.as_mut().unwrap();
        pending.info.abort_operation = Some(operation);
        pending.info.phase = Phase::AbortSent;
        Ok(request)
    }
    /// Only an exact successful Abort, with the real request/loan settled,
    /// removes an accepted stage. Refusal/timeout uses mark_uncertain instead.
    pub fn abort_confirmed(&mut self, receipt: AbortReceipt) -> Result<(), Error> {
        let info = self.pending().ok_or(Error::WrongPhase)?;
        if info.phase != Phase::AbortSent {
            return Err(Error::WrongPhase);
        }
        if info.abort_operation != Some(receipt.operation)
            || info.transfer != receipt.transfer
            || info.proposal.base_revision != receipt.revision
        {
            return self.uncertain(Error::Mismatch);
        }
        self.cancelled_save = Some(info.proposal);
        self.pending = None;
        Ok(())
    }
    pub fn commit_confirmed(&mut self, receipt: Receipt) -> Result<(), Error> {
        let info = self.pending().ok_or(Error::WrongPhase)?;
        if info.phase != Phase::CommitSent {
            return Err(Error::WrongPhase);
        }
        if receipt
            != (Receipt {
                transfer: info.transfer,
                revision: info.proposal.revision,
                length: info.proposal.length,
                digest: info.proposal.digest,
            })
        {
            return self.uncertain(Error::Mismatch);
        }
        self.pending.as_mut().unwrap().info.phase = Phase::Verify;
        Ok(())
    }
    pub fn readback(&mut self, revision: u64, offset: u64, bytes: &[u8]) -> Result<(), Error> {
        let info = self.pending().ok_or(Error::WrongPhase)?;
        if info.phase != Phase::Verify {
            return Err(Error::WrongPhase);
        }
        let Some(end) = offset.checked_add(bytes.len() as u64) else {
            return self.uncertain(Error::Mismatch);
        };
        if revision != info.proposal.revision
            || offset != info.read_back
            || end > info.proposal.length
            || bytes.len() > CHUNK_BYTES
            || (bytes.is_empty() && info.proposal.length != 0)
        {
            return self.uncertain(Error::Mismatch);
        }
        let start = usize::try_from(offset).map_err(|_| Error::Bounds)?;
        if self.bytes[start..start + bytes.len()] != *bytes {
            return self.uncertain(Error::Mismatch);
        }
        let p = self.pending.as_mut().unwrap();
        p.verification.update(bytes);
        p.info.read_back = end;
        p.observed_readback = true;
        Ok(())
    }
    pub fn finish_readback(&mut self) -> Result<(), Error> {
        let p = self.pending.as_ref().ok_or(Error::WrongPhase)?;
        if p.info.phase != Phase::Verify {
            return Err(Error::WrongPhase);
        }
        if !p.observed_readback || p.info.read_back != p.info.proposal.length {
            return Err(Error::Busy);
        }
        if <Hash>::from(p.verification.clone().finalize()) != p.info.proposal.digest {
            return self.uncertain(Error::Mismatch);
        }
        self.revision = p.info.proposal.revision;
        self.dirty = false;
        self.conflict = None;
        self.pending = None;
        Ok(())
    }
    /// Actual client must fence the loan/accepted work. This state keeps the
    /// original proposal and disallows any new edit/Save/automatic retry.
    pub fn mark_uncertain(&mut self) {
        if let Some(p) = self.pending.as_mut() {
            p.info.phase = Phase::Uncertain;
        }
    }
    /// May be called ONLY for a transport-proven pre-delivery rejection with
    /// the exact loan returned. Accepted/unknown failures use mark_uncertain.
    pub fn rejected_before_delivery(&mut self) -> Result<(), Error> {
        if !self
            .pending
            .as_ref()
            .is_some_and(|p| p.info.phase == Phase::Begin && p.info.transfer == 0)
        {
            return Err(Error::WrongPhase);
        }
        self.pending = None;
        Ok(())
    }
    /// Native owner must have received an exact correlated NoSpace/Conflict
    /// Begin response and recovered its actual control loan. Unlike transport
    /// nondelivery, this request was delivered and its operation stays consumed.
    /// A later-phase refusal cannot prove that an existing stage was aborted.
    pub fn begin_refused(&mut self, proposal: Proposal, reason: BeginRefusal) -> Result<(), Error> {
        let info = self.pending().ok_or(Error::WrongPhase)?;
        if info.phase != Phase::Begin
            || info.transfer != 0
            || info.staged != 0
            || info.read_back != 0
            || info.in_flight.is_some()
            || info.abort_operation.is_some()
        {
            return Err(Error::WrongPhase);
        }
        if info.proposal != proposal {
            return Err(Error::Mismatch);
        }
        self.refused_begin = Some(RefusedBegin { proposal, reason });
        self.pending = None;
        Ok(())
    }
}

#[cfg(test)]
mod cancellation_tests;
#[cfg(test)]
mod tests;
