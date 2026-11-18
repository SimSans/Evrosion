//! Local authenticated content to the actual image boundary. This continuation
//! owns no Backend, byte buffer, package borrow or authority to accept updates.
#![forbid(unsafe_code)]
use crate::{
    native_acquisition::{Buffers, Content},
    native_image::{Images, Io},
    native_sources::{Downloaded, Member},
    native_update::Update,
};
use ev_content_store::Backend;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    State,
    Content,
    Storage,
    Image,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Select,
    BeginRead,
    Read,
    BeginImage,
    Write,
    FinishRead,
    DrainRejected,
    FinishRejected,
    Seal,
    Verify,
    Associate,
    Register,
    Done,
    Failed,
}
#[derive(Clone, Copy)]
enum Row {
    Pending(Content),
    Rejected(Content),
    Registered(Member),
}
impl Row {
    fn content(self) -> Content {
        match self {
            Self::Pending(content) | Self::Rejected(content) => content,
            Self::Registered(member) => member.content(),
        }
    }
}
/// Exactly the already-defined two permanent image slots. A provisional row
/// cannot be exposed as a resolver binding before complete association/Register.
pub struct Loader {
    phase: Phase,
    member: usize,
    current: usize,
    slot: Option<usize>,
    chunk: usize,
    optional: bool,
    bindings: [Option<Row>; 2],
}
impl Default for Loader {
    fn default() -> Self {
        Self::new()
    }
}
impl Loader {
    pub const fn new() -> Self {
        Self {
            phase: Phase::Select,
            member: 0,
            current: 0,
            slot: None,
            chunk: 0,
            optional: false,
            bindings: [None; 2],
        }
    }
    pub fn bindings(&self) -> Option<[Option<(usize, Content)>; 2]> {
        Some(
            self.members()?
                .map(|m| m.map(|m| (m.kernel_slot(), m.content()))),
        )
    }
    pub fn members(&self) -> Option<[Option<Member>; 2]> {
        if self.phase != Phase::Done {
            return None;
        }
        let mut completed = [None; 2];
        for (out, entry) in completed.iter_mut().zip(self.bindings) {
            if let Some(entry) = entry {
                *out = match entry {
                    Row::Registered(member) => Some(member),
                    Row::Rejected(_) => None,
                    Row::Pending(_) => return None,
                };
            }
        }
        Some(completed)
    }
    /// Add a newly registered local reader after remote durability/association.
    /// This carries no selected/KnownGood transition; the caller must retain
    /// those durable references separately before replacing a candidate.
    pub fn adopt<T: Io>(&mut self, images: &Images<T>, member: Member) -> Result<(), Error> {
        let empty = self.phase == Phase::Select
            && self.member == 0
            && self.slot.is_none()
            && self.bindings.iter().all(Option::is_none);
        if self.phase != Phase::Done && !empty {
            return Err(Error::State);
        }
        member.check(images).map_err(|_| Error::Content)?;
        let index = member.slot().index();
        if let Some(row) = self.bindings[index]
            && !matches!(row, Row::Registered(old) if old == member)
        {
            return Err(Error::Content);
        }
        self.bindings[index] = Some(Row::Registered(member));
        self.phase = Phase::Done;
        Ok(())
    }
    pub fn failed(&self) -> bool {
        self.phase == Phase::Failed
    }
    /// One real IO/image/verification phase. The caller freshly observes time
    /// before and after each step, and retains this same private4KiB chunk.
    #[inline(never)]
    pub fn step<B: Backend, T: Io>(
        &mut self,
        update: &mut Update<B>,
        images: &mut Images<T>,
        buffers: &mut Buffers,
        now: u64,
    ) -> Result<bool, Error> {
        let result = self.body(update, images, buffers, now);
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }
    #[inline(never)]
    fn body<B: Backend, T: Io>(
        &mut self,
        update: &mut Update<B>,
        images: &mut Images<T>,
        buffers: &mut Buffers,
        now: u64,
    ) -> Result<bool, Error> {
        update.observe_after(now);
        if self.phase == Phase::Failed
            || !matches!(
                update.outcome(),
                Some(crate::native_update::Outcome::Complete(_))
            )
            || update.original_cut().is_none_or(|cut| now >= cut)
            || now == u64::MAX
        {
            return Err(Error::State);
        }
        if self.phase == Phase::Done {
            return Ok(true);
        }
        match self.phase {
            Phase::Select => {
                let snapshot = update.retained_snapshot().ok_or(Error::State)?;
                let members = [
                    snapshot.candidate(),
                    snapshot.active(),
                    snapshot.known_good(),
                ];
                let Some(content) = members.get(self.member).copied() else {
                    self.phase = Phase::Done;
                    return Ok(true);
                };
                let Some(content) = content else {
                    self.member += 1;
                    return Ok(false);
                };
                self.current = match content.version {
                    2 => 0,
                    3 => 1,
                    _ => return Err(Error::Content),
                };
                if let Some(previous) = self.bindings[self.current] {
                    if previous.content() != content {
                        return Err(Error::Content);
                    }
                    self.member += 1;
                    return Ok(false);
                }
                // An absent actual slot is private pending metadata, never a
                // fabricated Kernel identity or an exposed resolver binding.
                self.bindings[self.current] = Some(Row::Pending(content));
                self.optional = snapshot.candidate() == Some(content)
                    && snapshot.active() != Some(content)
                    && snapshot.known_good() != Some(content);
                self.slot = None;
                self.phase = Phase::BeginRead;
            }
            Phase::BeginRead => {
                update
                    .begin_retained_read(self.content()?, now)
                    .map_err(|_| Error::Storage)?;
                self.phase = Phase::Read;
            }
            Phase::Read => {
                self.chunk = update
                    .read_retained_chunk(&mut buffers.chunk, now)
                    .map_err(|_| Error::Storage)?;
                if self.chunk == 0 || self.chunk > 4096 {
                    return Err(Error::Storage);
                }
                self.phase = if self.slot.is_none() {
                    Phase::BeginImage
                } else {
                    Phase::Write
                };
            }
            Phase::BeginImage => {
                let header = match crate::native_image::request_from_prefix(
                    &buffers.chunk[..self.chunk],
                    self.content()?,
                ) {
                    Ok(header) => header,
                    Err(crate::native_image::Error::Package) if self.optional => {
                        // A syntax refusal does not finish the affine reader.
                        // Drain and authenticate the whole object before any
                        // independent member or Backend can become usable.
                        self.phase = if update.retained_remaining() == Some(0) {
                            Phase::FinishRejected
                        } else {
                            Phase::DrainRejected
                        };
                        return Ok(false);
                    }
                    Err(_) => return Err(Error::Content),
                };
                self.slot = Some(
                    images
                        .begin(header, now, update.original_cut().ok_or(Error::State)?)
                        .map_err(|_| Error::Image)?,
                );
                self.phase = Phase::Write;
            }
            Phase::Write => {
                images
                    .write_chunk(
                        self.slot.ok_or(Error::State)?,
                        now,
                        &buffers.chunk[..self.chunk],
                    )
                    .map_err(|_| Error::Image)?;
                self.phase = if update.retained_remaining() == Some(0) {
                    Phase::FinishRead
                } else {
                    Phase::Read
                };
            }
            Phase::FinishRead => {
                update
                    .finish_retained_read(now)
                    .map_err(|_| Error::Storage)?;
                self.phase = Phase::Seal;
            }
            Phase::DrainRejected => {
                let n = update
                    .read_retained_chunk(&mut buffers.chunk, now)
                    .map_err(|_| Error::Storage)?;
                if n == 0 || n > 4096 {
                    return Err(Error::Storage);
                }
                if update.retained_remaining() == Some(0) {
                    self.phase = Phase::FinishRejected;
                }
            }
            Phase::FinishRejected => {
                update
                    .finish_retained_read(now)
                    .map_err(|_| Error::Storage)?;
                self.reject_optional(update)?;
            }
            Phase::Seal => {
                images
                    .seal(self.slot.ok_or(Error::State)?, now)
                    .map_err(|_| Error::Image)?;
                self.phase = Phase::Verify;
            }
            Phase::Verify => {
                if images
                    .verify_step(self.slot.ok_or(Error::State)?, now)
                    .map_err(|_| Error::Image)?
                {
                    self.phase = Phase::Associate;
                }
            }
            Phase::Associate => {
                match Downloaded::from_images(
                    images,
                    self.slot.ok_or(Error::State)?,
                    update.retained_snapshot().ok_or(Error::State)?,
                    self.content()?,
                ) {
                    Ok(_) => self.phase = Phase::Register,
                    Err(
                        crate::native_sources::Error::Package
                        | crate::native_sources::Error::Schema
                        | crate::native_sources::Error::Contracts,
                    ) if self.optional => self.reject_optional(update)?,
                    Err(_) => return Err(Error::Content),
                }
            }
            Phase::Register => {
                let slot = self.slot.ok_or(Error::State)?;
                images.register(slot, now).map_err(|_| Error::Image)?;
                let member = Member::capture(
                    images,
                    slot,
                    update.retained_snapshot().ok_or(Error::State)?,
                    self.content()?,
                )
                .map_err(|_| Error::Content)?;
                self.bindings[self.current] = Some(Row::Registered(member));
                self.member += 1;
                self.phase = Phase::Select;
            }
            Phase::Done | Phase::Failed => return Err(Error::State),
        }
        Ok(false)
    }
    fn content(&self) -> Result<Content, Error> {
        self.bindings[self.current]
            .map(Row::content)
            .ok_or(Error::State)
    }
    fn reject_optional<B: Backend>(&mut self, update: &Update<B>) -> Result<(), Error> {
        let content = self.content()?;
        let snapshot = update.retained_snapshot().ok_or(Error::State)?;
        if !self.optional
            || snapshot.candidate() != Some(content)
            || snapshot.active() == Some(content)
            || snapshot.known_good() == Some(content)
        {
            return Err(Error::Content);
        }
        // Keep authenticated metadata and any permanent sealed reader. The
        // rejected member grants no resolver/Register/start authority; its
        // actual Kernel slot remains owned until ordinary Root retirement.
        self.bindings[self.current] = Some(Row::Rejected(content));
        self.member += 1;
        self.phase = Phase::Select;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn adopting_local_identity_never_discards_pending_or_failed_cold_work() {
        let mut images = crate::native_sources::tests::sealed_images(false);
        images.register(0, 100).unwrap();
        let snapshot = crate::native_acquisition::tests::retained_snapshot(false);
        let content = snapshot.candidate().unwrap();
        let member = Member::capture(&images, 0, &snapshot, content).unwrap();
        for phase in [Phase::BeginRead, Phase::Read, Phase::Failed] {
            let mut loader = Loader::new();
            loader.phase = phase;
            loader.bindings[0] = Some(Row::Pending(content));
            assert_eq!(loader.adopt(&images, member), Err(Error::State));
            assert!(loader.members().is_none());
            assert!(matches!(loader.bindings[0], Some(Row::Pending(c)) if c==content));
        }
    }
}
