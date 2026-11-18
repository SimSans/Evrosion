//! Fixed local-development target acquisition. One caller-owned chunk and the
//! existing Update IO owner; no clock, publisher, activation or health authority.
#![forbid(unsafe_code)]
use crate::{
    native_acquisition::{self as acq, Buffers, Content, Material, Remote},
    native_image::{Images, Io},
    native_network::{
        client::Client,
        download::{Download, Event as DownloadEvent, Expectation, Path},
    },
    native_update::{self as update, Update},
};
use ev_content_store::{Backend, Object};
use ev_net_driver::{protocol::Window, pump::Transport};
use ev_release_trust::{metadata as md, signature::Envelope};
use ev_userspace_contract::root_v4::catalogue::NetworkPolicy;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    State,
    Clock,
    Storage,
    Transport,
    Metadata,
    Image,
    Time,
    Authorization,
    Selection,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Working,
    NeedTime,
    NeedPreparation,
    NeedAuthorization,
    Published { slot: usize },
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    New,
    Inspect,
    RootBegin,
    RootRead,
    RootFinish,
    DownloadBegin,
    Download,
    ArtifactReserve,
    HeaderAck,
    MetadataReserve,
    MetadataWrite,
    SealObject,
    ReadObject,
    ImageBegin,
    ImageWrite,
    FinishObject,
    ParseMetadata,
    SealImage,
    VerifyImage,
    NeedPreparationTime,
    WaitingPreparationTime,
    Prepare,
    NeedTime,
    WaitingTime,
    Authorize,
    Commit,
    Associate,
    Register,
    Done,
    Failed,
}
pub struct Fetch {
    phase: Phase,
    download: Download,
    file: usize,
    expected: Expectation,
    lengths: [usize; 3],
    objects: [Option<Object>; 4],
    root: Option<Object>,
    offset: usize,
    chunk: usize,
    hash: [u8; 32],
    preparation: Option<acq::Preparation>,
    selected: Option<(crate::native_sources::Source, [u8; 32])>,
    image: Option<usize>,
    image_cut: u64,
    reused: bool,
    last: u64,
}
impl Default for Fetch {
    fn default() -> Self {
        Self::new()
    }
}
impl Fetch {
    pub const fn new() -> Self {
        Self {
            phase: Phase::New,
            download: Download::new(),
            file: 0,
            expected: Expectation::Bounded,
            lengths: [0; 3],
            objects: [None; 4],
            root: None,
            offset: 0,
            chunk: 0,
            hash: [0; 32],
            preparation: None,
            selected: None,
            image: None,
            image_cut: 0,
            reused: false,
            last: 0,
        }
    }
    /// One owner operation only; a later explicit command constructs a new
    /// continuation after actual settlement, never resets accepted work.
    pub fn begin(
        &mut self,
        now: u64,
        selected: Option<(crate::native_sources::Source, [u8; 32])>,
    ) -> Result<(), Error> {
        if self.phase != Phase::New || now == u64::MAX {
            return Err(Error::State);
        }
        self.last = now;
        self.selected = selected;
        self.phase = Phase::Inspect;
        Ok(())
    }
    #[cfg(feature = "native-owner-ui")]
    pub fn checking(&self) -> bool {
        !matches!(
            self.phase,
            Phase::New
                | Phase::Inspect
                | Phase::RootBegin
                | Phase::RootRead
                | Phase::RootFinish
                | Phase::DownloadBegin
                | Phase::Download
                | Phase::HeaderAck
        )
    }
    pub fn failed(&self) -> bool {
        self.phase == Phase::Failed
    }
    pub fn waiting_time(&self) -> bool {
        matches!(
            self.phase,
            Phase::WaitingTime | Phase::WaitingPreparationTime
        )
    }
    pub fn time_armed(&mut self) -> Result<(), Error> {
        self.phase = match self.phase {
            Phase::NeedPreparationTime => Phase::WaitingPreparationTime,
            Phase::NeedTime => Phase::WaitingTime,
            _ => return Err(Error::State),
        };
        Ok(())
    }
    pub fn time_finished(&mut self) -> Result<(), Error> {
        self.phase = match self.phase {
            Phase::WaitingPreparationTime => Phase::Prepare,
            Phase::WaitingTime => Phase::Authorize,
            _ => return Err(Error::State),
        };
        Ok(())
    }
    pub fn preparation_input<'a>(
        &self,
        b: &'a Buffers,
    ) -> Result<(&'a [u8], ev_release_trust::verifier::Bundle<'a>), Error> {
        if self.phase != Phase::Prepare {
            return Err(Error::State);
        }
        Ok((
            &b.root[..self.root.ok_or(Error::State)?.length() as usize],
            ev_release_trust::verifier::Bundle {
                targets: &b.targets[..self.lengths[2]],
                snapshot: &b.snapshot[..self.lengths[1]],
                timestamp: &b.timestamp[..self.lengths[0]],
            },
        ))
    }
    pub fn prepared<B: Backend>(
        &mut self,
        preparation: acq::Preparation,
        engine: &Update<B>,
    ) -> Result<(), Error> {
        if self.phase != Phase::Prepare
            || engine
                .authorization_store()
                .and_then(|s| s.authorization_binding())
                != Some(preparation.prior())
        {
            return Err(Error::State);
        }
        let target = preparation.target();
        // Before replacing the only candidate, a downloaded Registry selection
        // must already have its honest durable active retention. Never fakeKG
        // or accept C that would orphan selected B on the next cold boot.
        if let Some((crate::native_sources::Source::Downloaded(_), selected)) = self.selected
            && selected != target.sha256
            && engine
                .authorization_store()
                .and_then(|s| s.snapshot())
                .and_then(|s| s.active())
                .is_none_or(|c| c.package != selected)
        {
            return Err(Error::Selection);
        }
        for (file, index) in [(0, 2), (1, 1), (2, 0)] {
            if preparation
                .metadata(index)
                .is_none_or(|m| m.length != self.lengths[file] as u64)
            {
                return Err(Error::Metadata);
            }
        }
        self.preparation = Some(preparation);
        self.file = 0;
        self.phase = Phase::MetadataReserve;
        Ok(())
    }
    pub fn decision_started(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Authorize {
            return Err(Error::State);
        }
        self.phase = Phase::Commit;
        Ok(())
    }
    pub fn refuse(&mut self) {
        self.phase = Phase::Failed;
    }
    pub fn published_content(&self) -> Result<Content, Error> {
        if self.phase != Phase::Done {
            return Err(Error::State);
        }
        self.content(self.objects[3].ok_or(Error::State)?)
    }
    /// Slices are private complete metadata and actual sealed RO bytes. This
    /// creates no decision; only the actual Store-bound private clock may do so.
    pub fn remote<'a, T: Io>(
        &self,
        b: &'a Buffers,
        images: &'a Images<T>,
    ) -> Result<Remote<'a>, Error> {
        if self.phase != Phase::Authorize {
            return Err(Error::State);
        }
        let root = self.root.ok_or(Error::State)?;
        Ok(Remote {
            current_root: b
                .root
                .get(..root.length() as usize)
                .ok_or(Error::Metadata)?,
            root_updates: &[],
            metadata: [
                Material {
                    object: self.objects[2].ok_or(Error::State)?,
                    bytes: &b.targets[..self.lengths[2]],
                },
                Material {
                    object: self.objects[1].ok_or(Error::State)?,
                    bytes: &b.snapshot[..self.lengths[1]],
                },
                Material {
                    object: self.objects[0].ok_or(Error::State)?,
                    bytes: &b.timestamp[..self.lengths[0]],
                },
            ],
            candidate: Material {
                object: self.objects[3].ok_or(Error::State)?,
                bytes: images
                    .bytes(self.image.ok_or(Error::State)?)
                    .map_err(|_| Error::Image)?,
            },
        })
    }
    #[inline(never)]
    pub fn step<B: Backend, W: Window, T: Transport, I: Io>(
        &mut self,
        engine: &mut Update<B>,
        client: &mut Client<W, T>,
        scope: NetworkPolicy<'_>,
        images: &mut Images<I>,
        b: &mut Buffers,
        now: u64,
    ) -> Result<Event, Error> {
        let result = self.body(engine, client, scope, images, b, now);
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }
    #[inline(never)]
    fn body<B: Backend, W: Window, T: Transport, I: Io>(
        &mut self,
        engine: &mut Update<B>,
        client: &mut Client<W, T>,
        scope: NetworkPolicy<'_>,
        images: &mut Images<I>,
        b: &mut Buffers,
        now: u64,
    ) -> Result<Event, Error> {
        engine.observe_after(now);
        if matches!(engine.outcome(), Some(update::Outcome::Failed(_))) {
            return Err(Error::Storage);
        }
        if now == u64::MAX || now < self.last || engine.original_cut().is_none_or(|cut| now >= cut)
        {
            return Err(Error::Clock);
        }
        self.last = now;
        if self.phase == Phase::Failed || self.phase == Phase::New || client.quarantined() {
            return Err(Error::State);
        }
        match self.phase {
            Phase::Inspect => {
                if engine.active() {
                    engine.step(b, now);
                }
                match engine.outcome() {
                    Some(update::Outcome::Complete(_)) => self.phase = Phase::RootBegin,
                    None => (),
                    _ => return Err(Error::Storage),
                }
            }
            Phase::RootBegin => {
                let root = engine
                    .begin_fetch_root_read(now)
                    .map_err(|_| Error::Storage)?;
                if root.length() as usize > b.root.len() {
                    return Err(Error::Metadata);
                }
                self.root = Some(root);
                self.offset = 0;
                self.phase = Phase::RootRead;
            }
            Phase::RootRead => {
                let n = engine
                    .read_retained_chunk(&mut b.chunk, now)
                    .map_err(|_| Error::Storage)?;
                let end = self.offset.checked_add(n).ok_or(Error::Metadata)?;
                b.root
                    .get_mut(self.offset..end)
                    .ok_or(Error::Metadata)?
                    .copy_from_slice(&b.chunk[..n]);
                self.offset = end;
                if engine.retained_remaining() == Some(0) {
                    self.phase = Phase::RootFinish;
                }
            }
            Phase::RootFinish => {
                if Some(
                    engine
                        .finish_fetch_object(now)
                        .map_err(|_| Error::Storage)?,
                ) != self.root
                {
                    return Err(Error::Metadata);
                }
                self.file = 0;
                self.expected = Expectation::Bounded;
                self.phase = Phase::DownloadBegin;
            }
            Phase::DownloadBegin => {
                let cut = now
                    .checked_add(crate::native_network::download::MAX_DOWNLOAD_TICKS)
                    .ok_or(Error::Clock)?
                    .min(engine.original_cut().ok_or(Error::Clock)?);
                // Previous object returned Complete only after actual EOF,
                // consumed chunks and actual TCPClosed. Client history persists.
                self.download = Download::new();
                self.download
                    .begin(self.path(), self.expected, now, cut)
                    .map_err(|_| Error::Transport)?;
                self.offset = 0;
                self.phase = Phase::Download;
            }
            Phase::Download => match self
                .download
                .step(client, scope, now, &mut b.chunk)
                .map_err(|_| Error::Transport)?
            {
                DownloadEvent::Waiting => (),
                DownloadEvent::Headers { length } => {
                    if self.file < 3 {
                        if length as usize > self.metadata(b)?.len() {
                            return Err(Error::Metadata);
                        }
                        self.lengths[self.file] = length as usize;
                        self.phase = Phase::HeaderAck;
                    } else {
                        self.phase = Phase::ArtifactReserve;
                    }
                }
                DownloadEvent::Chunk { offset, length } => {
                    if offset != self.offset as u64 || length == 0 {
                        return Err(Error::Metadata);
                    }
                    if self.file < 3 {
                        let end = self.offset.checked_add(length).ok_or(Error::Metadata)?;
                        let chunk = &b.chunk[..length];
                        match self.file {
                            0 => b.timestamp.get_mut(self.offset..end),
                            1 => b.snapshot.get_mut(self.offset..end),
                            2 => b.targets.get_mut(self.offset..end),
                            _ => None,
                        }
                        .ok_or(Error::Metadata)?
                        .copy_from_slice(chunk);
                    } else {
                        engine
                            .write_fetch_chunk(&b.chunk[..length], now)
                            .map_err(|_| Error::Storage)?;
                    }
                    self.download
                        .consume_chunk(&b.chunk, now)
                        .map_err(|_| Error::Transport)?;
                    self.offset += length;
                }
                DownloadEvent::Complete { length, sha256 } => {
                    if length != self.offset as u64 {
                        return Err(Error::Metadata);
                    }
                    self.hash = sha256;
                    self.offset = 0;
                    self.phase = if self.file < 3 {
                        Phase::ParseMetadata
                    } else {
                        Phase::SealObject
                    };
                }
                DownloadEvent::Cancelled => return Err(Error::State),
            },
            Phase::ArtifactReserve => {
                let target = self.preparation.as_ref().ok_or(Error::Metadata)?.target();
                engine
                    .begin_fetch_put(target.length, target.sha256, now)
                    .map_err(|_| Error::Storage)?;
                self.phase = Phase::HeaderAck;
            }
            Phase::HeaderAck => {
                self.download
                    .acknowledge_headers(now)
                    .map_err(|_| Error::Transport)?;
                self.phase = Phase::Download;
            }
            Phase::MetadataReserve => {
                self.hash = self
                    .preparation
                    .as_ref()
                    .and_then(|p| p.metadata(2 - self.file))
                    .ok_or(Error::Metadata)?
                    .sha256;
                engine
                    .begin_fetch_put(self.lengths[self.file] as u64, self.hash, now)
                    .map_err(|_| Error::Storage)?;
                self.offset = 0;
                self.phase = Phase::MetadataWrite;
            }
            Phase::MetadataWrite => {
                let end = (self.offset + 4096).min(self.lengths[self.file]);
                engine
                    .write_fetch_chunk(&self.metadata(b)?[self.offset..end], now)
                    .map_err(|_| Error::Storage)?;
                self.offset = end;
                if end == self.lengths[self.file] {
                    self.phase = Phase::SealObject;
                }
            }
            Phase::SealObject => {
                engine.seal_fetch_object(now).map_err(|_| Error::Storage)?;
                self.offset = 0;
                self.phase = Phase::ReadObject;
            }
            Phase::ReadObject => {
                self.chunk = engine
                    .read_retained_chunk(&mut b.chunk, now)
                    .map_err(|_| Error::Storage)?;
                if self.chunk == 0 {
                    return Err(Error::Storage);
                }
                if self.file == 3 {
                    self.phase = if self.image.is_none() {
                        Phase::ImageBegin
                    } else {
                        Phase::ImageWrite
                    };
                } else if engine.retained_remaining() == Some(0) {
                    self.phase = Phase::FinishObject;
                }
            }
            Phase::ImageBegin => {
                let content =
                    self.content(engine.fetch_expected_object().ok_or(Error::Storage)?)?;
                for slot in 0..2 {
                    if images.package(slot).is_ok_and(|p| {
                        p.id().bytes() == content.package
                            && p.bytes().len() as u64 == content.object.length()
                    }) {
                        self.image = Some(slot);
                        self.reused = true;
                        break;
                    }
                }
                if self.image.is_none() {
                    let header =
                        crate::native_image::request_from_prefix(&b.chunk[..self.chunk], content)
                            .map_err(|_| Error::Metadata)?;
                    self.image_cut = now
                        .checked_add(crate::native_network::download::MAX_DOWNLOAD_TICKS)
                        .ok_or(Error::Clock)?
                        .min(engine.original_cut().ok_or(Error::Clock)?);
                    self.image = Some(
                        images
                            .begin(header, now, self.image_cut)
                            .map_err(|_| Error::Image)?,
                    );
                }
                self.phase = Phase::ImageWrite;
            }
            Phase::ImageWrite => {
                if !self.reused {
                    images
                        .write_chunk(self.image.ok_or(Error::Image)?, now, &b.chunk[..self.chunk])
                        .map_err(|_| Error::Image)?;
                }
                self.phase = if engine.retained_remaining() == Some(0) {
                    Phase::FinishObject
                } else {
                    Phase::ReadObject
                };
            }
            Phase::FinishObject => {
                let object = engine
                    .finish_fetch_object(now)
                    .map_err(|_| Error::Storage)?;
                if object.sha256() != self.hash {
                    return Err(Error::Storage);
                }
                self.objects[self.file] = Some(object);
                self.phase = if self.file < 3 {
                    if self.file < 2 {
                        self.file += 1;
                        Phase::MetadataReserve
                    } else {
                        self.file = 3;
                        let target = self.preparation.as_ref().ok_or(Error::Metadata)?.target();
                        self.expected = Expectation::Exact {
                            length: target.length,
                            sha256: target.sha256,
                        };
                        Phase::DownloadBegin
                    }
                } else if self.reused {
                    Phase::NeedTime
                } else {
                    Phase::SealImage
                };
            }
            Phase::ParseMetadata => self.parse_metadata(b)?,
            Phase::SealImage => {
                images
                    .seal(self.image.ok_or(Error::Image)?, now)
                    .map_err(|_| Error::Image)?;
                self.phase = Phase::VerifyImage;
            }
            Phase::VerifyImage => {
                if images
                    .verify_step(self.image.ok_or(Error::Image)?, now)
                    .map_err(|_| Error::Image)?
                {
                    self.phase = Phase::NeedTime;
                }
            }
            Phase::NeedPreparationTime | Phase::NeedTime => return Ok(Event::NeedTime),
            Phase::WaitingPreparationTime | Phase::WaitingTime => (),
            Phase::Prepare => return Ok(Event::NeedPreparation),
            Phase::Authorize => return Ok(Event::NeedAuthorization),
            Phase::Commit => {
                if engine.active() {
                    engine.step(b, now);
                }
                match engine.outcome() {
                    Some(update::Outcome::Complete(_)) => self.phase = Phase::Associate,
                    None => (),
                    _ => return Err(Error::Storage),
                }
            }
            Phase::Associate => {
                let content = self.content(self.objects[3].ok_or(Error::State)?)?;
                if engine.retained_snapshot().and_then(|s| s.candidate()) != Some(content) {
                    return Err(Error::Authorization);
                }
                crate::native_sources::Downloaded::from_images(
                    images,
                    self.image.ok_or(Error::Image)?,
                    engine.retained_snapshot().ok_or(Error::State)?,
                    content,
                )
                .map_err(|_| Error::Authorization)?;
                self.phase = Phase::Register;
            }
            Phase::Register => {
                let slot = self.image.ok_or(Error::Image)?;
                if images.registered_capability(slot).is_none() {
                    images.register(slot, now).map_err(|_| Error::Image)?;
                }
                self.phase = Phase::Done;
            }
            Phase::Done => {
                return Ok(Event::Published {
                    slot: self.image.ok_or(Error::Image)?,
                });
            }
            Phase::New | Phase::Failed => return Err(Error::State),
        }
        Ok(Event::Working)
    }
    fn path(&self) -> Path {
        match self.file {
            0 => Path::Timestamp,
            1 => Path::Snapshot,
            2 => Path::Targets,
            _ => Path::Artifact,
        }
    }
    fn metadata<'a>(&self, b: &'a Buffers) -> Result<&'a [u8], Error> {
        match self.file {
            0 => Ok(&b.timestamp),
            1 => Ok(&b.snapshot),
            2 => Ok(&b.targets),
            _ => Err(Error::Metadata),
        }
    }
    fn content(&self, object: Object) -> Result<Content, Error> {
        let t = self.preparation.as_ref().ok_or(Error::Metadata)?.target();
        Ok(Content {
            object,
            version: t.version,
            app: acq::HELLO_APP,
            package: t.sha256,
            build: t.build,
            descriptor: t.contract,
            source: t.source_revision,
        })
    }
    fn parse_metadata(&mut self, b: &Buffers) -> Result<(), Error> {
        let bytes = &self.metadata(b)?[..self.lengths[self.file]];
        let envelope = Envelope::parse(bytes).map_err(|_| Error::Metadata)?;
        if self.file < 2 {
            if envelope.role()
                != if self.file == 0 {
                    ev_release_trust::signature::Role::Timestamp
                } else {
                    ev_release_trust::signature::Role::Snapshot
                }
            {
                return Err(Error::Metadata);
            }
            let link = md::Linked::parse(&envelope)
                .map_err(|_| Error::Metadata)?
                .link();
            self.expected = Expectation::Exact {
                length: link.length,
                sha256: link.sha256,
            };
        } else {
            let targets = md::Targets::parse(&envelope).map_err(|_| Error::Metadata)?;
            if targets.count() != 1 {
                return Err(Error::Metadata);
            }
            let target = targets.iter().next().ok_or(Error::Metadata)?.spec();
            if target.name != acq::logical_target_name() || !matches!(target.version, 2 | 3) {
                return Err(Error::Metadata);
            }
            self.phase = Phase::NeedPreparationTime;
            return Ok(());
        }
        self.file += 1;
        self.phase = Phase::DownloadBegin;
        Ok(())
    }
}
#[cfg(test)]
mod tests;
