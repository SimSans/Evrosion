use crate::*;
pub struct Stage<'a, B: Backend> {
    pub(crate) arena: &'a mut Arena<B>,
    pub(crate) object: Object,
    pub(crate) transfer: TransferCut,
    pub(crate) written: u64,
    pub(crate) hash: Sha256,
}
impl<'a, B: Backend> Stage<'a, B> {
    pub fn remaining(&self) -> u64 {
        self.object.length - self.written
    }
    pub fn reserved_head(&self) -> [u8; 32] {
        self.arena.head_digest()
    }
    pub fn write_chunk(&mut self, bytes: &[u8], cut: IoCut) -> Result<(), Error<B::Error>> {
        self.arena.healthy()?;
        cut.check::<B::Error>(self.transfer)?;
        if bytes.is_empty()
            || bytes.len() > MAX_CHUNK_BYTES
            || bytes.len() as u64 > self.remaining()
            || (bytes.len() as u64 != self.remaining() && !bytes.len().is_multiple_of(512))
        {
            return Err(Error::Bounds);
        }
        self.arena.poisoned = true;
        let mut d = self.arena.backend.device(Area::Objects);
        for (i, chunk) in bytes.chunks(512).enumerate() {
            let mut sector = [0; 512];
            sector[..chunk.len()].copy_from_slice(chunk);
            d.write(
                self.object.start + 1 + self.written / 512 + i as u64,
                &sector,
                cut.end,
            )
            .map_err(Error::Io)?;
        }
        self.hash.update(bytes);
        self.written += bytes.len() as u64;
        self.arena.poisoned = false;
        Ok(())
    }
    pub fn seal(self, cut: IoCut) -> Result<Reader<'a, B>, Error<B::Error>> {
        self.arena.healthy()?;
        cut.check::<B::Error>(self.transfer)?;
        if self.written != self.object.length {
            return Err(Error::Incomplete);
        }
        if <[u8; 32]>::from(self.hash.finalize()) != self.object.hash {
            return Err(Error::Hash);
        }
        self.arena.poisoned = true;
        {
            let mut d = self.arena.backend.device(Area::Objects);
            d.flush(cut.end).map_err(Error::Io)?;
            d.write(
                self.object.start,
                &codec::encode_object(self.object),
                cut.end,
            )
            .map_err(Error::Io)?;
            d.flush(cut.end).map_err(Error::Io)?;
        }
        self.arena.poisoned = false;
        self.arena.reader(self.object, self.transfer, cut)
    }
}
pub struct Reader<'a, B: Backend> {
    pub(crate) arena: &'a mut Arena<B>,
    pub(crate) object: Object,
    pub(crate) transfer: TransferCut,
    pub(crate) read: u64,
    pub(crate) hash: Sha256,
}
impl<'a, B: Backend> Reader<'a, B> {
    pub fn remaining(&self) -> u64 {
        self.object.length - self.read
    }
    pub fn read_chunk(&mut self, out: &mut [u8], cut: IoCut) -> Result<usize, Error<B::Error>> {
        self.arena.healthy()?;
        cut.check::<B::Error>(self.transfer)?;
        if out.is_empty()
            || out.len() > MAX_CHUNK_BYTES
            || (!out.len().is_multiple_of(512) && (out.len() as u64) < self.remaining())
        {
            return Err(Error::Bounds);
        }
        if self.remaining() == 0 {
            return Ok(0);
        }
        let n = out.len().min(self.remaining() as usize);
        out.fill(0);
        self.arena.poisoned = true;
        let mut d = self.arena.backend.device(Area::Objects);
        for (i, chunk) in out[..n].chunks_mut(512).enumerate() {
            let mut sector = [0; 512];
            d.read(
                self.object.start + 1 + self.read / 512 + i as u64,
                &mut sector,
                cut.end,
            )
            .map_err(Error::Io)?;
            chunk.copy_from_slice(&sector[..chunk.len()]);
            if chunk.len() < 512 && sector[chunk.len()..].iter().any(|v| *v != 0) {
                return Err(Error::Corrupt);
            }
        }
        self.hash.update(&out[..n]);
        self.read += n as u64;
        self.arena.poisoned = false;
        Ok(n)
    }
    pub fn finish(self) -> Result<Verified<'a, B>, Error<B::Error>> {
        self.arena.healthy()?;
        if self.read != self.object.length {
            return Err(Error::Incomplete);
        }
        if <[u8; 32]>::from(self.hash.finalize()) != self.object.hash {
            self.arena.poisoned = true;
            return Err(Error::Hash);
        }
        Ok(Verified {
            arena: self.arena,
            object: self.object,
            transfer: self.transfer,
        })
    }
}
/// Complete hash-verified bytes tied to the sole actual backend borrow. This
/// token proves neither publisher identity nor permission to activate anything.
pub struct Verified<'a, B: Backend> {
    pub(crate) arena: &'a mut Arena<B>,
    pub(crate) object: Object,
    pub(crate) transfer: TransferCut,
}
impl<B: Backend> Verified<'_, B> {
    pub fn object(&self) -> Object {
        self.object
    }
    pub fn current_head(&self) -> [u8; 32] {
        self.arena.head_digest()
    }
    pub fn release(self) -> Object {
        self.object
    }
    pub fn publish(self, expected: [u8; 32], cut: MetadataCut) -> Result<Object, Error<B::Error>> {
        cut.check::<B::Error>(self.transfer)?;
        if expected != self.arena.head_digest() {
            return Err(Error::Conflict);
        }
        let next = Head {
            high: self.arena.head.high,
            revision: self
                .arena
                .head
                .revision
                .checked_add(1)
                .filter(|v| *v != u64::MAX)
                .ok_or(Error::Exhausted)?,
            published: Some(self.object),
        };
        self.arena.commit(next, cut)?;
        Ok(self.object)
    }
}
