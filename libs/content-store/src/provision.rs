use crate::*;
/// Explicit new-volume provisioning only. Not selected by generic open failure.
/// Full-region blank scan is bounded per step; no erase/repair/auto-format exists.
pub struct Provisioner<B: Backend> {
    backend: B,
    creation: GenerationManifest,
    transfer: TransferCut,
    scanned: u64,
    poisoned: bool,
}
impl<B: Backend> Provisioner<B> {
    pub fn new(
        backend: B,
        creation: GenerationManifest,
        transfer: TransferCut,
    ) -> Result<Self, Rejected<B>> {
        if !creation.valid() {
            return Err(Rejected {
                backend,
                error: Error::Foreign,
            });
        }
        Ok(Self {
            backend,
            creation,
            transfer,
            scanned: 0,
            poisoned: false,
        })
    }
    pub fn into_backend(self) -> B {
        self.backend
    }
    pub fn remaining(&self) -> u64 {
        ev_store::REQUIRED_SECTORS + OBJECT_SECTORS - self.scanned
    }
    /// A terminal NotBlank result still prohibits scan/format reuse. Only its
    /// already-completed read can be settled for returning the same backend.
    pub fn has_unresolved_io(&self) -> bool {
        self.backend.has_unresolved_io()
    }
    pub fn scan(&mut self, cut: IoCut) -> Result<(), Error<B::Error>> {
        if self.poisoned {
            return Err(Error::Recovery);
        }
        cut.check::<B::Error>(self.transfer)?;
        if self.remaining() == 0 {
            return Ok(());
        }
        self.poisoned = true;
        for _ in 0..8 {
            if self.remaining() == 0 {
                break;
            }
            let (area, local, expected) = if self.scanned < ev_store::REQUIRED_SECTORS {
                (Area::Checkpoint, self.scanned, ev_store::REQUIRED_SECTORS)
            } else {
                (
                    Area::Objects,
                    self.scanned - ev_store::REQUIRED_SECTORS,
                    OBJECT_SECTORS,
                )
            };
            let mut d = self.backend.device(area);
            if d.sectors() != expected {
                return Err(Error::Geometry);
            }
            let mut b = [0; 512];
            d.read(local, &mut b, cut.end).map_err(Error::Io)?;
            if b.iter().any(|v| *v != 0) {
                return Err(Error::NotBlank);
            }
            self.scanned += 1;
        }
        self.poisoned = false;
        Ok(())
    }
    pub fn finish(mut self, cut: MetadataCut) -> Result<Arena<B>, Rejected<B>> {
        let result = (|| {
            if self.poisoned {
                return Err(Error::Recovery);
            }
            cut.check::<B::Error>(self.transfer)?;
            if self.remaining() != 0 {
                return Err(Error::Incomplete);
            }
            let d = self.backend.device(Area::Checkpoint);
            Store::format_new(
                d,
                self.creation,
                &codec::encode_head(Head::EMPTY),
                BootPolicy::new(1).unwrap(),
                cut.end,
            )
            .map_err(|r| Error::Store(r.error))?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(Arena {
                backend: self.backend,
                creation: self.creation,
                head: Head::EMPTY,
                poisoned: false,
            }),
            Err(error) => Err(Rejected {
                backend: self.backend,
                error,
            }),
        }
    }
}
