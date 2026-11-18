use crate::*;
use sha2::{Digest as _, Sha256};

pub struct Dataset<'a, D: SectorIo> {
    device: D,
    scratch: &'a mut Scratch,
    root: Root,
    poisoned: bool,
    mirrored: bool,
    //0/1 is the sole slot holding selected committed state;2 means neither
    // specially protected. Recovery writes its peer first, never this copy.
    valid_slot: u8,
}
impl<'a, D: SectorIo> Dataset<'a, D> {
    /// Explicit NEW-region operation. Read-preflights the complete profile;
    /// nonblank/unknown data never triggers formatting or automatic migration.
    pub fn format_new(
        device: D,
        scratch: &'a mut Scratch,
        dataset: DatasetId,
        deadline: u64,
    ) -> Result<Self, RejectedDevice<D>> {
        let mut pending = Provisioning::new(device, scratch, dataset)?;
        loop {
            match pending.scan_step(128, deadline) {
                Ok(progress) if progress.verified_sectors == REQUIRED_SECTORS => break,
                Ok(_) => (),
                Err(error) => {
                    return Err(RejectedDevice {
                        device: pending.value.device,
                        error,
                    });
                }
            }
        }
        pending.finish(deadline)
    }
    /// Cold read-only reopen. Incomplete staging remains explicitly resumable;
    /// no writes, flushes, repair or destructive fallback occur during open.
    pub fn open(
        device: D,
        scratch: &'a mut Scratch,
        deadline: u64,
    ) -> Result<Self, RejectedDevice<D>> {
        let placeholder = Root {
            dataset: DatasetId([1; 16]),
            sequence: 1,
            namespace: 1,
            catalog: 0,
            catalog_digest: [0; 32],
            last_operation: 0,
            fingerprint: [0; 32],
            receipt: None,
            stage: None,
        };
        let mut value = Self {
            device,
            scratch,
            root: placeholder,
            poisoned: false,
            mirrored: false,
            valid_slot: 2,
        };
        let result = (|| {
            valid_deadline(deadline)?;
            if value.device.sectors() < REQUIRED_SECTORS {
                return Err(Error::Capacity);
            }
            let mut selected: Option<Root> = None;
            let mut roots = [None; 2];
            let mut nonblank = false;
            let mut provisioning = None;
            for sector in 0..2 {
                value.read_sector(sector, deadline)?;
                nonblank |= value.scratch.sector.iter().any(|b| *b != 0);
                if let Some(dataset) = codec::decode_provision(&value.scratch.sector) {
                    if provisioning.is_some_and(|old| old != dataset) {
                        return Err(Error::Corrupt);
                    }
                    provisioning = Some(dataset);
                }
                if codec::unsupported(&value.scratch.sector) {
                    return Err(Error::Unsupported);
                }
                if let Some(root) = codec::decode_root(&value.scratch.sector) {
                    roots[sector as usize] = Some(root);
                    if let Some(old) = selected {
                        if old.dataset != root.dataset
                            || (old.sequence == root.sequence && old != root)
                        {
                            return Err(Error::Corrupt);
                        }
                        if root.sequence > old.sequence {
                            selected = Some(root);
                        }
                    } else {
                        selected = Some(root);
                    }
                }
            }
            value.root = selected.ok_or(if provisioning.is_some() {
                Error::ProvisioningRequired
            } else if nonblank {
                Error::Corrupt
            } else {
                Error::Unformatted
            })?;
            if provisioning.is_some_and(|dataset| dataset != value.root.dataset) {
                return Err(Error::Corrupt);
            }
            value.mirrored = roots[0] == Some(value.root) && roots[1] == Some(value.root);
            value.valid_slot = if value.mirrored {
                2
            } else if roots[0] == Some(value.root) {
                0
            } else {
                1
            };
            value.load_catalog(deadline)?;
            value.validate_catalog()?;
            // This is metadata open, not a hidden64MiB startup scrub. Every
            // data range verifies its chunk before returning bytes. Explicit
            // scrub and staged verification cover full contents/checkpoints.
            Ok(())
        })();
        match result {
            Ok(()) => Ok(value),
            Err(error) => Err(RejectedDevice {
                device: value.device,
                error,
            }),
        }
    }
    pub fn into_device(self) -> D {
        self.device
    }
    pub fn dataset_id(&self) -> DatasetId {
        self.root.dataset
    }
    pub fn namespace_revision(&self) -> u64 {
        self.root.namespace
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    /// Readable committed state can need completion of an interrupted mirror.
    /// Inspection remains read-only; fresh mutations stay fenced until repair.
    pub fn needs_mirror_recovery(&self) -> bool {
        !self.mirrored
    }
    /// Flush the actual backing only after metadata and staging are settled.
    /// The caller must separately establish client/loan/device-owner retirement;
    /// this callback completion does not prove those external obligations.
    pub fn sync_quiescent(&mut self, deadline: u64) -> Result<(), Error<D::Error>> {
        valid_deadline(deadline)?;
        self.live()?;
        if !self.mirrored {
            return Err(Error::NeedsRecovery);
        }
        if self.root.stage.is_some() {
            return Err(Error::Busy);
        }
        self.flush(deadline)
    }
    pub fn recover_metadata(&mut self, deadline: u64) -> Result<(), Error<D::Error>> {
        valid_deadline(deadline)?;
        self.live()?;
        if !self.mirrored {
            let root = self.root;
            self.write_root(&root, deadline)?;
        }
        Ok(())
    }
    pub fn last_receipt(&self) -> Result<Option<Receipt>, Error<D::Error>> {
        self.live()?;
        Ok(self.root.receipt)
    }
    pub fn next_operation(&self) -> Result<OperationId, Error<D::Error>> {
        self.live()?;
        if !self.mirrored {
            return Err(Error::NeedsRecovery);
        }
        self.root
            .last_operation
            .checked_add(1)
            .and_then(OperationId::new)
            .ok_or(Error::Exhausted)
    }
    pub fn pending_stage(&self) -> Result<Option<StageInfo>, Error<D::Error>> {
        self.live()?;
        Ok(self.root.stage.map(|s| StageInfo {
            id: s.id,
            object: s.object,
            expected_revision: s.expected,
            length: s.length,
            written: s.written,
            sha256: s.digest,
        }))
    }
    /// Allocation quota includes retained trash and rounds each file to4KiB.
    pub fn allocated_bytes(&self) -> Result<u64, Error<D::Error>> {
        self.live()?;
        Ok(self
            .scratch
            .entries
            .iter()
            .map(|e| e.chunks as u64 * CHUNK_BYTES as u64)
            .sum())
    }
    pub fn metadata(&self, object: ObjectId) -> Result<Metadata, Error<D::Error>> {
        self.live()?;
        if object == ObjectId::ROOT {
            return Ok(Metadata {
                id: object,
                parent: object,
                kind: Kind::Directory,
                directly_trashed: false,
                revision: self.root.namespace,
                length: 0,
                sha256: [0; 32],
            });
        }
        let index = self.index(object)?;
        Ok(self.scratch.entries[index].metadata(index))
    }
    pub fn name(&self, object: ObjectId) -> Result<&str, Error<D::Error>> {
        self.live()?;
        if object == ObjectId::ROOT {
            return Ok("");
        }
        Ok(self.scratch.entries[self.index(object)?].name.as_str())
    }
    pub fn is_trashed(&self, object: ObjectId) -> Result<bool, Error<D::Error>> {
        self.live()?;
        self.hidden(object)
    }
    /// Enumerate one resident entry; next call uses its slot as after_slot.
    /// include_trashed is storage policy metadata, never authorization to list.
    pub fn list(
        &self,
        parent: ObjectId,
        after_slot: u16,
        include_trashed: bool,
    ) -> Result<Option<Metadata>, Error<D::Error>> {
        self.live()?;
        self.directory(parent)?;
        if !include_trashed && self.hidden(parent)? {
            return Err(Error::Hidden);
        }
        for (index, entry) in self
            .scratch
            .entries
            .iter()
            .enumerate()
            .skip(after_slot as usize)
        {
            if entry.kind != 0 && entry.parent == parent && (include_trashed || !entry.trashed) {
                return Ok(Some(entry.metadata(index)));
            }
        }
        Ok(None)
    }
    fn live(&self) -> Result<(), Error<D::Error>> {
        if self.poisoned {
            Err(Error::NeedsRecovery)
        } else {
            Ok(())
        }
    }
    fn index(&self, object: ObjectId) -> Result<usize, Error<D::Error>> {
        if ObjectId::new(object.slot, object.generation) != Some(object) || object.slot == 0 {
            return Err(Error::InvalidObject);
        }
        let index = object.slot as usize - 1;
        let entry = &self.scratch.entries[index];
        if entry.kind == 0 || entry.generation != object.generation {
            Err(Error::StaleObject)
        } else {
            Ok(index)
        }
    }
    fn directory(&self, object: ObjectId) -> Result<(), Error<D::Error>> {
        if object == ObjectId::ROOT {
            return Ok(());
        }
        if self.scratch.entries[self.index(object)?].kind != 2 {
            Err(Error::NotDirectory)
        } else {
            Ok(())
        }
    }
    fn hidden(&self, mut object: ObjectId) -> Result<bool, Error<D::Error>> {
        for _ in 0..=MAX_DEPTH {
            if object == ObjectId::ROOT {
                return Ok(false);
            }
            let entry = &self.scratch.entries[self.index(object)?];
            if entry.trashed {
                return Ok(true);
            }
            object = entry.parent;
        }
        Err(Error::Corrupt)
    }
    fn depth(
        &self,
        mut object: ObjectId,
        changed: Option<(ObjectId, ObjectId)>,
    ) -> Result<usize, Error<D::Error>> {
        let mut depth = 0;
        while object != ObjectId::ROOT {
            if depth >= MAX_DEPTH {
                return Err(Error::Depth);
            }
            let entry = &self.scratch.entries[self.index(object)?];
            object = if let Some((target, parent)) = changed {
                if target == object {
                    parent
                } else {
                    entry.parent
                }
            } else {
                entry.parent
            };
            depth += 1;
        }
        Ok(depth)
    }
    fn descendant(
        &self,
        mut object: ObjectId,
        ancestor: ObjectId,
    ) -> Result<bool, Error<D::Error>> {
        for _ in 0..=MAX_DEPTH {
            if object == ancestor {
                return Ok(true);
            }
            if object == ObjectId::ROOT {
                return Ok(false);
            }
            object = self.scratch.entries[self.index(object)?].parent;
        }
        Err(Error::Corrupt)
    }
    fn collision(&self, parent: ObjectId, name: Name, except: Option<ObjectId>) -> bool {
        self.scratch.entries.iter().enumerate().any(|(i, e)| {
            e.kind != 0
                && !e.trashed
                && e.parent == parent
                && e.name == name
                && Some(e.id(i)) != except
        })
    }
    fn preflight(
        &mut self,
        operation: OperationId,
        fingerprint: Digest,
        deadline: u64,
    ) -> Result<Option<Receipt>, Error<D::Error>> {
        valid_deadline(deadline)?;
        self.live()?;
        if operation.get() == self.root.last_operation {
            let mut receipt = self.root.receipt.ok_or(Error::Corrupt)?;
            if fingerprint != self.root.fingerprint
                || operation.request != receipt.operation.request
            {
                return Err(Error::Conflict);
            }
            self.recover_metadata(deadline)?;
            receipt.replayed = true;
            return Ok(Some(receipt));
        }
        if operation.get() < self.root.last_operation {
            return Err(Error::StaleOperation);
        }
        // Even the trusted adapter cannot disguise an immediate duplicate
        // client nonce as a fresh global transaction. Reconcile its old ID.
        if operation.request.is_some()
            && self
                .root
                .receipt
                .is_some_and(|r| r.operation.request == operation.request)
        {
            return Err(Error::Conflict);
        }
        if operation.get() != self.next_operation()?.get() {
            return Err(Error::OutOfOrder);
        }
        self.root
            .sequence
            .checked_add(1)
            .filter(|v| *v != u64::MAX)
            .ok_or(Error::Exhausted)?;
        self.root
            .namespace
            .checked_add(1)
            .filter(|v| *v != u64::MAX)
            .ok_or(Error::Exhausted)?;
        Ok(None)
    }
    fn namespace_matches(&self, expected: u64) -> Result<(), Error<D::Error>> {
        if expected != self.root.namespace {
            Err(Error::Conflict)
        } else {
            Ok(())
        }
    }
    fn read_sector(&mut self, lba: u64, deadline: u64) -> Result<(), Error<D::Error>> {
        self.device
            .read(lba, &mut self.scratch.sector, deadline)
            .map_err(|e| {
                self.poisoned = true;
                Error::Io(e)
            })
    }
    fn write_sector(&mut self, lba: u64, deadline: u64) -> Result<(), Error<D::Error>> {
        self.device
            .write(lba, &self.scratch.sector, deadline)
            .map_err(|e| {
                self.poisoned = true;
                Error::Io(e)
            })
    }
    fn flush(&mut self, deadline: u64) -> Result<(), Error<D::Error>> {
        self.device.flush(deadline).map_err(|e| {
            self.poisoned = true;
            Error::Io(e)
        })
    }
    fn write_root(&mut self, root: &Root, deadline: u64) -> Result<(), Error<D::Error>> {
        // First durable root is the atomic boundary. Mirror before ACK so one
        // later damaged root cannot silently revert acknowledged user work.
        let first = if *root == self.root && self.valid_slot < 2 {
            1 - self.valid_slot as u64
        } else {
            root.sequence % 2
        };
        for slot in [first, 1 - first] {
            codec::root(root, &mut self.scratch.sector);
            self.write_sector(slot, deadline)?;
            self.flush(deadline)?;
            self.read_sector(slot, deadline)?;
            if codec::decode_root(&self.scratch.sector) != Some(*root) {
                self.poisoned = true;
                return Err(Error::Corrupt);
            }
            self.valid_slot = slot as u8;
        }
        self.mirrored = true;
        self.valid_slot = 2;
        Ok(())
    }
    fn write_catalog(&mut self, bank: u8, deadline: u64) -> Result<Digest, Error<D::Error>> {
        let mut hash = Sha256::new();
        for sector in 0..CATALOG_SECTORS {
            for half in 0..2 {
                let index = sector as usize * 2 + half;
                codec::entry(
                    &self.scratch.entries[index],
                    index,
                    &mut self.scratch.sector[half * 256..half * 256 + 256],
                );
            }
            hash.update(self.scratch.sector);
            self.write_sector(2 + bank as u64 * CATALOG_SECTORS + sector, deadline)?;
        }
        self.flush(deadline)?;
        let expected: Digest = hash.finalize().into();
        let mut readback = Sha256::new();
        for sector in 0..CATALOG_SECTORS {
            self.read_sector(2 + bank as u64 * CATALOG_SECTORS + sector, deadline)?;
            readback.update(self.scratch.sector);
        }
        if Digest::from(readback.finalize()) != expected {
            self.poisoned = true;
            return Err(Error::Corrupt);
        }
        Ok(expected)
    }
    fn load_catalog(&mut self, deadline: u64) -> Result<(), Error<D::Error>> {
        let mut hash = Sha256::new();
        for sector in 0..CATALOG_SECTORS {
            self.read_sector(
                2 + self.root.catalog as u64 * CATALOG_SECTORS + sector,
                deadline,
            )?;
            hash.update(self.scratch.sector);
            for half in 0..2 {
                let index = sector as usize * 2 + half;
                self.scratch.entries[index] =
                    codec::decode_entry(&self.scratch.sector[half * 256..half * 256 + 256], index)
                        .ok_or(Error::Corrupt)?;
            }
        }
        if Digest::from(hash.finalize()) != self.root.catalog_digest {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
    fn validate_catalog(&self) -> Result<(), Error<D::Error>> {
        let mut directories = 0;
        let mut chunks = 0u32;
        for (index, entry) in self.scratch.entries.iter().enumerate() {
            if entry.kind == 0 {
                continue;
            }
            self.directory(entry.parent).map_err(|_| Error::Corrupt)?;
            self.depth(entry.id(index), None)
                .map_err(|_| Error::Corrupt)?;
            if entry.kind == 2 {
                directories += 1;
            }
            chunks = chunks.checked_add(entry.chunks).ok_or(Error::Corrupt)?;
            if entry.stamp > self.root.last_operation {
                return Err(Error::Corrupt);
            }
            for (other_index, other) in self.scratch.entries.iter().enumerate().take(index) {
                if other.kind == 0 {
                    continue;
                }
                if !entry.trashed
                    && !other.trashed
                    && entry.parent == other.parent
                    && entry.name == other.name
                {
                    return Err(Error::Corrupt);
                }
                if overlap(entry.start, entry.chunks, other.start, other.chunks)
                    || entry.id(index) == other.id(other_index)
                {
                    return Err(Error::Corrupt);
                }
            }
        }
        if directories > MAX_DIRECTORIES || chunks > USABLE_CHUNKS {
            return Err(Error::Corrupt);
        }
        if let Some(stage) = self.root.stage {
            let entry =
                &self.scratch.entries[self.index(stage.object).map_err(|_| Error::Corrupt)?];
            if entry.kind != 1 || entry.revision != stage.expected || self.hidden(stage.object)? {
                return Err(Error::Corrupt);
            }
            for entry in &self.scratch.entries {
                if entry.kind != 0 && overlap(stage.start, stage.chunks, entry.start, entry.chunks)
                {
                    return Err(Error::Corrupt);
                }
            }
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    fn publish(
        &mut self,
        operation: OperationId,
        fingerprint: Digest,
        mut root: Root,
        catalog_changed: bool,
        kind: ReceiptKind,
        object: ObjectId,
        object_revision: u64,
        stage: u64,
        bytes: u64,
        deadline: u64,
    ) -> Result<Receipt, Error<D::Error>> {
        root.sequence += 1;
        root.last_operation = operation.get();
        root.fingerprint = fingerprint;
        if catalog_changed {
            root.namespace += 1;
            root.catalog = 1 - self.root.catalog;
            root.catalog_digest = self.write_catalog(root.catalog, deadline)?;
        }
        let receipt = Receipt {
            operation,
            sequence: root.sequence,
            kind,
            object,
            object_revision,
            namespace_revision: root.namespace,
            stage,
            bytes,
            replayed: false,
        };
        root.receipt = Some(receipt);
        self.write_root(&root, deadline)?;
        self.root = root;
        Ok(receipt)
    }
}
fn overlap(a: u32, an: u32, b: u32, bn: u32) -> bool {
    an != 0 && bn != 0 && a < b + bn && b < a + an
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvisionProgress {
    /// Confirmed blank sectors through this relative cursor. Scanning itself
    /// is RAM progress until a NEW-region marker is durably published.
    pub verified_sectors: u64,
    pub total_sectors: u64,
    pub durably_marked: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerificationProgress {
    pub verified_bytes: u64,
    pub total_bytes: u64,
    pub complete: bool,
}
/// Opaque small RAM continuation. It verifies immutable acknowledged stage
/// chunks with separately captured bounded deadlines. It is not a receipt or
/// durable checkpoint, and can never authorize a different dataset/stage.
pub struct CommitVerifier {
    dataset: DatasetId,
    stage: Stage,
    next: u32,
    hash: Sha256,
    complete: bool,
}
impl CommitVerifier {
    pub fn progress(&self) -> VerificationProgress {
        VerificationProgress {
            verified_bytes: (self.next as u64 * CHUNK_BYTES as u64).min(self.stage.length),
            total_bytes: self.stage.length,
            complete: self.complete,
        }
    }
}

/// Exclusive, caller-resident continuation for costly guest provisioning.
/// Each scan_step has its own captured deadline and bounded sector count; this
/// must run BEFORE ordinary desktop health/admission. No old format is resumed.
pub struct Provisioning<'a, D: SectorIo> {
    value: Dataset<'a, D>,
    cursor: u64,
    marked: bool,
}
impl<'a, D: SectorIo> Provisioning<'a, D> {
    pub fn new(
        device: D,
        scratch: &'a mut Scratch,
        dataset: DatasetId,
    ) -> Result<Self, RejectedDevice<D>> {
        if device.sectors() < REQUIRED_SECTORS {
            return Err(RejectedDevice {
                device,
                error: Error::Capacity,
            });
        }
        let value = Dataset {
            device,
            scratch,
            poisoned: false,
            mirrored: false,
            valid_slot: 2,
            root: Root {
                dataset,
                sequence: 1,
                namespace: 1,
                catalog: 0,
                catalog_digest: [0; 32],
                last_operation: 0,
                fingerprint: [0; 32],
                receipt: None,
                stage: None,
            },
        };
        Ok(Self {
            value,
            cursor: 0,
            marked: false,
        })
    }
    /// Explicit owner recovery of THIS empty new dataset. A marker exists only
    /// after complete blank preflight. Existing committed roots refuse here;
    /// open/recover_metadata must handle them without erasing user content.
    pub fn resume(
        device: D,
        scratch: &'a mut Scratch,
        expected: DatasetId,
        deadline: u64,
    ) -> Result<Self, RejectedDevice<D>> {
        let mut pending = Self::new(device, scratch, expected)?;
        let result = (|| {
            valid_deadline(deadline)?;
            let mut marker = false;
            for slot in 0..2 {
                pending.value.read_sector(slot, deadline)?;
                let bytes = &pending.value.scratch.sector;
                if codec::unsupported(bytes) {
                    return Err(Error::Unsupported);
                }
                if codec::decode_root(bytes).is_some() {
                    return Err(Error::Conflict);
                }
                if let Some(dataset) = codec::decode_provision(bytes) {
                    if dataset != expected {
                        return Err(Error::Conflict);
                    }
                    marker = true;
                }
            }
            if !marker {
                return Err(Error::ProvisioningRequired);
            }
            Ok(())
        })();
        if let Err(error) = result {
            return Err(RejectedDevice {
                device: pending.value.device,
                error,
            });
        }
        pending.marked = true;
        pending.cursor = DATA_START;
        Ok(pending)
    }
    pub fn progress(&self) -> ProvisionProgress {
        ProvisionProgress {
            verified_sectors: self.cursor,
            total_sectors: REQUIRED_SECTORS,
            durably_marked: self.marked,
        }
    }
    pub fn scan_step(
        &mut self,
        max_sectors: u16,
        deadline: u64,
    ) -> Result<ProvisionProgress, Error<D::Error>> {
        valid_deadline(deadline)?;
        self.value.live()?;
        if max_sectors == 0 {
            return Err(Error::InvalidChunk);
        }
        let end = (self.cursor + max_sectors as u64).min(REQUIRED_SECTORS);
        while self.cursor < end {
            self.value.read_sector(self.cursor, deadline)?;
            if self.value.scratch.sector.iter().any(|b| *b != 0) {
                return Err(Error::NotBlank);
            }
            self.cursor += 1;
        }
        Ok(self.progress())
    }
    /// Finalization is a bounded263-I/O metadata transaction after the NEW
    /// marker. Give this dedicated provisioning phase an independently measured
    /// finite budget; never extend a captured RPC or claim startup health here.
    pub fn finish(mut self, deadline: u64) -> Result<Dataset<'a, D>, RejectedDevice<D>> {
        let result = (|| {
            valid_deadline(deadline)?;
            self.value.live()?;
            if self.cursor != REQUIRED_SECTORS {
                return Err(Error::Incomplete);
            }
            if !self.marked {
                for slot in 0..2 {
                    codec::provision(self.value.root.dataset, &mut self.value.scratch.sector);
                    self.value.write_sector(slot, deadline)?;
                    self.value.flush(deadline)?;
                    self.value.read_sector(slot, deadline)?;
                    if codec::decode_provision(&self.value.scratch.sector)
                        != Some(self.value.root.dataset)
                    {
                        self.value.poisoned = true;
                        return Err(Error::Corrupt);
                    }
                }
                self.marked = true;
            }
            self.value.scratch.entries.fill(Entry::EMPTY);
            self.value.root.catalog_digest = self.value.write_catalog(0, deadline)?;
            let root = self.value.root;
            self.value.write_root(&root, deadline)?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(self.value),
            Err(error) => Err(RejectedDevice {
                device: self.value.device,
                error,
            }),
        }
    }
    pub fn into_device(self) -> D {
        self.value.device
    }
}

impl<D: SectorIo> Dataset<'_, D> {
    pub fn create(
        &mut self,
        operation: OperationId,
        expected_namespace: u64,
        parent: ObjectId,
        name: Name,
        kind: Kind,
        deadline: u64,
    ) -> Result<Receipt, Error<D::Error>> {
        let fp = codec::fingerprint(
            1,
            &[
                expected_namespace,
                parent.slot as u64,
                parent.generation,
                kind as u64,
            ],
            name.as_bytes(),
        );
        if let Some(receipt) = self.preflight(operation, fp, deadline)? {
            return Ok(receipt);
        }
        self.namespace_matches(expected_namespace)?;
        self.directory(parent)?;
        if self.hidden(parent)? {
            return Err(Error::Hidden);
        }
        if self.depth(parent, None)? + 1 > MAX_DEPTH {
            return Err(Error::Depth);
        }
        if self.collision(parent, name, None) {
            return Err(Error::Collision);
        }
        if kind == Kind::Directory
            && self.scratch.entries.iter().filter(|e| e.kind == 2).count() >= MAX_DIRECTORIES
        {
            return Err(Error::DirectoryLimit);
        }
        let index = self
            .scratch
            .entries
            .iter()
            .position(|e| e.kind == 0 && e.generation < u64::MAX - 1)
            .ok_or(Error::EntryLimit)?;
        let generation = self.scratch.entries[index].generation + 1;
        let entry = Entry {
            generation,
            kind: kind as u8,
            parent,
            name,
            revision: 1,
            digest: if kind == Kind::File {
                codec::hash(&[])
            } else {
                [0; 32]
            },
            ..Entry::EMPTY
        };
        let object = entry.id(index);
        self.scratch.entries[index] = entry;
        self.publish(
            operation,
            fp,
            self.root,
            true,
            ReceiptKind::Created,
            object,
            1,
            0,
            0,
            deadline,
        )
    }
    pub fn rename(
        &mut self,
        operation: OperationId,
        expected_namespace: u64,
        object: ObjectId,
        name: Name,
        deadline: u64,
    ) -> Result<Receipt, Error<D::Error>> {
        let fp = codec::fingerprint(
            2,
            &[expected_namespace, object.slot as u64, object.generation],
            name.as_bytes(),
        );
        if let Some(receipt) = self.preflight(operation, fp, deadline)? {
            return Ok(receipt);
        }
        self.namespace_matches(expected_namespace)?;
        let index = self.index(object)?;
        if self.hidden(object)? {
            return Err(Error::Hidden);
        }
        let mut entry = self.scratch.entries[index];
        if self.collision(entry.parent, name, Some(object)) {
            return Err(Error::Collision);
        }
        entry.name = name;
        self.scratch.entries[index] = entry;
        self.publish(
            operation,
            fp,
            self.root,
            true,
            ReceiptKind::Renamed,
            object,
            entry.revision,
            0,
            0,
            deadline,
        )
    }
    /// Transactional metadata move within this dataset; external storage is not
    /// addressed by this API. Existing object identity/revision remain stable.
    pub fn move_object(
        &mut self,
        operation: OperationId,
        expected_namespace: u64,
        object: ObjectId,
        parent: ObjectId,
        name: Name,
        deadline: u64,
    ) -> Result<Receipt, Error<D::Error>> {
        let fp = codec::fingerprint(
            3,
            &[
                expected_namespace,
                object.slot as u64,
                object.generation,
                parent.slot as u64,
                parent.generation,
            ],
            name.as_bytes(),
        );
        if let Some(receipt) = self.preflight(operation, fp, deadline)? {
            return Ok(receipt);
        }
        self.namespace_matches(expected_namespace)?;
        let index = self.index(object)?;
        self.directory(parent)?;
        if self.hidden(object)? || self.hidden(parent)? {
            return Err(Error::Hidden);
        }
        if self.collision(parent, name, Some(object)) {
            return Err(Error::Collision);
        }
        if self.descendant(parent, object)? {
            return Err(Error::Depth);
        }
        for (i, e) in self.scratch.entries.iter().enumerate() {
            if e.kind != 0 {
                self.depth(e.id(i), Some((object, parent)))?;
            }
        }
        let mut entry = self.scratch.entries[index];
        entry.parent = parent;
        entry.name = name;
        self.scratch.entries[index] = entry;
        self.publish(
            operation,
            fp,
            self.root,
            true,
            ReceiptKind::Moved,
            object,
            entry.revision,
            0,
            0,
            deadline,
        )
    }
    pub fn trash(
        &mut self,
        operation: OperationId,
        expected_namespace: u64,
        object: ObjectId,
        deadline: u64,
    ) -> Result<Receipt, Error<D::Error>> {
        let fp = codec::fingerprint(
            4,
            &[expected_namespace, object.slot as u64, object.generation],
            &[],
        );
        if let Some(receipt) = self.preflight(operation, fp, deadline)? {
            return Ok(receipt);
        }
        self.namespace_matches(expected_namespace)?;
        let index = self.index(object)?;
        if self.hidden(object)? {
            return Err(Error::Hidden);
        }
        if let Some(stage) = self.root.stage
            && self.descendant(stage.object, object)?
        {
            return Err(Error::Busy);
        }
        self.scratch.entries[index].trashed = true;
        let revision = self.scratch.entries[index].revision;
        self.publish(
            operation,
            fp,
            self.root,
            true,
            ReceiptKind::Trashed,
            object,
            revision,
            0,
            0,
            deadline,
        )
    }
    pub fn restore(
        &mut self,
        operation: OperationId,
        expected_namespace: u64,
        object: ObjectId,
        deadline: u64,
    ) -> Result<Receipt, Error<D::Error>> {
        let fp = codec::fingerprint(
            5,
            &[expected_namespace, object.slot as u64, object.generation],
            &[],
        );
        if let Some(receipt) = self.preflight(operation, fp, deadline)? {
            return Ok(receipt);
        }
        self.namespace_matches(expected_namespace)?;
        let index = self.index(object)?;
        let entry = self.scratch.entries[index];
        if !entry.trashed {
            return Err(Error::NotTrashed);
        }
        if self.hidden(entry.parent)? {
            return Err(Error::Hidden);
        }
        if self.collision(entry.parent, entry.name, Some(object)) {
            return Err(Error::Collision);
        }
        self.scratch.entries[index].trashed = false;
        self.publish(
            operation,
            fp,
            self.root,
            true,
            ReceiptKind::Restored,
            object,
            entry.revision,
            0,
            0,
            deadline,
        )
    }
    /// Atomically restore a directly trashed object at an explicitly selected
    /// live destination/name. The destination and name are part of the durable
    /// replay fingerprint; no intermediate visible restore is published.
    pub fn restore_at(
        &mut self,
        operation: OperationId,
        expected_namespace: u64,
        object: ObjectId,
        parent: ObjectId,
        name: Name,
        deadline: u64,
    ) -> Result<Receipt, Error<D::Error>> {
        let fp = codec::fingerprint(
            11,
            &[
                expected_namespace,
                object.slot as u64,
                object.generation,
                parent.slot as u64,
                parent.generation,
            ],
            name.as_bytes(),
        );
        if let Some(receipt) = self.preflight(operation, fp, deadline)? {
            return Ok(receipt);
        }
        self.namespace_matches(expected_namespace)?;
        let index = self.index(object)?;
        let mut entry = self.scratch.entries[index];
        if !entry.trashed {
            return Err(Error::NotTrashed);
        }
        self.directory(parent)?;
        if self.hidden(parent)? {
            return Err(Error::Hidden);
        }
        if self.collision(parent, name, Some(object)) {
            return Err(Error::Collision);
        }
        if self.descendant(parent, object)? {
            return Err(Error::Depth);
        }
        for (i, existing) in self.scratch.entries.iter().enumerate() {
            if existing.kind != 0 {
                self.depth(existing.id(i), Some((object, parent)))?;
            }
        }
        entry.parent = parent;
        entry.name = name;
        entry.trashed = false;
        self.scratch.entries[index] = entry;
        self.publish(
            operation,
            fp,
            self.root,
            true,
            ReceiptKind::Restored,
            object,
            entry.revision,
            0,
            0,
            deadline,
        )
    }
    /// Irreversible removal of one trashed file or empty directory. The trusted
    /// service must hold an actual revocation/quiescence/delegation fence; this
    /// struct is an assertion for checking identity/epoch, not its evidence.
    pub fn purge(
        &mut self,
        operation: OperationId,
        fence: ReclaimFence,
        deadline: u64,
    ) -> Result<Receipt, Error<D::Error>> {
        let object = fence.object;
        let fp = codec::fingerprint(
            6,
            &[
                fence.namespace_revision,
                object.slot as u64,
                object.generation,
                fence.authority_epoch,
            ],
            &[],
        );
        if let Some(receipt) = self.preflight(operation, fp, deadline)? {
            return Ok(receipt);
        }
        self.namespace_matches(fence.namespace_revision)?;
        if fence.authority_epoch == 0 {
            return Err(Error::FenceRequired);
        }
        let index = self.index(object)?;
        let entry = self.scratch.entries[index];
        if !self.hidden(object)? {
            return Err(Error::NotTrashed);
        }
        if self.root.stage.is_some_and(|s| s.object == object) {
            return Err(Error::Busy);
        }
        if self
            .scratch
            .entries
            .iter()
            .any(|e| e.kind != 0 && e.parent == object)
        {
            return Err(Error::NotEmpty);
        }
        self.scratch.entries[index] = Entry {
            generation: entry.generation,
            ..Entry::EMPTY
        };
        self.publish(
            operation,
            fp,
            self.root,
            true,
            ReceiptKind::Purged,
            object,
            entry.revision,
            0,
            0,
            deadline,
        )
    }
    pub fn begin_write(
        &mut self,
        operation: OperationId,
        object: ObjectId,
        expected_revision: u64,
        length: u64,
        digest: Digest,
        deadline: u64,
    ) -> Result<Receipt, Error<D::Error>> {
        let fp = codec::fingerprint(
            7,
            &[
                object.slot as u64,
                object.generation,
                expected_revision,
                length,
            ],
            &digest,
        );
        if let Some(receipt) = self.preflight(operation, fp, deadline)? {
            return Ok(receipt);
        }
        let index = self.index(object)?;
        let entry = self.scratch.entries[index];
        if entry.kind != 1 {
            return Err(Error::NotFile);
        }
        if self.hidden(object)? {
            return Err(Error::Hidden);
        }
        if entry.revision != expected_revision {
            return Err(Error::Conflict);
        }
        if entry.revision >= u64::MAX - 1 {
            return Err(Error::Exhausted);
        }
        if self.root.stage.is_some() {
            return Err(Error::Busy);
        }
        if length > MAX_FILE_BYTES {
            return Err(Error::Capacity);
        }
        let chunks = chunks_for(length);
        let used: u32 = self.scratch.entries.iter().map(|e| e.chunks).sum();
        if used - entry.chunks + chunks > USABLE_CHUNKS {
            return Err(Error::NoSpace);
        }
        let start = self.allocate(chunks)?;
        let mut root = self.root;
        root.stage = Some(Stage {
            id: operation.get(),
            object,
            expected: expected_revision,
            length,
            written: 0,
            start,
            chunks,
            digest,
        });
        self.publish(
            operation,
            fp,
            root,
            false,
            ReceiptKind::Begun,
            object,
            entry.revision,
            operation.get(),
            0,
            deadline,
        )
    }
    fn allocate(&self, chunks: u32) -> Result<u32, Error<D::Error>> {
        if chunks == 0 {
            return Ok(0);
        }
        let mut candidate = 0u32;
        loop {
            if candidate
                .checked_add(chunks)
                .is_none_or(|end| end > POOL_CHUNKS)
            {
                return Err(Error::NoSpace);
            }
            let mut end = candidate;
            for entry in &self.scratch.entries {
                if entry.kind != 0 && overlap(candidate, chunks, entry.start, entry.chunks) {
                    end = end.max(entry.start + entry.chunks);
                }
            }
            if end == candidate {
                return Ok(candidate);
            }
            candidate = end;
        }
    }
    pub fn write_chunk(
        &mut self,
        operation: OperationId,
        stage_id: u64,
        offset: u64,
        bytes: &[u8],
        deadline: u64,
    ) -> Result<Receipt, Error<D::Error>> {
        let fp = codec::fingerprint(8, &[stage_id, offset], &codec::hash(bytes));
        if let Some(receipt) = self.preflight(operation, fp, deadline)? {
            return Ok(receipt);
        }
        let mut stage = self
            .root
            .stage
            .filter(|s| s.id == stage_id)
            .ok_or(Error::InvalidStage)?;
        if bytes.is_empty()
            || bytes.len() > CHUNK_BYTES
            || offset != stage.written
            || !offset.is_multiple_of(CHUNK_BYTES as u64)
            || offset + bytes.len() as u64 > stage.length
            || (bytes.len() != CHUNK_BYTES && offset + bytes.len() as u64 != stage.length)
        {
            return Err(Error::InvalidChunk);
        }
        let index = (offset / CHUNK_BYTES as u64) as u32;
        self.scratch.chunk.fill(0);
        self.scratch.chunk[..bytes.len()].copy_from_slice(bytes);
        let digest = codec::hash(&self.scratch.chunk);
        let base = DATA_START + (stage.start + index) as u64 * CHUNK_SECTORS;
        // Payload first, then durable header. Old committed data is elsewhere.
        for sector in 0..8 {
            self.scratch
                .sector
                .copy_from_slice(&self.scratch.chunk[sector * 512..sector * 512 + 512]);
            self.write_sector(base + 1 + sector as u64, deadline)?;
        }
        self.flush(deadline)?;
        codec::chunk_header(
            stage.object,
            stage.id,
            index,
            bytes.len(),
            digest,
            &mut self.scratch.sector,
        );
        self.write_sector(base, deadline)?;
        self.flush(deadline)?;
        self.load_chunk(
            stage.object,
            stage.id,
            stage.start,
            index,
            bytes.len(),
            deadline,
        )?;
        if self.scratch.chunk[..bytes.len()] != *bytes {
            self.poisoned = true;
            return Err(Error::Corrupt);
        }
        stage.written += bytes.len() as u64;
        let mut root = self.root;
        root.stage = Some(stage);
        self.publish(
            operation,
            fp,
            root,
            false,
            ReceiptKind::Chunk,
            stage.object,
            stage.expected,
            stage.id,
            stage.written,
            deadline,
        )
    }
    pub fn commit(
        &mut self,
        operation: OperationId,
        stage_id: u64,
        deadline: u64,
    ) -> Result<Receipt, Error<D::Error>> {
        let fp = codec::fingerprint(9, &[stage_id], &[]);
        if let Some(receipt) = self.preflight(operation, fp, deadline)? {
            return Ok(receipt);
        }
        let mut verifier = self.begin_verification(stage_id)?;
        self.verify_step(&mut verifier, u16::MAX, deadline)?;
        self.commit_verified(operation, &verifier, deadline)
    }
    pub fn begin_verification(&self, stage_id: u64) -> Result<CommitVerifier, Error<D::Error>> {
        self.live()?;
        let stage = self
            .root
            .stage
            .filter(|s| s.id == stage_id)
            .ok_or(Error::InvalidStage)?;
        if stage.written != stage.length {
            return Err(Error::Incomplete);
        }
        Ok(CommitVerifier {
            dataset: self.root.dataset,
            stage,
            next: 0,
            hash: Sha256::new(),
            complete: false,
        })
    }
    pub fn verify_step(
        &mut self,
        verifier: &mut CommitVerifier,
        max_chunks: u16,
        deadline: u64,
    ) -> Result<VerificationProgress, Error<D::Error>> {
        valid_deadline(deadline)?;
        self.live()?;
        if verifier.dataset != self.root.dataset || self.root.stage != Some(verifier.stage) {
            return Err(Error::InvalidStage);
        }
        if max_chunks == 0 {
            return Err(Error::InvalidChunk);
        }
        let stage = verifier.stage;
        let end = (verifier.next + max_chunks as u32).min(stage.chunks);
        while verifier.next < end {
            let index = verifier.next;
            let length = ((stage.length - index as u64 * CHUNK_BYTES as u64)
                .min(CHUNK_BYTES as u64)) as usize;
            self.load_chunk(stage.object, stage.id, stage.start, index, length, deadline)?;
            verifier.hash.update(&self.scratch.chunk[..length]);
            verifier.next += 1;
        }
        if verifier.next == stage.chunks {
            if Digest::from(verifier.hash.clone().finalize()) != stage.digest {
                return Err(Error::HashMismatch);
            }
            verifier.complete = true;
        }
        Ok(verifier.progress())
    }
    /// Final catalog publication after a private complete verifier. No whole
    /// file rescan occurs here; the exact stage remains immutable and current.
    pub fn commit_verified(
        &mut self,
        operation: OperationId,
        verifier: &CommitVerifier,
        deadline: u64,
    ) -> Result<Receipt, Error<D::Error>> {
        let stage_id = verifier.stage.id;
        let fp = codec::fingerprint(9, &[stage_id], &[]);
        if let Some(receipt) = self.preflight(operation, fp, deadline)? {
            return Ok(receipt);
        }
        if verifier.dataset != self.root.dataset || self.root.stage != Some(verifier.stage) {
            return Err(Error::InvalidStage);
        }
        if !verifier.complete {
            return Err(Error::Incomplete);
        }
        let stage = verifier.stage;
        let index = self.index(stage.object)?;
        let mut entry = self.scratch.entries[index];
        if entry.revision != stage.expected {
            return Err(Error::Conflict);
        }
        entry.start = stage.start;
        entry.chunks = stage.chunks;
        entry.length = stage.length;
        entry.digest = stage.digest;
        entry.stamp = stage.id;
        entry.revision += 1;
        self.scratch.entries[index] = entry;
        let mut root = self.root;
        root.stage = None;
        self.publish(
            operation,
            fp,
            root,
            true,
            ReceiptKind::Committed,
            stage.object,
            entry.revision,
            stage.id,
            stage.length,
            deadline,
        )
    }
    pub fn abort(
        &mut self,
        operation: OperationId,
        stage_id: u64,
        deadline: u64,
    ) -> Result<Receipt, Error<D::Error>> {
        let fp = codec::fingerprint(10, &[stage_id], &[]);
        if let Some(receipt) = self.preflight(operation, fp, deadline)? {
            return Ok(receipt);
        }
        let stage = self
            .root
            .stage
            .filter(|s| s.id == stage_id)
            .ok_or(Error::InvalidStage)?;
        let mut root = self.root;
        root.stage = None;
        self.publish(
            operation,
            fp,
            root,
            false,
            ReceiptKind::Aborted,
            stage.object,
            stage.expected,
            stage.id,
            stage.written,
            deadline,
        )
    }
    /// Returns only verified bytes. The caller must discard its output on Err;
    /// an error may follow verification/copy of the first of two chunks.
    pub fn read(
        &mut self,
        object: ObjectId,
        expected_revision: u64,
        offset: u64,
        out: &mut [u8],
        deadline: u64,
    ) -> Result<usize, Error<D::Error>> {
        valid_deadline(deadline)?;
        self.live()?;
        if out.len() > CHUNK_BYTES {
            return Err(Error::InvalidChunk);
        }
        let entry = self.scratch.entries[self.index(object)?];
        if entry.kind != 1 {
            return Err(Error::NotFile);
        }
        if entry.revision != expected_revision {
            return Err(Error::Conflict);
        }
        if offset > entry.length {
            return Err(Error::InvalidChunk);
        }
        let length = out.len().min((entry.length - offset) as usize);
        let mut copied = 0;
        while copied < length {
            let position = offset + copied as u64;
            let chunk = (position / CHUNK_BYTES as u64) as u32;
            let inside = (position % CHUNK_BYTES as u64) as usize;
            let valid = ((entry.length - chunk as u64 * CHUNK_BYTES as u64).min(CHUNK_BYTES as u64))
                as usize;
            self.load_chunk(object, entry.stamp, entry.start, chunk, valid, deadline)?;
            let count = (length - copied).min(valid - inside);
            out[copied..copied + count]
                .copy_from_slice(&self.scratch.chunk[inside..inside + count]);
            copied += count;
        }
        Ok(length)
    }
    fn load_chunk(
        &mut self,
        object: ObjectId,
        stamp: u64,
        start: u32,
        index: u32,
        length: usize,
        deadline: u64,
    ) -> Result<(), Error<D::Error>> {
        let base = DATA_START + (start + index) as u64 * CHUNK_SECTORS;
        self.read_sector(base, deadline)?;
        let expected =
            codec::decode_chunk_header(&self.scratch.sector, object, stamp, index, length)
                .ok_or_else(|| {
                    self.poisoned = true;
                    Error::Corrupt
                })?;
        for sector in 0..8 {
            self.read_sector(base + 1 + sector as u64, deadline)?;
            self.scratch.chunk[sector * 512..sector * 512 + 512]
                .copy_from_slice(&self.scratch.sector);
        }
        if codec::hash(&self.scratch.chunk) != expected
            || self.scratch.chunk[length..].iter().any(|b| *b != 0)
        {
            self.poisoned = true;
            return Err(Error::Corrupt);
        }
        Ok(())
    }
    pub fn scrub_file(&mut self, object: ObjectId, deadline: u64) -> Result<(), Error<D::Error>> {
        valid_deadline(deadline)?;
        self.live()?;
        let entry = self.scratch.entries[self.index(object)?];
        if entry.kind != 1 {
            return Err(Error::NotFile);
        }
        self.verify_file(object, entry, deadline)
    }
    /// Explicit bounded checkpoint validation before resuming an interrupted
    /// stage. Metadata alone is not a newly verified content-progress claim.
    pub fn verify_staged_chunk(
        &mut self,
        stage_id: u64,
        index: u32,
        deadline: u64,
    ) -> Result<(), Error<D::Error>> {
        valid_deadline(deadline)?;
        self.live()?;
        let stage = self
            .root
            .stage
            .filter(|s| s.id == stage_id)
            .ok_or(Error::InvalidStage)?;
        if index >= chunks_for(stage.written) {
            return Err(Error::InvalidChunk);
        }
        let length =
            ((stage.length - index as u64 * CHUNK_BYTES as u64).min(CHUNK_BYTES as u64)) as usize;
        self.load_chunk(stage.object, stage.id, stage.start, index, length, deadline)
    }
    fn verify_file(
        &mut self,
        object: ObjectId,
        entry: Entry,
        deadline: u64,
    ) -> Result<(), Error<D::Error>> {
        let mut hash = Sha256::new();
        for index in 0..entry.chunks {
            let length = ((entry.length - index as u64 * CHUNK_BYTES as u64)
                .min(CHUNK_BYTES as u64)) as usize;
            self.load_chunk(object, entry.stamp, entry.start, index, length, deadline)?;
            hash.update(&self.scratch.chunk[..length]);
        }
        if Digest::from(hash.finalize()) != entry.digest {
            self.poisoned = true;
            return Err(Error::Corrupt);
        }
        Ok(())
    }
}
