extern crate std;
use super::*;
use std::{vec, vec::Vec};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Power,
    Offline,
    Bounds,
    Deadline,
}
#[derive(Clone, Copy)]
enum Cut {
    Before,
    After,
    Torn,
}
#[derive(Clone)]
struct Disk {
    durable: Vec<Sector>,
    cache: Vec<Sector>,
    steps: usize,
    writes: usize,
    cut: Option<(usize, Cut)>,
    offline: bool,
    trace: Vec<(char, u64)>,
}
impl Disk {
    fn blank() -> Self {
        let mut bytes = vec![[0x92; 512]; 8192];
        for s in &mut bytes[128..142] {
            s.fill(0);
        }
        for s in &mut bytes[256..] {
            s.fill(0);
        }
        Self {
            cache: bytes.clone(),
            durable: bytes,
            steps: 0,
            writes: 0,
            cut: None,
            offline: false,
            trace: vec![],
        }
    }
    fn cold(mut self) -> Self {
        self.cache.clone_from(&self.durable);
        self.steps = 0;
        self.cut = None;
        self.offline = false;
        self.trace.clear();
        self
    }
    fn step(&mut self, kind: char, lba: u64, deadline: u64) -> Result<Option<Cut>, Fault> {
        if self.offline {
            return Err(Fault::Offline);
        }
        if deadline == 0 || deadline == u64::MAX {
            return Err(Fault::Deadline);
        }
        if lba >= 8192 {
            return Err(Fault::Bounds);
        }
        self.steps += 1;
        self.trace.push((kind, lba));
        Ok(self.cut.filter(|(n, _)| *n == self.steps).map(|(_, c)| c))
    }
    fn lost(&mut self) -> Result<(), Fault> {
        self.offline = true;
        Err(Fault::Power)
    }
}
struct Device<'a> {
    disk: &'a mut Disk,
    start: u64,
    len: u64,
}
impl SectorIo for Device<'_> {
    type Error = Fault;
    fn sectors(&self) -> u64 {
        self.len
    }
    fn read(&mut self, lba: u64, out: &mut Sector, d: u64) -> Result<(), Fault> {
        if lba >= self.len {
            return Err(Fault::Bounds);
        }
        let physical = self.start + lba;
        if self.disk.step('r', physical, d)?.is_some() {
            return self.disk.lost();
        }
        *out = self.disk.cache[physical as usize];
        Ok(())
    }
    fn write(&mut self, lba: u64, b: &Sector, d: u64) -> Result<(), Fault> {
        if lba >= self.len {
            return Err(Fault::Bounds);
        }
        let p = self.start + lba;
        let cut = self.disk.step('w', p, d)?;
        if matches!(cut, Some(Cut::Before)) {
            return self.disk.lost();
        }
        self.disk.writes += 1;
        self.disk.cache[p as usize] = *b;
        if let Some(c) = cut {
            match c {
                Cut::After => self.disk.durable[p as usize] = *b,
                Cut::Torn => self.disk.durable[p as usize][..257].copy_from_slice(&b[..257]),
                Cut::Before => unreachable!(),
            }
            return self.disk.lost();
        }
        Ok(())
    }
    fn flush(&mut self, d: u64) -> Result<(), Fault> {
        let cut = self.disk.step('f', self.start, d)?;
        if matches!(cut, Some(Cut::Before)) {
            return self.disk.lost();
        }
        if matches!(cut, Some(Cut::Torn)) {
            for i in (0..8192).step_by(2) {
                self.disk.durable[i] = self.disk.cache[i];
            }
            return self.disk.lost();
        }
        self.disk.durable.clone_from(&self.disk.cache);
        if cut.is_some() {
            return self.disk.lost();
        }
        Ok(())
    }
}
impl Backend for Disk {
    type Error = Fault;
    type Device<'a> = Device<'a>;
    fn device(&mut self, a: Area) -> Device<'_> {
        let (start, len) = match a {
            Area::Checkpoint => (128, 14),
            Area::Objects => (256, OBJECT_SECTORS),
        };
        Device {
            disk: self,
            start,
            len,
        }
    }
}
fn creation() -> GenerationManifest {
    GenerationManifest {
        generation: ev_store::GenerationId::new(1).unwrap(),
        cohort: [1; 32],
        supervisor_image: [2; 32],
        abi: [3; 32],
        health_contract: [4; 32],
        health_version: 1,
        required_checks: 3,
    }
}
fn transfer() -> TransferCut {
    TransferCut::new(0, 100_000).unwrap()
}
fn metadata() -> MetadataCut {
    transfer().metadata(1).unwrap()
}
fn cut() -> IoCut {
    transfer().child(1, 1024).unwrap()
}
fn format(d: Disk) -> Arena<Disk> {
    let mut p = Provisioner::new(d, creation(), transfer()).unwrap_or_else(|_| panic!("provision"));
    while p.remaining() != 0 {
        p.scan(cut()).unwrap();
    }
    p.finish(metadata())
        .unwrap_or_else(|e| panic!("format {:?}", e.error))
}
fn open(d: Disk) -> Arena<Disk> {
    Arena::open(d.cold(), creation(), metadata()).unwrap_or_else(|e| panic!("open {:?}", e.error))
}
fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
fn publish(a: &mut Arena<Disk>, payload: &[u8]) -> Result<Object, Error<Fault>> {
    let expected = a.head_digest();
    let mut s = a.begin(
        expected,
        payload.len() as u64,
        sha(payload),
        transfer(),
        metadata(),
    )?;
    for chunk in payload.chunks(4096) {
        s.write_chunk(chunk, cut())?;
    }
    let mut r = s.seal(cut())?;
    let mut out = [0; 4096];
    while r.remaining() != 0 {
        r.read_chunk(&mut out, cut())?;
    }
    let v = r.finish()?;
    let h = v.current_head();
    v.publish(h, metadata())
}
fn bytes(a: &mut Arena<Disk>, o: Object) -> Result<Vec<u8>, Error<Fault>> {
    let mut r = a.reader(o, transfer(), cut())?;
    let mut b = [0; 4096];
    let mut out = vec![];
    while r.remaining() != 0 {
        let n = r.read_chunk(&mut b, cut())?;
        out.extend_from_slice(&b[..n]);
    }
    r.finish()?.release();
    Ok(out)
}
fn outside_unchanged(d: &Disk, old: &[Sector]) {
    for (i, (a, b)) in d.durable.iter().zip(old).enumerate() {
        if !(128..142).contains(&i) && !(256..8192).contains(&i) {
            assert_eq!(a, b, "outside {i}");
        }
    }
}
#[test]
fn reserve_then_stream_header_last_readback_and_cold_pointer_are_real_store() {
    let mut a = format(Disk::blank());
    let before = a.backend.durable.clone();
    a.backend.trace.clear();
    let payload = vec![0x3a; 8701];
    let o = publish(&mut a, &payload).unwrap();
    assert_eq!(a.published_metadata(), Some(o));
    assert_eq!(bytes(&mut a, o).unwrap(), payload);
    let trace = &a.backend.trace;
    let header = trace
        .iter()
        .position(|&(k, l)| k == 'w' && l == 256)
        .unwrap();
    assert!(trace[..header].iter().any(|&(k, l)| k == 'w' && l == 257));
    assert!(trace[..header].iter().any(|&(k, _)| k == 'f'));
    outside_unchanged(&a.backend, &before);
    let mut a = open(a.into_backend());
    assert_eq!(a.published_metadata(), Some(o));
    assert_eq!(bytes(&mut a, o).unwrap(), payload);
}
#[test]
fn foreign_nonblank_unformatted_never_trigger_format() {
    let d = Disk::blank();
    assert!(matches!(
        Arena::open(d, creation(), metadata()).err().unwrap().error,
        Error::Store(ev_store::Error::Unformatted)
    ));
    let mut d = Disk::blank();
    d.cache[8191][511] = 1;
    d.durable = d.cache.clone();
    let mut p = Provisioner::new(d, creation(), transfer()).unwrap_or_else(|_| panic!());
    let mut result = Ok(());
    while p.remaining() != 0 && result.is_ok() {
        result = p.scan(cut());
    }
    assert_eq!(result, Err(Error::NotBlank));
    assert_eq!(p.into_backend().writes, 0);
    let mut a = format(Disk::blank());
    a.backend.trace.clear();
    let mut foreign = creation();
    foreign.cohort = [9; 32];
    let failed = Arena::open(a.into_backend(), foreign, metadata())
        .err()
        .unwrap();
    assert_eq!(failed.error, Error::Store(ev_store::Error::Conflict));
    assert!(failed.backend.trace.iter().all(|(kind, _)| *kind != 'w'));
}
#[test]
fn abandoned_reserved_extent_is_never_reused_and_capacity_is_bounded() {
    let mut a = format(Disk::blank());
    let h = a.head_digest();
    {
        let mut s = a
            .begin(h, 513, sha(&[7; 513]), transfer(), metadata())
            .unwrap();
        s.write_chunk(&[7; 512], cut()).unwrap();
    }
    assert_eq!(a.reserved_sectors(), 3);
    let mut a = open(a.into_backend());
    let o = publish(&mut a, &[2; 1]).unwrap();
    assert_eq!(o.start(), 3);
    assert_eq!(a.reserved_sectors(), 5);
    let prior = a.head_digest();
    assert!(matches!(
        a.begin(prior, MAX_OBJECT_BYTES + 1, [1; 32], transfer(), metadata()),
        Err(Error::Bounds)
    ));
    assert_eq!(a.head_digest(), prior);
    for _ in 0..15 {
        let h = a.head_digest();
        let _reserved = a
            .begin(h, MAX_OBJECT_BYTES, [1; 32], transfer(), metadata())
            .unwrap();
    }
    let high = a.reserved_sectors();
    let h = a.head_digest();
    assert!(matches!(
        a.begin(h, MAX_OBJECT_BYTES, [1; 32], transfer(), metadata()),
        Err(Error::NoSpace)
    ));
    assert_eq!(a.reserved_sectors(), high);
}
#[test]
fn original_transfer_and_child_cuts_do_not_slide_and_invalid_chunks_do_no_io() {
    assert!(TransferCut::new(0, 0).is_err());
    assert!(TransferCut::new(1, u64::MAX).is_err());
    let t = TransferCut::new(10, 5000).unwrap();
    assert_eq!(t.child(4500, 1024).unwrap().end(), 5000);
    assert!(t.child(5000, 1).is_err());
    assert!(t.child(9, 1).is_err());
    assert!(t.child(10, 1025).is_err());
    let mut a = format(Disk::blank());
    let h = a.head_digest();
    let mut s = a
        .begin(h, 1025, sha(&[1; 1025]), transfer(), metadata())
        .unwrap();
    let count = s.arena.backend.steps;
    assert_eq!(s.write_chunk(&[1; 1], cut()), Err(Error::Bounds));
    assert_eq!(s.write_chunk(&[1; 4097], cut()), Err(Error::Bounds));
    let foreign = TransferCut::new(0, 100_001)
        .unwrap()
        .child(1, 1024)
        .unwrap();
    assert_eq!(s.write_chunk(&[1; 512], foreign), Err(Error::Deadline));
    assert_eq!(s.arena.backend.steps, count);
    s.write_chunk(&[1; 1024], cut()).unwrap();
    s.write_chunk(&[1], cut()).unwrap();
    let mut r = s.seal(cut()).unwrap();
    let mut out = [0; 4096];
    assert_eq!(r.read_chunk(&mut out, cut()).unwrap(), 1025);
    let v = r.finish().unwrap();
    let wrong = [7; 32];
    assert_eq!(v.publish(wrong, metadata()), Err(Error::Conflict));
    assert_eq!(a.published_metadata(), None);
}
#[test]
fn incomplete_hash_mismatch_header_or_padding_corruption_never_publish() {
    let mut a = format(Disk::blank());
    let h = a.head_digest();
    let s = a.begin(h, 1, sha(&[7]), transfer(), metadata()).unwrap();
    assert!(matches!(s.seal(cut()), Err(Error::Incomplete)));
    let h = a.head_digest();
    let mut s = a.begin(h, 1, sha(&[7]), transfer(), metadata()).unwrap();
    s.write_chunk(&[8], cut()).unwrap();
    assert!(matches!(s.seal(cut()), Err(Error::Hash)));
    let o = publish(&mut a, &[9]).unwrap();
    let head = a.head_digest();
    a.backend.cache[(256 + o.start + 1) as usize][511] = 1;
    let mut r = a.reader(o, transfer(), cut()).unwrap();
    assert_eq!(r.read_chunk(&mut [0; 512], cut()), Err(Error::Corrupt));
    assert!(a.poisoned());
    assert_eq!(a.head_digest(), head);
    let mut d = a.into_backend().cold();
    d.cache[(256 + o.start) as usize][9] = 1;
    d.durable = d.cache.clone();
    let mut a = open(d);
    assert!(matches!(
        a.reader(o, transfer(), cut()),
        Err(Error::Corrupt)
    ));
    assert!(a.poisoned());
}
#[test]
fn every_actual_io_interruption_preserves_old_or_complete_pointer_and_never_reuses_written_reservation()
 {
    let mut a = format(Disk::blank());
    let old = publish(&mut a, b"previous trusted bundle").unwrap();
    let baseline = a.into_backend().cold();
    let outside = baseline.durable.clone();
    let payload = vec![0x66; 1537];
    let mut full = open(baseline.clone());
    full.backend.steps = 0;
    full.backend.trace.clear();
    let new = publish(&mut full, &payload).unwrap();
    let steps = full.backend.steps;
    assert!(steps > 50);
    std::println!("arena matrix: {steps} actual IO boundaries x3 interruption modes");
    for boundary in 1..=steps {
        for mode in [Cut::Before, Cut::After, Cut::Torn] {
            let mut a = open(baseline.clone());
            a.backend.steps = 0;
            a.backend.trace.clear();
            a.backend.cut = Some((boundary, mode));
            let result = publish(&mut a, &payload);
            assert!(result.is_err(), "cut {boundary} unexpectedly passed");
            assert!(a.poisoned(), "uncertain cut {boundary} not fenced");
            let before = a.backend.steps;
            let h = a.head_digest();
            assert!(matches!(
                a.begin(h, 1, sha(&[1]), transfer(), metadata()),
                Err(Error::Recovery)
            ));
            assert_eq!(a.backend.steps, before);
            let mut a = open(a.into_backend());
            let found = a.published_metadata().unwrap();
            assert!(found == old || found == new, "hybrid pointer at {boundary}");
            if found == new {
                assert_eq!(bytes(&mut a, found).unwrap(), payload);
            } else {
                assert_eq!(bytes(&mut a, found).unwrap(), b"previous trusted bundle");
            }
            let high = a.reserved_sectors();
            let disk = a.into_backend();
            for lba in (256 + old.sectors)..8192 {
                if disk.durable[lba as usize].iter().any(|v| *v != 0) {
                    assert!(
                        lba < 256 + high,
                        "unreserved durable bytes after cut {boundary}"
                    );
                }
            }
            outside_unchanged(&disk, &outside);
        }
    }
}
#[test]
fn maximum_object_streams_with_fresh_children_and_silent_body_change_fails_full_readback() {
    let mut a = format(Disk::blank());
    let original = TransferCut::new(100, 90_000).unwrap();
    let payload = vec![0x41; MAX_OBJECT_BYTES as usize];
    let mut s = a
        .begin(
            a.head_digest(),
            MAX_OBJECT_BYTES,
            sha(&payload),
            original,
            original.metadata(100).unwrap(),
        )
        .unwrap();
    for (i, chunk) in payload.chunks(MAX_CHUNK_BYTES).enumerate() {
        s.write_chunk(chunk, original.child(200 + i as u64 * 10, 1024).unwrap())
            .unwrap();
    }
    let mut r = s.seal(original.child(1000, 1024).unwrap()).unwrap();
    let mut out = [0; 4096];
    let mut index = 0;
    while r.remaining() != 0 {
        let n = r
            .read_chunk(&mut out, original.child(1100 + index * 10, 1024).unwrap())
            .unwrap();
        assert_eq!(
            &out[..n],
            &payload[index as usize * 4096..index as usize * 4096 + n]
        );
        index += 1;
    }
    assert_eq!(index, 64);
    let v = r.finish().unwrap();
    let expected = v.current_head();
    let old = v
        .publish(expected, original.metadata(2000).unwrap())
        .unwrap();
    let high = a.head_digest();
    let mut s = a
        .begin(high, 513, sha(&[7; 513]), transfer(), metadata())
        .unwrap();
    s.write_chunk(&[7; 513], cut()).unwrap();
    let mut r = s.seal(cut()).unwrap();
    let physical = (256 + r.object.start + 1) as usize;
    r.arena.backend.cache[physical][3] ^= 1;
    assert_eq!(r.read_chunk(&mut out, cut()).unwrap(), 513);
    assert!(matches!(r.finish(), Err(Error::Hash)));
    assert!(a.poisoned());
    assert_eq!(a.published_metadata(), Some(old));
    for bad in [
        Object::checked(0, 0, [1; 32]),
        Object::checked(0, 1, [0; 32]),
        Object::checked(OBJECT_SECTORS, 1, [1; 32]),
        Object::checked(u64::MAX, 1, [1; 32]),
    ] {
        assert!(bad.is_err());
    }
}
#[test]
fn checkpoint_reserved_bytes_and_impossible_highwater_do_not_become_an_arena() {
    let good = codec::encode_head(Head::EMPTY);
    for offset in [0, 8, 9, 15, 32, 33, 39, 40, 95, 96, 255] {
        let mut changed = good;
        changed[offset] ^= 1;
        assert!(codec::decode_head(&changed).is_none(), "offset {offset}");
    }
    for head in [
        Head {
            high: 0,
            revision: 1,
            published: None,
        },
        Head {
            high: 1,
            revision: 1,
            published: None,
        },
        Head {
            high: OBJECT_SECTORS + 1,
            revision: 1,
            published: None,
        },
    ] {
        assert!(codec::decode_head(&codec::encode_head(head)).is_none());
    }
}
#[test]
fn stable_format_identity_is_exact_description_hash() {
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(FORMAT_ABI_DESCRIPTION)),
        FORMAT_ABI
    );
}
#[test]
fn metadata_aggregate_is_distinct_original_bounded_and_foreign_cuts_publish_no_io() {
    let t = TransferCut::new(10, 50_000).unwrap();
    assert_eq!(t.child(10, 1024).unwrap().end(), 1034);
    assert_eq!(t.metadata(10).unwrap().end(), 8202);
    assert!(t.child(10, 8192).is_err());
    assert_eq!(
        TransferCut::new(10, 1000)
            .unwrap()
            .metadata(900)
            .unwrap()
            .end(),
        1000
    );
    assert!(t.metadata(9).is_err());
    assert!(t.metadata(50_000).is_err());
    assert!(
        TransferCut::new(u64::MAX - 20, u64::MAX - 1)
            .unwrap()
            .metadata(u64::MAX - 10)
            .is_err()
    );
    let mut a = format(Disk::blank());
    let expected = a.head_digest();
    let steps = a.backend.steps;
    let foreign = TransferCut::new(0, 100_001).unwrap().metadata(1).unwrap();
    assert!(matches!(
        a.begin(expected, 1, sha(&[1]), transfer(), foreign),
        Err(Error::Deadline)
    ));
    assert_eq!(a.backend.steps, steps);
    assert_eq!(a.head_digest(), expected);
    let mut s = a
        .begin(expected, 1, sha(&[1]), transfer(), metadata())
        .unwrap();
    s.write_chunk(&[1], cut()).unwrap();
    let mut r = s.seal(cut()).unwrap();
    r.read_chunk(&mut [0; 512], cut()).unwrap();
    let steps = r.arena.backend.steps;
    let v = r.finish().unwrap();
    let current = v.current_head();
    assert_eq!(v.publish(current, foreign), Err(Error::Deadline));
    assert_eq!(a.backend.steps, steps);
    assert_eq!(a.head_digest(), current);
    assert_eq!(a.published_metadata(), None);
    let p = Provisioner::new(Disk::blank(), creation(), transfer()).unwrap_or_else(|_| panic!());
    let rejected = p.finish(foreign).err().unwrap();
    assert_eq!(rejected.error, Error::Deadline);
    assert_eq!(rejected.backend.steps, 0);
    assert_eq!(rejected.backend.writes, 0);
}

#[test]
fn owned_continuations_move_between_steps_and_cold_read_exact_large_payload() {
    let a = format(Disk::blank());
    let before = a.backend.durable.clone();
    let expected = a.head_digest();
    let payload = vec![0x6b; MAX_OBJECT_BYTES as usize];
    let mut stage = a
        .begin_owned(
            expected,
            payload.len() as u64,
            sha(&payload),
            transfer(),
            metadata(),
        )
        .unwrap_or_else(|r| panic!("reserve {:?}", r.error));
    let foreign = TransferCut::new(1, 100_001)
        .unwrap()
        .child(2, 1024)
        .unwrap();
    assert_eq!(
        stage.write_chunk(&payload[..4096], foreign),
        Err(Error::Deadline)
    );
    assert_eq!(stage.remaining(), MAX_OBJECT_BYTES);
    // These values can be retained in a controller enum without a self-borrow.
    let mut slot = Some(stage);
    for chunk in payload.chunks(4096) {
        let mut next = slot.take().unwrap();
        next.write_chunk(chunk, cut()).unwrap();
        slot = Some(next);
    }
    let mut reader = slot
        .take()
        .unwrap()
        .seal(cut())
        .unwrap_or_else(|r| panic!("seal {:?}", r.error));
    let mut out = [0; 4096];
    let mut actual = vec![];
    while reader.remaining() != 0 {
        let n = reader.read_chunk(&mut out, cut()).unwrap();
        actual.extend_from_slice(&out[..n]);
    }
    assert_eq!(actual, payload);
    let verified = reader
        .finish()
        .unwrap_or_else(|r| panic!("readback {:?}", r.error));
    let expected = verified.current_head();
    let (a, object) = verified
        .publish(expected, metadata())
        .unwrap_or_else(|r| panic!("publish {:?}", r.error));
    outside_unchanged(&a.backend, &before);
    let mut cold = open(a.into_backend());
    assert_eq!(cold.published_metadata(), Some(object));
    assert_eq!(bytes(&mut cold, object).unwrap(), payload);
}
#[test]
fn failed_owned_reservation_retains_actual_io_owner_poison_and_never_retries() {
    let mut a = format(Disk::blank());
    let head = a.head_digest();
    let steps = a.backend.steps;
    a.backend.cut = Some((steps + 1, Cut::After));
    let rejected = a
        .begin_owned(head, 512, sha(&[4; 512]), transfer(), metadata())
        .err()
        .unwrap();
    assert!(rejected.arena.poisoned());
    assert_eq!(rejected.arena.backend.steps, steps + 1);
    assert_eq!(rejected.arena.head_digest(), head);
    let rejected = rejected
        .arena
        .begin_owned(head, 512, sha(&[4; 512]), transfer(), metadata())
        .err()
        .unwrap();
    assert_eq!(rejected.error, Error::Recovery);
    assert_eq!(rejected.arena.backend.steps, steps + 1);
    assert_eq!(rejected.arena.published_metadata(), None);
}
#[test]
fn owned_abandon_and_unsealed_read_refusal_keep_original_durable_highwater() {
    let a = format(Disk::blank());
    let head = a.head_digest();
    let stage = a
        .begin_owned(head, 512, sha(&[9; 512]), transfer(), metadata())
        .unwrap_or_else(|_| panic!());
    let mut a = stage.abandon();
    assert_eq!(a.reserved_sectors(), 2);
    assert!(a.published_metadata().is_none());
    let expected = a.head_digest();
    let object = {
        let stage = a
            .begin(expected, 512, sha(&[7; 512]), transfer(), metadata())
            .unwrap();
        stage.object
    };
    // Abandonment never recycles the earlier unpublished extent.
    assert_eq!(object.start(), 2);
    let a = open(a.into_backend());
    let high = a.reserved_sectors();
    assert_eq!(high, 4);
    let reader = a.reader_owned(object, transfer(), cut()).err().unwrap();
    // Header was never sealed; owner is retained and no publication appears.
    assert!(matches!(reader.error, Error::Corrupt));
    assert_eq!(reader.arena.reserved_sectors(), high);
    assert_eq!(reader.arena.published_metadata(), None);
}
