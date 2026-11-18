//! Actual Images continuation with a model of separate permanent RO receipts.
//! This tests protocol/availability, not hardware mapping or Kernel quiescence.
use super::*;
const B: &[u8] = include_bytes!("../../../fixtures/acquisition/phase-b/hello.zion");
const C: &[u8] = include_bytes!("../../../fixtures/acquisition/phase-c/hello.zion");

struct Permanent {
    staging: Model,
    readers: [Option<Vec<u8>>; 2],
    short_read: bool,
}
impl Io for Permanent {
    fn control(&mut self, op: Operation, a: u64, b: u64) -> CapReply {
        let r = self.staging.control(op, a, b);
        if op == Operation::Verify
            && r.status == 0
            && r.serial == 0
            && r.value == 0
            && r.capability != 0
        {
            self.readers[a as usize - 1] = Some(self.staging.bytes.clone());
        }
        r
    }
    fn write_header(&mut self, bytes: &[u8; abi::HEADER_BYTES]) -> Result<(), IoError> {
        let h = Header::decode(bytes).ok_or(IoError)?;
        self.staging.bytes.resize(h.bytes as usize, 0);
        self.staging.write_header(bytes)
    }
    fn write_staging(&mut self, offset: usize, bytes: &[u8]) -> Result<(), IoError> {
        self.staging.write_staging(offset, bytes)
    }
    fn readonly(&self, slot: usize, bytes: usize) -> Result<&[u8], IoError> {
        let data = self
            .readers
            .get(slot)
            .and_then(Option::as_ref)
            .filter(|data| data.len() == bytes)
            .ok_or(IoError)?;
        Ok(if self.short_read {
            &data[..data.len() - 1]
        } else {
            data
        })
    }
}
fn actual_header(bytes: &[u8]) -> Header {
    use sha2::{Digest, Sha256};
    let p = ev_zion::Package::parse(bytes).unwrap();
    let mut descriptor = Sha256::new();
    abi::app_descriptor_transcript(&p.executable().digest, |b| descriptor.update(b));
    Header {
        bytes: bytes.len() as u64,
        elf_offset: (p.executable().bytes.as_ptr() as usize - bytes.as_ptr() as usize) as u64,
        elf_bytes: p.executable().bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
        elf_sha256: p.executable().digest,
        package: p.id().bytes(),
        abi: ev_userspace_contract::ABI,
        descriptor: descriptor.finalize().into(),
    }
}
fn sequence(bytes: &[u8], slot: u64, writer: u64, reader: u64) -> Vec<CapReply> {
    let mut replies = vec![reply(slot, writer)];
    let mut n = 0;
    for chunk in bytes.chunks(4096) {
        n += chunk.len();
        replies.push(reply(n as u64, 0));
    }
    let mut remaining = (bytes.len() as u64).div_ceil(4096) * 4096;
    replies.push(reply(remaining, 0));
    while remaining != 0 {
        remaining -= 4096;
        replies.push(reply(remaining, if remaining == 0 { reader } else { 0 }));
    }
    replies.push(reply(0, 0));
    replies
}
fn owner() -> Images<Permanent> {
    let base = image(sequence(B, 1, 20, 21));
    Images::new(
        Permanent {
            staging: base.io,
            readers: [None, None],
            short_read: false,
        },
        BASE,
    )
    .unwrap()
}
fn seal(i: &mut Images<Permanent>, bytes: &[u8], tick: &mut u64) -> usize {
    let slot = i.begin(actual_header(bytes), *tick, 10_000).unwrap();
    for chunk in bytes.chunks(4096) {
        *tick += 1;
        i.write_chunk(slot, *tick, chunk).unwrap();
    }
    *tick += 1;
    i.seal(slot, *tick).unwrap();
    loop {
        *tick += 1;
        if i.verify_step(slot, *tick).unwrap() {
            return slot;
        }
    }
}
fn registered_b() -> (Images<Permanent>, u64) {
    let mut i = owner();
    i.initialize(1).unwrap();
    let mut tick = 2;
    assert_eq!(seal(&mut i, B, &mut tick), 0);
    tick += 1;
    assert_eq!(i.register(0, tick).unwrap(), 21);
    (i, tick + 1)
}
fn check_fence(i: &mut Images<Permanent>, tick: u64) {
    assert!(i.failed());
    assert_eq!(i.bytes(0).unwrap(), B);
    assert_eq!(i.package(0).unwrap().id().bytes(), actual_header(B).package);
    assert_eq!(i.registered_capability(0), Some(21));
    assert_eq!(i.registered_capability(1), None);
    assert_eq!(i.registered_capability(2), None);
    assert!(matches!(i.bytes(1), Err(Error::State)));
    assert!(matches!(i.bytes(2), Err(Error::Shape)));
    let calls = i.io.staging.calls.len();
    let writes = i.io.staging.writes;
    assert_eq!(i.begin(actual_header(C), tick, 10_000), Err(Error::State));
    assert_eq!(i.write_chunk(1, tick, b"x"), Err(Error::State));
    assert_eq!(i.seal(1, tick), Err(Error::State));
    assert_eq!(i.verify_step(1, tick), Err(Error::State));
    assert_eq!(i.register(1, tick), Err(Error::State));
    assert_eq!(i.abort(1, tick), Err(Error::State));
    assert_eq!(i.initialize(tick), Err(Error::State));
    assert_eq!(i.io.staging.calls.len(), calls);
    assert_eq!(i.io.staging.writes, writes);
}
#[test]
fn failed_c_write_preserves_registered_b_but_never_retries_or_exposes_c() {
    let (mut i, mut tick) = registered_b();
    i.io.staging.replies.push_back(reply(2, 22));
    assert_eq!(i.begin(actual_header(C), tick, 10_000), Ok(1));
    i.io.staging.fail_staging = true;
    tick += 1;
    assert_eq!(i.write_chunk(1, tick, &C[..4096]), Err(Error::Io));
    check_fence(&mut i, tick + 1);
}
#[test]
fn unknown_c_registration_or_wrong_cap_never_promotes_its_sealed_bytes() {
    for bad in [
        CapReply {
            status: 1,
            value: 3,
            capability: 0,
            serial: 0,
        },
        reply(0, 21),
        CapReply {
            status: 0,
            value: 0,
            capability: 0,
            serial: 1,
        },
    ] {
        let (mut i, mut tick) = registered_b();
        let mut replies = sequence(C, 2, 22, 23);
        *replies.last_mut().unwrap() = bad;
        i.io.staging.replies.extend(replies);
        assert_eq!(seal(&mut i, C, &mut tick), 1);
        assert!(i.package(1).is_ok());
        assert_eq!(i.register(1, tick + 1), Err(Error::Reply));
        check_fence(&mut i, tick + 2);
    }
}
#[test]
fn registered_reader_still_requires_exact_actual_slot_and_length_receipt() {
    let (mut i, tick) = registered_b();
    i.io.staging.replies.push_back(reply(1, 22)); // Old slot is not a fresh Begin.
    assert_eq!(i.begin(actual_header(C), tick, 10_000), Err(Error::Reply));
    check_fence(&mut i, tick + 1);
    assert!(i.io.readonly(0, B.len() - 1).is_err());
    assert!(i.io.readonly(1, B.len()).is_err());
    i.io.short_read = true;
    assert!(matches!(i.bytes(0), Err(Error::Shape)));
    i.io.short_read = false;
    i.io.readers[0] = None;
    assert!(matches!(i.bytes(0), Err(Error::Io)));
}
