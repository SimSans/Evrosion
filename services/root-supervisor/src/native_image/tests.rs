extern crate std;
use super::*;
use std::{collections::VecDeque, vec, vec::Vec};
mod registered;
struct Model {
    replies: VecDeque<CapReply>,
    calls: Vec<(Operation, u64, u64)>,
    writes: usize,
    bytes: Vec<u8>,
    fail_staging: bool,
}
impl Io for Model {
    fn control(&mut self, op: Operation, a: u64, b: u64) -> CapReply {
        self.calls.push((op, a, b));
        self.replies.pop_front().unwrap()
    }
    fn write_header(&mut self, _: &[u8; 256]) -> Result<(), IoError> {
        self.writes += 1;
        Ok(())
    }
    fn write_staging(&mut self, at: usize, b: &[u8]) -> Result<(), IoError> {
        self.writes += 1;
        if self.fail_staging {
            self.bytes[at] = b[0];
            return Err(IoError);
        }
        self.bytes[at..at + b.len()].copy_from_slice(b);
        Ok(())
    }
    fn readonly(&self, _: usize, n: usize) -> Result<&[u8], IoError> {
        self.bytes.get(..n).ok_or(IoError)
    }
}
const BASE: u64 = 0x8000000000;
fn reply(value: u64, capability: u64) -> CapReply {
    CapReply {
        status: 0,
        value,
        capability,
        serial: 0,
    }
}
fn image(extra: impl IntoIterator<Item = CapReply>) -> Images<Model> {
    let init = [
        reply(1, 0),
        reply(BASE + abi::REGION + abi::CONTROL as u64 * 4096, 0),
        reply(1, 0),
        reply(2, 0),
    ];
    Images::new(
        Model {
            replies: init.into_iter().chain(extra).collect(),
            calls: Vec::new(),
            writes: 0,
            bytes: vec![0; 8192],
            fail_staging: false,
        },
        BASE,
    )
    .unwrap()
}
fn header() -> Header {
    Header {
        bytes: 3,
        elf_offset: 0,
        elf_bytes: 3,
        sha256: [1; 32],
        elf_sha256: [2; 32],
        package: [3; 32],
        abi: ev_userspace_contract::ABI,
        descriptor: [4; 32],
    }
}
#[test]
fn actual_signed_package_prefix_requests_match_full_parse_and_malformed_indexes_refuse() {
    let snapshot = crate::native_acquisition::tests::retained_snapshot(false);
    let content = snapshot.candidate().unwrap();
    let bytes = include_bytes!("../../fixtures/acquisition/phase-b/hello.zion");
    let parsed = ev_zion::Package::parse(bytes).unwrap();
    let header = request_from_prefix(&bytes[..4096], content).unwrap();
    assert_eq!(
        header.elf_offset,
        (parsed.executable().bytes.as_ptr() as usize - bytes.as_ptr() as usize) as u64
    );
    assert_eq!(header.elf_bytes, parsed.executable().bytes.len() as u64);
    assert_eq!(header.elf_sha256, parsed.executable().digest);
    assert_eq!(header.sha256, parsed.id().bytes());
    for n in [0, 8, 95, 96] {
        assert!(request_from_prefix(&bytes[..n], content).is_err());
    }
    for at in [8, 12, 14, 16, 20, 24, 26, 28, 32, 64, 96] {
        let mut prefix = bytes[..4096].to_vec();
        prefix[at] ^= 0x80;
        assert!(request_from_prefix(&prefix, content).is_err(), "byte{at}");
    }
    let mut foreign = content;
    foreign.package[0] ^= 1;
    assert!(request_from_prefix(&bytes[..4096], foreign).is_err());
}
#[test]
fn all_bytes_and_successful_conversion_precede_readonly_access() {
    use sha2::{Digest, Sha256};
    let mut h = header();
    h.package = h.sha256;
    let mut descriptor = Sha256::new();
    abi::app_descriptor_transcript(&h.elf_sha256, |b| descriptor.update(b));
    h.descriptor = descriptor.finalize().into();
    let mut i = image([reply(1, 20), reply(3, 0), reply(4096, 0), reply(0, 21)]);
    i.initialize(1).unwrap();
    let slot = i.begin(h, 2, 100).unwrap();
    assert!(matches!(i.bytes(slot), Err(Error::State)));
    assert_eq!(i.seal(slot, 3), Err(Error::State));
    i.write_chunk(slot, 4, b"abc").unwrap();
    i.seal(slot, 5).unwrap();
    assert!(matches!(i.bytes(slot), Err(Error::State)));
    assert!(i.verify_step(slot, 6).unwrap());
    assert_eq!(i.bytes(slot).unwrap(), b"abc");
    // Readonly Kernel admission is not a Zion/release proof.
    assert!(matches!(i.package(slot), Err(Error::Package)));
    assert_eq!(i.register(slot, 7), Err(Error::Package));
    assert_eq!(i.io.calls.len(), 8);
}
#[test]
fn unknown_ack_fences_same_owner_without_accepted_write_retry() {
    for broken in [
        CapReply {
            status: 1,
            value: 5,
            capability: 0,
            serial: 0,
        },
        reply(2, 0),
        CapReply {
            status: 0,
            value: 3,
            capability: 0,
            serial: 1,
        },
    ] {
        let mut i = image([reply(1, 20), broken]);
        i.initialize(1).unwrap();
        i.begin(header(), 2, 100).unwrap();
        assert_eq!(i.write_chunk(0, 3, b"abc"), Err(Error::Reply));
        let count = i.io.calls.len();
        let writes = i.io.writes;
        assert_eq!(i.write_chunk(0, 4, b"abc"), Err(Error::State));
        assert_eq!(i.initialize(5), Err(Error::State));
        assert_eq!(i.io.calls.len(), count);
        assert_eq!(i.io.writes, writes);
        assert_eq!(&i.io.bytes[..3], b"abc");
        assert_eq!(i.slots[0].written, 0);
    }
}
#[test]
fn original_cut_and_monotonic_progress_are_checked_before_any_new_io() {
    for bad_tick in [1, 100] {
        let mut i = image([reply(1, 20)]);
        i.initialize(1).unwrap();
        i.begin(header(), 2, 100).unwrap();
        let count = i.io.calls.len();
        let writes = i.io.writes;
        assert_eq!(
            i.write_chunk(0, bad_tick, b"abc"),
            Err(if bad_tick == 1 {
                Error::Clock
            } else {
                Error::Deadline
            })
        );
        assert_eq!(i.io.calls.len(), count);
        assert_eq!(i.io.writes, writes);
    }
}
#[test]
fn wrong_version_or_noncanonical_capabilities_never_allow_window_writes() {
    let mut i = image([]);
    i.io.replies[0] = reply(2, 0);
    assert_eq!(i.initialize(1), Err(Error::Reply));
    assert_eq!(i.begin(header(), 2, 100), Err(Error::State));
    assert_eq!(i.io.writes, 0);
    for final_cap in [0, 20, u64::MAX] {
        let mut i = image([
            reply(1, 20),
            reply(3, 0),
            reply(4096, 0),
            reply(0, final_cap),
        ]);
        i.initialize(1).unwrap();
        i.begin(header(), 2, 100).unwrap();
        i.write_chunk(0, 3, b"abc").unwrap();
        i.seal(0, 4).unwrap();
        assert_eq!(i.verify_step(0, 5), Err(Error::Reply));
        assert!(matches!(i.bytes(0), Err(Error::State)));
    }
}

#[test]
fn cancellation_needs_actual_cleanup_ack_and_never_recycles_a_readonly_slot() {
    let mut i = image([
        reply(1, 20),
        reply(0, 0),
        reply(1, 22),
        reply(3, 0),
        reply(4096, 0),
        reply(0, 23),
    ]);
    i.initialize(1).unwrap();
    i.begin(header(), 2, 100).unwrap();
    assert_eq!(i.write_chunk(0, 100, b"abc"), Err(Error::Deadline));
    // Cleanup does not renew the expired transfer and is allowed after it.
    i.abort(0, 101).unwrap();
    assert_eq!(i.slots[0].cap, 0);
    i.begin(header(), 102, 200).unwrap();
    i.write_chunk(0, 103, b"abc").unwrap();
    i.seal(0, 104).unwrap();
    assert!(i.verify_step(0, 105).unwrap());
    let calls = i.io.calls.len();
    assert_eq!(i.abort(0, 106), Err(Error::State));
    assert_eq!(i.io.calls.len(), calls);
    assert_eq!(i.bytes(0).unwrap(), b"abc");
}

#[test]
fn partial_window_write_retains_owner_and_forbids_any_new_write_or_cleanup_claim() {
    let mut i = image([reply(1, 20)]);
    i.initialize(1).unwrap();
    i.begin(header(), 2, 100).unwrap();
    i.io.fail_staging = true;
    assert_eq!(i.write_chunk(0, 3, b"abc"), Err(Error::Io));
    assert_eq!(&i.io.bytes[..3], b"a\0\0");
    let calls = i.io.calls.len();
    let writes = i.io.writes;
    assert_eq!(i.abort(0, 4), Err(Error::State));
    assert_eq!(i.write_chunk(0, 5, b"abc"), Err(Error::State));
    assert_eq!(i.slots[0].cap, 20);
    assert_eq!(i.io.calls.len(), calls);
    assert_eq!(i.io.writes, writes);
}

#[test]
fn actual_development_zion_is_parsed_only_from_sealed_bytes_and_must_match_declared_identity() {
    use sha2::{Digest, Sha256};
    let bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/acquisition/phase-b/hello.zion"
    ));
    let parsed = ev_zion::Package::parse(bytes).unwrap();
    let h = Header {
        bytes: bytes.len() as u64,
        elf_offset: (parsed.executable().bytes.as_ptr() as usize - bytes.as_ptr() as usize) as u64,
        elf_bytes: parsed.executable().bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
        elf_sha256: parsed.executable().digest,
        package: parsed.id().bytes(),
        abi: ev_userspace_contract::ABI,
        descriptor: [
            0xe9, 0x2b, 0x03, 0x6c, 0x8c, 0x62, 0x67, 0xc5, 0xf7, 0xeb, 0x33, 0xe6, 0x52, 0x38,
            0xc4, 0x2a, 0xed, 0x16, 0x6c, 0xf4, 0x68, 0xd3, 0xff, 0x77, 0xdb, 0x32, 0x0a, 0xff,
            0xb7, 0xc0, 0x83, 0xf5,
        ],
    };
    for valid in [true, false] {
        let mut replies = vec![reply(1, 20)];
        let mut cumulative = 0;
        for chunk in bytes.chunks(4096) {
            cumulative += chunk.len();
            replies.push(reply(cumulative as u64, 0));
        }
        let mut remaining = (bytes.len() as u64).div_ceil(4096) * 4096;
        replies.push(reply(remaining, 0));
        while remaining > 0 {
            remaining -= 4096;
            replies.push(reply(remaining, if remaining == 0 { 21 } else { 0 }));
        }
        let mut i = image(replies);
        i.io.bytes.resize(bytes.len(), 0);
        i.initialize(1).unwrap();
        i.begin(
            if valid {
                h
            } else {
                Header {
                    package: [9; 32],
                    ..h
                }
            },
            2,
            1000,
        )
        .unwrap();
        let mut tick = 3;
        for chunk in bytes.chunks(4096) {
            i.write_chunk(0, tick, chunk).unwrap();
            tick += 1;
        }
        i.seal(0, tick).unwrap();
        tick += 1;
        while !i.verify_step(0, tick).unwrap() {
            tick += 1;
        }
        if valid {
            assert_eq!(i.package(0).unwrap().id(), parsed.id());
        } else {
            assert!(matches!(i.package(0), Err(Error::Shape)));
        }
    }
}
