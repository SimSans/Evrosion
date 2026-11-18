extern crate std;
use super::*;
use std::{collections::VecDeque, vec, vec::Vec};
const BASE: u64 = 1 << 39;
struct Model {
    replies: VecDeque<CapReply>,
    calls: Vec<(Operation, u64, u64)>,
    writes: usize,
    bytes: Vec<u8>,
    partial: bool,
}
impl Io for Model {
    fn control(&mut self, op: Operation, a: u64, b: u64) -> CapReply {
        self.calls.push((op, a, b));
        self.replies.pop_front().expect("unexpected control call")
    }
    fn write_header(&mut self, _: &[u8; 256]) -> Result<(), IoError> {
        self.writes += 1;
        Ok(())
    }
    fn write_staging(&mut self, at: usize, b: &[u8]) -> Result<(), IoError> {
        self.writes += 1;
        if self.partial {
            self.bytes[at] = b[0];
            Err(IoError)
        } else {
            self.bytes[at..at + b.len()].copy_from_slice(b);
            Ok(())
        }
    }
    fn readonly(&self, _: usize, n: usize) -> Result<&[u8], IoError> {
        self.bytes.get(..n).ok_or(IoError)
    }
}
fn r(value: u64, capability: u64) -> CapReply {
    CapReply {
        status: 0,
        value,
        capability,
        serial: 0,
    }
}
fn engine(bytes: usize, extra: impl IntoIterator<Item = CapReply>) -> Images<Model> {
    let init = [
        r(2, 0),
        r(BASE + abi::REGION + abi::CONTROL as u64 * 4096, 0),
        r(2, 0),
        r(2, 0),
    ];
    Images::new(
        Model {
            replies: init.into_iter().chain(extra).collect(),
            calls: Vec::new(),
            writes: 0,
            bytes: vec![0; bytes],
            partial: false,
        },
        BASE,
    )
    .unwrap()
}
fn h() -> Header {
    Header {
        bytes: 3,
        elf_offset: 0,
        elf_bytes: 3,
        sha256: [1; 32],
        elf_sha256: [2; 32],
        package: [1; 32],
        abi: ev_userspace_contract::ABI,
        descriptor: [4; 32],
    }
}
#[test]
fn v1_and_oversize_requests_do_not_enter_new_mappings() {
    let mut i = engine(3, []);
    i.io.replies[0] = r(1, 0);
    assert_eq!(i.initialize(1), Err(Error::Reply));
    assert_eq!(i.io.writes, 0);
    let mut i = engine(3, []);
    i.initialize(1).unwrap();
    let mut header = h();
    header.bytes = abi::MAX_BYTES;
    assert_eq!(i.begin(header, 2, 100), Err(Error::Shape));
    assert_eq!(i.io.writes, 0);
    assert_eq!(i.io.calls.len(), 4);
}
#[test]
fn accepted_unknown_write_retains_owner_and_never_replays() {
    for bad in [
        r(2, 0),
        CapReply {
            status: 1,
            value: 3,
            capability: 0,
            serial: 0,
        },
        CapReply {
            status: 0,
            value: 3,
            capability: 0,
            serial: 1,
        },
    ] {
        let mut i = engine(3, [r(1, 20), bad]);
        i.initialize(1).unwrap();
        i.begin(h(), 2, 100).unwrap();
        assert_eq!(i.write_chunk(0, 3, b"abc"), Err(Error::Reply));
        let calls = i.io.calls.len();
        let writes = i.io.writes;
        assert_eq!(i.write_chunk(0, 4, b"abc"), Err(Error::State));
        assert_eq!(i.abort(0, 5), Err(Error::State));
        assert_eq!((i.io.calls.len(), i.io.writes), (calls, writes));
        assert_eq!(i.slots[0].cap, 20);
        assert_eq!(i.slots[0].written, 0);
        assert_eq!(&i.io.bytes, b"abc");
    }
}
#[test]
fn partial_copy_fences_even_abort_and_does_not_return_credit() {
    let mut i = engine(3, [r(1, 20)]);
    i.initialize(1).unwrap();
    i.begin(h(), 2, 100).unwrap();
    i.io.partial = true;
    assert_eq!(i.write_chunk(0, 3, b"abc"), Err(Error::Io));
    assert_eq!(i.slots[0].cap, 20);
    assert_eq!(i.abort(0, 4), Err(Error::State));
    assert_eq!(&i.io.bytes, b"a\0\0");
    assert_eq!(i.io.calls.len(), 5);
}
#[test]
fn exact_original_cut_does_not_renew_on_progress_and_abort_needs_ack() {
    let mut i = engine(3, [r(1, 20), r(0, 0), r(1, 21)]);
    i.initialize(1).unwrap();
    i.begin(h(), 2, 100).unwrap();
    assert_eq!(i.write_chunk(0, 100, b"abc"), Err(Error::Deadline));
    assert_eq!(i.io.calls.len(), 5);
    assert_eq!(i.io.writes, 1);
    i.abort(0, 101).unwrap();
    assert_eq!(i.slots[0].cap, 0);
    i.begin(h(), 102, 200).unwrap();
    assert_eq!(i.slots[0].cut, 200);
    let calls = i.io.calls.len();
    assert_eq!(i.write_chunk(0, 101, b"abc"), Err(Error::Clock));
    assert_eq!(i.io.calls.len(), calls);
}
#[test]
fn same_or_missing_verify_capability_never_exposes_readonly_bytes() {
    for cap in [0, 20, u64::MAX] {
        let mut i = engine(3, [r(1, 20), r(3, 0), r(4096, 0), r(0, cap)]);
        i.initialize(1).unwrap();
        i.begin(h(), 2, 100).unwrap();
        i.write_chunk(0, 3, b"abc").unwrap();
        i.seal(0, 4).unwrap();
        assert!(matches!(i.bytes(0), Err(Error::State)));
        assert_eq!(i.verify_step(0, 5), Err(Error::Reply));
        assert!(matches!(i.bytes(0), Err(Error::State)));
    }
}
fn package(unsupported: bool) -> Vec<u8> {
    package_contract(
        if unsupported {
            "unavailable.contract"
        } else {
            "ev.internal.file"
        },
        2,
    )
}
fn package_contract(name: &str, major: u16) -> Vec<u8> {
    use ev_zion::{
        AppId, Contract, DataSchema, Platform, Version,
        producer::{self, Spec},
    };
    let mut elf = vec![0; 120];
    elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    elf[16..18].copy_from_slice(&2u16.to_le_bytes());
    elf[18..20].copy_from_slice(&62u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[32..40].copy_from_slice(&64u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1u16.to_le_bytes());
    // Parser-only ELF fixture. It is never passed to real admission or loaded.
    let contracts = [Contract {
        name,
        major,
        minimum_minor: 0,
        features: 0,
    }];
    producer::build(
        &Spec {
            app: AppId::new([7; 16]).unwrap(),
            name: "Independent utility",
            source: "Owner local DEVELOPMENT",
            publisher: None,
            version: Version {
                major: 0,
                minor: 4,
                patch: 0,
            },
            build_id: [8; 32],
            platform: Platform {
                minimum: 1,
                target: 1,
            },
            abi: ev_userspace_contract::ABI,
            data_schema: DataSchema {
                current: 1,
                oldest_readable: 1,
            },
            entrypoint: "bin/main.elf",
            contracts: &contracts,
            capabilities: &[],
        },
        &elf,
        &[],
    )
    .unwrap()
}
fn sealed(bytes: &[u8], header: Header) -> Images<Model> {
    let n = bytes.len() as u64;
    let mut i = engine(
        bytes.len(),
        [
            r(1, 20),
            r(n, 0),
            r(n.div_ceil(4096) * 4096, 0),
            r(0, 21),
            r(0, 0),
        ],
    );
    i.initialize(1).unwrap();
    i.begin(header, 2, 100).unwrap();
    i.write_chunk(0, 3, bytes).unwrap();
    i.seal(0, 4).unwrap();
    assert!(i.verify_step(0, 5).unwrap());
    i
}
#[test]
fn exact_immutable_package_and_requirements_precede_register() {
    let bytes = package(false);
    let loaded = crate::requirements::LoadedContracts {
        semantic_tree: false,
        file: Some(ev_userspace_contract::file_v2::Support {
            major: 2,
            minor: 0,
            features: 0,
        }),
    };
    let checked = crate::requirements::file_app(&bytes, &loaded).unwrap();
    let header = super::header(&checked).unwrap();
    assert_eq!(header.package, checked.package().id().bytes());
    assert_eq!(header.elf_sha256, checked.package().executable().digest);
    let mut i = sealed(&bytes, header);
    assert_eq!(i.register(0, 6, &loaded), Ok(21));
    let count = i.io.calls.len();
    assert_eq!(i.register(0, 7, &loaded), Err(Error::State));
    assert_eq!(i.io.calls.len(), count);
    i.io.replies.push_back(CapReply {
        status: 1,
        value: 3,
        capability: 0,
        serial: 0,
    });
    assert_eq!(i.initialize(8), Err(Error::State));
    // An unrelated actual failure blocks new mutation while retaining the exact
    // previously registered permanent reader. No release or live process claim.
    assert_eq!(i.reply(Operation::Inspect, 0, 0), Err(Error::Reply));
    assert_eq!(i.bytes(0).unwrap(), bytes);
    assert_eq!(i.registered_capability(0), Some(21));
}
#[test]
fn private_registration_requires_actual_context_without_widening_historical_registration() {
    let bytes = package_contract(ev_userspace_contract::app_data::INTERFACE, 1);
    let loaded = crate::requirements::LoadedContracts {
        semantic_tree: false,
        file: None,
    };
    let present = crate::requirements::PrivateDataContracts::new(&loaded, true);
    let absent = crate::requirements::PrivateDataContracts::new(&loaded, false);
    let checked = crate::requirements::private_file_app(&bytes, &present).unwrap();
    let header = super::header(&checked).unwrap();
    let mut historical = sealed(&bytes, header);
    let at = historical.io.calls.len();
    assert_eq!(historical.register(0, 6, &loaded), Err(Error::Package));
    assert_eq!(historical.io.calls.len(), at);
    let mut current = sealed(&bytes, header);
    let at = current.io.calls.len();
    assert_eq!(current.register_private(0, 6, &absent), Err(Error::Package));
    assert_eq!(current.io.calls.len(), at);
    assert_eq!(current.register_private(0, 7, &present), Ok(21));
    assert_eq!(current.registered_capability(0), Some(21));
}
#[test]
fn changed_header_unsupported_contract_or_expired_cut_cannot_register() {
    let bytes = package(false);
    let loaded = crate::requirements::LoadedContracts {
        semantic_tree: false,
        file: Some(ev_userspace_contract::file_v2::Support {
            major: 2,
            minor: 0,
            features: 0,
        }),
    };
    let checked = crate::requirements::file_app(&bytes, &loaded).unwrap();
    let original = super::header(&checked).unwrap();
    let mut wrong = original;
    wrong.descriptor[0] ^= 1;
    let mut i = sealed(&bytes, wrong);
    let before = i.io.calls.len();
    assert_eq!(i.register(0, 6, &loaded), Err(Error::Shape));
    assert_eq!(i.io.calls.len(), before);
    let mut i = sealed(&bytes, original);
    let before = i.io.calls.len();
    assert_eq!(i.register(0, 100, &loaded), Err(Error::Deadline));
    assert_eq!(i.io.calls.len(), before);
    assert_eq!(i.registered_capability(0), None);
    let bytes = package(true);
    let parsed = ev_zion::Package::parse(&bytes).unwrap();
    use sha2::{Digest, Sha256};
    let mut descriptor = Sha256::new();
    abi::app_descriptor_transcript(&parsed.executable().digest, |b| descriptor.update(b));
    let header = Header {
        bytes: bytes.len() as u64,
        elf_offset: (parsed.executable().bytes.as_ptr() as usize - bytes.as_ptr() as usize) as u64,
        elf_bytes: parsed.executable().bytes.len() as u64,
        sha256: parsed.id().bytes(),
        elf_sha256: parsed.executable().digest,
        package: parsed.id().bytes(),
        abi: ev_userspace_contract::ABI,
        descriptor: descriptor.finalize().into(),
    };
    let mut i = sealed(&bytes, header);
    let before = i.io.calls.len();
    assert_eq!(i.register(0, 6, &loaded), Err(Error::Package));
    assert_eq!(i.io.calls.len(), before);
}
