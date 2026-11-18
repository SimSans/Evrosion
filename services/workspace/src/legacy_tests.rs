extern crate std;

use super::*;
use ev_store::{BootPolicy, GenerationId, ObjectId as StoreObject, Request as StoreRequest};
use std::{vec, vec::Vec};

const CUT: u64 = 100_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Offline,
    Cut,
    Bounds,
}
struct Disk {
    bytes: Vec<Sector>,
    reads: Vec<u64>,
    writes: usize,
    flushes: usize,
    fail_read: bool,
    fail_flush: Option<usize>,
}
impl Disk {
    fn blank() -> Self {
        Self {
            bytes: vec![[0; 512]; LEGACY_LOGICAL_SECTORS as usize],
            reads: Vec::new(),
            writes: 0,
            flushes: 0,
            fail_read: false,
            fail_flush: None,
        }
    }
    fn reset_counts(&mut self) {
        self.reads.clear();
        self.writes = 0;
        self.flushes = 0;
    }
}
impl SectorIo for Disk {
    type Error = Fault;
    fn sectors(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read(&mut self, lba: u64, out: &mut Sector, _: u64) -> Result<(), Fault> {
        self.reads.push(lba);
        if self.fail_read {
            return Err(Fault::Offline);
        }
        *out = *self.bytes.get(lba as usize).ok_or(Fault::Bounds)?;
        Ok(())
    }
    fn write(&mut self, lba: u64, bytes: &Sector, _: u64) -> Result<(), Fault> {
        self.writes += 1;
        *self.bytes.get_mut(lba as usize).ok_or(Fault::Bounds)? = *bytes;
        Ok(())
    }
    fn flush(&mut self, _: u64) -> Result<(), Fault> {
        self.flushes += 1;
        if self.fail_flush == Some(self.flushes) {
            return Err(Fault::Cut);
        }
        Ok(())
    }
}

// Only new in-memory test fixtures implement a writable formatter adapter.
// Production ReadOnlyRegion has no such path or public backend accessor.
struct FixtureRegion<'a> {
    disk: &'a mut Disk,
    offset: u64,
}
impl SectorIo for FixtureRegion<'_> {
    type Error = Fault;
    fn sectors(&self) -> u64 {
        ev_store::REQUIRED_SECTORS
    }
    fn read(&mut self, local: u64, out: &mut Sector, cut: u64) -> Result<(), Fault> {
        self.disk.read(self.offset + local, out, cut)
    }
    fn write(&mut self, local: u64, bytes: &Sector, cut: u64) -> Result<(), Fault> {
        self.disk.write(self.offset + local, bytes, cut)
    }
    fn flush(&mut self, cut: u64) -> Result<(), Fault> {
        self.disk.flush(cut)
    }
}
fn manifest(tag: u8) -> GenerationManifest {
    GenerationManifest {
        generation: GenerationId::new(1).unwrap(),
        cohort: [tag; 32],
        supervisor_image: [tag + 1; 32],
        abi: [tag + 2; 32],
        health_contract: [tag + 3; 32],
        health_version: 1,
        required_checks: 3,
    }
}
fn creation() -> OriginalCreation {
    OriginalCreation::new(manifest(1), manifest(11)).unwrap()
}
fn envelope(payload: &[u8], counter: u64) -> Vec<u8> {
    let mut bytes = [0; ev_store::PAYLOAD_BYTES];
    let length = Envelope::initial(payload).unwrap().encode(&mut bytes);
    if counter != 0 {
        bytes[16..24].copy_from_slice(&counter.to_le_bytes());
        bytes[24..32].copy_from_slice(&9u64.to_le_bytes());
    }
    assert!(Envelope::decode(&bytes[..length]).is_ok());
    bytes[..length].to_vec()
}
fn format_region(disk: &mut Disk, offset: u64, tag: u8, user: &[u8]) {
    let _store = Store::format_new(
        FixtureRegion { disk, offset },
        manifest(tag),
        user,
        BootPolicy::new(1).unwrap(),
        CUT,
    )
    .unwrap_or_else(|error| panic!("fixture format: {:?}", error.error));
}
fn fixture(notes: &[u8], private: &[u8]) -> Owner<Disk> {
    let mut disk = Disk::blank();
    format_region(&mut disk, 0, 1, notes);
    format_region(&mut disk, 16, 11, private);
    disk.reset_counts();
    Owner::new(disk, creation())
}
fn normal() -> Owner<Disk> {
    fixture(
        &envelope(b"fixture notes", 7),
        &envelope(b"fixture private", 0),
    )
}
fn deadline() -> Deadline {
    Deadline::new(CUT).unwrap()
}
fn read_request(revision: u64, offset: u32, length: u32) -> wire::Request {
    wire::Request {
        request_id: 17,
        operation_id: 0,
        deadline: deadline(),
        expected_revision: revision,
        method: wire::Method::Read { offset, length },
    }
}
fn metadata(owner: &mut Owner<Disk>, object: Object) -> Metadata {
    owner
        .inspect(object, deadline(), &mut Scratch::new())
        .unwrap()
        .metadata
}
fn assert_no_mutations(owner: &Owner<Disk>, before: &[Sector]) {
    assert_eq!(owner.backend.writes, 0);
    assert_eq!(owner.backend.flushes, 0);
    assert_eq!(owner.backend.bytes, before);
}
fn assert_response(request: wire::Request, response: wire::Response) {
    let frame = response.encode().unwrap();
    assert_eq!(wire::client_decode(request, &frame, 0).unwrap(), response);
}

#[test]
fn actual_store2_original_envelopes_project_both_identities_and_exact_file2_chunks() {
    let mut owner = normal();
    let before = owner.backend.bytes.clone();
    let mut scratch = Scratch::new();
    let notes = {
        let snapshot = owner
            .inspect(Object::Notes, deadline(), &mut scratch)
            .unwrap();
        assert_eq!(snapshot.payload(), b"fixture notes");
        assert_eq!(snapshot.metadata.identity.volume, ORIGINAL_VOLUME);
        assert_eq!(snapshot.metadata.identity.local, 1);
        assert_eq!(
            snapshot.metadata.identity.projected_object,
            ObjectId {
                slot: 1,
                generation: 1
            }
        );
        assert_eq!(snapshot.metadata.counter, 7);
        assert_eq!(snapshot.metadata.global_operation, 9);
        assert_eq!(
            snapshot.metadata.digest,
            <[u8; 32]>::from(Sha256::digest(b"fixture notes"))
        );
        snapshot.metadata
    };
    let private = metadata(&mut owner, Object::Private);
    assert_eq!(private.identity.local, 2);
    assert_eq!(
        private.identity.projected_object,
        ObjectId {
            slot: 2,
            generation: 1
        }
    );
    assert_eq!(private.counter, 0);
    let mut out = [0xa5; 4096];
    let request = read_request(7, 8, 4096);
    let response = owner
        .file2_read(Object::Notes, notes, request, 1, &mut scratch, &mut out)
        .unwrap();
    assert_eq!(response.outcome, Outcome::Completed);
    assert_eq!(response.revision, 7);
    assert_eq!(response.offset, 8);
    assert_eq!(response.length, 5);
    assert_eq!(response.file_length, 13);
    assert_eq!(&out[..5], b"notes");
    assert!(out[5..].iter().all(|byte| *byte == 0));
    assert_eq!(response.digest, <[u8; 32]>::from(Sha256::digest(b"notes")));
    assert_response(request, response);
    let request = read_request(0, 0, 4096);
    let response = owner
        .file2_read(Object::Private, private, request, 1, &mut scratch, &mut out)
        .unwrap();
    assert_eq!(&out[..response.length as usize], b"fixture private");
    assert_response(request, response);
    assert_no_mutations(&owner, &before);
}

#[test]
fn empty_file_and_exact_eof_have_empty_sha256_and_no_sibling_bytes() {
    let mut owner = fixture(&envelope(b"", 0), &envelope(b"sibling", 0));
    let expected = metadata(&mut owner, Object::Notes);
    let request = read_request(0, 0, 1);
    let mut out = [0xa5; 4096];
    let response = owner
        .file2_read(
            Object::Notes,
            expected,
            request,
            1,
            &mut Scratch::new(),
            &mut out,
        )
        .unwrap();
    assert_eq!(response.length, 0);
    assert_eq!(response.file_length, 0);
    assert_eq!(response.digest, <[u8; 32]>::from(Sha256::digest(b"")));
    assert!(out.iter().all(|byte| *byte == 0));
    assert_response(request, response);
    let expected = metadata(&mut owner, Object::Private);
    let request = read_request(0, expected.length, 1);
    let response = owner
        .file2_read(
            Object::Private,
            expected,
            request,
            1,
            &mut Scratch::new(),
            &mut out,
        )
        .unwrap();
    assert_eq!(response.length, 0);
    assert_eq!(response.offset, expected.length);
    assert_response(request, response);
    let request = read_request(0, expected.length + 1, 1);
    let response = owner
        .file2_read(
            Object::Private,
            expected,
            request,
            1,
            &mut Scratch::new(),
            &mut out,
        )
        .unwrap();
    assert_eq!(response.outcome, Outcome::Denied);
    assert_response(request, response);
}

#[test]
fn all_mutators_and_queries_refuse_before_io_and_source_preflight_is_exact() {
    let mut owner = normal();
    let expected = metadata(&mut owner, Object::Notes);
    owner.backend.reset_counts();
    let before = owner.backend.bytes.clone();
    let mut scratch = Scratch::new();
    scratch.bytes.fill(0x5a);
    let mut out = [0xa5; 1];
    for method in [
        wire::Method::BeginWrite {
            length: 1,
            digest: [1; 32],
        },
        wire::Method::WriteChunk {
            transfer_id: 1,
            offset: 0,
            length: 1,
            digest: [1; 32],
        },
        wire::Method::Commit {
            transfer_id: 1,
            length: 1,
            digest: [1; 32],
        },
        wire::Method::Abort { transfer_id: 1 },
        wire::Method::QueryOperation,
    ] {
        let request = wire::Request {
            request_id: 1,
            operation_id: 1,
            deadline: deadline(),
            expected_revision: 0,
            method,
        };
        let response = owner
            .file2_read(Object::Notes, expected, request, 1, &mut scratch, &mut out)
            .unwrap();
        assert_eq!(response.outcome, Outcome::Denied);
        assert_response(request, response);
    }
    let request = read_request(6, 0, 1);
    assert_eq!(
        owner
            .file2_read(Object::Notes, expected, request, 1, &mut scratch, &mut out)
            .unwrap()
            .outcome,
        Outcome::Stale
    );
    let request = read_request(7, 0, 1);
    assert_eq!(
        owner
            .file2_read(
                Object::Private,
                expected,
                request,
                1,
                &mut scratch,
                &mut out
            )
            .unwrap()
            .outcome,
        Outcome::Stale
    );
    assert_eq!(
        owner
            .file2_read(
                Object::Notes,
                expected,
                request,
                CUT,
                &mut scratch,
                &mut out
            )
            .unwrap()
            .outcome,
        Outcome::Cancelled
    );
    let mut malformed = request;
    malformed.operation_id = 3;
    assert_eq!(
        owner.file2_read(
            Object::Notes,
            expected,
            malformed,
            1,
            &mut scratch,
            &mut out
        ),
        Err(ReadError::Protocol(CodecError::Identity))
    );
    assert!(owner.backend.reads.is_empty());
    assert!(scratch.bytes.iter().all(|byte| *byte == 0x5a));
    assert_eq!(out, [0xa5]);
    assert_no_mutations(&owner, &before);
    // A source with the same revision but another length/hash/global receipt is
    // still stale; caller request revision alone never overrides native proof.
    let mut changed = expected;
    changed.digest[0] ^= 1;
    assert_eq!(
        owner
            .file2_read(Object::Notes, changed, request, 1, &mut scratch, &mut out)
            .unwrap()
            .outcome,
        Outcome::Stale
    );
    assert_eq!(out, [0xa5]);
    assert_no_mutations(&owner, &before);
}

#[test]
fn foreign_unknown_unformatted_corrupt_and_strict_envelope_failures_never_write() {
    for case in 0..5 {
        let mut owner = normal();
        let expected_error = match case {
            0 => {
                owner.creation.notes = manifest(21);
                Unavailable::ForeignNamespace
            }
            1 => {
                owner.backend.bytes[1][8..10].copy_from_slice(&99u16.to_le_bytes());
                Unavailable::UnknownFormat
            }
            2 => {
                owner.backend.bytes[..14].fill([0; 512]);
                Unavailable::Unformatted
            }
            3 => {
                owner.backend.bytes[1][480] ^= 1;
                Unavailable::Corrupt
            }
            _ => {
                owner.backend.bytes[12][100] ^= 1;
                Unavailable::Corrupt
            }
        };
        let before = owner.backend.bytes.clone();
        assert_eq!(
            owner
                .inspect(Object::Notes, deadline(), &mut Scratch::new())
                .unwrap_err(),
            expected_error
        );
        assert_no_mutations(&owner, &before);
    }
    for case in 0..7 {
        let mut bytes = envelope(b"owned fixture", 0);
        match case {
            0 => bytes[0] ^= 1,
            1 => bytes[8] = 2,
            2 => bytes[12] = 1,
            3 => bytes[10] += 1,
            4 => bytes[16..24].copy_from_slice(&u64::MAX.to_le_bytes()),
            5 => bytes[24..32].copy_from_slice(&1u64.to_le_bytes()),
            _ => {
                bytes[16..24].copy_from_slice(&1u64.to_le_bytes());
                bytes[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
            }
        }
        let mut owner = fixture(&bytes, &envelope(b"other", 0));
        let before = owner.backend.bytes.clone();
        assert_eq!(
            owner
                .inspect(Object::Notes, deadline(), &mut Scratch::new())
                .unwrap_err(),
            Unavailable::Envelope
        );
        assert_no_mutations(&owner, &before);
    }
}

fn pending_fixture(flush: usize) -> Owner<Disk> {
    let mut owner = normal();
    owner.backend.fail_flush = Some(flush);
    let bytes = envelope(b"new pending fixture", 8);
    {
        let mut store = Store::open_mutable_namespace(
            FixtureRegion {
                disk: &mut owner.backend,
                offset: 0,
            },
            &manifest(1),
            CUT,
        )
        .unwrap_or_else(|error| panic!("fixture open: {:?}", error.error));
        let op = store.next_operation().unwrap();
        assert_eq!(
            store.execute(
                op,
                StoreRequest::WriteMutable {
                    object: StoreObject::user_data(),
                    bytes: &bytes
                },
                CUT
            ),
            Err(ev_store::Error::Io(Fault::Cut))
        );
    }
    owner.backend.fail_flush = None;
    owner.backend.reset_counts();
    owner
}

#[test]
fn actual_store_journal_and_partial_publication_require_recovery_without_write_or_flush() {
    // First cut follows journal persistence. Second follows data-slot
    // persistence while the committed root still selects the old envelope.
    for flush in [1, 2] {
        let mut owner = pending_fixture(flush);
        let before = owner.backend.bytes.clone();
        assert_eq!(
            owner
                .inspect(Object::Notes, deadline(), &mut Scratch::new())
                .unwrap_err(),
            Unavailable::RecoveryRequired
        );
        assert_no_mutations(&owner, &before);
        // Foreign namespace must refuse before attempting pending recovery.
        owner.creation.notes = manifest(21);
        assert_eq!(
            owner
                .inspect(Object::Notes, deadline(), &mut Scratch::new())
                .unwrap_err(),
            Unavailable::ForeignNamespace
        );
        assert_no_mutations(&owner, &before);
    }
}

#[test]
fn one_owner_serializes_disjoint_regions_and_read_failure_fences_window_reuse() {
    let mut owner = normal();
    let before = owner.backend.bytes.clone();
    for (object, range) in [(Object::Notes, 0..14), (Object::Private, 16..30)] {
        owner.backend.reads.clear();
        let mut scratch = Scratch::new();
        let snapshot = owner.inspect(object, deadline(), &mut scratch).unwrap();
        assert_eq!(snapshot.metadata.identity, Identity::for_object(object));
        assert!(!owner.backend.reads.is_empty());
        assert!(
            owner
                .backend
                .reads
                .iter()
                .all(|sector| range.contains(sector))
        );
    }
    let expected = metadata(&mut owner, Object::Notes);
    owner.backend.fail_read = true;
    assert_eq!(
        owner
            .inspect(Object::Notes, deadline(), &mut Scratch::new())
            .unwrap_err(),
        Unavailable::Transport
    );
    assert!(owner.is_fenced());
    let reads = owner.backend.reads.len();
    assert_eq!(
        owner
            .inspect(Object::Private, deadline(), &mut Scratch::new())
            .unwrap_err(),
        Unavailable::Fenced
    );
    assert_eq!(owner.backend.reads.len(), reads);
    let mut request = read_request(7, 0, 1);
    request.operation_id = 1;
    request.method = wire::Method::BeginWrite {
        length: 0,
        digest: [0; 32],
    };
    assert_eq!(
        owner
            .file2_read(
                Object::Notes,
                expected,
                request,
                1,
                &mut Scratch::new(),
                &mut [0; 1]
            )
            .unwrap()
            .outcome,
        Outcome::Denied
    );
    assert_eq!(owner.backend.reads.len(), reads);
    assert_no_mutations(&owner, &before);
    assert_eq!(core::mem::size_of::<Scratch>(), 256);
}

#[test]
fn readonly_wrapper_itself_blocks_every_mutation_and_small_media_never_reads() {
    let mut disk = Disk::blank();
    {
        let mut region = ReadOnlyRegion {
            backend: &mut disk,
            region: Region::FileA,
        };
        assert!(matches!(
            region.write(0, &[1; 512], CUT),
            Err(ReadOnlyError::Blocked)
        ));
        assert!(matches!(region.flush(CUT), Err(ReadOnlyError::Blocked)));
        assert!(matches!(
            region.read(14, &mut [0; 512], CUT),
            Err(ReadOnlyError::Bounds)
        ));
    }
    assert!(disk.reads.is_empty());
    assert_eq!(disk.writes, 0);
    assert_eq!(disk.flushes, 0);
    disk.bytes.truncate(29);
    let mut owner = Owner::new(disk, creation());
    assert_eq!(
        owner
            .inspect(Object::Notes, deadline(), &mut Scratch::new())
            .unwrap_err(),
        Unavailable::Capacity
    );
    assert!(owner.backend.reads.is_empty());
    let mut invalid = manifest(1);
    invalid.health_version = 2;
    assert_eq!(OriginalCreation::new(invalid, manifest(11)), None);
}

#[test]
fn reference_profile_matches_historical_constructor_and_refuses_m8_service_context() {
    let original = OriginalCreation::reference_desktop();
    assert_eq!(original.notes.cohort, [1; 32]);
    assert_eq!(original.private.cohort, [2; 32]);
    assert_eq!(original.notes.supervisor_image, [0x22; 32]);
    assert_eq!(original.notes.abi, ev_userspace_contract::ABI);
    assert_ne!(
        original.notes.abi,
        ev_userspace_contract::root_v5::child::ABI
    );
    let mut disk = Disk::blank();
    let bytes = envelope(b"original constructor model", 0);
    let _store = Store::format_new(
        FixtureRegion {
            disk: &mut disk,
            offset: 0,
        },
        original.notes,
        &bytes,
        BootPolicy::new(3).unwrap(),
        CUT,
    )
    .unwrap_or_else(|_| panic!("owned reference model fixture"));
    disk.reset_counts();
    let mut owner = Owner::new(disk, original);
    assert_eq!(
        owner
            .inspect(Object::Notes, deadline(), &mut Scratch::new())
            .unwrap()
            .payload(),
        b"original constructor model"
    );
    owner.creation.notes.abi = ev_userspace_contract::root_v5::child::ABI;
    assert_eq!(
        owner
            .inspect(Object::Notes, deadline(), &mut Scratch::new())
            .unwrap_err(),
        Unavailable::ForeignNamespace
    );
    assert_eq!(owner.backend.writes, 0);
    assert_eq!(owner.backend.flushes, 0);
}
