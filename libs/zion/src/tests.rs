use crate::*;
use producer::{Resource, Spec};
use std::vec::Vec;

const CONTRACTS: &[Contract<'_>] = &[Contract {
    name: "file.object",
    major: 1,
    minimum_minor: 2,
    features: 3,
}];
const CAPABILITIES: &[CapabilityRequest] = &[
    CapabilityRequest {
        capability: Capability::SelectedFileRead,
        required: true,
    },
    CapabilityRequest {
        capability: Capability::OwnSurfacePresent,
        required: true,
    },
];
fn spec() -> Spec<'static> {
    Spec {
        app: AppId::new([7; 16]).unwrap(),
        name: "Hello",
        source: "Owner local build",
        publisher: None,
        version: Version {
            major: 0,
            minor: 1,
            patch: 0,
        },
        build_id: [9; 32],
        platform: Platform {
            minimum: 0,
            target: 0,
        },
        abi: [8; 32],
        data_schema: DataSchema {
            current: 2,
            oldest_readable: 1,
        },
        entrypoint: "bin/main.elf",
        contracts: CONTRACTS,
        capabilities: CAPABILITIES,
    }
}
fn elf_fixture() -> Vec<u8> {
    // Structural fixture only, never loaded or claimed executable evidence.
    let mut b = std::vec![0; 120];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    b[16..18].copy_from_slice(&2_u16.to_le_bytes());
    b[18..20].copy_from_slice(&62_u16.to_le_bytes());
    b[20..24].copy_from_slice(&1_u32.to_le_bytes());
    b[32..40].copy_from_slice(&64_u64.to_le_bytes());
    b[52..54].copy_from_slice(&64_u16.to_le_bytes());
    b[54..56].copy_from_slice(&56_u16.to_le_bytes());
    b[56..58].copy_from_slice(&1_u16.to_le_bytes());
    b
}
fn fixture() -> Vec<u8> {
    producer::build(
        &spec(),
        &elf_fixture(),
        &[Resource {
            path: "res/message.txt",
            bytes: b"Hello owner",
        }],
    )
    .unwrap()
}

#[test]
fn actual_package_identity_and_compatibility_gate_lifecycle_metadata() {
    use lifecycle::{Error as LifecycleError, Record};
    let bytes = fixture();
    let first = Package::parse(&bytes).unwrap();
    let support = Support {
        major: 1,
        minor: 2,
        features: 3,
    };
    let compatible = first.compatible(0, [8; 32], &support).unwrap();
    let installed = Record::install(&compatible, 1).unwrap();
    let active = installed.activate(installed.revision()).unwrap();
    let mut changed_spec = spec();
    changed_spec.version.patch = 1;
    changed_spec.build_id = [10; 32];
    let changed_bytes = producer::build(&changed_spec, &elf_fixture(), &[]).unwrap();
    let changed = Package::parse(&changed_bytes).unwrap();
    let changed_compatible = changed.compatible(0, [8; 32], &support).unwrap();
    assert!(active.active().unwrap().matches(&compatible));
    assert!(!active.active().unwrap().matches(&changed_compatible));
    let staged = active
        .stage(active.revision(), &changed_compatible)
        .unwrap();
    assert_eq!(staged.active().unwrap().digest(), first.id.bytes());
    let updated = staged.activate(staged.revision()).unwrap();
    assert_eq!(updated.active().unwrap().digest(), changed.id.bytes());
    let rolled = updated.rollback(updated.revision()).unwrap();
    assert_eq!(rolled.active().unwrap().digest(), first.id.bytes());
    let removed = rolled.remove(rolled.revision()).unwrap();
    let reinstated = removed
        .reinstall(removed.revision(), &changed_compatible)
        .unwrap();
    assert_eq!(reinstated.data_epoch(), 1);
    assert!(Record::install(&compatible, 0).is_err());
    assert!(first.compatible(0, [9; 32], &support).is_err());

    changed_spec.app = AppId::new([9; 16]).unwrap();
    let wrong_bytes = producer::build(&changed_spec, &elf_fixture(), &[]).unwrap();
    let wrong = Package::parse(&wrong_bytes).unwrap();
    let wrong_compatible = wrong.compatible(0, [8; 32], &support).unwrap();
    let before = active.encode();
    assert!(matches!(
        active.stage(active.revision(), &wrong_compatible),
        Err(LifecycleError::Identity)
    ));
    assert_eq!(active.encode(), before);
}
fn manifest_end(b: &[u8]) -> usize {
    HEADER + u32_at(b, 20).unwrap() as usize
}
fn table_end(b: &[u8]) -> usize {
    manifest_end(b) + ENTRY * usize::from(u16_at(b, 24).unwrap())
}
fn field(b: &[u8], wanted: u16) -> core::ops::Range<usize> {
    let mut offset = HEADER;
    while offset < manifest_end(b) {
        let n = u32_at(b, offset + 4).unwrap() as usize;
        if u16_at(b, offset).unwrap() == wanted {
            return offset + 8..offset + 8 + n;
        }
        offset += 8 + n;
    }
    panic!("fixture field missing")
}
fn seal_manifest(b: &mut [u8]) {
    let end = manifest_end(b);
    let digest = sha(&b[HEADER..end]);
    b[32..64].copy_from_slice(&digest);
}
fn seal_table(b: &mut [u8]) {
    let start = manifest_end(b);
    let end = table_end(b);
    let digest = sha(&b[start..end]);
    b[64..96].copy_from_slice(&digest);
}
fn seal_content(b: &mut [u8], index: usize) {
    let row = manifest_end(b) + index * ENTRY;
    let start = u32_at(b, row + 4).unwrap() as usize;
    let n = u32_at(b, row + 8).unwrap() as usize;
    let digest = sha(&b[start..start + n]);
    b[row + 16..row + 48].copy_from_slice(&digest);
    seal_table(b);
}
fn replace_manifest(old: &[u8], manifest: &[u8]) -> Vec<u8> {
    let mut b = old[..HEADER].to_vec();
    b[20..24].copy_from_slice(&(manifest.len() as u32).to_le_bytes());
    b.extend_from_slice(manifest);
    b.extend_from_slice(&old[manifest_end(old)..]);
    let n = b.len();
    b[16..20].copy_from_slice(&(n as u32).to_le_bytes());
    let mut cursor = table_end(&b);
    let first = manifest_end(&b);
    let count = usize::from(u16_at(&b, 24).unwrap());
    for row in b[first..first + count * ENTRY].as_chunks_mut::<ENTRY>().0 {
        row[4..8].copy_from_slice(&(cursor as u32).to_le_bytes());
        cursor += u32_at(row, 8).unwrap() as usize;
    }
    seal_manifest(&mut b);
    seal_table(&mut b);
    b
}
fn optional_extension(required: bool) -> Vec<u8> {
    let b = fixture();
    let mut manifest = b[HEADER..manifest_end(&b)].to_vec();
    manifest.extend_from_slice(&100_u16.to_le_bytes());
    manifest.extend_from_slice(&u16::from(required).to_le_bytes());
    manifest.extend_from_slice(&3_u32.to_le_bytes());
    manifest.extend_from_slice(b"new");
    replace_manifest(&b, &manifest)
}
fn rejects(b: &[u8], e: Error) {
    assert_eq!(Package::parse(b).err(), Some(e));
}

#[test]
fn deterministic_borrowed_package_has_distinct_identity_dimensions() {
    let b = fixture();
    assert_eq!(b, fixture());
    let package = Package::parse(&b).unwrap();
    assert_eq!(package.app.claimed_app.bytes(), [7; 16]);
    assert_eq!(package.id.bytes(), sha(&b));
    assert_eq!(package.app.build_id, [9; 32]);
    assert_eq!(package.app.version.minor, 1);
    assert_eq!(package.app.publisher, None);
    assert_eq!(package.resources().next().unwrap().bytes, b"Hello owner");
    assert_eq!(
        package.executable().bytes.as_ptr(),
        b[table_end(&b)..].as_ptr()
    );
    assert_eq!(package.app.contracts().next().unwrap(), CONTRACTS[0]);
    assert_eq!(
        package.app.capability_requests().collect::<Vec<_>>(),
        CAPABILITIES
    );
    let mut changed = spec();
    changed.name = "Renamed";
    changed.source = "Changed metadata";
    changed.publisher = Some([11; 16]);
    changed.version.patch = 1;
    changed.build_id = [12; 32];
    let renamed = producer::build(&changed, &elf_fixture(), &[]).unwrap();
    let other = Package::parse(&renamed).unwrap();
    assert_eq!(other.app.claimed_app, package.app.claimed_app);
    assert_ne!(other.id, package.id);
    assert_ne!(other.app.publisher, package.app.publisher);
    assert!(other.app.data_schema.reads(1));
    assert!(!other.app.data_schema.reads(0));
    assert!(!other.app.data_schema.reads(3));
}

#[test]
fn additive_minor_optional_fields_are_allowed_required_semantics_fail() {
    let mut b = optional_extension(false);
    b[10..12].copy_from_slice(&19_u16.to_le_bytes());
    assert_eq!(Package::parse(&b).unwrap().format_minor, 19);
    rejects(&optional_extension(true), Error::RequiredField(100));
    b[8..10].copy_from_slice(&2_u16.to_le_bytes());
    rejects(&b, Error::FormatVersion);
    b = fixture();
    b[26..28].copy_from_slice(&2_u16.to_le_bytes());
    rejects(&b, Error::ManifestVersion);
}

#[test]
fn checksums_cover_manifest_index_and_each_payload() {
    let b = fixture();
    for (index, expected) in [
        (HEADER + 9, Error::ManifestDigest),
        (manifest_end(&b) + 17, Error::IndexDigest),
        (table_end(&b) + 110, Error::ContentDigest),
        (b.len() - 1, Error::ContentDigest),
    ] {
        let mut bad = b.clone();
        bad[index] ^= 1;
        rejects(&bad, expected);
    }
    let mut bad = b.clone();
    bad[0] ^= 1;
    rejects(&bad, Error::Magic);
    // Hashes are integrity checks. A malicious but resealed metadata change can
    // parse and is NOT thereby authenticated as an existing application.
    let mut resealed = b.clone();
    let range = field(&b, 1);
    resealed[range].fill(4);
    seal_manifest(&mut resealed);
    assert_eq!(
        Package::parse(&resealed).unwrap().app.claimed_app.bytes(),
        [4; 16]
    );
}

#[test]
fn lengths_truncation_trailing_and_overflow_fail_closed() {
    let b = fixture();
    for end in 0..b.len() {
        assert!(Package::parse(&b[..end]).is_err(), "truncation {end}");
    }
    let mut bad = b.clone();
    bad.push(0);
    rejects(&bad, Error::Length);
    let len = bad.len() as u32;
    bad[16..20].copy_from_slice(&len.to_le_bytes());
    rejects(&bad, Error::Length);
    for offset in [16, 20] {
        let mut bad = b.clone();
        bad[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Package::parse(&bad).is_err());
    }
    for count in [0, MAX_ENTRIES as u16 + 1, u16::MAX] {
        let mut bad = b.clone();
        bad[24..26].copy_from_slice(&count.to_le_bytes());
        rejects(&bad, Error::Bounds);
    }
    for offset in [4, 8] {
        let mut bad = b.clone();
        let at = manifest_end(&b) + offset;
        bad[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        seal_table(&mut bad);
        assert!(Package::parse(&bad).is_err());
    }
    let mut manifest = b[HEADER..manifest_end(&b)].to_vec();
    manifest[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(Package::parse(&replace_manifest(&b, &manifest)).is_err());
    assert_eq!(u64_at(&b, usize::MAX), Err(Error::Overflow));
    assert_eq!(array32(&b, usize::MAX), Err(Error::Overflow));
}

#[test]
fn manifest_required_missing_duplicate_and_reserved_are_rejected_after_reseal() {
    let b = fixture();
    let mut bad = b.clone();
    bad[HEADER..HEADER + 2].copy_from_slice(&0_u16.to_le_bytes());
    seal_manifest(&mut bad);
    rejects(&bad, Error::Duplicate);
    let name = field(&b, 2);
    let mut bad = b.clone();
    bad[name.start - 8..name.start - 6].copy_from_slice(&1_u16.to_le_bytes());
    seal_manifest(&mut bad);
    rejects(&bad, Error::Duplicate);
    let mut manifest = b[HEADER..manifest_end(&b)].to_vec();
    manifest.drain(..24);
    rejects(&replace_manifest(&b, &manifest), Error::MissingField(1));
    for at in [14, 28] {
        let mut bad = b.clone();
        bad[at] = 1;
        rejects(&bad, Error::Reserved);
    }
    let mut bad = b.clone();
    bad[HEADER + 2] = 2;
    seal_manifest(&mut bad);
    rejects(&bad, Error::Reserved);
    let mut bad = b.clone();
    bad[HEADER + 2] = 0;
    seal_manifest(&mut bad);
    rejects(&bad, Error::Field);
}

#[test]
fn unsafe_or_ambiguous_paths_never_normalize() {
    for name in [
        "/etc/passwd",
        "../escape",
        "bin/../escape",
        "bin/./main",
        "bin//main",
        "bin/main/",
        "C:/main",
        "bin\\main",
        "bin/%2e",
        "bin/\0main",
        "",
    ] {
        let mut s = spec();
        s.entrypoint = name;
        assert!(
            producer::build(&s, &elf_fixture(), &[]).is_err(),
            "path {name:?}"
        );
    }
    for path in [
        "../secret",
        "/secret",
        "res/./message.txt",
        "res//message.txt",
    ] {
        assert!(
            producer::build(&spec(), &elf_fixture(), &[Resource { path, bytes: b"x" }]).is_err()
        );
    }
    let b = fixture();
    let mut bad = b.clone();
    let at = manifest_end(&b) + ENTRY;
    bad[at + 48] = b'/';
    seal_table(&mut bad);
    rejects(&bad, Error::Path);
    let mut bad = b.clone();
    bad[at + 48 + 15] = b'x';
    seal_table(&mut bad);
    rejects(&bad, Error::Path);
    assert!(
        producer::build(
            &spec(),
            &elf_fixture(),
            &[Resource {
                path: "bin/main.elf",
                bytes: b"duplicate"
            }]
        )
        .is_err()
    );
}

#[test]
fn entries_have_exact_contiguous_extents_one_executable_and_no_aliases() {
    let b = fixture();
    let first = manifest_end(&b);
    let second = first + ENTRY;
    for delta in [1_i64, -1] {
        let mut bad = b.clone();
        let old = u32_at(&b, second + 4).unwrap();
        bad[second + 4..second + 8]
            .copy_from_slice(&((i64::from(old) + delta) as u32).to_le_bytes());
        seal_table(&mut bad);
        rejects(&bad, Error::Bounds);
    }
    for (offset, value, error) in [
        (first, 2, Error::Field),
        (second, 1, Error::Field),
        (second, 3, Error::Field),
        (second + 1, 1, Error::Reserved),
        (second + 12, 1, Error::Reserved),
        (second + 112, 1, Error::Reserved),
    ] {
        let mut bad = b.clone();
        bad[offset] = value;
        seal_table(&mut bad);
        rejects(&bad, error);
    }
    let mut bad = b.clone();
    bad[second + 8..second + 12].fill(0);
    seal_table(&mut bad);
    rejects(&bad, Error::Bounds);
    let mut bad = b.clone();
    let row = bad[first + 2..first + 4].to_vec();
    bad[second + 2..second + 4].copy_from_slice(&row);
    let name = bad[first + 48..first + 112].to_vec();
    bad[second + 48..second + 112].copy_from_slice(&name);
    seal_table(&mut bad);
    rejects(&bad, Error::Duplicate);
}

#[test]
fn contract_requirements_are_bounded_sorted_exact_and_not_an_endpoint() {
    let b = fixture();
    let contracts = field(&b, 12);
    for (relative, value) in [(2, 1), (8 + 6, 1), (8 + 16 + 11, 1), (8 + 1, 0)] {
        let mut bad = b.clone();
        bad[contracts.start + relative] = value;
        seal_manifest(&mut bad);
        assert!(Package::parse(&bad).is_err());
    }
    let duplicate = [CONTRACTS[0], CONTRACTS[0]];
    let mut s = spec();
    s.contracts = &duplicate;
    assert_eq!(
        producer::build(&s, &elf_fixture(), &[]).err(),
        Some(Error::Duplicate)
    );
    let nine = [CONTRACTS[0]; 9];
    s.contracts = &nine;
    assert_eq!(
        producer::build(&s, &elf_fixture(), &[]).err(),
        Some(Error::Bounds)
    );
    for name in [
        "../file",
        "File.Object",
        "file..object",
        ".file",
        "file.",
        "file/object",
        "",
    ] {
        let req = [Contract {
            name,
            major: 1,
            minimum_minor: 0,
            features: 0,
        }];
        let mut s = spec();
        s.contracts = &req;
        assert!(producer::build(&s, &elf_fixture(), &[]).is_err());
    }
}

struct Support {
    major: u16,
    minor: u16,
    features: u64,
}
impl Contracts for Support {
    fn supported(&self, name: &str, major: u16) -> Option<ContractSupport> {
        (name == "file.object" && major == self.major).then_some(ContractSupport {
            minor: self.minor,
            features: self.features,
        })
    }
}
#[test]
fn api_abi_and_major_minor_feature_compatibility_have_no_default_max_api() {
    let mut s = spec();
    s.platform = Platform {
        minimum: 5,
        target: 7,
    };
    let b = producer::build(&s, &elf_fixture(), &[]).unwrap();
    let p = Package::parse(&b).unwrap();
    let support = Support {
        major: 1,
        minor: 2,
        features: 7,
    };
    assert_eq!(
        p.check_requirements(4, [8; 32], &support),
        Err(Error::Platform)
    );
    assert_eq!(p.check_requirements(5, [0; 32], &support), Err(Error::Abi));
    assert_eq!(p.check_requirements(5, [8; 32], &support), Ok(()));
    assert_eq!(p.check_requirements(u32::MAX, [8; 32], &support), Ok(()));
    for support in [
        Support {
            major: 2,
            minor: 9,
            features: 7,
        },
        Support {
            major: 1,
            minor: 1,
            features: 7,
        },
        Support {
            major: 1,
            minor: 9,
            features: 1,
        },
    ] {
        assert_eq!(
            p.check_requirements(5, [8; 32], &support),
            Err(Error::UnsupportedContract)
        );
    }
}

#[test]
fn capability_requests_are_declarative_required_unknown_reject_optional_unknown_preserve() {
    let mut s = spec();
    let unknown = [CapabilityRequest {
        capability: Capability::UnknownOptional(91),
        required: false,
    }];
    s.capabilities = &unknown;
    let b = producer::build(&s, &elf_fixture(), &[]).unwrap();
    assert_eq!(
        Package::parse(&b)
            .unwrap()
            .app
            .capability_requests()
            .collect::<Vec<_>>(),
        unknown
    );
    let unknown = [CapabilityRequest {
        capability: Capability::UnknownOptional(91),
        required: true,
    }];
    s.capabilities = &unknown;
    assert_eq!(
        producer::build(&s, &elf_fixture(), &[]).err(),
        Some(Error::UnsupportedCapability(91))
    );
    let duplicate = [CAPABILITIES[0], CAPABILITIES[0]];
    s.capabilities = &duplicate;
    assert_eq!(
        producer::build(&s, &elf_fixture(), &[]).err(),
        Some(Error::Duplicate)
    );
    let b = fixture();
    let caps = field(&b, 13);
    for (at, value) in [(caps.start + 8 + 2, 2), (caps.start + 8 + 4, 1)] {
        let mut bad = b.clone();
        bad[at] = value;
        seal_manifest(&mut bad);
        rejects(&bad, Error::Reserved);
    }
}

#[test]
fn manifest_text_schema_architecture_and_identity_are_validated() {
    let b = fixture();
    for tag in [1, 6, 9] {
        let mut bad = b.clone();
        bad[field(&b, tag)].fill(0);
        seal_manifest(&mut bad);
        rejects(&bad, Error::Field);
    }
    for name in ["", "a\nb", "\u{202e}text"] {
        let mut s = spec();
        s.name = name;
        assert!(producer::build(&s, &elf_fixture(), &[]).is_err());
    }
    let mut bad = b.clone();
    bad[field(&b, 8).start] = 2;
    seal_manifest(&mut bad);
    rejects(&bad, Error::Architecture);
    let mut s = spec();
    s.platform = Platform {
        minimum: 2,
        target: 1,
    };
    assert_eq!(
        producer::build(&s, &elf_fixture(), &[]).err(),
        Some(Error::Field)
    );
    for schema in [
        DataSchema {
            current: 1,
            oldest_readable: 0,
        },
        DataSchema {
            current: 1,
            oldest_readable: 2,
        },
    ] {
        s = spec();
        s.data_schema = schema;
        assert_eq!(
            producer::build(&s, &elf_fixture(), &[]).err(),
            Some(Error::Field)
        );
    }
}

#[test]
fn malformed_elf_rejected_even_with_matching_content_and_index_hashes() {
    let b = fixture();
    let start = table_end(&b);
    for at in [0, 4, 5, 6, 16, 18, 20, 52, 54, 56] {
        let mut bad = b.clone();
        bad[start + at] ^= 8;
        seal_content(&mut bad, 0);
        assert!(Package::parse(&bad).is_err(), "ELF offset {at}");
    }
    let mut bad = b.clone();
    bad[start + 32..start + 40].copy_from_slice(&u64::MAX.to_le_bytes());
    seal_content(&mut bad, 0);
    assert!(Package::parse(&bad).is_err());
    let mut bad = b.clone();
    bad[start + 56..start + 58].copy_from_slice(&9_u16.to_le_bytes());
    seal_content(&mut bad, 0);
    rejects(&bad, Error::Elf);
}

#[test]
fn bounded_pools_are_explicit_and_producer_never_installs() {
    let resources: Vec<_> = (0..MAX_ENTRIES)
        .map(|_| Resource {
            path: "res/x",
            bytes: b"x",
        })
        .collect();
    assert_eq!(
        producer::build(&spec(), &elf_fixture(), &resources).err(),
        Some(Error::Bounds)
    );
    let huge = std::vec![0;MAX_BYTES+1];
    assert_eq!(
        producer::build(&spec(), &huge, &[]).err(),
        Some(Error::Bounds)
    );
    assert_eq!(Package::parse(&huge).err(), Some(Error::Length));
    assert!(core::mem::size_of::<Package<'_>>() < 4096);
}

#[test]
fn compact_index_eagerly_validates_last_resource_and_preserves_all_borrowed_views() {
    let names: Vec<_> = (0..MAX_ENTRIES - 1)
        .map(|i| std::format!("res/{i:02}"))
        .collect();
    let bodies: Vec<_> = (0..MAX_ENTRIES - 1)
        .map(|i| std::vec![i as u8+1;i+1])
        .collect();
    let resources: Vec<_> = names
        .iter()
        .zip(&bodies)
        .map(|(path, bytes)| Resource { path, bytes })
        .collect();
    let bytes = producer::build(&spec(), &elf_fixture(), &resources).unwrap();
    let package = Package::parse(&bytes).unwrap();
    assert!(core::mem::size_of::<Package<'_>>() <= 512);
    assert_eq!(package.resources().count(), MAX_ENTRIES - 1);
    for ((actual, path), body) in package.resources().zip(&names).zip(&bodies) {
        assert_eq!(actual.path, path);
        assert_eq!(actual.bytes, body);
        assert_eq!(actual.digest, sha(body));
        let start = bytes.as_ptr() as usize;
        let view = actual.bytes.as_ptr() as usize;
        assert!(view >= start && view + actual.bytes.len() <= start + bytes.len());
    }
    let mut bad = bytes.clone();
    *bad.last_mut().unwrap() ^= 1;
    // No resources iterator is ever constructed: parse must hash even the last
    // resource eagerly, rather than making validation depend on consumption.
    assert_eq!(Package::parse(&bad).err(), Some(Error::ContentDigest));
    assert_eq!(Package::parse(&bytes).unwrap().id(), package.id());
}

#[test]
fn total_arbitrary_inputs_and_resealed_mutations_never_panic() {
    let mut seed = 0x1234_abcd_u64;
    for length in 0..1024 {
        let mut bytes = std::vec![0;length];
        for byte in &mut bytes {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *byte = seed as u8;
        }
        let _ = Package::parse(&bytes);
    }
    let b = fixture();
    for index in 0..b.len() {
        let mut bytes = b.clone();
        bytes[index] ^= 0xa5;
        let _ = Package::parse(&bytes);
        if (HEADER..manifest_end(&b)).contains(&index) {
            seal_manifest(&mut bytes);
            let _ = Package::parse(&bytes);
        } else if (manifest_end(&b)..table_end(&b)).contains(&index) {
            seal_table(&mut bytes);
            let _ = Package::parse(&bytes);
        }
    }
}
