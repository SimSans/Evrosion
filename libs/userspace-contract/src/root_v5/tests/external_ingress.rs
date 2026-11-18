use super::*;
use catalogue::{ExternalIngress, INGRESS_AT, INGRESS_END, IngressProvenance, PackageBank};
fn ingress() -> ExternalIngress {
    ExternalIngress {
        package: catalogue::Package {
            app_id: [201; 16],
            digest: [202; 32],
            build: [203; 32],
            image: [204; 32],
            bytes: 4096,
            bank: PackageBank::Candidate,
            offset: catalogue::ingress_offset(description().packages[3]).unwrap(),
        },
        provenance: IngressProvenance::LocalOwnerDevelopment,
    }
}
#[test]
fn absent_ingress_retains_old_zero_tail_and_four_exact_package_identities() {
    let old = catalogue_bytes();
    assert_eq!(
        old,
        catalogue::encode_with_ingress(description(), None).unwrap()
    );
    assert!(
        old[catalogue::PLACEMENT_END..]
            .iter()
            .all(|byte| *byte == 0)
    );
    let parsed = catalogue::Catalogue::decode(&old).unwrap();
    assert_eq!(parsed.external_ingress(), None);
    for kind in catalogue::PACKAGES {
        assert_eq!(parsed.package(kind), description().packages[kind.index()]);
    }
}
#[test]
fn ingress_is_distinct_nonexecuting_record_and_exact_candidate_tail() {
    let old = catalogue_bytes();
    let bytes = catalogue::encode_with_ingress(description(), Some(ingress())).unwrap();
    assert_eq!(&old[..INGRESS_AT], &bytes[..INGRESS_AT]);
    assert_eq!(&old[INGRESS_END..], &bytes[INGRESS_END..]);
    let parsed = catalogue::Catalogue::decode(&bytes).unwrap();
    assert_eq!(parsed.external_ingress(), Some(ingress()));
    assert_eq!(parsed.images().count(), 10);
    assert_eq!(parsed.packages().count(), 4);
    assert_eq!(graph::CHILDREN.len(), 11);
    assert_eq!(ROLES.len(), 37);
    // The previous decoder required the complete post-placement tail to zero.
    assert!(
        bytes[catalogue::PLACEMENT_END..]
            .iter()
            .any(|byte| *byte != 0)
    );
    assert_eq!(
        ROLES
            .iter()
            .find(|spec| spec.role == Role::PackageCandidate)
            .unwrap()
            .rights,
        5
    );
}
#[test]
fn malformed_source_version_magic_reserved_and_bank_never_normalize_to_supported() {
    let bytes = catalogue::encode_with_ingress(description(), Some(ingress())).unwrap();
    for offset in [0, 7, 8, 10, 12, 13, 14, 20, 23, 144, 191] {
        let mut bad = bytes;
        bad[INGRESS_AT + offset] ^= 0x80;
        assert!(
            catalogue::Catalogue::decode(&bad).is_err(),
            "offset {offset}"
        );
    }
    for end in [INGRESS_AT, INGRESS_END - 1, catalogue::SIZE - 1] {
        assert!(catalogue::Catalogue::decode(&bytes[..end]).is_err());
    }
}
#[test]
fn foreign_alias_overlap_unaligned_gap_and_overflow_refuse() {
    for mutation in 0..12 {
        let mut value = ingress();
        match mutation {
            0..=3 => value.package.app_id = description().packages[mutation].app_id,
            4 => value.package.digest = description().packages[3].digest,
            5 => value.package.bank = PackageBank::Current,
            6 => value.package.offset = 0,
            7 => value.package.offset += 1,
            8 => value.package.offset += 16,
            9 => value.package.bytes = u64::MAX,
            10 => value.package.bytes = 0,
            11 => value.package.image = [0; 32],
            _ => unreachable!(),
        }
        assert_eq!(
            catalogue::encode_with_ingress(description(), Some(value)),
            Err(Error::Package)
        );
    }
}
#[test]
fn exact_bank_end_fits_one_extra_byte_and_full_candidate_refuse() {
    let mut value = ingress();
    value.package.bytes = PackageBank::Candidate.capacity_bytes() - u64::from(value.package.offset);
    assert!(catalogue::encode_with_ingress(description(), Some(value)).is_ok());
    value.package.bytes += 1;
    assert_eq!(
        catalogue::encode_with_ingress(description(), Some(value)),
        Err(Error::Package)
    );
    let mut full = description();
    full.packages[3].bytes = resources::PACKAGE_MAX_BYTES;
    value.package.offset = catalogue::ingress_offset(full.packages[3]).unwrap();
    value.package.bytes = 1;
    assert_eq!(
        catalogue::encode_with_ingress(full, Some(value)),
        Err(Error::Package)
    );
}
