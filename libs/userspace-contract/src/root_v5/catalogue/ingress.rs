//! Measured package input only; no startup image, role, install or trust grant.
use super::*;
pub const INGRESS_BYTES: usize = 192;
pub const INGRESS_AT: usize = PLACEMENT_END;
pub const INGRESS_END: usize = INGRESS_AT + INGRESS_BYTES;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum IngressProvenance {
    /// Explicit local development input, without publisher authentication.
    LocalOwnerDevelopment = 1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExternalIngress {
    pub package: Package,
    pub provenance: IngressProvenance,
}
impl ExternalIngress {
    pub fn validate(self, packages: [Package; 4]) -> Result<(), Error> {
        record(self, packages).map(|_| ())
    }
}
/// The existing Candidate occupies its original place. Only its aligned tail
/// can carry the independently described full package.
pub fn ingress_offset(candidate: Package) -> Result<u32, Error> {
    if candidate.bank != PackageBank::Candidate {
        return Err(Error::Package);
    }
    u64::from(candidate.offset)
        .checked_add(candidate.bytes)
        .and_then(|end| end.checked_add(u64::from(PACKAGE_ALIGNMENT - 1)))
        .map(|end| end & !u64::from(PACKAGE_ALIGNMENT - 1))
        .filter(|end| *end <= PackageBank::Candidate.capacity_bytes())
        .and_then(|end| end.try_into().ok())
        .ok_or(Error::Package)
}
pub(super) fn record(
    value: ExternalIngress,
    packages: [Package; 4],
) -> Result<[u8; INGRESS_BYTES], Error> {
    let p = value.package;
    if p.bank != PackageBank::Candidate
        || p.offset != ingress_offset(packages[PackageKind::EditorCandidate.index()])?
        || p.bytes == 0
        || p.bytes > resources::PACKAGE_MAX_BYTES
        || u64::from(p.offset)
            .checked_add(p.bytes)
            .is_none_or(|end| end > p.bank.capacity_bytes())
        || [&p.digest, &p.build, &p.image]
            .into_iter()
            .any(|hash| !nonzero(hash))
        || !nonzero(&p.app_id)
        || packages
            .into_iter()
            .any(|old| old.app_id == p.app_id || old.digest == p.digest)
    {
        return Err(Error::Package);
    }
    let mut b = [0; INGRESS_BYTES];
    b[..8].copy_from_slice(b"EVXING01");
    b[8..10].copy_from_slice(&1u16.to_le_bytes());
    b[10..12].copy_from_slice(&(INGRESS_BYTES as u16).to_le_bytes());
    b[12] = value.provenance as u8;
    b[13] = p.bank as u8;
    b[16..20].copy_from_slice(&p.offset.to_le_bytes());
    put(&mut b, 24, p.bytes);
    b[32..48].copy_from_slice(&p.app_id);
    b[48..80].copy_from_slice(&p.digest);
    b[80..112].copy_from_slice(&p.build);
    b[112..144].copy_from_slice(&p.image);
    Ok(b)
}
pub(super) fn read(b: &[u8]) -> ExternalIngress {
    // Only exposed through a fully canonical Catalogue decoder.
    ExternalIngress {
        package: Package {
            bank: PackageBank::Candidate,
            offset: u32::from_le_bytes(b[16..20].try_into().unwrap()),
            bytes: word(b, 24),
            app_id: b[32..48].try_into().unwrap(),
            digest: b[48..80].try_into().unwrap(),
            build: b[80..112].try_into().unwrap(),
            image: b[112..144].try_into().unwrap(),
        },
        provenance: IngressProvenance::LocalOwnerDevelopment,
    }
}
