//! Typed M8 Root selection over the shared strict manifest decoder. V4 and
//! older wrappers cannot select this ABI, graph, authority domain or layout.
use crate::root_manifest_v2::{self, kind_tag};
use ev_userspace_contract::root_v5;
pub use root_manifest_v2::Error;
use sha2::{Digest, Sha256};
pub const AUTHORITY_DOMAIN: &[u8] = root_v5::AUTHORITY_DOMAIN;
pub const MAX_BYTES: usize =
    root_v5::MANIFEST_HEADER + root_v5::MAX_GRANTS * root_v5::MANIFEST_GRANT_BYTES;
pub struct CurrentRoot<'a> {
    manifest: root_manifest_v2::Manifest<'a>,
}
impl<'a> CurrentRoot<'a> {
    pub fn manifest(&self) -> &root_manifest_v2::Manifest<'a> {
        &self.manifest
    }
    /// Join the exact measured12KiB bytes and canonical V5 graph/layout. The
    /// catalogue's nonzero measurement fields remain descriptive until the
    /// actual artifact producer independently joins/finalizes that transcript.
    pub fn catalogue<'b>(
        &self,
        bytes: &'b [u8],
    ) -> Result<root_v5::catalogue::Catalogue<'b>, Error> {
        if Sha256::digest(bytes).as_slice() != self.manifest.expected_catalogue_digest() {
            return Err(Error::Measurement);
        }
        let catalogue = root_v5::catalogue::Catalogue::decode(bytes).map_err(|_| Error::Roles)?;
        if catalogue.root_image() != <[u8; 32]>::from(Sha256::digest(self.manifest.root_image())) {
            return Err(Error::Image);
        }
        if catalogue.restart_attempts() != self.manifest.bytes()[112]
            || catalogue.restart_window()
                != u64::from_le_bytes(self.manifest.bytes()[120..128].try_into().unwrap())
        {
            return Err(Error::Restart);
        }
        Ok(catalogue)
    }
}
pub fn verify<'a>(
    bytes: &'a [u8],
    expected: [u8; 32],
    image: &'a [u8],
) -> Result<CurrentRoot<'a>, Error> {
    let manifest = root_manifest_v2::verify_v5(bytes, expected, image)?;
    let [cpu, frames, processes, threads] = root_v5::ROOT_LIMITS;
    if manifest.limits() != crate::scheduler::Limits::new(cpu, frames, processes, threads) {
        return Err(Error::Limits);
    }
    if manifest.profile() != root_v5::PROFILE || manifest.abi_fingerprint() != root_v5::ABI {
        return Err(Error::Profile);
    }
    if manifest.grants().count() != root_v5::CURRENT_GRANTS
        || manifest.executable() != root_v5::EXECUTABLE_SELECTOR
    {
        return Err(Error::Roles);
    }
    if manifest.expected_authority_digest() == [0; 32]
        || manifest.expected_catalogue_digest() == [0; 32]
    {
        return Err(Error::Measurement);
    }
    if u64::from_le_bytes(bytes[120..128].try_into().unwrap()) == u64::MAX {
        return Err(Error::Restart);
    }
    for (actual, expected) in manifest.grants().zip(root_v5::ROLES) {
        if (actual.selector, kind_tag(actual.kind), actual.rights.bits())
            != (expected.role.selector(), expected.kind, expected.rights)
        {
            return Err(Error::Roles);
        }
    }
    Ok(CurrentRoot { manifest })
}
