//! Thin typed v4 selection over the existing measured Root manifest validator.
//! No source authority, scheduler or custody lifecycle is duplicated here.
use crate::root_manifest_v2::{self, kind_tag};
use ev_userspace_contract::root_v4;
pub use root_manifest_v2::Error;
pub const AUTHORITY_DOMAIN: &[u8] = b"evrosion.bootstrap.authority.root.v4\0";
pub const MAX_BYTES: usize =
    root_v4::MANIFEST_HEADER + root_v4::MAX_GRANTS * root_v4::MANIFEST_GRANT_BYTES;
pub struct CurrentRoot<'a> {
    manifest: root_manifest_v2::Manifest<'a>,
}
impl<'a> CurrentRoot<'a> {
    pub fn manifest(&self) -> &root_manifest_v2::Manifest<'a> {
        &self.manifest
    }
}
pub fn verify<'a>(
    bytes: &'a [u8],
    expected: [u8; 32],
    image: &'a [u8],
) -> Result<CurrentRoot<'a>, Error> {
    let manifest = root_manifest_v2::verify_v4(bytes, expected, image)?;
    let [cpu, frames, processes, threads] = root_v4::ROOT_LIMITS;
    if manifest.limits() != crate::scheduler::Limits::new(cpu, frames, processes, threads) {
        return Err(Error::Limits);
    }
    if manifest.profile() != root_v4::PROFILE || manifest.abi_fingerprint() != root_v4::ABI {
        return Err(Error::Profile);
    }
    if manifest.grants().count() != root_v4::CURRENT_GRANTS
        || manifest.executable() != root_v4::EXECUTABLE_SELECTOR
    {
        return Err(Error::Roles);
    }
    for (actual, expected) in manifest.grants().zip(root_v4::ROLES) {
        if (actual.selector, kind_tag(actual.kind), actual.rights.bits())
            != (expected.role.selector(), expected.kind, expected.rights)
        {
            return Err(Error::Roles);
        }
    }
    Ok(CurrentRoot { manifest })
}
