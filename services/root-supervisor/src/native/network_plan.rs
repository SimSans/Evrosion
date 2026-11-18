//! V4 metadata admission beside the strict Native3 decoder. All views borrow
//! their actual validated source bytes; no fake legacy catalogue is encoded.
#![forbid(unsafe_code)]
use super::{Error, native, root_v2};
use ev_userspace_contract::{Context, root_v4};
use sha2::{Digest, Sha256};

pub fn network_roles_measurement(child: root_v4::graph::Child) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"evrosion.desktop.roles.v1\0");
    h.update([child.index() as u8]);
    for (i, g) in root_v4::graph::grants(child).enumerate() {
        h.update((i as u64 + 1).to_le_bytes());
        h.update([g.kind]);
        h.update(g.rights.to_le_bytes());
        match g.source {
            root_v4::graph::Source::Root(r) => {
                h.update([1]);
                h.update(r.selector().to_le_bytes());
            }
            root_v4::graph::Source::Endpoint(c) => {
                h.update([2]);
                h.update((c.wire_index() as u64 + 1).to_le_bytes());
            }
        }
    }
    h.finalize().into()
}
pub fn network_base_graph_measurement(base: &root_v2::catalogue::Components<'_>) -> [u8; 32] {
    let (a, b) = base.measurement_parts();
    let mut h = Sha256::new();
    h.update(root_v2::catalogue::MEASUREMENT_DOMAIN);
    h.update(a);
    h.update([0; 32]);
    h.update(b);
    h.update(root_v4::graph::description());
    h.finalize().into()
}
pub fn network_layout_measurement(c: &root_v4::catalogue::Catalogue<'_>) -> [u8; 32] {
    let (a, b) = c.measurement_parts();
    let mut h = Sha256::new();
    h.update(root_v4::catalogue::MEASUREMENT_DOMAIN);
    h.update(a);
    h.update([0; 32]);
    h.update(b);
    h.update(root_v4::layout_description());
    h.update(root_v4::graph::description());
    h.finalize().into()
}
pub fn verify_network(
    bytes: &[u8],
    context: Context,
) -> Result<root_v4::catalogue::Catalogue<'_>, Error> {
    let c = root_v4::catalogue::Catalogue::decode(bytes).map_err(|_| Error::Catalogue)?;
    if context.limits != root_v4::ROOT_LIMITS {
        return Err(Error::Limits);
    }
    // Managed/Recovery use the exact V4 downloaded-cohort controller. The raw
    // mode remains included in this actual startup manifest; the immutable
    // cohort recipe deliberately masks only that mode and measurement fields.
    if network_layout_measurement(&c) != c.layout_measurement()
        || network_base_graph_measurement(c.base()) != c.base().graph_measurement()
    {
        return Err(Error::Layout);
    }
    for (child, image) in root_v4::graph::CHILDREN
        .into_iter()
        .take(6)
        .zip(c.base().images())
    {
        if image.roles != network_roles_measurement(child) || image.limits != child.limits() {
            return Err(Error::Roles);
        }
    }
    for (child, image) in [
        (root_v4::graph::Child::App, c.app_b()),
        (root_v4::graph::Child::Shell, c.bad_shell()),
        (root_v4::graph::Child::NetDriver, c.net_driver()),
        (root_v4::graph::Child::NetService, c.net_service()),
    ] {
        if image.roles != network_roles_measurement(child) || image.limits != child.limits() {
            return Err(Error::Roles);
        }
    }
    let manifest = root_v4::manifest_profile(root_v2::ManifestInputs {
        root_image: c.base().root_image(),
        catalogue: Sha256::digest(bytes).into(),
        authority: context.authority,
        limits: context.limits,
        restart_attempts: c.base().restart_attempts(),
        restart_window: c.base().restart_window(),
    })
    .map_err(|_| Error::Manifest)?;
    if <[u8; 32]>::from(Sha256::digest(manifest)) != context.manifest {
        return Err(Error::Manifest);
    }
    Ok(c)
}
/// A validated borrowed profile remains typed. Returning Components does not
/// imply legacy App6 validation; its original constructor stays private.
pub enum CheckedCatalogue<'a> {
    Native3(native::catalogue::Catalogue<'a>),
    Network(root_v4::catalogue::Catalogue<'a>),
}
impl<'a> CheckedCatalogue<'a> {
    pub fn base(&self) -> &root_v2::catalogue::Components<'a> {
        match self {
            Self::Native3(c) => c.base().components(),
            Self::Network(c) => c.base(),
        }
    }
    pub fn bytes(&self) -> &'a [u8] {
        match self {
            Self::Native3(c) => c.bytes(),
            Self::Network(c) => c.bytes(),
        }
    }
    pub fn root_abi(&self) -> [u8; 32] {
        match self {
            Self::Native3(_) => native::ABI,
            Self::Network(_) => root_v4::ABI,
        }
    }
    pub const fn is_network(&self) -> bool {
        matches!(self, Self::Network(_))
    }
    pub fn package_a(&self) -> [u8; 32] {
        match self {
            Self::Native3(c) => c.package_a(),
            Self::Network(c) => c.package_a(),
        }
    }
    pub fn package_b(&self) -> [u8; 32] {
        match self {
            Self::Native3(c) => c.package_b(),
            Self::Network(c) => c.package_b(),
        }
    }
    pub fn package_b_build(&self) -> [u8; 32] {
        match self {
            Self::Native3(c) => c.package_b_build(),
            Self::Network(c) => c.package_b_build(),
        }
    }
    pub fn package_a_bytes(&self) -> u64 {
        match self {
            Self::Native3(c) => c.package_a_bytes(),
            Self::Network(c) => c.package_a_bytes(),
        }
    }
    pub fn package_b_bytes(&self) -> u64 {
        match self {
            Self::Native3(c) => c.package_b_bytes(),
            Self::Network(c) => c.package_b_bytes(),
        }
    }
    pub fn layout_measurement(&self) -> [u8; 32] {
        match self {
            Self::Native3(c) => c.layout_measurement(),
            Self::Network(c) => c.layout_measurement(),
        }
    }
    pub fn cohort_parts(&self) -> (&'a [u8], &'a [u8], &'a [u8]) {
        match self {
            Self::Native3(c) => c.cohort_parts(),
            Self::Network(c) => c.cohort_parts(),
        }
    }
    pub fn boot_mode(&self) -> native::catalogue::BootMode {
        use {native::catalogue::BootMode as Old, root_v4::catalogue::BootMode as New};
        match self {
            Self::Native3(c) => c.boot_mode(),
            Self::Network(c) => match c.boot_mode() {
                New::Standalone => Old::Standalone,
                New::SystemManaged => Old::SystemManaged,
                New::Recovery => Old::Recovery,
            },
        }
    }
    pub fn app_b(&self) -> native::catalogue::AppImage {
        match self {
            Self::Native3(c) => c.app_b(),
            Self::Network(c) => image(c.app_b()),
        }
    }
    pub fn bad_shell(&self) -> native::catalogue::AppImage {
        match self {
            Self::Native3(c) => c.bad_shell(),
            Self::Network(c) => image(c.bad_shell()),
        }
    }
    /// Exact V4 metadata remains available without widening a legacy type.
    pub fn network(&self) -> Option<&root_v4::catalogue::Catalogue<'a>> {
        match self {
            Self::Native3(_) => None,
            Self::Network(c) => Some(c),
        }
    }
}
fn image(i: root_v4::catalogue::Image) -> native::catalogue::AppImage {
    native::catalogue::AppImage {
        image: i.image,
        descriptor: i.descriptor,
        abi: i.abi,
        limits: i.limits,
        roles: i.roles,
    }
}
#[cfg(test)]
#[path = "network_plan_tests.rs"]
mod tests;
