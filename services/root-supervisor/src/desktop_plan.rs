//! Closed desktop metadata policy. Decoded fields create no capabilities.
#![forbid(unsafe_code)]
use ev_userspace_contract::{
    Context,
    root_v2::{
        self,
        catalogue::{Catalogue, Image},
        graph::{self, Child, Source},
    },
};
use sha2::{Digest, Sha256};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Catalogue,
    Graph,
    Roles,
    Manifest,
    Limits,
}
pub const ROOT_LIMITS: [u64; 4] = [65536, 512, 8, 8];
pub const RESTART_ATTEMPTS: u8 = 3;
pub const RESTART_WINDOW: u64 = 60000;
pub fn graph_measurement(catalogue: &Catalogue<'_>) -> [u8; 32] {
    let (a, b) = catalogue.measurement_parts();
    let mut hash = Sha256::new();
    hash.update(root_v2::catalogue::MEASUREMENT_DOMAIN);
    hash.update(a);
    hash.update([0; 32]);
    hash.update(b);
    hash.update(graph::description());
    hash.finalize().into()
}
pub fn roles_measurement(child: Child) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"evrosion.desktop.roles.v1\0");
    h.update([child.index() as u8]);
    for (i, g) in graph::grants(child).iter().enumerate() {
        h.update((i as u64 + 1).to_le_bytes());
        h.update([g.kind]);
        h.update(g.rights.to_le_bytes());
        match g.source {
            Source::Root(role) => {
                h.update([1]);
                h.update(role.selector().to_le_bytes());
            }
            Source::Endpoint(channel) => {
                h.update([2]);
                h.update((channel.index() as u64 + 1).to_le_bytes());
            }
        }
    }
    h.finalize().into()
}
pub fn verify<'a>(bytes: &'a [u8], context: Context) -> Result<Catalogue<'a>, Error> {
    let c = Catalogue::decode(bytes).map_err(|_| Error::Catalogue)?;
    if context.limits != ROOT_LIMITS {
        return Err(Error::Limits);
    }
    if graph_measurement(&c) != c.graph_measurement() {
        return Err(Error::Graph);
    }
    for (child, image) in graph::CHILDREN.into_iter().zip(c.images()) {
        if roles_measurement(child) != image.roles {
            return Err(Error::Roles);
        }
    }
    let manifest = root_v2::manifest_profile(root_v2::ManifestInputs {
        root_image: c.root_image(),
        catalogue: Sha256::digest(bytes).into(),
        authority: context.authority,
        limits: context.limits,
        restart_attempts: c.restart_attempts(),
        restart_window: c.restart_window(),
    })
    .map_err(|_| Error::Manifest)?;
    if <[u8; 32]>::from(Sha256::digest(manifest)) != context.manifest {
        return Err(Error::Manifest);
    }
    Ok(c)
}
pub fn image<'a>(c: &Catalogue<'a>, child: Child) -> Image {
    c.images().nth(child.index()).unwrap()
}
#[cfg(test)]
mod tests {
    use super::*;
    use ev_userspace_contract::root_v2::catalogue::{self, Description, Provenance};
    fn fixture() -> ([u8; catalogue::SIZE], Context) {
        let mut description = Description {
            root_image: [1; 32],
            kernel_input: [2; 32],
            graph: [0; 32],
            app_id: [3; 16],
            package: [4; 32],
            app_build: [5; 32],
            provenance: Provenance::Zion,
            restart_attempts: RESTART_ATTEMPTS,
            restart_window: RESTART_WINDOW,
            images: core::array::from_fn(|i| Image {
                role: graph::CHILDREN[i].image(),
                image: [i as u8 + 1; 32],
                descriptor: [8; 32],
                abi: ev_userspace_contract::ABI,
                limits: catalogue::CHILD_LIMITS,
                display_layout: i == 5,
                grants: catalogue::CHILD_ROLE_COUNTS[i],
                roles: roles_measurement(graph::CHILDREN[i]),
            }),
        };
        let first = catalogue::encode(description).unwrap();
        let c = Catalogue::decode(&first).unwrap();
        let graph = graph_measurement(&c);
        description = Description {
            graph,
            root_image: c.root_image(),
            kernel_input: c.kernel_input(),
            app_id: c.app_id(),
            package: c.package(),
            app_build: c.app_build(),
            provenance: c.provenance(),
            restart_attempts: c.restart_attempts(),
            restart_window: c.restart_window(),
            images: core::array::from_fn(|i| c.images().nth(i).unwrap()),
        };
        let bytes = catalogue::encode(description).unwrap();
        let mut context = Context {
            epoch: 1,
            incarnation: 2,
            process: 3,
            limits: ROOT_LIMITS,
            manifest: [0; 32],
            authority: [6; 32],
        };
        context.manifest = Sha256::digest(
            root_v2::manifest_profile(root_v2::ManifestInputs {
                root_image: [1; 32],
                catalogue: Sha256::digest(bytes).into(),
                authority: context.authority,
                limits: context.limits,
                restart_attempts: RESTART_ATTEMPTS,
                restart_window: RESTART_WINDOW,
            })
            .unwrap(),
        )
        .into();
        (bytes, context)
    }
    #[test]
    fn measured_catalogue_reconstructs_kernel_bound_manifest_without_self_reference() {
        let (b, c) = fixture();
        assert!(verify(&b, c).is_ok());
    }
    #[test]
    fn catalogue_substitution_or_authority_drift_rejects() {
        let (b, mut c) = fixture();
        c.authority[0] ^= 1;
        assert!(matches!(verify(&b, c), Err(Error::Manifest)));
        let (mut b, c) = fixture();
        b[16] ^= 1;
        assert!(verify(&b, c).is_err());
    }
}
