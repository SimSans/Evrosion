use super::*;
#[derive(Clone, Copy)]
pub(crate) struct Artifact {
    pub bytes: &'static [u8],
    pub sha256: [u8; 32],
}
#[derive(Clone, Copy)]
pub(crate) struct Placement {
    pub bank: u8,
    pub offset: u32,
}
pub(crate) struct Assets {
    pub root: Artifact,
    pub manifest: &'static [u8],
    pub measurement: [u8; 32],
    pub catalogue: Artifact,
    pub images: [Artifact; 10],
    pub packages: [Artifact; 4],
    pub placements: [Placement; 4],
    pub external_ingress: Option<Artifact>,
}
impl Assets {
    /// Syntax/descriptive catalogue fields never replace independent actual
    /// bytes/hash, strict descriptor, image/layout and package joins.
    pub fn verify(&self) -> ev_kernel::root_manifest_v5::CurrentRoot<'static> {
        for artifact in core::iter::once(self.root)
            .chain(core::iter::once(self.catalogue))
            .chain(self.images)
            .chain(self.packages)
            .chain(self.external_ingress)
        {
            assert!(!artifact.bytes.is_empty(), "V5 actual artifact required");
            assert_eq!(
                <[u8; 32]>::from(Sha256::digest(artifact.bytes)),
                artifact.sha256,
                "V5 artifact bytes/hash join"
            );
        }
        let root =
            ev_kernel::root_manifest_v5::verify(self.manifest, self.measurement, self.root.bytes)
                .expect("typed actual V5 Root manifest");
        let catalogue = root
            .catalogue(self.catalogue.bytes)
            .expect("measured actual V5 catalogue");
        ev_kernel::root_producer_v5::verify_external_ingress(
            &catalogue,
            self.external_ingress.map(|artifact| artifact.bytes),
        )
        .expect("measured full external ingress bytes and readonly Candidate tail");
        assert_eq!(
            root.manifest().expected_catalogue_digest(),
            self.catalogue.sha256
        );
        // This validates actual Root stack/layout before selected factories.
        ev_kernel::executable::Image::from_root_v5(&root).expect("actual V5 Root physical layout");
        for slot in graph::IMAGES {
            let artifact = self.images[slot.index()];
            let expected = catalogue.image(slot);
            assert_eq!(artifact.sha256, expected.image, "actual V5 child SHA");
            let descriptor = ServiceImage::verify_m8(artifact.bytes, artifact.sha256, slot)
                .expect("closed actual V5 child descriptor");
            assert_eq!(
                descriptor.digest(),
                expected.descriptor,
                "actual V5 descriptor join"
            );
            assert_eq!(
                expected.role_shape,
                ev_kernel::root_producer_v5::role_shape_digest(slot),
                "canonical V5 image role shape"
            );
        }
        for child in graph::CHILDREN {
            assert_eq!(
                catalogue.instance_binding(child),
                ev_kernel::root_producer_v5::instance_binding_digest(child),
                "canonical V5 per-instance bindings"
            );
        }
        for package in v5::catalogue::PACKAGES {
            let artifact = self.packages[package.index()];
            let expected = catalogue.package(package);
            assert_eq!(artifact.sha256, expected.digest);
            assert_eq!(artifact.bytes.len() as u64, expected.bytes);
            // Signed package validation/selected update admission remains the
            // Root producer's independent trust boundary, never this byte hash.
        }
        for (index, placement) in self.placements.iter().enumerate() {
            assert!(placement.bank < 2);
            let first = placement.offset as usize;
            let declared = catalogue.package(v5::catalogue::PACKAGES[index]);
            assert_eq!(
                placement.bank, declared.bank as u8,
                "actual package bank/catalogue join"
            );
            assert_eq!(
                placement.offset, declared.offset,
                "actual package offset/catalogue join"
            );
            assert!(first.is_multiple_of(v5::catalogue::PACKAGE_ALIGNMENT as usize));
            let end = first
                .checked_add(self.packages[index].bytes.len())
                .expect("V5 package placement overflow");
            assert!(
                end <= declared.bank.capacity_bytes() as usize,
                "actual full package bank capacity"
            );
            for (previous, old) in self.placements[..index].iter().enumerate() {
                if old.bank == placement.bank {
                    let old_end = old.offset as usize + self.packages[previous].bytes.len();
                    assert!(
                        end <= old.offset as usize || first >= old_end,
                        "V5 package bank overlap"
                    );
                }
            }
        }
        root
    }
}
