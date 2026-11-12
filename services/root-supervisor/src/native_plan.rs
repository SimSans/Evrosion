//! Safe Native profile metadata verification. It constructs no capabilities or
//! loaded executables; actual readonly banks/mappings remain loader obligations.
#![forbid(unsafe_code)]
use ev_userspace_contract::{
    Context,
    root_v2::{
        self,
        native::{self, catalogue::Catalogue},
    },
};
use sha2::{Digest as _, Sha256};
#[path = "native/owner.rs"]
pub mod owner;
#[cfg(feature = "native-root")]
#[path = "native/state.rs"]
pub mod state;
#[cfg(feature = "native-root")]
#[path = "native/storage_core.rs"]
pub mod storage;
#[path = "native/system.rs"]
pub mod system;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    A,
    B,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Catalogue,
    Limits,
    Layout,
    Roles,
    Manifest,
}
pub fn layout_measurement(catalogue: &Catalogue<'_>) -> [u8; 32] {
    let (a, b) = catalogue.measurement_parts();
    let mut hash = Sha256::new();
    hash.update(native::catalogue::MEASUREMENT_DOMAIN);
    hash.update(a);
    hash.update([0; 32]);
    hash.update(b);
    hash.update(native::layout_description());
    hash.update(root_v2::graph::description());
    hash.finalize().into()
}
pub fn verify(bytes: &[u8], context: Context) -> Result<Catalogue<'_>, Error> {
    let catalogue = Catalogue::decode(bytes).map_err(|_| Error::Catalogue)?;
    if context.limits != crate::desktop_plan::ROOT_LIMITS {
        return Err(Error::Limits);
    }
    if layout_measurement(&catalogue) != catalogue.layout_measurement() {
        return Err(Error::Layout);
    }
    for (child, image) in root_v2::graph::CHILDREN
        .into_iter()
        .zip(catalogue.base().images())
    {
        if crate::desktop_plan::roles_measurement(child) != image.roles {
            return Err(Error::Roles);
        }
    }
    let manifest = native::manifest_profile(root_v2::ManifestInputs {
        root_image: catalogue.base().root_image(),
        catalogue: Sha256::digest(bytes).into(),
        authority: context.authority,
        limits: context.limits,
        restart_attempts: catalogue.base().restart_attempts(),
        restart_window: catalogue.base().restart_window(),
    })
    .map_err(|_| Error::Manifest)?;
    if <[u8; 32]>::from(Sha256::digest(manifest)) != context.manifest {
        return Err(Error::Manifest);
    }
    Ok(catalogue)
}
#[cfg(test)]
mod tests {
    use super::*;
    use ev_userspace_contract::root_v2::{catalogue as base, native::catalogue as n};
    fn fixture() -> ([u8; n::SIZE], Context) {
        let base = base::encode(base::Description {
            root_image: [1; 32],
            kernel_input: [2; 32],
            graph: [3; 32],
            app_id: [4; 16],
            package: [5; 32],
            app_build: [6; 32],
            provenance: base::Provenance::Zion,
            restart_attempts: 3,
            restart_window: 60000,
            images: core::array::from_fn(|i| base::Image {
                role: root_v2::graph::CHILDREN[i].image(),
                image: [i as u8 + 10; 32],
                descriptor: [i as u8 + 20; 32],
                abi: ev_userspace_contract::ABI,
                limits: base::CHILD_LIMITS,
                display_layout: i == 5,
                grants: base::CHILD_ROLE_COUNTS[i],
                roles: crate::desktop_plan::roles_measurement(root_v2::graph::CHILDREN[i]),
            }),
        })
        .unwrap();
        let description = |layout| n::Description {
            base: &base,
            app_b: n::AppImage {
                image: [41; 32],
                descriptor: [42; 32],
                abi: ev_userspace_contract::ABI,
                limits: base::CHILD_LIMITS,
                roles: crate::desktop_plan::roles_measurement(root_v2::graph::Child::App),
            },
            bad_shell: n::AppImage {
                image: [51; 32],
                descriptor: [52; 32],
                abi: ev_userspace_contract::ABI,
                limits: base::CHILD_LIMITS,
                roles: crate::desktop_plan::roles_measurement(root_v2::graph::Child::Shell),
            },
            boot_mode: n::BootMode::Standalone,
            package_b: [43; 32],
            package_b_build: [44; 32],
            package_a_bytes: 4097,
            package_b_bytes: 8192,
            layout_measurement: layout,
        };
        let draft = n::encode(description([1; 32])).unwrap();
        let measured = layout_measurement(&n::Catalogue::decode(&draft).unwrap());
        let bytes = n::encode(description(measured)).unwrap();
        let mut context = Context {
            epoch: 1,
            incarnation: 2,
            process: 3,
            limits: crate::desktop_plan::ROOT_LIMITS,
            manifest: [0; 32],
            authority: [4; 32],
        };
        context.manifest = Sha256::digest(
            native::manifest_profile(root_v2::ManifestInputs {
                root_image: [1; 32],
                catalogue: Sha256::digest(bytes).into(),
                authority: context.authority,
                limits: context.limits,
                restart_attempts: 3,
                restart_window: 60000,
            })
            .unwrap(),
        )
        .into();
        (bytes, context)
    }
    #[test]
    fn full_native2048_measurement_binds880_and_rejects_desktop_consumer() {
        let (b, c) = fixture();
        assert!(verify(&b, c).is_ok());
        assert!(crate::desktop_plan::verify(&b, c).is_err());
    }
    #[test]
    fn native_layout_authority_and_extension_substitution_refuse() {
        let (b, c) = fixture();
        let mut changed = b;
        changed[n::BASE_SIZE + 80] ^= 1;
        assert!(matches!(verify(&changed, c), Err(Error::Layout)));
        let mut c = c;
        c.authority[0] ^= 1;
        assert!(matches!(verify(&b, c), Err(Error::Manifest)));
    }
    #[test]
    fn native_store_and_measured_layout_use_same_closed_regions() {
        let b = native::layout_description();
        let word = |at| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
        for (i, r) in [
            ev_store::native::Region::System,
            ev_store::native::Region::AppRegistry,
            ev_store::native::Region::AppData,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(word(112 + i * 8), r.physical_start() as u64);
            assert_eq!(word(144 + i * 8), r.wire_start() as u64);
        }
    }
}

/// Producer and consumer share the complete Native recipe; no Desktop-only hash.
pub fn graph_measurement(catalogue: &Catalogue<'_>) -> [u8; 32] {
    layout_measurement(catalogue)
}
/// Current native reference contracts. Discovery/support is metadata only;
/// actual startup/data authority remains explicitly delegated and scoped.
pub struct Contracts;
impl ev_zion::Contracts for Contracts {
    fn supported(&self, name: &str, major: u16) -> Option<ev_zion::ContractSupport> {
        (major == 1
            && matches!(
                name,
                "ev.internal.file"
                    | "ev.internal.focused-input"
                    | "ev.internal.surface-present"
                    | "ev.app.private-data"
            ))
        .then_some(ev_zion::ContractSupport {
            minor: 0,
            features: 0,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageError {
    Metadata(Error),
    Package(ev_zion::Error),
    Length,
    Digest,
    Identity,
    Build,
    Schema,
    PrivateData,
}
/// The borrowed slices are actual complete readonly banks, never caller-shaped
/// compatibility tags. Initial verification fully parses and hashes both banks.
/// Checked views keep those immutable proofs and recheck current requirements;
/// the Registry independently matches their exact backing before cache reuse.
pub struct Packages<'a> {
    catalogue: Catalogue<'a>,
    a: &'a [u8],
    b: &'a [u8],
    // These views borrow the actual immutable banks. Construction fully checks
    // every body/index/hash once; no writable metadata can replace that proof.
    parsed: [ev_zion::Package<'a>; 2],
}
impl<'a> Packages<'a> {
    pub fn verify(
        bytes: &'a [u8],
        context: Context,
        a: &'a [u8],
        b: &'a [u8],
    ) -> Result<Self, PackageError> {
        let catalogue = verify(bytes, context).map_err(PackageError::Metadata)?;
        if a.len() as u64 != catalogue.package_a_bytes()
            || b.len() as u64 != catalogue.package_b_bytes()
        {
            return Err(PackageError::Length);
        }
        let parsed = [
            ev_zion::Package::parse(a).map_err(PackageError::Package)?,
            ev_zion::Package::parse(b).map_err(PackageError::Package)?,
        ];
        let value = Self {
            catalogue,
            a,
            b,
            parsed,
        };
        value.checked(Slot::A)?;
        value.checked(Slot::B)?;
        Ok(value)
    }
    pub fn catalogue(&self) -> &Catalogue<'a> {
        &self.catalogue
    }
    pub fn bytes(&self, slot: Slot) -> &'a [u8] {
        match slot {
            Slot::A => self.a,
            Slot::B => self.b,
        }
    }
    pub fn digest(&self, slot: Slot) -> [u8; 32] {
        match slot {
            Slot::A => self.catalogue.package_a(),
            Slot::B => self.catalogue.package_b(),
        }
    }
    pub fn slot(&self, digest: [u8; 32]) -> Option<Slot> {
        [Slot::A, Slot::B]
            .into_iter()
            .find(|&slot| self.digest(slot) == digest)
    }
    pub fn app(&self) -> ev_zion::AppId {
        ev_zion::AppId::new(self.catalogue.base().app_id()).unwrap()
    }
    pub fn checked(&self, slot: Slot) -> Result<&ev_zion::Package<'a>, PackageError> {
        let package = &self.parsed[match slot {
            Slot::A => 0,
            Slot::B => 1,
        }];
        let (image, build) = match slot {
            Slot::A => (
                self.catalogue.base().images().nth(4).unwrap().image,
                self.catalogue.base().app_build(),
            ),
            Slot::B => (
                self.catalogue.app_b().image,
                self.catalogue.package_b_build(),
            ),
        };
        if package.id().bytes() != self.digest(slot) || package.executable().digest != image {
            return Err(PackageError::Digest);
        }
        if package.app().claimed_app.bytes() != self.catalogue.base().app_id() {
            return Err(PackageError::Identity);
        }
        if package.app().build_id != build {
            return Err(PackageError::Build);
        }
        package
            .compatible(1, ev_userspace_contract::ABI, &Contracts)
            .map_err(PackageError::Package)?;
        if package.app().data_schema.current != 1 || package.app().data_schema.oldest_readable != 1
        {
            return Err(PackageError::Schema);
        }
        let request = package
            .app()
            .capability_requests()
            .any(|r| r.required && r.capability == ev_zion::Capability::AppPrivateData);
        let contract = package.app().contracts().any(|r| {
            r.name == "ev.app.private-data"
                && r.major == 1
                && r.minimum_minor == 0
                && r.features == 0
        });
        if !request || !contract {
            return Err(PackageError::PrivateData);
        }
        Ok(package)
    }
    /// Actual immutable cohort references for Store formatting ONLY. No health
    /// report, known-good promotion or generation execution is fabricated.
    pub fn format_manifest(
        &self,
        region: ev_store::native::Region,
    ) -> ev_store::GenerationManifest {
        let mut h = Sha256::new();
        h.update(b"evrosion.native.store-format.v1\0");
        h.update(self.catalogue.bytes());
        h.update(region.physical_start().to_le_bytes());
        ev_store::GenerationManifest {
            generation: ev_store::GenerationId::new(1).unwrap(),
            cohort: h.finalize().into(),
            supervisor_image: self.catalogue.base().root_image(),
            abi: native::ABI,
            health_contract: Sha256::digest(b"format-context-only; no admitted health").into(),
            health_version: 1,
            required_checks: ev_store::HEALTH_STORAGE | ev_store::HEALTH_SUPERVISOR,
        }
    }
    /// Original creation context for the stable owner/App policy namespace.
    /// This is neither current System admission nor approved READ permission.
    pub fn grant_format_manifest(&self, owner: [u8; 16]) -> ev_store::GenerationManifest {
        let mut h = Sha256::new();
        h.update(b"evrosion.native.owner-grant-namespace.v1\0");
        h.update(owner);
        h.update(self.app().bytes());
        h.update(1u64.to_le_bytes());
        h.update(
            ev_store::native::Region::GrantPolicy
                .physical_start()
                .to_le_bytes(),
        );
        ev_store::GenerationManifest {
            generation: ev_store::GenerationId::new(1).unwrap(),
            cohort: h.finalize().into(),
            supervisor_image: self.catalogue.base().root_image(),
            abi: native::ABI,
            health_contract: Sha256::digest(b"format-context-only; no System admission or health")
                .into(),
            health_version: 1,
            required_checks: 3,
        }
    }
}
impl ev_app_registry::Packages for Packages<'_> {
    fn resolve(&self, digest: [u8; 32]) -> Option<&[u8]> {
        self.slot(digest).map(|slot| self.bytes(slot))
    }
    fn parsed(&self, digest: [u8; 32]) -> Option<&ev_zion::Package<'_>> {
        self.slot(digest).and_then(|slot| self.checked(slot).ok())
    }
}
