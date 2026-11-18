//! Actual Root compatibility policy, independent of host package tooling.
//! Parsing/compatibility creates no endpoint, signature or admission authority.
use ev_userspace_contract::{
    file_v2,
    root_v5::{catalogue, child, graph::ImageSlot},
    workspace,
};
use ev_workspace_client::semantic;
use ev_zion::{ContractSupport, Contracts, Package};
pub const PLATFORM: u32 = 1;
pub struct LoadedContracts {
    /// Only the actual Root adapter sets this after its A1 handler is loaded.
    /// This is compatibility metadata, not a provider permission or endpoint.
    pub semantic_tree: bool,
    /// Filled by native Root only from its authenticated, identity-bound
    /// Workspace FileContract reply. Source constants never establish this.
    pub file: Option<file_v2::Support>,
}
impl Contracts for LoadedContracts {
    fn supported(&self, name: &str, major: u16) -> Option<ContractSupport> {
        if self.semantic_tree && name == semantic::INTERFACE && major == semantic::MAJOR {
            return Some(ContractSupport {
                minor: semantic::MINOR,
                features: semantic::FEATURES,
            });
        }
        if name == file_v2::INTERFACE {
            return self
                .file
                .filter(|s| s.major == major && major == file_v2::VERSION)
                .map(|s| ContractSupport {
                    minor: s.minor,
                    features: s.features,
                });
        }
        ((name == workspace::INTERFACE && major == workspace::VERSION)
            || (name == "ev.internal.workspace-ui" && major == 1)
            || (name == "ev.internal.surface-present" && major == 5))
            .then_some(ContractSupport {
                minor: 0,
                features: 0,
            })
    }
}
/// Contextual compatibility wrapper used only while the actual native Root ND
/// handler and sole SystemIo owner are available. This allocates no namespace
/// and grants no AppPrivateData permission; held enrollment remains separate.
pub struct PrivateDataContracts<'a> {
    loaded: &'a LoadedContracts,
    available: bool,
}
impl<'a> PrivateDataContracts<'a> {
    pub const fn new(loaded: &'a LoadedContracts, actual_available: bool) -> Self {
        Self {
            loaded,
            available: actual_available,
        }
    }
}
impl Contracts for PrivateDataContracts<'_> {
    fn supported(&self, name: &str, major: u16) -> Option<ContractSupport> {
        if self.available
            && name == ev_userspace_contract::app_data::INTERFACE
            && major == u16::from(ev_userspace_contract::app_data::VERSION)
        {
            Some(ContractSupport {
                minor: 0,
                features: 0,
            })
        } else {
            self.loaded.supported(name, major)
        }
    }
}
/// Captured native actor/grant facts, never obtained from the support packet.
/// Equality only correlates metadata; the native owner checks the real held
/// ProcessCONTROL's identity/liveness before and after every use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceIdentity {
    pub control: u64,
    pub identity: crate::Identity,
    pub endpoint: u64,
    pub epoch: u64,
    pub mapping_epoch: u32,
    pub image: [u8; 32],
    pub descriptor: [u8; 32],
}
impl ServiceIdentity {
    pub fn valid(self) -> bool {
        self.identity.valid()
            && ![self.control, self.endpoint, self.epoch]
                .into_iter()
                .any(|v| matches!(v, 0 | u64::MAX))
            && !matches!(self.mapping_epoch, 0 | u32::MAX)
            && self.image != [0; 32]
            && self.descriptor != [0; 32]
    }
}
pub struct FileSupport {
    service: ServiceIdentity,
    support: file_v2::Support,
}
impl FileSupport {
    /// Native caller has already matched the actual finite probe response.
    /// This descriptive value alone supplies no endpoint or authority.
    pub fn observed(service: ServiceIdentity, support: file_v2::Support) -> Result<Self, Error> {
        if !service.valid() || support.major != file_v2::VERSION {
            return Err(Error::Binding);
        }
        Ok(Self { service, support })
    }
    pub fn for_service(&self, actual: ServiceIdentity) -> Result<file_v2::Support, Error> {
        if !actual.valid() || actual != self.service {
            Err(Error::Binding)
        } else {
            Ok(self.support)
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Parse,
    Requirements,
    Binding,
    Schema,
}
/// Affine metadata check tied to exact immutable package bytes. Later native52
/// staging must retain this value; it is not signature/ELF/grant acceptance.
pub struct Checked<'a> {
    package: Package<'a>,
}
impl Checked<'_> {
    pub fn package(&self) -> &Package<'_> {
        &self.package
    }
}
pub fn file_app<'a>(bytes: &'a [u8], loaded: &LoadedContracts) -> Result<Checked<'a>, Error> {
    let package = Package::parse(bytes).map_err(|_| Error::Parse)?;
    check(package, ImageSlot::Editor, loaded)
}
/// Separate opt-in contract context; historical public FileApp checks do not
/// start advertising private data merely because this source module exists.
pub fn private_file_app<'a>(
    bytes: &'a [u8],
    loaded: &PrivateDataContracts<'_>,
) -> Result<Checked<'a>, Error> {
    let package = Package::parse(bytes).map_err(|_| Error::Parse)?;
    check(package, ImageSlot::Editor, loaded)
}
fn check<'a>(
    package: Package<'a>,
    slot: ImageSlot,
    loaded: &impl Contracts,
) -> Result<Checked<'a>, Error> {
    structure(&package, slot)?;
    package
        .check_requirements(PLATFORM, child::abi(slot.representative()), loaded)
        .map_err(|_| Error::Requirements)?;
    Ok(Checked { package })
}
fn structure(package: &Package<'_>, slot: ImageSlot) -> Result<(), Error> {
    if package.app().platform.minimum > PLATFORM
        || package.app().abi != child::abi(slot.representative())
    {
        return Err(Error::Requirements);
    }
    if package.app().data_schema.current != 1 || package.app().data_schema.oldest_readable != 1 {
        return Err(Error::Schema);
    }
    Ok(())
}
fn binding(package: &Package<'_>, expected: catalogue::Package) -> Result<(), Error> {
    if package.bytes().len() as u64 != expected.bytes
        || package.id().bytes() != expected.digest
        || package.app().claimed_app.bytes() != expected.app_id
        || package.app().build_id != expected.build
        || package.executable().digest != expected.image
    {
        return Err(Error::Binding);
    }
    Ok(())
}
/// Preboot integrity/ABI/schema check only. Contract availability is deferred
/// explicitly until actual Workspace negotiation, before any App delegation.
pub fn catalogue_structure(
    bytes: &[u8],
    expected: catalogue::Package,
    slot: ImageSlot,
) -> Result<(), Error> {
    let package = Package::parse(bytes).map_err(|_| Error::Parse)?;
    structure(&package, slot)?;
    binding(&package, expected)
}
pub fn catalogue_package<'a>(
    bytes: &'a [u8],
    expected: catalogue::Package,
    slot: ImageSlot,
    loaded: &LoadedContracts,
) -> Result<Checked<'a>, Error> {
    let checked = check(
        Package::parse(bytes).map_err(|_| Error::Parse)?,
        slot,
        loaded,
    )?;
    let package = checked.package();
    binding(package, expected)?;
    Ok(checked)
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{vec, vec::Vec};

    fn package(minor: u16, features: u64) -> Vec<u8> {
        use ev_zion::{
            AppId, Contract, DataSchema, Platform, Version,
            producer::{self, Spec},
        };
        // Parser-only ELF fixture, never passed to admission or executed.
        let mut elf = vec![0; 120];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[16..18].copy_from_slice(&2u16.to_le_bytes());
        elf[18..20].copy_from_slice(&62u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1u16.to_le_bytes());
        producer::build(
            &Spec {
                app: AppId::new([7; 16]).unwrap(),
                name: "Editor",
                source: "test only",
                publisher: None,
                version: Version {
                    major: 0,
                    minor: 4,
                    patch: 0,
                },
                build_id: [4; 32],
                platform: Platform {
                    minimum: 1,
                    target: 1,
                },
                abi: child::abi(ImageSlot::Editor.representative()),
                data_schema: DataSchema {
                    current: 1,
                    oldest_readable: 1,
                },
                entrypoint: "bin/editor.elf",
                contracts: &[Contract {
                    name: file_v2::INTERFACE,
                    major: 2,
                    minimum_minor: minor,
                    features,
                }],
                capabilities: &[],
            },
            &elf,
            &[],
        )
        .unwrap()
    }
    #[test]
    fn absent_old_or_missing_bit_support_refuses_new_requirements_without_legacy_regression() {
        let old = package(0, 0);
        let new = package(1, file_v2::FEATURE_STAGED_VERIFY);
        for support in [
            None,
            Some(file_v2::Support {
                major: 2,
                minor: 0,
                features: 0,
            }),
            Some(file_v2::Support {
                major: 2,
                minor: 1,
                features: 0,
            }),
        ] {
            let loaded = LoadedContracts {
                semantic_tree: false,
                file: support,
            };
            assert!(matches!(file_app(&new, &loaded), Err(Error::Requirements)));
        }
        let old_loaded = LoadedContracts {
            semantic_tree: false,
            file: Some(file_v2::Support {
                major: 2,
                minor: 0,
                features: 0,
            }),
        };
        assert!(file_app(&old, &old_loaded).is_ok());
        let loaded = LoadedContracts {
            semantic_tree: false,
            file: Some(file_v2::SUPPORT),
        };
        assert!(file_app(&new, &loaded).is_ok());
        assert!(file_app(&old, &loaded).is_ok());
    }
    #[test]
    fn support_never_crosses_actual_service_identity_control_endpoint_epoch_or_image() {
        let service = ServiceIdentity {
            control: 10,
            identity: crate::Identity {
                process: 11,
                thread: 12,
                registered: 13,
            },
            endpoint: 14,
            epoch: 15,
            mapping_epoch: 1,
            image: [16; 32],
            descriptor: [17; 32],
        };
        let proof = FileSupport::observed(service, file_v2::SUPPORT).unwrap();
        assert_eq!(proof.for_service(service), Ok(file_v2::SUPPORT));
        for changed in [
            ServiceIdentity {
                control: 20,
                ..service
            },
            ServiceIdentity {
                endpoint: 20,
                ..service
            },
            ServiceIdentity {
                epoch: 20,
                ..service
            },
            ServiceIdentity {
                mapping_epoch: 2,
                ..service
            },
            ServiceIdentity {
                image: [18; 32],
                ..service
            },
            ServiceIdentity {
                descriptor: [18; 32],
                ..service
            },
            ServiceIdentity {
                identity: crate::Identity {
                    process: 21,
                    ..service.identity
                },
                ..service
            },
            ServiceIdentity {
                identity: crate::Identity {
                    thread: 21,
                    ..service.identity
                },
                ..service
            },
            ServiceIdentity {
                identity: crate::Identity {
                    registered: 21,
                    ..service.identity
                },
                ..service
            },
        ] {
            assert_eq!(proof.for_service(changed), Err(Error::Binding));
        }
        assert!(
            FileSupport::observed(
                ServiceIdentity {
                    control: 0,
                    ..service
                },
                file_v2::SUPPORT
            )
            .is_err()
        );
        assert!(
            FileSupport::observed(
                service,
                file_v2::Support {
                    major: 1,
                    ..file_v2::SUPPORT
                }
            )
            .is_err()
        );
    }
    #[test]
    fn loaded_contract_table_is_exact_and_semantic_support_is_not_an_authority_bit() {
        let no = LoadedContracts {
            semantic_tree: false,
            file: None,
        };
        let yes = LoadedContracts {
            semantic_tree: true,
            file: Some(file_v2::SUPPORT),
        };
        assert!(no.supported(semantic::INTERFACE, semantic::MAJOR).is_none());
        let support = yes.supported(semantic::INTERFACE, semantic::MAJOR).unwrap();
        assert_eq!(
            (support.minor, support.features),
            (semantic::MINOR, semantic::FEATURES)
        );
        assert!(
            yes.supported(semantic::INTERFACE, semantic::MAJOR + 1)
                .is_none()
        );
        assert!(yes.supported("ev.internal.namespace", 1).is_none());
        assert!(yes.supported(file_v2::INTERFACE, 1).is_none());
        assert!(
            yes.supported(file_v2::INTERFACE, file_v2::VERSION)
                .is_some()
        );
        assert!(no.supported(file_v2::INTERFACE, file_v2::VERSION).is_none());
        assert!(
            yes.supported(workspace::INTERFACE, workspace::VERSION)
                .is_some()
        );
    }
}
