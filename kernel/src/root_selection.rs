//! A typed Root format selection inside the SAME incarnation/Custodian owner.
//! No extra activation/reset path is introduced by choosing the larger record.
use crate::{
    bootstrap_binding::{self, CatalogEntry},
    bootstrap_manifest::Manifest,
    capability::{Authority, Handle, Kind, SpaceId},
    executable::{self, Image},
    root_binding_v2,
    root_manifest_v2::{CurrentRoot, NativeRoot},
};
#[derive(Clone, Copy)]
pub(crate) enum Selection<'a> {
    V1(&'a Manifest<'a>),
    V2(&'a CurrentRoot<'a>),
    Native(&'a NativeRoot<'a>),
    V4(&'a crate::root_manifest_v4::CurrentRoot<'a>),
    #[cfg(feature = "workspace-authority")]
    V5(&'a crate::root_manifest_v5::CurrentRoot<'a>),
}
pub(crate) struct Grant {
    pub selector: u64,
    pub kind: crate::capability::Kind,
    pub rights: crate::capability::Rights,
}
impl<'a> Selection<'a> {
    pub(crate) fn is_root_v2(self) -> bool {
        matches!(self, Self::V2(_))
    }
    pub(crate) fn is_native_root(self) -> bool {
        matches!(self, Self::Native(_))
    }
    pub(crate) fn is_root_v4(self) -> bool {
        matches!(self, Self::V4(_))
    }
    pub(crate) fn has_root_record(self) -> bool {
        #[cfg(feature = "workspace-authority")]
        if self.is_root_v5() {
            return true;
        }
        matches!(self, Self::V2(_) | Self::Native(_) | Self::V4(_))
    }
    #[cfg(feature = "workspace-authority")]
    pub(crate) fn is_root_v5(self) -> bool {
        matches!(self, Self::V5(_))
    }
    pub(crate) fn same(self, other: Self) -> bool {
        match (self, other) {
            (Self::V1(a), Self::V1(b)) => core::ptr::eq(a, b),
            (Self::V2(a), Self::V2(b)) => core::ptr::eq(a, b),
            (Self::Native(a), Self::Native(b)) => core::ptr::eq(a, b),
            (Self::V4(a), Self::V4(b)) => core::ptr::eq(a, b),
            #[cfg(feature = "workspace-authority")]
            (Self::V5(a), Self::V5(b)) => core::ptr::eq(a, b),
            _ => false,
        }
    }
    pub(crate) fn digest(self) -> [u8; 32] {
        match self {
            Self::V1(m) => m.digest(),
            Self::V2(m) => m.manifest().digest(),
            Self::Native(m) => m.manifest().digest(),
            Self::V4(m) => m.manifest().digest(),
            #[cfg(feature = "workspace-authority")]
            Self::V5(m) => m.manifest().digest(),
        }
    }
    pub(crate) fn abi_fingerprint(self) -> [u8; 32] {
        match self {
            Self::V1(m) => m.abi_fingerprint(),
            Self::V2(_) => ev_userspace_contract::root_v2::ABI,
            Self::Native(_) => ev_userspace_contract::root_v2::native::ABI,
            Self::V4(_) => ev_userspace_contract::root_v4::ABI,
            #[cfg(feature = "workspace-authority")]
            Self::V5(_) => ev_userspace_contract::root_v5::ABI,
        }
    }
    pub(crate) fn limits(self) -> crate::scheduler::Limits {
        match self {
            Self::V1(m) => m.limits(),
            Self::V2(m) => m.manifest().limits(),
            Self::Native(m) => m.manifest().limits(),
            Self::V4(m) => m.manifest().limits(),
            #[cfg(feature = "workspace-authority")]
            Self::V5(m) => m.manifest().limits(),
        }
    }
    pub(crate) fn restart_policy(self) -> crate::restart::Policy {
        match self {
            Self::V1(m) => m.restart_policy(),
            Self::V2(m) => m.manifest().restart_policy(),
            Self::Native(m) => m.manifest().restart_policy(),
            Self::V4(m) => m.manifest().restart_policy(),
            #[cfg(feature = "workspace-authority")]
            Self::V5(m) => m.manifest().restart_policy(),
        }
    }
    pub(crate) fn executable_plan(self) -> Result<Image<'a>, executable::Error> {
        match self {
            Self::V1(m) => Image::from_manifest(m),
            Self::V2(m) => Image::from_root_manifest_v2(m),
            Self::Native(m) => Image::from_native_root(m),
            Self::V4(m) => Image::from_root_v4(m),
            #[cfg(feature = "workspace-authority")]
            Self::V5(m) => Image::from_root_v5(m),
        }
    }
    pub(crate) fn grants(self) -> impl Iterator<Item = Grant> + 'a {
        let mut i = 0;
        core::iter::from_fn(move || {
            let value = match self {
                Self::V1(m) => m.grants().nth(i).map(|g| Grant {
                    selector: g.selector.value(),
                    kind: g.kind,
                    rights: g.rights,
                }),
                Self::V2(m) => m.manifest().grants().nth(i).map(|g| Grant {
                    selector: g.selector,
                    kind: g.kind,
                    rights: g.rights,
                }),
                Self::Native(m) => m.manifest().grants().nth(i).map(|g| Grant {
                    selector: g.selector,
                    kind: g.kind,
                    rights: g.rights,
                }),
                Self::V4(m) => m.manifest().grants().nth(i).map(|g| Grant {
                    selector: g.selector,
                    kind: g.kind,
                    rights: g.rights,
                }),
                #[cfg(feature = "workspace-authority")]
                Self::V5(m) => m.manifest().grants().nth(i).map(|g| Grant {
                    selector: g.selector,
                    kind: g.kind,
                    rights: g.rights,
                }),
            };
            if value.is_some() {
                i += 1;
            }
            value
        })
    }
    fn sources<const N: usize>(
        catalog: &[CatalogEntry],
    ) -> Result<([root_binding_v2::Source; N], usize), bootstrap_binding::Error> {
        if catalog.len() > N {
            return Err(bootstrap_binding::Error::Catalog);
        }
        let mut sources = [root_binding_v2::Source {
            selector: 0,
            handle: Handle(0),
            kind: Kind::Memory,
        }; N];
        for (i, e) in catalog.iter().enumerate() {
            sources[i] = root_binding_v2::Source {
                selector: e.selector,
                handle: e.root,
                kind: e.kind,
            };
        }
        Ok((sources, catalog.len()))
    }
    pub(crate) fn install(
        self,
        a: &mut Authority,
        custody: SpaceId,
        branches: SpaceId,
        destination: SpaceId,
        catalog: &[CatalogEntry],
    ) -> Result<bootstrap_binding::ScopedInstalled, bootstrap_binding::Error> {
        match self {
            Self::V1(m) => {
                bootstrap_binding::install_scoped(a, custody, branches, destination, catalog, m)
            }
            Self::V2(m) => {
                let (s, n) =
                    Self::sources::<{ ev_userspace_contract::root_v2::MAX_GRANTS }>(catalog)?;
                let installed =
                    root_binding_v2::install(a, custody, branches, destination, &s[..n], m)
                        .map_err(bootstrap_binding::Error::RootV2)?;
                Ok(bootstrap_binding::ScopedInstalled {
                    digest: installed.digest,
                    grants: installed.grants,
                })
            }
            Self::Native(m) => {
                let (s, n) =
                    Self::sources::<{ ev_userspace_contract::root_v2::MAX_GRANTS }>(catalog)?;
                let installed =
                    root_binding_v2::install_native(a, custody, branches, destination, &s[..n], m)
                        .map_err(bootstrap_binding::Error::RootV2)?;
                Ok(bootstrap_binding::ScopedInstalled {
                    digest: installed.digest,
                    grants: installed.grants,
                })
            }
            Self::V4(m) => {
                let (s, n) =
                    Self::sources::<{ ev_userspace_contract::root_v4::MAX_GRANTS }>(catalog)?;
                let installed =
                    root_binding_v2::install_v4(a, custody, branches, destination, &s[..n], m)
                        .map_err(bootstrap_binding::Error::RootV2)?;
                Ok(bootstrap_binding::ScopedInstalled {
                    digest: installed.digest,
                    grants: installed.grants,
                })
            }
            #[cfg(feature = "workspace-authority")]
            Self::V5(m) => {
                let (s, n) =
                    Self::sources::<{ ev_userspace_contract::root_v5::MAX_GRANTS }>(catalog)?;
                let installed =
                    root_binding_v2::install_v5(a, custody, branches, destination, &s[..n], m)
                        .map_err(bootstrap_binding::Error::RootV2)?;
                Ok(bootstrap_binding::ScopedInstalled {
                    digest: installed.digest,
                    grants: installed.grants,
                })
            }
        }
    }
    pub(crate) fn revalidate(
        self,
        a: &Authority,
        custody: SpaceId,
        catalog: &[CatalogEntry],
        view: bootstrap_binding::InstalledView<'_>,
    ) -> Result<(), bootstrap_binding::Error> {
        match self {
            Self::V1(m) => bootstrap_binding::revalidate(a, custody, catalog, m, view),
            Self::V2(m) => {
                let (s, n) =
                    Self::sources::<{ ev_userspace_contract::root_v2::MAX_GRANTS }>(catalog)?;
                root_binding_v2::revalidate(a, custody, &s[..n], m, view)
                    .map_err(bootstrap_binding::Error::RootV2)
            }
            Self::Native(m) => {
                let (s, n) =
                    Self::sources::<{ ev_userspace_contract::root_v2::MAX_GRANTS }>(catalog)?;
                root_binding_v2::revalidate_native(a, custody, &s[..n], m, view)
                    .map_err(bootstrap_binding::Error::RootV2)
            }
            Self::V4(m) => {
                let (s, n) =
                    Self::sources::<{ ev_userspace_contract::root_v4::MAX_GRANTS }>(catalog)?;
                root_binding_v2::revalidate_v4(a, custody, &s[..n], m, view)
                    .map_err(bootstrap_binding::Error::RootV2)
            }
            #[cfg(feature = "workspace-authority")]
            Self::V5(m) => {
                let (s, n) =
                    Self::sources::<{ ev_userspace_contract::root_v5::MAX_GRANTS }>(catalog)?;
                root_binding_v2::revalidate_v5(a, custody, &s[..n], m, view)
                    .map_err(bootstrap_binding::Error::RootV2)
            }
        }
    }
}
