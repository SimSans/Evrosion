//! Local concrete dispatch over original banks or a checked sealed-byte view.
use super::*;
use crate::{
    native_acquisition::{Content, Snapshot},
    native_image::{Images, Io},
};

/// A local resolver, never a resident package owner or an authority snapshot.
/// Its parsed values borrow the separate immutable Images owner. State retains
/// only identities after each scoped call; moving Images is excluded meanwhile.
#[allow(clippy::large_enum_variant)] // One bounded local View; no allocator or duplicate owner.
pub enum Resolver<'a, 'bank, T: Io> {
    Banks(&'a Packages<'bank>),
    Sealed(View<'a, 'bank, T>),
}
impl<'a, 'bank, T: Io> Resolver<'a, 'bank, T> {
    /// Volatile identity for already registered local readers. This does not
    /// borrow or substitute an authenticated Store for any remote decision.
    pub fn from_members(
        banks: &'a Packages<'bank>,
        images: &'a Images<T>,
        members: [Option<Member>; 2],
    ) -> Result<Self, Error> {
        if members.iter().all(Option::is_none) {
            return Ok(Self::Banks(banks));
        }
        View::from_members(banks, images, members).map(Self::Sealed)
    }
    /// Binding positions are the distinct downloaded B/C identities. Kernel
    /// slots select only the actual same Images owner. Snapshot absence permits
    /// no downloaded binding; presence grants no automatic loading or fallback.
    pub fn new(
        banks: &'a Packages<'bank>,
        images: &'a Images<T>,
        snapshot: Option<&'a Snapshot>,
        bindings: [Option<(usize, Content)>; 2],
    ) -> Result<Self, Error> {
        let Some(snapshot) = snapshot else {
            if bindings.iter().any(Option::is_some) {
                return Err(Error::Snapshot);
            }
            return Ok(Self::Banks(banks));
        };
        let mut downloaded = [None, None];
        for (i, binding) in bindings.into_iter().enumerate() {
            if let Some((slot, content)) = binding {
                downloaded[i] = Some(Downloaded::from_images(images, slot, snapshot, content)?);
            }
        }
        View::new(banks, images, snapshot, downloaded).map(Self::Sealed)
    }
}
impl<T: Io> ev_app_registry::Packages for Resolver<'_, '_, T> {
    fn resolve(&self, digest: [u8; 32]) -> Option<&[u8]> {
        match self {
            Self::Banks(banks) => ev_app_registry::Packages::resolve(*banks, digest),
            Self::Sealed(view) => ev_app_registry::Packages::resolve(view, digest),
        }
    }
    fn parsed(&self, digest: [u8; 32]) -> Option<&ev_zion::Package<'_>> {
        match self {
            Self::Banks(banks) => ev_app_registry::Packages::parsed(*banks, digest),
            Self::Sealed(view) => ev_app_registry::Packages::parsed(view, digest),
        }
    }
}
impl<T: Io> Sources for Resolver<'_, '_, T> {
    fn banks(&self) -> &Packages<'_> {
        match self {
            Self::Banks(banks) => banks,
            Self::Sealed(view) => view.banks(),
        }
    }
    fn source(&self, digest: [u8; 32]) -> Option<Source> {
        match self {
            Self::Banks(banks) => banks.source(digest),
            Self::Sealed(view) => view.source(digest),
        }
    }
    fn source_digest(&self, source: Source) -> Option<[u8; 32]> {
        match self {
            Self::Banks(banks) => banks.source_digest(source),
            Self::Sealed(view) => view.source_digest(source),
        }
    }
    fn checked_source(&self, source: Source) -> Result<&ev_zion::Package<'_>, PackageError> {
        match self {
            Self::Banks(banks) => banks.checked_source(source),
            Self::Sealed(view) => view.checked_source(source),
        }
    }
}

#[cfg(test)]
#[path = "facade_tests.rs"]
mod tests;
