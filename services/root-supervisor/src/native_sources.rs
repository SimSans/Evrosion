//! Scoped immutable package resolution. Lookup/compatibility is not release,
//! executable, activation, permission or KnownGood authority.
#![forbid(unsafe_code)]
use crate::native_plan::{PackageError, Packages, Slot};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DownloadedSlot {
    B,
    C,
}
impl DownloadedSlot {
    pub const fn index(self) -> usize {
        match self {
            Self::B => 0,
            Self::C => 1,
        }
    }
    pub const fn version(self) -> u64 {
        match self {
            Self::B => 2,
            Self::C => 3,
        }
    }
}
/// A downloaded package is never a compiled Slot::B identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Bank(Slot),
    Downloaded(DownloadedSlot),
}
impl Source {
    pub const fn bank(self) -> Option<Slot> {
        match self {
            Self::Bank(s) => Some(s),
            Self::Downloaded(_) => None,
        }
    }
}

/// Current scoped backing plus the original measured namespace context.
/// Implementations resolve complete immutable containers and recheck current
/// compatibility. No method authenticates a new repository decision.
pub trait Sources: ev_app_registry::Packages {
    fn banks(&self) -> &Packages<'_>;
    fn source(&self, digest: [u8; 32]) -> Option<Source>;
    fn source_digest(&self, source: Source) -> Option<[u8; 32]>;
    fn checked_source(&self, source: Source) -> Result<&ev_zion::Package<'_>, PackageError>;
    fn app(&self) -> ev_zion::AppId {
        self.banks().app()
    }
    fn is_session(&self) -> bool {
        self.banks().is_session()
    }
    fn note_format_manifest(&self) -> ev_store::GenerationManifest {
        self.banks().note_format_manifest()
    }
    fn grant_format_manifest(&self, owner: [u8; 16]) -> ev_store::GenerationManifest {
        self.banks().grant_format_manifest(owner)
    }
}
impl Sources for Packages<'_> {
    fn banks(&self) -> &Packages<'_> {
        self
    }
    fn source(&self, digest: [u8; 32]) -> Option<Source> {
        self.slot(digest).map(Source::Bank)
    }
    fn source_digest(&self, source: Source) -> Option<[u8; 32]> {
        source.bank().map(|s| self.digest(s))
    }
    fn checked_source(&self, source: Source) -> Result<&ev_zion::Package<'_>, PackageError> {
        self.checked(source.bank().ok_or(PackageError::Identity)?)
    }
}

#[cfg(feature = "native-network")]
mod downloaded {
    use super::*;
    use crate::{
        native_acquisition::{Content, Snapshot},
        native_image::{Images, Io},
    };
    use sha2::{Digest, Sha256};
    mod retained;
    pub use retained::Member;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Error {
        Profile,
        Slot,
        Snapshot,
        Package,
        Identity,
        Build,
        Source,
        Descriptor,
        Schema,
        Contracts,
        Collision,
        Owner,
    }
    /// Borrows the actual Images owner and its separate immutable parsed view.
    /// It borrows no bytes owned by itself; neither owner can be mutated/moved
    /// while this view is live. Snapshot membership is retained identity, not
    /// new remote trust/freshness or proof of lifecycle health.
    /// ```compile_fail,E0502
    /// use ev_root_supervisor::{native_sources::Downloaded, native_image::{Images,Io}, native_acquisition::{Snapshot,Content}};
    /// use ev_userspace_contract::root_v4::dynamic::Header;
    /// fn cannot_replace<T:Io>(images:&mut Images<T>, snapshot:&Snapshot, content:Content, header:Header) {
    ///     let view=Downloaded::from_images(images,0,snapshot,content).unwrap();
    ///     images.begin(header,1,100).unwrap();
    ///     core::hint::black_box(view);
    /// }
    /// ```
    pub struct Downloaded<'a, T: Io> {
        images: &'a Images<T>,
        snapshot: Option<&'a Snapshot>,
        kernel_slot: usize,
        slot: DownloadedSlot,
        content: Content,
        package: ev_zion::Package<'a>,
    }
    impl<'a, T: Io> Downloaded<'a, T> {
        pub fn from_images(
            images: &'a Images<T>,
            kernel_slot: usize,
            snapshot: &'a Snapshot,
            content: Content,
        ) -> Result<Self, Error> {
            if kernel_slot >= 2 {
                return Err(Error::Slot);
            }
            if ![
                snapshot.candidate(),
                snapshot.active(),
                snapshot.known_good(),
            ]
            .into_iter()
            .flatten()
            .any(|c| c == content)
            {
                return Err(Error::Snapshot);
            }
            let slot = match content.version {
                2 => DownloadedSlot::B,
                3 => DownloadedSlot::C,
                _ => return Err(Error::Slot),
            };
            let package = images.package(kernel_slot).map_err(image_error)?;
            validate(&package, content)?;
            Ok(Self {
                images,
                snapshot: Some(snapshot),
                kernel_slot,
                slot,
                content,
                package,
            })
        }
        pub const fn slot(&self) -> DownloadedSlot {
            self.slot
        }
        pub const fn kernel_slot(&self) -> usize {
            self.kernel_slot
        }
        pub const fn content(&self) -> Content {
            self.content
        }
        pub fn package(&self) -> &ev_zion::Package<'a> {
            &self.package
        }
    }
    fn image_error(error: crate::native_image::Error) -> Error {
        match error {
            crate::native_image::Error::Package => Error::Package,
            // Missing/uncertain immutable ownership or a header/content
            // association mismatch is never a clean optional syntax refusal.
            _ => Error::Owner,
        }
    }
    pub(super) fn validate(package: &ev_zion::Package<'_>, c: Content) -> Result<(), Error> {
        let a = package.app();
        if c.package != c.object.sha256()
            || c.object.length() != package.bytes().len() as u64
            || package.id().bytes() != c.package
            || a.claimed_app.bytes() != c.app
            || c.app != crate::native_acquisition::HELLO_APP
            || a.version.major != 0
            || !matches!(a.version.minor, 2 | 3)
            || u64::from(a.version.patch) + 1 != c.version
        {
            return Err(Error::Identity);
        }
        if a.build_id != c.build {
            return Err(Error::Build);
        }
        let prefix = match c.version {
            2 => b"Evrosion DEV B ".as_slice(),
            3 => b"Evrosion DEV C ".as_slice(),
            _ => return Err(Error::Slot),
        };
        let text = a.developer_source.as_bytes();
        if text.len() != prefix.len() + 64 || !text.starts_with(prefix) {
            return Err(Error::Source);
        }
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (i, b) in c.source.into_iter().enumerate() {
            if text[prefix.len() + 2 * i] != HEX[(b >> 4) as usize]
                || text[prefix.len() + 2 * i + 1] != HEX[(b & 15) as usize]
            {
                return Err(Error::Source);
            }
        }
        let mut h = Sha256::new();
        ev_userspace_contract::root_v4::dynamic::app_descriptor_transcript(
            &package.executable().digest,
            |b| h.update(b),
        );
        if <[u8; 32]>::from(h.finalize()) != c.descriptor {
            return Err(Error::Descriptor);
        }
        // Establish every known parsed identity binding before returning a
        // compatibility error that the cold loader may isolate as optional.
        if a.abi != ev_userspace_contract::ABI
            || a.data_schema.current != 1
            || a.data_schema.oldest_readable != 1
        {
            return Err(Error::Schema);
        }
        package
            .check_requirements(
                1,
                ev_userspace_contract::ABI,
                &crate::native_plan::Contracts,
            )
            .map_err(|_| Error::Contracts)?;
        if !crate::native_package_profile::downloaded(a) {
            return Err(Error::Contracts);
        }
        Ok(())
    }
    /// Separate owners supply banks, sealed bytes and retained authorization.
    /// Parsed cache reuse remains exact-backing matched by Registry itself.
    pub struct View<'a, 'bank, T: Io> {
        banks: &'a Packages<'bank>,
        downloaded: [Option<Downloaded<'a, T>>; 2],
    }
    impl<'a, 'bank, T: Io> View<'a, 'bank, T> {
        pub fn new(
            banks: &'a Packages<'bank>,
            images: &'a Images<T>,
            snapshot: &'a Snapshot,
            downloaded: [Option<Downloaded<'a, T>>; 2],
        ) -> Result<Self, Error> {
            Self::checked(banks, images, Some(snapshot), downloaded)
        }
        fn checked(
            banks: &'a Packages<'bank>,
            images: &'a Images<T>,
            snapshot: Option<&'a Snapshot>,
            downloaded: [Option<Downloaded<'a, T>>; 2],
        ) -> Result<Self, Error> {
            if !banks.is_network() {
                return Err(Error::Profile);
            }
            for (i, d) in downloaded.iter().enumerate() {
                if let Some(d) = d {
                    if d.slot.index() != i {
                        return Err(Error::Slot);
                    }
                    let same_snapshot = match (d.snapshot, snapshot) {
                        (Some(actual), Some(expected)) => core::ptr::eq(actual, expected),
                        (None, None) => true,
                        _ => false,
                    };
                    if !core::ptr::eq(d.images, images) || !same_snapshot {
                        return Err(Error::Owner);
                    }
                    if banks.slot(d.content.package).is_some()
                        || d.content.app != banks.app().bytes()
                        || downloaded[..i].iter().flatten().any(|p| {
                            p.content.package == d.content.package || p.kernel_slot == d.kernel_slot
                        })
                    {
                        return Err(Error::Collision);
                    }
                }
            }
            Ok(Self { banks, downloaded })
        }
        pub fn downloaded(&self, slot: DownloadedSlot) -> Option<&Downloaded<'a, T>> {
            self.downloaded[slot.index()].as_ref()
        }
    }
    impl<T: Io> ev_app_registry::Packages for View<'_, '_, T> {
        fn resolve(&self, digest: [u8; 32]) -> Option<&[u8]> {
            if let Some(s) = self.banks.slot(digest) {
                return Some(self.banks.bytes(s));
            }
            self.downloaded
                .iter()
                .flatten()
                .find(|d| d.content.package == digest)
                .map(|d| d.package.bytes())
        }
        fn parsed(&self, digest: [u8; 32]) -> Option<&ev_zion::Package<'_>> {
            self.source(digest)
                .and_then(|s| self.checked_source(s).ok())
        }
    }
    impl<T: Io> Sources for View<'_, '_, T> {
        fn banks(&self) -> &Packages<'_> {
            self.banks
        }
        fn source(&self, digest: [u8; 32]) -> Option<Source> {
            self.banks.slot(digest).map(Source::Bank).or_else(|| {
                self.downloaded
                    .iter()
                    .flatten()
                    .find(|d| d.content.package == digest)
                    .map(|d| Source::Downloaded(d.slot))
            })
        }
        fn source_digest(&self, source: Source) -> Option<[u8; 32]> {
            match source {
                Source::Bank(s) => Some(self.banks.digest(s)),
                Source::Downloaded(s) => self.downloaded(s).map(|d| d.content.package),
            }
        }
        fn checked_source(&self, source: Source) -> Result<&ev_zion::Package<'_>, PackageError> {
            match source {
                Source::Bank(s) => self.banks.checked(s),
                Source::Downloaded(s) => {
                    let d = self.downloaded(s).ok_or(PackageError::Identity)?;
                    d.package
                        .compatible(
                            1,
                            ev_userspace_contract::ABI,
                            &crate::native_plan::Contracts,
                        )
                        .map_err(PackageError::Package)?;
                    Ok(&d.package)
                }
            }
        }
    }
}
#[cfg(feature = "native-network")]
pub use downloaded::{Downloaded, Error, Member, View};
#[cfg(feature = "native-network")]
mod facade;
#[cfg(feature = "native-network")]
pub use facade::Resolver;
#[cfg(all(test, feature = "native-network"))]
pub(crate) mod tests;
