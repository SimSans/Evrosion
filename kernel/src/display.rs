//! Device-only Display authority. Scanout backing is never allocator RAM.
//! Physical discovery/publication and quiescence remain the hardware boundary.
use crate::capability::{Authority, Error as CapError, Handle, Kind, Rights, SpaceId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Information {
    pub fingerprint: [u8; 32],
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub byte_length: u32,
    pub page_count: u16,
    pub byte_offset: u16,
    pub format: u8,
}
impl Information {
    fn valid(self) -> bool {
        self.fingerprint != [0; 32]
            && self.width > 0
            && self.height > 0
            && self.stride >= self.width
            && matches!(self.format, 1 | 2)
            && (1..=1024).contains(&self.page_count)
            && self.byte_offset < 4096
            && self
                .stride
                .checked_mul(self.height)
                .and_then(|n| n.checked_mul(4))
                == Some(self.byte_length)
            && u64::from(self.byte_length) + u64::from(self.byte_offset)
                <= u64::from(self.page_count) * 4096
            && u64::from(self.byte_length) + u64::from(self.byte_offset)
                > (u64::from(self.page_count) - 1) * 4096
    }
}
/// Owned non-RAM backing discovered from the actual boot GOP mapping.
///
/// # Safety
/// The implementation must retain the unique trusted framebuffer/device source,
/// with every KVA page translated through its actual retained page tables and
/// original PAT/cache attributes. No page may overlap allocator Usable RAM.
/// information() is immutable, truthful and bounded; backing/PAT/MTRRs/source
/// tables remain retained and stable until every mapping is physically detached
/// and all CPU/reference access is quiescent. No PhysicalFrame may be invented
/// for the scanout pages, and Drop must never release/recycle device memory.
#[allow(unsafe_code)] // Contract declaration only, like LoadedExecutable.
pub unsafe trait DisplayBacking {
    fn information(&self) -> Information;
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Authority(CapError),
    InvalidBacking,
    WrongObject,
    Busy,
    Stale,
    Overflow,
}
impl From<CapError> for Error {
    fn from(value: CapError) -> Self {
        Self::Authority(value)
    }
}
#[derive(Clone, Copy)]
struct Mapping {
    token: u64,
    owner: SpaceId,
    capability: Handle,
}
/// Move-only logical claim. The hardware owner consumes it before installing
/// PTEs, so only an actual detached/uninstalled owner can return it afterward.
pub struct DisplayLease {
    object: usize,
    token: u64,
    owner: SpaceId,
    capability: Handle,
}
impl DisplayLease {
    pub fn owner(&self) -> SpaceId {
        self.owner
    }
}
pub struct DisplayObject<S: DisplayBacking> {
    object: usize,
    backing: S,
    sequence: u64,
    mapping: Option<Mapping>,
}
impl<S: DisplayBacking> DisplayObject<S> {
    pub fn new(
        authority: &mut Authority,
        owner: SpaceId,
        backing: S,
    ) -> Result<(Self, Handle), (Error, S)> {
        if !backing.information().valid() {
            return Err((Error::InvalidBacking, backing));
        }
        let rights = Rights::READ
            | Rights::WRITE
            | Rights::MAP
            | Rights::DERIVE
            | Rights::TRANSFER
            | Rights::REVOKE
            | Rights::CONTROL;
        let cap = match authority.create_root(owner, Kind::Display, rights) {
            Ok(cap) => cap,
            Err(error) => return Err((error.into(), backing)),
        };
        let object = authority
            .authorize(owner, cap, Kind::Display, Rights::CONTROL)
            .expect("new display authority")
            .identity();
        Ok((
            Self {
                object,
                backing,
                sequence: 0,
                mapping: None,
            },
            cap,
        ))
    }
    fn authorize(
        &self,
        authority: &Authority,
        owner: SpaceId,
        capability: Handle,
    ) -> Result<(), Error> {
        if authority
            .authorize(
                owner,
                capability,
                Kind::Display,
                Rights::READ | Rights::WRITE | Rights::MAP,
            )?
            .identity()
            != self.object
        {
            return Err(Error::WrongObject);
        }
        Ok(())
    }
    pub fn map(
        &mut self,
        authority: &Authority,
        owner: SpaceId,
        capability: Handle,
    ) -> Result<DisplayLease, Error> {
        self.authorize(authority, owner, capability)?;
        if self.mapping.is_some() {
            return Err(Error::Busy);
        }
        let token = self.sequence.checked_add(1).ok_or(Error::Overflow)?;
        self.mapping = Some(Mapping {
            token,
            owner,
            capability,
        });
        self.sequence = token;
        Ok(DisplayLease {
            object: self.object,
            token,
            owner,
            capability,
        })
    }
    fn exact(&self, lease: &DisplayLease) -> Result<(), Error> {
        if lease.object != self.object {
            return Err(Error::WrongObject);
        }
        if self.mapping.is_none_or(|m| {
            m.token != lease.token || m.owner != lease.owner || m.capability != lease.capability
        }) {
            return Err(Error::Stale);
        }
        Ok(())
    }
    pub fn backing_for<'s>(
        &'s self,
        authority: &Authority,
        lease: &DisplayLease,
    ) -> Result<&'s S, Error> {
        self.exact(lease)?;
        self.authorize(authority, lease.owner, lease.capability)?;
        Ok(&self.backing)
    }
    /// Scalar DisplayInfo must additionally use the actual registered mapping
    /// owner; possession of an unrelated/foreign device capability is not enough.
    pub fn mapped_information(
        &self,
        authority: &Authority,
        owner: SpaceId,
        capability: Handle,
    ) -> Result<Information, Error> {
        self.authorize(authority, owner, capability)?;
        if self
            .mapping
            .is_none_or(|m| m.owner != owner || m.capability != capability)
        {
            return Err(Error::Stale);
        }
        Ok(self.backing.information())
    }
    /// Return only a never-installed or physically detached claim. Revalidation
    /// of a revoked public cap is deliberately unnecessary for exact cleanup.
    pub fn unmap(&mut self, lease: DisplayLease) -> Result<(), (Error, DisplayLease)> {
        if let Err(error) = self.exact(&lease) {
            return Err((error, lease));
        }
        self.mapping = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Model;
    #[test]
    fn additive_display_tag_has_identical_kernel_and_startup_rights_validation() {
        let context = ev_userspace_contract::Context {
            epoch: 1,
            incarnation: 1,
            process: 1,
            limits: [1; 4],
            manifest: [1; 32],
            authority: [2; 32],
        };
        for bits in 0..=u16::MAX {
            let expected = bits != 0
                && Rights::from_bits(bits).is_some_and(|rights| Kind::Display.permits(rights));
            let grant = ev_userspace_contract::Grant {
                selector: 1,
                handle: 1,
                kind: 8,
                rights: bits,
            };
            assert_eq!(
                ev_userspace_contract::encode(context, &[grant]).is_ok(),
                expected,
                "{bits}"
            );
        }
    }
    // SAFETY: host-only source model, no physical pages or hardware proof.
    #[allow(unsafe_code)]
    unsafe impl DisplayBacking for Model {
        fn information(&self) -> Information {
            Information {
                fingerprint: [1; 32],
                width: 1280,
                height: 800,
                stride: 1280,
                byte_length: 4_096_000,
                page_count: 1000,
                byte_offset: 0,
                format: 2,
            }
        }
    }
    #[test]
    fn display_is_distinct_from_memory_and_writable_mapping_requires_read_too() {
        let mut a = Authority::new();
        let owner = a.create_space().unwrap();
        let (mut object, cap) =
            DisplayObject::new(&mut a, owner, Model).unwrap_or_else(|_| panic!("display model"));
        assert_eq!(
            a.authorize(owner, cap, Kind::Memory, Rights::READ).err(),
            Some(CapError::WrongKind)
        );
        let writeonly = a
            .derive(owner, cap, owner, Rights::WRITE | Rights::MAP)
            .unwrap();
        assert!(matches!(
            object.map(&a, owner, writeonly),
            Err(Error::Authority(CapError::Denied))
        ));
        let memory = a
            .create_root(
                owner,
                Kind::Memory,
                Rights::READ | Rights::WRITE | Rights::MAP,
            )
            .unwrap();
        assert!(matches!(
            object.map(&a, owner, memory),
            Err(Error::Authority(CapError::WrongKind))
        ));
        let lease = object.map(&a, owner, cap).unwrap();
        assert!(object.backing_for(&a, &lease).is_ok());
        assert!(matches!(object.map(&a, owner, cap), Err(Error::Busy)));
    }
    #[test]
    fn revoked_exact_lease_can_return_but_never_validate_or_alias_a_newer_mapping() {
        let mut a = Authority::new();
        let owner = a.create_space().unwrap();
        let (mut object, root) =
            DisplayObject::new(&mut a, owner, Model).unwrap_or_else(|_| panic!("display model"));
        let branch = a
            .derive(
                owner,
                root,
                owner,
                Rights::READ | Rights::WRITE | Rights::MAP | Rights::DERIVE | Rights::REVOKE,
            )
            .unwrap();
        let child = a
            .derive(
                owner,
                branch,
                owner,
                Rights::READ | Rights::WRITE | Rights::MAP,
            )
            .unwrap();
        let lease = object.map(&a, owner, child).unwrap();
        let old = (lease.object, lease.token, lease.owner, lease.capability);
        a.revoke(owner, branch).unwrap();
        assert!(object.backing_for(&a, &lease).is_err());
        object
            .unmap(lease)
            .unwrap_or_else(|_| panic!("exact revoked cleanup"));
        let current = object.map(&a, owner, root).unwrap();
        let forged = DisplayLease {
            object: old.0,
            token: old.1,
            owner: old.2,
            capability: old.3,
        };
        assert!(matches!(object.unmap(forged), Err((Error::Stale, _))));
        assert!(object.backing_for(&a, &current).is_ok());
        let foreign = a.create_space().unwrap();
        let alias = a
            .derive(
                owner,
                root,
                foreign,
                Rights::READ | Rights::WRITE | Rights::MAP,
            )
            .unwrap();
        assert_eq!(
            object.mapped_information(&a, foreign, alias),
            Err(Error::Stale)
        );
    }
}
