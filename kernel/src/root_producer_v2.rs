//! Pure description encoder shared by producer tests. This creates bytes only.
//! The boot factory must independently realize these full source identities;
//! root_binding_v2 compares them against real retained Authority custody.
use crate::{
    capability::{Kind, Rights},
    root_manifest_v2::{self, kind_tag},
};
use ev_userspace_contract::root_v2;
use sha2::{Digest, Sha256};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub object: u64,
    pub lineage: u64,
}
#[derive(Clone, Copy)]
pub struct SourceIdentity {
    pub selector: u64,
    pub kind: Kind,
    pub rights: Rights,
    pub object: u64,
    pub lineage: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Count,
    Order,
    Kind,
    Rights,
    Alias,
    Limits,
    Restart,
    Image,
    Profile,
    Catalogue,
}
pub struct Description {
    entries: [Option<SourceIdentity>; root_v2::MAX_GRANTS],
    count: usize,
    limits: [u64; 4],
    attempts: u8,
    window: u64,
    catalogue: Option<[u8; 32]>,
}
impl Description {
    /// Trusted producer INPUT, not proof that the source exists. In particular
    /// no first_object+i arithmetic substitutes for a generation-tagged identity.
    pub fn new(
        entries: &[Option<SourceIdentity>],
        limits: [u64; 4],
        attempts: u8,
        window: u64,
    ) -> Result<Self, Error> {
        if !(1..=root_v2::MAX_GRANTS).contains(&entries.len()) {
            return Err(Error::Count);
        }
        if limits.iter().any(|x| matches!(*x, 0 | u64::MAX))
            || limits[2] > crate::scheduler::MAX_PROCESSES as u64
            || limits[3] > crate::scheduler::MAX_THREADS as u64
        {
            return Err(Error::Limits);
        }
        crate::restart::Policy::new(attempts, window).map_err(|_| Error::Restart)?;
        let mut stored = [None; root_v2::MAX_GRANTS];
        let mut previous = 0;
        for (i, entry) in entries.iter().enumerate() {
            let e = entry.ok_or(Error::Count)?;
            if e.selector <= previous || e.selector == 1000 {
                return Err(Error::Order);
            }
            previous = e.selector;
            if e.rights.bits() == 0 || !e.kind.permits(e.rights) {
                return Err(Error::Rights);
            }
            if entries[..i].iter().flatten().any(|p| p.object == e.object) {
                return Err(Error::Alias);
            }
            stored[i] = Some(e);
        }
        Ok(Self {
            entries: stored,
            count: entries.len(),
            limits,
            attempts,
            window,
            catalogue: None,
        })
    }
    pub fn full_graph(
        limits: [u64; 4],
        attempts: u8,
        window: u64,
        identities: [Identity; root_v2::CURRENT_GRANTS],
    ) -> Result<Self, Error> {
        let mut entries = [None; root_v2::CURRENT_GRANTS];
        for (i, s) in root_v2::ROLES.into_iter().enumerate() {
            let kind = match s.kind {
                1 => Kind::Memory,
                2 => Kind::Endpoint,
                5 => Kind::Job,
                7 => Kind::IoPorts,
                8 => Kind::Display,
                _ => return Err(Error::Kind),
            };
            entries[i] = Some(SourceIdentity {
                selector: s.role.selector(),
                kind,
                rights: Rights::from_bits(s.rights).ok_or(Error::Rights)?,
                object: identities[i].object,
                lineage: identities[i].lineage,
            });
        }
        Self::new(&entries, limits, attempts, window)
    }
    /// Native profile has the same generation-safe source identity input, with
    /// exactly the independently named21 roles. This encodes no authority.
    pub fn full_native_graph(
        limits: [u64; 4],
        attempts: u8,
        window: u64,
        identities: [Identity; root_v2::native::CURRENT_GRANTS],
    ) -> Result<Self, Error> {
        let mut entries = [None; root_v2::native::CURRENT_GRANTS];
        for (i, role) in root_v2::native::ROLES.into_iter().enumerate() {
            let kind = match role.kind {
                1 => Kind::Memory,
                2 => Kind::Endpoint,
                5 => Kind::Job,
                7 => Kind::IoPorts,
                8 => Kind::Display,
                _ => return Err(Error::Kind),
            };
            entries[i] = Some(SourceIdentity {
                selector: role.selector,
                kind,
                rights: Rights::from_bits(role.rights).ok_or(Error::Rights)?,
                object: identities[i].object,
                lineage: identities[i].lineage,
            });
        }
        Self::new(&entries, limits, attempts, window)
    }
    /// Explicit post-build catalogue measurement; creates description bytes
    /// only. The real boot factory must verify exact contents before binding.
    pub fn bind_catalogue(mut self, measurement: [u8; 32]) -> Self {
        self.catalogue = Some(measurement);
        self
    }
    pub fn authority_digest(&self) -> [u8; 32] {
        self.authority_digest_profile(root_v2::ABI, root_v2::PROFILE)
    }
    fn authority_digest_profile(&self, abi: [u8; 32], profile: u16) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"evrosion.bootstrap.authority.root.v2\0");
        hash.update(abi);
        hash.update((root_v2::SIZE as u64).to_le_bytes());
        hash.update(profile.to_le_bytes());
        hash.update((self.count as u64).to_le_bytes());
        for e in self.entries.iter().flatten() {
            hash.update(e.selector.to_le_bytes());
            hash.update([kind_tag(e.kind)]);
            hash.update(e.object.to_le_bytes());
            hash.update(e.lineage.to_le_bytes());
            hash.update(e.rights.bits().to_le_bytes());
            hash.update([0]);
            hash.update(0u64.to_le_bytes());
            hash.update(0u64.to_le_bytes());
        }
        hash.finalize().into()
    }
}
pub struct Encoded {
    bytes: [u8; root_manifest_v2::MAX_BYTES],
    len: usize,
}
impl Encoded {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.bytes()).into()
    }
}
fn put(bytes: &mut [u8], i: usize, n: u64) {
    bytes[i..i + 8].copy_from_slice(&n.to_le_bytes());
}
/// Low-level measured description encoder. Production calls encode_current.
pub fn encode(image: &[u8], description: &Description) -> Result<Encoded, Error> {
    if image.is_empty() || image.len() > crate::bootstrap_manifest::MAX_IMAGE_BYTES {
        return Err(Error::Image);
    }
    let d = description;
    let catalogue = d.catalogue.ok_or(Error::Catalogue)?;
    let mut bytes = [0; root_manifest_v2::MAX_BYTES];
    bytes[..8].copy_from_slice(b"EVBM0002");
    put(&mut bytes, 8, root_v2::EXECUTABLE_SELECTOR);
    bytes[16..48].copy_from_slice(&Sha256::digest(image));
    bytes[48..80].copy_from_slice(&root_v2::ABI);
    for (i, n) in d.limits.into_iter().enumerate() {
        put(&mut bytes, 80 + i * 8, n);
    }
    bytes[112] = d.attempts;
    put(&mut bytes, 120, d.window);
    bytes[128..160].copy_from_slice(&d.authority_digest());
    bytes[160] = d.count as u8;
    bytes[168..170].copy_from_slice(&root_v2::VERSION.to_le_bytes());
    bytes[170..172].copy_from_slice(&(root_v2::SIZE as u16).to_le_bytes());
    bytes[172..174].copy_from_slice(&root_v2::PROFILE.to_le_bytes());
    bytes[176..208].copy_from_slice(&catalogue);
    for (i, e) in d.entries.iter().flatten().enumerate() {
        let b = &mut bytes[root_manifest_v2::HEADER + i * root_manifest_v2::GRANT_BYTES..];
        put(b, 0, e.selector);
        b[8] = kind_tag(e.kind);
        b[10..12].copy_from_slice(&e.rights.bits().to_le_bytes());
    }
    Ok(Encoded {
        bytes,
        len: root_manifest_v2::HEADER + d.count * root_manifest_v2::GRANT_BYTES,
    })
}
pub fn encode_current(image: &[u8], description: &Description) -> Result<Encoded, Error> {
    let encoded = encode(image, description)?;
    let canonical = root_v2::manifest_profile(root_v2::ManifestInputs {
        root_image: Sha256::digest(image).into(),
        catalogue: description.catalogue.ok_or(Error::Catalogue)?,
        authority: description.authority_digest(),
        limits: description.limits,
        restart_attempts: description.attempts,
        restart_window: description.window,
    })
    .map_err(|_| Error::Profile)?;
    if encoded.bytes() != canonical {
        return Err(Error::Profile);
    }
    root_manifest_v2::verify(encoded.bytes(), encoded.digest(), image)
        .map_err(|_| Error::Profile)?
        .current_profile()
        .map_err(|_| Error::Profile)?;
    Ok(encoded)
}
/// Explicit Native serializer. The original generic/current encoders retain
/// their exact bytes; profile3 cannot be selected by appending arbitrary roles.
pub fn encode_native(image: &[u8], description: &Description) -> Result<Encoded, Error> {
    use root_v2::native;
    if description.count != native::CURRENT_GRANTS {
        return Err(Error::Profile);
    }
    for (entry, role) in description.entries.iter().flatten().zip(native::ROLES) {
        if (entry.selector, kind_tag(entry.kind), entry.rights.bits())
            != (role.selector, role.kind, role.rights)
        {
            return Err(Error::Profile);
        }
    }
    let canonical = native::manifest_profile(root_v2::ManifestInputs {
        root_image: Sha256::digest(image).into(),
        catalogue: description.catalogue.ok_or(Error::Catalogue)?,
        authority: description.authority_digest_profile(native::ABI, native::PROFILE),
        limits: description.limits,
        restart_attempts: description.attempts,
        restart_window: description.window,
    })
    .map_err(|_| Error::Profile)?;
    let mut bytes = [0; root_manifest_v2::MAX_BYTES];
    bytes[..canonical.len()].copy_from_slice(&canonical);
    let encoded = Encoded {
        bytes,
        len: canonical.len(),
    };
    root_manifest_v2::verify(encoded.bytes(), encoded.digest(), image)
        .map_err(|_| Error::Profile)?
        .native_profile()
        .map_err(|_| Error::Profile)?;
    Ok(encoded)
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    #[test]
    fn native_producer_binds_its_own_abi_profile_and_all22_source_generations() {
        let build = |last: u64| {
            Description::full_native_graph(
                [65536, 512, 8, 8],
                3,
                60000,
                core::array::from_fn(|i| Identity {
                    object: i as u64,
                    lineage: if i == 21 { last } else { i as u64 },
                }),
            )
            .unwrap()
            .bind_catalogue([7; 32])
        };
        let d = build(20);
        let native = encode_native(b"actual-root", &d).unwrap();
        assert_eq!(
            native.bytes().len(),
            root_v2::native::MANIFEST_CURRENT_BYTES
        );
        let parsed =
            root_manifest_v2::verify(native.bytes(), native.digest(), b"actual-root").unwrap();
        assert_ne!(parsed.expected_authority_digest(), d.authority_digest());
        assert!(parsed.native_profile().is_ok());
        assert!(encode_current(b"actual-root", &d).is_err());
        assert_ne!(
            native.digest(),
            encode_native(b"actual-root", &build(21)).unwrap().digest()
        );
        let old = Description::full_graph(
            [65536, 512, 8, 8],
            3,
            60000,
            core::array::from_fn(|i| Identity {
                object: i as u64,
                lineage: i as u64,
            }),
        )
        .unwrap()
        .bind_catalogue([7; 32]);
        assert!(encode_native(b"actual-root", &old).is_err());
    }
    fn fixture() -> Encoded {
        let d = Description::full_graph(
            [4096, 256, 7, 7],
            3,
            60,
            core::array::from_fn(|i| Identity {
                object: 0x100 + i as u64,
                lineage: 0x80 + i as u64,
            }),
        )
        .unwrap()
        .bind_catalogue([7; 32]);
        encode_current(b"image", &d).unwrap()
    }
    #[test]
    fn root_v2_producer_abi_and_complete_description_match_kernel_parser() {
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(root_v2::ABI_DESCRIPTION)),
            root_v2::ABI
        );
        let e = fixture();
        let m = root_manifest_v2::verify(e.bytes(), e.digest(), b"image")
            .unwrap()
            .current_profile()
            .unwrap();
        assert_eq!(m.manifest().grants().count(), 18);
        assert_eq!(e.bytes().len(), 784);
        assert!(
            crate::bootstrap_manifest::verify(e.bytes(), e.digest(), b"image", root_v2::ABI)
                .is_err()
        );
    }
    #[test]
    fn root_v2_every_manifest_bit_is_bound_to_trusted_measurement() {
        let e = fixture();
        for bit in 0..e.bytes().len() * 8 {
            let mut b = e.bytes;
            b[bit / 8] ^= 1 << (bit % 8);
            assert!(root_manifest_v2::verify(&b[..e.len], e.digest(), b"image").is_err());
        }
    }
    #[test]
    fn root_v2_manifest_rejects_remeasured_version_abi_length_and_ranges() {
        let e = fixture();
        for offset in [
            0,
            48,
            113,
            161,
            168,
            170,
            172,
            174,
            root_manifest_v2::HEADER + 9,
            root_manifest_v2::HEADER + 16,
        ] {
            let mut b = e.bytes;
            b[offset] ^= 1;
            let bytes = &b[..e.len];
            assert!(
                root_manifest_v2::verify(bytes, Sha256::digest(bytes).into(), b"image").is_err(),
                "{offset}"
            );
        }
        for n in 0..e.len {
            let bytes = &e.bytes()[..n];
            assert!(
                root_manifest_v2::verify(bytes, Sha256::digest(bytes).into(), b"image").is_err()
            );
        }
        let mut b = std::vec::Vec::from(e.bytes());
        b.push(0);
        assert!(root_manifest_v2::verify(&b, Sha256::digest(&b).into(), b"image").is_err());
        for count in [0, 25, 255] {
            let mut b = e.bytes;
            b[160] = count;
            let bytes = &b[..e.len];
            assert!(
                root_manifest_v2::verify(bytes, Sha256::digest(bytes).into(), b"image").is_err()
            );
        }
    }
    #[test]
    fn root_v2_catalogue_is_explicit_and_bound_into_manifest_measurement() {
        let description = Description::full_graph(
            [4096, 512, 8, 8],
            3,
            60,
            core::array::from_fn(|i| Identity {
                object: i as u64,
                lineage: i as u64,
            }),
        )
        .unwrap();
        assert!(matches!(
            encode_current(b"image", &description),
            Err(Error::Catalogue)
        ));
        let first = encode_current(b"image", &description.bind_catalogue([7; 32])).unwrap();
        let m = root_manifest_v2::verify(first.bytes(), first.digest(), b"image").unwrap();
        assert_eq!(m.expected_catalogue_digest(), [7; 32]);
        let description = Description::full_graph(
            [4096, 512, 8, 8],
            3,
            60,
            core::array::from_fn(|i| Identity {
                object: i as u64,
                lineage: i as u64,
            }),
        )
        .unwrap();
        let second = encode_current(b"image", &description.bind_catalogue([8; 32])).unwrap();
        assert_ne!(first.digest(), second.digest());
        assert!(root_manifest_v2::verify(second.bytes(), first.digest(), b"image").is_err());
    }
    #[test]
    fn root_v2_description_rejects_alias_overflow_limits_and_wrong_current_role() {
        let mut ids = core::array::from_fn(|i| Identity {
            object: i as u64,
            lineage: i as u64,
        });
        ids[1] = ids[0];
        assert!(Description::full_graph([4096, 256, 7, 7], 3, 60, ids).is_err());
        let ids = core::array::from_fn(|i| Identity {
            object: i as u64,
            lineage: i as u64,
        });
        assert!(Description::full_graph([0, 256, 7, 7], 3, 60, ids).is_err());
        let desc = Description::new(
            &[Some(SourceIdentity {
                selector: 1,
                kind: Kind::Memory,
                rights: Rights::WRITE,
                object: 0,
                lineage: 0,
            })],
            [4096, 256, 7, 7],
            3,
            60,
        )
        .unwrap()
        .bind_catalogue([7; 32]);
        assert!(encode_current(b"image", &desc).is_err());
    }
}
