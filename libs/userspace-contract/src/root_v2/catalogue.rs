//! Readonly measured desktop cohort metadata. These bytes create no authority.
//! Kernel factories verify content/backing; Root checks the manifest binding.
#![forbid(unsafe_code)]
use super::{ABI, Role};
pub const SIZE: usize = 1536;
pub const HEADER: usize = 288;
pub const IMAGE_BYTES: usize = 176;
pub const IMAGES: usize = 6;
pub const MEASUREMENT_OFFSET: usize = 144;
pub const MEASUREMENT_DOMAIN: &[u8] = b"evrosion.desktop.fullgraph.v1\0";
pub const CHILD_LIMITS: [u64; 4] = [16_384, 32, 1, 1];
pub const CHILD_ROLE_COUNTS: [u8; IMAGES] = [8, 4, 8, 6, 6, 8];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Version,
    Reserved,
    Abi,
    Identity,
    Policy,
    Profile,
    Image,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provenance {
    DevelopmentSource,
    Zion,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Image {
    pub role: Role,
    pub image: [u8; 32],
    pub descriptor: [u8; 32],
    pub abi: [u8; 32],
    pub limits: [u64; 4],
    pub display_layout: bool,
    pub grants: u8,
    pub roles: [u8; 32],
}
pub struct Description {
    pub root_image: [u8; 32],
    pub kernel_input: [u8; 32],
    pub graph: [u8; 32],
    pub app_id: [u8; 16],
    pub package: [u8; 32],
    pub app_build: [u8; 32],
    pub provenance: Provenance,
    pub restart_attempts: u8,
    pub restart_window: u64,
    pub images: [Image; IMAGES],
}
fn word(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
}
fn put(b: &mut [u8], i: usize, n: u64) {
    b[i..i + 8].copy_from_slice(&n.to_le_bytes());
}
fn nonzero(b: &[u8]) -> bool {
    b.iter().any(|&n| n != 0)
}
fn image_role(i: usize) -> Role {
    [
        Role::ShellImage,
        Role::InputImage,
        Role::FileImage,
        Role::BlockImage,
        Role::AppImage,
        Role::DisplayImage,
    ][i]
}
pub struct Catalogue<'a> {
    bytes: &'a [u8],
}
impl<'a> Catalogue<'a> {
    pub fn decode(b: &'a [u8]) -> Result<Self, Error> {
        if b.len() != SIZE {
            return Err(Error::Length);
        }
        if &b[..8] != b"EVGRAPH1"
            || b[8..10] != 1u16.to_le_bytes()
            || b[10..12] != (SIZE as u16).to_le_bytes()
        {
            return Err(Error::Version);
        }
        if b[12..14] != 1u16.to_le_bytes() || word(b, 272) != 1 || word(b, 280) != 1 {
            return Err(Error::Profile);
        }
        if b[14..16]
            .iter()
            .chain(&b[258..264])
            .chain(&b[HEADER + IMAGES * IMAGE_BYTES..])
            .any(|&n| n != 0)
        {
            return Err(Error::Reserved);
        }
        if b[48..80] != ABI || b[80..112] != crate::ABI {
            return Err(Error::Abi);
        }
        if !nonzero(&b[16..48])
            || !nonzero(&b[112..144])
            || !nonzero(&b[176..192])
            || !nonzero(&b[224..256])
        {
            return Err(Error::Identity);
        }
        if b[256] > 8 || word(b, 264) == 0 {
            return Err(Error::Policy);
        }
        let value = Self { bytes: b };
        for (i, image) in value.images().enumerate() {
            let slot = &b[HEADER + i * IMAGE_BYTES..HEADER + (i + 1) * IMAGE_BYTES];
            if word(slot, 0) != image_role(i).selector()
                || !nonzero(&image.image)
                || !nonzero(&image.descriptor)
                || !nonzero(&image.roles)
            {
                return Err(Error::Image);
            }
            if image.abi != crate::ABI
                || image.limits != CHILD_LIMITS
                || image.grants != CHILD_ROLE_COUNTS[i]
                || image.display_layout != (i == 5)
            {
                return Err(Error::Profile);
            }
            if slot[136] > 1 || slot[138..144].iter().any(|&n| n != 0) {
                return Err(Error::Reserved);
            }
        }
        match b[257] {
            1 if !nonzero(&b[192..224])
                && value.app_build() == value.images().nth(4).unwrap().image => {}
            2 if nonzero(&b[192..224]) => (),
            _ => return Err(Error::Identity),
        }
        Ok(value)
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub fn root_image(&self) -> [u8; 32] {
        self.bytes[16..48].try_into().unwrap()
    }
    pub fn kernel_input(&self) -> [u8; 32] {
        self.bytes[112..144].try_into().unwrap()
    }
    pub fn graph_measurement(&self) -> [u8; 32] {
        self.bytes[144..176].try_into().unwrap()
    }
    pub fn app_id(&self) -> [u8; 16] {
        self.bytes[176..192].try_into().unwrap()
    }
    pub fn package(&self) -> [u8; 32] {
        self.bytes[192..224].try_into().unwrap()
    }
    pub fn app_build(&self) -> [u8; 32] {
        self.bytes[224..256].try_into().unwrap()
    }
    pub fn provenance(&self) -> Provenance {
        if self.bytes[257] == 1 {
            Provenance::DevelopmentSource
        } else {
            Provenance::Zion
        }
    }
    pub fn restart_attempts(&self) -> u8 {
        self.bytes[256]
    }
    pub fn restart_window(&self) -> u64 {
        word(self.bytes, 264)
    }
    pub fn measurement_parts(&self) -> (&'a [u8], &'a [u8]) {
        (
            &self.bytes[..MEASUREMENT_OFFSET],
            &self.bytes[MEASUREMENT_OFFSET + 32..],
        )
    }
    pub fn images(&self) -> impl Iterator<Item = Image> + '_ {
        (0..IMAGES).map(|i| {
            let b = &self.bytes[HEADER + i * IMAGE_BYTES..];
            Image {
                role: image_role(i),
                image: b[8..40].try_into().unwrap(),
                descriptor: b[40..72].try_into().unwrap(),
                abi: b[72..104].try_into().unwrap(),
                limits: [104, 112, 120, 128].map(|n| word(b, n)),
                display_layout: b[136] != 0,
                grants: b[137],
                roles: b[144..176].try_into().unwrap(),
            }
        })
    }
}
pub fn encode(d: Description) -> Result<[u8; SIZE], Error> {
    let mut b = [0; SIZE];
    b[..8].copy_from_slice(b"EVGRAPH1");
    b[8..10].copy_from_slice(&1u16.to_le_bytes());
    b[10..12].copy_from_slice(&(SIZE as u16).to_le_bytes());
    b[12..14].copy_from_slice(&1u16.to_le_bytes());
    b[16..48].copy_from_slice(&d.root_image);
    b[48..80].copy_from_slice(&ABI);
    b[80..112].copy_from_slice(&crate::ABI);
    b[112..144].copy_from_slice(&d.kernel_input);
    b[144..176].copy_from_slice(&d.graph);
    b[176..192].copy_from_slice(&d.app_id);
    b[192..224].copy_from_slice(&d.package);
    b[224..256].copy_from_slice(&d.app_build);
    b[256] = d.restart_attempts;
    b[257] = if d.provenance == Provenance::DevelopmentSource {
        1
    } else {
        2
    };
    put(&mut b, 264, d.restart_window);
    put(&mut b, 272, 1);
    put(&mut b, 280, 1);
    for (i, image) in d.images.into_iter().enumerate() {
        let slot = &mut b[HEADER + i * IMAGE_BYTES..HEADER + (i + 1) * IMAGE_BYTES];
        put(slot, 0, image.role.selector());
        slot[8..40].copy_from_slice(&image.image);
        slot[40..72].copy_from_slice(&image.descriptor);
        slot[72..104].copy_from_slice(&image.abi);
        for (j, n) in image.limits.into_iter().enumerate() {
            put(slot, 104 + j * 8, n);
        }
        slot[136] = u8::from(image.display_layout);
        slot[137] = image.grants;
        slot[144..176].copy_from_slice(&image.roles);
    }
    Catalogue::decode(&b)?;
    Ok(b)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> [u8; SIZE] {
        encode(Description {
            root_image: [1; 32],
            kernel_input: [2; 32],
            graph: [3; 32],
            app_id: [4; 16],
            package: [0; 32],
            app_build: [9; 32],
            provenance: Provenance::DevelopmentSource,
            restart_attempts: 3,
            restart_window: 60000,
            images: core::array::from_fn(|i| Image {
                role: image_role(i),
                image: if i == 4 { [9; 32] } else { [i as u8 + 1; 32] },
                descriptor: [8; 32],
                abi: crate::ABI,
                limits: CHILD_LIMITS,
                display_layout: i == 5,
                grants: CHILD_ROLE_COUNTS[i],
                roles: [7; 32],
            }),
        })
        .unwrap()
    }
    #[test]
    fn catalogue_keeps_root_abi2_and_children_abi1_and_stable_identity() {
        let b = fixture();
        let c = Catalogue::decode(&b).unwrap();
        assert_eq!(c.images().count(), 6);
        assert_eq!(c.app_id(), [4; 16]);
        assert_eq!(c.package(), [0; 32]);
        assert_eq!(c.provenance(), Provenance::DevelopmentSource);
    }
    #[test]
    fn malformed_cohort_lengths_reserved_roles_profiles_and_fake_package_fail() {
        let b = fixture();
        for n in 0..SIZE {
            assert!(Catalogue::decode(&b[..n]).is_err());
        }
        for offset in [
            0,
            8,
            10,
            12,
            14,
            48,
            80,
            257,
            258,
            272,
            280,
            HEADER,
            HEADER + 72,
            HEADER + 104,
            HEADER + 136,
            HEADER + 137,
            HEADER + 138,
            SIZE - 1,
        ] {
            let mut changed = b;
            changed[offset] ^= 1;
            assert!(Catalogue::decode(&changed).is_err(), "offset {offset}");
        }
        let mut changed = b;
        changed[192] = 1;
        assert!(Catalogue::decode(&changed).is_err());
    }
}
