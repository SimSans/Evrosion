//! Volatile writer for an actual admitted, retained RAM surface mapping.
//! No safe arbitrary-address constructor and no shared Rust pixel references.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
use core::marker::PhantomData;
use ev_graphics::{
    Color, Error, HEADER_BYTES, HEIGHT, MAPPED_BYTES, PIXEL_BYTES, Pixels, SurfaceHeader, WIDTH,
};
/// Sole userspace writer. The raw marker prevents accidental Send/Sync between
/// threads; mapping/transport ownership still belongs to the admitted runtime.
///
/// ```compile_fail,E0133
/// use ev_userspace_graphics::Surface;
/// let _ = Surface::from_validated_mapping(4096, ev_graphics::MAPPED_BYTES);
/// ```
/// ```compile_fail,E0277
/// use ev_userspace_graphics::Surface;
/// fn require_send<T: Send>() {}
/// require_send::<Surface>();
/// ```
/// ```compile_fail,E0277
/// use ev_userspace_graphics::Surface;
/// fn require_sync<T: Sync>() {}
/// require_sync::<Surface>();
/// ```
pub struct Surface {
    address: usize,
    _single_writer: PhantomData<*mut ()>,
}
impl Surface {
    /// # Safety
    /// For an accepted address/extent, caller must retain an initialized RW RAM
    /// mapping of exactly63 pages, matching the admitted Surface role, for this
    /// value's whole lifetime. It must be the sole writer and must not access
    /// pixels/header while another actor holds accepted Present read credit.
    /// No CPU/device/unmap can revoke storage while these operations execute.
    /// Syntax-invalid arguments cause no memory access. The address is data,
    /// never proof that a capability, physical mapping or credit exists.
    pub unsafe fn from_validated_mapping(address: usize, extent: usize) -> Result<Self, Error> {
        if address == 0
            || !address.is_multiple_of(4096)
            || extent != MAPPED_BYTES
            || address
                .checked_add(extent)
                .is_none_or(|end| end > 1usize << 47)
        {
            return Err(Error::Bounds);
        }
        Ok(Self {
            address,
            _single_writer: PhantomData,
        })
    }
    pub fn is_zero(&self) -> bool {
        for index in 0..MAPPED_BYTES {
            // SAFETY: constructor's retained initialized RAM extent/credit;
            // no reference is created or carried across a syscall.
            if unsafe { (self.address as *const u8).add(index).read_volatile() } != 0 {
                return false;
            }
        }
        true
    }
    pub fn try_header(&self) -> Result<SurfaceHeader, Error> {
        let bytes = core::array::from_fn(|index| {
            // SAFETY: first64 initialized bytes within the retained mapping.
            unsafe { (self.address as *const u8).add(index).read_volatile() }
        });
        SurfaceHeader::parse(&bytes)
    }
    pub fn publish(&mut self, sequence: u64) -> Result<(), Error> {
        let header = SurfaceHeader { sequence }.encode()?;
        for (index, byte) in header.into_iter().enumerate() {
            // SAFETY: sole writer owns the exact checked extent/render credit.
            unsafe { (self.address as *mut u8).add(index).write_volatile(byte) };
        }
        for index in HEADER_BYTES + PIXEL_BYTES..MAPPED_BYTES {
            // SAFETY: fixed initialized unused tail in the same owned mapping.
            unsafe { (self.address as *mut u8).add(index).write_volatile(0) };
        }
        Ok(())
    }
    pub fn valid_tail(&self) -> bool {
        for index in HEADER_BYTES + PIXEL_BYTES..MAPPED_BYTES {
            // SAFETY: exact initialized tail with caller-retained read credit.
            if unsafe { (self.address as *const u8).add(index).read_volatile() } != 0 {
                return false;
            }
        }
        true
    }
}
impl Pixels for Surface {
    fn dimensions(&self) -> (usize, usize) {
        (WIDTH, HEIGHT)
    }
    fn write(&mut self, x: usize, y: usize, color: Color) -> Result<(), Error> {
        if x >= WIDTH || y >= HEIGHT || color.0 & 0xff000000 != 0 {
            return Err(Error::Bounds);
        }
        // SAFETY: aligned XRGB pixel within fixed bounds; sole writer/retained
        // mapping/credit promised by unsafe constructor. No borrowed pixels.
        unsafe {
            (self.address as *mut u32)
                .add(HEADER_BYTES / 4 + y * WIDTH + x)
                .write_volatile(color.0)
        };
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::boxed::Box;
    #[repr(C, align(4096))]
    struct Guarded {
        before: [u8; 4096],
        surface: [u8; MAPPED_BYTES],
        after: [u8; 4096],
    }
    fn storage() -> Box<Guarded> {
        Box::new(Guarded {
            before: [0xa5; 4096],
            surface: [0; MAPPED_BYTES],
            after: [0x5a; 4096],
        })
    }
    #[test]
    fn invalid_syntax_never_dereferences_or_constructs_an_address_owner() {
        for (address, extent) in [
            (0, MAPPED_BYTES),
            (1, MAPPED_BYTES),
            (4096, 0),
            (4096, MAPPED_BYTES - 1),
            (usize::MAX - 4095, MAPPED_BYTES),
            (1usize << 47, MAPPED_BYTES),
        ] {
            // SAFETY: rejected syntax performs no access and establishes no owner.
            assert!(unsafe { Surface::from_validated_mapping(address, extent) }.is_err());
        }
    }
    #[test]
    fn pixels_header_tail_and_guards_follow_exact_63page_mapping() {
        let mut memory = storage();
        let address = memory.surface.as_mut_ptr() as usize;
        // SAFETY: aligned live Box owns initialized RW extent for the Surface
        // lifetime; this test is sole writer and makes no handoff/syscall.
        let mut surface =
            unsafe { Surface::from_validated_mapping(address, MAPPED_BYTES) }.unwrap();
        assert!(surface.is_zero());
        assert!(surface.try_header().is_err());
        for (x, y) in [(0, 0), (WIDTH - 1, HEIGHT - 1)] {
            surface.write(x, y, Color::rgb(1, 2, 3)).unwrap();
        }
        for (x, y, color) in [
            (WIDTH, 0, Color(1)),
            (0, HEIGHT, Color(1)),
            (usize::MAX, usize::MAX, Color(1)),
            (0, 0, Color(0xff000000)),
        ] {
            assert_eq!(surface.write(x, y, color), Err(Error::Bounds));
        }
        assert_eq!(surface.publish(0), Err(Error::Counter));
        assert_eq!(&memory.surface[..HEADER_BYTES], &[0; HEADER_BYTES]);
        surface.publish(7).unwrap();
        assert_eq!(surface.try_header(), Ok(SurfaceHeader { sequence: 7 }));
        assert!(surface.valid_tail());
        assert_eq!(memory.before, [0xa5; 4096]);
        assert_eq!(memory.after, [0x5a; 4096]);
        assert_eq!(
            &memory.surface[HEADER_BYTES..HEADER_BYTES + 4],
            &Color::rgb(1, 2, 3).0.to_le_bytes()
        );
        assert_eq!(
            &memory.surface[HEADER_BYTES + PIXEL_BYTES - 4..HEADER_BYTES + PIXEL_BYTES],
            &Color::rgb(1, 2, 3).0.to_le_bytes()
        );
    }
    #[test]
    fn publication_clears_only_unused_tail_and_invalid_counter_is_atomic() {
        let mut memory = storage();
        let address = memory.surface.as_mut_ptr() as usize;
        memory.surface[HEADER_BYTES..].fill(0x33);
        // SAFETY: same retained aligned sole-writer storage as the prior test.
        let mut surface =
            unsafe { Surface::from_validated_mapping(address, MAPPED_BYTES) }.unwrap();
        assert!(!surface.valid_tail());
        surface.publish(1).unwrap();
        assert!(surface.valid_tail());
        assert!(
            memory.surface[HEADER_BYTES..HEADER_BYTES + PIXEL_BYTES]
                .iter()
                .all(|b| *b == 0x33)
        );
        let header = surface.try_header();
        assert_eq!(surface.publish(u64::MAX), Err(Error::Counter));
        assert_eq!(surface.try_header(), header);
        assert_eq!(memory.before, [0xa5; 4096]);
        assert_eq!(memory.after, [0x5a; 4096]);
    }
}
