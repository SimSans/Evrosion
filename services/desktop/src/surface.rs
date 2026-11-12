//! Exact volatile access to owned surface mappings, never a shared Rust borrow.
use crate::require;
use ev_graphics::{Color, HEADER_BYTES, HEIGHT, MAPPED_BYTES, PIXEL_BYTES, SurfaceHeader, WIDTH};
#[cfg(not(feature = "display"))]
use ev_graphics::{Error, Pixels};
pub struct Surface {
    address: usize,
}
impl Surface {
    #[cfg(all(feature = "interactive", not(feature = "display")))]
    pub fn is_zero(&self) -> bool {
        for i in 0..MAPPED_BYTES {
            // SAFETY: this newly admitted App owns its initialized RW surface;
            // no Present has been accepted and no other actor can write it.
            if unsafe { (self.address as *const u8).add(i).read_volatile() } != 0 {
                return false;
            }
        }
        true
    }
    pub fn at(record: u64) -> Self {
        let base = record
            .checked_sub(509 * 4096)
            .unwrap_or_else(|| ev_userspace_runtime::exit(710));
        Self {
            address: usize::try_from(base + 384 * 4096)
                .unwrap_or_else(|_| ev_userspace_runtime::exit(711)),
        }
    }
    #[cfg(not(feature = "compositor"))]
    pub fn header(&self) -> SurfaceHeader {
        self.try_header()
            .unwrap_or_else(|_| ev_userspace_runtime::exit(712))
    }
    pub fn try_header(&self) -> Result<SurfaceHeader, ev_graphics::Error> {
        let bytes = core::array::from_fn(|i| {
            // SAFETY: exact initialized64-byte header inside retained mapped extent.
            unsafe { (self.address as *const u8).add(i).read_volatile() }
        });
        SurfaceHeader::parse(&bytes)
    }
    #[cfg(feature = "compositor")]
    pub fn auxiliary_at(record: u64) -> Self {
        let base = record
            .checked_sub(509 * 4096)
            .unwrap_or_else(|| ev_userspace_runtime::exit(710));
        Self {
            address: usize::try_from(base + 304 * 4096)
                .unwrap_or_else(|_| ev_userspace_runtime::exit(711)),
        }
    }
    #[cfg(not(feature = "display"))]
    pub fn publish(&mut self, sequence: u64) {
        let header = SurfaceHeader { sequence }
            .encode()
            .unwrap_or_else(|_| ev_userspace_runtime::exit(713));
        for (i, byte) in header.into_iter().enumerate() {
            // SAFETY: sole App thread owns RW mapping and has no in-flight Present.
            unsafe { (self.address as *mut u8).add(i).write_volatile(byte) };
        }
        for i in HEADER_BYTES + PIXEL_BYTES..MAPPED_BYTES {
            // SAFETY: exact63-page extent, unused initialized tail, exclusive App credit.
            unsafe { (self.address as *mut u8).add(i).write_volatile(0) };
        }
    }
    #[cfg(not(feature = "compositor"))]
    pub fn tail(&self) {
        require(self.valid_tail(), 714);
    }
    pub fn valid_tail(&self) -> bool {
        for i in HEADER_BYTES + PIXEL_BYTES..MAPPED_BYTES {
            // SAFETY: fixed bounded initialized tail; App is blocked while Display reads.
            if unsafe { (self.address as *const u8).add(i).read_volatile() } != 0 {
                return false;
            }
        }
        true
    }
    #[cfg(all(feature = "display", not(feature = "compositor")))]
    pub fn pixel(&self, x: usize, y: usize) -> Color {
        let value = self.sample(x, y);
        require(value & 0xff000000 == 0, 716);
        Color(value)
    }
    #[cfg(feature = "display")]
    fn sample(&self, x: usize, y: usize) -> u32 {
        require(x < WIDTH && y < HEIGHT, 715);
        // SAFETY: bounded initialized XRGB pixel; actual mapping and blocked writer
        // retain ownership. The integer value introduces no shared reference alias.
        unsafe {
            (self.address as *const u32)
                .add(HEADER_BYTES / 4 + y * WIDTH + x)
                .read_volatile()
        }
    }
    #[cfg(feature = "compositor")]
    pub fn opaque_pixel(&self, x: usize, y: usize) -> Color {
        // X in XRGB carries no alpha or authority. Arbitrary App padding bits
        // are ignored rather than allowed to terminate the compositor.
        Color(self.sample(x, y) & 0x00ff_ffff)
    }
    #[cfg(all(feature = "display-denied-surface", not(feature = "compositor")))]
    pub fn attempt_forbidden_write(&self) {
        // SAFETY: deliberate actual write to a READ-only surface lease. The expected
        // user page fault is contained by the ordinary runtime; no alias is borrowed.
        unsafe {
            (self.address as *mut u32)
                .add(HEADER_BYTES / 4)
                .write_volatile(0x00ff00ff)
        };
        ev_userspace_runtime::exit(717)
    }
}
#[cfg(not(feature = "display"))]
impl Pixels for Surface {
    fn dimensions(&self) -> (usize, usize) {
        (WIDTH, HEIGHT)
    }
    fn write(&mut self, x: usize, y: usize, color: Color) -> Result<(), Error> {
        if x >= WIDTH || y >= HEIGHT || color.0 & 0xff000000 != 0 {
            return Err(Error::Bounds);
        }
        // SAFETY: sole App thread's RW mapping and render credit, no syscall/shared
        // reference retained, exact prebound pixel bounds checked before mutation.
        unsafe {
            (self.address as *mut u32)
                .add(HEADER_BYTES / 4 + y * WIDTH + x)
                .write_volatile(color.0)
        };
        Ok(())
    }
}
