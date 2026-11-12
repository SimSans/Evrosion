use crate::{event, grant, now, require, surface::Surface, yield_now};
use ev_graphics::{Color, HEADER_BYTES, HEIGHT, Present, WIDTH};
use ev_userspace_runtime as rt;
struct Scanout {
    address: usize,
    width: usize,
    height: usize,
    stride: usize,
    bgr: bool,
}
impl Scanout {
    fn open(cap: u64) -> Self {
        let get = |selector| {
            let r = rt::call(rt::syscall::DISPLAY_INFO, cap, selector, 0);
            require(r.status == 0 && r.capability == 0, 730);
            usize::try_from(r.value).unwrap_or_else(|_| rt::exit(731))
        };
        let address = get(1);
        let width = get(2);
        let height = get(3);
        let stride = get(4);
        let length = get(5);
        let format = get(6);
        require(
            address != 0
                && address.is_multiple_of(4)
                && width >= 800
                && height >= 600
                && width <= 2048
                && height <= 2048
                && stride >= width,
            732,
        );
        require(
            stride
                .checked_mul(height)
                .and_then(|n| n.checked_mul(4))
                .is_some_and(|n| n <= length)
                && matches!(format, 1 | 2),
            733,
        );
        Self {
            address,
            width,
            height,
            stride,
            bgr: format == 2,
        }
    }
    fn pixel(&mut self, x: usize, y: usize, color: Color) {
        require(x < self.width && y < self.height, 734);
        let [r, g, b] = color.components();
        let bytes = if self.bgr { [b, g, r, 0] } else { [r, g, b, 0] };
        // SAFETY: independently authorized, initialized device-only aperture; exact
        // actual geometry bounds, preserved source cache type, no RAM ownership claim.
        unsafe {
            (self.address as *mut u32)
                .add(y * self.stride + x)
                .write_volatile(u32::from_le_bytes(bytes))
        };
    }
    fn present(&mut self, surface: &Surface) {
        let left = (self.width - WIDTH * 2) / 2;
        let top = (self.height - HEIGHT * 2) / 2;
        for y in 0..self.height {
            for x in 0..self.width {
                let color = if x >= left && x < left + WIDTH * 2 && y >= top && y < top + HEIGHT * 2
                {
                    surface.pixel((x - left) / 2, (y - top) / 2)
                } else if x + 2 >= left
                    && x < left + WIDTH * 2 + 2
                    && y + 2 >= top
                    && y < top + HEIGHT * 2 + 2
                {
                    ev_graphics::ACCENT
                } else {
                    ev_graphics::BACKGROUND
                };
                self.pixel(x, y, color);
            }
        }
        // SAFETY: Display alone owns this writable device aperture. Source PAT
        // and MTRR typing can make scanout stores write-combining, so publish
        // their visibility before the protected reply releases the App credit.
        // No nomem option hides the store-ordering boundary from the compiler.
        unsafe { core::arch::asm!("sfence", options(nostack, preserves_flags)) };
    }
}
pub fn run(b: &ev_userspace_contract::Bootstrap<'_>, record: u64, stop: u64) -> ! {
    require(b.grants().count() == 4, 735);
    let memory = grant(b, 1, 1, 5);
    let endpoint = grant(b, 2, 2, 272);
    let device = grant(b, 3, 8, 7);
    let events = grant(b, 4, 2, 8);
    require(rt::inspect(memory, 1).status == 0, 736);
    let denied = rt::inspect(memory, 2);
    require(
        denied.status == 1 && denied.value == 0 && denied.capability == 0,
        745,
    );
    let mut scanout = Scanout::open(device);
    let surface = Surface::at(record);
    let bound = rt::call(rt::syscall::BIND_RECEIVER, endpoint, 0, 0);
    require(
        bound.status == 0 && bound.value == 0 && bound.capability == 0,
        737,
    );
    event(events, *b"EVGDRDY1", stop);
    let mut next = 1u32;
    loop {
        require(now() < stop, 738);
        let received = rt::discipline::receive(endpoint).unwrap_or_else(|_| rt::exit(739));
        let Some(request) = received else {
            yield_now();
            continue;
        };
        let present = Present::parse_request(request.bytes).unwrap_or_else(|_| rt::exit(740));
        require(
            present.0 == next && surface.header().sequence == u64::from(next),
            741,
        );
        surface.tail();
        #[cfg(feature = "display-denied-surface")]
        surface.attempt_forbidden_write();
        scanout.present(&surface);
        rt::discipline::reply(endpoint, present.reply().unwrap(), request.nonce)
            .unwrap_or_else(|_| rt::exit(742));
        event(events, *b"EVGDDON1", stop);
        next = next.checked_add(1).unwrap_or_else(|| rt::exit(743));
        // Header length is fixed in the measured contract; no client-selected pointer.
        require(HEADER_BYTES == 64, 744);
    }
}
