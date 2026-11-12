//! Separate userspace compositor. Each surface is read only while servicing its
//! sole writer's protected Present. Chrome composition never samples App RAM.
use crate::{event, grant, now, require, surface::Surface, yield_now};
use ev_desktop::{
    compositor_policy::{Producer, SessionReset, State},
    protocol::WindowControl,
};
use ev_graphics::{
    Color, HEIGHT, Present, WIDTH,
    composition::{APP_VIEW, app_sample},
};
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
        let get = |field| {
            let r = rt::call(rt::syscall::DISPLAY_INFO, cap, field, 0);
            require(r.status == 0 && r.capability == 0, 810);
            usize::try_from(r.value).unwrap_or_else(|_| rt::exit(811))
        };
        let address = get(1);
        let width = get(2);
        let height = get(3);
        let stride = get(4);
        let bytes = get(5);
        let format = get(6);
        require(
            address != 0
                && address.is_multiple_of(4)
                && (800..=2048).contains(&width)
                && (600..=2048).contains(&height)
                && stride >= width
                && stride
                    .checked_mul(height)
                    .and_then(|n| n.checked_mul(4))
                    .is_some_and(|n| n <= bytes)
                && matches!(format, 1 | 2),
            812,
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
        require(x < self.width && y < self.height, 813);
        let [r, g, b] = color.components();
        let bytes = if self.bgr { [b, g, r, 0] } else { [r, g, b, 0] };
        // SAFETY: exact independently scoped device aperture, actual validated
        // geometry/cache typing. Only this Display process owns writable scanout.
        unsafe {
            (self.address as *mut u32)
                .add(y * self.stride + x)
                .write_volatile(u32::from_le_bytes(bytes))
        };
    }
    fn shell(&mut self, surface: &Surface, visible: bool) {
        let left = (self.width - WIDTH * 2) / 2;
        let top = (self.height - HEIGHT * 2) / 2;
        for y in 0..self.height {
            for x in 0..self.width {
                let color = if x >= left && x < left + WIDTH * 2 && y >= top && y < top + HEIGHT * 2
                {
                    let sx = (x - left) / 2;
                    let sy = (y - top) / 2;
                    if visible && APP_VIEW.contains(sx, sy) {
                        continue;
                    }
                    surface.opaque_pixel(sx, sy)
                } else {
                    ev_graphics::BACKGROUND
                };
                self.pixel(x, y, color);
            }
        }
        Self::flush();
    }
    fn app(&mut self, surface: &Surface) {
        let left = (self.width - WIDTH * 2) / 2;
        let top = (self.height - HEIGHT * 2) / 2;
        for y in APP_VIEW.y..APP_VIEW.y + APP_VIEW.height {
            for x in APP_VIEW.x..APP_VIEW.x + APP_VIEW.width {
                let (sx, sy) = app_sample(x, y).unwrap();
                let color = surface.opaque_pixel(sx, sy);
                for dy in 0..2 {
                    for dx in 0..2 {
                        self.pixel(left + x * 2 + dx, top + y * 2 + dy, color);
                    }
                }
            }
        }
        Self::flush();
    }
    fn flush() {
        // SAFETY: preserve visibility of any actual WC device stores before the
        // protected reply releases this producer's sole surface-write credit.
        unsafe { core::arch::asm!("sfence", options(nostack, preserves_flags)) };
    }
}
fn bind(cap: u64) {
    let r = rt::call(rt::syscall::BIND_RECEIVER, cap, 0, 0);
    require(r.status == 0 && r.value == 0 && r.capability == 0, 814);
}
fn reply(cap: u64, bytes: [u8; 8], nonce: rt::discipline::ReplyNonce) {
    rt::discipline::reply(cap, bytes, nonce).unwrap_or_else(|_| rt::exit(815));
}
pub fn run(b: &ev_userspace_contract::Bootstrap<'_>, record: u64, stop: u64) -> ! {
    require(b.grants().count() == 8, 816);
    let app_memory = grant(b, 1, 1, 5);
    let app_present = grant(b, 2, 2, 272);
    let shell_memory = grant(b, 3, 1, 5);
    let shell_present = grant(b, 4, 2, 272);
    let window = grant(b, 5, 2, 272);
    let root = grant(b, 6, 2, 272);
    let device = grant(b, 7, 8, 7);
    let events = grant(b, 8, 2, 8);
    for cap in [app_memory, shell_memory] {
        let r = rt::inspect(cap, 1);
        require(r.status == 0 && r.capability == 0, 817);
    }
    for cap in [app_present, shell_present, window, root] {
        bind(cap);
    }
    let app = Surface::at(record);
    let shell = Surface::auxiliary_at(record);
    let mut scanout = Scanout::open(device);
    let mut state = State::new();
    event(events, *b"EVGDRDY1", stop);
    loop {
        require(now() < stop, 818);
        if let Some(r) = rt::discipline::receive(root).unwrap_or_else(|_| rt::exit(819)) {
            let bytes = match SessionReset::parse_request(r.bytes) {
                Ok(reset) if state.reset(reset).is_ok() => reset.reply().unwrap(),
                _ => *b"EVDE\x01\0\0\0",
            };
            reply(root, bytes, r.nonce);
            continue;
        }
        if let Some(r) = rt::discipline::receive(window).unwrap_or_else(|_| rt::exit(820)) {
            let bytes = match WindowControl::parse_request(r.bytes) {
                Ok(control) if state.window(control).is_ok() => control.reply().unwrap(),
                _ => *b"EVDE\x02\0\0\0",
            };
            reply(window, bytes, r.nonce);
            continue;
        }
        for (producer, endpoint, surface) in [
            (Producer::Shell, shell_present, &shell),
            (Producer::App, app_present, &app),
        ] {
            let Some(r) = rt::discipline::receive(endpoint).unwrap_or_else(|_| rt::exit(821))
            else {
                continue;
            };
            let request = Present::parse_request(r.bytes);
            let header = surface.try_header();
            let valid = match (request, header) {
                (Ok(p), Ok(h)) if surface.valid_tail() => {
                    state.present(producer, p.0, h.sequence).map(|()| p).ok()
                }
                _ => None,
            };
            let Some(present) = valid else {
                reply(endpoint, *b"EVDE\x03\0\0\0", r.nonce);
                continue;
            };
            match producer {
                Producer::Shell => scanout.shell(surface, state.visible()),
                Producer::App if state.visible() => scanout.app(surface),
                Producer::App => {}
            }
            reply(endpoint, present.reply().unwrap(), r.nonce);
            event(
                events,
                if producer == Producer::Shell {
                    *b"EVSHDON1"
                } else {
                    *b"EVGDDON1"
                },
                stop,
            );
        }
        yield_now();
    }
}
