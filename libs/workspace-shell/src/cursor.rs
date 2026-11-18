//! Root-controlled V5 cursor over the compositor's own actual scanout. No App
//! surface is read, and no metadata here authenticates a Root control message.
use ev_graphics::Color;
pub const SAVED: usize = 8 * 12 * 4 * 4;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Geometry,
    Scanout,
}
pub trait Scanout {
    fn dimensions(&self) -> (usize, usize);
    fn read(&self, x: usize, y: usize) -> Result<u32, Error>;
    fn write(&mut self, x: usize, y: usize, raw: u32) -> Result<(), Error>;
    fn encode(&self, color: Color) -> u32;
    fn synchronize(&mut self);
}
#[derive(Clone, Copy)]
struct Footprint {
    left: usize,
    top: usize,
    width: usize,
    height: usize,
}
pub struct Cursor {
    saved: [u32; SAVED],
    drawn: Option<Footprint>,
}
impl Default for Cursor {
    fn default() -> Self {
        Self::new()
    }
}
impl Cursor {
    pub const fn new() -> Self {
        Self {
            saved: [0; SAVED],
            drawn: None,
        }
    }
    pub fn hide<S: Scanout>(&mut self, sink: &mut S) -> Result<(), Error> {
        let Some(f) = self.drawn else {
            return Ok(());
        };
        let (w, h) = sink.dimensions();
        if f.left + f.width > w || f.top + f.height > h {
            return Err(Error::Geometry);
        }
        for y in 0..f.height {
            for x in 0..f.width {
                sink.write(f.left + x, f.top + y, self.saved[y * f.width + x])?;
            }
        }
        sink.synchronize();
        self.drawn = None;
        Ok(())
    }
    /// `left/top` locate the complete scaled640x480 desktop in the actual
    /// framebuffer. The caller must hide before every producer/chrome update.
    pub fn show<S: Scanout>(
        &mut self,
        sink: &mut S,
        left: usize,
        top: usize,
        scale: u8,
        x: u16,
        y: u16,
    ) -> Result<(), Error> {
        if self.drawn.is_some() || !(1..=4).contains(&scale) || x >= 640 || y >= 480 {
            return Err(Error::Geometry);
        }
        let (w, h) = sink.dimensions();
        let scale = usize::from(scale);
        if left.checked_add(640 * scale).is_none_or(|right| right > w)
            || top.checked_add(480 * scale).is_none_or(|bottom| bottom > h)
        {
            return Err(Error::Geometry);
        }
        let f = Footprint {
            left: left + usize::from(x) * scale,
            top: top + usize::from(y) * scale,
            width: (640 - usize::from(x)).min(8) * scale,
            height: (480 - usize::from(y)).min(12) * scale,
        };
        if f.width * f.height > SAVED {
            return Err(Error::Geometry);
        }
        sink.synchronize();
        for y in 0..f.height {
            for x in 0..f.width {
                self.saved[y * f.width + x] = sink.read(f.left + x, f.top + y)?;
            }
        }
        // Retain the complete underlying rectangle before the first cursor
        // write, so a failed sink still has one exact restoration obligation.
        self.drawn = Some(f);
        for cy in 0..f.height {
            for cx in 0..f.width {
                if let Some(color) = ev_graphics::composition::cursor_pixel(cx / scale, cy / scale)
                {
                    let raw = sink.encode(color);
                    sink.write(f.left + cx, f.top + cy, raw)?;
                }
            }
        }
        sink.synchronize();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{vec, vec::Vec};
    struct Pixels {
        w: usize,
        h: usize,
        data: Vec<u32>,
        reads: usize,
    }
    impl Scanout for Pixels {
        fn dimensions(&self) -> (usize, usize) {
            (self.w, self.h)
        }
        fn read(&self, x: usize, y: usize) -> Result<u32, Error> {
            if x >= self.w || y >= self.h {
                return Err(Error::Scanout);
            }
            Ok(self.data[1 + y * self.w + x])
        }
        fn write(&mut self, x: usize, y: usize, raw: u32) -> Result<(), Error> {
            if x >= self.w || y >= self.h {
                return Err(Error::Scanout);
            }
            self.data[1 + y * self.w + x] = raw;
            Ok(())
        }
        fn encode(&self, color: Color) -> u32 {
            color.0
        }
        fn synchronize(&mut self) {
            self.reads += 1;
        }
    }
    #[test]
    fn full_u16_y_offscreen_clipping_and_raw_restore_keep_guards() {
        let mut p = Pixels {
            w: 800,
            h: 600,
            data: vec![0xaabbccdd; 800 * 600 + 2],
            reads: 0,
        };
        let original = p.data.clone();
        let mut cursor = Cursor::new();
        cursor.show(&mut p, 80, 60, 1, 639, 479).unwrap();
        assert_ne!(p.data, original);
        cursor.hide(&mut p).unwrap();
        assert_eq!(p.data, original);
        assert!(p.reads >= 3);
        assert_eq!(
            cursor.show(&mut p, 80, 60, 1, 640, 479),
            Err(Error::Geometry)
        );
        assert_eq!(
            cursor.show(&mut p, 80, 60, 1, 100, 480),
            Err(Error::Geometry)
        );
        assert_eq!(p.data, original);
    }
    #[test]
    fn maximum_scale_restores_new_scanout_without_any_producer_borrow() {
        let mut p = Pixels {
            w: 2560,
            h: 1920,
            data: vec![0x11223344; 2560 * 1920 + 2],
            reads: 0,
        };
        let mut cursor = Cursor::new();
        cursor.show(&mut p, 0, 0, 4, 10, 20).unwrap();
        cursor.hide(&mut p).unwrap();
        p.data[1 + 80 * 2560 + 40] = 0x89abcdef;
        let new = p.data.clone();
        cursor.show(&mut p, 0, 0, 4, 10, 20).unwrap();
        cursor.hide(&mut p).unwrap();
        assert_eq!(p.data, new);
        assert_eq!(cursor.show(&mut p, 1, 0, 4, 0, 0), Err(Error::Geometry));
        assert_eq!(cursor.show(&mut p, 0, 0, 0, 0, 0), Err(Error::Geometry));
        assert_eq!(p.data, new);
    }
}
