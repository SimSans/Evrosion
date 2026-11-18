//! Fixed initial desktop layout. Sampling is a coordinate calculation only;
//! the caller must retain the matching blocked producer's actual frame credit.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    pub x: usize,
    pub y: usize,
    pub width: usize,
    pub height: usize,
}
pub const APP_VIEW: Rect = Rect {
    x: 20,
    y: 54,
    width: 280,
    height: 116,
};
/// Explicit session layout, leaving legacy preview composition byte-for-byte.
pub const SESSION_APP_VIEW: Rect = Rect {
    x: 8,
    y: 20,
    width: 304,
    height: 172,
};
impl Rect {
    pub fn contains(self, x: usize, y: usize) -> bool {
        x >= self.x && y >= self.y && x - self.x < self.width && y - self.y < self.height
    }
}
pub fn app_sample(x: usize, y: usize) -> Option<(usize, usize)> {
    // The desktop App renders specifically for this fixed viewport. Sampling
    // is one-to-one so every 5×7 font row survives composition; the larger
    // backing surface and its header/mapping stay unchanged.
    APP_VIEW
        .contains(x, y)
        .then(|| (x - APP_VIEW.x, y - APP_VIEW.y))
}
pub fn session_app_sample(x: usize, y: usize) -> Option<(usize, usize)> {
    SESSION_APP_VIEW
        .contains(x, y)
        .then(|| (x - SESSION_APP_VIEW.x, y - SESSION_APP_VIEW.y))
}
/// Small bounded cursor silhouette. Compositor alone owns the scanout pixels
/// underneath; rendering this mask never reads another producer's surface.
pub const CURSOR_WIDTH: usize = 8;
pub const CURSOR_HEIGHT: usize = 12;
pub fn cursor_pixel(x: usize, y: usize) -> Option<crate::Color> {
    if x >= CURSOR_WIDTH || y >= CURSOR_HEIGHT {
        return None;
    }
    let rows = [
        0x80u8, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff, 0xf0, 0xd8, 0x98, 0x0c,
    ];
    if rows[y] & (0x80 >> x) == 0 {
        return None;
    }
    Some(
        if x == 0 || x == 7 || y == 0 || y == 11 || rows[y] & (0x40 >> x) == 0 {
            crate::BACKGROUND
        } else {
            crate::INK
        },
    )
}

/// The compositor's OWN scanout, never a producer surface. Accessors preserve
/// the exact raw device representation, including its unused high byte.
pub trait CursorPixels {
    fn dimensions(&self) -> (usize, usize);
    fn read(&self, x: usize, y: usize) -> u32;
    fn write(&mut self, x: usize, y: usize, pixel: u32);
    fn encode(&self, color: crate::Color) -> u32;
    /// Complete this device owner's earlier writes before reading underneath
    /// the cursor, including overlapping old/new footprints in WC mappings.
    fn synchronize(&mut self);
}
/// Only the small cursor footprint is retained. Erase before painting a real
/// producer, then save/redraw after it; no out-of-credit shared-surface read.
pub struct CursorOverlay {
    position: Option<(u16, u8)>,
    drawn: bool,
    saved: [u32; CURSOR_WIDTH * CURSOR_HEIGHT * 4],
}
impl Default for CursorOverlay {
    fn default() -> Self {
        Self::new()
    }
}
impl CursorOverlay {
    pub const fn new() -> Self {
        Self {
            position: None,
            drawn: false,
            saved: [0; CURSOR_WIDTH * CURSOR_HEIGHT * 4],
        }
    }
    fn geometry<P: CursorPixels>(pixels: &P) -> Result<(usize, usize), crate::Error> {
        let (width, height) = pixels.dimensions();
        if width < crate::WIDTH * 2 || height < crate::HEIGHT * 2 {
            return Err(crate::Error::Geometry);
        }
        Ok((
            (width - crate::WIDTH * 2) / 2,
            (height - crate::HEIGHT * 2) / 2,
        ))
    }
    pub fn before_paint<P: CursorPixels>(&mut self, pixels: &mut P) -> Result<(), crate::Error> {
        let (left, top) = Self::geometry(pixels)?;
        if !self.drawn {
            return Ok(());
        }
        let (x, y) = self.position.unwrap();
        for cy in 0..CURSOR_HEIGHT.min(crate::HEIGHT - usize::from(y)) {
            for cx in 0..CURSOR_WIDTH.min(crate::WIDTH - usize::from(x)) {
                for dy in 0..2 {
                    for dx in 0..2 {
                        let i = (cy * CURSOR_WIDTH + cx) * 4 + dy * 2 + dx;
                        pixels.write(
                            left + (usize::from(x) + cx) * 2 + dx,
                            top + (usize::from(y) + cy) * 2 + dy,
                            self.saved[i],
                        );
                    }
                }
            }
        }
        self.drawn = false;
        Ok(())
    }
    pub fn after_paint<P: CursorPixels>(&mut self, pixels: &mut P) -> Result<(), crate::Error> {
        let (left, top) = Self::geometry(pixels)?;
        if self.drawn {
            return Err(crate::Error::Counter);
        }
        let Some((x, y)) = self.position else {
            return Ok(());
        };
        pixels.synchronize();
        for cy in 0..CURSOR_HEIGHT.min(crate::HEIGHT - usize::from(y)) {
            for cx in 0..CURSOR_WIDTH.min(crate::WIDTH - usize::from(x)) {
                for dy in 0..2 {
                    for dx in 0..2 {
                        let px = left + (usize::from(x) + cx) * 2 + dx;
                        let py = top + (usize::from(y) + cy) * 2 + dy;
                        let i = (cy * CURSOR_WIDTH + cx) * 4 + dy * 2 + dx;
                        self.saved[i] = pixels.read(px, py);
                        if let Some(color) = cursor_pixel(cx, cy) {
                            pixels.write(px, py, pixels.encode(color));
                        }
                    }
                }
            }
        }
        self.drawn = true;
        Ok(())
    }
    pub fn move_to<P: CursorPixels>(
        &mut self,
        pixels: &mut P,
        x: u16,
        y: u8,
    ) -> Result<(), crate::Error> {
        if usize::from(x) >= crate::WIDTH || usize::from(y) >= crate::HEIGHT {
            return Err(crate::Error::Bounds);
        }
        Self::geometry(pixels)?;
        self.before_paint(pixels)?;
        self.position = Some((x, y));
        self.after_paint(pixels)
    }
    pub fn hide<P: CursorPixels>(&mut self, pixels: &mut P) -> Result<(), crate::Error> {
        self.before_paint(pixels)?;
        self.position = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::{HEIGHT, WIDTH};
    struct Device {
        width: usize,
        height: usize,
        pixels: std::vec::Vec<u32>,
    }
    impl CursorPixels for Device {
        fn dimensions(&self) -> (usize, usize) {
            (self.width, self.height)
        }
        fn read(&self, x: usize, y: usize) -> u32 {
            assert!(x < self.width && y < self.height);
            self.pixels[y * self.width + x]
        }
        fn write(&mut self, x: usize, y: usize, value: u32) {
            assert!(x < self.width && y < self.height);
            self.pixels[y * self.width + x] = value;
        }
        fn encode(&self, color: crate::Color) -> u32 {
            let [r, g, b] = color.components();
            u32::from_le_bytes([b, g, r, 0])
        }
        fn synchronize(&mut self) {}
    }
    #[test]
    fn cursor_moves_clips_and_restores_exact_scanout_bytes_across_real_repaints() {
        let mut d = Device {
            width: 800,
            height: 600,
            pixels: (0..800 * 600).map(|i| 0xab000000 ^ i as u32).collect(),
        };
        let original = d.pixels.clone();
        let mut cursor = CursorOverlay::new();
        for (x, y) in [(160, 100), (319, 199), (0, 0), (315, 195), (160, 100)] {
            cursor.move_to(&mut d, x, y).unwrap();
            assert_ne!(d.pixels, original);
            cursor.before_paint(&mut d).unwrap();
            assert_eq!(d.pixels, original);
            cursor.after_paint(&mut d).unwrap();
        }
        let drawn = d.pixels.clone();
        assert_eq!(cursor.after_paint(&mut d), Err(crate::Error::Counter));
        assert_eq!(cursor.move_to(&mut d, 320, 0), Err(crate::Error::Bounds));
        assert_eq!(d.pixels, drawn);
        cursor.before_paint(&mut d).unwrap();
        d.pixels.fill(0xcd123456); // actual producer repaint under old cursor
        cursor.after_paint(&mut d).unwrap();
        cursor.move_to(&mut d, 319, 199).unwrap();
        cursor.hide(&mut d).unwrap();
        assert!(d.pixels.iter().all(|p| *p == 0xcd123456));
        let mut invalid = Device {
            width: 320,
            height: 200,
            pixels: std::vec![0;320*200],
        };
        assert_eq!(
            cursor.move_to(&mut invalid, 0, 0),
            Err(crate::Error::Geometry)
        );
        assert!(invalid.pixels.iter().all(|p| *p == 0));
    }
    #[test]
    fn session_viewport_is_exact_one_to_one_and_leaves_only_its_measured_chrome() {
        let mut count = 0;
        for y in 0..HEIGHT {
            for x in 0..WIDTH {
                if let Some((sx, sy)) = session_app_sample(x, y) {
                    assert_eq!((sx, sy), (x - 8, y - 20));
                    assert!(sx < 304 && sy < 172);
                    count += 1;
                }
            }
        }
        assert_eq!(count, 304 * 172);
        assert_eq!(session_app_sample(8, 20), Some((0, 0)));
        assert_eq!(session_app_sample(311, 191), Some((303, 171)));
        for (x, y) in [
            (7, 20),
            (8, 19),
            (312, 191),
            (311, 192),
            (usize::MAX, usize::MAX),
        ] {
            assert_eq!(session_app_sample(x, y), None);
        }
    }
    #[test]
    fn every_source_pixel_has_one_distinct_viewport_destination() {
        for sy in 0..APP_VIEW.height {
            for sx in 0..APP_VIEW.width {
                assert_eq!(app_sample(APP_VIEW.x + sx, APP_VIEW.y + sy), Some((sx, sy)));
            }
        }
        assert_eq!(app_sample(20, 54), Some((0, 0)));
        assert_eq!(app_sample(299, 169), Some((279, 115)));
    }
    #[test]
    fn destination_maps_only_inside_the_app_surface_without_touching_chrome() {
        let mut count = 0;
        for y in 0..HEIGHT {
            for x in 0..WIDTH {
                if let Some((sx, sy)) = app_sample(x, y) {
                    assert_eq!((sx, sy), (x - APP_VIEW.x, y - APP_VIEW.y));
                    assert!(sx < APP_VIEW.width && sy < APP_VIEW.height);
                    assert!(APP_VIEW.contains(x, y));
                    count += 1;
                }
            }
        }
        assert_eq!(count, APP_VIEW.width * APP_VIEW.height);
        for (x, y) in [
            (0, 0),
            (19, 54),
            (20, 53),
            (300, 54),
            (20, 170),
            (usize::MAX, usize::MAX),
        ] {
            assert_eq!(app_sample(x, y), None);
        }
    }
}
