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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HEIGHT, WIDTH};
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
