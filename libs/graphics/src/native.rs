//! Native lifecycle Hello view. The saved value is supplied by the app ONLY
//! after an actual authenticated Root data reply; rendering grants no authority.
use crate::{
    ACCENT, BACKGROUND, Canvas, Error, HEIGHT, HelloControl, HelloView, INK, MUTED, PANEL, Pixels,
    WIDTH,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Build {
    A,
    B,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct View<'a> {
    pub hello: HelloView<'a>,
    pub build: Build,
    pub saved_value: u32,
}
pub fn render<P: Pixels>(pixels: &mut P, view: View<'_>) -> Result<(), Error> {
    if pixels.dimensions() != (WIDTH, HEIGHT) {
        return Err(Error::Geometry);
    }
    let mut c = Canvas::new(pixels);
    c.fill(PANEL)?;
    c.text(
        8,
        8,
        match view.build {
            Build::A => b"Hello A",
            Build::B => b"Hello B",
        },
        INK,
    )?;
    let mut line = [b' '; 23];
    let prefix = b"Saved value: ";
    line[..prefix.len()].copy_from_slice(prefix);
    let mut digits = [b'0'; 10];
    let mut value = view.saved_value;
    let mut first = 9;
    loop {
        digits[first] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
        first -= 1;
    }
    line[prefix.len()..prefix.len() + 10 - first].copy_from_slice(&digits[first..]);
    c.text(8, 21, &line[..prefix.len() + 10 - first], ACCENT)?;
    for (control, x) in [(HelloControl::OpenFile, 8), (HelloControl::CrashMe, 144)] {
        let focused = view.hello.focus == control;
        c.rect(x, 36, 128, 18, if focused { ACCENT } else { BACKGROUND })?;
        c.text(
            x + 9,
            42,
            control.label(),
            if focused { BACKGROUND } else { INK },
        )?;
    }
    match view.hello.content {
        None => {
            c.text(8, 64, b"File access: not yet granted", MUTED)?;
            c.text(8, 80, b"Choose Open File to request access.", INK)?;
        }
        Some(content) => {
            c.text(8, 64, b"Read-only selected file", ACCENT)?;
            let mut line = [b' '; 43];
            for (dst, src) in line.iter_mut().zip(content.iter().copied()) {
                *dst = if src.is_ascii_graphic() || src == b' ' {
                    src
                } else {
                    b'?'
                };
            }
            c.text(8, 80, &line, INK)?;
        }
    }
    c.text(8, 101, b"Tab: focus   Enter: choose", MUTED)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::{Color, composition::APP_VIEW};
    use std::{vec, vec::Vec};
    struct Buffer {
        w: usize,
        h: usize,
        pixels: Vec<Color>,
        writes: usize,
    }
    impl Pixels for Buffer {
        fn dimensions(&self) -> (usize, usize) {
            (self.w, self.h)
        }
        fn write(&mut self, x: usize, y: usize, color: Color) -> Result<(), Error> {
            if x >= self.w || y >= self.h {
                return Err(Error::Bounds);
            }
            self.pixels[y * self.w + x] = color;
            self.writes += 1;
            Ok(())
        }
    }
    fn view(value: u32) -> View<'static> {
        View {
            hello: HelloView {
                focus: HelloControl::OpenFile,
                content: Some(b"Hello"),
                incarnation: 1,
            },
            build: Build::A,
            saved_value: value,
        }
    }
    #[test]
    fn native_saved_value_build_focus_and_content_are_visible_with_full_glyph_rows() {
        let mut b = Buffer {
            w: WIDTH,
            h: HEIGHT,
            pixels: vec![BACKGROUND; WIDTH * HEIGHT],
            writes: 0,
        };
        render(&mut b, view(1001)).unwrap();
        let initial = b.pixels.clone();
        // Initial H and selected-content H retain each of their seven bitmap rows.
        for y in [8, 80] {
            for (row, bits) in [17u8, 17, 17, 31, 17, 17, 17].into_iter().enumerate() {
                for col in 0..5 {
                    assert_eq!(
                        b.pixels[(y + row) * WIDTH + 8 + col],
                        if bits & (1 << (4 - col)) != 0 {
                            INK
                        } else {
                            PANEL
                        }
                    );
                }
            }
        }
        render(&mut b, view(2026)).unwrap();
        assert_ne!(
            &initial[21 * WIDTH..28 * WIDTH],
            &b.pixels[21 * WIDTH..28 * WIDTH]
        );
        let mut changed = view(2026);
        changed.build = Build::B;
        changed.hello.focus = HelloControl::CrashMe;
        render(&mut b, changed).unwrap();
        assert_ne!(
            &initial[8 * WIDTH..15 * WIDTH],
            &b.pixels[8 * WIDTH..15 * WIDTH]
        );
        assert_eq!(b.pixels[36 * WIDTH + 144], ACCENT);
    }
    #[test]
    fn saved_decimal_1001_and_2026_show_every_expected_digit_row() {
        let mut buffer = Buffer {
            w: WIDTH,
            h: HEIGHT,
            pixels: vec![BACKGROUND; WIDTH * HEIGHT],
            writes: 0,
        };
        let one = [4u8, 12, 4, 4, 4, 4, 14];
        let zero = [14u8, 17, 19, 21, 25, 17, 14];
        let two = [14u8, 17, 1, 2, 4, 8, 31];
        let six = [14u8, 16, 16, 30, 17, 17, 14];
        for (value, digits) in [
            (1001, [one, zero, zero, one]),
            (2026, [two, zero, two, six]),
        ] {
            render(&mut buffer, view(value)).unwrap();
            for (index, glyph) in digits.into_iter().enumerate() {
                for (row, bits) in glyph.into_iter().enumerate() {
                    for col in 0..5 {
                        assert_eq!(
                            buffer.pixels[(21 + row) * WIDTH + 86 + index * 6 + col],
                            if bits & (1 << (4 - col)) != 0 {
                                ACCENT
                            } else {
                                PANEL
                            }
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn all_u32_values_and_long_content_fit_exact_viewport_and_geometry_refuses_before_write() {
        let mut b = Buffer {
            w: WIDTH,
            h: HEIGHT,
            pixels: vec![BACKGROUND; WIDTH * HEIGHT],
            writes: 0,
        };
        for value in [0, 1, 1001, 2026, u32::MAX] {
            let mut v = view(value);
            v.hello.content = Some(&[b'A'; 224]);
            render(&mut b, v).unwrap();
            for y in 0..HEIGHT {
                for x in 0..WIDTH {
                    if x >= APP_VIEW.width || y >= APP_VIEW.height {
                        assert_eq!(b.pixels[y * WIDTH + x], PANEL);
                    }
                }
            }
        }
        let mut wrong = Buffer {
            w: 280,
            h: 116,
            pixels: vec![BACKGROUND; 280 * 116],
            writes: 0,
        };
        assert_eq!(render(&mut wrong, view(1)), Err(Error::Geometry));
        assert_eq!(wrong.writes, 0);
    }
}
