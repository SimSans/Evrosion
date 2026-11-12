//! Bounded software surfaces. Pixels and layout carry no object authority.
//! Hardware storage stays at the separately scoped userspace boundary.
#![no_std]
#![deny(unsafe_code)]
pub mod composition;
pub mod native;
pub mod shell;
pub const WIDTH: usize = 320;
pub const HEIGHT: usize = 200;
pub const HEADER_BYTES: usize = 64;
pub const PIXEL_BYTES: usize = WIDTH * HEIGHT * 4;
pub const MAPPED_BYTES: usize = 63 * 4096;
pub const FRAME_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Header,
    Geometry,
    Counter,
    Bounds,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SurfaceHeader {
    pub sequence: u64,
}
impl SurfaceHeader {
    pub fn encode(self) -> Result<[u8; HEADER_BYTES], Error> {
        if self.sequence == 0 || self.sequence == u64::MAX {
            return Err(Error::Counter);
        }
        let mut b = [0; HEADER_BYTES];
        b[..8].copy_from_slice(b"EVSURF01");
        b[8..10].copy_from_slice(&FRAME_VERSION.to_le_bytes());
        b[10..12].copy_from_slice(&(HEADER_BYTES as u16).to_le_bytes());
        b[12..14].copy_from_slice(&(WIDTH as u16).to_le_bytes());
        b[14..16].copy_from_slice(&(HEIGHT as u16).to_le_bytes());
        b[16..20].copy_from_slice(&((WIDTH * 4) as u32).to_le_bytes());
        b[20..24].copy_from_slice(&1u32.to_le_bytes()); // XRGB8888, no native-endian ambiguity.
        b[24..32].copy_from_slice(&self.sequence.to_le_bytes());
        Ok(b)
    }
    pub fn parse(b: &[u8; HEADER_BYTES]) -> Result<Self, Error> {
        if &b[..8] != b"EVSURF01"
            || u16::from_le_bytes(b[8..10].try_into().unwrap()) != FRAME_VERSION
            || u16::from_le_bytes(b[10..12].try_into().unwrap()) != HEADER_BYTES as u16
            || b[32..].iter().any(|v| *v != 0)
        {
            return Err(Error::Header);
        }
        if u16::from_le_bytes(b[12..14].try_into().unwrap()) != WIDTH as u16
            || u16::from_le_bytes(b[14..16].try_into().unwrap()) != HEIGHT as u16
            || u32::from_le_bytes(b[16..20].try_into().unwrap()) != (WIDTH * 4) as u32
            || u32::from_le_bytes(b[20..24].try_into().unwrap()) != 1
        {
            return Err(Error::Geometry);
        }
        let h = Self {
            sequence: u64::from_le_bytes(b[24..32].try_into().unwrap()),
        };
        h.encode()?;
        Ok(h)
    }
}

/// Versioned scalar Present protocol. The selected endpoint determines the
/// surface and recipient; the serial itself grants no object access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Present(pub u32);
impl Present {
    pub fn request(self) -> Result<[u8; 8], Error> {
        self.encode(*b"EVP1")
    }
    pub fn reply(self) -> Result<[u8; 8], Error> {
        self.encode(*b"EVR1")
    }
    fn encode(self, tag: [u8; 4]) -> Result<[u8; 8], Error> {
        if self.0 == 0 || self.0 == u32::MAX {
            return Err(Error::Counter);
        }
        let mut b = [0; 8];
        b[..4].copy_from_slice(&tag);
        b[4..].copy_from_slice(&self.0.to_le_bytes());
        Ok(b)
    }
    pub fn parse_request(b: [u8; 8]) -> Result<Self, Error> {
        Self::decode(b, *b"EVP1")
    }
    pub fn parse_reply(b: [u8; 8]) -> Result<Self, Error> {
        Self::decode(b, *b"EVR1")
    }
    fn decode(b: [u8; 8], tag: [u8; 4]) -> Result<Self, Error> {
        if b[..4] != tag {
            return Err(Error::Header);
        }
        let p = Self(u32::from_le_bytes(b[4..].try_into().unwrap()));
        p.encode(tag)?;
        Ok(p)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Color(pub u32);
impl Color {
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self(((r as u32) << 16) | ((g as u32) << 8) | (b as u32))
    }
    pub fn components(self) -> [u8; 3] {
        [(self.0 >> 16) as u8, (self.0 >> 8) as u8, self.0 as u8]
    }
}
pub const BACKGROUND: Color = Color::rgb(18, 24, 35);
pub const PANEL: Color = Color::rgb(29, 39, 55);
pub const INK: Color = Color::rgb(231, 238, 246);
pub const MUTED: Color = Color::rgb(153, 173, 194);
pub const ACCENT: Color = Color::rgb(106, 222, 194);
pub const DANGER: Color = Color::rgb(246, 133, 137);

/// A sink describes its exact extent and safely rejects out-of-range pixels.
/// The hardware sink uses volatile stores; no shared Rust reference crosses IPC.
pub trait Pixels {
    fn dimensions(&self) -> (usize, usize);
    fn write(&mut self, x: usize, y: usize, color: Color) -> Result<(), Error>;
}
pub struct Canvas<'a, P: Pixels> {
    sink: &'a mut P,
}
impl<'a, P: Pixels> Canvas<'a, P> {
    pub fn new(sink: &'a mut P) -> Self {
        Self { sink }
    }
    pub fn fill(&mut self, color: Color) -> Result<(), Error> {
        let (w, h) = self.sink.dimensions();
        self.rect(0, 0, w, h, color)
    }
    pub fn rect(
        &mut self,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
        color: Color,
    ) -> Result<(), Error> {
        let (width, height) = self.sink.dimensions();
        let right = x.checked_add(w).ok_or(Error::Bounds)?;
        let bottom = y.checked_add(h).ok_or(Error::Bounds)?;
        if right > width || bottom > height {
            return Err(Error::Bounds);
        }
        for row in y..bottom {
            for col in x..right {
                self.sink.write(col, row, color)?;
            }
        }
        Ok(())
    }
    pub fn text(&mut self, x: usize, y: usize, text: &[u8], color: Color) -> Result<(), Error> {
        let w = text.len().checked_mul(6).ok_or(Error::Bounds)?;
        let (width, height) = self.sink.dimensions();
        if x.checked_add(w).is_none_or(|v| v > width) || y.checked_add(7).is_none_or(|v| v > height)
        {
            return Err(Error::Bounds);
        }
        for (index, character) in text.iter().copied().enumerate() {
            let glyph = glyph(character);
            for (row, bits) in glyph.into_iter().enumerate() {
                for col in 0..5 {
                    if bits & (1 << (4 - col)) != 0 {
                        self.sink.write(x + index * 6 + col, y + row, color)?;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Semantic controls stay independent of raster coordinates so input routing,
/// keyboard focus and later accessibility are not coupled to pixel inspection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelloControl {
    OpenFile,
    CrashMe,
}
impl HelloControl {
    pub fn label(self) -> &'static [u8] {
        match self {
            Self::OpenFile => b"Open File",
            Self::CrashMe => b"Crash Me",
        }
    }
    pub fn next(self) -> Self {
        match self {
            Self::OpenFile => Self::CrashMe,
            Self::CrashMe => Self::OpenFile,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HelloView<'a> {
    pub focus: HelloControl,
    pub content: Option<&'a [u8]>,
    pub incarnation: u64,
}
pub fn hello<P: Pixels>(pixels: &mut P, view: HelloView<'_>) -> Result<(), Error> {
    if pixels.dimensions() != (WIDTH, HEIGHT) {
        return Err(Error::Geometry);
    }
    let mut c = Canvas::new(pixels);
    c.fill(PANEL)?;
    c.text(20, 24, b"Hello from Evrosion.", INK)?;
    c.text(20, 42, b"A native isolated application", MUTED)?;
    for (control, x) in [(HelloControl::OpenFile, 20), (HelloControl::CrashMe, 166)] {
        let focused = view.focus == control;
        c.rect(x, 73, 134, 27, if focused { ACCENT } else { BACKGROUND })?;
        c.text(
            x + 10,
            83,
            control.label(),
            if focused { BACKGROUND } else { INK },
        )?;
    }
    c.text(20, 119, b"File access:", MUTED)?;
    match view.content {
        None => c.text(20, 135, b"Choose Open File to request access.", INK)?,
        Some(content) => {
            c.text(20, 135, b"One selected object granted", ACCENT)?;
            // One bounded text row, no terminal control or markup execution.
            let mut line = [b' '; 46];
            for (dst, src) in line.iter_mut().zip(content.iter().copied()) {
                *dst = if src.is_ascii_graphic() || src == b' ' {
                    src
                } else {
                    b'?'
                };
            }
            c.text(20, 152, &line, INK)?;
        }
    }
    c.text(20, 178, b"Tab: focus   Enter: choose", MUTED)?;
    Ok(())
}

/// Initial desktop Hello layout inside the fixed 280×116 App viewport.
///
/// The complete surface remains 320×200. Its top-left viewport is composed at
/// one source pixel per logical desktop pixel, preserving all seven glyph rows.
/// This bounded Internal layout trades spacious component-demo spacing for
/// readable controls/content; it does not resize the surface or change input
/// control identities. The remaining source pixels are deterministic panel fill.
pub fn hello_window<P: Pixels>(pixels: &mut P, view: HelloView<'_>) -> Result<(), Error> {
    if pixels.dimensions() != (WIDTH, HEIGHT) {
        return Err(Error::Geometry);
    }
    let mut c = Canvas::new(pixels);
    c.fill(PANEL)?;
    c.text(8, 8, b"Hello from Evrosion.", INK)?;
    c.text(8, 21, b"A native isolated application", MUTED)?;
    for (control, x) in [(HelloControl::OpenFile, 8), (HelloControl::CrashMe, 144)] {
        let focused = view.focus == control;
        c.rect(x, 36, 128, 18, if focused { ACCENT } else { BACKGROUND })?;
        c.text(
            x + 9,
            42,
            control.label(),
            if focused { BACKGROUND } else { INK },
        )?;
    }
    match view.content {
        None => {
            c.text(8, 64, b"File access: not yet granted", MUTED)?;
            c.text(8, 80, b"Choose Open File to request access.", INK)?;
        }
        Some(content) => {
            c.text(8, 64, b"Read-only access to one selected file", ACCENT)?;
            // One bounded row inside the viewport, without terminal controls,
            // markup, horizontal scaling or vertical glyph-row loss.
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

// Original compact 5x7 bitmap alphabet; lowercase shares uppercase glyphs.
fn glyph(c: u8) -> [u8; 7] {
    match c.to_ascii_uppercase() {
        b'A' => [14, 17, 17, 31, 17, 17, 17],
        b'B' => [30, 17, 17, 30, 17, 17, 30],
        b'C' => [14, 17, 16, 16, 16, 17, 14],
        b'D' => [30, 17, 17, 17, 17, 17, 30],
        b'E' => [31, 16, 16, 30, 16, 16, 31],
        b'F' => [31, 16, 16, 30, 16, 16, 16],
        b'G' => [14, 17, 16, 23, 17, 17, 15],
        b'H' => [17, 17, 17, 31, 17, 17, 17],
        b'I' => [14, 4, 4, 4, 4, 4, 14],
        b'J' => [7, 2, 2, 2, 18, 18, 12],
        b'K' => [17, 18, 20, 24, 20, 18, 17],
        b'L' => [16, 16, 16, 16, 16, 16, 31],
        b'M' => [17, 27, 21, 21, 17, 17, 17],
        b'N' => [17, 25, 21, 19, 17, 17, 17],
        b'O' => [14, 17, 17, 17, 17, 17, 14],
        b'P' => [30, 17, 17, 30, 16, 16, 16],
        b'Q' => [14, 17, 17, 17, 21, 18, 13],
        b'R' => [30, 17, 17, 30, 20, 18, 17],
        b'S' => [15, 16, 16, 14, 1, 1, 30],
        b'T' => [31, 4, 4, 4, 4, 4, 4],
        b'U' => [17, 17, 17, 17, 17, 17, 14],
        b'V' => [17, 17, 17, 17, 17, 10, 4],
        b'W' => [17, 17, 17, 21, 21, 21, 10],
        b'X' => [17, 17, 10, 4, 10, 17, 17],
        b'Y' => [17, 17, 10, 4, 4, 4, 4],
        b'Z' => [31, 1, 2, 4, 8, 16, 31],
        b'0' => [14, 17, 19, 21, 25, 17, 14],
        b'1' => [4, 12, 4, 4, 4, 4, 14],
        b'2' => [14, 17, 1, 2, 4, 8, 31],
        b'3' => [30, 1, 1, 14, 1, 1, 30],
        b'4' => [2, 6, 10, 18, 31, 2, 2],
        b'5' => [31, 16, 16, 30, 1, 1, 30],
        b'6' => [14, 16, 16, 30, 17, 17, 14],
        b'7' => [31, 1, 2, 4, 8, 8, 8],
        b'8' => [14, 17, 17, 14, 17, 17, 14],
        b'9' => [14, 17, 17, 15, 1, 1, 14],
        b'.' => [0, 0, 0, 0, 0, 12, 12],
        b':' => [0, 12, 12, 0, 12, 12, 0],
        b'-' => [0, 0, 0, 31, 0, 0, 0],
        b'/' => [1, 2, 2, 4, 8, 8, 16],
        b'[' => [14, 8, 8, 8, 8, 8, 14],
        b']' => [14, 2, 2, 2, 2, 2, 14],
        b' ' => [0; 7],
        _ => [14, 17, 1, 2, 4, 0, 4],
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    struct Buffer {
        w: usize,
        h: usize,
        bytes: std::vec::Vec<Color>,
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
            self.bytes[y * self.w + x] = color;
            self.writes += 1;
            Ok(())
        }
    }
    #[test]
    fn compact_window_preserves_glyph_rows_and_named_control_focus() {
        let mut b = Buffer {
            w: WIDTH,
            h: HEIGHT,
            bytes: vec![BACKGROUND; WIDTH * HEIGHT],
            writes: 0,
        };
        for focus in [HelloControl::OpenFile, HelloControl::CrashMe] {
            hello_window(
                &mut b,
                HelloView {
                    focus,
                    content: Some(b"Hello"),
                    incarnation: 1,
                },
            )
            .unwrap();
            // H is a full seven-row glyph. Both title and file content retain
            // the exact 5×7 bitmap instead of nearest-neighbor compression.
            let h = [17u8, 17, 17, 31, 17, 17, 17];
            for y in [8, 80] {
                for (row, bits) in h.iter().copied().enumerate() {
                    for col in 0..5 {
                        let expected = if bits & (1 << (4 - col)) != 0 {
                            INK
                        } else {
                            PANEL
                        };
                        assert_eq!(b.bytes[(y + row) * WIDTH + 8 + col], expected);
                    }
                }
            }
            for (control, x) in [(HelloControl::OpenFile, 8), (HelloControl::CrashMe, 144)] {
                let expected = if focus == control { ACCENT } else { BACKGROUND };
                // All eighteen button rows survive inside the viewport.
                for y in 36..54 {
                    assert_eq!(b.bytes[y * WIDTH + x], expected);
                }
            }
        }
    }
    #[test]
    fn compact_window_content_is_bounded_sanitized_and_clears_unused_surface() {
        let mut b = Buffer {
            w: WIDTH,
            h: HEIGHT,
            bytes: vec![DANGER; WIDTH * HEIGHT],
            writes: 0,
        };
        for content in [None, Some(&[b'A'; 224][..]), Some(&b"safe\x1b\xff"[..])] {
            hello_window(
                &mut b,
                HelloView {
                    focus: HelloControl::OpenFile,
                    content,
                    incarnation: 1,
                },
            )
            .unwrap();
            for y in 0..HEIGHT {
                for x in 0..WIDTH {
                    if x >= composition::APP_VIEW.width || y >= composition::APP_VIEW.height {
                        assert_eq!(b.bytes[y * WIDTH + x], PANEL);
                    }
                }
            }
        }
        // The nonprinting bytes use the ordinary question-mark glyph, never
        // escape/control interpretation. Both glyphs remain wholly visible.
        for index in [4, 5] {
            for (row, bits) in glyph(b'?').into_iter().enumerate() {
                for col in 0..5 {
                    let expected = if bits & (1 << (4 - col)) != 0 {
                        INK
                    } else {
                        PANEL
                    };
                    assert_eq!(b.bytes[(80 + row) * WIDTH + 8 + index * 6 + col], expected);
                }
            }
        }
        let mut wrong = Buffer {
            w: 280,
            h: 116,
            bytes: vec![DANGER; 280 * 116],
            writes: 0,
        };
        assert_eq!(
            hello_window(
                &mut wrong,
                HelloView {
                    focus: HelloControl::OpenFile,
                    content: None,
                    incarnation: 1
                }
            ),
            Err(Error::Geometry)
        );
        assert_eq!(wrong.writes, 0);
    }
    #[test]
    fn present_request_and_release_are_distinct_and_never_wrap() {
        let frame = Present(9);
        assert_eq!(Present::parse_request(frame.request().unwrap()), Ok(frame));
        assert_eq!(Present::parse_reply(frame.reply().unwrap()), Ok(frame));
        assert_eq!(
            Present::parse_request(frame.reply().unwrap()),
            Err(Error::Header)
        );
        assert_eq!(
            Present::parse_reply(frame.request().unwrap()),
            Err(Error::Header)
        );
        assert!(Present(0).request().is_err());
        assert!(Present(u32::MAX).request().is_err());
        assert!(Present::parse_request(*b"EVP1\0\0\0\0").is_err());
    }
    #[test]
    fn hostile_geometry_refuses_before_writing() {
        let mut b = Buffer {
            w: 10,
            h: 10,
            bytes: vec![BACKGROUND; 100],
            writes: 0,
        };
        let mut c = Canvas::new(&mut b);
        assert_eq!(c.rect(usize::MAX, 0, 2, 1, INK), Err(Error::Bounds));
        assert_eq!(c.rect(9, 9, 2, 2, INK), Err(Error::Bounds));
        assert_eq!(c.text(0, 4, b"AB", INK), Err(Error::Bounds));
        assert_eq!(b.writes, 0);
    }
    #[test]
    fn header_checks_reserved_bytes_and_exact_geometry() {
        let h = SurfaceHeader { sequence: 17 };
        let b = h.encode().unwrap();
        assert_eq!(SurfaceHeader::parse(&b), Ok(h));
        for index in [0, 8, 10, 12, 14, 16, 20, 32, 63] {
            let mut wrong = b;
            wrong[index] ^= 1;
            assert!(SurfaceHeader::parse(&wrong).is_err());
        }
        assert!(SurfaceHeader { sequence: 0 }.encode().is_err());
        assert!(SurfaceHeader { sequence: u64::MAX }.encode().is_err());
        const { assert!(HEADER_BYTES + PIXEL_BYTES <= MAPPED_BYTES) };
    }
    #[test]
    fn visible_focus_moves_between_named_controls_and_sanitizes_content() {
        let mut b = Buffer {
            w: WIDTH,
            h: HEIGHT,
            bytes: vec![BACKGROUND; WIDTH * HEIGHT],
            writes: 0,
        };
        hello(
            &mut b,
            HelloView {
                focus: HelloControl::OpenFile,
                content: None,
                incarnation: 1,
            },
        )
        .unwrap();
        assert_eq!(b.bytes[73 * WIDTH + 20], ACCENT);
        assert_eq!(b.bytes[73 * WIDTH + 166], BACKGROUND);
        hello(
            &mut b,
            HelloView {
                focus: HelloControl::CrashMe,
                content: Some(b"safe\x1b[31m"),
                incarnation: 2,
            },
        )
        .unwrap();
        assert_eq!(b.bytes[73 * WIDTH + 20], BACKGROUND);
        assert_eq!(b.bytes[73 * WIDTH + 166], ACCENT);
        assert_eq!(HelloControl::OpenFile.next(), HelloControl::CrashMe);
    }
}
