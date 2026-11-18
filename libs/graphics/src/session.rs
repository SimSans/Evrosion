// SPDX-License-Identifier: Apache-2.0
//! Bounded manual-session note view. Pixels confer no file or save authority.
use crate::{
    ACCENT, BACKGROUND, Canvas, Error, HEIGHT, INK, MUTED, PANEL, Pixels, WIDTH, native::Build,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Focus {
    Note,
    Save,
    OpenFile,
    CrashMe,
}
impl Focus {
    pub fn next(self, reverse: bool) -> Self {
        const ITEMS: [Focus; 4] = [Focus::Note, Focus::Save, Focus::OpenFile, Focus::CrashMe];
        let index = ITEMS.iter().position(|v| *v == self).unwrap();
        ITEMS[(index + if reverse { 3 } else { 1 }) % 4]
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveState {
    Loading,
    Saved,
    Unsaved,
    Saving,
    Unavailable,
    Busy,
}
pub struct View<'a> {
    pub build: Build,
    pub focus: Focus,
    pub note: &'a [u8],
    pub state: SaveState,
    pub file: Option<&'a [u8]>,
}
pub fn render<P: Pixels>(pixels: &mut P, view: View<'_>) -> Result<(), Error> {
    if pixels.dimensions() != (WIDTH, HEIGHT) {
        return Err(Error::Geometry);
    }
    if view.note.len() > 128 || view.note.iter().any(|b| !(0x20..=0x7e).contains(b)) {
        return Err(Error::Text);
    }
    let mut c = Canvas::new(pixels);
    c.fill(PANEL)?;
    c.text(
        8,
        8,
        if view.build == Build::A {
            b"Hello A"
        } else {
            b"Hello B"
        },
        INK,
    )?;
    for (focus, x, label) in [
        (Focus::OpenFile, 8, b"Open File".as_slice()),
        (Focus::CrashMe, 160, b"Crash Me".as_slice()),
    ] {
        let selected = view.focus == focus;
        c.rect(x, 28, 136, 20, if selected { ACCENT } else { BACKGROUND })?;
        c.text(x + 9, 35, label, if selected { BACKGROUND } else { INK })?;
    }
    c.text(8, 59, b"Your note", INK)?;
    c.rect(
        8,
        72,
        288,
        42,
        if view.focus == Focus::Note {
            ACCENT
        } else {
            MUTED
        },
    )?;
    c.rect(10, 74, 284, 38, BACKGROUND)?;
    for (row, line) in view.note.chunks(46).enumerate() {
        c.text_exact(14, 79 + row * 10, line, INK)?;
    }
    let selected = view.focus == Focus::Save;
    c.rect(8, 122, 80, 20, if selected { ACCENT } else { BACKGROUND })?;
    c.text(32, 129, b"Save", if selected { BACKGROUND } else { INK })?;
    c.text(
        100,
        129,
        match view.state {
            SaveState::Loading => b"Loading...",
            SaveState::Saved => b"Saved",
            SaveState::Unsaved => b"Unsaved",
            SaveState::Saving => b"Saving...",
            SaveState::Unavailable => b"Save unavailable",
            SaveState::Busy => b"Storage busy. Try Save again.",
        },
        if view.state == SaveState::Saved {
            ACCENT
        } else {
            INK
        },
    )?;
    c.text(
        8,
        151,
        if view.file.is_some() {
            b"Selected file (read only)"
        } else {
            b"File access not yet granted"
        },
        MUTED,
    )?;
    if let Some(file) = view.file {
        let mut line = [b' '; 46];
        for (a, b) in line.iter_mut().zip(file.iter().copied()) {
            *a = if (0x20..=0x7e).contains(&b) { b } else { b'?' };
        }
        c.text_exact(8, 164, &line, INK)?;
    }
    Ok(())
}
/// Coordinates in the304×172 session App viewport, after trusted composition.
pub fn hit_test(x: usize, y: usize) -> Option<Focus> {
    use crate::composition::Rect;
    [
        (
            Focus::OpenFile,
            Rect {
                x: 8,
                y: 28,
                width: 136,
                height: 20,
            },
        ),
        (
            Focus::CrashMe,
            Rect {
                x: 160,
                y: 28,
                width: 136,
                height: 20,
            },
        ),
        (
            Focus::Note,
            Rect {
                x: 8,
                y: 72,
                width: 288,
                height: 42,
            },
        ),
        (
            Focus::Save,
            Rect {
                x: 8,
                y: 122,
                width: 80,
                height: 20,
            },
        ),
    ]
    .into_iter()
    .find_map(|(focus, r)| r.contains(x, y).then_some(focus))
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::Color;
    struct Buffer {
        pixels: std::vec::Vec<Color>,
        writes: usize,
    }
    impl Pixels for Buffer {
        fn dimensions(&self) -> (usize, usize) {
            (WIDTH, HEIGHT)
        }
        fn write(&mut self, x: usize, y: usize, color: Color) -> Result<(), Error> {
            if x >= WIDTH || y >= HEIGHT {
                return Err(Error::Bounds);
            }
            self.pixels[y * WIDTH + x] = color;
            self.writes += 1;
            Ok(())
        }
    }
    #[test]
    fn case_and_save_state_are_visible_and_oversized_or_control_text_refuses_before_paint() {
        let mut b = Buffer {
            pixels: std::vec![BACKGROUND;WIDTH*HEIGHT],
            writes: 0,
        };
        let view = |note, state| View {
            build: Build::A,
            focus: Focus::Note,
            note,
            state,
            file: None,
        };
        render(&mut b, view(b"aA_!", SaveState::Unsaved)).unwrap();
        let first = b.pixels.clone();
        render(&mut b, view(b"AA_!", SaveState::Saved)).unwrap();
        assert_ne!(
            &first[79 * WIDTH..86 * WIDTH],
            &b.pixels[79 * WIDTH..86 * WIDTH]
        );
        assert_ne!(
            &first[129 * WIDTH..136 * WIDTH],
            &b.pixels[129 * WIDTH..136 * WIDTH]
        );
        let before = b.writes;
        for invalid in [b"\0".as_slice(), b"\n", &[b'a'; 129]] {
            assert_eq!(
                render(&mut b, view(invalid, SaveState::Saved)),
                Err(Error::Text)
            );
        }
        assert_eq!(before, b.writes);
        render(&mut b, view(&[b'~'; 128], SaveState::Saving)).unwrap();
    }
}
