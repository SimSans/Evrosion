//! Trusted shell views, with named controls independent of raster coordinates.
//! A rendered file choice is data. Only the separate validated grant owner can
//! turn actual fresh input and a matching selection into an object capability.
use crate::{ACCENT, BACKGROUND, Canvas, Error, HEIGHT, INK, MUTED, PANEL, Pixels, WIDTH};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileChoice {
    Notes,
    Private,
}
impl FileChoice {
    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::Notes => b"Notes.txt",
            Self::Private => b"Private.txt",
        }
    }
    pub const fn next(self) -> Self {
        match self {
            Self::Notes => Self::Private,
            Self::Private => Self::Notes,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    Home,
    AppRunning,
    Picker { selected: FileChoice },
    Opening { selected: FileChoice },
    AppStopped,
}

pub fn render<P: Pixels>(pixels: &mut P, screen: Screen) -> Result<(), Error> {
    if pixels.dimensions() != (WIDTH, HEIGHT) {
        return Err(Error::Geometry);
    }
    let mut c = Canvas::new(pixels);
    c.fill(BACKGROUND)?;
    match screen {
        Screen::Home => {
            c.text(20, 16, b"Evrosion", ACCENT)?;
            c.text(20, 35, b"Your workspace.", INK)?;
            c.text(20, 61, b"Open Hello to begin.", MUTED)?;
            c.rect(20, 83, 280, 36, ACCENT)?;
            c.text(30, 97, b"Open Hello", BACKGROUND)?;
            c.text(20, 178, b"Enter: open Hello", MUTED)?;
        }
        Screen::AppRunning => {
            c.text(20, 16, b"Evrosion", ACCENT)?;
            c.text(20, 36, b"Hello", INK)?;
            c.text(20, 182, b"Esc: launcher", MUTED)?;
        }
        Screen::Picker { selected } => {
            c.text(20, 16, b"Choose a file", ACCENT)?;
            c.text(20, 35, b"For Hello", INK)?;
            c.text(20, 50, b"Read only", MUTED)?;
            for (choice, y) in [(FileChoice::Notes, 68), (FileChoice::Private, 105)] {
                let focused = choice == selected;
                c.rect(20, y, 280, 28, if focused { ACCENT } else { PANEL })?;
                c.text(
                    30,
                    y + 10,
                    choice.label(),
                    if focused { BACKGROUND } else { INK },
                )?;
            }
            c.text(20, 158, b"Enter opens the selected file.", INK)?;
            c.text(20, 177, b"Escape cancels.", MUTED)?;
        }
        Screen::Opening { selected } => {
            c.text(20, 16, b"Opening the file...", ACCENT)?;
            c.text(20, 43, selected.label(), INK)?;
            c.text(20, 64, b"For Hello", MUTED)?;
        }
        Screen::AppStopped => {
            c.text(20, 16, b"Hello closed unexpectedly.", INK)?;
            c.text(20, 51, b"Your workspace is still running.", MUTED)?;
            c.rect(20, 86, 280, 34, ACCENT)?;
            c.text(30, 99, b"Open Hello again", BACKGROUND)?;
            c.text(20, 178, b"Enter: open  Esc: home", MUTED)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::Color;
    use std::{vec, vec::Vec};
    struct Buffer(Vec<Color>);
    impl Pixels for Buffer {
        fn dimensions(&self) -> (usize, usize) {
            (WIDTH, HEIGHT)
        }
        fn write(&mut self, x: usize, y: usize, color: Color) -> Result<(), Error> {
            if x >= WIDTH || y >= HEIGHT {
                return Err(Error::Bounds);
            }
            self.0[y * WIDTH + x] = color;
            Ok(())
        }
    }
    #[test]
    fn every_shell_view_fits_the_owned_surface() {
        let mut pixels = Buffer(vec![BACKGROUND; WIDTH * HEIGHT]);
        for screen in [
            Screen::Home,
            Screen::AppRunning,
            Screen::Picker {
                selected: FileChoice::Notes,
            },
            Screen::Picker {
                selected: FileChoice::Private,
            },
            Screen::Opening {
                selected: FileChoice::Notes,
            },
            Screen::AppStopped,
        ] {
            render(&mut pixels, screen).unwrap();
        }
    }
    #[test]
    fn the_visible_selection_tracks_exactly_one_named_file() {
        let mut pixels = Buffer(vec![BACKGROUND; WIDTH * HEIGHT]);
        render(
            &mut pixels,
            Screen::Picker {
                selected: FileChoice::Notes,
            },
        )
        .unwrap();
        assert_eq!(pixels.0[68 * WIDTH + 20], ACCENT);
        assert_eq!(pixels.0[105 * WIDTH + 20], PANEL);
        render(
            &mut pixels,
            Screen::Picker {
                selected: FileChoice::Private,
            },
        )
        .unwrap();
        assert_eq!(pixels.0[68 * WIDTH + 20], PANEL);
        assert_eq!(pixels.0[105 * WIDTH + 20], ACCENT);
        assert_ne!(FileChoice::Notes.label(), FileChoice::Private.label());
    }
}
