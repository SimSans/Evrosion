//! Trusted shell views, with named controls independent of raster coordinates.
//! A rendered file choice is data. Only the separate validated grant owner can
//! turn actual fresh input and a matching selection into an object capability.
use crate::composition::Rect;
use crate::{ACCENT, BACKGROUND, Canvas, Error, HEIGHT, INK, MUTED, PANEL, Pixels, WIDTH};
pub const HOME_LAUNCH: Rect = Rect {
    x: 20,
    y: 83,
    width: 280,
    height: 36,
};
pub const STOPPED_LAUNCH: Rect = Rect {
    x: 20,
    y: 86,
    width: 280,
    height: 34,
};
pub const NOTES_CHOICE: Rect = Rect {
    x: 20,
    y: 68,
    width: 280,
    height: 28,
};
pub const PRIVATE_CHOICE: Rect = Rect {
    x: 20,
    y: 105,
    width: 280,
    height: 28,
};
pub const PICKER_OPEN: Rect = Rect {
    x: 20,
    y: 145,
    width: 140,
    height: 24,
};
pub const PICKER_CANCEL: Rect = Rect {
    x: 180,
    y: 145,
    width: 120,
    height: 24,
};
pub const SESSION_HOME: Rect = Rect {
    x: 4,
    y: 0,
    width: 112,
    height: 18,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hit {
    Launch,
    Choice(FileChoice),
    Open,
    Cancel,
    Home,
}
pub fn hit_test(screen: Screen, x: usize, y: usize) -> Option<Hit> {
    match screen {
        Screen::Home if HOME_LAUNCH.contains(x, y) => Some(Hit::Launch),
        Screen::AppStopped if STOPPED_LAUNCH.contains(x, y) => Some(Hit::Launch),
        Screen::AppRunning if SESSION_HOME.contains(x, y) => Some(Hit::Home),
        Screen::Picker { .. } if NOTES_CHOICE.contains(x, y) => {
            Some(Hit::Choice(FileChoice::Notes))
        }
        Screen::Picker { .. } if PRIVATE_CHOICE.contains(x, y) => {
            Some(Hit::Choice(FileChoice::Private))
        }
        Screen::Picker { .. } if PICKER_OPEN.contains(x, y) => Some(Hit::Open),
        Screen::Picker { .. } if PICKER_CANCEL.contains(x, y) => Some(Hit::Cancel),
        _ => None,
    }
}

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
    Picker {
        selected: FileChoice,
    },
    Opening {
        selected: FileChoice,
    },
    AppStopped,
    #[cfg(feature = "owner-ui")]
    Connection(crate::connection::View),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryNotice {
    Busy,
    Degraded,
}

/// Trusted chrome only. This status is never an acknowledgement, input proof,
/// permission decision or a sample of a runnable App surface.
pub fn delivery_notice<P: Pixels>(pixels: &mut P, notice: DeliveryNotice) -> Result<(), Error> {
    if pixels.dimensions() != (WIDTH, HEIGHT) {
        return Err(Error::Geometry);
    }
    let mut canvas = Canvas::new(pixels);
    canvas.rect(0, 193, WIDTH, 7, BACKGROUND)?;
    canvas.text(
        4,
        193,
        match notice {
            DeliveryNotice::Busy => b"Input paused. Please wait.".as_slice(),
            DeliveryNotice::Degraded => b"Delivery stopped. Esc: return home".as_slice(),
        },
        MUTED,
    )
}

pub fn render<P: Pixels>(pixels: &mut P, screen: Screen) -> Result<(), Error> {
    if pixels.dimensions() != (WIDTH, HEIGHT) {
        return Err(Error::Geometry);
    }
    #[cfg(feature = "owner-ui")]
    if let Screen::Connection(view) = screen {
        return crate::connection::render(pixels, view);
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
        #[cfg(feature = "owner-ui")]
        Screen::Connection(_) => unreachable!(),
    }
    Ok(())
}

/// Explicit session chrome leaves the measured304x172 App viewport intact.
/// Legacy renderer/corpus remain unchanged; hit rectangles are shared policy.
pub fn render_session<P: Pixels>(pixels: &mut P, screen: Screen) -> Result<(), Error> {
    if screen == Screen::AppRunning {
        if pixels.dimensions() != (WIDTH, HEIGHT) {
            return Err(Error::Geometry);
        }
        let mut c = Canvas::new(pixels);
        c.fill(BACKGROUND)?;
        c.text(4, 6, b"Evrosion", ACCENT)?;
        c.text(164, 6, b"Hello", INK)?;
        c.text(8, 193, b"Esc: launcher", MUTED)?;
        return Ok(());
    }
    render(pixels, screen)?;
    if matches!(screen, Screen::Picker { .. }) {
        let mut c = Canvas::new(pixels);
        c.rect(0, 145, WIDTH, HEIGHT - 145, BACKGROUND)?;
        for (rect, label) in [
            (PICKER_OPEN, b"Open selected".as_slice()),
            (PICKER_CANCEL, b"Cancel".as_slice()),
        ] {
            c.rect(rect.x, rect.y, rect.width, rect.height, ACCENT)?;
            c.text(rect.x + 8, rect.y + 8, label, BACKGROUND)?;
        }
        c.text(20, 177, b"Enter opens. Escape cancels.", MUTED)?;
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
    #[test]
    fn delivery_feedback_changes_only_trusted_footer_and_preserves_app_view_and_widgets() {
        for screen in [
            Screen::AppRunning,
            Screen::Picker {
                selected: FileChoice::Notes,
            },
            Screen::Home,
        ] {
            let mut pixels = Buffer(vec![BACKGROUND; WIDTH * HEIGHT]);
            render_session(&mut pixels, screen).unwrap();
            let before = pixels.0.clone();
            for notice in [DeliveryNotice::Busy, DeliveryNotice::Degraded] {
                delivery_notice(&mut pixels, notice).unwrap();
                assert_eq!(&pixels.0[..193 * WIDTH], &before[..193 * WIDTH]);
                assert_ne!(&pixels.0[193 * WIDTH..], &before[193 * WIDTH..]);
            }
        }
    }
    #[test]
    fn pointer_targets_match_visible_session_widgets_and_exclude_borders() {
        let mut pixels = Buffer(vec![BACKGROUND; WIDTH * HEIGHT]);
        for (screen, rect, hit) in [
            (Screen::Home, HOME_LAUNCH, Hit::Launch),
            (Screen::AppStopped, STOPPED_LAUNCH, Hit::Launch),
            (
                Screen::Picker {
                    selected: FileChoice::Notes,
                },
                NOTES_CHOICE,
                Hit::Choice(FileChoice::Notes),
            ),
            (
                Screen::Picker {
                    selected: FileChoice::Private,
                },
                PRIVATE_CHOICE,
                Hit::Choice(FileChoice::Private),
            ),
            (
                Screen::Picker {
                    selected: FileChoice::Notes,
                },
                PICKER_OPEN,
                Hit::Open,
            ),
            (
                Screen::Picker {
                    selected: FileChoice::Private,
                },
                PICKER_CANCEL,
                Hit::Cancel,
            ),
        ] {
            render_session(&mut pixels, screen).unwrap();
            assert_eq!(pixels.0[rect.y * WIDTH + rect.x], ACCENT);
            assert_eq!(hit_test(screen, rect.x, rect.y), Some(hit));
            assert_eq!(
                hit_test(screen, rect.x + rect.width - 1, rect.y + rect.height - 1),
                Some(hit)
            );
            assert_ne!(hit_test(screen, rect.x + rect.width, rect.y), Some(hit));
            assert_ne!(hit_test(screen, rect.x, rect.y + rect.height), Some(hit));
        }
        render_session(&mut pixels, Screen::AppRunning).unwrap();
        assert_eq!(hit_test(Screen::AppRunning, 8, 6), Some(Hit::Home));
        assert_eq!(hit_test(Screen::AppRunning, 160, 100), None);
        assert_eq!(
            hit_test(
                Screen::Opening {
                    selected: FileChoice::Notes
                },
                100,
                156
            ),
            None
        );
    }
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

/// Trusted document consent text is painted before the actual Present/barrier.
/// It describes one incarnation-local action; this view grants no capability.
pub fn document_intent<P: Pixels>(
    pixels: &mut P,
    screen: Screen,
    access: ev_userspace_contract::document::Access,
) -> Result<(), Error> {
    use ev_userspace_contract::document::Access;
    if let Screen::Picker { selected } = screen {
        if !matches!(access, Access::Read | Access::Edit) {
            return Err(Error::Header);
        }
        let mut c = Canvas::new(pixels);
        c.rect(20, 16, 280, 47, BACKGROUND)?;
        c.text_exact(
            20,
            16,
            if access == Access::Edit {
                b"Open document for editing"
            } else {
                b"Open document read only"
            },
            ACCENT,
        )?;
        c.text_exact(20, 35, b"For Documents", INK)?;
        c.text_exact(
            20,
            50,
            if access == Access::Edit {
                b"Read and save this document only"
            } else {
                b"Read this document only"
            },
            MUTED,
        )?;
        for (choice, y, label) in [
            (FileChoice::Notes, 68, b"Notes.txt".as_slice()),
            (FileChoice::Private, 105, b"Private.txt".as_slice()),
        ] {
            c.rect(
                20,
                y,
                280,
                28,
                if choice == selected { ACCENT } else { PANEL },
            )?;
            c.text_exact(
                30,
                y + 10,
                label,
                if choice == selected { BACKGROUND } else { INK },
            )?;
        }
    }
    Ok(())
}
