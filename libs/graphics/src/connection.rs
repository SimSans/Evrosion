//! Owner-facing connection/update view. Visible progress is never authority.
use crate::{
    ACCENT, BACKGROUND, Canvas, Error, HEIGHT, INK, MUTED, PANEL, Pixels, WIDTH, composition::Rect,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Connection {
    Connecting,
    Online,
    Offline,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Update {
    Idle,
    Preparing,
    Downloading,
    Checking,
    Ready,
    Failed,
    Selecting,
    Unavailable,
    Selected,
    SetupRequired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Back,
    Fetch,
    SelectNext,
    Restart,
    Cancel,
    Confirm,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub connection: Connection,
    pub update: Update,
    pub app_running: bool,
    pub confirm: bool,
    pub candidate_available: bool,
}
impl Default for Status {
    fn default() -> Self {
        Self {
            connection: Connection::Connecting,
            update: Update::Idle,
            app_running: false,
            confirm: false,
            candidate_available: false,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct View {
    pub status: Status,
    pub focus: Action,
}
pub const ENTRY: Rect = Rect {
    x: 20,
    y: 132,
    width: 280,
    height: 28,
};
pub const BACK: Rect = Rect {
    x: 8,
    y: 163,
    width: 64,
    height: 24,
};
pub const FETCH: Rect = Rect {
    x: 80,
    y: 163,
    width: 88,
    height: 24,
};
pub const SELECT_NEXT: Rect = Rect {
    x: 176,
    y: 163,
    width: 136,
    height: 24,
};
pub const CANCEL: Rect = Rect {
    x: 16,
    y: 155,
    width: 112,
    height: 28,
};
pub const CONFIRM: Rect = Rect {
    x: 144,
    y: 155,
    width: 160,
    height: 28,
};
pub const fn enabled(status: Status, action: Action) -> bool {
    if status.confirm {
        return matches!(action, Action::Cancel | Action::Confirm);
    }
    match action {
        Action::Back => true,
        Action::Fetch => {
            matches!(status.connection, Connection::Online)
                && (matches!(status.update, Update::Idle | Update::Failed)
                    || (matches!(status.update, Update::SetupRequired)
                        && !status.candidate_available))
        }
        Action::SelectNext => {
            status.candidate_available
                && matches!(
                    status.update,
                    Update::Ready | Update::Failed | Update::SetupRequired
                )
        }
        Action::Restart => matches!(status.update, Update::Selected),
        _ => false,
    }
}
pub const fn primary(status: Status) -> Action {
    if matches!(status.update, Update::Selected) {
        Action::Restart
    } else {
        Action::SelectNext
    }
}
pub fn hit(view: View, x: usize, y: usize) -> Option<Action> {
    let buttons = if view.status.confirm {
        [
            (Action::Cancel, CANCEL),
            (Action::Confirm, CONFIRM),
            (Action::Back, BACK),
        ]
    } else {
        [
            (Action::Back, BACK),
            (Action::Fetch, FETCH),
            (primary(view.status), SELECT_NEXT),
        ]
    };
    buttons
        .into_iter()
        .find_map(|(a, r)| (enabled(view.status, a) && r.contains(x, y)).then_some(a))
}
fn button<P: Pixels>(
    c: &mut Canvas<'_, P>,
    rect: Rect,
    text: &[u8],
    focused: bool,
    active: bool,
) -> Result<(), Error> {
    let background = if focused && active { ACCENT } else { PANEL };
    let ink = if !active {
        MUTED
    } else if focused {
        BACKGROUND
    } else {
        INK
    };
    c.rect(rect.x, rect.y, rect.width, rect.height, background)?;
    c.text(rect.x + 8, rect.y + 10, text, ink)
}
pub fn entry<P: Pixels>(pixels: &mut P) -> Result<(), Error> {
    let mut c = Canvas::new(pixels);
    button(&mut c, ENTRY, b"Connection and updates", false, true)
}
pub fn render<P: Pixels>(pixels: &mut P, view: View) -> Result<(), Error> {
    if pixels.dimensions() != (WIDTH, HEIGHT) {
        return Err(Error::Geometry);
    }
    let mut c = Canvas::new(pixels);
    c.fill(BACKGROUND)?;
    c.text(16, 14, b"Connection and updates", ACCENT)?;
    if view.status.confirm {
        c.text(16, 46, b"Restart this workspace now?", INK)?;
        c.text(
            16,
            68,
            if view.status.app_running {
                b"Your open app will close.".as_slice()
            } else {
                b"Workspace services will restart.".as_slice()
            },
            INK,
        )?;
        c.text(16, 90, b"Save your note before restarting.", INK)?;
        c.text(16, 112, b"Cancel to return to your workspace.", MUTED)?;
        button(
            &mut c,
            CANCEL,
            b"Cancel",
            view.focus == Action::Cancel,
            true,
        )?;
        button(
            &mut c,
            CONFIRM,
            b"Restart now",
            view.focus == Action::Confirm,
            true,
        )?;
    } else {
        c.text(
            16,
            43,
            match view.status.connection {
                Connection::Connecting => b"Connecting...",
                Connection::Online => b"Connected",
                Connection::Offline => b"Not connected",
            },
            INK,
        )?;
        c.text(
            16,
            73,
            match view.status.update {
                Update::Idle => b"No update downloaded.",
                Update::Preparing => b"Getting ready...",
                Update::Downloading => b"Downloading the update...",
                Update::Checking => b"Checking the update...",
                Update::Ready => b"Update downloaded.",
                Update::Failed => b"The update did not finish.",
                Update::Selecting => b"Preparing the next restart...",
                Update::Unavailable => b"Updates unavailable.",
                Update::Selected => b"Update selected for next restart.",
                Update::SetupRequired => b"Ready for first use.",
            },
            INK,
        )?;
        c.text(
            16,
            102,
            match view.status.update {
                Update::Unavailable => b"Restart or recovery is needed.",
                Update::SetupRequired if view.status.candidate_available => {
                    b"Use after restart prepares this workspace."
                }
                Update::SetupRequired => b"Fetch prepares this workspace.",
                Update::Failed => b"You can try Fetch again.",
                Update::Selected => b"Restart when your work is saved.",
                _ => b"Your current app keeps running.",
            },
            MUTED,
        )?;
        for (a, r, label) in [
            (Action::Back, BACK, b"Back".as_slice()),
            (Action::Fetch, FETCH, b"Fetch"),
            (
                primary(view.status),
                SELECT_NEXT,
                if matches!(view.status.update, Update::Selected) {
                    b"Restart now".as_slice()
                } else {
                    b"Use after restart".as_slice()
                },
            ),
        ] {
            button(&mut c, r, label, view.focus == a, enabled(view.status, a))?;
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
        fn write(&mut self, x: usize, y: usize, c: Color) -> Result<(), Error> {
            if x >= WIDTH || y >= HEIGHT {
                return Err(Error::Bounds);
            }
            self.0[y * WIDTH + x] = c;
            Ok(())
        }
    }
    #[test]
    fn every_state_renders_and_only_visible_enabled_buttons_hit() {
        for connection in [
            Connection::Connecting,
            Connection::Online,
            Connection::Offline,
        ] {
            for update in [
                Update::Idle,
                Update::Preparing,
                Update::Downloading,
                Update::Checking,
                Update::Ready,
                Update::Failed,
                Update::Selecting,
                Update::Unavailable,
                Update::Selected,
                Update::SetupRequired,
            ] {
                for candidate_available in [false, true] {
                    let status = Status {
                        connection,
                        update,
                        app_running: true,
                        confirm: false,
                        candidate_available,
                    };
                    let view = View {
                        status,
                        focus: Action::Back,
                    };
                    render(&mut Buffer(vec![BACKGROUND; WIDTH * HEIGHT]), view).unwrap();
                    assert_eq!(hit(view, 17, 164), Some(Action::Back));
                    assert_eq!(hit(view, 97, 164).is_some(), enabled(status, Action::Fetch));
                    assert_eq!(
                        hit(view, 177, 164).is_some(),
                        enabled(status, primary(status))
                    );
                    assert_eq!(hit(view, 0, 0), None);
                }
            }
        }
    }
    #[test]
    fn restart_warning_defaults_to_cancel_and_has_separate_safe_hit_targets() {
        let view = View {
            status: Status {
                connection: Connection::Online,
                update: Update::Selected,
                app_running: true,
                confirm: true,
                candidate_available: true,
            },
            focus: Action::Cancel,
        };
        let mut p = Buffer(vec![BACKGROUND; WIDTH * HEIGHT]);
        render(&mut p, view).unwrap();
        assert_eq!(hit(view, 17, 156), Some(Action::Cancel));
        assert_eq!(hit(view, 145, 156), Some(Action::Confirm));
        assert_eq!(hit(view, 130, 156), None);
        assert_eq!(hit(view, 100, 164), Some(Action::Cancel));
    }
    #[test]
    fn actual_recovery_fence_disables_mutations_even_with_a_cached_candidate() {
        let status = Status {
            connection: Connection::Online,
            update: Update::Unavailable,
            app_running: true,
            confirm: false,
            candidate_available: true,
        };
        assert!(!enabled(status, Action::Fetch));
        assert!(!enabled(status, Action::SelectNext));
        assert!(!enabled(status, Action::Restart));
        assert!(enabled(status, Action::Back));
        let retryable = Status {
            update: Update::Failed,
            ..status
        };
        assert!(enabled(retryable, Action::Fetch));
        assert!(enabled(retryable, Action::SelectNext));
    }
}
