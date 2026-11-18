//! Native document view and bounded scalar/cell layout. The semantic snapshot
//! supplies named controls and state; raster coordinates grant no authority.
use crate::{
    ACCENT, BACKGROUND, Canvas, DANGER, Error, HEIGHT, INK, MUTED, PANEL, Pixels, WIDTH,
    composition::Rect,
};
use ev_userspace_contract::document::{Access, Choice, Feedback, Focus, Snapshot, State, Text};

pub const COLUMNS: usize = 46;
pub const VISIBLE_ROWS: usize = 7;
pub const TEXT_RECT: Rect = Rect {
    x: 8,
    y: 56,
    width: 288,
    height: 74,
};
pub const OPEN_RECT: Rect = Rect {
    x: 8,
    y: 26,
    width: 88,
    height: 20,
};
pub const SAVE_RECT: Rect = Rect {
    x: 104,
    y: 26,
    width: 88,
    height: 20,
};
pub const CLOSE_RECT: Rect = Rect {
    x: 200,
    y: 26,
    width: 96,
    height: 20,
};
pub const SELECT_ALL_RECT: Rect = Rect {
    x: 8,
    y: 157,
    width: 80,
    height: 14,
};
pub const OPEN_READ_RECT: Rect = Rect {
    x: 96,
    y: 157,
    width: 112,
    height: 14,
};
pub const KEEP_RECT: Rect = Rect {
    x: 12,
    y: 114,
    width: 136,
    height: 26,
};
pub const DISCARD_RECT: Rect = Rect {
    x: 160,
    y: 114,
    width: 136,
    height: 26,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Position {
    pub row: usize,
    pub column: usize,
}
fn advance(position: &mut Position, character: char, after_cr: &mut bool) {
    match character {
        '\r' => {
            position.row += 1;
            position.column = 0;
            *after_cr = true;
        }
        '\n' => {
            if !*after_cr {
                position.row += 1;
                position.column = 0;
            }
            *after_cr = false;
        }
        '\t' => {
            *after_cr = false;
            position.column += 4 - position.column % 4;
            position.row += position.column / COLUMNS;
            position.column %= COLUMNS;
        }
        _ => {
            *after_cr = false;
            position.column += 1;
            if position.column == COLUMNS {
                position.row += 1;
                position.column = 0;
            }
        }
    }
}
/// Byte offsets always refer to UTF-8 scalar boundaries, not displayed glyph
/// bytes. Unsupported font glyphs remain intact in the semantic/document text.
pub fn position(text: &Text, offset: usize) -> Option<Position> {
    if !text.boundary(offset) {
        return None;
    }
    let mut position = Position::default();
    let mut after_cr = false;
    for (at, character) in text.as_str().char_indices() {
        if at == offset {
            return Some(position);
        }
        advance(&mut position, character, &mut after_cr);
    }
    Some(position)
}
pub fn offset_at(text: &Text, row: usize, column: usize) -> usize {
    let mut position = Position::default();
    let mut after_cr = false;
    let mut found = None;
    for (at, character) in text.as_str().char_indices() {
        if position.row > row {
            return found.unwrap_or(at);
        }
        if position.row == row {
            if position.column > column {
                return found.unwrap_or(at);
            }
            found = Some(at);
        }
        advance(&mut position, character, &mut after_cr);
    }
    if position.row == row && position.column <= column {
        return text.len();
    }
    found.unwrap_or(text.len())
}
pub fn first_visible_line(view: &Snapshot) -> usize {
    position(&view.text, usize::from(view.cursor))
        .map(|p| p.row.saturating_sub(VISIBLE_ROWS - 1))
        .unwrap_or(0)
}
pub fn pointer_offset(view: &Snapshot, x: usize, y: usize) -> Option<usize> {
    if !TEXT_RECT.contains(x, y) {
        return None;
    }
    let row = first_visible_line(view) + (y.saturating_sub(62) / 9).min(VISIBLE_ROWS - 1);
    let column = (x.saturating_sub(14) / 6).min(COLUMNS - 1);
    Some(offset_at(&view.text, row, column))
}
pub fn enabled(view: &Snapshot, focus: Focus) -> bool {
    if view.state == State::ConfirmDiscard {
        return matches!(focus, Focus::KeepEditing | Focus::Discard);
    }
    match focus {
        Focus::Open | Focus::OpenRead => !matches!(
            view.state,
            State::Selecting | State::Saving | State::Readback | State::Unavailable
        ),
        Focus::Text | Focus::SelectAll => view.choice != Choice::None,
        Focus::Save => view.can_save(),
        Focus::Close => {
            view.choice != Choice::None
                && !matches!(
                    view.state,
                    State::Saving | State::Readback | State::Unavailable
                )
        }
        Focus::Discard | Focus::KeepEditing => false,
    }
}
pub fn next_focus(view: &Snapshot, reverse: bool) -> Focus {
    let items: &[Focus] = if view.state == State::ConfirmDiscard {
        &[Focus::KeepEditing, Focus::Discard]
    } else {
        &[
            Focus::Open,
            Focus::Text,
            Focus::SelectAll,
            Focus::Save,
            Focus::Close,
            Focus::OpenRead,
        ]
    };
    let start = items.iter().position(|f| *f == view.focus).unwrap_or(0);
    for step in 1..=items.len() {
        let at = (start + if reverse { items.len() - step } else { step }) % items.len();
        if enabled(view, items[at]) {
            return items[at];
        }
    }
    view.focus
}
pub fn hit_test(view: &Snapshot, x: usize, y: usize) -> Option<Focus> {
    let items: &[(Focus, Rect)] = if view.state == State::ConfirmDiscard {
        &[
            (Focus::KeepEditing, KEEP_RECT),
            (Focus::Discard, DISCARD_RECT),
        ]
    } else {
        &[
            (Focus::Open, OPEN_RECT),
            (Focus::Text, TEXT_RECT),
            (Focus::SelectAll, SELECT_ALL_RECT),
            (Focus::Save, SAVE_RECT),
            (Focus::Close, CLOSE_RECT),
            (Focus::OpenRead, OPEN_READ_RECT),
        ]
    };
    items
        .iter()
        .find_map(|(focus, rect)| (enabled(view, *focus) && rect.contains(x, y)).then_some(*focus))
}
fn button<P: Pixels>(
    canvas: &mut Canvas<'_, P>,
    view: &Snapshot,
    focus: Focus,
    rect: Rect,
) -> Result<(), Error> {
    let active = enabled(view, focus);
    let selected = active && view.focus == focus;
    canvas.rect(
        rect.x,
        rect.y,
        rect.width,
        rect.height,
        if selected { ACCENT } else { BACKGROUND },
    )?;
    canvas.text_exact(
        rect.x + 5,
        rect.y + (rect.height - 7) / 2,
        focus.label().as_bytes(),
        if selected {
            BACKGROUND
        } else if active {
            INK
        } else {
            MUTED
        },
    )
}
pub fn status(view: &Snapshot) -> &'static [u8] {
    match view.state {
        State::Closed => b"Choose a local document to begin.",
        State::Selecting => b"Choose a document in the picker.",
        State::Saved => b"Saved",
        State::Dirty => b"Unsaved changes",
        State::Saving => b"Saving...",
        State::Readback => b"Checking saved data...",
        State::Unavailable => b"Save unavailable or unconfirmed",
        State::ConfirmDiscard => b"Unsaved changes",
    }
}
pub fn feedback(view: &Snapshot) -> &'static [u8] {
    match view.feedback {
        Feedback::None => {
            if view.text.as_bytes().iter().any(|b| !b.is_ascii()) {
                b"Some glyphs shown as ?; text is preserved."
            } else {
                b""
            }
        }
        Feedback::Full => b"Document is full (224 bytes).",
        Feedback::ReadOnly => b"Read only. Open for editing to save.",
        Feedback::UnsupportedText => b"Unsupported text; original is preserved.",
        Feedback::Conflict => b"Document changed. Close and reopen.",
        Feedback::Storage => b"Storage unavailable; save is unconfirmed.",
        Feedback::Denied => b"Access refused.",
        Feedback::Busy => b"Waiting for storage.",
        Feedback::Uncertain => b"Save unconfirmed. Recovery is required.",
        Feedback::Exhausted => b"Document revision is exhausted.",
    }
}
pub fn render<P: Pixels>(pixels: &mut P, view: &Snapshot) -> Result<(), Error> {
    if pixels.dimensions() != (WIDTH, HEIGHT) {
        return Err(Error::Geometry);
    }
    view.valid().map_err(|_| Error::Header)?;
    let mut c = Canvas::new(pixels);
    c.fill(PANEL)?;
    if view.state == State::ConfirmDiscard {
        c.text_exact(12, 24, b"Unsaved changes", INK)?;
        c.text_exact(12, 47, b"Keep editing or discard your changes.", INK)?;
        c.text_exact(12, 68, b"Discard does not save these changes.", MUTED)?;
        button(&mut c, view, Focus::KeepEditing, KEEP_RECT)?;
        button(&mut c, view, Focus::Discard, DISCARD_RECT)?;
        return Ok(());
    }
    c.text_exact(8, 8, view.choice.label().as_bytes(), INK)?;
    c.text_exact(
        224,
        8,
        match view.access {
            Access::None => b"",
            Access::Read => b"READ ONLY",
            Access::Edit => b"EDIT",
        },
        MUTED,
    )?;
    for (focus, rect) in [
        (Focus::Open, OPEN_RECT),
        (Focus::Save, SAVE_RECT),
        (Focus::Close, CLOSE_RECT),
        (Focus::SelectAll, SELECT_ALL_RECT),
        (Focus::OpenRead, OPEN_READ_RECT),
    ] {
        button(&mut c, view, focus, rect)?;
    }
    c.rect(
        TEXT_RECT.x,
        TEXT_RECT.y,
        TEXT_RECT.width,
        TEXT_RECT.height,
        if view.focus == Focus::Text {
            ACCENT
        } else {
            MUTED
        },
    )?;
    c.rect(
        TEXT_RECT.x + 2,
        TEXT_RECT.y + 2,
        TEXT_RECT.width - 4,
        TEXT_RECT.height - 4,
        BACKGROUND,
    )?;
    let first = first_visible_line(view);
    let start = usize::from(view.cursor.min(view.anchor));
    let end = usize::from(view.cursor.max(view.anchor));
    let mut point = Position::default();
    let mut after_cr = false;
    for (at, character) in view.text.as_str().char_indices() {
        if (first..first + VISIBLE_ROWS).contains(&point.row)
            && !matches!(character, '\n' | '\r' | '\t')
        {
            let x = 14 + point.column * 6;
            let y = 62 + (point.row - first) * 9;
            let selected = (start..end).contains(&at);
            if selected {
                c.rect(x, y - 1, 6, 9, ACCENT)?;
            }
            let glyph = if character.is_ascii() {
                character as u8
            } else {
                b'?'
            };
            c.text_exact(x, y, &[glyph], if selected { BACKGROUND } else { INK })?;
        }
        advance(&mut point, character, &mut after_cr);
    }
    if view.focus == Focus::Text && view.choice != Choice::None {
        let caret = position(&view.text, usize::from(view.cursor)).ok_or(Error::Text)?;
        c.rect(
            14 + caret.column * 6,
            61 + (caret.row - first) * 9,
            1,
            9,
            ACCENT,
        )?;
    }
    c.text_exact(
        8,
        135,
        status(view),
        if view.state == State::Saved {
            ACCENT
        } else if view.state == State::Unavailable {
            DANGER
        } else {
            INK
        },
    )?;
    c.text_exact(8, 148, feedback(view), MUTED)?;
    c.text_exact(240, 161, b"Tab", MUTED)?;
    Ok(())
}

#[cfg(test)]
#[path = "document_tests.rs"]
mod tests;
