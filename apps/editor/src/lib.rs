//! Native Editor's bounded app-owned pixels; document state remains separate.
#![no_std]
#![forbid(unsafe_code)]
pub mod admission;
pub mod save;
pub mod semantic;

use ev_graphics::{ACCENT, BACKGROUND, Canvas, Color, Error, INK, MUTED, PANEL, Pixels};
use ev_workspace_client::ui::{ReleaseMode, State};
use ev_workspace_editor::{BeginRefusal, Editor, Phase};

/// Local protocol state, not a kernel retirement receipt. Once bound, this
/// actor must stop using its FileWindow before accepting another selection.
#[derive(Default)]
pub struct FileHandoff {
    bound: bool,
    last_release: Option<(u32, ReleaseMode)>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseAction {
    Close,
    RepeatAck,
}
impl FileHandoff {
    pub const fn may_receive(&self) -> bool {
        !self.bound
    }
    pub fn release_action(&self, nonce: u32, mode: ReleaseMode) -> Option<ReleaseAction> {
        if matches!(nonce, 0 | u32::MAX) {
            return None;
        }
        if let Some((previous, previous_mode)) = self.last_release {
            if !self.bound && nonce == previous && mode == previous_mode {
                return Some(ReleaseAction::RepeatAck);
            }
            if nonce <= previous {
                return None;
            }
        }
        Some(ReleaseAction::Close)
    }
    /// Call only after the actual local client handle closes with no loan.
    pub fn released(&mut self, nonce: u32, mode: ReleaseMode) {
        self.bound = false;
        self.last_release = Some((nonce, mode));
    }
    pub fn receive_mode(&self) -> Option<ReleaseMode> {
        self.last_release.map(|(_, mode)| mode)
    }
    /// Call only after accepting the actual capability and matching metadata.
    pub fn received(&mut self) {
        self.bound = true;
    }
}

#[derive(Clone, Copy)]
pub struct View<'a, 'b> {
    pub editor: Option<&'a Editor<'b>>,
    pub name: Option<&'a str>,
    pub state: State,
    pub start: usize,
    pub focused: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Painted {
    pub end: usize,
    pub caret_visible: bool,
}
/// A bounded backward scan keeps the caret in view without indexing/hash work
/// over a whole1MiB document on every key. Every offset is a scalar boundary.
pub fn around_caret(editor: &Editor<'_>, width: usize, height: usize) -> usize {
    let columns = width.saturating_sub(8) / 6;
    let rows = height.saturating_sub(48) / 10;
    if columns == 0 || rows == 0 {
        return editor.caret();
    }
    let mut budget = rows.saturating_sub(1) * columns;
    let mut at = editor.caret();
    for (offset, c) in editor.text()[..editor.caret()].char_indices().rev() {
        let cost = match c {
            '\r' | '\n' => columns,
            '\t' => 4,
            _ => 1,
        };
        if cost > budget {
            break;
        }
        budget -= cost;
        at = offset;
    }
    at
}
fn label<P: Pixels>(p: &mut P, x: usize, y: usize, text: &[u8], color: Color) -> Result<(), Error> {
    let (w, h) = p.dimensions();
    if y + 7 <= h && x < w {
        let n = text.len().min((w - x) / 6);
        Canvas::new(p).text_exact(x, y, &text[..n], color)?;
    }
    Ok(())
}
fn status_label(view: View<'_, '_>) -> &'static str {
    match view.state {
        State::NoFile if cfg!(feature = "update-b") => "Choose a file (B)",
        State::Saved if cfg!(feature = "update-b") => "Saved (B)",
        State::NoFile => "Choose a file",
        State::Loading => "Opening...",
        State::Saved => "Saved",
        State::Dirty
            if view.editor.is_some_and(|e| {
                e.refused_begin()
                    .is_some_and(|r| r.reason == BeginRefusal::NoSpace)
            }) =>
        {
            "No space; changes kept"
        }
        State::Dirty if view.editor.is_some_and(|e| e.cancelled_save().is_some()) => {
            "Save cancelled; changes kept"
        }
        State::Dirty => "Unsaved changes",
        State::Saving
            if view
                .editor
                .and_then(Editor::pending)
                .is_some_and(|p| matches!(p.phase, Phase::AbortReady | Phase::AbortSent)) =>
        {
            "Cancelling save..."
        }
        State::Saving => "Saving and verifying...",
        State::Uncertain => "Recovery required",
        State::Conflict => "Changed elsewhere; Save As",
    }
}
pub fn cancel_available(view: View<'_, '_>) -> bool {
    view.state == State::Saving && view.editor.is_some_and(Editor::can_cancel_save)
}
fn fourth_label(view: View<'_, '_>) -> &'static str {
    if cancel_available(view) {
        "Cancel"
    } else if view.state == State::Saving
        && view
            .editor
            .and_then(Editor::pending)
            .is_some_and(|p| matches!(p.phase, Phase::AbortReady | Phase::AbortSent))
    {
        "Cancelling"
    } else {
        "Close"
    }
}
pub fn render<P: Pixels>(pixels: &mut P, view: View<'_, '_>) -> Result<Painted, Error> {
    let (w, h) = pixels.dimensions();
    if w == 0 || h == 0 || w > 320 || h > 200 {
        return Err(Error::Geometry);
    }
    Canvas::new(pixels).fill(PANEL)?;
    let button = w / 4;
    for (i, text) in [
        b"Open".as_slice(),
        b"Save",
        b"Save As",
        fourth_label(view).as_bytes(),
    ]
    .into_iter()
    .enumerate()
    {
        if button > 2 {
            Canvas::new(pixels).rect(i * button, 0, button - 1, h.min(19), BACKGROUND)?;
            let n = text.len().min(button.saturating_sub(4) / 6);
            label(pixels, i * button + 2, 6, &text[..n], INK)?;
        }
    }
    if let Some(name) = view.name {
        for (i, c) in name.chars().take(w.saturating_sub(8) / 6).enumerate() {
            let b = if c.is_ascii_graphic() || c == ' ' {
                c as u8
            } else {
                b'?'
            };
            label(pixels, 4 + i * 6, 25, &[b], MUTED)?;
        }
    }
    let text = status_label(view).as_bytes();
    if h >= 10 {
        Canvas::new(pixels).rect(0, h - 10, w, 10, BACKGROUND)?;
        label(pixels, 2, h - 8, text, MUTED)?;
    }
    let Some(editor) = view.editor else {
        return Ok(Painted {
            end: 0,
            caret_visible: false,
        });
    };
    if !editor.text().is_char_boundary(view.start) || view.start > editor.bytes().len() {
        return Err(Error::Text);
    }
    let cols = w.saturating_sub(8) / 6;
    let rows = h.saturating_sub(48) / 10;
    if cols == 0 || rows == 0 {
        return Ok(Painted {
            end: view.start,
            caret_visible: false,
        });
    }
    let mut row = 0;
    let mut col = 0;
    let mut end = view.start;
    let selected = editor.selection();
    let cursor = editor.caret();
    let mut caret_visible = false;
    let mut after_cr = false;
    for (offset, c) in editor.text()[view.start..].char_indices() {
        let at = view.start + offset;
        if row >= rows {
            break;
        }
        if at == cursor {
            caret_visible = true;
        }
        if view.focused && selected.is_empty() && at == cursor {
            Canvas::new(pixels).rect(4 + col * 6, 38 + row * 10, 1, 8, ACCENT)?;
        }
        end = at + c.len_utf8();
        if c == '\n' && after_cr {
            after_cr = false;
            continue;
        }
        if matches!(c, '\r' | '\n') {
            row += 1;
            col = 0;
            after_cr = c == '\r';
            continue;
        }
        after_cr = false;
        let cells = if c == '\t' { 4 - col % 4 } else { 1 };
        for _ in 0..cells {
            if row >= rows {
                break;
            }
            let x = 4 + col * 6;
            let y = 38 + row * 10;
            let highlighted = selected.contains(&at);
            if highlighted {
                Canvas::new(pixels).rect(x, y, 6, 9, ACCENT)?;
            }
            let byte = if c == '\t' {
                b' '
            } else if c.is_ascii_graphic() || c == ' ' {
                c as u8
            } else {
                b'?'
            };
            label(
                pixels,
                x,
                y,
                &[byte],
                if highlighted { BACKGROUND } else { INK },
            )?;
            col += 1;
            if col == cols {
                col = 0;
                row += 1;
            }
        }
    }
    if view.focused
        && selected.is_empty()
        && cursor == editor.bytes().len()
        && end == cursor
        && row < rows
    {
        caret_visible = true;
        Canvas::new(pixels).rect(4 + col * 6, 38 + row * 10, 1, 8, ACCENT)?;
    }
    Ok(Painted { end, caret_visible })
}

#[cfg(test)]
mod admission_tests;
#[cfg(test)]
mod cancel_tests;
#[cfg(test)]
mod tests;
