extern crate std;
use super::*;
use crate::Color;
struct Buffer {
    data: std::vec::Vec<Color>,
    writes: usize,
}
impl Buffer {
    fn new() -> Self {
        Self {
            data: std::vec![BACKGROUND;WIDTH*HEIGHT],
            writes: 0,
        }
    }
}
impl Pixels for Buffer {
    fn dimensions(&self) -> (usize, usize) {
        (WIDTH, HEIGHT)
    }
    fn write(&mut self, x: usize, y: usize, color: Color) -> Result<(), Error> {
        if x >= WIDTH || y >= HEIGHT {
            return Err(Error::Bounds);
        }
        self.data[y * WIDTH + x] = color;
        self.writes += 1;
        Ok(())
    }
}
fn view() -> Snapshot {
    Snapshot {
        state: State::Saved,
        focus: Focus::Text,
        choice: Choice::Notes,
        access: Access::Edit,
        text: Text::new(b"hello").unwrap(),
        cursor: 5,
        anchor: 5,
        revision: 1,
        feedback: Feedback::None,
        dirty: false,
    }
}

#[test]
fn all_document_and_dialog_states_render_inside_the_actual_reference_surface() {
    let mut buffer = Buffer::new();
    let saved = view();
    render(&mut buffer, &saved).unwrap();
    let pixels = buffer.data.clone();
    for state in [
        State::Dirty,
        State::Saving,
        State::Readback,
        State::Unavailable,
    ] {
        let candidate = Snapshot {
            state,
            dirty: true,
            feedback: if state == State::Unavailable {
                Feedback::Uncertain
            } else {
                Feedback::None
            },
            ..saved
        };
        render(&mut buffer, &candidate).unwrap();
        assert_ne!(
            &buffer.data[135 * WIDTH..142 * WIDTH],
            &pixels[135 * WIDTH..142 * WIDTH]
        );
    }
    let dialog = Snapshot {
        state: State::ConfirmDiscard,
        focus: Focus::KeepEditing,
        dirty: true,
        ..saved
    };
    render(&mut buffer, &dialog).unwrap();
    assert_eq!(hit_test(&dialog, 18, 120), Some(Focus::KeepEditing));
    assert_eq!(hit_test(&dialog, 170, 120), Some(Focus::Discard));
    assert_eq!(hit_test(&dialog, 110, 30), None);
    assert_eq!(next_focus(&dialog, false), Focus::Discard);
}

#[test]
fn disabled_save_has_no_pointer_action_and_keyboard_only_cycles_enabled_controls() {
    let saved = view();
    assert!(!enabled(&saved, Focus::Save));
    assert_eq!(hit_test(&saved, 110, 30), None);
    let dirty = Snapshot {
        state: State::Dirty,
        dirty: true,
        ..saved
    };
    assert_eq!(hit_test(&dirty, 110, 30), Some(Focus::Save));
    let readonly = Snapshot {
        access: Access::Read,
        ..saved
    };
    assert!(!enabled(&readonly, Focus::Save));
    assert_eq!(next_focus(&readonly, false), Focus::SelectAll);
    assert_eq!(
        next_focus(
            &Snapshot {
                focus: Focus::SelectAll,
                ..readonly
            },
            false
        ),
        Focus::Close
    );
    let closed = Snapshot {
        state: State::Closed,
        focus: Focus::Open,
        choice: Choice::None,
        access: Access::None,
        text: Text::empty(),
        cursor: 0,
        anchor: 0,
        revision: 0,
        feedback: Feedback::None,
        dirty: false,
    };
    assert_eq!(next_focus(&closed, false), Focus::OpenRead);
    assert_eq!(
        next_focus(
            &Snapshot {
                focus: Focus::OpenRead,
                ..closed
            },
            false
        ),
        Focus::Open
    );
    assert_eq!(hit_test(&closed, 10, 60), None);
}

#[test]
fn utf8_crlf_tabs_wrapping_and_last_caret_are_preserved_by_shared_layout() {
    let text = Text::new("Aé🙂\r\n\tZ".as_bytes()).unwrap();
    assert_eq!(position(&text, 3), Some(Position { row: 0, column: 2 }));
    assert_eq!(position(&text, 2), None);
    assert_eq!(
        position(&text, text.len()),
        Some(Position { row: 1, column: 5 })
    );
    for offset in [0, 1, 3, 7, 8, 9, 10, text.len()] {
        assert!(text.boundary(offset));
        assert!(position(&text, offset).is_some());
    }
    let full = Text::new(&[b'x'; 224]).unwrap();
    assert_eq!(position(&full, 224), Some(Position { row: 4, column: 40 }));
    assert_eq!(offset_at(&full, 2, 5), 97);
    assert_eq!(offset_at(&full, 200, 0), 224);
    let many = Text::new(&[b'\n'; 224]).unwrap();
    let snapshot = Snapshot {
        text: many,
        cursor: 224,
        anchor: 224,
        ..view()
    };
    assert_eq!(first_visible_line(&snapshot), 218);
    render(&mut Buffer::new(), &snapshot).unwrap();
}

#[test]
fn invalid_semantics_refuse_before_any_paint_and_unicode_bytes_are_never_rewritten() {
    let mut b = Buffer::new();
    let invalid = Snapshot {
        cursor: 225,
        ..view()
    };
    assert_eq!(render(&mut b, &invalid), Err(Error::Header));
    assert_eq!(b.writes, 0);
    let unicode = Snapshot {
        text: Text::new("新🙂".as_bytes()).unwrap(),
        cursor: 7,
        anchor: 7,
        ..view()
    };
    let before = unicode.text;
    render(&mut b, &unicode).unwrap();
    assert_eq!(unicode.text, before);
    assert!(!feedback(&unicode).is_empty());
}
