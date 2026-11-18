//! Semantic data for the exact last accepted native Editor presentation.
//! Callers authenticate the actual provider and compare the full Display tuple.
use crate::View;
use ev_workspace_client::{semantic as a1, ui::State};

/// Exact supported action bits, shared by publication and native dispatch.
pub fn actions(view: View<'_, '_>, writable: bool, local: u16) -> u8 {
    if view.state == State::Saving {
        return u8::from(local == 19 && crate::cancel_available(view));
    }
    let busy = matches!(
        view.state,
        State::Loading | State::Saving | State::Uncertain
    );
    if busy {
        return 0;
    }
    match local {
        16 | 19 => 1,
        17 if view.editor.is_some() && writable && view.state == State::Dirty => 1,
        18 if view.editor.is_some() => 1,
        3 if view.editor.is_some() => 0b1110,
        _ => 0,
    }
}

/// Page0 is complete: four toolbar buttons, document, status and full-name
/// range. A label-range reader supplies the name's full UTF-8 bytes under READ;
/// document ranges separately require TEXT. No identifier authorizes either.
pub fn publish(
    out: &mut a1::Publisher,
    header: a1::Header,
    view: View<'_, '_>,
    visible_end: usize,
    writable: bool,
) -> Result<(), a1::Error> {
    let (w, h) = (header.width, header.height);
    if header.page != 0 || header.pages != 1 || w < 16 || h < 49 {
        return Err(a1::Error::Bounds);
    }
    let rect = |x, y, width, height| a1::Rect {
        x,
        y,
        width,
        height,
    };
    let node = |local, parent, role, label, bounds, value, flags, actions| {
        Ok(a1::Node {
            local,
            parent,
            role,
            label: a1::Label::new(label)?,
            bounds,
            value,
            flags,
            actions,
        })
    };
    let mut nodes = [a1::Node::EMPTY; 9];
    nodes[0] = node(
        1,
        0,
        a1::Role::Window,
        "Editor",
        rect(0, 0, w, h),
        a1::Value::None,
        0,
        0,
    )?;
    nodes[1] = node(
        2,
        1,
        a1::Role::Menu,
        "File actions",
        rect(0, 0, w, 20),
        a1::Value::None,
        0,
        0,
    )?;
    let busy = matches!(
        view.state,
        State::Loading | State::Saving | State::Uncertain
    );
    for (i, label) in ["Open", "Save", "Save As", crate::fourth_label(view)]
        .into_iter()
        .enumerate()
    {
        let offered = actions(view, writable, 16 + i as u16);
        let disabled = offered == 0;
        nodes[2 + i] = node(
            16 + i as u16,
            2,
            a1::Role::Button,
            label,
            rect(i as u16 * (w / 4), 0, w / 4 - 1, 19),
            a1::Value::None,
            u8::from(disabled),
            offered,
        )?;
    }
    let document = match view.editor {
        Some(editor)
            if view.start <= visible_end
                && visible_end <= editor.bytes().len()
                && editor.text().is_char_boundary(view.start)
                && editor.text().is_char_boundary(visible_end) =>
        {
            a1::Value::TextRange {
                revision: header.view,
                offset: view.start as u64,
                length: (visible_end - view.start) as u32,
                total: editor.bytes().len() as u64,
            }
        }
        Some(_) => return Err(a1::Error::Bounds),
        None => a1::Value::None,
    };
    nodes[6] = node(
        3,
        1,
        a1::Role::Document,
        "Document",
        rect(0, 38, w, h - 48),
        document,
        u8::from(busy),
        actions(view, writable, 3),
    )?;
    let status = crate::status_label(view);
    nodes[7] = node(
        4,
        1,
        a1::Role::Label,
        status,
        rect(0, h - 10, w, 10),
        a1::Value::None,
        0,
        0,
    )?;
    let name = match view.name {
        Some(name) => a1::Value::TextRange {
            revision: header.view,
            offset: 0,
            length: name.len() as u32,
            total: name.len() as u64,
        },
        None => a1::Value::None,
    };
    nodes[8] = node(
        5,
        1,
        a1::Role::Label,
        "File name",
        rect(0, 23, w, 10),
        name,
        0,
        0,
    )?;
    out.begin(header, &nodes)
}
