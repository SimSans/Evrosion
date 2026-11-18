//! Actual Files adapter for Root's selected control/events channels. No semantic
//! packet is used as a namespace window, owner identity or permission proof.
use super::*;
use ev_workspace_client::semantic::{self as a1, operation as op};
pub(super) struct Context<'a> {
    pub browser: &'a mut Browser,
    pub client: &'a mut Client<NativeLink>,
    pub surface: &'a mut Surface,
    pub session: &'a mut ev_native_files::semantic::Session,
    pub paint: &'a mut bool,
    pub available: bool,
    pub focused: bool,
    pub events: u64,
    pub bound: u64,
}
pub(super) fn operation(q: op::Request, c: Context<'_>) {
    let h = c.surface.header;
    let Some(page) = c.session.bound_page(q.binding).filter(|_| {
        c.available
            && q.binding.model == h.model_revision
            && q.binding.view == h.view_revision
            && q.binding.frame == h.frame
            && q.binding.mapping_epoch == h.mapping_epoch
    }) else {
        c.session.terminal(q.nonce, Err(op::Refusal::Stale));
        return;
    };
    match q.kind {
        op::Kind::Range {
            kind: op::RangeKind::AccessibleLabel,
            offset,
            length,
        } if q.binding.text_revision == h.view_revision => {
            let input = c.browser.editing_name();
            let entry = if page == 2 && q.node >= 32 {
                c.browser
                    .entries()
                    .nth(usize::from(q.node - 32))
                    .filter(|_| {
                        usize::from(q.node - 32)
                            < ev_native_files::semantic::visible_rows(h.height as u16)
                    })
            } else {
                None
            };
            let text = if q.node == 5 && input {
                Some(c.browser.name())
            } else {
                entry.as_ref().map(|e| e.name.as_str())
            };
            let reply = text
                .ok_or(a1::Error::Field)
                .and_then(|s| op::text_range(s, offset, length))
                .and_then(|s| {
                    c.session
                        .range(q.nonce, q.node, op::RangeKind::AccessibleLabel, s)
                });
            if reply.is_err() {
                c.session.terminal(q.nonce, Err(op::Refusal::Denied));
            }
        }
        op::Kind::Range { .. } => c.session.terminal(q.nonce, Err(op::Refusal::Denied)),
        op::Kind::Action { action, argument } => {
            let command = match action {
                op::Action::Activate if page == 1 => {
                    ev_native_files::semantic::button(c.browser, q.node).map(Command::Activate)
                }
                op::Action::Activate if page == 2 && q.node >= 32 => {
                    let row = usize::from(q.node - 32);
                    (ev_native_files::semantic::row_actions(
                        c.browser,
                        row,
                        ev_native_files::semantic::visible_rows(h.height as u16),
                    ) & 1
                        != 0)
                        .then(|| Command::Activate(ev_native_files::action::ENTER + row as u16))
                }
                op::Action::Select
                    if page == 2
                        && q.node >= 32
                        && argument == 0
                        && q.binding.text_revision == h.view_revision =>
                {
                    let row = usize::from(q.node - 32);
                    (ev_native_files::semantic::row_actions(
                        c.browser,
                        row,
                        ev_native_files::semantic::visible_rows(h.height as u16),
                    ) & 4
                        != 0)
                        .then(|| Command::Activate(ev_native_files::action::SELECT + row as u16))
                }
                op::Action::Scroll
                    if page == 2
                        && q.node == 3
                        && !c.browser.loading()
                        && !c.browser.editing_name()
                        && c.browser.status() != Status::Uncertain =>
                {
                    Some(Command::Scroll(argument as i64 as i16))
                }
                // Group expansion only pages the semantic projection; no app state or
                // authority changes. Root fetches the declared page after this receipt.
                op::Action::Expand if page == 0 && matches!(q.node, 2 | 3) => {
                    c.session.terminal(q.nonce, Ok(()));
                    return;
                }
                // Keyboard/window ownership belongs to Root, never this wire packet.
                op::Action::Focus if q.node == 5 && c.browser.editing_name() && c.focused => {
                    c.session.terminal(q.nonce, Ok(()));
                    return;
                }
                _ => None,
            };
            let Some(command) = command else {
                c.session.terminal(q.nonce, Err(op::Refusal::Denied));
                return;
            };
            let before = h.frame;
            let event = c.browser.command(c.client, command, cut(c.bound));
            c.surface.bump();
            *c.paint = true;
            if let Some(event) = event {
                notify(c.events, event, c.bound);
            }
            c.session.after_present(q.nonce, before);
        }
    }
}
