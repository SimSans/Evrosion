//! Observational, non-atomic actual Job rows. Partial packet streams never
//! constitute an Inspector snapshot or a process-control authorization.
use super::*;
use ev_workspace_shell::composition::{Contrast, FocusStyle};
pub(super) struct Snapshot {
    fields: [u64; 128],
    next: usize,
    pub nonce: u32,
    page: u8,
    model: u64,
    next_tick: u64,
    active: bool,
    selected: u8,
    gesture: Option<Gesture>,
}
#[derive(Clone, Copy)]
struct Gesture {
    identity: Identity,
    model: u64,
    view: u32,
    action: u8,
    row: u8,
    by: u64,
}
impl Snapshot {
    pub(super) const fn collecting(&self) -> bool {
        self.active
    }
    pub(super) fn suspend(&mut self) {
        self.active = false;
    }
    pub(super) fn resume(&mut self) {
        self.active = false;
        self.next_tick = 0;
    }
    pub const fn new() -> Self {
        Self {
            fields: [0; 128],
            next: 0,
            nonce: 0,
            page: 0,
            model: 0,
            next_tick: 0,
            active: false,
            selected: 0,
            gesture: None,
        }
    }
}
fn field(index: usize) -> Option<u8> {
    match index {
        0..=76 => Some(index as u8),
        77..=82 => Some((index + 43) as u8),
        83 => Some(127),
        _ => None,
    }
}
impl Root<'_> {
    pub(super) fn inspector_click(&mut self, node: u16) {
        self.inspector_click_until(node, deadline(v5::resources::RPC_TICKS));
    }
    pub(super) fn inspector_click_until(&mut self, node: u16, original_by: u64) -> bool {
        let by = original_by.min(deadline(v5::resources::RPC_TICKS));
        if now() >= by || self.inspector_self.entry.pending() {
            return false;
        }
        if node == 14
            && self.owner.pending.is_none()
            && self
                .accepted_view(v5::display_control::Slot::Inspector)
                .is_some()
        {
            if !self.inspector_self_hold_ordinary(14, by) {
                return false;
            }
            if now() < by && self.queue(Child::Inspector, Command::Activate(14)) {
                return true;
            }
            self.inspector_self_abandon_ordinary();
            return false;
        }
        if self.inspector.active || self.owner.pending.is_some() {
            return false;
        }
        let slot = v5::display_control::Slot::Inspector;
        if self
            .accepted_view(slot)
            .is_none_or(|(_, view)| view != u64::from(self.inspector.nonce))
        {
            return false;
        }
        if (100..106).contains(&node) {
            if now() < by && self.queue(Child::Inspector, Command::Activate(node)) {
                self.inspector.selected = (node - 100) as u8;
                return true;
            }
            return false;
        }
        let Ok(action) = u8::try_from(node) else {
            return false;
        };
        if !(1..=14).contains(&action) {
            return false;
        }
        let row = if (4..=7).contains(&action) {
            self.inspector.selected
        } else {
            0
        };
        if action == 14 {
            return false; // handled above, including the ordinary receipt
        }
        if self.inspector_self.enabled
            && matches!(action, 1..=3)
            && self.inspector_self.refresh_stats.pending()
        {
            return false;
        }
        if now() < by && self.queue(Child::Inspector, Command::Activate(node)) {
            if self.inspector_self.enabled && matches!(action, 1..=3) {
                require(self.inspector_self.refresh_stats.request(action), 1685);
            }
            self.inspector.gesture = Some(Gesture {
                identity: self.actor(Child::Inspector).identity,
                model: self.policy.as_ref().unwrap().scene,
                view: self.inspector.nonce,
                action,
                row,
                by,
            });
            return true;
        }
        false
    }
    pub(super) fn inspector_action(&mut self, action: u8, row: u8, view: u32) {
        let Some(gesture) = self.inspector.gesture.take() else {
            return;
        };
        if self.inspector.active || view != self.inspector.nonce {
            return;
        }
        if gesture.identity != self.actor(Child::Inspector).identity
            || gesture.model != self.policy.as_ref().unwrap().scene
            || gesture.view != view
            || gesture.action != action
            || gesture.row != row
            || now() >= gesture.by
            || self.owner.pending.is_some()
            || self.file_transition_modal()
            || self.grant.is_some() && !matches!(action, 1..=4 | 8..=11)
            || self
                .accepted_view(v5::display_control::Slot::Inspector)
                .is_none_or(|(_, accepted)| accepted != u64::from(view))
        {
            return;
        }
        if self.inspector_self.enabled
            && matches!(action, 1..=3)
            && !self.inspector_self.refresh_stats.accepted_action(action)
        {
            return;
        }
        match action {
            1 => {
                self.inspector.next_tick = 0;
            }
            2 | 3 => {
                self.inspector.page ^= 1;
                self.inspector.next_tick = 0;
            }
            4 => {
                let global = usize::from(self.inspector.page) * 6 + usize::from(row);
                if global > 0 {
                    let child = graph::CHILDREN[global - 1];
                    if let Some(slot) = child_slot(child)
                        && slot.index() < 4
                        && !self.actor(child).failed
                    {
                        let _ = self.policy.as_mut().unwrap().focus(slot.index());
                        self.scene_dirty = true;
                    }
                }
            }
            8 => {
                let policy = self.policy.as_mut().unwrap();
                let next = match policy.desktop.view().layer {
                    Layer::Simple => Layer::Advanced,
                    Layer::Advanced => Layer::AbsoluteAccess,
                    Layer::AbsoluteAccess => Layer::Simple,
                };
                let _ = policy.layer(next);
                self.inspector.next_tick = 0;
                self.owner.dirty = true;
            }
            9 | 10 => {
                let policy = self.policy.as_mut().unwrap();
                let mut preferences = policy.desktop.preferences();
                if action == 9 {
                    preferences.contrast = if preferences.contrast == Contrast::Normal {
                        Contrast::High
                    } else {
                        Contrast::Normal
                    };
                } else {
                    preferences.focus = if preferences.focus == FocusStyle::Outline {
                        FocusStyle::ThickOutline
                    } else {
                        FocusStyle::Outline
                    };
                }
                if policy
                    .desktop
                    .set_preferences(policy.shell, preferences)
                    .is_ok()
                {
                    self.scene_dirty = true;
                }
            }
            11 => {
                let maximum = self.display_command(v5::display_control::Command::Inspect {
                    slot: v5::display_control::Slot::ProtectedRoot,
                    field: 5,
                });
                if !(1..=4).contains(&maximum) {
                    return;
                }
                let policy = self.policy.as_mut().unwrap();
                let mut preferences = policy.desktop.preferences();
                if maximum == 1 {
                    self.status=b"Current admitted framebuffer supports scale1 only; accessibility scaling is pending";
                    self.owner.dirty = true;
                } else {
                    preferences.scale = if u64::from(preferences.scale) >= maximum {
                        1
                    } else {
                        preferences.scale + 1
                    };
                    if policy
                        .desktop
                        .set_preferences(policy.shell, preferences)
                        .is_ok()
                    {
                        self.scene_dirty = true;
                    }
                }
            }
            5..=7 => {
                self.status=b"Requested scoped owner operation is pending actual retirement/quiescence support";
                self.owner.dirty = true;
            }
            12..=13 => {
                self.status = b"Use protected Root Shutdown; checked restart is unavailable";
                self.owner.dirty = true;
            }
            _ => {}
        }
    }
    fn collect_inspector(&mut self) {
        self.inspector.nonce = self
            .inspector
            .nonce
            .checked_add(1)
            .filter(|v| *v != u32::MAX)
            .unwrap_or_else(|| rt::exit(1652));
        self.inspector.fields = [0; 128];
        self.inspector.fields[0] = u64::from(self.inspector.nonce);
        let start = now();
        for row in 0..6 {
            let global = usize::from(self.inspector.page) * 6 + row;
            let offset = 1 + row * 12;
            let (identity, control, root) = if global == 0 {
                (self.protected.identity, 0, true)
            } else {
                let child = graph::CHILDREN[global - 1];
                let Some(actor) = self.actors[child.index()] else {
                    continue;
                };
                (actor.identity, actor.control, false)
            };
            let mut values = [0; 9];
            let mut valid = true;
            for (field, value) in values.iter_mut().enumerate() {
                let reply = rt::call(
                    if root {
                        s::JOB_INFO
                    } else {
                        s::PROCESS_JOB_INFO
                    },
                    control,
                    field as u64,
                    0,
                );
                if reply.status != 0 || reply.capability != 0 {
                    valid = false;
                    break;
                }
                *value = reply.value;
            }
            let state = if !valid {
                3
            } else if root {
                1
            } else {
                let reply = rt::call(s::OBSERVE, control, 0, 0);
                if reply.status != 0 || reply.capability != 0 || reply.value > 1 {
                    3
                } else if reply.value == 1 {
                    2
                } else {
                    1
                }
            };
            self.inspector.fields[offset] = state | ((global as u64) << 8);
            self.inspector.fields[offset + 1] = identity.process;
            self.inspector.fields[offset + 2] = identity.thread;
            if valid {
                self.inspector.fields[offset + 3..offset + 12].copy_from_slice(&[
                    values[0], values[1], values[5], values[2], values[6], values[3], values[7],
                    values[4], values[8],
                ]);
            }
        }
        let policy = self.policy.as_ref().unwrap();
        let view = policy.desktop.view();
        self.inspector.fields[73] = u64::from(self.inspector.page);
        self.inspector.fields[74] = 12;
        self.inspector.fields[75] = start;
        self.inspector.fields[76] = now();
        self.inspector.fields[120] = match view.layer {
            Layer::Simple => 1,
            Layer::Advanced => 2,
            Layer::AbsoluteAccess => 3,
        };
        self.inspector.fields[121] = u64::from(view.preferences.scale);
        self.inspector.fields[122] = u64::from(view.preferences.contrast == Contrast::High);
        self.inspector.fields[123] = u64::from(view.preferences.focus == FocusStyle::ThickOutline);
        for (index, rights) in self.lease_rights.iter().enumerate() {
            self.inspector.fields[124] |= u64::from(*rights) << (index * 2);
        }
        self.inspector.fields[125] = 1;
        self.inspector.fields[127] = u64::from(self.inspector.nonce);
        self.inspector.model = policy.scene;
        self.inspector.next = 0;
        self.inspector.active = true;
    }
    pub(super) fn inspector_tick(&mut self) {
        if (self.inspector_self.entry.pending()
            || self.inspector_self.enabled && !self.inspector_self.refresh_stats.ready())
            && !self.inspector.active
        {
            return;
        }
        if self.policy.is_none() || self.semantic.active() || self.semantic.context_pending {
            return;
        }
        let actor = self.actor(Child::Inspector);
        if actor.failed || !actor.ready {
            return;
        }
        let model = self.policy.as_ref().unwrap().scene;
        if self.inspector.active && self.inspector.model != model {
            self.inspector.active = false;
            self.inspector.next_tick = 0;
        }
        if !self.inspector.active {
            if now() < self.inspector.next_tick {
                return;
            }
            self.collect_inspector();
            if self.inspector_self.enabled {
                // One explicit desired refresh starts at most one sample.
                // Its exact stream finishes before quiet own-tree capture.
                require(self.inspector_self.refresh_stats.started(), 1684);
            }
        }
        let Some(field) = field(self.inspector.next / 2) else {
            self.inspector.active = false;
            self.inspector.next_tick = deadline(256);
            return;
        };
        let high = !self.inspector.next.is_multiple_of(2);
        let value = self.inspector.fields[usize::from(field)];
        let command = Command::InfoWord {
            field,
            high,
            word: if high {
                (value >> 32) as u32
            } else {
                value as u32
            },
        };
        if self.outbox.input(3, actor.identity, model, command) {
            self.inspector.next += 1;
        }
    }
}

impl Root<'_> {
    pub(super) fn inspector_keyboard(&mut self, command: Command) -> bool {
        if self.inspector_self_keyboard(command) {
            return true;
        }
        use ev_workspace_client::ui::Navigation;
        if self.semantic.active() {
            let tool = match command {
                Command::Navigate {
                    key: Navigation::Up,
                    ..
                } => Some(201),
                Command::Navigate {
                    key: Navigation::Down,
                    ..
                } => Some(202),
                Command::Navigate {
                    key: Navigation::Left,
                    ..
                } => Some(210),
                Command::Navigate {
                    key: Navigation::Right,
                    ..
                } => Some(211),
                Command::Insert('\n') => Some(204),
                Command::Insert(c) => match c.to_ascii_lowercase() {
                    'f' => Some(203),
                    'k' => Some(205),
                    'e' => Some(206),
                    'n' => Some(207),
                    't' => Some(208),
                    'r' => Some(209),
                    'x' => Some(212),
                    's' => Some(215),
                    'u' => Some(216),
                    'd' => Some(217),
                    'm' => Some(218),
                    _ => None,
                },
                _ => None,
            };
            if let Some(tool) = tool {
                self.semantic_click(tool);
            }
            return true;
        }
        match command {
            Command::Navigate {
                key: Navigation::Up,
                ..
            } => self.inspector_click(100 + u16::from(self.inspector.selected.saturating_sub(1))),
            Command::Navigate {
                key: Navigation::Down,
                ..
            } => self.inspector_click(100 + u16::from((self.inspector.selected + 1).min(5))),
            Command::Navigate {
                key: Navigation::Left,
                ..
            } => self.inspector_click(3),
            Command::Navigate {
                key: Navigation::Right,
                ..
            } => self.inspector_click(2),
            Command::Insert('\n') => self.inspector_click(4),
            Command::Insert('a' | 'A') => self.inspector_click(14),
            Command::Insert('r' | 'R') => self.inspector_click(1),
            _ => (),
        }
        true
    }
}
