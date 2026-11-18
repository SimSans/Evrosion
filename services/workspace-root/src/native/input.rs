use super::*;
use ev_input::{
    Key, KeyEvent, SessionBarrierReply,
    pointer::{FreshGate as PointerGate, LEFT, PointerEvent},
    protocol::FreshGate,
    text::{Text, TextEvent},
};
use ev_workspace_client::ui::Navigation;
pub(super) struct Input {
    pub lifetime: u32,
    pub x: i32,
    pub y: i32,
    last: u32,
    buttons: u8,
    keys: Option<FreshGate>,
    pointer: Option<PointerGate>,
    drag: Option<(usize, bool, i32, i32)>,
}
impl Input {
    pub const fn new() -> Self {
        Self {
            lifetime: 1,
            x: 320,
            y: 240,
            last: 0,
            buttons: 0,
            keys: None,
            pointer: None,
            drag: None,
        }
    }
    pub fn arm(&mut self, reply: SessionBarrierReply) {
        self.keys = Some(FreshGate::after_barrier(reply.keyboard()).unwrap());
        self.pointer = Some(PointerGate::after_barrier(reply).unwrap());
    }
    pub fn cancel(&mut self) {
        self.keys = None;
        self.pointer = None;
        self.drag = None;
    }
    pub fn serial(&self, sequence: u32) -> u64 {
        (u64::from(self.lifetime) << 32) | u64::from(sequence)
    }
}
impl Root<'_> {
    pub(super) fn input_event(&mut self, bytes: [u8; 8]) {
        if self.policy.is_none() {
            return;
        }
        if self.shutdown.active() {
            self.shutdown_input(bytes);
            return;
        }
        if self.development.active() {
            self.development_input(bytes);
            return;
        }
        if let Ok(event) = PointerEvent::decode(bytes) {
            self.pointer_event(event);
            return;
        }
        if let Ok(event) = KeyEvent::decode(bytes) {
            if event.sequence <= self.input.last {
                return;
            }
            self.input.last = event.sequence;
            if self.semantic_consent() {
                if let Some(key) = self
                    .input
                    .keys
                    .as_mut()
                    .and_then(|gate| gate.observe(event).ok().flatten())
                {
                    let action = match key {
                        Key::Escape => Some(6),
                        Key::Left => Some(0),
                        Key::Right => Some(1),
                        Key::Up => Some(2),
                        Key::Down => Some(3),
                        Key::Enter => Some(5),
                        _ => None,
                    };
                    if let Some(action) = action {
                        self.semantic_consent_action(action, event.sequence);
                    }
                }
                return;
            }
            if self.file_transition_modal() {
                if event.key == Key::Escape {
                    self.cancel_grant();
                } else if self.file_notice_fenced() {
                    let node = match event.key {
                        Key::Up => Some(201),
                        Key::Down | Key::Tab => Some(202),
                        _ => None,
                    };
                    if let Some(node) = node {
                        self.semantic_modal_reader_input(node, event.sequence);
                    }
                }
                return;
            }
            if self.owner.pending.is_some() {
                // Cancellation only decreases authority. A failed chooser may
                // have no barrier; authenticated Input must still escape it.
                if event.key == Key::Escape {
                    self.cancel_owner();
                    return;
                }
                let fresh = self
                    .input
                    .keys
                    .as_mut()
                    .and_then(|gate| gate.observe(event).ok().flatten());
                if let Some(key) = fresh {
                    match key {
                        Key::Escape => self.cancel_owner(),
                        Key::Up => self.browse(-1),
                        Key::Down => self.browse(1),
                        Key::Left => self.picker_up(),
                        Key::Right => self.choose_rights(),
                        Key::Enter => self.choose(event.sequence),
                        Key::Tab => {
                            self.semantic_modal_reader_input(202, event.sequence);
                        }
                    }
                }
                return;
            }
            match event.key {
                Key::Tab => {
                    let _ = self.policy.as_mut().unwrap().switch_window();
                    self.scene_dirty = true;
                }
                Key::Escape if self.semantic.phase == semantic::Phase::Requested => {
                    self.semantic_begin_consent(event.sequence)
                }
                Key::Escape => {
                    if let Some(command) = ev_workspace_root::policy::save_cancel_command(
                        self.policy.as_ref().unwrap().focused(),
                        &self.states,
                    ) {
                        self.focused_command(command);
                        return;
                    }
                    if let Some(index @ (1 | 2)) = self.policy.as_ref().unwrap().focused() {
                        self.request_revoke(index);
                    } else {
                        self.status=b"Root controls: focus an Editor and choose Revoke; copied private bytes remain";
                        self.owner.dirty = true;
                    }
                }
                Key::Enter => self.focused_command(Command::Insert('\n')),
                Key::Left => self.focused_command(Command::Navigate {
                    key: Navigation::Left,
                    extend: false,
                }),
                Key::Right => self.focused_command(Command::Navigate {
                    key: Navigation::Right,
                    extend: false,
                }),
                Key::Up => self.focused_command(Command::Navigate {
                    key: Navigation::Up,
                    extend: false,
                }),
                Key::Down => self.focused_command(Command::Navigate {
                    key: Navigation::Down,
                    extend: false,
                }),
            }
            return;
        }
        if let Ok(event) = TextEvent::decode(bytes) {
            if event.sequence <= self.input.last {
                return;
            }
            self.input.last = event.sequence;
            if self.owner.pending.is_some()
                || self.file_transition_modal() && self.file_notice_fenced()
            {
                if let Text::Ascii(b'v' | b'V') = event.text {
                    self.picker_source();
                    return;
                }
                if let Text::Ascii(byte) = event.text {
                    let node = match byte.to_ascii_lowercase() {
                        b'j' => Some(202),
                        b'k' => Some(201),
                        b'e' => Some(206),
                        b'n' => Some(207),
                        b'r' => Some(209),
                        b'a' => Some(204),
                        b'm' => Some(218),
                        b'x' => Some(212),
                        _ => None,
                    };
                    if let Some(node) = node {
                        self.semantic_modal_reader_input(node, event.sequence);
                    }
                }
                return;
            }
            if self.file_transition_modal() || self.semantic_consent() {
                return;
            }
            match event.text {
                Text::Ascii(byte) => self.focused_command(Command::Insert(char::from(byte))),
                Text::Backspace => self.focused_command(Command::Navigate {
                    key: Navigation::Backspace,
                    extend: false,
                }),
            }
        }
    }
    fn focused_command(&mut self, command: Command) {
        if let Some(index) = self.policy.as_ref().unwrap().focused() {
            if index == 3 && self.inspector_keyboard(command) {
                return;
            }
            if self.grant.is_some()
                && (index == 0 || !matches!(command, Command::Navigate { .. } | Command::Scroll(_)))
            {
                return; // hidden debt permits private navigation, no new file intent
            }
            let child = app_child(index).unwrap();
            if self.actor(child).ready && !self.actor(child).failed {
                self.queue(child, command);
            }
        }
    }
    fn pointer_event(&mut self, event: PointerEvent) {
        if event.sequence <= self.input.last {
            return;
        }
        self.input.last = event.sequence;
        self.input.x = (self.input.x + i32::from(event.dx)).clamp(0, 639);
        self.input.y = (self.input.y - i32::from(event.dy)).clamp(0, 479);
        self.update_cursor();
        let ordinary_press = event.buttons & LEFT != 0 && self.input.buttons & LEFT == 0;
        self.input.buttons = event.buttons;
        if self.semantic_consent() {
            let fresh = self
                .input
                .pointer
                .as_mut()
                .and_then(|gate| gate.observe(event).ok())
                .unwrap_or(0);
            if fresh & LEFT != 0 && (70..80).contains(&self.input.y) {
                let action = match self.input.x {
                    0..=44 => 0,
                    45..=89 => 1,
                    90..=179 => 2,
                    180..=269 => 3,
                    270..=389 => 4,
                    390..=499 => 5,
                    _ => 6,
                };
                self.semantic_consent_action(action, event.sequence);
            }
            return;
        }
        if self.file_transition_modal() {
            if ordinary_press && self.input.y >= 70 && self.input.y < 80 && self.input.x >= 500 {
                self.cancel_grant();
            } else if ordinary_press && self.file_notice_fenced() {
                self.modal_reader_pointer(event.sequence);
            }
            return;
        }
        if self.owner.pending.is_some() {
            if ordinary_press && (70..80).contains(&self.input.y) && self.input.x >= 500 {
                self.cancel_owner();
                return;
            }
            let fresh = self
                .input
                .pointer
                .as_mut()
                .and_then(|gate| gate.observe(event).ok())
                .unwrap_or(0);
            if fresh & LEFT != 0 && self.input.y >= 70 && self.input.y < 80 {
                if self.input.x >= 500 {
                    self.cancel_owner();
                } else if self.input.x >= 300 {
                    self.choose(event.sequence);
                } else if self.input.x >= 250 {
                    self.picker_source();
                } else if self.input.x >= 150 {
                    self.choose_rights();
                } else if self.input.x >= 90 {
                    self.picker_up();
                } else {
                    self.browse(if self.input.x < 45 { -1 } else { 1 });
                }
            } else if fresh & LEFT != 0 {
                self.modal_reader_pointer(event.sequence);
            }
            return;
        }
        if event.buttons & LEFT == 0 {
            self.input.drag = None;
        }
        if let Some((index, resize, oldx, oldy)) = self.input.drag {
            if event.buttons & LEFT != 0
                && let Ok(mut bounds) = self.policy.as_ref().unwrap().bounds(index)
            {
                if resize {
                    bounds.width =
                        (bounds.width as i32 + self.input.x - oldx).clamp(120, 320) as u32;
                    bounds.height =
                        (bounds.height as i32 + self.input.y - oldy).clamp(80, 180) as u32;
                } else {
                    bounds.x += self.input.x - oldx;
                    bounds.y += self.input.y - oldy;
                }
                if self
                    .policy
                    .as_mut()
                    .unwrap()
                    .geometry(index, bounds)
                    .is_ok()
                {
                    self.scene_dirty = true;
                }
                self.input.drag = Some((index, resize, self.input.x, self.input.y));
            }
            return;
        }
        if !ordinary_press {
            return;
        }
        if (70..80).contains(&self.input.y)
            && self.development_offer_click(self.input.x, event.sequence)
        {
            return;
        }
        if self.input.y >= 462 {
            let slot = ev_userspace_contract::root_v5::display_control::Slot::Shell;
            if self.actor(Child::Shell).ready
                && !self.actor(Child::Shell).failed
                && self.accepted_view(slot).is_some()
            {
                let window = (self.input.x / 160 + 1) as u8;
                let actor = self.actor(Child::Shell);
                let model = self.policy.as_ref().unwrap().scene;
                if self.queue(Child::Shell, Command::Activate(u16::from(window))) {
                    self.shell_gesture = Some((
                        window,
                        actor.identity,
                        model,
                        deadline(v5::resources::RPC_TICKS),
                    ));
                }
            }
            return;
        }
        if self.input.y < 11 {
            match self.input.x {
                0..=29 => {
                    let _ = self.policy.as_mut().unwrap().layer(Layer::Simple);
                }
                30..=59 => {
                    let _ = self.policy.as_mut().unwrap().layer(Layer::Advanced);
                }
                60..=89 => {
                    let _ = self.policy.as_mut().unwrap().layer(Layer::AbsoluteAccess);
                }
                180..=249 => {
                    let index = self.policy.as_ref().unwrap().focused().unwrap_or(1);
                    self.request_picker(if matches!(index, 1 | 2) { index } else { 1 });
                }
                90..=179 if self.semantic.phase == semantic::Phase::Requested => {
                    self.semantic_begin_consent(event.sequence)
                }
                90..=179 => {
                    if let Some(index) = self.policy.as_ref().unwrap().focused() {
                        self.request_revoke(index);
                    }
                }
                250..=319 => {
                    if !self.actor(Child::Inspector).failed {
                        let _ = self.policy.as_mut().unwrap().focus(3);
                        self.scene_dirty = true;
                    }
                }
                320..=449 => self.shutdown_request(
                    ev_workspace_root::shutdown::Intent::Shutdown,
                    event.sequence,
                ),
                450..=579 => self
                    .shutdown_request(ev_workspace_root::shutdown::Intent::Restart, event.sequence),
                580..=639 => {
                    if let Some(index) = self.policy.as_ref().unwrap().focused() {
                        self.request_revoke(index);
                    }
                }
                _ => {}
            }
            self.owner.dirty = true;
            return;
        }
        let Some((index, title)) = self
            .policy
            .as_ref()
            .unwrap()
            .hit(self.input.x, self.input.y)
        else {
            return;
        };
        let slot = [
            v5::display_control::Slot::Files,
            v5::display_control::Slot::EditorOne,
            v5::display_control::Slot::EditorTwo,
            v5::display_control::Slot::Inspector,
        ][index];
        if self.accepted_view(slot).is_none() {
            return;
        }
        if self.policy.as_ref().unwrap().focused() != Some(index) {
            let _ = self.policy.as_mut().unwrap().focus(index);
            self.scene_dirty = true;
        }
        let bounds = self.policy.as_ref().unwrap().bounds(index).unwrap();
        let resize = self.input.x >= bounds.x + bounds.width as i32 - 10
            && self.input.y >= bounds.y + bounds.height as i32 - 10;
        if title || resize {
            self.input.drag = Some((index, resize, self.input.x, self.input.y));
            return;
        }
        let x = self.input.x - bounds.x;
        let y = self.input.y - bounds.y;
        if self.grant.is_some() && index != 3 {
            return; // activation/geometry above are safe; file-content intents stay blocked
        }
        if index == 0
            && let Some(action) = ev_native_files::hit_test(
                bounds.width as usize,
                bounds.height as usize,
                x as usize,
                y as usize,
            )
        {
            self.queue(Child::Files, Command::Activate(action));
        }
        if index == 3 && self.semantic.active() {
            if let Some(node) = ev_native_inspector::consumer::hit_test(
                bounds.width as usize,
                bounds.height as usize,
                x as usize,
                y as usize,
                self.semantic.selected,
            ) {
                self.semantic_click(node);
            }
            return;
        }
        if index == 3
            && let Some(node) = ev_native_inspector::hit_test(
                bounds.width as usize,
                bounds.height as usize,
                x as usize,
                y as usize,
            )
        {
            self.inspector_click(node);
        }
        if matches!(index, 1 | 2) && y < 19 {
            let part = (x * 4 / bounds.width as i32) as u16 + 1;
            self.queue(app_child(index).unwrap(), Command::Activate(part));
        }
    }
    fn development_input(&mut self, bytes: [u8; 8]) {
        if !self.development.dialog() {
            return;
        }
        if let Ok(event) = PointerEvent::decode(bytes) {
            if event.sequence <= self.input.last {
                return;
            }
            self.input.last = event.sequence;
            self.input.x = (self.input.x + i32::from(event.dx)).clamp(0, 639);
            self.input.y = (self.input.y - i32::from(event.dy)).clamp(0, 479);
            self.update_cursor();
            let ordinary = event.buttons & LEFT != 0 && self.input.buttons & LEFT == 0;
            self.input.buttons = event.buttons;
            if ordinary && (70..80).contains(&self.input.y) && self.input.x >= 500 {
                self.development_cancel();
                return;
            }
            let fresh = self
                .input
                .pointer
                .as_mut()
                .and_then(|g| g.observe(event).ok())
                .unwrap_or(0);
            if fresh & LEFT != 0
                && (70..80).contains(&self.input.y)
                && (300..500).contains(&self.input.x)
            {
                self.development_confirm(event.sequence);
            }
            return;
        }
        if let Ok(event) = KeyEvent::decode(bytes) {
            if event.sequence <= self.input.last {
                return;
            }
            self.input.last = event.sequence;
            if event.key == Key::Escape {
                self.development_cancel();
                return;
            }
            if self
                .input
                .keys
                .as_mut()
                .and_then(|g| g.observe(event).ok().flatten())
                == Some(Key::Enter)
            {
                self.development_confirm(event.sequence);
            }
        }
    }
    fn shutdown_input(&mut self, bytes: [u8; 8]) {
        // No ordinary app/cursor/display work after confirmed shutdown. A
        // retained failure never silently reopens fresh I/O or drops its cut.
        if !self.shutdown.dialog() {
            return;
        }
        if let Ok(event) = PointerEvent::decode(bytes) {
            if event.sequence <= self.input.last {
                return;
            }
            self.input.last = event.sequence;
            self.input.x = (self.input.x + i32::from(event.dx)).clamp(0, 639);
            self.input.y = (self.input.y - i32::from(event.dy)).clamp(0, 479);
            self.update_cursor();
            let ordinary = event.buttons & LEFT != 0 && self.input.buttons & LEFT == 0;
            self.input.buttons = event.buttons;
            if ordinary && (70..80).contains(&self.input.y) && self.input.x >= 500 {
                self.shutdown_cancel();
                return;
            }
            let fresh = self
                .input
                .pointer
                .as_mut()
                .and_then(|gate| gate.observe(event).ok())
                .unwrap_or(0);
            if fresh & LEFT != 0
                && (70..80).contains(&self.input.y)
                && (300..500).contains(&self.input.x)
            {
                self.shutdown_confirm(event.sequence);
            }
            return;
        }
        if let Ok(event) = KeyEvent::decode(bytes) {
            if event.sequence <= self.input.last {
                return;
            }
            self.input.last = event.sequence;
            if event.key == Key::Escape {
                self.shutdown_cancel();
                return;
            }
            if self
                .input
                .keys
                .as_mut()
                .and_then(|gate| gate.observe(event).ok().flatten())
                == Some(Key::Enter)
            {
                self.shutdown_confirm(event.sequence);
            }
        }
    }
    /// Authenticated Input only. Consent uses its fresh barrier; a fenced
    /// journal permits existing current Root READ navigation without confirming
    /// or changing the retained transaction. The semantic helper rechecks scope
    /// and the accepted Inspector/Root views before forwarding any control.
    fn modal_reader_pointer(&mut self, serial: u32) {
        let policy = self.policy.as_ref().unwrap();
        if policy.hit(self.input.x, self.input.y) != Some((3, false)) {
            return;
        }
        let Ok(bounds) = policy.bounds(3) else {
            return;
        };
        let (x, y) = (self.input.x - bounds.x, self.input.y - bounds.y);
        if x < 0 || y < 0 {
            return;
        }
        let Some(node) = ev_native_inspector::consumer::hit_test(
            bounds.width as usize,
            bounds.height as usize,
            x as usize,
            y as usize,
            self.semantic.selected,
        ) else {
            return;
        };
        if self.file_notice_fenced() && node == 213 {
            return;
        }
        self.semantic_modal_reader_input(node, serial);
    }
}
