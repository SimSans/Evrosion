#![no_std]
#![no_main]
use core::sync::atomic::{AtomicBool, Ordering};
use core::{arch::global_asm, panic::PanicInfo};
use ev_graphics::{Color, Error as GraphicsError, Pixels};
use ev_native_inspector::{
    Model, Profile, consumer::Consumer, presentation::Presentation, self_tree,
};
static CONSUMER_CLAIMED: AtomicBool = AtomicBool::new(false);
static mut CONSUMER: Consumer = Consumer::new();
static mut SELF_TREE: self_tree::Session = self_tree::Session::new();
use ev_userspace_contract::root_v5::{
    Role, resources,
    surface::{Header, Producer},
};
use ev_userspace_runtime as rt;
use ev_workspace_client::{
    native::self_facts,
    ui::{Command, Event, State},
};
// SAFETY: the sole executable entry owns the scalar runtime symbols.
global_asm!(ev_userspace_runtime::start_assembly!());
// SAFETY: independently admitted eight RW/NX stack pages480..487 and both
// absent guards are selected by the measured selected M8 UI loader profile.
global_asm!(
    ".section .text",
    ".global ev_user_main",
    "ev_user_main:",
    "mov rsp,0x80001e8000",
    "and rsp,-16",
    "call ev_inspector_main",
    "ud2"
);
const BASE: usize = 1 << 39;
const SURFACE: usize = BASE + resources::APP_SURFACE_FIRST_PAGE as usize * 4096;
// SAFETY: only the fixed measured scalar entry calls this symbol with the
// actual retained readonly V1 startup page and separately admitted surface.
#[unsafe(no_mangle)]
extern "C" fn ev_inspector_main(record: u64, length: u64, bound: u64) -> ! {
    require(
        length == ev_userspace_contract::SIZE as u64 && record as usize == BASE + 509 * 4096,
        1610,
    );
    // SAFETY: exact initialized retained readonly startup extent checked above.
    let bytes = unsafe { core::slice::from_raw_parts(record as *const u8, length as usize) };
    let profile = Profile::parse(bytes).unwrap_or_else(|_| rt::exit(1611));
    let handles = profile.handles;
    for (handle, rights) in handles.into_iter().zip([7, 8, 8, 272, 7, 272]) {
        let r = rt::inspect(handle, rights);
        require(r.status == 0 && r.value == 0 && r.capability == 0, 1612);
    }
    let facts = self_facts().unwrap_or_else(|_| rt::exit(1613));
    require(
        facts.process == profile.process && facts.registered_incarnation == profile.incarnation,
        1614,
    );
    let mut surface = Surface {
        header: Header {
            producer: Producer::Application,
            instance: 4,
            process: facts.process,
            thread: facts.thread,
            incarnation: facts.registered_incarnation,
            surface_object: Role::InspectorSurface.selector(),
            surface_generation: facts.process,
            frame: 1,
            view_revision: 1,
            model_revision: 1,
            width: 320,
            height: 180,
            stride_bytes: 1280,
            payload_bytes: 230400,
            mapping_epoch: 1,
            protected_scope_nonce: 0,
        },
        fenced: false,
    };
    let mut model = Model::new();
    require(!CONSUMER_CLAIMED.swap(true, Ordering::AcqRel), 1625);
    // SAFETY: the sole actual native entry claims this process-private RW/NX
    // static exactly once; no other thread or mapping can alias the consumer.
    let consumer = unsafe { &mut *core::ptr::addr_of_mut!(CONSUMER) };
    // SAFETY: the same process-once claim also owns this separate private
    // bounded outbox. It shares no external-consumer or File2 window storage.
    let self_tree = unsafe { &mut *core::ptr::addr_of_mut!(SELF_TREE) };
    let mut accepted_surface = None;
    let mut accepted_reader = None;
    let mut local_focus = None;
    let mut configured = false;
    let mut scene_ready = false;
    let mut scene_low = None;
    let mut focused = false;
    let mut presentation = Presentation::new();
    let mut refresh_desired = false;
    let mut ordinary = self_tree::ordinary::Gate::new();
    let mut last_state = State::Loading;
    loop {
        require(rt::execution::live(bound, now()), 1615);
        ordinary.tick(now());
        if ordinary.blocked() {
            surface.fenced = true;
        }
        for _ in 0..16 {
            let r = rt::receive(handles[3]);
            if r.status == 2 {
                require(r.value == 0 && r.capability == 0, 1616);
                break;
            }
            require(r.status == 0 && r.capability == 0, 1617);
            let bytes = r.value.to_le_bytes();
            if bytes[..2] == *b"IC" {
                let scope = self_tree.ordinary_scope(
                    ev_workspace_client::semantic::Header {
                        nonce: 1,
                        page: 0,
                        pages: 1,
                        model: surface.header.model_revision,
                        view: surface.header.view_revision,
                        frame: surface.header.frame,
                        mapping_epoch: surface.header.mapping_epoch,
                        width: surface.header.width as u16,
                        height: surface.header.height as u16,
                        keyboard: 0,
                        modal: 0,
                    },
                    consumer,
                    local_focus,
                    configured
                        && focused
                        && scene_ready
                        && !presentation.pending()
                        && !refresh_desired
                        && !surface.fenced
                        && accepted_reader == Some(true)
                        && accepted_surface == Some(surface.header),
                );
                let result = self_tree::ordinary::Request::decode(bytes).and_then(|request| {
                    ordinary.receive(request, scope, now(), deadline(bound, 512))
                });
                match result {
                    Ok(Some(control)) => {
                        // No Present may occur between this ordinary action
                        // and Root's exact original-binding validation/ack.
                        let intent = consumer.activate(control);
                        if ordinary.record_reply(intent, now()).is_err() {
                            surface.fenced = true;
                        }
                        presentation.urgent();
                    }
                    Ok(None) => (),
                    Err(_) => {
                        ordinary.fence();
                        surface.fenced = true;
                        notify(handles[2], Event::Refused(6), bound);
                    }
                }
                continue;
            }
            if bytes[..2] == *b"IS" {
                let result = self_tree::Request::decode(bytes).and_then(|request| {
                    self_tree.request(
                        request,
                        ev_workspace_client::semantic::Header {
                            nonce: 1,
                            page: 0,
                            pages: 1,
                            model: surface.header.model_revision,
                            view: surface.header.view_revision,
                            frame: surface.header.frame,
                            mapping_epoch: surface.header.mapping_epoch,
                            width: surface.header.width as u16,
                            height: surface.header.height as u16,
                            keyboard: 0,
                            modal: 0,
                        },
                        &model,
                        consumer,
                        local_focus,
                        configured
                            && scene_ready
                            && !presentation.pending()
                            && !refresh_desired
                            && !ordinary.holding()
                            && !surface.fenced
                            && accepted_reader == Some(consumer.active())
                            && accepted_surface == Some(surface.header),
                    )
                });
                if result.is_err() {
                    notify(handles[2], Event::Refused(6), bound);
                }
                continue;
            }
            if bytes[..2] == [0x41, 1] {
                if !configured {
                    notify(handles[2], Event::Refused(6), bound);
                    continue;
                }
                match consumer.receive(bytes) {
                    Ok(true) => {
                        surface.header.view_revision = u64::from(consumer.presentation_view());
                        presentation.urgent();
                    }
                    Ok(false) => (),
                    Err(_) => notify(handles[2], Event::Refused(6), bound),
                }
                continue;
            }
            let Ok(mut command) = Command::decode(bytes) else {
                notify(handles[2], Event::Refused(1), bound);
                continue;
            };
            // Leaving only removes local focus. It remains possible after a
            // source/focus transition, without changing any retained outbox.
            if command == Command::Activate(self_tree::NAV_LEAVE) {
                local_focus = None;
                presentation.urgent();
                continue;
            }
            // Root explicitly forwards actual focused navigation. Absolute
            // entry avoids toggle drift after provider/focus replacement.
            if configured && focused && scene_ready && !surface.fenced {
                match command {
                    Command::Activate(self_tree::NAV_ENTER) => {
                        local_focus = self_tree::next_control(
                            &model,
                            consumer,
                            None,
                            true,
                            surface.header.width as u16,
                            surface.header.height as u16,
                        );
                        presentation.urgent();
                        continue;
                    }
                    Command::Insert('?') => {
                        local_focus = if local_focus.is_some() {
                            None
                        } else {
                            self_tree::next_control(
                                &model,
                                consumer,
                                None,
                                true,
                                surface.header.width as u16,
                                surface.header.height as u16,
                            )
                        };
                        presentation.urgent();
                        continue;
                    }
                    Command::Navigate { key, extend: false }
                        if local_focus.is_some()
                            && matches!(
                                key,
                                ev_workspace_client::ui::Navigation::Left
                                    | ev_workspace_client::ui::Navigation::Right
                                    | ev_workspace_client::ui::Navigation::Up
                                    | ev_workspace_client::ui::Navigation::Down
                            ) =>
                    {
                        local_focus = self_tree::next_control(
                            &model,
                            consumer,
                            local_focus,
                            matches!(
                                key,
                                ev_workspace_client::ui::Navigation::Right
                                    | ev_workspace_client::ui::Navigation::Down
                            ),
                            surface.header.width as u16,
                            surface.header.height as u16,
                        );
                        presentation.urgent();
                        continue;
                    }
                    Command::Insert('\n') if local_focus.is_some() => {
                        let Some(action) = self_tree::visible_control(
                            &model,
                            consumer,
                            local_focus.unwrap(),
                            surface.header.width as u16,
                            surface.header.height as u16,
                        ) else {
                            continue;
                        };
                        command = Command::Activate(action);
                    }
                    _ => (),
                }
            }
            match command {
                Command::Configure {
                    instance: 4,
                    mapping_epoch,
                } if !configured => {
                    surface.header.mapping_epoch = u64::from(mapping_epoch);
                    configured = true;
                    scene_ready = false;
                    notify(handles[2], Event::Ready(4), bound);
                }
                Command::Configure { .. } => notify(handles[2], Event::Refused(1), bound),
                Command::ScenePart { high: false, word } => {
                    scene_low = Some(word);
                    scene_ready = false;
                }
                Command::ScenePart { high: true, word } => {
                    if let Some(low) = scene_low.take() {
                        let revision = (u64::from(word) << 32) | u64::from(low);
                        if !matches!(revision, 0 | u64::MAX) {
                            surface.header.model_revision = revision;
                            scene_ready = true;
                            presentation.urgent();
                        }
                    }
                }
                Command::Resize { width, height } => {
                    consumer.geometry(width, height);
                    surface.header.width = u32::from(width);
                    surface.header.height = u32::from(height);
                    surface.header.stride_bytes = u32::from(width) * 4;
                    surface.header.payload_bytes = u32::from(width) * u32::from(height) * 4;
                    scene_ready = false;
                    presentation.urgent();
                }
                Command::Focus(value) => {
                    focused = value;
                    if !value {
                        local_focus = None;
                    }
                    presentation.urgent();
                }
                Command::InfoWord { field, high, word } if configured && !consumer.active() => {
                    match model.put(field, high, word) {
                        Ok(true) => {
                            // Root binds Display's accepted view3 to this exact
                            // committed snapshot. Other local repaint changes
                            // do not fabricate a new snapshot identity.
                            surface.header.view_revision =
                                u64::from(model.snapshot().unwrap().view());
                            if refresh_desired {
                                presentation.urgent();
                                refresh_desired = false;
                            } else {
                                presentation.stats();
                            }
                        }
                        Ok(false) => (),
                        Err(_) => {
                            notify(handles[2], Event::Refused(6), bound);
                            presentation.urgent();
                        }
                    }
                }
                Command::Activate(node)
                    if configured
                        && (focused
                            || consumer.modal_reader_control(node)
                            || consumer.protected_confirm(node))
                        && scene_ready
                        && !surface.fenced =>
                {
                    if consumer.active() {
                        if let Some(intent) = consumer.activate(node) {
                            notify_bytes(
                                handles[2],
                                intent.encode().unwrap_or_else(|_| rt::exit(1626)),
                                bound,
                            );
                        }
                        presentation.urgent();
                    } else if node == 14 {
                        if let Some(snapshot) = model.snapshot() {
                            let intent = ev_userspace_contract::root_v5::assistive::Intent {
                                kind: ev_userspace_contract::root_v5::assistive::IntentKind::Enable,
                                index: 0,
                                view: snapshot.view(),
                            };
                            notify_bytes(
                                handles[2],
                                intent.encode().unwrap_or_else(|_| rt::exit(1626)),
                                bound,
                            );
                        }
                    } else if (100..106).contains(&node) {
                        model.select((node - 100) as u8);
                        presentation.urgent();
                    } else if let Ok(action) = u8::try_from(node)
                        && let Some(event) = model.action(action)
                    {
                        notify(handles[2], event, bound);
                        if matches!(action, 1..=3) {
                            // A single desired refresh applies to its next
                            // complete sample, never a repaint of old metrics.
                            refresh_desired = true;
                        }
                    }
                }
                Command::Close { .. } => {
                    if surface.fenced {
                        notify(handles[2], Event::Refused(3), bound);
                        continue;
                    }
                    let r = rt::call(rt::syscall::CLOSE, handles[1], 0, 0);
                    require(r.status == 0 && r.value == 0 && r.capability == 0, 1618);
                    notify(handles[2], Event::Closed, bound);
                    rt::exit(0)
                }
                _ => (),
            }
        }
        // Root-fed metadata never requires a File lease or a second frame owner.
        // Refuse unsolicited grants without reading Selection or file bytes.
        let r = rt::receive(handles[5]);
        match r.status {
            0 => {
                require(r.capability != 0, 1619);
                let closed = rt::call(rt::syscall::CLOSE, r.capability, 0, 0);
                require(
                    closed.status == 0 && closed.value == 0 && closed.capability == 0,
                    1620,
                );
                notify(handles[2], Event::Refused(4), bound);
            }
            2 => require(r.value == 0 && r.capability == 0, 1621),
            _ => rt::exit(1622),
        }
        let state = if surface.fenced {
            State::Uncertain
        } else if !consumer.active() && model.snapshot().is_none() {
            State::Loading
        } else {
            State::Saved
        };
        if state != last_state {
            notify(handles[2], Event::State(state), bound);
            last_state = state;
        }
        if presentation.ready(now())
            && !ordinary.holding()
            && configured
            && scene_ready
            && !surface.fenced
            && ((consumer.active() && consumer.paintable())
                || (!consumer.active() && model.paintable(surface.header.view_revision)))
        {
            if consumer.active() {
                ev_native_inspector::consumer::render(&mut surface, consumer)
            } else {
                ev_native_inspector::render(&mut surface, &model, focused)
            }
            .unwrap_or_else(|_| rt::exit(1623));
            if let Some(id) = local_focus {
                if self_tree::visible_control(
                    &model,
                    consumer,
                    id,
                    surface.header.width as u16,
                    surface.header.height as u16,
                )
                .is_some()
                {
                    self_tree::render_focus(&mut surface, consumer, id)
                        .unwrap_or_else(|_| rt::exit(1623));
                } else {
                    local_focus = None;
                }
            }
            match surface.present(handles[1], bound, &mut presentation) {
                Ok(true) => {
                    accepted_surface = Some(surface.header);
                    accepted_reader = Some(consumer.active());
                    if let Some(marker) = consumer.presented() {
                        notify_bytes(handles[2], marker, bound);
                        consumer.marker_sent();
                    }
                }
                Ok(false) => {
                    accepted_surface = None;
                    accepted_reader = None;
                    scene_ready = false;
                }
                Err(()) => {
                    accepted_surface = None;
                    accepted_reader = None;
                    surface.fenced = true;
                    notify(handles[2], Event::Refused(5), bound);
                }
            }
        }
        if let Some(bytes) = self_tree.next() {
            let r = rt::send(handles[2], bytes);
            require(r.value == 0 && r.capability == 0, 1627);
            match r.status {
                0 => require(self_tree.sent(bytes).is_ok(), 1628),
                2 => (), // original immutable word remains held until status0
                _ => rt::exit(1629),
            }
        }
        if let Some(bytes) = ordinary.next() {
            let r = rt::send(handles[2], bytes);
            require(r.value == 0 && r.capability == 0, 1630);
            match r.status {
                0 => require(ordinary.sent(bytes).is_ok(), 1631),
                2 => (), // exact original reply remains held, cut never renewed
                _ => rt::exit(1632),
            }
        }
        let r = rt::yield_now();
        require(r.status == 0 && r.value == 0 && r.capability == 0, 1624);
    }
}
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    rt::exit(1699)
}
fn require(ok: bool, code: u64) {
    if !ok {
        rt::exit(code);
    }
}
fn now() -> u64 {
    let r = rt::monotonic();
    require(
        r.status == 0 && r.capability == 0 && r.value != u64::MAX,
        1600,
    );
    r.value
}
fn deadline(bound: u64, span: u64) -> u64 {
    rt::execution::deadline(bound, now(), span).unwrap_or_else(|_| rt::exit(1601))
}
fn notify(events: u64, event: Event, bound: u64) {
    let bytes = event.encode().unwrap_or_else(|_| rt::exit(1602));
    notify_bytes(events, bytes, bound);
}
fn notify_bytes(events: u64, bytes: [u8; 8], bound: u64) {
    let cut = deadline(bound, 512);
    loop {
        let r = rt::send(events, bytes);
        require(r.value == 0 && r.capability == 0, 1603);
        match r.status {
            0 => return,
            2 => {
                require(now() < cut, 1604);
                let _ = rt::yield_now();
            }
            _ => rt::exit(1605),
        }
    }
}
struct Surface {
    header: Header,
    fenced: bool,
}
impl Pixels for Surface {
    fn dimensions(&self) -> (usize, usize) {
        (self.header.width as usize, self.header.height as usize)
    }
    fn write(&mut self, x: usize, y: usize, color: Color) -> Result<(), GraphicsError> {
        if self.fenced || x >= self.header.width as usize || y >= self.header.height as usize {
            return Err(GraphicsError::Bounds);
        }
        let offset = 256 + y * self.header.stride_bytes as usize + x * 4;
        if offset + 4 > resources::APP_SURFACE_PAGES as usize * 4096 {
            return Err(GraphicsError::Bounds);
        }
        // SAFETY: exact separately admitted RW/NX app surface, one-thread sole
        // writer, checked extent. No write occurs while Present is retained.
        unsafe { ((SURFACE + offset) as *mut u32).write_volatile(color.0 & 0x00ff_ffff) };
        Ok(())
    }
}
impl Surface {
    fn present(
        &mut self,
        endpoint: u64,
        bound: u64,
        presentation: &mut Presentation,
    ) -> Result<bool, ()> {
        if self.fenced {
            return Err(());
        }
        self.header.frame = self
            .header
            .frame
            .checked_add(1)
            .filter(|v| *v != u64::MAX)
            .ok_or(())?;
        if presentation.begin(now(), self.header).is_err() {
            self.fenced = true;
            return Err(());
        }
        let bytes = self.header.encode().map_err(|_| {
            presentation.uncertain();
            self.fenced = true;
        })?;
        for (i, byte) in bytes.into_iter().enumerate() {
            // SAFETY: owned initialized256B header before RPC acceptance; no
            // shared Rust reference is retained through the actual syscall.
            unsafe { ((SURFACE + i) as *mut u8).write_volatile(byte) };
        }
        let outcome = match rt::rpc::call(
            endpoint,
            self.header.frame.to_le_bytes(),
            deadline(bound, resources::RPC_TICKS),
        ) {
            Ok(reply) if u64::from_le_bytes(reply) == self.header.frame => Some(true),
            Ok(reply) if u64::from_le_bytes(reply) == u64::MAX => Some(false),
            _ => None,
        };
        if let Some(accepted) = outcome
            && presentation.completed(self.header, accepted, now()).is_ok()
        {
            return Ok(accepted);
        }
        presentation.uncertain();
        self.fenced = true;
        Err(())
    }
}
