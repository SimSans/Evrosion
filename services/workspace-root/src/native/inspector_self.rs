//! Actual Inspector39 provenance and private, nonrecursive own-tree controller.
use super::*;
use core::sync::atomic::{AtomicBool, Ordering};
use ev_native_inspector::self_tree::{NAV_ENTER, NAV_LEAVE};
use ev_userspace_contract::root_v5::display_control::Slot;
use ev_workspace_root::inspector_self::{
    Binding, Capture, EnterWait, EntryScope, EntryWait, OrdinaryReceipt, Outcome, Phase,
    ReaderOutcome, ReaderPhase, ReaderTransfer, StatsRefresh,
};
use ev_workspace_root::semantic::Presented;

pub(super) struct State {
    capture: Capture,
    pub enabled: bool,
    pub refresh_stats: StatsRefresh,
    pub entry: EntryWait,
    enter: EnterWait,
    ordinary: Option<OrdinaryReceipt>,
    reader: ReaderTransfer,
    wait_frame: Option<u64>,
    capture_by: u64,
    page: u8,
    published: u64,
    last_reader: bool,
}
impl State {
    const fn new() -> Self {
        Self {
            capture: Capture::new(),
            enabled: false,
            refresh_stats: StatsRefresh::new(),
            entry: EntryWait::new(),
            enter: EnterWait::new(),
            ordinary: None,
            reader: ReaderTransfer::new(),
            wait_frame: None,
            capture_by: 0,
            page: 1,
            published: 0,
            last_reader: false,
        }
    }
}
static CLAIMED: AtomicBool = AtomicBool::new(false);
static mut STATE: State = State::new();
pub(super) fn claim() -> &'static mut State {
    require(!CLAIMED.swap(true, Ordering::AcqRel), 1680);
    // SAFETY: sole Root entry claims initialized private RW/NX resident state
    // once. No other thread or mapping gets a reference to this receiver.
    unsafe { &mut *core::ptr::addr_of_mut!(STATE) }
}
impl Root<'_> {
    /// Drain only this private self-description stream under the shutdown
    /// controller's original absolute cut. No new capture or UI intent starts.
    /// This proves no File/window/application/global shutdown quiescence.
    pub(super) fn inspector_self_shutdown(&mut self, cut: u64) -> Result<bool, ()> {
        self.inspector_self.entry.cancel();
        self.inspector_self.enter.cancel();
        self.inspector_self.ordinary = None;
        self.inspector_self_reader_tick(None, now());
        match self.inspector_self.reader.phase() {
            ReaderPhase::Idle => (),
            ReaderPhase::Blocked => return Err(()),
            _ => return Ok(false),
        }
        self.inspector_self.enabled = false;
        self.inspector_self.refresh_stats.clear();
        self.inspector_self.published = 0;
        self.inspector_self.capture.invalidate(cut);
        self.inspector_self.capture.tick(now(), cut);
        match self.inspector_self.capture.phase() {
            Phase::Idle => Ok(true),
            Phase::Blocked => Err(()),
            Phase::AbortSend | Phase::Aborting => {
                if let Some(bytes) = self.inspector_self.capture.next() {
                    match send(self.channel(Channel::InspectorControl), bytes) {
                        Ok(true) => self.inspector_self.capture.sent(bytes).map_err(|_| ())?,
                        Ok(false) => (),
                        Err(()) => {
                            self.inspector_self.capture.transport_failed();
                            return Err(());
                        }
                    }
                }
                Ok(false)
            }
            _ => Err(()),
        }
    }
    pub(super) fn inspector_self_binding(&mut self) -> Option<Binding> {
        let actor = self.actor(Child::Inspector);
        if actor.failed
            || !actor.ready
            || self.shutdown.active()
            || self.scene_dirty
            || self.owner.pending.is_some()
            || self.policy.as_ref()?.focused() != Some(3)
        {
            return None;
        }
        let context = self.inspector_self_context()?;
        let (frame, view) = self.accepted_view(Slot::Inspector)?;
        if view != u64::from(context.view) {
            return None;
        }
        let policy = self.policy.as_ref()?;
        let window = policy.ids[3]?;
        let actual = policy.desktop.window(window).ok()?;
        if actual.owner != ev_workspace_root::policy::owner(actor.identity)
            || actual.surface.object != Slot::Inspector.source().selector()
            || actual.surface.generation != actor.identity.process
        {
            return None;
        }
        Some(Binding {
            owner: actor.identity,
            window,
            context,
            presented: Presented {
                model: policy.scene,
                view,
                frame,
                mapping_epoch: u64::from(actor.mapping_epoch),
                width: u16::try_from(actual.bounds.width).ok()?,
                height: u16::try_from(actual.bounds.height).ok()?,
            },
        })
    }
    /// Cheap Root-owned cancellation facts while an accepted read is partial.
    /// This intentionally cannot certify a current Display frame and is never
    /// used to publish a tree, activate a node or consume an ordinary reply.
    fn inspector_self_recorded_scope_matches(&self, old: Binding) -> bool {
        let actor = self.actor(Child::Inspector);
        let Some(policy) = self.policy.as_ref() else {
            return false;
        };
        if actor.failed
            || !actor.ready
            || actor.identity != old.owner
            || self.shutdown.active()
            || self.scene_dirty
            || self.owner.pending.is_some()
            || policy.focused() != Some(3)
            || policy.ids[3] != Some(old.window)
            || policy.scene != old.presented.model
            || u64::from(actor.mapping_epoch) != old.presented.mapping_epoch
            || self.inspector_self_recorded_context() != Some(old.context)
        {
            return false;
        }
        policy.desktop.window(old.window).is_ok_and(|actual| {
            actual.visible
                && actual.owner == ev_workspace_root::policy::owner(old.owner)
                && actual.surface.object == Slot::Inspector.source().selector()
                && actual.surface.generation == old.owner.process
                && (actual.bounds.width, actual.bounds.height)
                    == (
                        u32::from(old.presented.width),
                        u32::from(old.presented.height),
                    )
        })
    }
    fn inspector_self_entry_scope(&self) -> Option<EntryScope> {
        let actor = self.actor(Child::Inspector);
        let policy = self.policy.as_ref()?;
        if actor.failed || !actor.ready || self.scene_dirty || policy.focused() != Some(3) {
            return None;
        }
        Some(EntryScope {
            owner: actor.identity,
            window: policy.ids[3]?,
            model: policy.scene,
        })
    }
    fn inspector_self_disable(&mut self, unavailable: bool) {
        self.inspector_self.entry.cancel();
        self.inspector_self.enter.cancel();
        // Input and an already queued IR can share one receive batch. Deny
        // ordinary authority now, before NAV_LEAVE produces a different frame;
        // keep any accepted words/reply/nonce/cut for their exact transport.
        self.inspector_self.reader.tick(None, None, now());
        self.inspector_self.ordinary = None;
        self.inspector_self.enabled = false;
        self.inspector_self.refresh_stats.clear();
        self.inspector_self.published = 0;
        self.inspector_self
            .capture
            .invalidate(deadline(v5::resources::FILE_TRANSACTION_TICKS));
        self.queue(Child::Inspector, Command::Activate(NAV_LEAVE));
        self.inspector.resume();
        if unavailable {
            self.status =
                b"Inspector own controls unavailable; any partial stream remains retained";
            self.owner.dirty = true;
        } else if self.semantic.phase == semantic::Phase::Off {
            self.status = b"Inspector own controls left; no current control is verified";
            self.owner.dirty = true;
        }
    }
    fn inspector_self_wait_after(&mut self, frame: u64) {
        self.inspector_self.enter.cancel();
        self.inspector_self
            .capture
            .invalidate(deadline(v5::resources::FILE_TRANSACTION_TICKS));
        self.inspector_self.published = 0;
        self.inspector_self.page = 1;
        self.inspector_self.wait_frame = Some(frame);
        self.inspector_self.capture_by = deadline(v5::resources::FILE_TRANSACTION_TICKS);
        if self.semantic.phase == semantic::Phase::Off {
            self.status = b"Inspector current control pending; verifying accepted frame";
            self.owner.dirty = true;
        }
    }
    fn inspector_self_ready_status(&mut self, control: u16) {
        if !matches!(
            self.semantic.phase,
            semantic::Phase::Off | semantic::Phase::Ready
        ) {
            return;
        }
        // Public local control names only. Nested provider labels/text are
        // never copied into Inspector's own status or self-description.
        self.status = match control {
            1 => b"Inspector control ready: Refresh",
            2 => b"Inspector control ready: Next page",
            3 => b"Inspector control ready: Previous page",
            4 => b"Inspector control ready: Focus selected process",
            5 => b"Inspector control ready: Request stop",
            6 => b"Inspector control ready: Request restart",
            7 => b"Inspector control ready: Request file revoke",
            8 => b"Inspector control ready: Layer",
            9 => b"Inspector control ready: Contrast",
            10 => b"Inspector control ready: Focus outline",
            11 => b"Inspector control ready: Scale",
            12 => b"Inspector control ready: Request shutdown",
            13 => b"Inspector control ready: Request restart all",
            14 => b"Inspector control ready: Request assistive access",
            100..=105 => b"Inspector control ready: Process row",
            201 => b"Inspector control ready: Previous node or text page",
            202 => b"Inspector control ready: Next node or text page",
            203 => b"Inspector control ready: Assistive focus",
            204 => b"Inspector control ready: Activate source node",
            205 => b"Inspector control ready: Keyboard focus",
            206 => b"Inspector control ready: Expand",
            207 => b"Inspector control ready: Read source name",
            208 => b"Inspector control ready: Read document text",
            209 => b"Inspector control ready: Refresh",
            210 => b"Inspector control ready: Previous source",
            211 => b"Inspector control ready: Next source",
            212 => b"Inspector control ready: Revoke semantic access",
            214 => b"Inspector control ready: Cancel",
            215 => b"Inspector control ready: Select",
            216 => b"Inspector control ready: Scroll up",
            217 => b"Inspector control ready: Scroll down",
            218 => b"Inspector control ready: More text",
            300..=315 => b"Inspector control ready: Source row under original scope",
            _ => b"Inspector current control is unavailable",
        };
        self.owner.dirty = true;
    }
    pub(super) fn inspector_self_hold_ordinary(&mut self, node: u16, by: u64) -> bool {
        if !self.inspector_self.enabled {
            return true;
        }
        if self.inspector_self.ordinary.is_some() {
            return false;
        }
        let Some(binding) = self.inspector_self_binding() else {
            return false;
        };
        let Some(receipt) = OrdinaryReceipt::new(
            binding,
            node,
            if binding.context.reader {
                self.semantic.selected
            } else {
                0
            },
            if binding.context.reader {
                self.semantic.candidate.nodes().len() as u8
            } else {
                0
            },
            by,
        ) else {
            return false;
        };
        self.inspector_self.ordinary = Some(receipt);
        true
    }
    pub(super) fn inspector_self_abandon_ordinary(&mut self) {
        self.inspector_self.ordinary = None;
    }
    fn inspector_self_publication(&self, binding: Option<Binding>) -> Option<u64> {
        let binding = binding?;
        Some(
            self.policy
                .as_ref()?
                .desktop
                .window(binding.window)
                .ok()?
                .view_revision,
        )
    }
    pub(super) fn inspector_self_start_reader(&mut self, node: u16, by: u64) -> bool {
        let Some(binding) = self.inspector_self_binding() else {
            return false;
        };
        let publication = self.inspector_self.published;
        if !binding.context.reader
            || now() >= by
            || publication == 0
            || self.inspector_self_publication(Some(binding)) != Some(publication)
            || self.inspector_self.capture.control(binding) != Some(node)
        {
            return false;
        }
        let started = self
            .inspector_self
            .reader
            .begin(
                binding,
                publication,
                node,
                self.inspector_self.capture.nonce(),
                self.semantic.selected,
                self.semantic.candidate.nodes().len() as u8,
                by,
            )
            .is_ok();
        if started {
            // The accepted four-word ordinary request is already immutable.
            // Send it before cosmetic Root presentation or another probe.
            self.inspector_self_reader_send();
        }
        started
    }
    fn inspector_self_reader_tick(&mut self, current: Option<Binding>, time: u64) {
        let publication = self.inspector_self_publication(current);
        self.inspector_self.reader.tick(current, publication, time);
        self.inspector_self_reader_send();
    }
    fn inspector_self_reader_send(&mut self) {
        if !self.inspector_self.reader.pending() {
            return;
        }
        let actor = self.actor(Child::Inspector);
        if actor.failed
            || self
                .inspector_self
                .reader
                .binding()
                .is_none_or(|b| b.owner != actor.identity)
        {
            self.inspector_self.reader.failed();
            return;
        }
        // At most one four-word request, or its one exact transport Ack.
        // Busy stops this batch without changing bytes or the original cut.
        for _ in 0..4 {
            let Some(bytes) = self.inspector_self.reader.next() else {
                break;
            };
            if now() >= self.inspector_self.reader.by() {
                self.inspector_self.reader.failed();
                break;
            }
            match send(self.channel(Channel::InspectorControl), bytes) {
                Ok(true) => {
                    if self.inspector_self.reader.sent(bytes, now()).is_err() {
                        break;
                    }
                }
                Ok(false) => break,
                Err(()) => {
                    self.inspector_self.reader.failed();
                    break;
                }
            }
        }
    }
    pub(super) fn inspector_self_ordinary_intent(
        &mut self,
        intent: ev_userspace_contract::root_v5::assistive::Intent,
    ) -> bool {
        if !self.inspector_self.enabled {
            return true;
        }
        let Some(receipt) = self.inspector_self.ordinary.take() else {
            return false;
        };
        let current = self.inspector_self_binding();
        receipt.accept(current, intent, now())
    }
    fn inspector_self_enter_tick(&mut self, current: Option<Binding>, time: u64) {
        if !self.inspector_self.enter.pending() {
            return;
        }
        let publication = current.and_then(|binding| {
            self.policy
                .as_ref()?
                .desktop
                .window(binding.window)
                .ok()
                .map(|w| w.view_revision)
        });
        let ready = self.inspector_self.enter.ready(
            current,
            time,
            &self.inspector_self.capture,
            self.inspector_self.published,
            publication,
        );
        if !self.inspector_self.enter.pending() {
            self.status =
                b"Inspector Enter expired or current control changed; no control forwarded";
            self.owner.dirty = true;
            return;
        }
        let Some((control, by)) = ready else {
            return;
        };
        let binding = current.unwrap();
        let transferred = if binding.context.reader {
            if matches!(control, 212 | 214) {
                self.semantic_revoke(true);
                true
            } else {
                self.semantic_click_until(control, by)
            }
        } else {
            self.inspector_click_until(control, by)
        };
        if transferred {
            // From here only the immutable outbox/held callback receipt owns
            // delivery. No tick can retry this physical Enter after transfer.
            self.inspector_self.enter.cancel();
            self.inspector_self_wait_after(binding.presented.frame);
            self.status = b"Inspector Enter forwarded once for the verified current control";
            self.owner.dirty = true;
        }
    }
    /// Called only by the actual focused Input route. Tab/Esc/Root controls
    /// are handled independently before this path. No packet can invoke it.
    pub(super) fn inspector_self_keyboard(&mut self, command: Command) -> bool {
        use ev_workspace_client::ui::Navigation;
        if command == Command::Insert('?') {
            if self.inspector_self.enabled || self.inspector_self.entry.pending() {
                self.inspector_self_disable(false);
                return true;
            }
            if !matches!(
                self.inspector_self.capture.phase(),
                Phase::Idle | Phase::Ready
            ) {
                self.status =
                    b"Inspector own controls unavailable; previous exact stream is still retained";
                self.owner.dirty = true;
                return true;
            }
            if let Some(scope) = self.inspector_self_entry_scope() {
                let by = deadline(v5::resources::FILE_TRANSACTION_TICKS);
                require(self.inspector_self.entry.request(scope, by).is_ok(), 1683);
                self.status = b"Inspector own entry pending; waiting for the accepted frame";
                self.owner.dirty = true;
            }
            return true;
        }
        if !self.inspector_self.enabled {
            return self.inspector_self.entry.pending();
        }
        let Some(binding) = self.inspector_self_binding() else {
            return true;
        };
        if command == Command::Insert('\n') {
            if !self.inspector_self.enter.pending() {
                let by = deadline(v5::resources::FILE_TRANSACTION_TICKS);
                require(self.inspector_self.enter.request(binding, by).is_ok(), 1686);
                self.status = b"Inspector Enter pending; waiting for the exact current control";
                self.owner.dirty = true;
            }
            return true;
        }
        let published = self.inspector_self.published;
        if published == 0
            || self
                .policy
                .as_ref()
                .unwrap()
                .desktop
                .window(binding.window)
                .ok()
                .is_none_or(|w| w.view_revision != published)
        {
            return true;
        }
        if self.inspector_self.capture.control(binding).is_none() {
            return true;
        }
        if matches!(
            command,
            Command::Navigate {
                key: Navigation::Left | Navigation::Right | Navigation::Up | Navigation::Down,
                extend: false
            }
        ) && self.queue(Child::Inspector, command)
        {
            self.inspector_self_wait_after(binding.presented.frame);
        }
        true
    }
    pub(super) fn inspector_self_event(&mut self, child: Child, bytes: [u8; 8]) -> bool {
        if bytes[..2] == *b"IR" {
            if child != Child::Inspector {
                return true;
            }
            let sender = self.actor(child).identity;
            let current = self.inspector_self_binding();
            let publication = self.inspector_self_publication(current);
            let reply = ev_native_inspector::self_tree::ordinary::Reply::decode(bytes);
            let outcome = match reply {
                Ok(reply) => {
                    self.inspector_self
                        .reader
                        .receive(sender, reply, current, publication, now())
                }
                Err(_) => {
                    self.inspector_self.reader.failed();
                    return true;
                }
            };
            match outcome {
                Ok(ReaderOutcome::Intent(intent)) => {
                    self.semantic_own_intent(intent, self.inspector_self.reader.by())
                }
                Ok(ReaderOutcome::Local) => {
                    self.status =
                        b"Inspector reader local intent acknowledged; no source action requested";
                    self.owner.dirty = true;
                }
                Ok(ReaderOutcome::Rejected) => {
                    self.status =
                        b"Inspector reader control changed or expired; source action refused";
                    self.owner.dirty = true;
                }
                Err(_) => (),
            }
            // The exact transport acknowledgment is sent only after full
            // binding validation and existing source policy have run. It has
            // no protected-confirmation or source permission meaning.
            self.inspector_self_reader_send();
            return true;
        }
        if bytes[..2] != *b"IT" {
            return false;
        }
        if child != Child::Inspector {
            return true;
        }
        // event(child) came only from actual39 process/thread matching the
        // installed Actor. No packet source/slot/identity is consulted.
        let sender = self.actor(child).identity;
        self.inspector_self
            .capture
            .tick(now(), deadline(v5::resources::FILE_TRANSACTION_TICKS));
        let field = u16::from_le_bytes([bytes[2], bytes[3]]);
        let after = if field == ev_workspace_client::semantic::COMMIT {
            self.inspector_self_binding()
        } else {
            None
        };
        self.inspector_self
            .capture
            .tick(now(), deadline(v5::resources::FILE_TRANSACTION_TICKS));
        let outcome = self.inspector_self.capture.receive(
            sender,
            bytes,
            after,
            deadline(v5::resources::FILE_TRANSACTION_TICKS),
        );
        if outcome == Outcome::Complete {
            let header = self.inspector_self.capture.candidate().header();
            if header.keyboard == 0 {
                let last = if header.pages == 4 { 2 } else { 3 };
                if header.page < last {
                    self.inspector_self.page = header.page + 1;
                } else {
                    self.inspector_self_disable(true);
                }
                return true;
            }
            let Some(binding) = self.inspector_self.capture.binding() else {
                return true;
            };
            let policy = self.policy.as_mut().unwrap();
            let Ok(window) = policy.desktop.window(binding.window) else {
                self.inspector_self_disable(true);
                return true;
            };
            let bounds = window.bounds;
            let Some(publication) = window
                .view_revision
                .checked_add(1)
                .filter(|n| *n != u64::MAX)
            else {
                rt::exit(1681);
            };
            let Ok(tree) = ev_workspace_root::semantic::project(
                self.inspector_self.capture.candidate(),
                binding.presented,
                bounds,
                publication,
            ) else {
                self.inspector_self_disable(true);
                return true;
            };
            if policy
                .desktop
                .publish_presented_view(
                    ev_workspace_root::policy::owner(binding.owner),
                    binding.window,
                    publication,
                    tree,
                    Some(header.keyboard),
                )
                .is_err()
            {
                self.inspector_self_disable(true);
                return true;
            }
            self.inspector_self.published = publication;
            if let Some(control) = self.inspector_self.capture.control(binding) {
                self.inspector_self_ready_status(control);
            }
        }
        true
    }
    pub(super) fn inspector_self_tick(&mut self) {
        let time = now();
        let abort_by = deadline(v5::resources::FILE_TRANSACTION_TICKS);
        self.inspector_self.capture.tick(time, abort_by);
        let actor = self.actor(Child::Inspector);
        if actor.failed {
            self.inspector_self.entry.cancel();
            self.inspector_self.enter.cancel();
            self.inspector_self.ordinary = None;
            if self.inspector_self.reader.pending() {
                self.inspector_self.reader.failed();
            }
            // Unknown channel debt is not repaired by identity replacement.
            if matches!(
                self.inspector_self.capture.phase(),
                Phase::Idle | Phase::Request | Phase::Ready
            ) {
                self.inspector_self.capture.invalidate(abort_by);
            } else {
                self.inspector_self.capture.transport_failed();
            }
            self.inspector_self.enabled = false;
            return;
        }
        if self.inspector_self.reader.pending() {
            let original = self.inspector_self.reader.binding();
            let unchanged = self.inspector_self.enabled
                && original.is_some_and(|b| self.inspector_self_recorded_scope_matches(b));
            let publication = self.inspector_self_publication(original);
            self.inspector_self
                .reader
                .retain_recorded_scope(unchanged, publication, now());
            self.inspector_self_reader_send();
            return;
        }
        if self.inspector_self.entry.pending() {
            let scope = self.inspector_self_entry_scope();
            if let Some(by) = self.inspector_self.entry.current(scope, time) {
                if let Some(binding) = self.inspector_self_binding()
                    && !self.outbox.has_pending()
                    && now() < by
                {
                    let bytes = Command::Activate(NAV_ENTER).encode().unwrap();
                    match send(self.channel(Channel::InspectorControl), bytes) {
                        Ok(true) => {
                            self.inspector_self.enabled = true;
                            self.inspector_self.refresh_stats.clear();
                            self.inspector_self.last_reader = binding.context.reader;
                            self.inspector_self_wait_after(binding.presented.frame);
                            // The wait and first own capture share the physical
                            // request's original cut. Enabling cannot renew it.
                            self.inspector_self.capture_by = by;
                            self.inspector_self.entry.cancel();
                        }
                        Ok(false) => (), // no SEND accepted; keep original desire/cut
                        Err(()) => {
                            self.inspector_self.capture.transport_failed();
                            self.inspector_self_disable(true);
                        }
                    }
                }
            } else {
                self.status =
                    b"Inspector own entry expired or desktop changed; no control forwarded";
                self.owner.dirty = true;
            }
        }
        if self.inspector_self.enabled
            && self.policy.as_ref().is_none_or(|p| p.focused() != Some(3))
        {
            self.inspector_self_disable(false);
        }
        if self.inspector_self.enabled {
            let reader = self.semantic.active();
            if reader != self.inspector_self.last_reader {
                self.inspector_self.enter.cancel();
                self.inspector_self.ordinary = None;
                self.inspector_self.last_reader = reader;
                self.inspector_self.refresh_stats.clear();
                if !reader {
                    self.inspector_self.refresh_stats.context_ready();
                }
                self.inspector_self.published = 0;
                self.inspector_self.capture.invalidate(abort_by);
                self.inspector_self.capture_by = deadline(v5::resources::FILE_TRANSACTION_TICKS);
                self.inspector_self.page = 1;
                self.queue(Child::Inspector, Command::Activate(NAV_ENTER));
            }
            if self.inspector_self.capture.phase() == Phase::Receiving
                && self
                    .inspector_self
                    .capture
                    .binding()
                    .is_some_and(|old| self.inspector_self_recorded_scope_matches(old))
            {
                // A1 is bracketed before request and at actual COMMIT. Avoid
                // a large source/own Display RPC convoy between every word.
                // Exact original binding, bytes, cut and receiver stay held.
                let had_enter = self.inspector_self.enter.pending();
                if self
                    .inspector_self
                    .enter
                    .binding()
                    .is_some_and(|old| !self.inspector_self_recorded_scope_matches(old))
                {
                    self.inspector_self.enter.cancel();
                }
                self.inspector_self.enter.expire(now());
                if had_enter && !self.inspector_self.enter.pending() {
                    self.status =
                        b"Inspector Enter expired or current control changed; no control forwarded";
                    self.owner.dirty = true;
                }
                self.inspector_self.capture.tick(now(), abort_by);
                if self.inspector_self.capture.phase() == Phase::Receiving {
                    return;
                }
            }
            let current = self.inspector_self_binding();
            self.inspector_self_reader_tick(current, time);
            if self
                .inspector_self
                .ordinary
                .as_ref()
                .is_some_and(|receipt| !receipt.current(current, time))
            {
                // This is only an unsatisfied ordinary intent receipt; no
                // accepted source operation or IS/IT debt is retired here.
                self.inspector_self.ordinary = None;
            }
            self.inspector_self_enter_tick(current, time);
            if self
                .inspector_self
                .capture
                .binding()
                .is_some_and(|old| Some(old) != current)
            {
                if self.inspector_self.capture.phase() == Phase::Ready {
                    // A completed old read has no accepted stream debt. A
                    // changed actual presentation starts a distinct bounded
                    // observation; no old request or drain is renewed.
                    self.inspector_self.capture_by =
                        deadline(v5::resources::FILE_TRANSACTION_TICKS);
                    self.inspector_self.page = 1;
                }
                self.inspector_self.capture.invalidate(abort_by);
                self.inspector_self.published = 0;
            }
            let phase = self.inspector_self.capture.phase();
            if phase == Phase::Blocked
                || time >= self.inspector_self.capture_by && phase != Phase::Ready
            {
                self.inspector_self_disable(true);
            } else if let Some(binding) = current {
                let waiting = self.inspector_self.wait_frame;
                let moved = waiting.is_none_or(|old| old != binding.presented.frame);
                let need = phase == Phase::Idle
                    || phase == Phase::Ready && self.inspector_self.published == 0;
                if moved
                    && need
                    && !self.inspector.collecting()
                    && !self.inspector_self.reader.pending()
                {
                    self.inspector_self.wait_frame = None;
                    let page = self.inspector_self.page;
                    let by = self.inspector_self.capture_by;
                    if now() >= by
                        || self
                            .inspector_self
                            .capture
                            .begin(binding, page, by)
                            .is_err()
                    {
                        self.inspector_self_disable(true);
                    }
                }
            }
        }
        self.inspector_self
            .capture
            .tick(now(), deadline(v5::resources::FILE_TRANSACTION_TICKS));
        if let Some(bytes) = self.inspector_self.capture.next() {
            match send(self.channel(Channel::InspectorControl), bytes) {
                Ok(true) => require(self.inspector_self.capture.sent(bytes).is_ok(), 1682),
                Ok(false) => (),
                Err(()) => {
                    self.inspector_self.capture.transport_failed();
                    if self.inspector_self.enabled {
                        self.inspector_self_disable(true);
                    }
                }
            }
        }
    }
}
