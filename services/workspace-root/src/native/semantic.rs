//! Native bounded semantic broker. Only actual Root-owned routes call this
//! adapter; all IDs and tuples remain descriptive until checked here.
use super::*;
use core::sync::atomic::{AtomicBool, Ordering};
use ev_userspace_contract::root_v5::{
    assistive::{self as at, Context, Intent, IntentKind, Mode},
    display_control::Slot,
};
use ev_workspace_client::semantic::{
    self as a1, Frame, Progress, Receiver, Snapshot, operation as op,
};
use ev_workspace_root::{policy::owner as model_owner, semantic::Presented};
use ev_workspace_shell::{ProviderLease, ProviderRights, WindowId};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase {
    Off,
    Requested,
    Consent,
    Request,
    Receiving,
    Relay,
    AwaitPresent,
    Ready,
    OpSend,
    OpWait,
    OpAbort,
    RangeRelay,
    RangeAwaitPresent,
    AbortSource,
    AbortRelay,
    Revoked,
    Blocked,
}
#[derive(Clone, Copy)]
pub(super) struct Lease {
    pub client: Identity,
    pub source: Identity,
    pub window: Option<WindowId>,
    pub target: usize,
    pub rights: u8,
    pub provider: ProviderLease,
}
#[derive(Clone, Copy)]
struct ConfirmTicket {
    client: Identity,
    provider: ProviderLease,
    challenge: Option<ev_workspace_shell::Challenge>,
    root: Presented,
    view: u32,
    inspector_frame: u64,
    input_serial: u64,
    input_sequence: u32,
    input_lifetime: u32,
    by: u64,
}
pub(super) struct State {
    pub phase: Phase,
    pub target: usize,
    pub next_target: Option<usize>,
    pub rights: u8,
    pub lease: Option<Lease>,
    pub receiver: Receiver,
    pub candidate: Snapshot,
    nodes: [a1::Node; 16],
    pub nonce: u32,
    pub consumer_view: u32,
    pub page: u8,
    pub by: u64,
    pub relay: u16,
    pub context_next: u8,
    pub context: Context,
    pub context_view: u32,
    pub context_pending: bool,
    pub consumer_started: bool,
    pub selected: u8,
    pub publication: u64,
    pub next_check: u64,
    pub disable: bool,
    pub abort_source_sent: bool,
    pub abort_relay_next: u8,
    pub client: Option<Identity>,
    pub operation: Option<op::Request>,
    pub next_operation: u32,
    pub operation_next: u16,
    pub operation_abort_sent: bool,
    pub range: Option<op::RangeReceiver>,
    pub range_reply: Option<op::RangeReply>,
    pub range_refused: Option<Frame>,
    pub range_next: u16,
    pub range_descriptor: u16,
    pub range_offset: u64,
    pub range_last: Option<(u16, op::RangeKind, u64)>,
    confirm: Option<ConfirmTicket>,
}
impl State {
    const fn new() -> Self {
        Self {
            phase: Phase::Off,
            target: 1,
            next_target: None,
            rights: 1,
            lease: None,
            receiver: Receiver::new(),
            candidate: Snapshot::EMPTY,
            nodes: [a1::Node::EMPTY; 16],
            nonce: 0,
            consumer_view: 0,
            page: 0,
            by: 0,
            relay: 0,
            context_next: 0,
            context: Context {
                mode: Mode::Stats,
                source: Slot::EditorOne,
                scopes: 0,
            },
            context_view: 0,
            context_pending: false,
            consumer_started: false,
            selected: 0,
            publication: 0,
            next_check: 0,
            disable: false,
            abort_source_sent: false,
            abort_relay_next: 0,
            client: None,
            operation: None,
            next_operation: 0,
            operation_next: 0,
            operation_abort_sent: false,
            range: None,
            range_reply: None,
            range_refused: None,
            range_next: 0,
            range_descriptor: 0,
            range_offset: 0,
            range_last: None,
            confirm: None,
        }
    }
    pub(super) fn active(&self) -> bool {
        self.phase != Phase::Off
    }
}
static CLAIMED: AtomicBool = AtomicBool::new(false);
static mut STATE: State = State::new();
/// The actual sole Root entry claims process-private resident buffers once.
pub(super) fn claim() -> &'static mut State {
    require(!CLAIMED.swap(true, Ordering::AcqRel), 1670);
    // SAFETY: sole successful claim of a statically initialized process-private
    // RW/NX owner. No aliases are constructed and no other thread can claim it.
    unsafe { &mut *core::ptr::addr_of_mut!(STATE) }
}
impl Root<'_> {
    /// Private own-Inspector capture pins the currently authorized external
    /// provider without granting a second provider or relaying its bytes.
    pub(super) fn inspector_self_context(
        &mut self,
    ) -> Option<ev_workspace_root::inspector_self::Context> {
        let context = self.inspector_self_recorded_context()?;
        if context.reader && context.phase == 2 {
            // One coherent source bracket replaces two redundant brackets.
            // The actual source MUST still match the original complete page.
            if Some(self.semantic_presented()?) != context.source_presented {
                return None;
            }
        }
        Some(context)
    }
    /// Root-owned metadata stamp for retaining/cancelling an incomplete own
    /// read only. It is never current Display evidence or action authority.
    /// Publication, physical activation and IR still use the full getter.
    pub(super) fn inspector_self_recorded_context(
        &self,
    ) -> Option<ev_workspace_root::inspector_self::Context> {
        use ev_workspace_root::inspector_self::Context;
        if self.development.active()
            || self.semantic.active() && !self.development_semantic_available(self.semantic.target)
        {
            return None;
        }
        if self.semantic.context_pending || self.scene_dirty {
            return None;
        }
        if self.semantic.phase == Phase::Off {
            return (!self.inspector.collecting()).then_some(Context {
                reader: false,
                phase: 0,
                view: self.inspector.nonce,
                rights: 0,
                target: 255,
                provider: None,
                source: None,
                source_presented: None,
            });
        }
        if self.semantic.phase == Phase::Requested {
            return Some(Context {
                reader: true,
                phase: 1,
                view: self.semantic.context_view,
                rights: self.semantic.rights,
                target: self.semantic.target as u8,
                provider: None,
                source: None,
                source_presented: None,
            });
        }
        if self.semantic.phase != Phase::Ready || !self.semantic_live() {
            return None;
        }
        let lease = self.semantic.lease?;
        let h = self.semantic.candidate.header();
        let source = Presented {
            model: h.model,
            view: h.view,
            frame: h.frame,
            mapping_epoch: h.mapping_epoch,
            width: h.width,
            height: h.height,
        };
        // Mapping, geometry and the Root-owned scene/actor changes are cheap
        // cancellation facts; they cannot certify an unqueried Display frame.
        if lease.target == 3 {
            let actual = self.protected.header;
            if self.owner.dirty
                || self.protected.body.is_none()
                || (
                    source.model,
                    source.view,
                    source.frame,
                    source.mapping_epoch,
                    source.width,
                    source.height,
                ) != (
                    actual.model_revision,
                    actual.view_revision,
                    actual.frame,
                    actual.mapping_epoch,
                    640,
                    80,
                )
            {
                return None;
            }
        } else {
            let bounds = self.policy.as_ref()?.bounds(lease.target).ok()?;
            let actor = self.actor(app_child(lease.target)?);
            if source.model != self.policy.as_ref()?.scene
                || source.mapping_epoch != u64::from(actor.mapping_epoch)
                || (u32::from(source.width), u32::from(source.height))
                    != (bounds.width, bounds.height)
            {
                return None;
            }
        }
        Some(Context {
            reader: true,
            phase: 2,
            view: self.semantic.consumer_view,
            rights: lease.rights,
            target: lease.target as u8,
            provider: Some(lease.provider),
            source: Some(lease.source),
            source_presented: Some(source),
        })
    }
    fn semantic_nonce(&mut self) -> u32 {
        self.inspector.nonce = self
            .inspector
            .nonce
            .checked_add(1)
            .filter(|v| *v != u32::MAX)
            .unwrap_or_else(|| rt::exit(1671));
        self.inspector.nonce
    }
    fn semantic_context(&mut self, mode: Mode, view: u32) {
        self.semantic.context = Context {
            mode,
            source: [
                Slot::Files,
                Slot::EditorOne,
                Slot::EditorTwo,
                Slot::ProtectedRoot,
            ][self.semantic.target],
            scopes: self.semantic.rights,
        };
        self.semantic.context_view = view;
        self.semantic.context_next = 0;
        self.semantic.context_pending = true;
    }
    pub(super) fn semantic_request_attention(&mut self) {
        if self.semantic.phase != Phase::Off
            || self.policy.is_none()
            || self.actor(Child::Inspector).failed
            || !self.actor(Child::Inspector).ready
        {
            return;
        }
        self.semantic.client = Some(self.actor(Child::Inspector).identity);
        self.inspector.suspend();
        self.semantic.phase = Phase::Requested;
        self.semantic.rights = 1;
        let view = self.semantic_nonce();
        self.semantic_context(Mode::AttentionRequested, view);
        self.status=b"Inspector requests semantic access; use independent Root Controls/Esc to review scope";
        self.owner.dirty = true;
    }
    fn semantic_live(&self) -> bool {
        if self.development.active() || !self.development_semantic_available(self.semantic.target) {
            return false;
        }
        let Some(lease) = self.semantic.lease else {
            return false;
        };
        let client = self.actor(Child::Inspector);
        if client.failed || client.identity != lease.client {
            return false;
        }
        if lease.target == 3 {
            return lease.source == self.protected.identity;
        }
        let source = self.actor(app_child(lease.target).unwrap());
        !source.failed
            && source.identity == lease.source
            && self
                .policy
                .as_ref()
                .is_some_and(|p| p.ids[lease.target] == lease.window)
    }
    fn semantic_presented(&mut self) -> Option<Presented> {
        let lease = self.semantic.lease?;
        if self.scene_dirty {
            return None;
        }
        if !self.semantic_live() {
            return None;
        }
        let slot = [
            Slot::Files,
            Slot::EditorOne,
            Slot::EditorTwo,
            Slot::ProtectedRoot,
        ][lease.target];
        let (frame, view) = self.accepted_view(slot)?;
        if lease.target == 3 {
            if self.owner.dirty || self.scene_dirty {
                return None;
            }
            let header = self.protected.header;
            if self.protected.body.is_none()
                || header.frame != frame
                || header.view_revision != view
            {
                return None;
            }
            return Some(Presented {
                model: header.model_revision,
                view,
                frame,
                mapping_epoch: header.mapping_epoch,
                width: 640,
                height: 80,
            });
        }
        let policy = self.policy.as_ref()?;
        let bounds = policy.bounds(lease.target).ok()?;
        Some(Presented {
            model: policy.scene,
            view,
            frame,
            mapping_epoch: u64::from(self.actor(app_child(lease.target)?).mapping_epoch),
            width: u16::try_from(bounds.width).ok()?,
            height: u16::try_from(bounds.height).ok()?,
        })
    }
    fn semantic_current(&mut self) -> bool {
        self.semantic_presented()
            .is_some_and(|p| p.matches(self.semantic.candidate.header()))
    }
    pub(super) fn semantic_event(&mut self, child: Child, bytes: [u8; 8]) -> bool {
        if bytes[..2] != [0x41, 1] {
            return false;
        }
        if child == Child::Inspector {
            if let Ok(intent) = Intent::decode(bytes) {
                self.semantic_intent(intent);
                return true;
            }
            if self.semantic.client != Some(self.actor(Child::Inspector).identity) {
                return true;
            }
            if let Ok(view) = at::decode_range_presented(bytes) {
                if self.semantic.phase == Phase::RangeAwaitPresent
                    && self.semantic.operation.is_some_and(|q| q.nonce == view)
                    && self.semantic_live()
                    && self.semantic_current()
                    && self
                        .accepted_view(Slot::Inspector)
                        .is_some_and(|(_, v)| v == u64::from(view))
                {
                    self.semantic.consumer_view = view;
                    self.semantic.operation = None;
                    self.semantic.range_reply = None;
                    self.semantic.range_refused = None;
                    self.semantic.range_descriptor = 0;
                    self.semantic.phase = Phase::Ready;
                    self.semantic.next_check = deadline(256);
                } else if self.semantic.phase == Phase::RangeAwaitPresent {
                    self.semantic_revoke(false);
                }
                return true;
            }
            if let Ok(view) = at::decode_presented(bytes) {
                if self.semantic.phase == Phase::AwaitPresent
                    && view == self.semantic.nonce
                    && self.semantic_live()
                    && self.semantic_current()
                    && self
                        .accepted_view(Slot::Inspector)
                        .is_some_and(|(_, v)| v == u64::from(view))
                {
                    self.semantic.consumer_view = view;
                    self.semantic.phase = Phase::Ready;
                    self.semantic.next_check = deadline(256);
                } else if self.semantic.phase == Phase::Revoked
                    && view == self.semantic.context_view
                    && self
                        .accepted_view(Slot::Inspector)
                        .is_some_and(|(_, v)| v == u64::from(view))
                {
                    self.semantic_finish_revoke();
                }
                return true;
            }
            return true;
        }
        let Some(lease) = self.semantic.lease else {
            return true;
        };
        if lease.target == 3
            || child != app_child(lease.target).unwrap()
            || self.actor(child).identity != lease.source
        {
            return true;
        }
        let Ok(frame) = Frame::decode(&bytes) else {
            self.semantic_revoke(true);
            return true;
        };
        if self.semantic_operation_event(frame) {
            return true;
        }
        if !matches!(self.semantic.phase, Phase::Receiving | Phase::AbortSource) {
            return true;
        }
        match self.semantic.receiver.push(frame) {
            Ok(Progress::Complete) if self.semantic.phase == Phase::Receiving => {
                if self
                    .semantic
                    .receiver
                    .candidate(&mut self.semantic.candidate)
                    .is_err()
                    || !self.semantic_current()
                {
                    self.semantic_revoke(false);
                    return true;
                }
                if self.semantic.candidate.header().modal != 0 {
                    self.semantic_revoke(true);
                    return true;
                }
                let lease = self.semantic.lease.unwrap();
                let policy = self.policy.as_mut().unwrap();
                let Ok(window) = policy.desktop.window(lease.window.unwrap()) else {
                    self.semantic_revoke(true);
                    return true;
                };
                let publication = window
                    .view_revision
                    .checked_add(1)
                    .filter(|v| *v != u64::MAX)
                    .unwrap_or_else(|| rt::exit(1672));
                let presented = Presented {
                    model: self.semantic.candidate.header().model,
                    view: self.semantic.candidate.header().view,
                    frame: self.semantic.candidate.header().frame,
                    mapping_epoch: self.semantic.candidate.header().mapping_epoch,
                    width: self.semantic.candidate.header().width,
                    height: self.semantic.candidate.header().height,
                };
                let Ok(tree) = ev_workspace_root::semantic::project(
                    &self.semantic.candidate,
                    presented,
                    window.bounds,
                    publication,
                ) else {
                    self.semantic_revoke(false);
                    return true;
                };
                if policy
                    .desktop
                    .publish_presented_view(
                        model_owner(lease.source),
                        lease.window.unwrap(),
                        publication,
                        tree,
                        (self.semantic.candidate.header().keyboard != 0)
                            .then_some(self.semantic.candidate.header().keyboard),
                    )
                    .is_err()
                {
                    self.semantic_revoke(true);
                    return true;
                }
                self.semantic.publication = publication;
                self.semantic.relay = 0;
                self.semantic.consumer_started = false;
                self.semantic.selected = 0;
                self.semantic.phase = Phase::Relay;
                self.semantic_context(Mode::Receiving, self.semantic.nonce);
            }
            Ok(Progress::Aborted) if self.semantic.phase == Phase::AbortSource => {
                self.semantic_after_source_abort()
            }
            Ok(Progress::Refused(_)) if self.semantic.phase == Phase::Receiving => {
                // This is a canonical completed refusal, not a repair of an
                // expired or malformed old stream.
                self.semantic_revoke(true);
            }
            Ok(Progress::Receiving) => (),
            _ => self.semantic_revoke(true),
        }
        true
    }
    pub(super) fn semantic_intent(&mut self, intent: Intent) {
        // Ordinary own-tree Enter is a one-shot intent under its original
        // accepted binding/cut. Dedicated protected confirmation continues to
        // require its independent physical ConfirmTicket below.
        if intent.kind != IntentKind::ConfirmProtected
            && !self.inspector_self_ordinary_intent(intent)
        {
            return;
        }
        self.semantic_intent_current(intent, None);
    }
    /// Only the private nonce-correlated reader reply route calls this after
    /// exact actor/frame/publication/cut validation while App repaint is held.
    /// Its transport acknowledgment never authorizes protected confirmation.
    pub(super) fn semantic_own_intent(&mut self, intent: Intent, original_by: u64) {
        if matches!(
            intent.kind,
            IntentKind::Enable | IntentKind::ConfirmProtected
        ) {
            return;
        }
        self.semantic_intent_current(intent, Some(original_by));
    }
    fn semantic_intent_current(&mut self, intent: Intent, own_by: Option<u64>) {
        if own_by.is_some_and(|by| now() >= by) {
            return;
        }
        if intent.kind == IntentKind::Enable {
            // Attention requests are untrusted intent, not an input witness or
            // permission. The actual Inspector provenance was checked by39;
            // an unrelated in-flight stats refresh need not discard the request.
            self.semantic_request_attention();
            return;
        }
        if intent.kind == IntentKind::Disable || intent.kind == IntentKind::Cancel {
            self.semantic_revoke(true);
            return;
        }
        if self.semantic.phase != Phase::Ready
            || intent.view != self.semantic.consumer_view
            || !self.semantic_live()
            || !self.semantic_current()
            || own_by.is_some_and(|by| now() >= by)
        {
            return;
        }
        let Some(node) = self
            .semantic
            .candidate
            .nodes()
            .get(usize::from(intent.index))
            .copied()
        else {
            return;
        };
        self.semantic.selected = intent.index;
        if intent.kind == IntentKind::PreviousSource || intent.kind == IntentKind::NextSource {
            // Changing sources always returns to an independent owner decision.
            self.semantic.next_target = Some(if intent.kind == IntentKind::PreviousSource {
                (self.semantic.target + 3) % 4
            } else {
                (self.semantic.target + 1) % 4
            });
            self.semantic_revoke(true);
            return;
        }
        if self.semantic.lease.is_some_and(|l| l.target == 3) && intent.kind == IntentKind::Activate
        {
            self.semantic_root_activate(node);
            return;
        }
        if intent.kind == IntentKind::Expand && node.actions & 16 != 0 {
            let header = self.semantic.candidate.header();
            self.semantic.page = if header.page == 0 {
                if node.local == 2 {
                    1
                } else {
                    2.min(header.pages - 1)
                }
            } else {
                0
            };
            self.semantic_revoke(false);
            return;
        }
        if matches!(
            intent.kind,
            IntentKind::ReadLabel
                | IntentKind::ReadDocument
                | IntentKind::MoreText
                | IntentKind::Activate
                | IntentKind::Select
                | IntentKind::ScrollUp
                | IntentKind::ScrollDown
        ) {
            self.semantic_operation(intent.kind, node, own_by);
            return;
        }
        if intent.kind == IntentKind::ConfirmProtected {
            self.semantic_confirm_intent(intent);
            return;
        }
        if self.semantic.lease.is_some_and(|l| l.target == 3) {
            if matches!(
                intent.kind,
                IntentKind::PreviousNode | IntentKind::NextNode | IntentKind::AssistiveFocus
            ) {
                return;
            }
            if intent.kind == IntentKind::Refresh {
                self.semantic_revoke(false);
            }
            return;
        }
        match intent.kind {
            IntentKind::PreviousNode | IntentKind::NextNode | IntentKind::AssistiveFocus => {
                let lease = self.semantic.lease.unwrap();
                let accepted = self
                    .policy
                    .as_mut()
                    .unwrap()
                    .desktop
                    .assistive_focus(
                        model_owner(lease.client),
                        lease.provider,
                        ev_workspace_shell::NodeId {
                            window: lease.window.unwrap(),
                            local: node.local,
                        },
                        self.semantic.publication,
                    )
                    .is_ok();
                if own_by.is_some() && accepted {
                    self.status = match intent.kind {
                        IntentKind::PreviousNode => {
                            b"Inspector reader action verified: Previous node"
                        }
                        IntentKind::NextNode => b"Inspector reader action verified: Next node",
                        _ => b"Inspector reader action verified: Assistive focus",
                    };
                    self.owner.dirty = true;
                }
            }
            IntentKind::Refresh => self.semantic_revoke(false),
            IntentKind::Expand => {
                let header = self.semantic.candidate.header();
                if node.actions & 16 != 0 && header.pages > 1 {
                    self.semantic.page = if header.page == 0 {
                        if node.local == 2 {
                            1
                        } else {
                            2.min(header.pages - 1)
                        }
                    } else {
                        0
                    };
                    self.semantic_revoke(false);
                }
            }
            IntentKind::KeyboardFocus => {
                let lease = self.semantic.lease.unwrap();
                if lease.rights & 2 == 0 {
                    return;
                }
                let policy = self.policy.as_mut().unwrap();
                let id = ev_workspace_shell::NodeId {
                    window: lease.window.unwrap(),
                    local: node.local,
                };
                if let Ok(ticket) = policy.desktop.semantic_action(
                    model_owner(lease.client),
                    lease.provider,
                    id,
                    self.semantic.publication,
                    ev_workspace_shell::Action::Focus,
                ) && policy
                    .desktop
                    .dispatch_semantic(model_owner(lease.client), ticket)
                    .is_ok()
                {
                    self.scene_dirty = true;
                    self.semantic_revoke(false);
                }
            }
            // Mutating operations and text are wired only after the retained
            // operation/abort broker is loaded; do not advertise success here.
            _ => {
                self.status = b"This assistive operation is not loaded in the current Root adapter";
                self.owner.dirty = true;
            }
        }
    }
    pub(super) fn semantic_revoke(&mut self, disable: bool) {
        if self.semantic.phase == Phase::Off {
            return;
        }
        self.semantic.confirm = None;
        self.semantic.disable |= disable;
        match self.semantic.phase {
            Phase::OpSend | Phase::OpWait => {
                if self.semantic.operation_next == 0 {
                    self.semantic.operation = None;
                    self.semantic_after_source_abort();
                } else {
                    self.semantic.phase = Phase::OpAbort;
                    self.semantic.operation_abort_sent = false;
                }
            }
            Phase::OpAbort => (),
            Phase::RangeRelay | Phase::RangeAwaitPresent => {
                self.semantic.phase = Phase::AbortRelay;
                self.semantic.abort_relay_next = 0;
            }
            Phase::Receiving if self.semantic.lease.is_some_and(|l| l.target == 3) => {
                self.semantic_after_source_abort()
            }
            Phase::Receiving => {
                self.semantic.receiver.expire();
                if self.semantic.receiver.abort().is_ok() {
                    self.semantic.phase = Phase::AbortSource;
                    self.semantic.abort_source_sent = false;
                } else {
                    self.semantic.phase = Phase::Blocked;
                }
            }
            Phase::AbortSource | Phase::AbortRelay | Phase::Revoked | Phase::Blocked => (),
            _ => self.semantic_after_source_abort(),
        }
    }
    fn semantic_after_source_abort(&mut self) {
        if self.semantic.consumer_started {
            self.semantic.phase = Phase::AbortRelay;
            self.semantic.abort_relay_next = 0;
        } else {
            self.semantic_after_relay_abort();
        }
    }
    fn semantic_after_relay_abort(&mut self) {
        if self.semantic.disable {
            self.semantic.phase = Phase::Revoked;
            if self.owner.challenge.is_some() {
                self.cancel_owner();
            }
            if let Some(lease) = self.semantic.lease {
                let _ = self
                    .policy
                    .as_mut()
                    .unwrap()
                    .desktop
                    .revoke_provider(lease.provider);
            }
            let view = self.semantic_nonce();
            self.semantic_context(Mode::Revoked, view);
            self.semantic.phase = Phase::Revoked;
        } else {
            self.semantic.nonce = self.semantic_nonce();
            self.semantic.phase = Phase::Request;
            self.semantic.by = deadline(v5::resources::FILE_TRANSACTION_TICKS);
            self.semantic.consumer_started = false;
        }
    }
    fn semantic_finish_revoke(&mut self) {
        self.semantic.lease = None;
        self.semantic.client = None;
        self.semantic.disable = false;
        self.semantic.consumer_started = false;
        self.semantic.phase = Phase::Off;
        self.inspector.resume();
        if let Some(target) = self.semantic.next_target.take() {
            self.semantic.target = target;
            self.semantic_request_attention();
        } else {
            let view = self.semantic_nonce();
            self.semantic_context(Mode::Stats, view);
        }
    }
    pub(super) fn semantic_tick(&mut self) {
        let inspector = self.actor(Child::Inspector);
        if inspector.failed {
            if self.semantic.active() {
                self.semantic_revoke(true);
            }
            return;
        }
        if self.semantic.context_pending {
            let bytes = if self.semantic.context_next == 0 {
                self.semantic.context.encode().unwrap()
            } else {
                at::commit(self.semantic.context_view).unwrap()
            };
            match send(self.channel(Channel::InspectorControl), bytes) {
                Ok(true) => {
                    self.semantic.context_next += 1;
                    if self.semantic.context_next == 2 {
                        self.semantic.context_pending = false;
                    }
                }
                Ok(false) => (),
                Err(()) => self.semantic.phase = Phase::Blocked,
            }
            return;
        }
        if self.semantic.lease.is_some() && !self.semantic_live() {
            self.semantic_revoke(true);
            return;
        }
        if self.semantic_operation_tick() {
            return;
        }
        match self.semantic.phase {
            Phase::Request => {
                if now() >= self.semantic.by {
                    self.semantic_revoke(true);
                    return;
                }
                let Some(lease) = self.semantic.lease else {
                    self.semantic_revoke(true);
                    return;
                };
                if self.semantic_presented().is_none() {
                    return;
                }
                if lease.target == 3 {
                    self.semantic_root_snapshot();
                    return;
                }
                let frame = a1::Request::Snapshot {
                    page: self.semantic.page,
                    nonce: self.semantic.nonce,
                }
                .frame()
                .unwrap();
                match send(
                    self.channel(control_channel(app_child(lease.target).unwrap()).unwrap()),
                    frame.encode(),
                ) {
                    Ok(true) => {
                        require(
                            self.semantic
                                .receiver
                                .request(self.semantic.page, self.semantic.nonce)
                                .is_ok(),
                            1673,
                        );
                        self.semantic.phase = Phase::Receiving;
                    }
                    Ok(false) => (),
                    Err(()) => self.semantic.phase = Phase::Blocked,
                }
            }
            Phase::Receiving | Phase::AwaitPresent => {
                if now() >= self.semantic.by {
                    self.semantic_revoke(true);
                }
            }
            Phase::Relay => {
                if now() >= self.semantic.by {
                    self.semantic_revoke(true);
                    return;
                }
                let bytes = if !self.semantic.consumer_started {
                    a1::Request::Snapshot {
                        page: self.semantic.page,
                        nonce: self.semantic.nonce,
                    }
                    .frame()
                    .unwrap()
                    .encode()
                } else {
                    let Some(frame) = self.semantic.candidate.frame(self.semantic.relay) else {
                        self.semantic.phase = Phase::AwaitPresent;
                        return;
                    };
                    if frame.field == a1::COMMIT && !self.semantic_current() {
                        self.semantic_revoke(false);
                        return;
                    }
                    frame.encode()
                };
                match send(self.channel(Channel::InspectorControl), bytes) {
                    Ok(true) => {
                        if !self.semantic.consumer_started {
                            self.semantic.consumer_started = true;
                        } else {
                            self.semantic.relay += 1;
                        }
                    }
                    Ok(false) => (),
                    Err(()) => self.semantic.phase = Phase::Blocked,
                }
            }
            Phase::Ready => {
                if now() >= self.semantic.next_check {
                    self.semantic.next_check = deadline(256);
                    if !self.semantic_current() {
                        self.semantic_revoke(false);
                    }
                }
            }
            Phase::AbortSource => {
                if self.semantic.abort_source_sent {
                    return;
                }
                let Some(lease) = self.semantic.lease else {
                    self.semantic.phase = Phase::Blocked;
                    return;
                };
                let frame = a1::Request::Abort {
                    nonce: self.semantic.nonce,
                }
                .frame()
                .unwrap();
                match send(
                    self.channel(control_channel(app_child(lease.target).unwrap()).unwrap()),
                    frame.encode(),
                ) {
                    Ok(true) => self.semantic.abort_source_sent = true,
                    Ok(false) => (),
                    Err(()) => self.semantic.phase = Phase::Blocked,
                }
            }
            Phase::AbortRelay => {
                if self.semantic.range_descriptor != 0 {
                    let request = self.semantic.operation.unwrap();
                    match send(
                        self.channel(Channel::InspectorControl),
                        Frame {
                            field: op::ABORT,
                            word: request.nonce,
                        }
                        .encode(),
                    ) {
                        Ok(true) => {
                            self.semantic.range_descriptor = 0;
                            self.semantic.operation = None;
                            self.semantic.range_reply = None;
                            self.semantic.range_refused = None;
                        }
                        Ok(false) => (),
                        Err(()) => self.semantic.phase = Phase::Blocked,
                    }
                    return;
                }
                let bytes = if self.semantic.abort_relay_next == 0 {
                    at::abort_relay(self.semantic.nonce).unwrap()
                } else {
                    Frame {
                        field: a1::ABORT_ACK,
                        word: self.semantic.nonce,
                    }
                    .encode()
                };
                match send(self.channel(Channel::InspectorControl), bytes) {
                    Ok(true) => {
                        self.semantic.abort_relay_next += 1;
                        if self.semantic.abort_relay_next == 2 {
                            self.semantic.consumer_started = false;
                            self.semantic_after_relay_abort();
                        }
                    }
                    Ok(false) => (),
                    Err(()) => self.semantic.phase = Phase::Blocked,
                }
            }
            _ => (),
        }
    }
}

impl Root<'_> {
    fn semantic_scope(&self) -> Option<ev_workspace_shell::ActionScope> {
        if self.development.active() || !self.development_semantic_available(self.semantic.target) {
            return None;
        }
        use ev_workspace_shell::{ActionScope, ActionTarget, ProtectedKind};
        let client = self.actor(Child::Inspector);
        if client.failed {
            return None;
        }
        let scopes = ev_workspace_root::semantic::Scopes::new(
            self.semantic.rights,
            self.semantic.target == 3,
        )
        .ok()?;
        let target = if self.semantic.target == 3 {
            ActionTarget::ProtectedRoot {
                owner: model_owner(self.protected.identity),
                thread: self.protected.identity.thread,
                mapping_epoch: self.protected.header.mapping_epoch,
            }
        } else {
            let actor = self.actor(app_child(self.semantic.target)?);
            if actor.failed {
                return None;
            }
            ActionTarget::Window {
                id: self.policy.as_ref()?.ids[self.semantic.target]?,
                owner: model_owner(actor.identity),
            }
        };
        Some(ActionScope {
            kind: ProtectedKind::OwnerOverride,
            requester: model_owner(client.identity),
            target,
            rights: scopes.challenge_rights(),
        })
    }
    pub(super) fn semantic_begin_consent(&mut self, serial: u32) {
        if !matches!(self.semantic.phase, Phase::Requested | Phase::Consent)
            || self.owner.pending.is_some()
            || self.file_transition_modal()
        {
            return;
        }
        let Some(scope) = self.semantic_scope() else {
            return;
        };
        let policy = self.policy.as_mut().unwrap();
        let _ = policy.trusted.cancel(&mut policy.desktop);
        let Ok(attention) = policy
            .trusted
            .attest_attention(&mut policy.desktop, self.input.serial(serial))
        else {
            return;
        };
        let Ok(challenge) = policy
            .trusted
            .challenge(&mut policy.desktop, attention, scope)
        else {
            return;
        };
        self.semantic.phase = Phase::Consent;
        self.owner.challenge = Some(challenge);
        self.owner.witness = None;
        self.owner.rearm = true;
        self.owner.dirty = true;
    }
    pub(super) fn semantic_consent(&self) -> bool {
        self.semantic.phase == Phase::Consent
    }
    /// Only independently authenticated, fresh Input after the protected barrier
    /// reaches this function. Inspector packets never select or approve scope.
    pub(super) fn semantic_consent_action(&mut self, action: u8, serial: u32) {
        if !self.semantic_consent() {
            return;
        }
        if action == 6 {
            self.cancel_owner();
            return;
        }
        if action == 5 {
            self.semantic_approve(serial);
            return;
        }
        match action {
            0 => self.semantic.target = (self.semantic.target + 3) % 4,
            1 => self.semantic.target = (self.semantic.target + 1) % 4,
            2 => {
                self.semantic.rights ^= 2;
                if self.semantic.rights & 2 == 0 {
                    self.semantic.rights &= !8;
                }
            }
            3 => self.semantic.rights ^= 4,
            4 if self.semantic.target == 3 => {
                self.semantic.rights ^= 8;
                if self.semantic.rights & 8 != 0 {
                    self.semantic.rights |= 2;
                }
            }
            _ => return,
        }
        if self.semantic.target != 3 {
            self.semantic.rights &= !8;
        }
        self.semantic_begin_consent(serial);
    }
    fn semantic_approve(&mut self, serial: u32) {
        let Some(scope) = self.semantic_scope() else {
            self.cancel_owner();
            return;
        };
        let Some(challenge) = self.owner.challenge else {
            return;
        };
        if challenge.scope != scope {
            self.cancel_owner();
            return;
        }
        let client = self.actor(Child::Inspector);
        if identity(client.control, client.identity.registered) != client.identity
            || value(s::OBSERVE, client.control, 0, 0) != 0
        {
            self.cancel_owner();
            return;
        }
        let source = if self.semantic.target == 3 {
            self.protected.identity
        } else {
            let actor = self.actor(app_child(self.semantic.target).unwrap());
            if identity(actor.control, actor.identity.registered) != actor.identity
                || value(s::OBSERVE, actor.control, 0, 0) != 0
            {
                self.cancel_owner();
                return;
            }
            actor.identity
        };
        let Some(witness) = self.owner.witness.take() else {
            return;
        };
        let policy = self.policy.as_mut().unwrap();
        let Ok(effect) = policy.trusted.attest_confirmation(
            &mut policy.desktop,
            witness,
            scope,
            self.input.serial(serial),
            ev_workspace_shell::ConfirmationSource::Physical,
        ) else {
            self.cancel_owner();
            return;
        };
        if effect.scope() != scope {
            return;
        }
        let mut rights = ProviderRights::READ;
        if self.semantic.rights & 2 != 0 {
            rights = rights.union(ProviderRights::ACTION);
        }
        if self.semantic.rights & 8 != 0 {
            rights = rights.union(ProviderRights::CONFIRM);
        }
        let Ok(provider) = policy
            .desktop
            .provider(model_owner(client.identity), rights)
        else {
            self.cancel_owner();
            return;
        };
        self.semantic.lease = Some(Lease {
            client: client.identity,
            source,
            window: if self.semantic.target < 3 {
                policy.ids[self.semantic.target]
            } else {
                None
            },
            target: self.semantic.target,
            rights: self.semantic.rights,
            provider,
        });
        self.owner.cancel();
        self.input.cancel();
        self.semantic.nonce = self.semantic_nonce();
        self.semantic.page = 0;
        self.semantic.disable = false;
        self.semantic.phase = Phase::Request;
        self.semantic.by = deadline(v5::resources::FILE_TRANSACTION_TICKS);
        self.status = b"Explicit semantic scope granted to the shown Inspector and actual owner";
        self.owner.dirty = true;
    }
    pub(super) fn semantic_consent_view(
        &self,
        layer: u8,
    ) -> Option<ev_workspace_root::render::AssistiveView> {
        if !self.semantic_consent() {
            return None;
        }
        let target = if self.semantic.target == 3 {
            self.protected.identity
        } else {
            self.actor(app_child(self.semantic.target).unwrap())
                .identity
        };
        let window_generation = if self.semantic.target == 3 {
            self.protected.header.mapping_epoch
        } else {
            self.policy.as_ref().unwrap().ids[self.semantic.target]
                .unwrap()
                .generation
        };
        Some(ev_workspace_root::render::AssistiveView {
            inspector: self.actor(Child::Inspector).identity,
            target,
            slot: self.semantic.target as u8 + 1,
            window_generation,
            rights: self.semantic.rights,
            nonce: self.owner.nonce(),
            layer,
        })
    }
    fn semantic_root_snapshot(&mut self) {
        let Some(presented) = self.semantic_presented() else {
            return;
        };
        let body = self.protected.body.unwrap();
        let (mode, title, status, entry, recipient, writable) = match body {
            display::Body::Desktop(v) => {
                (v.mode, v.title, v.status, v.entry, v.recipient, v.writable)
            }
            display::Body::Assistive(_) => (
                ev_workspace_root::render::Mode::Consent,
                b"Semantic owner permission".as_slice(),
                b"Inspect the full scoped actual recipients and explicit rights".as_slice(),
                None,
                None,
                false,
            ),
        };
        let has_dataset = matches!(body, display::Body::Desktop(v) if v.dataset != [0; 16]);
        let shutdown_dialog = matches!(
            mode,
            ev_workspace_root::render::Mode::Shutdown
                | ev_workspace_root::render::Mode::ShutdownPending
                | ev_workspace_root::render::Mode::Development
                | ev_workspace_root::render::Mode::DevelopmentPending
        );
        let dialog = !matches!(mode, ev_workspace_root::render::Mode::Desktop);
        let root = a1::Node {
            local: 1,
            parent: 0,
            role: a1::Role::Window,
            flags: 0,
            actions: 0,
            label: a1::Label::new("Protected Root controls and dialogs").unwrap(),
            bounds: a1::Rect {
                x: 0,
                y: 0,
                width: 640,
                height: 80,
            },
            value: a1::Value::None,
        };
        self.semantic.nodes.fill(a1::Node::EMPTY);
        self.semantic.nodes[0] = root;
        let toolbar = a1::Node {
            local: 2,
            parent: 1,
            role: a1::Role::Menu,
            label: a1::Label::new("Root toolbar; Expand reads its page").unwrap(),
            bounds: a1::Rect {
                x: 0,
                y: 0,
                width: 640,
                height: 11,
            },
            actions: 16,
            ..root
        };
        let group = a1::Node {
            local: 3,
            parent: 1,
            role: a1::Role::Dialog,
            label: a1::Label::new("Current Root dialog; Expand reads its page").unwrap(),
            bounds: a1::Rect {
                x: 0,
                y: 11,
                width: 640,
                height: 69,
            },
            actions: 16,
            ..root
        };
        let text_value = |length: usize| a1::Value::TextRange {
            revision: presented.view,
            offset: 0,
            length: length as u32,
            total: length as u64,
        };
        let status_node = a1::Node {
            local: 4,
            parent: if self.semantic.page == 2 { 3 } else { 1 },
            role: a1::Role::Label,
            label: a1::Label::new("Root status; Name reads the full UTF8 text").unwrap(),
            bounds: a1::Rect {
                x: 0,
                y: 23,
                width: 640,
                height: 7,
            },
            value: text_value(status.len()),
            ..root
        };
        let title_node = a1::Node {
            local: 10,
            parent: if self.semantic.page == 2 { 3 } else { 1 },
            role: a1::Role::Label,
            label: a1::Label::new("Current dialog title; Name reads full text").unwrap(),
            bounds: a1::Rect {
                x: 0,
                y: 11,
                width: if has_dataset { 300 } else { 520 },
                height: 10,
            },
            value: text_value(title.len()),
            ..root
        };
        let count = match self.semantic.page {
            0 => {
                self.semantic.nodes[1] = toolbar;
                self.semantic.nodes[2] = group;
                self.semantic.nodes[3] = status_node;
                self.semantic.nodes[4] = title_node;
                5
            }
            1 => {
                self.semantic.nodes[1] = toolbar;
                let revoke_label = if ev_workspace_root::policy::save_cancel_command(
                    self.policy.as_ref().and_then(Policy::focused),
                    &self.states,
                )
                .is_some()
                {
                    "Revoke focused Editor File access"
                } else {
                    "Revoke focused Editor File access [Esc]"
                };
                for (i, (x, width, label)) in [
                    (0, 30, "Layer 1 Simple"),
                    (30, 30, "Layer 2 Advanced"),
                    (60, 30, "Layer 3 owner responsibility"),
                    (90, 90, "Root controls; exact focused Editor File revoke"),
                    (180, 70, "Open selected file"),
                    (250, 70, "Focus Inspector"),
                    (320, 130, "Checked shutdown"),
                    (450, 130, "Checked restart"),
                    (580, 60, revoke_label),
                ]
                .into_iter()
                .enumerate()
                {
                    self.semantic.nodes[2 + i] = a1::Node {
                        local: 16 + i as u16,
                        parent: 2,
                        role: a1::Role::Button,
                        flags: u8::from(dialog),
                        actions: 1,
                        label: a1::Label::new(label).unwrap(),
                        bounds: a1::Rect {
                            x,
                            y: 0,
                            width,
                            height: 11,
                        },
                        ..root
                    };
                }
                self.semantic.nodes[11] = status_node;
                12
            }
            _ => {
                self.semantic.nodes[1] = group;
                self.semantic.nodes[2] = title_node;
                self.semantic.nodes[3] = status_node;
                self.semantic.nodes[4] = a1::Node {
                    local: 5,
                    parent: 3,
                    role: a1::Role::Label,
                    label: a1::Label::new("Selected file name; Name reads full UTF8").unwrap(),
                    bounds: a1::Rect {
                        x: 0,
                        y: 31,
                        width: 640,
                        height: 39,
                    },
                    value: entry.map_or(a1::Value::None, |e| text_value(e.name.as_bytes().len())),
                    ..root
                };
                let mut object =
                    *b"Object 0000 generation 0000000000000000 revision 0000000000000000";
                if let Some(entry) = entry {
                    let digits = b"0123456789abcdef";
                    for i in 0..4 {
                        object[7 + i] =
                            digits[((entry.object.slot >> ((3 - i) * 4)) & 15) as usize];
                    }
                    semantic_hex(&mut object[23..39], entry.object.generation);
                    semantic_hex(&mut object[49..65], entry.revision);
                }
                // Full object identity is read as bounded label text. The node
                // label itself avoids silent truncation of its65-byte value.
                self.semantic.nodes[5] = a1::Node {
                    local: 6,
                    parent: 3,
                    role: a1::Role::Label,
                    label: a1::Label::new("Object identity and revision; Name reads full value")
                        .unwrap(),
                    bounds: a1::Rect {
                        x: 0,
                        y: 21,
                        width: 390,
                        height: 10,
                    },
                    value: if entry.is_some() {
                        text_value(object.len())
                    } else {
                        a1::Value::None
                    },
                    ..root
                };
                self.semantic.nodes[6] = a1::Node {
                    local: 7,
                    parent: 3,
                    role: a1::Role::Label,
                    label: a1::Label::new(
                        "Actual recipient process and thread; Name reads full value",
                    )
                    .unwrap(),
                    bounds: a1::Rect {
                        x: 400,
                        y: 21,
                        width: 240,
                        height: 10,
                    },
                    value: if recipient.is_some() {
                        text_value(38)
                    } else {
                        a1::Value::None
                    },
                    ..root
                };
                if entry.is_none()
                    && let display::Body::Desktop(view) = body
                    && view.refusal.is_some()
                {
                    self.semantic.nodes[5] = a1::Node {
                        local: 11,
                        parent: 3,
                        role: a1::Role::Label,
                        label: a1::Label::new(
                            "Last actual refusal identity/code; Name reads full value",
                        )
                        .unwrap(),
                        bounds: a1::Rect {
                            x: 0,
                            y: 41,
                            width: 640,
                            height: 7,
                        },
                        value: text_value(65),
                        ..root
                    };
                    self.semantic.nodes[6] = a1::Node {
                        local: 12,
                        parent: 3,
                        role: a1::Role::Label,
                        label: a1::Label::new("Refusal count/observed tick; Name reads full value")
                            .unwrap(),
                        bounds: a1::Rect {
                            x: 0,
                            y: 51,
                            width: 640,
                            height: 7,
                        },
                        value: text_value(66),
                        ..root
                    };
                }
                self.semantic.nodes[7] = a1::Node {
                    local: 8,
                    parent: 3,
                    role: a1::Role::Label,
                    label: a1::Label::new(if writable {
                        "Explicit READ/WRITE request"
                    } else {
                        "READ ONLY request"
                    })
                    .unwrap(),
                    bounds: a1::Rect {
                        x: 150,
                        y: 70,
                        width: 150,
                        height: 10,
                    },
                    ..root
                };
                let mut nonce = if mode == ev_workspace_root::render::Mode::System {
                    *b"Operation nonce 0000000000000000"
                } else {
                    *b"Protected nonce 0000000000000000"
                };
                semantic_hex(
                    &mut nonce[16..32],
                    if mode == ev_workspace_root::render::Mode::System {
                        recipient.map_or(0, |r| r.nonce)
                    } else {
                        self.protected.header.protected_scope_nonce
                    },
                );
                self.semantic.nodes[8] = a1::Node {
                    local: 9,
                    parent: 3,
                    role: a1::Role::Label,
                    label: a1::Label::new(core::str::from_utf8(&nonce).unwrap()).unwrap(),
                    bounds: a1::Rect {
                        x: 520,
                        y: 11,
                        width: 120,
                        height: 10,
                    },
                    ..root
                };
                for (i, (x, width, label)) in [
                    (0, 45, "Previous metadata entry"),
                    (45, 45, "Next metadata entry"),
                    (90, 60, "Parent directory"),
                    (150, 100, "Change requested READ/WRITE rights"),
                    (
                        300,
                        200,
                        if shutdown_dialog {
                            "Shutdown requires separate physical Root confirmation"
                        } else if mode == ev_workspace_root::render::Mode::Revoke {
                            "Confirm exact File revoke; protected fresh gesture"
                        } else {
                            "Select or confirm; explicit protected opt-in and fresh gesture"
                        },
                    ),
                    (
                        500,
                        140,
                        if shutdown_dialog {
                            "Shutdown cancellation uses physical Esc"
                        } else {
                            "Cancel current protected operation"
                        },
                    ),
                ]
                .into_iter()
                .enumerate()
                {
                    self.semantic.nodes[9 + i] = a1::Node {
                        local: 32 + i as u16,
                        parent: 3,
                        role: a1::Role::Button,
                        flags: if shutdown_dialog {
                            if i == 4 { 3 } else { 1 }
                        } else if i == 4 {
                            2
                        } else {
                            u8::from(
                                !dialog || mode == ev_workspace_root::render::Mode::Revoke && i < 4,
                            )
                        },
                        actions: u8::from(
                            !shutdown_dialog
                                && i != 4
                                && dialog
                                && !(mode == ev_workspace_root::render::Mode::Revoke && i < 4),
                        ),
                        label: a1::Label::new(label).unwrap(),
                        bounds: a1::Rect {
                            x,
                            y: 70,
                            width,
                            height: 10,
                        },
                        ..root
                    };
                }
                let source_nav = matches!(
                    mode,
                    ev_workspace_root::render::Mode::Picker
                        | ev_workspace_root::render::Mode::Refused
                ) && self
                    .owner
                    .pending
                    .is_some_and(|p| p.purpose == super::filegrant::Purpose::Open)
                    && self.owner.challenge.is_none();
                self.semantic.nodes[15] = if let display::Body::Desktop(view) = body
                    && view.dataset != [0; 16]
                {
                    a1::Node {
                        local: 13,
                        parent: 3,
                        role: a1::Role::Label,
                        label: a1::Label::new("Exact recorded dataset UUID; Name reads full value")
                            .unwrap(),
                        bounds: a1::Rect {
                            x: 306,
                            y: 11,
                            width: 204,
                            height: 7,
                        },
                        value: text_value(34),
                        ..root
                    }
                } else {
                    a1::Node {
                        local: 38,
                        parent: 3,
                        role: a1::Role::Button,
                        flags: u8::from(!source_nav),
                        actions: u8::from(source_nav),
                        label: a1::Label::new(
                            "Source [V]: workspace, original Notes or original Private",
                        )
                        .unwrap(),
                        bounds: a1::Rect {
                            x: 250,
                            y: 70,
                            width: 50,
                            height: 10,
                        },
                        ..root
                    }
                };
                16
            }
        };
        let header = a1::Header {
            nonce: self.semantic.nonce,
            page: self.semantic.page,
            pages: 3,
            model: presented.model,
            view: presented.view,
            frame: presented.frame,
            mapping_epoch: presented.mapping_epoch,
            width: 640,
            height: 80,
            keyboard: 0,
            modal: if dialog && self.semantic.page != 1 {
                3
            } else {
                0
            },
        };
        require(
            self.semantic
                .candidate
                .replace(header, &self.semantic.nodes[..count])
                .is_ok(),
            1675,
        );
        self.semantic.relay = 0;
        self.semantic.consumer_started = false;
        self.semantic.selected = 0;
        self.semantic.phase = Phase::Relay;
        self.semantic_context(Mode::Receiving, self.semantic.nonce);
    }
}

impl Root<'_> {
    pub(super) fn semantic_click(&mut self, node: u16) {
        self.semantic_click_until(node, deadline(v5::resources::RPC_TICKS));
    }
    pub(super) fn semantic_click_until(&mut self, node: u16, original_by: u64) -> bool {
        let by = original_by.min(deadline(v5::resources::RPC_TICKS));
        if now() >= by
            || self.semantic.phase != Phase::Ready
            || self.owner.pending.is_some()
            || self.owner.challenge.is_some()
            || self.file_transition_modal()
        {
            return false;
        }
        let nonce = self.semantic.consumer_view;
        if self
            .accepted_view(Slot::Inspector)
            .is_none_or(|(_, v)| v != u64::from(nonce))
            || !self.semantic_current()
        {
            return false;
        }
        if self.inspector_self.enabled {
            return self.inspector_self_start_reader(node, by);
        }
        if !self.inspector_self_hold_ordinary(node, by) {
            return false;
        }
        if now() < by && self.queue(Child::Inspector, Command::Activate(node)) {
            true
        } else {
            self.inspector_self_abandon_ordinary();
            false
        }
    }
}

impl Root<'_> {
    fn semantic_operation(&mut self, intent: IntentKind, node: a1::Node, original_by: Option<u64>) {
        let lease = self.semantic.lease.unwrap();
        if self.grant.is_some() && lease.target != 3 && intent == IntentKind::Activate {
            return; // retained file debt cannot initiate another App file operation
        }
        let header = self.semantic.candidate.header();
        let (kind, text_revision) = match intent {
            IntentKind::ReadLabel => (
                op::Kind::Range {
                    kind: op::RangeKind::AccessibleLabel,
                    offset: 0,
                    length: 128,
                },
                header.view,
            ),
            IntentKind::ReadDocument => {
                if lease.rights & 4 == 0
                    || !matches!(node.role, a1::Role::Document | a1::Role::TextBox)
                {
                    return;
                }
                let a1::Value::TextRange { offset, .. } = node.value else {
                    return;
                };
                (
                    op::Kind::Range {
                        kind: op::RangeKind::Document,
                        offset,
                        length: 128,
                    },
                    header.view,
                )
            }
            IntentKind::MoreText => {
                let Some((local, kind, offset)) = self.semantic.range_last else {
                    return;
                };
                if node.local != local || kind == op::RangeKind::Document && lease.rights & 4 == 0 {
                    return;
                }
                (
                    op::Kind::Range {
                        kind,
                        offset,
                        length: 128,
                    },
                    header.view,
                )
            }
            IntentKind::Activate
            | IntentKind::Select
            | IntentKind::ScrollUp
            | IntentKind::ScrollDown => {
                if lease.rights & 2 == 0 || lease.target == 3 {
                    return;
                }
                let action = match intent {
                    IntentKind::Activate => op::Action::Activate,
                    IntentKind::Select => op::Action::Select,
                    _ => op::Action::Scroll,
                };
                let model_action = match action {
                    op::Action::Activate => ev_workspace_shell::Action::Activate,
                    op::Action::Select => ev_workspace_shell::Action::Select,
                    _ => ev_workspace_shell::Action::Scroll,
                };
                let policy = self.policy.as_mut().unwrap();
                let id = ev_workspace_shell::NodeId {
                    window: lease.window.unwrap(),
                    local: node.local,
                };
                let Ok(ticket) = policy.desktop.semantic_action(
                    model_owner(lease.client),
                    lease.provider,
                    id,
                    self.semantic.publication,
                    model_action,
                ) else {
                    return;
                };
                if policy
                    .desktop
                    .dispatch_semantic(model_owner(lease.client), ticket)
                    .is_err()
                {
                    return;
                }
                let argument = if action == op::Action::Scroll {
                    if intent == IntentKind::ScrollUp {
                        (-1i64) as u64
                    } else {
                        1
                    }
                } else {
                    0
                };
                (
                    op::Kind::Action { action, argument },
                    if action == op::Action::Select {
                        header.view
                    } else {
                        0
                    },
                )
            }
            _ => return,
        };
        self.semantic.next_operation = self.semantic_nonce();
        let request = op::Request {
            nonce: self.semantic.next_operation,
            node: node.local,
            binding: op::Binding {
                snapshot_nonce: header.nonce,
                model: header.model,
                view: header.view,
                frame: header.frame,
                mapping_epoch: header.mapping_epoch,
                text_revision,
            },
            kind,
        };
        require(request.validate().is_ok(), 1677);
        self.semantic.operation = Some(request);
        self.semantic.operation_next = 0;
        self.semantic.operation_abort_sent = false;
        self.semantic.range = None;
        self.semantic.range_reply = None;
        self.semantic.range_refused = None;
        self.semantic.range_descriptor = 0;
        self.semantic.range_next = 0;
        self.semantic.by = original_by.map_or_else(
            || deadline(v5::resources::FILE_TRANSACTION_TICKS),
            |by| by.min(deadline(v5::resources::FILE_TRANSACTION_TICKS)),
        );
        if let op::Kind::Range { kind, offset, .. } = kind {
            self.semantic.range_offset = offset;
            if lease.target == 3 {
                self.semantic_local_range(request);
                return;
            }
            if kind == op::RangeKind::AccessibleLabel
                && !matches!(node.value, a1::Value::TextRange { .. })
            {
                let text = op::text_range(node.label.as_str(), offset, 128);
                self.semantic.range_reply = text
                    .ok()
                    .and_then(|s| op::RangeReply::new(request.nonce, node.local, kind, s).ok());
                if self.semantic.range_reply.is_none() {
                    self.semantic.range_refused =
                        Some(op::terminal(request.nonce, Err(op::Refusal::Stale)));
                }
                self.semantic.range_last = Some((
                    node.local,
                    kind,
                    offset + text.map_or(0, |s| s.len() as u64),
                ));
                self.semantic.phase = Phase::RangeRelay;
                return;
            }
            self.semantic.range = Some(op::RangeReceiver::new(request).unwrap());
        }
        self.semantic.phase = Phase::OpSend;
    }
    fn semantic_local_range(&mut self, request: op::Request) {
        let op::Kind::Range { kind, offset, .. } = request.kind else {
            return;
        };
        let body = self.protected.body.unwrap();
        let result = if kind != op::RangeKind::AccessibleLabel {
            Err(op::Refusal::Denied)
        } else {
            match request.node {
                4=>semantic_range_text(request,match body{display::Body::Desktop(v)=>v.status,display::Body::Assistive(_)=>b"Inspect the full scoped actual recipients and explicit rights"}),
                10=>semantic_range_text(request,match body{display::Body::Desktop(v)=>v.title,display::Body::Assistive(_)=>b"Semantic owner permission"}),
                5=>match body {
                    display::Body::Desktop(v)=>v.entry.ok_or(op::Refusal::Unsupported).and_then(|e|semantic_range_text(request,e.name.as_bytes())),
                    _=>Err(op::Refusal::Unsupported),
                },
                6=>match body {
                    display::Body::Desktop(v)=>v.entry.ok_or(op::Refusal::Unsupported).and_then(|e|{
                        let mut text=*b"Object 0000 generation 0000000000000000 revision 0000000000000000";
                        let digits=b"0123456789abcdef";for i in 0..4{ text[7+i]=digits[((e.object.slot>>((3-i)*4))&15)as usize];}
                        semantic_hex(&mut text[23..39],e.object.generation);semantic_hex(&mut text[49..65],e.revision);semantic_range_text(request,&text)
                    }),_=>Err(op::Refusal::Unsupported),
                },
                7=>match body {
                    display::Body::Desktop(v)=>v.recipient.ok_or(op::Refusal::Unsupported).and_then(|r|{
                        let mut text=*b"E1 P0000000000000000 T0000000000000000";text[1]=b'0'+r.editor;
                        semantic_hex(&mut text[4..20],r.process);semantic_hex(&mut text[22..38],r.thread);semantic_range_text(request,&text)
                    }),_=>Err(op::Refusal::Unsupported),
                },
                13=>match body {
                    display::Body::Desktop(v) if v.dataset != [0;16]=>semantic_range_text(request,&ev_workspace_root::render::dataset_text(v.dataset)),
                    _=>Err(op::Refusal::Unsupported),
                },
                11|12=>match body {
                    display::Body::Desktop(view)=>view.refusal.ok_or(op::Refusal::Unsupported).and_then(|r|{
                        if request.node==11 {
                            let mut text=*b"Last refusal PID 0000000000000000 thread 0000000000000000 code 00";
                            semantic_hex(&mut text[17..33],r.process);semantic_hex(&mut text[41..57],r.thread);let digits=b"0123456789abcdef";text[63]=digits[(r.code>>4)as usize];text[64]=digits[(r.code&15)as usize];semantic_range_text(request,&text)
                        }else{
                            let mut text=*b"Refusal count 0000000000000000 Root observed tick 0000000000000000";
                            semantic_hex(&mut text[14..30],r.count);semantic_hex(&mut text[50..66],r.observed);semantic_range_text(request,&text)
                        }
                    }),_=>Err(op::Refusal::Unsupported),
                },
                _=>self.semantic.candidate.nodes().iter().find(|n|n.local==request.node).ok_or(op::Refusal::Stale).and_then(|node|semantic_range_text(request,node.label.as_str().as_bytes())),
            }
        };
        match result {
            Ok((reply, count)) => {
                self.semantic.range_reply = Some(reply);
                self.semantic.range_last = Some((request.node, kind, offset + count as u64));
            }
            Err(reason) => {
                self.semantic.range_refused = Some(op::terminal(request.nonce, Err(reason)))
            }
        }
        self.semantic.phase = Phase::RangeRelay;
    }
    fn semantic_operation_event(&mut self, frame: Frame) -> bool {
        if !matches!(
            self.semantic.phase,
            Phase::OpSend | Phase::OpWait | Phase::OpAbort
        ) {
            return false;
        }
        let Some(request) = self.semantic.operation else {
            self.semantic.phase = Phase::Blocked;
            return true;
        };
        if frame.word == request.nonce
            && frame.field == op::ABORT_ACK
            && self.semantic.phase == Phase::OpAbort
            && self.semantic.operation_abort_sent
        {
            self.semantic.operation = None;
            self.semantic.range = None;
            self.semantic_after_source_abort();
            return true;
        }
        if (0x9f00..=0x9f04).contains(&frame.field) && frame.word == request.nonce {
            if self.semantic.operation_next != 18 {
                self.semantic_revoke(true);
                return true;
            }
            if self.semantic.phase == Phase::OpAbort && self.semantic.operation_abort_sent {
                return true;
            }
            match request.kind {
                op::Kind::Range { .. }
                    if self.semantic.phase != Phase::OpAbort && self.semantic_current() =>
                {
                    if frame.field == 0x9f00 {
                        self.semantic_revoke(true);
                        return true;
                    }
                    self.semantic.range_refused = Some(frame);
                    self.semantic.range = None;
                    self.semantic.phase = Phase::RangeRelay;
                }
                _ => {
                    self.semantic.operation = None;
                    self.semantic.range = None;
                    // A canonical terminal consumed here completes this exact
                    // source request. Never manufacture an Abort with no retained
                    // operation after clearing its identity.
                    self.semantic_after_source_abort();
                }
            }
            return true;
        }
        if self.semantic.phase == Phase::OpAbort {
            return true;
        }
        if self.semantic.phase != Phase::OpWait || self.semantic.operation_next != 18 {
            self.semantic_revoke(true);
            return true;
        }
        let Some(range) = self.semantic.range.as_mut() else {
            self.semantic_revoke(true);
            return true;
        };
        match range.push(frame) {
            Ok(true) => {
                if !self.semantic_current() {
                    self.semantic_revoke(false);
                    return true;
                }
                let text = self.semantic.range.as_ref().unwrap().staged_text().unwrap();
                let op::Kind::Range { kind, offset, .. } = request.kind else {
                    self.semantic_revoke(true);
                    return true;
                };
                self.semantic.range_reply =
                    Some(op::RangeReply::new(request.nonce, request.node, kind, text).unwrap());
                self.semantic.range_last = Some((request.node, kind, offset + text.len() as u64));
                self.semantic.range = None;
                self.semantic.phase = Phase::RangeRelay;
            }
            Ok(false) => (),
            Err(_) => self.semantic_revoke(true),
        }
        true
    }
    fn semantic_operation_tick(&mut self) -> bool {
        if !matches!(
            self.semantic.phase,
            Phase::OpSend
                | Phase::OpWait
                | Phase::OpAbort
                | Phase::RangeRelay
                | Phase::RangeAwaitPresent
        ) {
            return false;
        }
        if matches!(
            self.semantic.phase,
            Phase::OpSend | Phase::OpWait | Phase::RangeRelay | Phase::RangeAwaitPresent
        ) && now() >= self.semantic.by
        {
            self.semantic_revoke(true);
            return true;
        }
        let Some(request) = self.semantic.operation else {
            self.semantic.phase = Phase::Blocked;
            return true;
        };
        let lease = self.semantic.lease.unwrap();
        match self.semantic.phase {
            Phase::OpSend => {
                if (self.semantic.operation_next == 0 || self.semantic.operation_next == 17)
                    && !self.semantic_current()
                {
                    self.semantic_revoke(false);
                    return true;
                }
                let frame = request
                    .frame(self.semantic.operation_next)
                    .unwrap()
                    .unwrap();
                match send(
                    self.channel(control_channel(app_child(lease.target).unwrap()).unwrap()),
                    frame.encode(),
                ) {
                    Ok(true) => {
                        self.semantic.operation_next += 1;
                        if self.semantic.operation_next == 18 {
                            self.semantic.phase = Phase::OpWait;
                        }
                    }
                    Ok(false) => (),
                    Err(()) => self.semantic.phase = Phase::Blocked,
                }
            }
            Phase::OpAbort => {
                if !self.semantic.operation_abort_sent {
                    match send(
                        self.channel(control_channel(app_child(lease.target).unwrap()).unwrap()),
                        Frame {
                            field: op::ABORT,
                            word: request.nonce,
                        }
                        .encode(),
                    ) {
                        Ok(true) => self.semantic.operation_abort_sent = true,
                        Ok(false) => (),
                        Err(()) => self.semantic.phase = Phase::Blocked,
                    }
                }
            }
            Phase::RangeRelay => {
                if (self.semantic.range_descriptor == 0
                    || self.semantic.range_descriptor == 18
                        && (self.semantic.range_next == 67
                            || self.semantic.range_refused.is_some()))
                    && !self.semantic_current()
                {
                    self.semantic_revoke(false);
                    return true;
                }
                let frame = if self.semantic.range_descriptor < 18 {
                    request
                        .frame(self.semantic.range_descriptor)
                        .unwrap()
                        .unwrap()
                } else if let Some(refused) = self.semantic.range_refused {
                    refused
                } else {
                    self.semantic
                        .range_reply
                        .as_ref()
                        .unwrap()
                        .frame(self.semantic.range_next)
                        .unwrap()
                };
                match send(self.channel(Channel::InspectorControl), frame.encode()) {
                    Ok(true) => {
                        if self.semantic.range_descriptor < 18 {
                            self.semantic.range_descriptor += 1;
                        } else if self.semantic.range_refused.is_some()
                            || self.semantic.range_next == 67
                        {
                            self.semantic.phase = Phase::RangeAwaitPresent;
                        } else {
                            self.semantic.range_next += 1;
                        }
                    }
                    Ok(false) => (),
                    Err(()) => self.semantic.phase = Phase::Blocked,
                }
            }
            _ => (),
        }
        true
    }
}

impl Root<'_> {
    /// Called only by the actual authenticated Input path after FreshGate has
    /// accepted this deliberate press following the exact protected barrier.
    pub(super) fn semantic_confirm_input(&mut self, serial: u32) -> bool {
        if self.shutdown.active() {
            return false;
        }
        let Some(lease) = self.semantic.lease else {
            return false;
        };
        if self.semantic.phase != Phase::Ready
            || lease.target != 3
            || lease.rights & 10 != 10
            || self.owner.pending.is_none()
            || self.semantic.candidate.header().modal == 0
            || self.owner.challenge.is_some() && self.owner.witness.is_none()
            || self.grant.is_some()
            || !self.semantic_current()
        {
            return false;
        }
        let challenge = self.owner.challenge;
        let Some(root) = self.semantic_presented() else {
            return false;
        };
        let Some((inspector_frame, view)) = self.accepted_view(Slot::Inspector) else {
            return false;
        };
        if view != u64::from(self.semantic.consumer_view) {
            return false;
        }
        let ticket = ConfirmTicket {
            client: lease.client,
            provider: lease.provider,
            challenge,
            root,
            view: self.semantic.consumer_view,
            inspector_frame,
            input_serial: self.input.serial(serial),
            input_sequence: serial,
            input_lifetime: self.input.lifetime,
            by: deadline(v5::resources::RPC_TICKS),
        };
        if !self.queue(Child::Inspector, Command::Activate(213)) {
            return false;
        }
        self.semantic.confirm = Some(ticket);
        true
    }
    fn semantic_confirm_intent(&mut self, intent: Intent) {
        if self.shutdown.active() {
            self.semantic.confirm = None;
            return;
        }
        let Some(ticket) = self.semantic.confirm.take() else {
            return;
        };
        let Some(lease) = self.semantic.lease else {
            return;
        };
        if lease.target != 3
            || lease.rights & 10 != 10
            || lease.client != ticket.client
            || lease.provider != ticket.provider
            || self.semantic.consumer_view != ticket.view
            || intent.view != ticket.view
            || now() >= ticket.by
            || self.owner.challenge != ticket.challenge
            || self.input.lifetime != ticket.input_lifetime
            || self.input.serial(ticket.input_sequence) != ticket.input_serial
            || self.semantic_presented() != Some(ticket.root)
            || self
                .accepted_view(Slot::Inspector)
                .is_none_or(|(frame, view)| {
                    frame < ticket.inspector_frame || view != u64::from(ticket.view)
                })
        {
            return;
        }
        if ticket.challenge.is_some() {
            self.confirm_grant_assistive(ticket.input_serial, ticket.provider);
        } else {
            self.choose(ticket.input_sequence);
        }
    }
}

impl Root<'_> {
    pub(super) fn semantic_cancel_confirmation(&mut self) {
        self.semantic.confirm = None;
    }
}

fn semantic_hex(out: &mut [u8], value: u64) {
    let digits = b"0123456789abcdef";
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = digits[((value >> ((15 - i) * 4)) & 15) as usize];
    }
}
impl Root<'_> {
    fn semantic_root_activate(&mut self, node: a1::Node) {
        if self.shutdown.active() {
            return;
        }
        let lease = self.semantic.lease.unwrap();
        if lease.rights & 2 == 0 || node.flags & 3 != 0 || node.actions & 1 == 0 {
            return;
        }
        match node.local {
            16..=18
                if self.owner.pending.is_none()
                    && self.owner.challenge.is_none()
                    && !self.file_transition_modal() =>
            {
                let _ = self.policy.as_mut().unwrap().layer(
                    [Layer::Simple, Layer::Advanced, Layer::AbsoluteAccess]
                        [usize::from(node.local - 16)],
                );
                self.owner.dirty = true;
            }
            19 => {
                if let Some(index) = self.policy.as_ref().unwrap().focused() {
                    self.request_revoke(index);
                }
            }
            20 => {
                let index = self.policy.as_ref().unwrap().focused().unwrap_or(1);
                self.request_picker(if matches!(index, 1 | 2) { index } else { 1 });
            }
            21 => {
                let _ = self.policy.as_mut().unwrap().focus(3);
                self.scene_dirty = true;
            }
            22 | 23 => {
                self.status =
                    b"Checked shutdown/restart is refused until actual Workspace/device quiescence";
                self.owner.dirty = true;
            }
            24 => {
                if let Some(index) = self.policy.as_ref().unwrap().focused() {
                    self.request_revoke(index);
                }
            }
            32 if self.owner.challenge.is_none() => self.browse(-1),
            33 if self.owner.challenge.is_none() => self.browse(1),
            34 if self.owner.challenge.is_none() => self.picker_up(),
            35 if self.owner.challenge.is_none() => self.choose_rights(),
            37 if self.file_notice_fenced() => self.cancel_grant(),
            37 => self.cancel_owner(),
            38 if !self.owner.dirty
                && self.owner.challenge.is_none()
                && self
                    .owner
                    .pending
                    .is_some_and(|p| p.purpose == super::filegrant::Purpose::Open) =>
            {
                // Exact current authorized Root reader navigation only. The
                // next source is actually inspected; this grants no File SEND.
                self.picker_source();
            }
            _ => (),
        }
    }
}

fn semantic_range_text(
    request: op::Request,
    text: &[u8],
) -> Result<(op::RangeReply, usize), op::Refusal> {
    let op::Kind::Range {
        kind,
        offset,
        length,
    } = request.kind
    else {
        return Err(op::Refusal::Denied);
    };
    let text = core::str::from_utf8(text).map_err(|_| op::Refusal::Stale)?;
    let part = op::text_range(text, offset, length).map_err(|_| op::Refusal::Stale)?;
    op::RangeReply::new(request.nonce, request.node, kind, part)
        .map(|reply| (reply, part.len()))
        .map_err(|_| op::Refusal::Stale)
}

impl Root<'_> {
    pub(super) fn semantic_modal_reader_input(&mut self, node: u16, serial: u32) -> bool {
        if node == 213 {
            return self.semantic_confirm_input(serial);
        }
        let Some(lease) = self.semantic.lease else {
            return false;
        };
        if self.semantic.phase != Phase::Ready
            || lease.target != 3
            || lease.rights & 1 == 0
            || self.semantic.candidate.header().modal == 0
            || !matches!(node,201..=204|206..=207|209|212|214|218|300..=315)
            || !self.semantic_current()
            || self
                .accepted_view(Slot::Inspector)
                .is_none_or(|(_, view)| view != u64::from(self.semantic.consumer_view))
        {
            return false;
        }
        self.queue(Child::Inspector, Command::Activate(node))
    }
}
