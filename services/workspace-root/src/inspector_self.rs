//! Private Inspector self-tree receiver. Source identity, accepted Display and
//! current underlying provider are captured by the actual native Root adapter.
//! No packet field supplies those facts or protected-confirmation authority.
use crate::{Identity, semantic::Presented};
use ev_native_inspector::self_tree::{Request, decode_reply};
use ev_userspace_contract::root_v5::assistive::{Intent, IntentKind};
use ev_workspace_client::semantic::{self as a1, Progress, Receiver, Snapshot};
use ev_workspace_shell::{ProviderLease, WindowId};
mod reader;
pub use reader::{ReaderOutcome, ReaderPhase, ReaderTransfer};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context {
    pub reader: bool,
    pub phase: u8,
    pub view: u32,
    pub rights: u8,
    pub target: u8,
    pub provider: Option<ProviderLease>,
    pub source: Option<Identity>,
    pub source_presented: Option<Presented>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    pub owner: Identity,
    pub window: WindowId,
    pub presented: Presented,
    pub context: Context,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryScope {
    pub owner: Identity,
    pub window: WindowId,
    pub model: u64,
}

/// One ordinary physical navigation desire, never a loan or approval. Waiting
/// for the existing sample cannot renew its original cut or replace its scope.
pub struct EntryWait {
    pending: Option<(EntryScope, u64)>,
}
impl Default for EntryWait {
    fn default() -> Self {
        Self::new()
    }
}
impl EntryWait {
    pub const fn new() -> Self {
        Self { pending: None }
    }
    pub const fn pending(&self) -> bool {
        self.pending.is_some()
    }
    pub fn request(&mut self, scope: EntryScope, by: u64) -> Result<(), a1::Error> {
        if self.pending.is_some() {
            return Err(a1::Error::State);
        }
        if !scope.owner.valid() || matches!(scope.model, 0 | u64::MAX) || matches!(by, 0 | u64::MAX)
        {
            return Err(a1::Error::Value);
        }
        self.pending = Some((scope, by));
        Ok(())
    }
    /// The native adapter supplies actual current focus/owner/window/scene.
    /// Cancellation drops only this unsent desire, never a Capture or Present.
    pub fn current(&mut self, current: Option<EntryScope>, now: u64) -> Option<u64> {
        let (scope, by) = self.pending?;
        if current != Some(scope) || now >= by || now == u64::MAX {
            self.pending = None;
            None
        } else {
            Some(by)
        }
    }
    pub fn cancel(&mut self) {
        self.pending = None;
    }
}
/// One unsent ordinary physical Enter. Its accepted Inspector presentation is
/// immutable while the independent current self-tree capture finishes. This
/// owns no stream/Present credit and cannot authorize protected confirmation.
pub struct EnterWait {
    pending: Option<(Binding, u64)>,
}
impl Default for EnterWait {
    fn default() -> Self {
        Self::new()
    }
}
impl EnterWait {
    pub const fn new() -> Self {
        Self { pending: None }
    }
    pub const fn pending(&self) -> bool {
        self.pending.is_some()
    }
    pub const fn binding(&self) -> Option<Binding> {
        match self.pending {
            Some((binding, _)) => Some(binding),
            None => None,
        }
    }
    /// Expiry alone cancels only an unsent desire, with no Display assertion
    /// and no effect on an independently accepted snapshot/abort/Present.
    pub fn expire(&mut self, now: u64) {
        if self.pending.is_some_and(|(_, by)| now >= by) {
            self.cancel();
        }
    }
    pub fn request(&mut self, binding: Binding, by: u64) -> Result<(), a1::Error> {
        if self.pending.is_some() {
            return Err(a1::Error::State);
        }
        if !binding.owner.valid() || matches!(by, 0 | u64::MAX) {
            return Err(a1::Error::Value);
        }
        self.pending = Some((binding, by));
        Ok(())
    }
    /// Actual focus, actor, accepted frame, scene and provider are rechecked
    /// even before the capture becomes ready. A new binding cannot inherit it.
    pub fn current(&mut self, current: Option<Binding>, now: u64) -> Option<u64> {
        let (binding, by) = self.pending?;
        if current != Some(binding) || now >= by || now == u64::MAX {
            self.cancel();
            None
        } else {
            Some(by)
        }
    }
    pub fn ready(
        &mut self,
        current: Option<Binding>,
        now: u64,
        capture: &Capture,
        published: u64,
        current_publication: Option<u64>,
    ) -> Option<(u16, u64)> {
        let by = self.current(current, now)?;
        if published == 0 || current_publication != Some(published) {
            return None;
        }
        Some((capture.control(current?)?, by))
    }
    /// Call only once the ordinary command has entered the immutable outbox,
    /// or when explicitly abandoning the still-unsent desire. No retry credit.
    pub fn cancel(&mut self) {
        self.pending = None;
    }
}
/// A transferred ordinary reader command waits for its one exact App intent.
/// It is separate from protected physical confirmation and accepted RPC debt.
pub struct OrdinaryReceipt {
    binding: Binding,
    kind: IntentKind,
    index: u8,
    by: u64,
}
impl OrdinaryReceipt {
    pub fn new(binding: Binding, control: u16, selected: u8, count: u8, by: u64) -> Option<Self> {
        if control != 14 && !binding.context.reader {
            return None;
        }
        let kind = match control {
            14 if !binding.context.reader => IntentKind::Enable,
            201 => IntentKind::PreviousNode,
            202 => IntentKind::NextNode,
            203 | 300..=315 => IntentKind::AssistiveFocus,
            204 => IntentKind::Activate,
            205 => IntentKind::KeyboardFocus,
            206 => IntentKind::Expand,
            207 => IntentKind::ReadLabel,
            208 => IntentKind::ReadDocument,
            209 => IntentKind::Refresh,
            210 => IntentKind::PreviousSource,
            211 => IntentKind::NextSource,
            212 => IntentKind::Disable,
            214 => IntentKind::Cancel,
            215 => IntentKind::Select,
            216 => IntentKind::ScrollUp,
            217 => IntentKind::ScrollDown,
            218 => IntentKind::MoreText,
            _ => return None, // 213 protected Confirm has no ordinary receipt
        };
        if !binding.owner.valid()
            || matches!(by, 0 | u64::MAX)
            || count > a1::MAX_NODES as u8
            || selected >= count && count != 0
            || selected >= a1::MAX_NODES as u8
        {
            return None;
        }
        let index = match control {
            14 => 0,
            201 if count > 0 => (selected + count - 1) % count,
            202 if count > 0 => (selected + 1) % count,
            300..=315 if control - 300 < u16::from(count) => (control - 300) as u8,
            300..=315 => return None,
            _ => selected,
        };
        Some(Self {
            binding,
            kind,
            index,
            by,
        })
    }
    /// Consuming validation prevents the adapter from replaying this receipt.
    /// An App reply cannot choose a different action/index or renew the cut.
    pub fn accept(self, current: Option<Binding>, intent: Intent, now: u64) -> bool {
        self.matches(current, intent, now)
    }
    pub fn matches(&self, current: Option<Binding>, intent: Intent, now: u64) -> bool {
        self.current(current, now)
            && intent.view == self.binding.context.view
            && intent.kind == self.kind
            && intent.index == self.index
    }
    pub fn current(&self, current: Option<Binding>, now: u64) -> bool {
        current == Some(self.binding) && now < self.by
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefreshPhase {
    Idle,
    AwaitAction(u8),
    Ready,
}
/// One desired metadata refresh. An old Display binding cannot acknowledge an
/// ordinary App action: the native adapter first validates its actual origin,
/// exact held gesture/view and matching action, then calls `accepted_action`.
pub struct StatsRefresh {
    phase: RefreshPhase,
}
impl Default for StatsRefresh {
    fn default() -> Self {
        Self::new()
    }
}
impl StatsRefresh {
    pub const fn new() -> Self {
        Self {
            phase: RefreshPhase::Idle,
        }
    }
    pub const fn pending(&self) -> bool {
        !matches!(self.phase, RefreshPhase::Idle)
    }
    pub const fn ready(&self) -> bool {
        matches!(self.phase, RefreshPhase::Ready)
    }
    pub fn request(&mut self, action: u8) -> bool {
        if !(1..=3).contains(&action) || self.pending() {
            return false;
        }
        self.phase = RefreshPhase::AwaitAction(action);
        true
    }
    pub fn accepted_action(&mut self, action: u8) -> bool {
        if self.phase != RefreshPhase::AwaitAction(action) {
            return false;
        }
        self.phase = RefreshPhase::Ready;
        true
    }
    /// A native return from external reader mode needs one fresh stats sample,
    /// but cannot replace an already requested exact ordinary action.
    pub fn context_ready(&mut self) -> bool {
        if self.pending() {
            return false;
        }
        self.phase = RefreshPhase::Ready;
        true
    }
    pub fn started(&mut self) -> bool {
        if !self.ready() {
            return false;
        }
        self.phase = RefreshPhase::Idle;
        true
    }
    pub fn clear(&mut self) {
        self.phase = RefreshPhase::Idle;
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Request,
    Receiving,
    Ready,
    AbortSend,
    Aborting,
    Blocked,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Ignored,
    Receiving,
    Complete,
    Refused,
    Stale,
    Aborted,
    Fenced,
}
pub struct Capture {
    receiver: Receiver,
    candidate: Snapshot,
    binding: Option<Binding>,
    phase: Phase,
    nonce: u32,
    page: u8,
    by: u64,
}
impl Default for Capture {
    fn default() -> Self {
        Self::new()
    }
}
impl Capture {
    pub const fn new() -> Self {
        Self {
            receiver: Receiver::new(),
            candidate: Snapshot::EMPTY,
            binding: None,
            phase: Phase::Idle,
            nonce: 0,
            page: 1,
            by: 0,
        }
    }
    pub const fn phase(&self) -> Phase {
        self.phase
    }
    pub const fn binding(&self) -> Option<Binding> {
        self.binding
    }
    pub const fn nonce(&self) -> u32 {
        self.nonce
    }
    pub fn candidate(&self) -> &Snapshot {
        &self.candidate
    }
    pub fn begin(&mut self, binding: Binding, page: u8, by: u64) -> Result<(), a1::Error> {
        if !matches!(self.phase, Phase::Idle | Phase::Ready) {
            return Err(a1::Error::State);
        }
        if !binding.owner.valid() || !(1..=3).contains(&page) || matches!(by, 0 | u64::MAX) {
            return Err(a1::Error::Value);
        }
        let Some(nonce) = self.nonce.checked_add(1).filter(|n| *n != u32::MAX) else {
            self.phase = Phase::Blocked;
            return Err(a1::Error::Nonce);
        };
        self.nonce = nonce;
        self.page = page;
        self.by = by;
        self.binding = Some(binding);
        self.phase = Phase::Request;
        Ok(())
    }
    pub fn next(&self) -> Option<[u8; 8]> {
        match self.phase {
            Phase::Request => Request::Snapshot {
                page: self.page,
                nonce: self.nonce,
            }
            .encode()
            .ok(),
            Phase::AbortSend => Request::Abort { nonce: self.nonce }.encode().ok(),
            _ => None,
        }
    }
    /// Advance only after actual status0 on the original held InspectorControl.
    pub fn sent(&mut self, bytes: [u8; 8]) -> Result<(), a1::Error> {
        if self.next() != Some(bytes) {
            return Err(a1::Error::Order);
        }
        match self.phase {
            Phase::Request => {
                self.receiver.request(self.page, self.nonce)?;
                self.phase = Phase::Receiving;
            }
            Phase::AbortSend => self.phase = Phase::Aborting,
            _ => return Err(a1::Error::State),
        }
        Ok(())
    }
    /// A new abort cut bounds independent drain; the accepted snapshot's cut
    /// is not renewed. Repeated invalidation never extends a pending drain.
    pub fn invalidate(&mut self, abort_by: u64) {
        match self.phase {
            Phase::Request | Phase::Ready => {
                self.phase = Phase::Idle;
                self.binding = None;
            }
            Phase::Receiving => {
                if self.receiver.abort().is_err() {
                    self.phase = Phase::Blocked;
                    return;
                }
                self.phase = Phase::AbortSend;
                self.by = abort_by;
            }
            _ => (),
        }
    }
    pub fn tick(&mut self, now: u64, abort_by: u64) {
        if now < self.by {
            return;
        }
        match self.phase {
            Phase::Request => {
                self.phase = Phase::Idle;
                self.binding = None;
            }
            Phase::Receiving => self.invalidate(abort_by),
            Phase::AbortSend | Phase::Aborting => {
                self.receiver.expire();
                self.phase = Phase::Blocked;
            }
            _ => (),
        }
    }
    pub fn transport_failed(&mut self) {
        self.receiver.expire();
        self.phase = Phase::Blocked;
    }
    pub fn receive(
        &mut self,
        sender: Identity,
        bytes: [u8; 8],
        after: Option<Binding>,
        abort_by: u64,
    ) -> Outcome {
        if self.binding.is_none_or(|b| b.owner != sender) {
            return Outcome::Ignored;
        }
        if !matches!(
            self.phase,
            Phase::Receiving | Phase::AbortSend | Phase::Aborting
        ) {
            self.transport_failed();
            return Outcome::Fenced;
        }
        let result = decode_reply(bytes).and_then(|f| self.receiver.push(f));
        match result {
            Ok(Progress::Receiving) => Outcome::Receiving,
            Ok(Progress::Aborted) if self.phase == Phase::Aborting => {
                self.phase = Phase::Idle;
                self.binding = None;
                Outcome::Aborted
            }
            Ok(Progress::Aborted) => {
                // An ACK before our actual Abort SEND cannot certify drain.
                self.transport_failed();
                Outcome::Fenced
            }
            Ok(Progress::Refused(_)) if self.phase == Phase::Receiving => {
                self.phase = Phase::Idle;
                self.binding = None;
                Outcome::Refused
            }
            Ok(Progress::Complete) if self.phase == Phase::Receiving => {
                if self.receiver.candidate(&mut self.candidate).is_err() {
                    self.invalidate(abort_by);
                    return Outcome::Fenced;
                }
                let header = self.candidate.header();
                let binding = self.binding.unwrap();
                if after != Some(binding)
                    || !binding.presented.matches(header)
                    || header.modal != 0
                    || header.pages != if binding.context.reader { 5 } else { 4 }
                {
                    self.phase = Phase::Idle;
                    self.binding = None;
                    return Outcome::Stale;
                }
                self.phase = Phase::Ready;
                Outcome::Complete
            }
            _ => {
                self.invalidate(abort_by);
                Outcome::Fenced
            }
        }
    }
    /// Resolve only the actual current own keyboard control. Disabled or
    /// protected controls and every unknown local ID fail closed. In particular
    /// no ordinary Enter can mint the independent protected Confirm ticket.
    pub fn control(&self, current: Binding) -> Option<u16> {
        if self.phase != Phase::Ready || self.binding != Some(current) {
            return None;
        }
        let local = self.candidate.header().keyboard;
        let node = self.candidate.nodes().iter().find(|n| n.local == local)?;
        if node.flags != 0 || node.actions & 5 == 0 {
            return None;
        }
        let mut parent = node.parent;
        for _ in 0..a1::MAX_NODES {
            if parent == 0 {
                break;
            }
            let ancestor = self.candidate.nodes().iter().find(|n| n.local == parent)?;
            if ancestor.flags != 0 {
                return None;
            }
            parent = ancestor.parent;
        }
        if parent != 0 {
            return None;
        }
        if current.context.reader {
            ((201..=218).contains(&local) && local != 213 || (300..316).contains(&local))
                .then_some(local)
        } else if (16..30).contains(&local) {
            Some(local - 15)
        } else {
            (100..106).contains(&local).then_some(local)
        }
    }
}

#[cfg(test)]
mod tests;
