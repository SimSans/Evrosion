use crate::composition::Preferences;
use crate::protected::{ControlState, TrustedAdapter};
use crate::semantic::{
    Action, ActionDelivery, NodeId, Provider, ProviderLease, ProviderRights, Role, SemanticView,
    Tree,
};
use crate::{Error, Owner, Rect, Surface, WINDOWS, WindowId, next};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowKind {
    Files,
    EditorOne,
    EditorTwo,
    Inspector,
}
impl WindowKind {
    const fn slot(self) -> usize {
        match self {
            Self::Files => 0,
            Self::EditorOne => 1,
            Self::EditorTwo => 2,
            Self::Inspector => 3,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    Simple,
    Advanced,
    AbsoluteAccess,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Modal {
    pub node: u16,
    pub surface: Surface,
    /// Desktop logical coordinates. Parent-window geometry remains authoritative.
    pub bounds: Rect,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    pub id: WindowId,
    pub kind: WindowKind,
    pub owner: Owner,
    pub surface: Surface,
    pub bounds: Rect,
    pub visible: bool,
    pub modal: Option<Modal>,
    pub view_revision: u64,
    pub(crate) tree: Option<Tree>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputTarget {
    pub window: WindowId,
    pub owner: Owner,
    pub surface: Surface,
    pub modal: Option<u16>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct View {
    pub revision: u64,
    pub layer: Layer,
    pub windows: [Option<WindowId>; WINDOWS],
    pub focused: Option<WindowId>,
    pub show_permissions: bool,
    pub show_raw_state: bool,
    /// This describes the UI affordance, never an authorization bit.
    pub show_owner_controls: bool,
    pub trusted_attention: bool,
    pub preferences: Preferences,
}

pub struct Desktop {
    pub(crate) shell: Owner,
    bounds: Rect,
    windows: [Option<Window>; WINDOWS],
    generations: [u64; WINDOWS],
    z: [Option<WindowId>; WINDOWS],
    focused: Option<WindowId>,
    keyboard_node: Option<NodeId>,
    assistive_focus: Option<NodeId>,
    provider: Option<Provider>,
    pub(crate) provider_generation: u64,
    action_serial: u64,
    pub(crate) pending_action: Option<ActionDelivery>,
    revision: u64,
    layer: Layer,
    preferences: Preferences,
    pub(crate) control: ControlState,
}
impl Desktop {
    /// Only the actual controller keeps the returned adapter issuer. Ordinary
    /// Shell/App/provider handlers receive the Desktop message APIs, not this
    /// issuer. Each instance has a distinct non-repeating in-process binding.
    pub fn new(
        shell: Owner,
        trusted_owner: Owner,
        bounds: Rect,
    ) -> Result<(Self, TrustedAdapter), Error> {
        if !shell.valid() || !trusted_owner.valid() || shell == trusted_owner {
            return Err(Error::Identity);
        }
        if !bounds.valid() {
            return Err(Error::Geometry);
        }
        let (control, adapter) = ControlState::bind(trusted_owner)?;
        Ok((
            Self {
                shell,
                bounds,
                windows: [None; WINDOWS],
                generations: [0; WINDOWS],
                z: [None; WINDOWS],
                focused: None,
                keyboard_node: None,
                assistive_focus: None,
                provider: None,
                provider_generation: 0,
                action_serial: 0,
                pending_action: None,
                revision: 1,
                layer: Layer::Simple,
                preferences: Preferences::DEFAULT,
                control,
            },
            adapter,
        ))
    }
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub fn window(&self, id: WindowId) -> Result<&Window, Error> {
        self.windows
            .get(usize::from(id.slot))
            .and_then(Option::as_ref)
            .filter(|window| window.id == id)
            .ok_or(Error::Stale)
    }
    fn index(&self, id: WindowId) -> Result<usize, Error> {
        self.window(id).map(|_| usize::from(id.slot))
    }
    fn sender(&self, sender: Owner, id: WindowId) -> Result<usize, Error> {
        let index = self.index(id)?;
        if self.windows[index].as_ref().unwrap().owner != sender {
            return Err(Error::Owner);
        }
        Ok(index)
    }
    fn shell(&self, sender: Owner) -> Result<(), Error> {
        if sender != self.shell {
            return Err(Error::Owner);
        }
        if self.control.active() {
            return Err(Error::Protected);
        }
        Ok(())
    }
    pub(crate) fn advance(&mut self) -> Result<(), Error> {
        self.revision = next(self.revision)?;
        Ok(())
    }
    pub(crate) fn available_revision(&self) -> Result<(), Error> {
        next(self.revision).map(|_| ())
    }
    pub(crate) fn live_owner(&self, owner: Owner) -> bool {
        owner == self.control.owner()
            || self
                .windows
                .iter()
                .flatten()
                .any(|window| window.owner == owner)
    }

    /// Controller admission after actual owner/surface/mapping validation.
    /// Capacity failure changes no generation, ordering or focus state.
    pub fn install(
        &mut self,
        kind: WindowKind,
        owner: Owner,
        surface: Surface,
        bounds: Rect,
    ) -> Result<WindowId, Error> {
        if !owner.valid()
            || !surface.valid()
            || owner == self.shell
            || owner == self.control.owner()
        {
            return Err(Error::Identity);
        }
        let index = kind.slot();
        if self.windows[index].is_some() {
            return Err(Error::Capacity);
        }
        if self.windows.iter().flatten().any(|w| {
            w.owner == owner
                || w.surface == surface
                || w.modal.is_some_and(|modal| modal.surface == surface)
        }) {
            return Err(Error::Duplicate);
        }
        let bounds = bounds.clamped(self.bounds)?;
        let generation = next(self.generations[index])?;
        self.available_revision()?;
        let id = WindowId {
            slot: index as u8,
            generation,
        };
        self.generations[index] = generation;
        self.windows[index] = Some(Window {
            id,
            kind,
            owner,
            surface,
            bounds,
            visible: true,
            modal: None,
            view_revision: 0,
            tree: None,
        });
        self.raise(id);
        if !self.control.active() {
            self.focused = Some(id);
            self.keyboard_node = None;
        }
        self.advance()?;
        Ok(id)
    }
    fn raise(&mut self, id: WindowId) {
        let mut z = [None; WINDOWS];
        let mut count = 0;
        for old in self.z.into_iter().flatten().filter(|old| *old != id) {
            z[count] = Some(old);
            count += 1;
        }
        z[count] = Some(id);
        self.z = z;
    }
    /// Controller retirement requires the actual stopped/detached owner outside
    /// this model. Full WindowId generation and sender still reject stale use.
    pub fn retire(&mut self, id: WindowId, owner: Owner) -> Result<(), Error> {
        let index = self.sender(owner, id)?;
        self.available_revision()?;
        self.windows[index] = None;
        let mut z = [None; WINDOWS];
        for (at, old) in self
            .z
            .into_iter()
            .flatten()
            .filter(|old| *old != id)
            .enumerate()
        {
            z[at] = Some(old);
        }
        self.z = z;
        if self.focused == Some(id) {
            self.focused = self
                .z
                .iter()
                .rev()
                .flatten()
                .copied()
                .find(|candidate| self.window(*candidate).is_ok_and(|window| window.visible));
            self.keyboard_node = None;
        }
        if self.assistive_focus.is_some_and(|node| node.window == id) {
            self.assistive_focus = None;
        }
        self.control.invalidate();
        self.pending_action = None;
        self.advance()
    }
    pub fn activate(&mut self, shell: Owner, id: WindowId) -> Result<(), Error> {
        self.shell(shell)?;
        if !self.window(id)?.visible {
            return Err(Error::Focus);
        }
        self.available_revision()?;
        self.raise(id);
        self.focused = Some(id);
        self.keyboard_node = None;
        self.advance()
    }
    pub fn switch(&mut self, shell: Owner, reverse: bool) -> Result<Option<WindowId>, Error> {
        self.shell(shell)?;
        let mut visible = [None; WINDOWS];
        let mut count = 0;
        for id in self.z.iter().flatten().copied() {
            if self.window(id)?.visible {
                visible[count] = Some(id);
                count += 1;
            }
        }
        if count == 0 {
            return Ok(None);
        }
        let current = visible
            .iter()
            .position(|id| *id == self.focused)
            .unwrap_or(count - 1);
        let next = if reverse {
            (current + count - 1) % count
        } else {
            (current + 1) % count
        };
        let target = visible[next].ok_or(Error::Focus)?;
        self.available_revision()?;
        // Preserve the switching ring; explicit activation/pointer raises it.
        self.focused = Some(target);
        self.keyboard_node = None;
        self.advance()?;
        Ok(Some(target))
    }
    pub fn geometry(&mut self, shell: Owner, id: WindowId, bounds: Rect) -> Result<Rect, Error> {
        self.shell(shell)?;
        let index = self.index(id)?;
        let clamped = bounds.clamped(self.bounds)?;
        if self.windows[index].unwrap().modal.is_some() {
            return Err(Error::Modal);
        }
        self.available_revision()?;
        let window = self.windows[index].as_mut().unwrap();
        window.bounds = clamped;
        // Old pixel/node bounds cannot be used after resize/move until the
        // actual view is coherently republished at its next revision.
        window.tree = None;
        if self.assistive_focus.is_some_and(|node| node.window == id) {
            self.assistive_focus = None;
        }
        if self.keyboard_node.is_some_and(|node| node.window == id) {
            self.keyboard_node = None;
        }
        if self
            .pending_action
            .is_some_and(|delivery| delivery.target.window == id)
        {
            self.pending_action = None;
        }
        self.advance()?;
        Ok(clamped)
    }
    pub fn set_layer(&mut self, shell: Owner, layer: Layer) -> Result<(), Error> {
        self.shell(shell)?;
        self.available_revision()?;
        self.layer = layer;
        self.advance()
    }
    pub const fn bounds(&self) -> Rect {
        self.bounds
    }
    pub const fn preferences(&self) -> Preferences {
        self.preferences
    }
    pub fn set_preferences(&mut self, shell: Owner, preferences: Preferences) -> Result<(), Error> {
        self.shell(shell)?;
        preferences.valid()?;
        self.available_revision()?;
        self.preferences = preferences;
        self.pending_action = None;
        self.advance()
    }
    pub fn set_visible(&mut self, shell: Owner, id: WindowId, visible: bool) -> Result<(), Error> {
        self.shell(shell)?;
        let index = self.index(id)?;
        self.available_revision()?;
        self.windows[index].as_mut().unwrap().visible = visible;
        if !visible {
            if self.focused == Some(id) {
                self.focused =
                    self.z.iter().rev().flatten().copied().find(|candidate| {
                        self.window(*candidate).is_ok_and(|window| window.visible)
                    });
                self.keyboard_node = None;
            }
            if self.assistive_focus.is_some_and(|node| node.window == id) {
                self.assistive_focus = None;
            }
        }
        self.pending_action = None;
        self.advance()
    }
    pub fn view(&self) -> View {
        View {
            revision: self.revision,
            layer: self.layer,
            windows: self.z,
            focused: self.focused,
            show_permissions: self.layer != Layer::Simple,
            show_raw_state: self.layer == Layer::AbsoluteAccess,
            show_owner_controls: self.layer == Layer::AbsoluteAccess,
            trusted_attention: self.control.active(),
            preferences: self.preferences,
        }
    }
    pub fn replace_shell(&mut self, old: Owner, replacement: Owner) -> Result<(), Error> {
        if self.shell != old
            || !replacement.valid()
            || replacement == old
            || replacement == self.control.owner()
            || self
                .windows
                .iter()
                .flatten()
                .any(|window| window.owner == replacement)
            || (replacement.process == old.process && replacement.incarnation <= old.incarnation)
        {
            return Err(Error::Owner);
        }
        self.available_revision()?;
        self.shell = replacement;
        self.control.invalidate();
        self.pending_action = None;
        self.advance()
    }
    fn target(&self, id: WindowId) -> Result<InputTarget, Error> {
        let window = self.window(id)?;
        if !window.visible {
            return Err(Error::Focus);
        }
        Ok(InputTarget {
            window: id,
            owner: window.owner,
            surface: window.modal.map_or(window.surface, |modal| modal.surface),
            modal: window.modal.map(|modal| modal.node),
        })
    }
    pub fn keyboard_target(&self, shell: Owner) -> Result<Option<InputTarget>, Error> {
        self.shell(shell)?;
        self.focused.map(|id| self.target(id)).transpose()
    }
    /// Revalidate a queued target immediately before actual protected delivery.
    /// A routing decision made before focus/owner/modal replacement is stale.
    pub fn validate_delivery(&self, target: InputTarget) -> Result<(), Error> {
        if self.control.active() {
            return Err(Error::Protected);
        }
        if self.focused != Some(target.window) || self.target(target.window)? != target {
            return Err(Error::Stale);
        }
        Ok(())
    }
    pub fn pointer_target(
        &mut self,
        shell: Owner,
        x: i32,
        y: i32,
    ) -> Result<Option<InputTarget>, Error> {
        self.shell(shell)?;
        let id = self.z.iter().rev().flatten().copied().find(|id| {
            self.window(*id)
                .is_ok_and(|window| window.visible && window.bounds.contains(x, y))
        });
        let Some(id) = id else {
            return Ok(None);
        };
        let window = self.window(id)?;
        if window
            .modal
            .is_some_and(|modal| !modal.bounds.contains(x, y))
        {
            return Err(Error::Modal);
        }
        self.activate(shell, id)?;
        self.target(id).map(Some)
    }
    pub fn publish_view(
        &mut self,
        sender: Owner,
        id: WindowId,
        displayed_revision: u64,
        tree: Tree,
    ) -> Result<(), Error> {
        let index = self.sender(sender, id)?;
        let window = self.windows[index].as_ref().unwrap();
        if displayed_revision != tree.revision()
            || displayed_revision != next(window.view_revision)?
        {
            return Err(Error::Revision);
        }
        if tree
            .nodes()
            .next()
            .is_none_or(|node| node.bounds != window.bounds)
            || tree
                .nodes()
                .any(|node| !window.bounds.encloses(node.bounds))
        {
            return Err(Error::Geometry);
        }
        if let Some(modal) = window.modal
            && !tree
                .node(modal.node)
                .is_some_and(|node| node.role == Role::Dialog && node.bounds == modal.bounds)
        {
            return Err(Error::Modal);
        }
        self.available_revision()?;
        let window = self.windows[index].as_mut().unwrap();
        window.view_revision = displayed_revision;
        window.tree = Some(tree);
        if self
            .assistive_focus
            .is_some_and(|id| id.window == window.id && tree.node(id.local).is_none())
        {
            self.assistive_focus = None;
        }
        if self
            .keyboard_node
            .is_some_and(|id| id.window == window.id && tree.node(id.local).is_none())
        {
            self.keyboard_node = None;
        }
        if self
            .pending_action
            .is_some_and(|delivery| delivery.target.window == id)
        {
            self.pending_action = None;
        }
        self.advance()
    }
    /// Native adapters may publish the subcontrol keyboard focus only within
    /// the window already selected by Root. Tree and focus become visible at
    /// the same publication revision; an app cannot choose another window.
    pub fn publish_presented_view(
        &mut self,
        sender: Owner,
        id: WindowId,
        displayed_revision: u64,
        tree: Tree,
        keyboard: Option<u16>,
    ) -> Result<(), Error> {
        self.sender(sender, id)?;
        if let Some(local) = keyboard
            && (self.focused != Some(id) || tree.node(local).is_none())
        {
            return Err(Error::Focus);
        }
        self.publish_view(sender, id, displayed_revision, tree)?;
        if self.focused == Some(id) {
            self.keyboard_node = keyboard.map(|local| NodeId { window: id, local });
        }
        Ok(())
    }
    pub fn modal(
        &mut self,
        sender: Owner,
        id: WindowId,
        modal: Option<Modal>,
    ) -> Result<(), Error> {
        let index = self.sender(sender, id)?;
        if let Some(modal) = modal {
            let window = self.windows[index].as_ref().unwrap();
            if !modal.surface.valid()
                || !window.bounds.encloses(modal.bounds)
                || !window
                    .tree
                    .as_ref()
                    .and_then(|tree| tree.node(modal.node))
                    .is_some_and(|node| node.role == Role::Dialog && node.bounds == modal.bounds)
            {
                return Err(Error::Modal);
            }
            if self.windows.iter().flatten().any(|window| {
                window.surface == modal.surface
                    || window.modal.is_some_and(|old| old.surface == modal.surface)
            }) {
                return Err(Error::Duplicate);
            }
        }
        self.available_revision()?;
        self.windows[index].as_mut().unwrap().modal = modal;
        self.keyboard_node = None;
        self.assistive_focus = None;
        if self
            .pending_action
            .is_some_and(|delivery| delivery.target.window == id)
        {
            self.pending_action = None;
        }
        self.advance()
    }
    /// Controller supplies a grant already delivered to this actual provider
    /// incarnation. Replacing/revoking it invalidates every old lease/action.
    pub fn provider(
        &mut self,
        owner: Owner,
        rights: ProviderRights,
    ) -> Result<ProviderLease, Error> {
        if !owner.valid() || !rights.permits(ProviderRights::READ) {
            return Err(Error::Identity);
        }
        let generation = next(self.provider_generation)?;
        self.available_revision()?;
        let lease = ProviderLease { owner, generation };
        self.provider_generation = generation;
        self.provider = Some(Provider { lease, rights });
        self.assistive_focus = None;
        self.control.invalidate();
        self.pending_action = None;
        self.advance()?;
        Ok(lease)
    }
    pub fn revoke_provider(&mut self, lease: ProviderLease) -> Result<(), Error> {
        self.check_provider(lease.owner(), lease, ProviderRights::READ)?;
        self.available_revision()?;
        self.provider = None;
        self.assistive_focus = None;
        self.control.invalidate();
        self.pending_action = None;
        self.advance()
    }
    pub(crate) fn check_provider(
        &self,
        sender: Owner,
        lease: ProviderLease,
        rights: ProviderRights,
    ) -> Result<(), Error> {
        let provider = self.provider.ok_or(Error::Denied)?;
        if sender != lease.owner || provider.lease != lease || !provider.rights.permits(rights) {
            return Err(Error::Denied);
        }
        Ok(())
    }
    pub fn semantic(
        &self,
        sender: Owner,
        lease: ProviderLease,
        id: WindowId,
    ) -> Result<SemanticView<'_>, Error> {
        self.check_provider(sender, lease, ProviderRights::READ)?;
        let window = self.window(id)?;
        let tree = window.tree.as_ref().ok_or(Error::Unsettled)?;
        Ok(SemanticView {
            desktop_revision: self.revision,
            window: id,
            owner: window.owner,
            displayed_revision: window.view_revision,
            tree,
            assistive_focus: self.assistive_focus,
            keyboard_focus: self.keyboard_node,
            modal: window.modal.map(|modal| NodeId {
                window: id,
                local: modal.node,
            }),
            visible: window.visible,
        })
    }
    fn semantic_node(&self, id: NodeId, revision: u64) -> Result<&crate::Node, Error> {
        let window = self.window(id.window)?;
        if !window.visible {
            return Err(Error::Focus);
        }
        let tree = window.tree.as_ref().ok_or(Error::Unsettled)?;
        if window.view_revision != revision {
            return Err(Error::Revision);
        }
        if window
            .modal
            .is_some_and(|modal| !tree.descendant(id.local, modal.node))
        {
            return Err(Error::Modal);
        }
        tree.node(id.local).ok_or(Error::Missing)
    }
    pub fn assistive_focus(
        &mut self,
        sender: Owner,
        lease: ProviderLease,
        id: NodeId,
        revision: u64,
    ) -> Result<(), Error> {
        self.check_provider(sender, lease, ProviderRights::READ)?;
        if self.control.active() {
            return Err(Error::Protected);
        }
        self.semantic_node(id, revision)?;
        self.available_revision()?;
        self.assistive_focus = Some(id);
        self.advance()
    }
    pub fn semantic_action(
        &mut self,
        sender: Owner,
        lease: ProviderLease,
        id: NodeId,
        revision: u64,
        action: Action,
    ) -> Result<ActionDelivery, Error> {
        self.check_provider(
            sender,
            lease,
            ProviderRights::READ.union(ProviderRights::ACTION),
        )?;
        if self.control.active() {
            return Err(Error::Protected);
        }
        self.semantic_node(id, revision)?;
        self.window(id.window)?
            .tree
            .as_ref()
            .unwrap()
            .action(id.local, action)?;
        let owner = self.window(id.window)?.owner;
        if self.pending_action.is_some() {
            return Err(Error::Unsettled);
        }
        let serial = next(self.action_serial)?;
        self.available_revision()?;
        let delivery = ActionDelivery {
            owner,
            target: id,
            view_revision: revision,
            action,
            provider: lease,
            serial,
        };
        self.action_serial = serial;
        self.pending_action = Some(delivery);
        self.advance()?;
        Ok(delivery)
    }
    /// Consume the one pending delivery after rechecking actual current sender,
    /// provider, view, modal and window owner. The ticket cannot be replayed or
    /// carried across provider replacement/focus-control recovery.
    pub fn dispatch_semantic(
        &mut self,
        sender: Owner,
        delivery: ActionDelivery,
    ) -> Result<(), Error> {
        self.check_provider(
            sender,
            delivery.provider,
            ProviderRights::READ.union(ProviderRights::ACTION),
        )?;
        if self.control.active() {
            return Err(Error::Protected);
        }
        if self.pending_action != Some(delivery) {
            return Err(Error::Stale);
        }
        self.semantic_node(delivery.target, delivery.view_revision)?;
        self.window(delivery.target.window)?
            .tree
            .as_ref()
            .unwrap()
            .action(delivery.target.local, delivery.action)?;
        if self.window(delivery.target.window)?.owner != delivery.owner {
            return Err(Error::Owner);
        }
        self.available_revision()?;
        self.pending_action = None;
        if delivery.action == Action::Focus {
            self.raise(delivery.target.window);
            self.focused = Some(delivery.target.window);
            self.keyboard_node = Some(delivery.target);
        }
        self.advance()
    }
    pub const fn keyboard_focus(&self) -> Option<NodeId> {
        self.keyboard_node
    }
    pub const fn assistive_focus_node(&self) -> Option<NodeId> {
        self.assistive_focus
    }
}
