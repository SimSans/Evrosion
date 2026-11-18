//! Transactional semantic data, with fixed-size labels and range metadata.
//! A Tree/NodeId/ProviderLease alone is descriptive, never kernel authority.
use crate::{Error, NODES, Owner, Rect, WindowId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Label {
    bytes: [u8; 64],
    len: u8,
}
impl Label {
    pub fn new(text: &str) -> Result<Self, Error> {
        if text.len() > 64 || text.chars().any(char::is_control) {
            return Err(Error::Text);
        }
        let mut label = Self {
            bytes: [0; 64],
            len: text.len() as u8,
        };
        label.bytes[..text.len()].copy_from_slice(text.as_bytes());
        Ok(label)
    }
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..usize::from(self.len)]).expect("validated label")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeId {
    pub window: WindowId,
    pub local: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Window,
    Dialog,
    Button,
    TextBox,
    Label,
    List,
    ListItem,
    Document,
    Menu,
    Slider,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Action {
    Activate = 0,
    Focus = 1,
    Select = 2,
    Scroll = 3,
    Expand = 4,
    SetValue = 5,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Actions(u8);
impl Actions {
    pub const NONE: Self = Self(0);
    pub const fn one(action: Action) -> Self {
        Self(1 << action as u8)
    }
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
    pub const fn permits(self, action: Action) -> bool {
        self.0 & (1 << action as u8) != 0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    None,
    Number(i64),
    /// UTF-8 byte range at a specific application document revision. Fetching
    /// bytes requires a separately authorized route; no document is copied here.
    TextRange {
        revision: u64,
        offset: u64,
        length: u32,
        total: u64,
    },
}
impl Value {
    fn valid(self) -> bool {
        match self {
            Self::TextRange {
                revision,
                offset,
                length,
                total,
            } => {
                revision != u64::MAX
                    && offset
                        .checked_add(u64::from(length))
                        .is_some_and(|end| end <= total)
            }
            _ => true,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Node {
    pub local: u16,
    pub parent: Option<u16>,
    pub role: Role,
    pub label: Label,
    pub bounds: Rect,
    pub value: Value,
    pub actions: Actions,
    pub disabled: bool,
    /// Picker/Absolute Access confirmation may be described but cannot be
    /// activated through the ordinary semantic-action route.
    pub protected: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tree {
    revision: u64,
    nodes: [Option<Node>; NODES],
    len: u8,
}
impl Tree {
    pub fn new(revision: u64, nodes: &[Node]) -> Result<Self, Error> {
        if revision == 0 || revision == u64::MAX {
            return Err(Error::Revision);
        }
        if nodes.is_empty() || nodes.len() > NODES {
            return Err(Error::Capacity);
        }
        let mut tree = Self {
            revision,
            nodes: [None; NODES],
            len: nodes.len() as u8,
        };
        for (at, node) in nodes.iter().copied().enumerate() {
            if node.local == 0
                || !node.bounds.valid()
                || !node.value.valid()
                || nodes[..at].iter().any(|old| old.local == node.local)
                || (at == 0 && (node.parent.is_some() || node.role != Role::Window))
                || (at > 0
                    && !nodes[..at].iter().any(|old| {
                        Some(old.local) == node.parent && old.bounds.encloses(node.bounds)
                    }))
            {
                return Err(Error::Tree);
            }
            tree.nodes[at] = Some(node);
        }
        Ok(tree)
    }
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub fn nodes(&self) -> impl Iterator<Item = &Node> {
        self.nodes[..usize::from(self.len)].iter().flatten()
    }
    pub fn node(&self, local: u16) -> Option<&Node> {
        self.nodes().find(|node| node.local == local)
    }
    pub fn descendant(&self, local: u16, ancestor: u16) -> bool {
        let mut current = Some(local);
        for _ in 0..NODES {
            let Some(node) = current.and_then(|id| self.node(id)) else {
                return false;
            };
            if node.local == ancestor {
                return true;
            }
            current = node.parent;
        }
        false
    }
    /// Disabled/protected ancestors cannot be bypassed by activating a child.
    pub(crate) fn action(&self, local: u16, action: Action) -> Result<(), Error> {
        let target = self.node(local).ok_or(Error::Missing)?;
        let mut current = Some(local);
        for _ in 0..NODES {
            let Some(node) = current.and_then(|id| self.node(id)) else {
                break;
            };
            if node.protected {
                return Err(Error::Protected);
            }
            if node.disabled {
                return Err(Error::Denied);
            }
            current = node.parent;
        }
        if !target.actions.permits(action) {
            return Err(Error::Denied);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderRights(u8);
impl ProviderRights {
    pub const READ: Self = Self(1);
    pub const ACTION: Self = Self(2);
    /// Explicit protected-confirmation opt-in. Ordinary semantic actions never
    /// acquire this right, even when ACTION is present.
    pub const CONFIRM: Self = Self(4);
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
    pub(crate) const fn permits(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderLease {
    pub(crate) owner: Owner,
    pub(crate) generation: u64,
}
impl ProviderLease {
    pub const fn owner(self) -> Owner {
        self.owner
    }
    pub const fn generation(self) -> u64 {
        self.generation
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Provider {
    pub lease: ProviderLease,
    pub rights: ProviderRights,
}

#[derive(Debug)]
pub struct SemanticView<'a> {
    pub desktop_revision: u64,
    pub window: WindowId,
    pub owner: Owner,
    pub displayed_revision: u64,
    pub tree: &'a Tree,
    pub assistive_focus: Option<NodeId>,
    pub keyboard_focus: Option<NodeId>,
    pub modal: Option<NodeId>,
    pub visible: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActionDelivery {
    pub owner: Owner,
    pub target: NodeId,
    pub view_revision: u64,
    pub action: Action,
    pub(crate) provider: ProviderLease,
    pub(crate) serial: u64,
}
