//! Internal bounded workspace interaction model. No renderer, syscalls, grants,
//! storage or hardware attestations live here. Actual adapters authenticate the
//! sender and retain mapping/device owners before calling controller methods.
#![no_std]
#![forbid(unsafe_code)]

pub mod composition;
pub mod cursor;
pub mod desktop;
pub mod protected;
pub mod semantic;

pub use desktop::{Desktop, InputTarget, Layer, Modal, View, Window, WindowKind};
pub use protected::{
    ActionScope, ActionTarget, AttentionWitness, Challenge, ConfirmationSource, Effect,
    PresentedWitness, ProtectedKind, Rights, TrustedAdapter,
};
pub use semantic::{
    Action, Actions, Label, Node, NodeId, ProviderLease, ProviderRights, Role, SemanticView, Tree,
    Value,
};

pub const WINDOWS: usize = 4;
pub const NODES: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Identity,
    Stale,
    Exhausted,
    Capacity,
    Geometry,
    Duplicate,
    Missing,
    Owner,
    Modal,
    Focus,
    Revision,
    Tree,
    Text,
    Denied,
    Protected,
    Unsettled,
}

pub(crate) fn next(value: u64) -> Result<u64, Error> {
    value
        .checked_add(1)
        .filter(|v| *v != u64::MAX)
        .ok_or(Error::Exhausted)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owner {
    pub process: u64,
    pub incarnation: u64,
}
impl Owner {
    pub fn valid(self) -> bool {
        self.process != 0
            && self.process != u64::MAX
            && self.incarnation != 0
            && self.incarnation != u64::MAX
    }
}

/// Full actual surface identity, resolved by the adapter, never by app text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Surface {
    pub object: u64,
    pub generation: u64,
}
impl Surface {
    pub fn valid(self) -> bool {
        self.object != 0
            && self.object != u64::MAX
            && self.generation != 0
            && self.generation != u64::MAX
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowId {
    pub slot: u8,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}
impl Rect {
    pub fn valid(self) -> bool {
        self.width != 0
            && self.height != 0
            && self.width <= i32::MAX as u32
            && self.height <= i32::MAX as u32
            && self.x.checked_add(self.width as i32).is_some()
            && self.y.checked_add(self.height as i32).is_some()
    }
    pub fn contains(self, x: i32, y: i32) -> bool {
        self.valid()
            && x >= self.x
            && y >= self.y
            && x < self.x + self.width as i32
            && y < self.y + self.height as i32
    }
    pub fn encloses(self, other: Self) -> bool {
        self.valid()
            && other.valid()
            && other.x >= self.x
            && other.y >= self.y
            && other.x + other.width as i32 <= self.x + self.width as i32
            && other.y + other.height as i32 <= self.y + self.height as i32
    }
    pub fn clamped(self, bounds: Self) -> Result<Self, Error> {
        if !self.valid() || !bounds.valid() {
            return Err(Error::Geometry);
        }
        let width = self.width.min(bounds.width);
        let height = self.height.min(bounds.height);
        Ok(Self {
            x: self
                .x
                .clamp(bounds.x, bounds.x + (bounds.width - width) as i32),
            y: self
                .y
                .clamp(bounds.y, bounds.y + (bounds.height - height) as i32),
            width,
            height,
        })
    }
}

#[cfg(test)]
mod tests;
