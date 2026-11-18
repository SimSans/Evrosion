//! Selected V5 Root policy. Actual Kernel calls and protected input/presentation
//! adapters live in the separate executable; packet fields never mint authority.
#![no_std]
#![forbid(unsafe_code)]
pub mod app_data;
pub mod development;
pub mod inspector_self;
pub mod install_plan;
pub mod legacy_selection;
pub mod outbox;
pub mod picker;
pub mod policy;
pub mod render;
pub mod requirements;
pub mod retirement;
pub mod semantic;
pub mod shutdown;
use ev_userspace_contract::root_v5::{
    display_control::Slot,
    graph::{Channel, Child},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub process: u64,
    pub thread: u64,
    pub registered: u64,
}
impl Identity {
    pub fn valid(self) -> bool {
        ![self.process, self.thread]
            .into_iter()
            .any(|v| matches!(v, 0 | u64::MAX))
            && self.registered != u64::MAX
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Actor {
    pub control: u64,
    pub identity: Identity,
    pub ready: bool,
    pub mapping_epoch: u32,
    pub failed: bool,
}
pub const fn app_child(index: usize) -> Option<Child> {
    match index {
        0 => Some(Child::Files),
        1 => Some(Child::EditorOne),
        2 => Some(Child::EditorTwo),
        3 => Some(Child::Inspector),
        _ => None,
    }
}
pub const fn child_slot(child: Child) -> Option<Slot> {
    match child {
        Child::Files => Some(Slot::Files),
        Child::EditorOne => Some(Slot::EditorOne),
        Child::EditorTwo => Some(Slot::EditorTwo),
        Child::Inspector => Some(Slot::Inspector),
        Child::Shell => Some(Slot::Shell),
        _ => None,
    }
}
pub const fn control_channel(child: Child) -> Option<Channel> {
    match child {
        Child::Files => Some(Channel::FilesControl),
        Child::EditorOne => Some(Channel::EditorOneControl),
        Child::EditorTwo => Some(Channel::EditorTwoControl),
        Child::Inspector => Some(Channel::InspectorControl),
        Child::Shell => Some(Channel::ShellControl),
        _ => None,
    }
}
pub const fn lease_channel(index: usize) -> Option<Channel> {
    match index {
        0 => Some(Channel::FilesFileLease),
        1 => Some(Channel::EditorOneFileLease),
        2 => Some(Channel::EditorTwoFileLease),
        3 => Some(Channel::InspectorFileLease),
        _ => None,
    }
}
pub const fn inbox_channel(index: usize) -> Option<Channel> {
    match index {
        0 => Some(Channel::FilesGrantInbox),
        1 => Some(Channel::EditorOneGrantInbox),
        2 => Some(Channel::EditorTwoGrantInbox),
        3 => Some(Channel::InspectorGrantInbox),
        _ => None,
    }
}
pub const fn ready_bytes(child: Child) -> Option<[u8; 8]> {
    match child {
        Child::Display => Some(*b"EVDPRDY5"),
        Child::Input => Some(*b"EVINRDY1"),
        Child::Block => Some(*b"EVBLRDY1"),
        Child::Workspace => Some(*b"EVWSRDY1"),
        Child::NetDriver => Some(*b"EVNDRDY1"),
        Child::NetService => Some(*b"EVNSRDY1"),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
