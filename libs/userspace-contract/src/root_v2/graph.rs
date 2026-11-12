//! One closed reference desktop graph. Names and wiring are metadata; actual
//! source handles, backing, process ownership and admission remain mandatory.
#![forbid(unsafe_code)]
use super::Role;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Child {
    Shell,
    Input,
    File,
    Block,
    App,
    Display,
}
pub const CHILDREN: [Child; 6] = [
    Child::Shell,
    Child::Input,
    Child::File,
    Child::Block,
    Child::App,
    Child::Display,
];
impl Child {
    pub const fn index(self) -> usize {
        self as usize
    }
    pub const fn image(self) -> Role {
        [
            Role::ShellImage,
            Role::InputImage,
            Role::FileImage,
            Role::BlockImage,
            Role::AppImage,
            Role::DisplayImage,
        ][self.index()]
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Channel {
    AppPresent,
    ShellPresent,
    ShellWindow,
    RootSession,
    InputKeys,
    InputBarrier,
    ShellControl,
    AppControl,
    GrantInbox,
    SystemBlock,
    UserBlock,
    NotesRead,
    NotesWrite,
    PrivateRead,
    PrivateWrite,
}
pub const CHANNELS: [Channel; 15] = [
    Channel::AppPresent,
    Channel::ShellPresent,
    Channel::ShellWindow,
    Channel::RootSession,
    Channel::InputKeys,
    Channel::InputBarrier,
    Channel::ShellControl,
    Channel::AppControl,
    Channel::GrantInbox,
    Channel::SystemBlock,
    Channel::UserBlock,
    Channel::NotesRead,
    Channel::NotesWrite,
    Channel::PrivateRead,
    Channel::PrivateWrite,
];
impl Channel {
    pub const fn index(self) -> usize {
        self as usize
    }
    pub const fn receiver(self) -> Child {
        match self {
            Self::AppPresent | Self::ShellPresent | Self::ShellWindow | Self::RootSession => {
                Child::Display
            }
            Self::InputKeys | Self::ShellControl => Child::Shell,
            Self::InputBarrier => Child::Input,
            Self::AppControl | Self::GrantInbox => Child::App,
            Self::SystemBlock | Self::UserBlock => Child::Block,
            Self::NotesRead | Self::NotesWrite | Self::PrivateRead | Self::PrivateWrite => {
                Child::File
            }
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Root(Role),
    Endpoint(Channel),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    pub kind: u8,
    pub rights: u16,
    pub source: Source,
}
const fn r(role: Role, kind: u8, rights: u16) -> Grant {
    Grant {
        kind,
        rights,
        source: Source::Root(role),
    }
}
const fn e(channel: Channel, rights: u16) -> Grant {
    Grant {
        kind: 2,
        rights,
        source: Source::Endpoint(channel),
    }
}
const SHELL: [Grant; 8] = [
    r(Role::ShellSurface, 1, 7),
    e(Channel::ShellPresent, 8),
    e(Channel::InputKeys, 272),
    e(Channel::ShellControl, 272),
    r(Role::Events, 2, 8),
    e(Channel::InputBarrier, 8),
    e(Channel::ShellWindow, 8),
    r(Role::Events, 2, 8),
];
const INPUT: [Grant; 4] = [
    r(Role::InputPorts, 7, 3),
    e(Channel::InputKeys, 8),
    r(Role::Events, 2, 8),
    e(Channel::InputBarrier, 272),
];
const FILE: [Grant; 8] = [
    r(Role::FileIo, 1, 7),
    e(Channel::UserBlock, 8),
    r(Role::AppFile, 1, 7),
    e(Channel::NotesRead, 272),
    e(Channel::NotesWrite, 272),
    e(Channel::PrivateRead, 272),
    e(Channel::PrivateWrite, 272),
    r(Role::Events, 2, 8),
];
const BLOCK: [Grant; 6] = [
    r(Role::AtaPorts, 7, 3),
    r(Role::SystemIo, 1, 7),
    e(Channel::SystemBlock, 272),
    r(Role::FileIo, 1, 7),
    e(Channel::UserBlock, 272),
    r(Role::Events, 2, 8),
];
const APP: [Grant; 6] = [
    r(Role::Surface, 1, 7),
    e(Channel::AppPresent, 8),
    r(Role::Events, 2, 8),
    e(Channel::AppControl, 272),
    r(Role::AppFile, 1, 7),
    e(Channel::GrantInbox, 272),
];
const DISPLAY: [Grant; 8] = [
    r(Role::Surface, 1, 5),
    e(Channel::AppPresent, 272),
    r(Role::ShellSurface, 1, 5),
    e(Channel::ShellPresent, 272),
    e(Channel::ShellWindow, 272),
    e(Channel::RootSession, 272),
    r(Role::Display, 8, 7),
    r(Role::Events, 2, 8),
];
pub fn grants(child: Child) -> &'static [Grant] {
    match child {
        Child::Shell => &SHELL,
        Child::Input => &INPUT,
        Child::File => &FILE,
        Child::Block => &BLOCK,
        Child::App => &APP,
        Child::Display => &DISPLAY,
    }
}

/// Canonical wiring/layout/range input to the full-graph measurement. No physical
/// address or capability handle is serialized. The record is fixed and zero-tail.
pub const DESCRIPTION_BYTES: usize = 1536;
pub fn description() -> [u8; DESCRIPTION_BYTES] {
    let mut b = [0; DESCRIPTION_BYTES];
    b[..8].copy_from_slice(b"EVWIRE01");
    let mut offset = 8;
    for child in CHILDREN {
        for (i, g) in grants(child).iter().enumerate() {
            let slot = &mut b[offset..offset + 16];
            slot[0] = child.index() as u8;
            slot[1] = i as u8 + 1;
            slot[2] = g.kind;
            slot[4..6].copy_from_slice(&g.rights.to_le_bytes());
            match g.source {
                Source::Root(role) => {
                    slot[6] = 1;
                    slot[8..16].copy_from_slice(&role.selector().to_le_bytes());
                }
                Source::Endpoint(channel) => {
                    slot[6] = 2;
                    slot[8..16].copy_from_slice(&(channel.index() as u64 + 1).to_le_bytes());
                }
            }
            offset += 16;
        }
    }
    // Actual fixed virtual pages: primary/auxiliary surfaces, guards, IO and
    // catalogue, readonly bootstrap, measured16KiB stack, device aperture+tables.
    for n in [
        384u64,
        63,
        383,
        447,
        304,
        63,
        303,
        367,
        507,
        508,
        509,
        256,
        4,
        255,
        260,
        4 * 1024 * 1024,
        4 * 1024 * 1024,
        2,
        16,
        14,
        32,
        14,
        48,
        14,
    ] {
        b[offset..offset + 8].copy_from_slice(&n.to_le_bytes());
        offset += 8;
    }
    b
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_graph_has_no_ambient_app_sources_and_fits_eight_roles() {
        for child in CHILDREN {
            assert!(grants(child).len() <= 8);
        }
        let app = grants(Child::App);
        assert_eq!(app.len(), 6);
        assert!(app.iter().all(|g| !matches!(
            g.source,
            Source::Root(Role::AtaPorts | Role::InputPorts | Role::OwnerUart | Role::Display)
        )));
        assert_eq!(
            CHANNELS
                .iter()
                .filter(|&&c| c.receiver() == Child::Display)
                .count(),
            4
        );
        assert_ne!(description(), [0; DESCRIPTION_BYTES]);
    }
}
