//! Additive typed graph; first six children and fifteen wire IDs stay fixed.
//! Only actual Kernel endpoint ownership and admission make these routes live.
use super::Role;
use crate::root_v2::graph as old;
pub use old::DeliveryMode;
pub const ROOT_EVENTS_WIRE: usize = 15;
pub const WIRE_SLOTS: usize = 18;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Child {
    Shell = 0,
    Input = 1,
    File = 2,
    Block = 3,
    App = 4,
    Display = 5,
    NetDriver = 6,
    NetService = 7,
}
pub const CHILDREN: [Child; 8] = [
    Child::Shell,
    Child::Input,
    Child::File,
    Child::Block,
    Child::App,
    Child::Display,
    Child::NetDriver,
    Child::NetService,
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
            Role::NetDriverImage,
            Role::NetServiceImage,
        ][self.index()]
    }
    pub const fn frame_limit(self) -> u64 {
        self.limits()[1]
    }
    /// Index into the trusted Registry's measured finite template table.
    /// The userspace caller never supplies the template's resource limits.
    pub const fn job_template(self) -> u64 {
        match self {
            Self::NetService => 1,
            _ => 0,
        }
    }
    pub const fn limits(self) -> [u64; 4] {
        super::JOB_TEMPLATE_LIMITS[self.job_template() as usize]
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Channel {
    AppPresent = 0,
    ShellPresent = 1,
    ShellWindow = 2,
    RootSession = 3,
    InputKeys = 4,
    InputBarrier = 5,
    ShellControl = 6,
    AppControl = 7,
    GrantInbox = 8,
    SystemBlock = 9,
    UserBlock = 10,
    NotesRead = 11,
    NotesWrite = 12,
    PrivateRead = 13,
    PrivateWrite = 14,
    NetDriverRpc = 16,
    NetClientRpc = 17,
}
pub const CHANNELS: [Channel; 17] = [
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
    Channel::NetDriverRpc,
    Channel::NetClientRpc,
];
impl Channel {
    pub const fn from_wire_index(index: usize) -> Option<Self> {
        match index {
            0..=14 => Some(CHANNELS[index]),
            16 => Some(Self::NetDriverRpc),
            17 => Some(Self::NetClientRpc),
            _ => None,
        }
    }
    /// Aggregate File transaction routes remain finite. Every actual child
    /// Block request keeps a separately captured cut of at most1024 ticks.
    pub const fn session_rpc_ticks(self) -> u64 {
        match self {
            Self::NotesRead | Self::NotesWrite | Self::PrivateRead | Self::PrivateWrite => {
                super::FILE_TRANSACTION_MAX_TICKS
            }
            _ => super::RPC_MAX_TICKS,
        }
    }
    /// Actual wire index, deliberately not a dense index into CHANNELS.
    pub const fn wire_index(self) -> usize {
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
            Self::NetDriverRpc => Child::NetDriver,
            Self::NetClientRpc => Child::NetService,
        }
    }
    pub const fn delivery(self) -> DeliveryMode {
        match self {
            Self::InputKeys | Self::ShellControl | Self::AppControl => DeliveryMode::Async,
            Self::GrantInbox => DeliveryMode::Selected,
            _ => DeliveryMode::Rpc,
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
const DRIVER: [Grant; 4] = [
    Grant {
        kind: 7,
        rights: 3,
        source: Source::Root(Role::NicPorts),
    },
    Grant {
        kind: 1,
        rights: 7,
        source: Source::Root(Role::NicWindow),
    },
    Grant {
        kind: 2,
        rights: 272,
        source: Source::Endpoint(Channel::NetDriverRpc),
    },
    Grant {
        kind: 2,
        rights: 8,
        source: Source::Root(Role::Events),
    },
];
const NETWORK: [Grant; 5] = [
    Grant {
        kind: 1,
        rights: 7,
        source: Source::Root(Role::NicWindow),
    },
    Grant {
        kind: 2,
        rights: 8,
        source: Source::Endpoint(Channel::NetDriverRpc),
    },
    Grant {
        kind: 1,
        rights: 7,
        source: Source::Root(Role::NetClientWindow),
    },
    Grant {
        kind: 2,
        rights: 272,
        source: Source::Endpoint(Channel::NetClientRpc),
    },
    Grant {
        kind: 2,
        rights: 8,
        source: Source::Root(Role::Events),
    },
];
pub const GRANT_COUNTS: [usize; 8] = [8, 4, 8, 6, 7, 8, 4, 5];
pub struct Grants {
    child: Child,
    index: usize,
}
pub fn grants(child: Child) -> Grants {
    Grants { child, index: 0 }
}
impl Iterator for Grants {
    type Item = Grant;
    fn next(&mut self) -> Option<Grant> {
        if self.index >= GRANT_COUNTS[self.child.index()] {
            return None;
        }
        let index = self.index;
        self.index += 1;
        if self.child == Child::NetDriver {
            return Some(DRIVER[index]);
        }
        if self.child == Child::NetService {
            return Some(NETWORK[index]);
        }
        if self.child == Child::App && index == 6 {
            return Some(Grant {
                kind: 1,
                rights: 7,
                source: Source::Root(Role::NoteWindow),
            });
        }
        let original = old::grants(old::CHILDREN[self.child.index()])[index];
        Some(Grant {
            kind: original.kind,
            rights: original.rights,
            source: match original.source {
                old::Source::Root(role) => {
                    Source::Root(Role::from_selector(role.selector()).unwrap())
                }
                old::Source::Endpoint(channel) => Source::Endpoint(CHANNELS[channel.index()]),
            },
        })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = GRANT_COUNTS[self.child.index()] - self.index;
        (n, Some(n))
    }
}
impl ExactSizeIterator for Grants {}
pub const DESCRIPTION_BYTES: usize = 1536;
pub fn description() -> [u8; DESCRIPTION_BYTES] {
    let mut b = [0; DESCRIPTION_BYTES];
    b[..8].copy_from_slice(b"EVWIRE04");
    b[8] = 8;
    b[9] = 17;
    b[10] = WIRE_SLOTS as u8;
    b[11] = ROOT_EVENTS_WIRE as u8;
    b[12] = CHILDREN.len() as u8;
    b[13] = super::JOB_TEMPLATE_LIMITS.len() as u8;
    let mut at = 32;
    for child in CHILDREN {
        for (i, g) in grants(child).enumerate() {
            let slot = &mut b[at..at + 16];
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
                    slot[8..16].copy_from_slice(&(channel.wire_index() as u64 + 1).to_le_bytes());
                }
            }
            at += 16;
        }
    }
    for channel in CHANNELS {
        let slot = &mut b[at..at + 8];
        slot[0] = channel.wire_index() as u8;
        slot[1] = channel.receiver().index() as u8;
        slot[2] = match channel.delivery() {
            DeliveryMode::Async => 1,
            DeliveryMode::Rpc => 2,
            DeliveryMode::Selected => 3,
        };
        slot[4..8].copy_from_slice(&(channel.session_rpc_ticks() as u32).to_le_bytes());
        at += 8;
    }
    for child in CHILDREN {
        for value in [child.index() as u64, child.job_template()]
            .into_iter()
            .chain(child.limits())
        {
            b[at..at + 8].copy_from_slice(&value.to_le_bytes());
            at += 8;
        }
    }
    b
}
