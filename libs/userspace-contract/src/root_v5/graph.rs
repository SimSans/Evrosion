//! Independent closed V5 graph. Sender classes are declared policy, never
//! caller IDs taken from a packet. Kernel/Root must bind actual capabilities.
use super::Role;
use super::resources;
pub const ROOT_EVENTS_WIRE: usize = 23;
pub const WIRE_SLOTS: usize = 24;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Child {
    Shell = 0,
    Input = 1,
    Workspace = 2,
    Block = 3,
    Display = 4,
    NetDriver = 5,
    NetService = 6,
    Files = 7,
    EditorOne = 8,
    EditorTwo = 9,
    Inspector = 10,
}
pub const CHILDREN: [Child; 11] = [
    Child::Shell,
    Child::Input,
    Child::Workspace,
    Child::Block,
    Child::Display,
    Child::NetDriver,
    Child::NetService,
    Child::Files,
    Child::EditorOne,
    Child::EditorTwo,
    Child::Inspector,
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum ImageSlot {
    Shell = 0,
    Input = 1,
    Workspace = 2,
    Block = 3,
    Display = 4,
    NetDriver = 5,
    NetService = 6,
    Files = 7,
    Editor = 8,
    Inspector = 9,
}
pub const IMAGES: [ImageSlot; 10] = [
    ImageSlot::Shell,
    ImageSlot::Input,
    ImageSlot::Workspace,
    ImageSlot::Block,
    ImageSlot::Display,
    ImageSlot::NetDriver,
    ImageSlot::NetService,
    ImageSlot::Files,
    ImageSlot::Editor,
    ImageSlot::Inspector,
];
impl ImageSlot {
    pub const fn index(self) -> usize {
        self as usize
    }
    pub const fn role(self) -> Role {
        [
            Role::ShellImage,
            Role::InputImage,
            Role::WorkspaceImage,
            Role::BlockImage,
            Role::DisplayImage,
            Role::NetDriverImage,
            Role::NetServiceImage,
            Role::FilesImage,
            Role::EditorImage,
            Role::InspectorImage,
        ][self.index()]
    }
    pub const fn representative(self) -> Child {
        [
            Child::Shell,
            Child::Input,
            Child::Workspace,
            Child::Block,
            Child::Display,
            Child::NetDriver,
            Child::NetService,
            Child::Files,
            Child::EditorOne,
            Child::Inspector,
        ][self.index()]
    }
}
impl Child {
    pub const fn index(self) -> usize {
        self as usize
    }
    pub const fn image_slot(self) -> ImageSlot {
        match self {
            Self::EditorOne | Self::EditorTwo => ImageSlot::Editor,
            _ => [
                ImageSlot::Shell,
                ImageSlot::Input,
                ImageSlot::Workspace,
                ImageSlot::Block,
                ImageSlot::Display,
                ImageSlot::NetDriver,
                ImageSlot::NetService,
                ImageSlot::Files,
                ImageSlot::Editor,
                ImageSlot::Editor,
                ImageSlot::Inspector,
            ][self.index()],
        }
    }
    pub const fn image(self) -> Role {
        self.image_slot().role()
    }
    pub const fn job_template(self) -> u64 {
        match self {
            Self::Input | Self::Block | Self::NetDriver => 0,
            Self::NetService => 1,
            Self::Shell | Self::Files | Self::Inspector | Self::Workspace | Self::Display => 2,
            Self::EditorOne | Self::EditorTwo => 3,
        }
    }
    pub const fn limits(self) -> [u64; 4] {
        resources::JOB_TEMPLATE_LIMITS[self.job_template() as usize]
    }
    pub const fn frame_limit(self) -> u64 {
        self.limits()[1]
    }
    pub const fn instance(self) -> u16 {
        match self {
            Self::Files => 1,
            Self::EditorOne => 2,
            Self::EditorTwo => 3,
            Self::Inspector => 4,
            _ => 0,
        }
    }
    pub const fn surface(self) -> Option<Role> {
        match self {
            Self::Shell => Some(Role::ShellSurface),
            Self::Files => Some(Role::FilesSurface),
            Self::EditorOne => Some(Role::EditorOneSurface),
            Self::EditorTwo => Some(Role::EditorTwoSurface),
            Self::Inspector => Some(Role::InspectorSurface),
            _ => None,
        }
    }
    pub const fn frame(self) -> Option<Role> {
        match self {
            Self::Files => Some(Role::FilesFrame),
            Self::EditorOne => Some(Role::EditorOneFrame),
            Self::EditorTwo => Some(Role::EditorTwoFrame),
            Self::Inspector => Some(Role::InspectorFrame),
            _ => None,
        }
    }
    pub const fn control(self) -> Option<Channel> {
        match self {
            Self::Files => Some(Channel::FilesControl),
            Self::EditorOne => Some(Channel::EditorOneControl),
            Self::EditorTwo => Some(Channel::EditorTwoControl),
            Self::Inspector => Some(Channel::InspectorControl),
            _ => None,
        }
    }
    pub const fn inbox(self) -> Option<Channel> {
        match self {
            Self::Files => Some(Channel::FilesGrantInbox),
            Self::EditorOne => Some(Channel::EditorOneGrantInbox),
            Self::EditorTwo => Some(Channel::EditorTwoGrantInbox),
            Self::Inspector => Some(Channel::InspectorGrantInbox),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Channel {
    DisplayPresent = 0,
    DisplayControl = 1,
    InputBarrier = 2,
    ShellControl = 3,
    FilesControl = 4,
    EditorOneControl = 5,
    EditorTwoControl = 6,
    InspectorControl = 7,
    FilesGrantInbox = 8,
    EditorOneGrantInbox = 9,
    EditorTwoGrantInbox = 10,
    InspectorGrantInbox = 11,
    SystemBlock = 12,
    LegacyFileBlock = 13,
    WorkspaceBlock = 14,
    WorkspaceNamespace = 15,
    FilesFileLease = 16,
    EditorOneFileLease = 17,
    EditorTwoFileLease = 18,
    InspectorFileLease = 19,
    NetDriverRpc = 20,
    NetClientRpc = 21,
    RootWorkspaceControl = 22,
}
pub const CHANNELS: [Channel; 23] = [
    Channel::DisplayPresent,
    Channel::DisplayControl,
    Channel::InputBarrier,
    Channel::ShellControl,
    Channel::FilesControl,
    Channel::EditorOneControl,
    Channel::EditorTwoControl,
    Channel::InspectorControl,
    Channel::FilesGrantInbox,
    Channel::EditorOneGrantInbox,
    Channel::EditorTwoGrantInbox,
    Channel::InspectorGrantInbox,
    Channel::SystemBlock,
    Channel::LegacyFileBlock,
    Channel::WorkspaceBlock,
    Channel::WorkspaceNamespace,
    Channel::FilesFileLease,
    Channel::EditorOneFileLease,
    Channel::EditorTwoFileLease,
    Channel::InspectorFileLease,
    Channel::NetDriverRpc,
    Channel::NetClientRpc,
    Channel::RootWorkspaceControl,
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DeliveryMode {
    Async = 1,
    Rpc = 2,
    Selected = 3,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sender {
    Root,
    Child(Child),
}
impl Channel {
    pub const fn wire_index(self) -> usize {
        self as usize
    }
    pub const fn index(self) -> usize {
        self.wire_index()
    }
    pub const fn from_wire_index(value: usize) -> Option<Self> {
        if value < CHANNELS.len() {
            Some(CHANNELS[value])
        } else {
            None
        }
    }
    pub const fn receiver(self) -> Child {
        match self {
            Self::DisplayPresent | Self::DisplayControl => Child::Display,
            Self::InputBarrier => Child::Input,
            Self::ShellControl => Child::Shell,
            Self::FilesControl | Self::FilesGrantInbox => Child::Files,
            Self::EditorOneControl | Self::EditorOneGrantInbox => Child::EditorOne,
            Self::EditorTwoControl | Self::EditorTwoGrantInbox => Child::EditorTwo,
            Self::InspectorControl | Self::InspectorGrantInbox => Child::Inspector,
            Self::SystemBlock | Self::LegacyFileBlock | Self::WorkspaceBlock => Child::Block,
            Self::WorkspaceNamespace
            | Self::FilesFileLease
            | Self::EditorOneFileLease
            | Self::EditorTwoFileLease
            | Self::InspectorFileLease
            | Self::RootWorkspaceControl => Child::Workspace,
            Self::NetDriverRpc => Child::NetDriver,
            Self::NetClientRpc => Child::NetService,
        }
    }
    pub const fn delivery(self) -> DeliveryMode {
        match self {
            Self::ShellControl
            | Self::FilesControl
            | Self::EditorOneControl
            | Self::EditorTwoControl
            | Self::InspectorControl => DeliveryMode::Async,
            Self::FilesGrantInbox
            | Self::EditorOneGrantInbox
            | Self::EditorTwoGrantInbox
            | Self::InspectorGrantInbox => DeliveryMode::Selected,
            _ => DeliveryMode::Rpc,
        }
    }
    pub const fn session_rpc_ticks(self) -> u64 {
        match self {
            Self::WorkspaceNamespace
            | Self::FilesFileLease
            | Self::EditorOneFileLease
            | Self::EditorTwoFileLease
            | Self::InspectorFileLease
            | Self::RootWorkspaceControl => resources::FILE_TRANSACTION_TICKS,
            _ => resources::RPC_TICKS,
        }
    }
    pub fn allows(self, sender: Sender) -> bool {
        match self {
            Self::DisplayPresent => matches!(
                sender,
                Sender::Root
                    | Sender::Child(
                        Child::Shell
                            | Child::Files
                            | Child::EditorOne
                            | Child::EditorTwo
                            | Child::Inspector
                    )
            ),
            Self::LegacyFileBlock | Self::WorkspaceBlock => {
                sender == Sender::Child(Child::Workspace)
            }
            Self::WorkspaceNamespace | Self::FilesFileLease => {
                sender == Sender::Child(Child::Files)
            }
            Self::EditorOneFileLease => sender == Sender::Child(Child::EditorOne),
            Self::EditorTwoFileLease => sender == Sender::Child(Child::EditorTwo),
            Self::InspectorFileLease => sender == Sender::Child(Child::Inspector),
            Self::NetDriverRpc => sender == Sender::Child(Child::NetService),
            _ => sender == Sender::Root,
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
const SHELL: [Grant; 4] = [
    r(Role::ShellSurface, 1, 7),
    e(Channel::DisplayPresent, 8),
    e(Channel::ShellControl, 272),
    r(Role::RootEvents, 2, 8),
];
const INPUT: [Grant; 3] = [
    r(Role::InputPorts, 7, 3),
    r(Role::RootEvents, 2, 8),
    e(Channel::InputBarrier, 272),
];
const WORKSPACE: [Grant; 16] = [
    r(Role::LegacyFileIo, 1, 7),
    e(Channel::LegacyFileBlock, 8),
    r(Role::WorkspaceBlockWindow, 1, 7),
    e(Channel::WorkspaceBlock, 8),
    r(Role::RootWorkspaceFrame, 1, 7),
    r(Role::FilesFrame, 1, 7),
    r(Role::EditorOneFrame, 1, 7),
    r(Role::EditorTwoFrame, 1, 7),
    r(Role::InspectorFrame, 1, 7),
    e(Channel::WorkspaceNamespace, 272),
    e(Channel::FilesFileLease, 272),
    e(Channel::EditorOneFileLease, 272),
    e(Channel::EditorTwoFileLease, 272),
    e(Channel::InspectorFileLease, 272),
    r(Role::RootEvents, 2, 8),
    e(Channel::RootWorkspaceControl, 272),
];
const BLOCK: [Grant; 8] = [
    r(Role::AtaPorts, 7, 3),
    r(Role::SystemIo, 1, 7),
    e(Channel::SystemBlock, 272),
    r(Role::LegacyFileIo, 1, 7),
    e(Channel::LegacyFileBlock, 272),
    r(Role::RootEvents, 2, 8),
    r(Role::WorkspaceBlockWindow, 1, 7),
    e(Channel::WorkspaceBlock, 272),
];
const DISPLAY: [Grant; 10] = [
    r(Role::FilesSurface, 1, 5),
    r(Role::EditorOneSurface, 1, 5),
    r(Role::EditorTwoSurface, 1, 5),
    r(Role::InspectorSurface, 1, 5),
    r(Role::ShellSurface, 1, 5),
    r(Role::ProtectedSurface, 1, 5),
    e(Channel::DisplayPresent, 272),
    r(Role::Display, 8, 7),
    r(Role::RootEvents, 2, 8),
    e(Channel::DisplayControl, 272),
];
const NET_DRIVER: [Grant; 4] = [
    r(Role::NicPorts, 7, 3),
    r(Role::NicWindow, 1, 7),
    e(Channel::NetDriverRpc, 272),
    r(Role::RootEvents, 2, 8),
];
const NET_SERVICE: [Grant; 5] = [
    r(Role::NicWindow, 1, 7),
    e(Channel::NetDriverRpc, 8),
    r(Role::NetClientWindow, 1, 7),
    e(Channel::NetClientRpc, 272),
    r(Role::RootEvents, 2, 8),
];
const FILES: [Grant; 7] = [
    r(Role::FilesSurface, 1, 7),
    e(Channel::DisplayPresent, 8),
    r(Role::RootEvents, 2, 8),
    e(Channel::FilesControl, 272),
    r(Role::FilesFrame, 1, 7),
    e(Channel::FilesGrantInbox, 272),
    e(Channel::WorkspaceNamespace, 8),
];
const EDITOR_ONE: [Grant; 6] = [
    r(Role::EditorOneSurface, 1, 7),
    e(Channel::DisplayPresent, 8),
    r(Role::RootEvents, 2, 8),
    e(Channel::EditorOneControl, 272),
    r(Role::EditorOneFrame, 1, 7),
    e(Channel::EditorOneGrantInbox, 272),
];
const EDITOR_TWO: [Grant; 6] = [
    r(Role::EditorTwoSurface, 1, 7),
    e(Channel::DisplayPresent, 8),
    r(Role::RootEvents, 2, 8),
    e(Channel::EditorTwoControl, 272),
    r(Role::EditorTwoFrame, 1, 7),
    e(Channel::EditorTwoGrantInbox, 272),
];
const INSPECTOR: [Grant; 6] = [
    r(Role::InspectorSurface, 1, 7),
    e(Channel::DisplayPresent, 8),
    r(Role::RootEvents, 2, 8),
    e(Channel::InspectorControl, 272),
    r(Role::InspectorFrame, 1, 7),
    e(Channel::InspectorGrantInbox, 272),
];
pub const GRANT_COUNTS: [usize; 11] = [4, 3, 16, 8, 10, 4, 5, 7, 6, 6, 6];
pub fn grants(child: Child) -> impl ExactSizeIterator<Item = Grant> {
    let values: &'static [Grant] = match child {
        Child::Shell => &SHELL,
        Child::Input => &INPUT,
        Child::Workspace => &WORKSPACE,
        Child::Block => &BLOCK,
        Child::Display => &DISPLAY,
        Child::NetDriver => &NET_DRIVER,
        Child::NetService => &NET_SERVICE,
        Child::Files => &FILES,
        Child::EditorOne => &EDITOR_ONE,
        Child::EditorTwo => &EDITOR_TWO,
        Child::Inspector => &INSPECTOR,
    };
    values.iter().copied()
}
pub const DESCRIPTION_BYTES: usize = 4096;
pub fn description() -> [u8; DESCRIPTION_BYTES] {
    let mut b = [0; DESCRIPTION_BYTES];
    b[..8].copy_from_slice(b"EVWIRE05");
    b[8] = CHILDREN.len() as u8;
    b[9] = CHANNELS.len() as u8;
    b[10] = ROOT_EVENTS_WIRE as u8;
    b[11] = WIRE_SLOTS as u8;
    let mut at = 32;
    for child in CHILDREN {
        for (i, g) in grants(child).enumerate() {
            b[at] = child.index() as u8;
            b[at + 1] = i as u8 + 1;
            b[at + 2] = g.kind;
            b[at + 4..at + 6].copy_from_slice(&g.rights.to_le_bytes());
            match g.source {
                Source::Root(role) => {
                    b[at + 6] = 1;
                    super::put(&mut b, at + 8, role.selector());
                }
                Source::Endpoint(channel) => {
                    b[at + 6] = 2;
                    super::put(&mut b, at + 8, channel.wire_index() as u64);
                }
            }
            at += 16;
        }
    }
    for channel in CHANNELS {
        b[at] = channel.wire_index() as u8;
        b[at + 1] = channel.receiver().index() as u8;
        b[at + 2] = channel.delivery() as u8;
        super::put(&mut b, at + 8, channel.session_rpc_ticks());
        let mut mask = if channel.allows(Sender::Root) {
            1u16
        } else {
            0
        };
        for child in CHILDREN {
            if channel.allows(Sender::Child(child)) {
                mask |= 1 << (child.index() + 1);
            }
        }
        b[at + 4..at + 6].copy_from_slice(&mask.to_le_bytes());
        at += 16;
    }
    for child in CHILDREN {
        for value in [
            child.index() as u64,
            child.image().selector(),
            child.instance() as u64,
            child.job_template(),
            super::child::startup_size(child) as u64,
        ]
        .into_iter()
        .chain(child.limits())
        {
            super::put(&mut b, at, value);
            at += 8;
        }
    }
    b
}
