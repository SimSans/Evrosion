//! Explicit profile5: unchanged legacy routes and an independently bound new
//! workspace region/window. A packet never selects the client, profile or disk.
//! No ID, Rust backend value or startup metadata grants kernel authority.
use crate::{
    StartupError,
    store_io::{Error as IoError, Window, Wire},
};
use ev_store::{Sector, SectorIo};
use ev_userspace_contract::{
    Bootstrap,
    block::{DecodeError, Request, Response},
};

pub const PROFILE: u16 = 5;
pub const DISK_SECTORS: u32 = 196_608;
pub const SERIAL: [u8; 20] = *b"EVROSION-M8-WORK    ";
pub const WORKSPACE_START: u32 = 16_384;
pub const WORKSPACE_SECTORS: u32 = 152_322;
pub const WORKSPACE_END: u32 = WORKSPACE_START + WORKSPACE_SECTORS;
/// One additive external-App allocation pair, reachable only through profile5's
/// already Root-owned System receiver. Original0.2/0.3 regions stay unchanged.
pub const EXTERNAL_REGISTRY_WIRE: u32 = 8192;
pub const EXTERNAL_DATA_WIRE: u32 = 8208;
pub const EXTERNAL_REGION_SECTORS: u32 = ev_store::REQUIRED_SECTORS as u32;
pub const EXTERNAL_REGISTRY_START: u32 = 168_720;
pub const EXTERNAL_DATA_START: u32 = 168_736;
pub const EXTERNAL_ALLOCATION_END: u32 = EXTERNAL_DATA_START + EXTERNAL_REGION_SECTORS;
const _: () = assert!(
    WORKSPACE_END < EXTERNAL_REGISTRY_START
        && EXTERNAL_REGISTRY_START + EXTERNAL_REGION_SECTORS < EXTERNAL_DATA_START
        && EXTERNAL_ALLOCATION_END < DISK_SECTORS
);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalRegion {
    Registry,
    PrivateData,
}
impl ExternalRegion {
    pub const fn wire_start(self) -> u32 {
        match self {
            Self::Registry => EXTERNAL_REGISTRY_WIRE,
            Self::PrivateData => EXTERNAL_DATA_WIRE,
        }
    }
    pub const fn physical_start(self) -> u32 {
        match self {
            Self::Registry => EXTERNAL_REGISTRY_START,
            Self::PrivateData => EXTERNAL_DATA_START,
        }
    }
    pub const fn wire_sector(self, local: u64) -> Option<u32> {
        if local < EXTERNAL_REGION_SECTORS as u64 {
            Some(self.wire_start() + local as u32)
        } else {
            None
        }
    }
}
/// Selected profile5 Root-only mapping. This does not widen profile4, Files or
/// Workspace and never accepts a packet-selected AppId/allocation/namespace.
pub const fn system_physical_sector(sector: u32) -> Option<u32> {
    if sector >= EXTERNAL_REGISTRY_WIRE && sector < EXTERNAL_REGISTRY_WIRE + EXTERNAL_REGION_SECTORS
    {
        Some(EXTERNAL_REGISTRY_START + sector - EXTERNAL_REGISTRY_WIRE)
    } else if sector >= EXTERNAL_DATA_WIRE && sector < EXTERNAL_DATA_WIRE + EXTERNAL_REGION_SECTORS
    {
        Some(EXTERNAL_DATA_START + sector - EXTERNAL_DATA_WIRE)
    } else {
        ev_store::network::physical_sector(sector)
    }
}
pub const READY: [u8; 8] = *b"EVBLRDY1";
const _: () = assert!(WORKSPACE_START > crate::DISK_SECTORS && WORKSPACE_END < DISK_SECTORS);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub ports: u64,
    pub system_buffer: u64,
    pub system_request: u64,
    pub file_buffer: u64,
    pub file_request: u64,
    pub events: u64,
    pub workspace_buffer: u64,
    pub workspace_request: u64,
}
/// New strict eight-role profile. Existing six-role startup remains unchanged.
pub fn startup(bytes: &[u8]) -> Result<Capabilities, StartupError> {
    let b = Bootstrap::parse(bytes).map_err(StartupError::Bootstrap)?;
    for (index, value) in ev_userspace_contract::root_v5::resources::JOB_TEMPLATE_LIMITS[0]
        .into_iter()
        .enumerate()
    {
        if bytes[40 + index * 8..48 + index * 8] != value.to_le_bytes() {
            return Err(StartupError::Limits);
        }
    }
    if b.grants().count() != 8 {
        return Err(StartupError::Count);
    }
    let mut handles = [0; 8];
    for (index, (kind, rights)) in [
        (7, 3),
        (1, 7),
        (2, 272),
        (1, 7),
        (2, 272),
        (2, 8),
        (1, 7),
        (2, 272),
    ]
    .into_iter()
    .enumerate()
    {
        let grant = b.find(index as u64 + 1).ok_or(StartupError::Missing)?;
        if grant.kind != kind || grant.rights != rights || handles[..index].contains(&grant.handle)
        {
            return Err(StartupError::Authority);
        }
        handles[index] = grant.handle;
    }
    Ok(Capabilities {
        ports: handles[0],
        system_buffer: handles[1],
        system_request: handles[2],
        file_buffer: handles[3],
        file_request: handles[4],
        events: handles[5],
        workspace_buffer: handles[6],
        workspace_request: handles[7],
    })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Client {
    System,
    Files,
    Workspace,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteError {
    UnknownEndpoint,
    Malformed(DecodeError),
    Bounds,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Operation {
    pub client: Client,
    pub physical: Request,
    pub reply: Response,
}
impl Operation {
    pub fn complete(self, physical: Response) -> Option<Response> {
        (physical == self.physical.success()).then_some(self.reply)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Routes {
    system: u64,
    files: u64,
    workspace: u64,
}
impl Routes {
    pub fn new(system: u64, files: u64, workspace: u64) -> Option<Self> {
        let values = [system, files, workspace];
        if values
            .iter()
            .enumerate()
            .any(|(i, v)| *v == 0 || values[..i].contains(v))
        {
            None
        } else {
            Some(Self {
                system,
                files,
                workspace,
            })
        }
    }
    pub fn resolve(&self, received_on: u64, bytes: [u8; 8]) -> Result<Operation, RouteError> {
        let client = if received_on == self.system {
            Client::System
        } else if received_on == self.files {
            Client::Files
        } else if received_on == self.workspace {
            Client::Workspace
        } else {
            return Err(RouteError::UnknownEndpoint);
        };
        let request = Request::decode(&bytes).map_err(RouteError::Malformed)?;
        let translate = |sector: u32| match client {
            // Preserve every original profile4 mapping. Only profile5 adds
            // the two closed appended external-App regions above.
            Client::System => system_physical_sector(sector),
            Client::Files => ev_store::desktop::Client::Files.physical_sector(sector),
            Client::Workspace => {
                if sector < WORKSPACE_SECTORS {
                    Some(WORKSPACE_START + sector)
                } else {
                    None
                }
            }
        };
        let physical = match request {
            Request::Read { sector } => Request::Read {
                sector: translate(sector).ok_or(RouteError::Bounds)?,
            },
            Request::Write { sector } => Request::Write {
                sector: translate(sector).ok_or(RouteError::Bounds)?,
            },
            Request::Flush => Request::Flush,
        };
        if !physical.in_bounds(DISK_SECTORS) {
            return Err(RouteError::Bounds);
        }
        Ok(Operation {
            client,
            physical,
            reply: request.success(),
        })
    }
}

/// One non-Clone workspace owner and actual shared sector window. Window and
/// transport values alone do not prove exclusivity or permit timeout reuse.
pub struct Region<T, W> {
    transport: T,
    window: W,
    poisoned: bool,
}
impl<T: Wire, W: Window> Region<T, W> {
    pub fn new(transport: T, window: W) -> Option<Self> {
        transport.supports_session().then_some(Self {
            transport,
            window,
            poisoned: false,
        })
    }
    pub fn into_parts(self) -> (T, W) {
        (self.transport, self.window)
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    fn preflight(&self, lba: u64, deadline: u64) -> Result<(u32, u64), IoError<T::Error>> {
        if self.poisoned {
            return Err(IoError::NeedsRecovery);
        }
        if lba >= WORKSPACE_SECTORS as u64 {
            return Err(IoError::Bounds);
        }
        if deadline == 0 || deadline == u64::MAX {
            return Err(IoError::Deadline);
        }
        let child = self
            .transport
            .capture_session_deadline(deadline)
            .ok_or(IoError::Deadline)?;
        if child == 0 || child == u64::MAX || child > deadline {
            return Err(IoError::Deadline);
        }
        Ok((lba as u32, child))
    }
    fn request(&mut self, request: Request, deadline: u64) -> Result<(), IoError<T::Error>> {
        let result = (|| {
            let frame = self
                .transport
                .call(request.encode(), deadline)
                .map_err(IoError::Transport)?;
            let response = Response::decode(&frame).map_err(IoError::Decode)?;
            if response != request.success() {
                return Err(IoError::UnexpectedReply(response));
            }
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}
impl<T: Wire, W: Window> SectorIo for Region<T, W> {
    type Error = IoError<T::Error>;
    fn sectors(&self) -> u64 {
        WORKSPACE_SECTORS as u64
    }
    fn read(&mut self, lba: u64, out: &mut Sector, deadline: u64) -> Result<(), Self::Error> {
        let (sector, child) = self.preflight(lba, deadline)?;
        self.request(Request::Read { sector }, child)?;
        self.window.load(out);
        Ok(())
    }
    fn write(&mut self, lba: u64, bytes: &Sector, deadline: u64) -> Result<(), Self::Error> {
        let (sector, child) = self.preflight(lba, deadline)?;
        self.window.store(bytes);
        self.request(Request::Write { sector }, child)
    }
    fn flush(&mut self, deadline: u64) -> Result<(), Self::Error> {
        let (_, child) = self.preflight(0, deadline)?;
        self.request(Request::Flush, child)
    }
}

#[cfg(test)]
#[path = "workspace_tests.rs"]
mod tests;
