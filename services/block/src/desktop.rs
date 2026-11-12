//! Immutable userspace endpoint-to-slice/window policy. Kernel routing remains
//! opaque; no application or System packet can choose the File client identity.
use crate::{DISK_SECTORS, StartupError};
use ev_store::desktop::Client;
use ev_userspace_contract::{
    Bootstrap,
    block::{DecodeError, Request, Response},
};
pub const READY: [u8; 8] = *b"EVBLRDY1";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub ports: u64,
    pub system_buffer: u64,
    pub system_request: u64,
    pub file_buffer: u64,
    pub file_request: u64,
    pub events: u64,
}
pub fn startup(bytes: &[u8]) -> Result<Capabilities, StartupError> {
    let b = Bootstrap::parse(bytes).map_err(StartupError::Bootstrap)?;
    for (index, value) in ev_userspace_contract::root_v2::catalogue::CHILD_LIMITS
        .into_iter()
        .enumerate()
    {
        if bytes[40 + index * 8..48 + index * 8] != value.to_le_bytes() {
            return Err(StartupError::Limits);
        }
    }
    if b.grants().count() != 6 {
        return Err(StartupError::Count);
    }
    let mut handles = [0; 6];
    for (index, (kind, rights)) in [(7, 3), (1, 7), (2, 272), (1, 7), (2, 272), (2, 8)]
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
    })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Routes {
    system: u64,
    files: u64,
    native_system: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
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
impl Routes {
    pub fn new(system: u64, files: u64) -> Option<Self> {
        if system == 0 || files == 0 || system == files {
            None
        } else {
            Some(Self {
                system,
                files,
                native_system: false,
            })
        }
    }
    /// An explicitly compiled Native driver may expose the four closed Root
    /// regions. This never changes File bounds or accepts a packet route tag.
    pub fn new_native(system: u64, files: u64) -> Option<Self> {
        Self::new(system, files).map(|mut routes| {
            routes.native_system = true;
            routes
        })
    }
    fn physical_sector(&self, client: Client, logical: u32) -> Option<u32> {
        if self.native_system && client == Client::System {
            ev_store::native::physical_sector(logical)
        } else {
            client.physical_sector(logical)
        }
    }
    /// received_on is the actual successful kernel receive handle. No route ID
    /// is decoded from the scalar request. Validate BEFORE buffer/PIO access.
    pub fn resolve(&self, received_on: u64, bytes: [u8; 8]) -> Result<Operation, Error> {
        let client = if received_on == self.system {
            Client::System
        } else if received_on == self.files {
            Client::Files
        } else {
            return Err(Error::UnknownEndpoint);
        };
        let request = Request::decode(&bytes).map_err(Error::Malformed)?;
        let physical = match request {
            Request::Read { sector } => Request::Read {
                sector: self.physical_sector(client, sector).ok_or(Error::Bounds)?,
            },
            Request::Write { sector } => Request::Write {
                sector: self.physical_sector(client, sector).ok_or(Error::Bounds)?,
            },
            Request::Flush => Request::Flush,
        };
        if !physical.in_bounds(DISK_SECTORS) {
            return Err(Error::Bounds);
        }
        Ok(Operation {
            client,
            physical,
            reply: request.success(),
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_endpoint_selects_slice_not_an_untrusted_request_sector() {
        let r = Routes::new(256, 257).unwrap();
        for sector in 0..14 {
            assert_eq!(
                r.resolve(256, Request::Write { sector }.encode())
                    .unwrap()
                    .physical,
                Request::Write {
                    sector: 16 + sector
                }
            );
            assert_eq!(
                r.resolve(257, Request::Write { sector }.encode())
                    .unwrap()
                    .physical,
                Request::Write {
                    sector: 32 + sector
                }
            );
        }
        for sector in 16..30 {
            assert_eq!(
                r.resolve(257, Request::Read { sector }.encode())
                    .unwrap()
                    .physical,
                Request::Read {
                    sector: 32 + sector
                }
            );
            assert_eq!(
                r.resolve(256, Request::Read { sector }.encode()),
                Err(Error::Bounds)
            );
        }
        for sector in [14, 15, 30, 31, 32, 48, u32::MAX] {
            assert_eq!(
                r.resolve(257, Request::Read { sector }.encode()),
                Err(Error::Bounds)
            );
        }
        assert_eq!(
            r.resolve(999, Request::Flush.encode()),
            Err(Error::UnknownEndpoint)
        );
        assert!(r.resolve(256, [0; 8]).is_err());
        let mut invalid = Request::Flush.encode();
        invalid[4] = 1;
        assert!(r.resolve(256, invalid).is_err());
        assert_eq!(
            r.resolve(257, Request::Write { sector: 16 }.encode())
                .unwrap()
                .reply,
            Response::Written { sector: 16 }
        );
    }
    #[test]
    fn native_profile_is_explicit_and_the_file_route_cannot_reach_native_state() {
        let old = Routes::new(256, 257).unwrap();
        let native = Routes::new_native(256, 257).unwrap();
        for sector in 0..128 {
            for request in [Request::Read { sector }, Request::Write { sector }] {
                let expected = ev_store::native::physical_sector(sector);
                let resolved = native.resolve(256, request.encode());
                match expected {
                    Some(physical) => {
                        assert_eq!(
                            resolved.unwrap().physical,
                            match request {
                                Request::Read { .. } => Request::Read { sector: physical },
                                _ => Request::Write { sector: physical },
                            }
                        );
                    }
                    None => assert_eq!(resolved, Err(Error::Bounds)),
                }
                assert_eq!(
                    native.resolve(257, request.encode()),
                    old.resolve(257, request.encode())
                );
                if sector >= 14 {
                    assert_eq!(old.resolve(256, request.encode()), Err(Error::Bounds));
                }
            }
        }
        assert_eq!(
            native.resolve(257, Request::Write { sector: 32 }.encode()),
            Err(Error::Bounds)
        );
        assert_eq!(
            native.resolve(999, Request::Flush.encode()),
            Err(Error::UnknownEndpoint)
        );
        assert!(native.resolve(256, [0; 8]).is_err());
    }
    #[test]
    fn startup_requires_exact_two_independent_windows_receivers_and_scoped_ports() {
        use ev_userspace_contract::{Context, Grant, encode};
        let context = Context {
            epoch: 1,
            incarnation: 1,
            process: 1,
            limits: ev_userspace_contract::root_v2::catalogue::CHILD_LIMITS,
            manifest: [1; 32],
            authority: [2; 32],
        };
        let mut grants = core::array::from_fn::<_, 6, _>(|i| {
            let (kind, rights) = [(7, 3), (1, 7), (2, 272), (1, 7), (2, 272), (2, 8)][i];
            Grant {
                selector: i as u64 + 1,
                handle: 256 + i as u64,
                kind,
                rights,
            }
        });
        let bytes = encode(context, &grants).unwrap();
        let caps = startup(&bytes).unwrap();
        let mut wrong_limits = context;
        wrong_limits.limits[0] = 2048;
        assert_eq!(
            startup(&encode(wrong_limits, &grants).unwrap()),
            Err(StartupError::Limits)
        );
        assert_ne!(caps.system_buffer, caps.file_buffer);
        assert_ne!(caps.system_request, caps.file_request);
        assert!(startup(&encode(context, &grants[..5]).unwrap()).is_err());
        for index in 0..6 {
            let mut wrong = grants;
            wrong[index].rights ^= 128;
            assert!(startup(&encode(context, &wrong).unwrap()).is_err());
        }
        grants[3].handle = grants[1].handle;
        assert!(startup(&encode(context, &grants).unwrap()).is_err());
    }
}

#[cfg(test)]
mod native_grant_tests {
    use super::*;
    #[test]
    fn owner_policy_sectors_require_actual_root_system_receiver_and_preserve_file_route() {
        let native = Routes::new_native(256, 257).unwrap();
        let desktop = Routes::new(256, 257).unwrap();
        for local in 0..14 {
            for req in [
                Request::Read { sector: 48 + local },
                Request::Write { sector: 48 + local },
            ] {
                let actual = native.resolve(256, req.encode()).unwrap();
                assert_eq!(
                    actual.physical,
                    match req {
                        Request::Read { .. } => Request::Read { sector: 96 + local },
                        _ => Request::Write { sector: 96 + local },
                    }
                );
                assert_eq!(native.resolve(257, req.encode()), Err(Error::Bounds));
                assert_eq!(desktop.resolve(256, req.encode()), Err(Error::Bounds));
            }
        }
        for sector in [46, 47, 62, 63, 94, 95, 96, 109, u32::MAX] {
            assert_eq!(
                native.resolve(256, Request::Read { sector }.encode()),
                Err(Error::Bounds)
            );
        }
    }
}
